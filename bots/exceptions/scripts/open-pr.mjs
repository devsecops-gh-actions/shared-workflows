#!/usr/bin/env node
// open-pr.mjs (F-c, W1). Abre un pull request que añade una entrada a security/exceptions.yml.
// Función inyectable openExceptionPr(...): con dryRun (por defecto) no hace red y devuelve el plan.
// Sin dependencias externas (Node 20+). El bot nunca fusiona: la excepción solo surte efecto al
// fusionarse el PR en la rama base.
//
// Secuencia real (dryRun false):
//   1. GET git/ref/heads/<base>            -> SHA de la base
//   2. GET contents/security/exceptions.yml (en la base) -> texto actual y blob sha
//   3. Validación local: id no duplicado, texto resultante válido con el parser compartido
//   4. POST git/refs                        -> crea la rama bot/exceptions/*
//   5. PUT contents/security/exceptions.yml -> commit con la entrada añadida, en la rama nueva
//   6. POST pulls                           -> PR de la rama nueva a la base
// Si la validación falla no se crea nada en GitHub.
//
// Token: se exige solo para la ejecución real. Nunca se imprime ni aparece en los errores.

import { checkExceptions, parseExceptions } from '../../../security/scripts/lib/exceptions-parse.mjs';

export const EXCEPTIONS_PATH = 'security/exceptions.yml';
export const BRANCH_PREFIX = 'bot/exceptions/';
const API = 'https://api.github.com';
const BRANCH_RE = /^bot\/exceptions\/[A-Za-z0-9][A-Za-z0-9._/-]*$/;

const todayUtc = () => new Date().toISOString().slice(0, 10);

// "CVE-2026-7777" -> "cve-2026-7777". Solo minúsculas, dígitos y guiones.
export function sanitizeId(id) {
  return String(id ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/, '');
}

// Inserta el bloque YAML de una entrada en el texto del registro.
// Sustituye "exceptions: []" por la lista con la entrada, o añade la entrada al final si la lista ya existe.
export function insertEntry(currentText, yamlText) {
  const emptyRe = /^exceptions:[ \t]*\[\][ \t]*$/m;
  if (emptyRe.test(currentText)) {
    return currentText.replace(emptyRe, `exceptions:\n${yamlText}`);
  }
  if (/^exceptions:[ \t]*$/m.test(currentText)) {
    const base = currentText.endsWith('\n') ? currentText : `${currentText}\n`;
    return `${base}${yamlText}`;
  }
  throw new Error('no se encuentra la clave raíz "exceptions" en security/exceptions.yml');
}

// Validación offline del plan: id, rama, entrada válida y sin caducar. No usa red.
function buildPlan({ entry, yamlText, baseBranch, branch, today }) {
  const id = String(entry?.id ?? '').trim();
  if (!id) throw new Error('la entrada no tiene id');
  if (typeof yamlText !== 'string' || yamlText.trim() === '') throw new Error('falta el bloque YAML de la entrada');
  if (!baseBranch) throw new Error('falta la rama base');

  const safeId = sanitizeId(id);
  if (!safeId) throw new Error('el id no produce un nombre de rama válido');
  const branchName = branch ?? `${BRANCH_PREFIX}${safeId}-${today}`;
  if (!branchName.startsWith(BRANCH_PREFIX)) {
    throw new Error(`la rama debe empezar por ${BRANCH_PREFIX}`);
  }
  if (!BRANCH_RE.test(branchName) || branchName.includes('..')) {
    throw new Error(`nombre de rama no válido: ${branchName}`);
  }

  const check = checkExceptions(`exceptions:\n${yamlText}`, { today });
  if (!check.valid) throw new Error(`entrada no válida: ${check.errors.join(' | ')}`);
  if (check.expired.length) throw new Error(`la entrada ya está caducada: ${check.expired.join(' | ')}`);

  const fields = check.accepted[0];
  const title = `Excepción de seguridad ${id} (caduca ${fields.expires})`;
  const body = [
    'Propuesta de excepción de seguridad generada por el bot de excepciones.',
    '',
    ...['id', 'scope', 'control', 'owner', 'reason', 'approved_by', 'created', 'expires', 'ticket']
      .map((k) => `- **${k}**: ${fields[k]}`),
    '',
    'El bot no fusiona este PR. La excepción surte efecto solo al fusionarse en la rama base.',
  ].join('\n');

  return { id, branch: branchName, baseBranch, path: EXCEPTIONS_PATH, title, body, expires: fields.expires };
}

async function gh(fetchImpl, token, method, path, payload) {
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const init = { method, headers };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(payload);
  }
  const res = await fetchImpl(`${API}${path}`, init);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail = data && typeof data.message === 'string' ? `: ${data.message}` : '';
    throw new Error(`GitHub ${method} ${path.split('?')[0]} respondió ${res.status}${detail}`);
  }
  return data;
}

const encodePath = (s) => s.split('/').map(encodeURIComponent).join('/');

// Abre el PR. Devuelve el plan; en la ejecución real, además url y number del PR creado.
export async function openExceptionPr({
  entry,
  yamlText,
  baseBranch = 'main',
  org,
  repo,
  token,
  fetchImpl = globalThis.fetch,
  dryRun = true,
  branch,
  today = todayUtc(),
} = {}) {
  const plan = buildPlan({ entry, yamlText, baseBranch, branch, today });
  if (dryRun) return { dryRun: true, ...plan };

  if (!token) throw new Error('falta el token de GitHub');
  if (!org || !repo) throw new Error('faltan org o repo');
  if (typeof fetchImpl !== 'function') throw new Error('falta fetchImpl');

  const repoPath = `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}`;
  const filePath = `${repoPath}/contents/${EXCEPTIONS_PATH}`;

  // 1-2. SHA de la base y contenido actual del registro.
  const baseRef = await gh(fetchImpl, token, 'GET', `${repoPath}/git/ref/heads/${encodePath(baseBranch)}`);
  const baseSha = baseRef?.object?.sha;
  if (!baseSha) throw new Error('no se ha podido leer el SHA de la rama base');

  const file = await gh(fetchImpl, token, 'GET', `${filePath}?ref=${encodeURIComponent(baseBranch)}`);
  const currentText = Buffer.from(String(file?.content ?? ''), 'base64').toString('utf8');
  const fileSha = file?.sha;
  if (!fileSha) throw new Error(`no se ha podido leer ${EXCEPTIONS_PATH}`);

  // 3. Duplicados y validación del texto resultante, antes de crear nada.
  const existing = parseExceptions(currentText);
  if (existing.some((e) => e.fields.id === plan.id)) {
    throw new Error(`el id ${plan.id} ya existe en ${EXCEPTIONS_PATH}`);
  }
  const newText = insertEntry(currentText, yamlText);
  const check = checkExceptions(newText, { today });
  if (!check.valid) throw new Error(`el registro resultante no es válido: ${check.errors.join(' | ')}`);

  // 4-6. Rama, commit y PR.
  await gh(fetchImpl, token, 'POST', `${repoPath}/git/refs`, { ref: `refs/heads/${plan.branch}`, sha: baseSha });
  await gh(fetchImpl, token, 'PUT', filePath, {
    message: `chore(exceptions): añade excepción ${plan.id}`,
    content: Buffer.from(newText, 'utf8').toString('base64'),
    sha: fileSha,
    branch: plan.branch,
  });
  const pr = await gh(fetchImpl, token, 'POST', `${repoPath}/pulls`, {
    title: plan.title,
    head: plan.branch,
    base: baseBranch,
    body: plan.body,
  });

  return { dryRun: false, ...plan, url: pr?.html_url ?? null, number: pr?.number ?? null };
}
