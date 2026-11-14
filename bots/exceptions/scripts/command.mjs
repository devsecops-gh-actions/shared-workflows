#!/usr/bin/env node
// command.mjs (F-c, W2). Comando /security-exception en comentarios de pull request.
// Funciones puras (parseCommand, parseMembers, isAuthorized, decideCommand) y una CLI que lee
// variables de entorno y escribe la decision en JSON por stdout. Sin dependencias (Node 20+).
// Solo abre PR (open-pr.mjs) si action === "accept" y EXCEPTIONS_APPLY === "SI"; si no, dry-run.
//
// Formato del comentario: la primera linea es solo el comando; despues, un campo por linea "clave: valor":
//   /security-exception
//   id: CVE-2026-0000
//   scope: acme/api
//   control: dependencies
//   owner: ana.lopez
//   reason: Mitigado con WAF; actualizacion planificada
//   approved_by: appsec-lead
//   created: 2026-11-14
//   expires: 2027-02-12
//   ticket: JIRA-1234
//
// Variables de entorno de la CLI:
//   COMMENT_BODY, COMMENT_AUTHOR, IS_PR (true|false), HEAD_REPO, BASE_REPO,
//   APPSEC_MEMBERS (logins separados por comas o espacios; en CI viene de vars.APPSEC_MEMBERS),
//   TODAY (opcional, AAAA-MM-DD; por defecto la fecha UTC actual),
//   EXCEPTIONS_APPLY (solo "SI" abre el PR), GITHUB_TOKEN (solo se usa si se abre el PR).
// Salida: {"action":"ignore"|"reject"|"accept","message":"...","errors":[...],"yaml":"..."|null}
// Codigos de salida: 0 decision emitida; 2 error interno.

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { REQUIRED } from '../../../security/scripts/lib/exceptions-parse.mjs';
import { buildEntry } from './build-exception-entry.mjs';
import { openExceptionPr } from './open-pr.mjs';

export const COMMAND = '/security-exception';
const CMD_RE = /^\/security-exception(?=\s|$)/;
const FIELD_RE = /^([a-z_]+):\s*(.*)$/;

const todayUtc = () => new Date().toISOString().slice(0, 10);

// Extrae el comando y sus campos. No decide nada: devuelve isCommand, fields y errors de formato.
export function parseCommand(body) {
  const text = typeof body === 'string' ? body.replace(/\r\n/g, '\n').trimStart() : '';
  if (!CMD_RE.test(text)) return { isCommand: false, fields: {}, errors: [] };

  const [first, ...rest] = text.split('\n');
  const errors = [];
  if (first.slice(COMMAND.length).trim() !== '') {
    errors.push('el comando va solo en su linea; los campos van debajo, uno por linea (clave: valor)');
  }

  const fields = {};
  for (const raw of rest) {
    const line = raw.trim();
    if (line === '') continue;
    const m = FIELD_RE.exec(line);
    if (!m) { errors.push(`linea no valida: "${line}" (se espera clave: valor)`); continue; }
    const [, key, value] = m;
    if (!REQUIRED.includes(key)) { errors.push(`campo desconocido: ${key}`); continue; }
    if (key in fields) { errors.push(`campo duplicado: ${key}`); continue; }
    fields[key] = value.trim();
  }
  return { isCommand: true, fields, errors };
}

// Convierte "@ana, Luis  bob" en ["ana", "luis", "bob"] (minusculas, sin @).
export function parseMembers(text) {
  const list = String(text ?? '')
    .split(/[\s,]+/)
    .map((s) => s.trim().replace(/^@/, '').toLowerCase())
    .filter(Boolean);
  return [...new Set(list)];
}

// Fail closed: sin lista de miembros nadie esta autorizado.
export function isAuthorized(author, members) {
  if (!author || !Array.isArray(members) || members.length === 0) return false;
  return members.map((m) => String(m).toLowerCase()).includes(String(author).toLowerCase());
}

function result(action, errors, message, yaml = null) {
  return { action, message, errors, yaml };
}

function rejectWith(errors, title) {
  const list = errors.map((e) => `- ${e}`).join('\n');
  return result('reject', errors, `${title}\n\n${list}`);
}

// Decision completa para un comentario. Orden: ignorar -> solo PR -> sin fork -> autor -> formato -> validacion.
export function decideCommand({ body, author, isPullRequest, headRepo, baseRepo, appsecMembers, today = todayUtc() }) {
  const parsed = parseCommand(body);
  if (!parsed.isCommand) return result('ignore', [], '');

  if (!isPullRequest) {
    return rejectWith(['el comando solo se admite en comentarios de pull request'], 'No se ha procesado el comando.');
  }

  const head = String(headRepo ?? '').toLowerCase();
  const base = String(baseRepo ?? '').toLowerCase();
  if (!head || head !== base) {
    return rejectWith(
      ['el pull request viene de un fork o su repositorio de origen no existe; no se procesa el comando'],
      'No se ha procesado el comando.',
    );
  }

  if (!Array.isArray(appsecMembers) || appsecMembers.length === 0) {
    return rejectWith(
      ['no hay lista de AppSec configurada (variable APPSEC_MEMBERS del repositorio); se rechaza por defecto'],
      'No se ha procesado el comando.',
    );
  }
  if (!isAuthorized(author, appsecMembers)) {
    return rejectWith(
      [`@${author || 'desconocido'} no esta en el equipo de AppSec; solo AppSec puede solicitar excepciones`],
      'No se ha procesado el comando.',
    );
  }

  if (parsed.errors.length) return rejectWith(parsed.errors, 'No se ha procesado el comando.');

  const built = buildEntry(parsed.fields, { today });
  if (!built.ok) return rejectWith(built.errors, 'La excepcion no es valida.');

  const id = parsed.fields.id;
  return {
    ...result(
      'accept',
      [],
      `Excepcion valida para \`${id}\` (caduca ${parsed.fields.expires}).`,
      built.yaml,
    ),
    entry: parsed.fields,
  };
}

// Paso posterior a la decision. Solo actua si action === 'accept'.
// apply !== true -> dry-run: devuelve el plan y lo indica en el mensaje; no hay llamadas de escritura.
// apply === true -> abre el PR con openExceptionPr; si falla, la decision pasa a reject sin detalles de token.
export async function publishDecision(decision, { apply = false, baseRepo = '', token = '', baseBranch = 'main', today, fetchImpl } = {}) {
  if (decision.action !== 'accept') return decision;

  const [org, repo] = String(baseRepo).split('/');
  const dryRun = apply !== true;
  try {
    const pr = await openExceptionPr({
      entry: decision.entry,
      yamlText: decision.yaml,
      baseBranch,
      org,
      repo,
      token,
      fetchImpl,
      dryRun,
      today,
    });
    if (dryRun) {
      return {
        ...decision,
        message: `${decision.message}\n\nModo dry-run: EXCEPTIONS_APPLY no es 'SI'. No se ha abierto ningun PR. Rama prevista: \`${pr.branch}\`.`,
        pr,
      };
    }
    return { ...decision, message: `${decision.message}\n\nPR abierto: ${pr.url}`, pr };
  } catch (err) {
    return {
      action: 'reject',
      message: `No se ha podido abrir el PR de la excepcion: ${err.message}`,
      errors: [err.message],
      yaml: decision.yaml,
    };
  }
}

async function main(env, fetchImpl = globalThis.fetch) {
  const today = env.TODAY || todayUtc();
  const decision = decideCommand({
    body: env.COMMENT_BODY ?? '',
    author: env.COMMENT_AUTHOR ?? '',
    isPullRequest: env.IS_PR === 'true',
    headRepo: env.HEAD_REPO ?? '',
    baseRepo: env.BASE_REPO ?? '',
    appsecMembers: parseMembers(env.APPSEC_MEMBERS),
    today,
  });
  const published = await publishDecision(decision, {
    apply: env.EXCEPTIONS_APPLY === 'SI',
    baseRepo: env.BASE_REPO ?? '',
    token: env.GITHUB_TOKEN ?? '',
    today,
    fetchImpl,
  });
  process.stdout.write(`${JSON.stringify(published)}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = await main(process.env);
  } catch (err) {
    console.error(`ERROR ${err.message}`);
    process.exitCode = 2;
  }
}
