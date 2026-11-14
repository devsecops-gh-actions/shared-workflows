// Parser y validador ÚNICO del registro security/exceptions.yml (F-c, W1).
// Lo usan security/scripts/gen-ignores.mjs y bots/exceptions/. Sin dependencias externas (Node 20+).
//
// API principal: checkExceptions(text, { today }) -> { valid, errors, expired, accepted }
//   - valid:    false si hay errores de sintaxis o de validación (bloquea la generación).
//   - errors:   mensajes "línea N (id): motivo".
//   - expired:  entradas válidas pero caducadas (se excluyen y deben avisarse).
//   - accepted: entradas válidas y vigentes (con sus campos y línea).
//
// Subconjunto YAML soportado (ver security/exceptions.yml): clave raíz `exceptions` (lista vacía
// `[]` o bloque), items `- clave: valor` y campos con 4 espacios; escalares planos, cadenas entre
// comillas dobles o simples y comentarios `#`. Cualquier otra construcción se rechaza.

export const MAX_DAYS = 90;
export const CONTROLS = ['secrets', 'codeql', 'dependencies', 'containers', 'iac'];
export const REQUIRED = ['id', 'scope', 'control', 'owner', 'reason', 'approved_by', 'created', 'expires', 'ticket'];

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
// scope: owner/repo (o varios separados por coma). Sin comodines: "todos", "*" o "all" no son válidos.
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86400000;

// Formatos de credenciales conocidas. Un valor que los contiene no puede ser una excepción:
// el registro no debe guardar secretos. Se comprueba en todos los campos de texto.
const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/, 'clave de acceso AWS'],
  [/gh[pousr]_[A-Za-z0-9]{20,}/, 'token de GitHub'],
  [/github_pat_[A-Za-z0-9_]{20,}/, 'token de GitHub'],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/, 'token de Slack'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'clave privada'],
];

export class ParseError extends Error {}

function fail(lineNo, msg) {
  throw new ParseError(`línea ${lineNo}: ${msg}`);
}

// Quita el comentario final de una línea respetando las cadenas entrecomilladas.
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (quote === '"' && c === '\\') { i++; continue; }
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseScalar(raw, lineNo) {
  const v = raw.trim();
  if (v === '') return '';
  if (v[0] === '"') {
    const m = /^"((?:[^"\\]|\\.)*)"$/.exec(v);
    if (!m) fail(lineNo, 'cadena con comillas dobles mal formada');
    return m[1].replace(/\\(["\\])/g, '$1');
  }
  if (v[0] === "'") {
    const m = /^'((?:[^']|'')*)'$/.exec(v);
    if (!m) fail(lineNo, 'cadena con comillas simples mal formada');
    return m[1].replace(/''/g, "'");
  }
  if (/^[[\]{}&*!|>%@`]/.test(v)) fail(lineNo, `construcción YAML no soportada: ${v}`);
  return v;
}

// Parser del subconjunto descrito arriba. Lanza ParseError ante cualquier duda.
export function parseExceptions(text) {
  const entries = [];
  let sawRoot = false;
  let inlineEmpty = false;
  let current = null;

  const setField = (lineNo, key, rawValue) => {
    if (!REQUIRED.includes(key)) fail(lineNo, `campo desconocido: ${key}`);
    if (key in current.fields) fail(lineNo, `campo duplicado: ${key}`);
    current.fields[key] = parseScalar(rawValue ?? '', lineNo);
  };

  text.split(/\r?\n/).forEach((rawLine, idx) => {
    const lineNo = idx + 1;
    if (rawLine.includes('\t')) fail(lineNo, 'tabulaciones no soportadas');
    const line = stripComment(rawLine).replace(/\s+$/, '');
    if (line.trim() === '') return;
    const indent = line.length - line.trimStart().length;
    const body = line.trim();

    if (indent === 0) {
      if (sawRoot) fail(lineNo, 'solo se admite la clave raíz "exceptions"');
      const m = /^exceptions:\s*(\[\s*\])?$/.exec(body);
      if (!m) fail(lineNo, 'se esperaba "exceptions:" como clave raíz');
      sawRoot = true;
      inlineEmpty = Boolean(m[1]);
      return;
    }
    if (!sawRoot || inlineEmpty) fail(lineNo, 'contenido inesperado');

    if (indent === 2 && body.startsWith('-')) {
      const m = /^- (\w+):(?:\s+(.*))?$/.exec(body);
      if (!m) fail(lineNo, 'entrada de lista inválida');
      current = { line: lineNo, fields: {} };
      entries.push(current);
      setField(lineNo, m[1], m[2]);
    } else if (indent === 4 && current) {
      const m = /^(\w+):(?:\s+(.*))?$/.exec(body);
      if (!m) fail(lineNo, 'línea de campo inválida');
      setField(lineNo, m[1], m[2]);
    } else {
      fail(lineNo, 'indentación no soportada');
    }
  });

  if (!sawRoot) throw new ParseError('falta la clave raíz "exceptions"');
  return entries;
}

function toDayMs(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return NaN;
  const t = Date.parse(`${s}T00:00:00Z`);
  return new Date(t).toISOString().slice(0, 10) === s ? t : NaN;
}

// Valida entradas ya parseadas. today: AAAA-MM-DD.
export function validate(entries, today) {
  const todayMs = toDayMs(today);
  if (Number.isNaN(todayMs)) throw new Error(`fecha de referencia no válida: ${today}`);
  const accepted = [];
  const expired = [];
  const errors = [];

  for (const e of entries) {
    const f = e.fields;
    const problems = [];
    for (const k of REQUIRED) if (!f[k]) problems.push(`falta ${k}`);
    if (f.id && !ID_RE.test(f.id)) problems.push(`id no válido: ${f.id}`);
    if (f.control && !CONTROLS.includes(f.control)) problems.push(`control no válido: ${f.control}`);
    if (f.scope) {
      const repos = f.scope.split(',').map((s) => s.trim());
      if (!repos.every((r) => REPO_RE.test(r))) {
        problems.push(`scope no válido: ${f.scope} (owner/repo, sin comodines)`);
      }
    }
    for (const k of REQUIRED) {
      const hit = SECRET_PATTERNS.find(([re]) => f[k] && re.test(f[k]));
      if (hit) problems.push(`${k} parece contener un secreto (${hit[1]}); no se guarda en el registro`);
    }

    const created = toDayMs(f.created);
    const expires = toDayMs(f.expires);
    if (f.created && Number.isNaN(created)) problems.push(`created no es AAAA-MM-DD: ${f.created}`);
    if (f.expires && Number.isNaN(expires)) problems.push(`expires no es AAAA-MM-DD: ${f.expires}`);
    if (!Number.isNaN(created) && !Number.isNaN(expires)) {
      const days = Math.round((expires - created) / DAY_MS);
      if (days < 0) problems.push('expires anterior a created');
      else if (days > MAX_DAYS) problems.push(`caducidad de ${days} días; máximo ${MAX_DAYS}`);
    }

    const where = `línea ${e.line} (${f.id || 'sin id'})`;
    if (problems.length) {
      errors.push(`${where}: ${problems.join('; ')}`);
    } else if (expires < todayMs) {
      expired.push(`${where}: caducó el ${f.expires}`);
    } else {
      accepted.push({ ...f, line: e.line });
    }
  }
  return { accepted, expired, errors };
}

// Función única de parseo + validación. No lanza por datos del registro: los devuelve en errors.
export function checkExceptions(text, { today }) {
  let entries;
  try {
    entries = parseExceptions(text);
  } catch (err) {
    if (err instanceof ParseError) return { valid: false, errors: [err.message], expired: [], accepted: [] };
    throw err;
  }
  const { accepted, expired, errors } = validate(entries, today);
  return { valid: errors.length === 0, errors, expired, accepted };
}
