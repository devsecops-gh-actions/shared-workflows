#!/usr/bin/env node
// build-exception-entry.mjs (F-c, W1). Convierte los campos de un issue de excepción en la entrada
// YAML que se añade a security/exceptions.yml. Valida el resultado con el parser compartido.
// Sin red. Sin dependencias externas (Node 20+).
//
// Uso: node build-exception-entry.mjs <campos.json> [--today AAAA-MM-DD] [--out <fichero>]
//   campos.json: objeto JSON con las claves id, scope, control, owner, reason, approved_by,
//                created, expires, ticket (strings). Las claves desconocidas se ignoran.
//                El valor "_No response_" (campo vacío en un issue de GitHub) cuenta como vacío.
//   Salida: bloque "  - id: ..." listo para ir bajo "exceptions:" en security/exceptions.yml.
//
// Códigos de salida: 0 entrada generada; 1 campos inválidos (no escribe nada); 2 uso o error interno.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkExceptions, REQUIRED } from '../../../security/scripts/lib/exceptions-parse.mjs';

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DATE_KEYS = ['created', 'expires'];

// Normaliza el objeto de entrada: solo claves obligatorias, sin espacios sobrantes ni "_No response_".
export function normalizeFields(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('la entrada debe ser un objeto JSON con los campos del issue');
  }
  const out = {};
  for (const k of REQUIRED) {
    const v = input[k];
    if (v === undefined || v === null) { out[k] = ''; continue; }
    if (typeof v !== 'string') throw new Error(`el campo ${k} debe ser texto`);
    const t = v.trim();
    out[k] = t === '_No response_' ? '' : t;
  }
  return out;
}

// Escalar YAML: fechas en plano (como en el registro), resto entre comillas dobles.
function yamlScalar(key, value) {
  if (DATE_KEYS.includes(key) && DATE_RE.test(value)) return value;
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// Devuelve { ok, errors, yaml }. Nunca escribe: el llamador decide.
export function buildEntry(input, { today }) {
  let fields;
  try {
    fields = normalizeFields(input);
  } catch (err) {
    return { ok: false, errors: [err.message], yaml: null };
  }

  const errors = [];
  for (const k of REQUIRED) {
    if (!fields[k]) errors.push(`campo vacío: ${k}`);
    else if (/[\r\n]/.test(fields[k])) errors.push(`campo ${k}: debe ocupar una sola línea`);
  }
  if (errors.length) return { ok: false, errors, yaml: null };

  const block = [
    `  - id: ${yamlScalar('id', fields.id)}`,
    ...REQUIRED.slice(1).map((k) => `    ${k}: ${yamlScalar(k, fields[k])}`),
  ].join('\n') + '\n';

  // Validación con el mismo parser que usa gen-ignores.mjs: caducidad > 90 días, formato, secretos...
  const check = checkExceptions(`exceptions:\n${block}`, { today });
  if (!check.valid) return { ok: false, errors: check.errors, yaml: null };
  if (check.expired.length) {
    return { ok: false, errors: [`la entrada ya está caducada (expires ${fields.expires}, referencia ${today})`], yaml: null };
  }
  return { ok: true, errors: [], yaml: block };
}

function parseArgs(argv) {
  const opts = { input: null, today: null, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--today' || a === '--out') {
      const v = argv[++i];
      if (!v || v.startsWith('--')) throw new Error(`${a} requiere valor`);
      opts[a.slice(2)] = v;
    } else if (a.startsWith('--')) {
      throw new Error(`opción desconocida: ${a}`);
    } else if (opts.input === null) {
      opts.input = a;
    } else {
      throw new Error(`argumento inesperado: ${a}`);
    }
  }
  if (opts.input === null) throw new Error('falta el fichero JSON de campos');
  if (opts.today !== null && !DATE_RE.test(opts.today)) throw new Error('--today debe ser AAAA-MM-DD');
  return opts;
}

function main(argv) {
  const opts = parseArgs(argv);
  const today = opts.today ?? new Date().toISOString().slice(0, 10);
  const input = JSON.parse(readFileSync(resolve(opts.input), 'utf8'));
  const res = buildEntry(input, { today });
  if (!res.ok) {
    for (const e of res.errors) console.error(`ERROR ${e}`);
    console.error('No se ha generado ninguna entrada.');
    return 1;
  }
  if (opts.out) {
    writeFileSync(resolve(opts.out), res.yaml, 'utf8');
    console.log(`OK: entrada escrita en ${resolve(opts.out)}`);
  } else {
    process.stdout.write(res.yaml);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    console.error(`ERROR ${err.message}`);
    process.exitCode = 2;
  }
}
