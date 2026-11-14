// Pruebas del parser compartido y de build-exception-entry.mjs.
// Ejecutar: node --test bots/exceptions/scripts/exceptions.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { checkExceptions, parseExceptions, MAX_DAYS } from '../../../security/scripts/lib/exceptions-parse.mjs';
import { buildEntry, normalizeFields } from './build-exception-entry.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const FIX = join(here, '..', 'fixtures');
const SCRIPT = join(here, 'build-exception-entry.mjs');
const TODAY = '2026-11-13';
const fixtureJson = (name) => JSON.parse(readFileSync(join(FIX, name), 'utf8'));

const base = {
  id: 'CVE-2026-7777',
  scope: 'acme/api',
  control: 'dependencies',
  owner: 'ana.lopez',
  reason: 'Motivo de prueba',
  approved_by: 'appsec-lead',
  created: '2026-11-13',
  expires: '2027-02-11',
  ticket: 'JIRA-9001',
};
const entryText = (over = {}) => {
  const f = { ...base, ...over };
  return `exceptions:\n  - id: "${f.id}"\n` +
    ['scope', 'control', 'owner', 'reason', 'approved_by', 'created', 'expires', 'ticket']
      .map((k) => `    ${k}: ${/^\d{4}-/.test(f[k]) ? f[k] : `"${f[k]}"`}`).join('\n') + '\n';
};

// ---------- Parser y validador compartidos ----------

test('checkExceptions acepta una entrada válida de 90 días exactos', () => {
  const r = checkExceptions(entryText(), { today: TODAY });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.equal(r.accepted.length, 1);
  assert.equal(MAX_DAYS, 90);
});

test('checkExceptions rechaza 91 días', () => {
  const r = checkExceptions(entryText({ expires: '2027-02-12' }), { today: TODAY });
  assert.equal(r.valid, false);
  assert.match(r.errors[0], /caducidad de 91 días; máximo 90/);
});

test('checkExceptions devuelve expired (sin error) para entradas caducadas', () => {
  const r = checkExceptions(entryText({ created: '2026-01-01', expires: '2026-03-01' }), { today: TODAY });
  assert.equal(r.valid, true);
  assert.equal(r.accepted.length, 0);
  assert.equal(r.expired.length, 1);
});

test('checkExceptions rechaza campos obligatorios vacíos', () => {
  const r = checkExceptions(entryText({ owner: '' }), { today: TODAY });
  assert.equal(r.valid, false);
  assert.match(r.errors[0], /falta owner/);
});

test('checkExceptions rechaza scope con comodín o formato no owner/repo', () => {
  for (const scope of ['*', 'todos', 'all', 'acme']) {
    const r = checkExceptions(entryText({ scope }), { today: TODAY });
    assert.equal(r.valid, false, `scope ${scope} debería rechazarse`);
    assert.match(r.errors[0], /scope no válido/);
  }
});

test('checkExceptions acepta varios repos en scope separados por coma', () => {
  const r = checkExceptions(entryText({ scope: 'acme/api, acme/web' }), { today: TODAY });
  assert.equal(r.valid, true);
});

test('checkExceptions rechaza credenciales pegadas en campos de texto', () => {
  const r = checkExceptions(entryText({ reason: 'token AKIAABCDEFGHIJKLMNOP' }), { today: TODAY });
  assert.equal(r.valid, false);
  assert.match(r.errors[0], /parece contener un secreto/);
});

test('checkExceptions rechaza sintaxis fuera del subconjunto sin lanzar', () => {
  const r = checkExceptions('exceptions: [{id: x}]\n', { today: TODAY });
  assert.equal(r.valid, false);
  assert.equal(r.errors.length, 1);
});

test('parseExceptions sigue lanzando ante sintaxis no soportada', () => {
  assert.throws(() => parseExceptions('exceptions:\n\t- id: CVE-1\n'), /tabulaciones/);
});

// ---------- build-exception-entry ----------

test('buildEntry genera un bloque que el parser compartido acepta', () => {
  const r = buildEntry(fixtureJson('valid.json'), { today: TODAY });
  assert.equal(r.ok, true, r.errors.join('; '));
  const check = checkExceptions(`exceptions:\n${r.yaml}`, { today: TODAY });
  assert.equal(check.valid, true);
  assert.equal(check.accepted[0].id, 'CVE-2026-4444');
  assert.equal(check.accepted[0].expires, '2027-02-11');
});

test('buildEntry rechaza caducidad de 91 días', () => {
  const r = buildEntry(fixtureJson('too-long.json'), { today: TODAY });
  assert.equal(r.ok, false);
  assert.equal(r.yaml, null);
  assert.match(r.errors[0], /caducidad de 91 días; máximo 90/);
});

test('buildEntry rechaza una entrada ya caducada', () => {
  const r = buildEntry(fixtureJson('expired.json'), { today: TODAY });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /ya está caducada/);
});

test('buildEntry rechaza campos vacíos y trata "_No response_" como vacío', () => {
  const r = buildEntry({ ...fixtureJson('valid.json'), reason: '   ', ticket: '_No response_' }, { today: TODAY });
  assert.equal(r.ok, false);
  assert.ok(r.errors.includes('campo vacío: reason'));
  assert.ok(r.errors.includes('campo vacío: ticket'));
});

test('buildEntry rechaza campos ausentes', () => {
  const { ticket, ...rest } = fixtureJson('valid.json');
  const r = buildEntry(rest, { today: TODAY });
  assert.equal(r.ok, false);
  assert.ok(r.errors.includes('campo vacío: ticket'));
});

test('buildEntry escapa comillas y barras en los valores', () => {
  const r = buildEntry({ ...fixtureJson('valid.json'), reason: 'Mitigado con "WAF" \\ regla 7' }, { today: TODAY });
  assert.equal(r.ok, true, r.errors.join('; '));
  const check = checkExceptions(`exceptions:\n${r.yaml}`, { today: TODAY });
  assert.equal(check.accepted[0].reason, 'Mitigado con "WAF" \\ regla 7');
});

test('buildEntry rechaza valores con saltos de línea', () => {
  const r = buildEntry({ ...fixtureJson('valid.json'), reason: 'línea 1\nlínea 2' }, { today: TODAY });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /una sola línea/);
});

test('normalizeFields exige un objeto', () => {
  assert.throws(() => normalizeFields(['x']), /objeto JSON/);
});

test('CLI: genera la entrada en stdout con código 0', () => {
  const r = spawnSync(process.execPath, [SCRIPT, join(FIX, 'valid.json'), '--today', TODAY], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^  - id: "CVE-2026-4444"$/m);
});

test('CLI: con --out escribe el fichero', () => {
  const out = join(mkdtempSync(join(tmpdir(), 'exc-entry-')), 'entry.yml');
  const r = spawnSync(process.execPath, [SCRIPT, join(FIX, 'valid.json'), '--today', TODAY, '--out', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(out));
});

test('CLI: caducidad excesiva sale con código 1 y no escribe', () => {
  const out = join(mkdtempSync(join(tmpdir(), 'exc-entry-')), 'entry.yml');
  const r = spawnSync(process.execPath, [SCRIPT, join(FIX, 'too-long.json'), '--today', TODAY, '--out', out], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /ERROR/);
  assert.equal(existsSync(out), false);
});

test('CLI: sin argumentos sale con código 2', () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
  assert.equal(r.status, 2);
});
