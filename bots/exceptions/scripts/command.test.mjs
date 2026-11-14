// Pruebas de command.mjs (F-c, W2). Sin red.
// Ejecutar: node --test bots/exceptions/scripts/command.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCommand, parseMembers, isAuthorized, decideCommand } from './command.mjs';

const TODAY = '2026-11-14';
const APPSEC = parseMembers('ana.lopez, @luis.perez\nappsec-lead');
const REPO = 'acme/api';

const cmd = (over = {}) => {
  const f = {
    id: 'CVE-2026-7777',
    scope: 'acme/api',
    control: 'dependencies',
    owner: 'ana.lopez',
    reason: 'Mitigado con WAF; actualizacion planificada',
    approved_by: 'appsec-lead',
    created: '2026-11-14',
    expires: '2027-02-12',
    ticket: 'JIRA-9001',
    ...over,
  };
  const lines = Object.entries(f).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}: ${v}`);
  return ['/security-exception', ...lines].join('\n');
};

const decide = (over = {}) => decideCommand({
  body: cmd(),
  author: 'ana.lopez',
  isPullRequest: true,
  headRepo: REPO,
  baseRepo: REPO,
  appsecMembers: APPSEC,
  today: TODAY,
  ...over,
});

// ---------- Comando valido ----------

test('comando valido de 90 dias: accept con entrada YAML', () => {
  const d = decide();
  assert.equal(d.action, 'accept');
  assert.deepEqual(d.errors, []);
  assert.match(d.yaml, /^ {2}- id: "CVE-2026-7777"/);
  assert.match(d.yaml, /expires: 2027-02-12/);
  assert.match(d.message, /Excepcion valida/);
});

test('comentario que no es el comando: ignore', () => {
  assert.equal(decide({ body: 'hola, /security-exception no es esto' }).action, 'ignore');
  assert.equal(decide({ body: '/security-exceptions\nid: x' }).action, 'ignore');
});

// ---------- Caducidad ----------

test('caducidad de 91 dias: reject con motivo claro', () => {
  const d = decide({ body: cmd({ expires: '2027-02-13' }) });
  assert.equal(d.action, 'reject');
  assert.ok(d.errors.some((e) => /caducidad de 91 d[ií]as; m[áa]ximo 90/.test(e)), d.errors.join(' | '));
  assert.equal(d.yaml, null);
});

test('entrada ya caducada: reject', () => {
  const d = decide({ body: cmd({ created: '2026-01-01', expires: '2026-03-01' }) });
  assert.equal(d.action, 'reject');
});

// ---------- Campos ----------

test('campo obligatorio vacio: reject', () => {
  const d = decide({ body: cmd({ ticket: '' }) });
  assert.equal(d.action, 'reject');
  assert.ok(d.errors.some((e) => e.includes('campo vacío: ticket')), d.errors.join(' | '));
});

test('campo que falta del todo: reject', () => {
  const body = cmd().split('\n').filter((l) => !l.startsWith('ticket:')).join('\n');
  const d = decide({ body });
  assert.equal(d.action, 'reject');
  assert.ok(d.errors.some((e) => e.includes('ticket')));
});

test('campo desconocido y duplicado: reject', () => {
  const d1 = decide({ body: cmd() + '\nextra: x' });
  assert.equal(d1.action, 'reject');
  assert.ok(d1.errors.some((e) => e.includes('campo desconocido: extra')));
  const d2 = decide({ body: cmd() + '\nticket: OTRO-1' });
  assert.equal(d2.action, 'reject');
  assert.ok(d2.errors.some((e) => e.includes('campo duplicado: ticket')));
});

test('linea sin formato clave: valor: reject', () => {
  const d = decide({ body: cmd() + '\nesto no es un campo' });
  assert.equal(d.action, 'reject');
});

// ---------- Autor ----------

test('autor que no es de AppSec: reject', () => {
  const d = decide({ author: 'mallory' });
  assert.equal(d.action, 'reject');
  assert.match(d.message, /@mallory no esta en el equipo de AppSec/);
  assert.equal(d.yaml, null);
});

test('lista de AppSec vacia: reject (fail closed)', () => {
  const d = decide({ appsecMembers: [] });
  assert.equal(d.action, 'reject');
  assert.match(d.message, /APPSEC_MEMBERS/);
});

test('isAuthorized: sin autor, sin lista o autor vacio no autoriza; mayusculas no importan', () => {
  assert.equal(isAuthorized('', APPSEC), false);
  assert.equal(isAuthorized('ana.lopez', []), false);
  assert.equal(isAuthorized('ANA.LOPEZ', APPSEC), true);
  assert.equal(isAuthorized('ana', APPSEC), false);
});

test('parseMembers: separadores mixtos, sin arroba, sin duplicados', () => {
  assert.deepEqual(parseMembers('@A, b  a\nC'), ['a', 'b', 'c']);
  assert.deepEqual(parseMembers(undefined), []);
});

// ---------- Origen del PR (condicion de fork que decide el workflow) ----------

test('comentario en PR desde fork: reject, sin procesar', () => {
  const d = decide({ headRepo: 'mallory/api' });
  assert.equal(d.action, 'reject');
  assert.match(d.message, /fork/);
  assert.equal(d.yaml, null);
});

test('head desconocido (repo borrado, valor vacio) se trata como fork', () => {
  assert.equal(decide({ headRepo: '' }).action, 'reject');
  assert.equal(decide({ headRepo: undefined }).action, 'reject');
});

test('mismo repo sin distinguir mayusculas: accept', () => {
  assert.equal(decide({ headRepo: 'ACME/api' }).action, 'accept');
});

test('comentario en un issue normal (no PR): reject', () => {
  const d = decide({ isPullRequest: false });
  assert.equal(d.action, 'reject');
  assert.match(d.message, /pull request/);
});

// ---------- Parser ----------

test('parseCommand: el comando debe ir solo en su linea', () => {
  const p = parseCommand('/security-exception id: x\nscope: a/b');
  assert.equal(p.isCommand, true);
  assert.ok(p.errors.some((e) => e.includes('solo en su linea')));
});

test('parseCommand: claves en mayusculas o con espacios no son campos validos', () => {
  const p = parseCommand('/security-exception\nID: x');
  assert.ok(p.errors.length > 0);
});
