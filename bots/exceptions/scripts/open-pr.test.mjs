// Pruebas de open-pr.mjs (F-c, W1). Sin red: fetch simulado.
// Ejecutar: node --test bots/exceptions/scripts/open-pr.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openExceptionPr, sanitizeId } from './open-pr.mjs';
import { publishDecision } from './command.mjs';

const TODAY = '2026-11-14';
const ORG = 'acme';
const REPO = 'platform';
const TOKEN = 'ghp_TESTTOKEN_0123456789abcdefghij';

const entry = {
  id: 'CVE-2026-7777',
  scope: 'acme/api',
  control: 'dependencies',
  owner: 'ana.lopez',
  reason: 'Mitigado con WAF; actualizacion planificada',
  approved_by: 'appsec-lead',
  created: '2026-11-14',
  expires: '2027-02-12',
  ticket: 'JIRA-9001',
};

const yamlText = [
  '  - id: "CVE-2026-7777"',
  '    scope: "acme/api"',
  '    control: "dependencies"',
  '    owner: "ana.lopez"',
  '    reason: "Mitigado con WAF; actualizacion planificada"',
  '    approved_by: "appsec-lead"',
  '    created: 2026-11-14',
  '    expires: 2027-02-12',
  '    ticket: "JIRA-9001"',
  '',
].join('\n');

const REGISTRY_EMPTY = [
  '# Registro de excepciones de seguridad (WS3).',
  '# Ejemplo (comentado, no activo):',
  '# exceptions:',
  '',
  'exceptions: []',
  '',
].join('\n');

const REGISTRY_WITH_ID = [
  'exceptions:',
  '  - id: "CVE-2026-7777"',
  '    scope: "acme/api"',
  '    control: "dependencies"',
  '    owner: "ana.lopez"',
  '    reason: "ya existente"',
  '    approved_by: "appsec-lead"',
  '    created: 2026-11-10',
  '    expires: 2027-02-08',
  '    ticket: "JIRA-1"',
  '',
].join('\n');

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

// fetch simulado: responde por "METODO ruta" y registra cada llamada.
function fakeFetch(routes = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const path = url.replace('https://api.github.com', '');
    const method = init.method ?? 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body });
    const key = `${method} ${path.split('?')[0]}`;
    const route = routes[key] ?? routes[`${method} *`];
    const { status = 200, data = {} } = typeof route === 'function' ? route({ method, path, body }) : (route ?? {});
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => data,
    };
  };
  return { fetchImpl, calls };
}

const happyRoutes = (registry = REGISTRY_EMPTY) => ({
  [`GET /repos/${ORG}/${REPO}/git/ref/heads/main`]: { data: { object: { sha: 'basesha123' } } },
  [`GET /repos/${ORG}/${REPO}/contents/security/exceptions.yml`]: {
    data: { content: b64(registry).replace(/(.{20})/g, '$1\n'), sha: 'blobsha456' },
  },
  [`POST /repos/${ORG}/${REPO}/git/refs`]: { status: 201, data: { ref: 'refs/heads/x' } },
  [`PUT /repos/${ORG}/${REPO}/contents/security/exceptions.yml`]: { status: 200, data: { commit: { sha: 'c1' } } },
  [`POST /repos/${ORG}/${REPO}/pulls`]: {
    status: 201,
    data: { number: 42, html_url: `https://github.com/${ORG}/${REPO}/pull/42` },
  },
});

const base = { entry, yamlText, baseBranch: 'main', org: ORG, repo: REPO, token: TOKEN, today: TODAY };

test('dry-run: devuelve el plan sin llamar a red', async () => {
  const { fetchImpl, calls } = fakeFetch();
  const plan = await openExceptionPr({ ...base, fetchImpl });
  assert.equal(calls.length, 0);
  assert.equal(plan.dryRun, true);
  assert.equal(plan.branch, 'bot/exceptions/cve-2026-7777-2026-11-14');
  assert.equal(plan.path, 'security/exceptions.yml');
  assert.match(plan.title, /CVE-2026-7777/);
  assert.match(plan.body, /no fusiona/);
});

test('dry-run por defecto aunque no haya token', async () => {
  const { fetchImpl, calls } = fakeFetch();
  const plan = await openExceptionPr({ ...base, token: '', fetchImpl });
  assert.equal(plan.dryRun, true);
  assert.equal(calls.length, 0);
});

test('creacion correcta: secuencia de llamadas y PUT con la entrada añadida', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes());
  const res = await openExceptionPr({ ...base, dryRun: false, fetchImpl });

  assert.deepEqual(
    calls.map((c) => `${c.method} ${c.path.split('?')[0]}`),
    [
      `GET /repos/${ORG}/${REPO}/git/ref/heads/main`,
      `GET /repos/${ORG}/${REPO}/contents/security/exceptions.yml`,
      `POST /repos/${ORG}/${REPO}/git/refs`,
      `PUT /repos/${ORG}/${REPO}/contents/security/exceptions.yml`,
      `POST /repos/${ORG}/${REPO}/pulls`,
    ],
  );

  const refCall = calls[2].body;
  assert.equal(refCall.ref, 'refs/heads/bot/exceptions/cve-2026-7777-2026-11-14');
  assert.equal(refCall.sha, 'basesha123');

  const putCall = calls[3].body;
  assert.equal(putCall.branch, 'bot/exceptions/cve-2026-7777-2026-11-14');
  assert.equal(putCall.sha, 'blobsha456');
  const written = Buffer.from(putCall.content, 'base64').toString('utf8');
  assert.doesNotMatch(written, /^exceptions: \[\]$/m);
  assert.match(written, /^exceptions:\n {2}- id: "CVE-2026-7777"/m);
  assert.match(written, /^# Registro de excepciones/m, 'conserva la cabecera del registro');

  const prCall = calls[4].body;
  assert.equal(prCall.head, 'bot/exceptions/cve-2026-7777-2026-11-14');
  assert.equal(prCall.base, 'main');

  assert.equal(res.dryRun, false);
  assert.equal(res.number, 42);
  assert.equal(res.url, `https://github.com/${ORG}/${REPO}/pull/42`);
});

test('creacion correcta: añade al final si la lista ya tiene entradas', async () => {
  const registry = REGISTRY_WITH_ID.replace('CVE-2026-7777', 'CVE-2026-1111');
  const { fetchImpl, calls } = fakeFetch(happyRoutes(registry));
  await openExceptionPr({ ...base, dryRun: false, fetchImpl });
  const written = Buffer.from(calls[3].body.content, 'base64').toString('utf8');
  assert.match(written, /CVE-2026-1111/);
  assert.match(written, /CVE-2026-7777/);
});

test('id duplicado: rechazado sin escribir (sin POST ni PUT)', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes(REGISTRY_WITH_ID));
  await assert.rejects(
    openExceptionPr({ ...base, dryRun: false, fetchImpl }),
    /ya existe/,
  );
  const writes = calls.filter((c) => c.method !== 'GET');
  assert.equal(writes.length, 0);
});

test('rama fuera de bot/exceptions/: rechazada en dry-run y en real, sin red', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes());
  await assert.rejects(openExceptionPr({ ...base, branch: 'feature/x', fetchImpl }), /bot\/exceptions\//);
  await assert.rejects(openExceptionPr({ ...base, branch: 'main', dryRun: false, fetchImpl }), /bot\/exceptions\//);
  await assert.rejects(
    openExceptionPr({ ...base, branch: 'bot/exceptions/../../main', dryRun: false, fetchImpl }),
    /no válido/,
  );
  assert.equal(calls.length, 0);
});

test('token ausente: rechazado en la ejecucion real, sin llamadas', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes());
  await assert.rejects(
    openExceptionPr({ ...base, token: '', dryRun: false, fetchImpl }),
    /falta el token/,
  );
  await assert.rejects(
    openExceptionPr({ ...base, token: undefined, dryRun: false, fetchImpl }),
    /falta el token/,
  );
  assert.equal(calls.length, 0);
});

test('el token no aparece en la salida ni en los errores', async () => {
  const ok = fakeFetch(happyRoutes());
  const res = await openExceptionPr({ ...base, dryRun: false, fetchImpl: ok.fetchImpl });
  assert.equal(JSON.stringify(res).includes(TOKEN), false);

  const failing = fakeFetch({
    ...happyRoutes(),
    [`POST /repos/${ORG}/${REPO}/git/refs`]: { status: 422, data: { message: 'Reference already exists' } },
  });
  await assert.rejects(openExceptionPr({ ...base, dryRun: false, fetchImpl: failing.fetchImpl }), (err) => {
    assert.match(err.message, /422/);
    assert.equal(err.message.includes(TOKEN), false);
    return true;
  });
});

test('entrada no válida (caducidad de 91 días): rechazada en dry-run, sin red', async () => {
  const { fetchImpl, calls } = fakeFetch();
  const bad = yamlText.replace('expires: 2027-02-12', 'expires: 2027-02-13');
  await assert.rejects(openExceptionPr({ ...base, yamlText: bad, fetchImpl }), /máximo 90/);
  assert.equal(calls.length, 0);
});

test('sanitizeId normaliza el id para la rama', () => {
  assert.equal(sanitizeId('CVE-2026-7777'), 'cve-2026-7777');
  assert.equal(sanitizeId('  CKV_AWS/18 '), 'ckv-aws-18');
  assert.equal(sanitizeId('***'), '');
});

test('publishDecision sin EXCEPTIONS_APPLY=SI: dry-run, sin red, indicado en el mensaje', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes());
  const decision = {
    action: 'accept',
    message: 'Excepcion valida',
    errors: [],
    yaml: yamlText,
    entry,
  };
  const out = await publishDecision(decision, { apply: false, baseRepo: `${ORG}/${REPO}`, token: TOKEN, today: TODAY, fetchImpl });
  assert.equal(calls.length, 0);
  assert.equal(out.action, 'accept');
  assert.match(out.message, /dry-run/);
  assert.equal(out.pr.dryRun, true);
});

test('publishDecision con apply y decision reject: no toca nada', async () => {
  const { fetchImpl, calls } = fakeFetch(happyRoutes());
  const out = await publishDecision({ action: 'reject', message: 'no', errors: ['x'], yaml: null }, { apply: true, fetchImpl });
  assert.equal(out.action, 'reject');
  assert.equal(calls.length, 0);
});
