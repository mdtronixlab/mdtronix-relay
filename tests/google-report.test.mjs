// End-to-end test of Google Home proactive-reporting support against a local relay:
// POST /v1/ha/google-report-state. The real JWT-bearer exchange with Google isn't reachable from a
// test (no service account in this environment), so only what's testable without it is covered here:
// the tunnel-token auth guard, payload validation, and the not-configured path. The full chain (sign
// the JWT, exchange it, cache the token, Home Graph accepting a reportStateAndNotification call) is
// verified live.
// Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8793;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const ADMIN_TOKEN = 'testadmin';
const HA_PASSWORD = 'correct horse battery staple';
const cwd = fileURLToPath(new URL('..', import.meta.url));

let dev;

async function waitForHealth() {
  for (let i = 0; i < 90; i++) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('relay did not start');
}

before(async () => {
  spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'mdtronix-customers', '--local'], { cwd, shell: true, stdio: 'ignore' });
  dev = spawn(
    'npx',
    [
      'wrangler', 'dev', '--port', String(PORT), '--local',
      '--var', 'DEV_LOGIN:true',
      '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`,
      // GOOGLE_HOMEGRAPH_CLIENT_EMAIL/PRIVATE_KEY deliberately left unset, to exercise the not-configured path.
    ],
    { cwd, shell: true, stdio: 'ignore' },
  );
  await waitForHealth();
});

after(() => {
  if (!dev) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(dev.pid), '/T', '/F']);
  else dev.kill();
});

/**
 * Registers a real password account, approves it, then signs HA in directly with POST /v1/ha/login —
 * the flow the mdtronix_cloud integration itself uses.
 */
async function linkHome(email) {
  await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password: HA_PASSWORD, password_confirm: HA_PASSWORD, next: '/account' }),
    redirect: 'manual',
  });
  await fetch(`${BASE}/v1/admin/approved-emails`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, action: 'approve' }),
  });
  const res = await fetch(`${BASE}/v1/ha/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: HA_PASSWORD }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return res.json();
}

function reportState(token, body) {
  return fetch(`${BASE}/v1/ha/google-report-state`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test('report state: no bearer token is refused', async () => {
  const res = await fetch(`${BASE}/v1/ha/google-report-state`, { method: 'POST', body: '{}' });
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

test('report state: an unknown tunnel token is refused', async () => {
  const res = await reportState('not-a-real-token', { payload: {} });
  assert.equal(res.status, 401);
});

test('report state: a linked home gets not_configured until the service account secrets are set', async () => {
  const email = `google-report-${Date.now()}@example.test`;
  const { tunnel_token: token } = await linkHome(email);

  const res = await reportState(token, { payload: { devices: { states: {} } } });
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { error: 'not_configured' });
});

test('report state: a malformed or missing payload is refused before any Google call', async () => {
  const email = `google-report-bad-${Date.now()}@example.test`;
  const { tunnel_token: token } = await linkHome(email);

  const missingPayload = await reportState(token, { requestId: 'x' });
  assert.equal(missingPayload.status, 400);
  assert.deepEqual(await missingPayload.json(), { error: 'invalid_request' });

  const notJson = await fetch(`${BASE}/v1/ha/google-report-state`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: 'not json',
  });
  assert.equal(notJson.status, 400);

  // Even with a valid payload shape, this still can't reach Google without the service account secrets —
  // confirms validation happens first, not just that the whole path 503s regardless of the body.
  const validShape = await reportState(token, { payload: { devices: { states: {} } } });
  assert.equal(validShape.status, 503);
});
