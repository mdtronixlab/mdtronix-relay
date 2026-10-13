// End-to-end test of Google Home proactive-reporting support against a local relay:
// GET /v1/ha/google-report-token. The real JWT-bearer exchange with Google isn't reachable from a
// test (no service account in this environment), so only what's testable without it is covered here:
// the tunnel-token auth guard and the not-configured path. The full chain (sign the JWT, exchange it,
// cache the token, Home Graph accepting a reportStateAndNotification call) is verified live.
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

async function login(email) {
  const r = await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });
  const cookie = r.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session='));
  assert.ok(cookie, 'dev login set a session cookie');
  return cookie.split(';')[0];
}

/**
 * Claims a password on the (already dev-logged-in) account, approves it, then signs HA in directly
 * with POST /v1/ha/login — the flow the mdtronix_cloud integration itself uses.
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

test('report token: no bearer token is refused', async () => {
  const res = await fetch(`${BASE}/v1/ha/google-report-token`);
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

test('report token: an unknown tunnel token is refused', async () => {
  const res = await fetch(`${BASE}/v1/ha/google-report-token`, { headers: { authorization: 'Bearer not-a-real-token' } });
  assert.equal(res.status, 401);
});

test('report token: a linked home gets not_configured until the service account secrets are set', async () => {
  const email = `google-report-${Date.now()}@example.test`;
  await login(email);
  const { tunnel_token: token } = await linkHome(email);

  const res = await fetch(`${BASE}/v1/ha/google-report-token`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { error: 'not_configured' });
});
