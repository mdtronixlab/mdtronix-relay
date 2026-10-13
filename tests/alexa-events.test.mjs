// End-to-end test of Alexa proactive-reporting support against a local relay: the AcceptGrant
// directive (POST /v1/voice/alexa) and GET /v1/ha/alexa-report-token. The actual LWA exchange with
// Amazon isn't mocked (no such mocking exists in this test suite), so only what's reachable without
// it is covered here; the full chain (AcceptGrant -> stored grant -> refreshed token -> a real
// ChangeReport accepted by Alexa's Event Gateway) was verified live. Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8794;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const ALEXA = {
  clientId: 'alexa-test-client',
  clientSecret: 'alexa-test-secret',
  redirect: 'https://pitangui.amazon.com/api/skill/link/M23Q7Y64C1HJD4',
};
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
      '--var', `ALEXA_CLIENT_ID:${ALEXA.clientId}`,
      '--var', `ALEXA_CLIENT_SECRET:${ALEXA.clientSecret}`,
      '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`,
      // ALEXA_LWA_CLIENT_ID/SECRET deliberately left unset, to exercise the not-configured path.
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
 * Registers a real password account, approves it, and signs it in both as a browser session (for Alexa
 * account-linking consent) and directly via HA login (POST /v1/ha/login) — the same account for both.
 * /register no longer claims an existing passwordless row (that was an account-takeover path), so this
 * always creates a fresh account rather than relying on a prior dev login.
 */
async function registerAndLink(email) {
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
  const loginRes = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password: HA_PASSWORD, next: '/account' }),
    redirect: 'manual',
  });
  const cookie = loginRes.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session='));
  assert.ok(cookie, 'password login set a session cookie');

  const haRes = await fetch(`${BASE}/v1/ha/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: HA_PASSWORD }),
  });
  assert.equal(haRes.status, 200, await haRes.clone().text());
  return { cookie: cookie.split(';')[0], link: await haRes.json() };
}

/** Runs the Alexa account-linking consent and returns an OAuth access token, the way Alexa holds one. */
async function alexaAccessToken(cookie) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: ALEXA.clientId,
    redirect_uri: ALEXA.redirect,
    response_type: 'code',
    state: 'state-proactive',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const form = new URLSearchParams(params);
  form.set('decision', 'allow');
  const consent = await fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
    redirect: 'manual',
  });
  assert.equal(consent.status, 302);
  const code = new URL(consent.headers.get('location')).searchParams.get('code');

  const exchange = await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: ALEXA.redirect, code_verifier: verifier,
      client_id: ALEXA.clientId, client_secret: ALEXA.clientSecret,
    }),
  });
  assert.equal(exchange.status, 200, await exchange.clone().text());
  return (await exchange.json()).access_token;
}

function acceptGrant(messageId, code, granteeToken) {
  return {
    directive: {
      header: { namespace: 'Alexa.Authorization', name: 'AcceptGrant', messageId, payloadVersion: '3' },
      payload: { grant: { type: 'OAuth2.AuthorizationCode', code }, grantee: { type: 'BearerToken', token: granteeToken } },
    },
  };
}

test('report token: no bearer token is refused', async () => {
  const res = await fetch(`${BASE}/v1/ha/alexa-report-token`);
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

test('report token: an unknown tunnel token is refused', async () => {
  const res = await fetch(`${BASE}/v1/ha/alexa-report-token`, { headers: { authorization: 'Bearer not-a-real-token' } });
  assert.equal(res.status, 401);
});

test('report token: a linked home with no AcceptGrant yet gets no_proactive_grant', async () => {
  const email = `alexa-events-${Date.now()}@example.test`;
  const { link } = await registerAndLink(email);
  const token = link.tunnel_token;

  const res = await fetch(`${BASE}/v1/ha/alexa-report-token`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'no_proactive_grant' });
});

test('accept grant: a malformed directive is refused without touching the database', async () => {
  const res = await fetch(`${BASE}/v1/voice/alexa`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(acceptGrant('m1', undefined, undefined)),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.event.header.name, 'ErrorResponse');
  assert.equal(body.event.header.namespace, 'Alexa.Authorization');
  assert.equal(body.event.payload.type, 'ACCEPT_GRANT_FAILED');
});

test('accept grant: an unrecognized grantee token is refused', async () => {
  const res = await fetch(`${BASE}/v1/voice/alexa`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(acceptGrant('m2', 'some-code', 'not-a-real-access-token')),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.event.header.name, 'ErrorResponse');
});

test('accept grant: a real account link resolves, then fails without LWA credentials configured', async () => {
  const email = `alexa-events-grant-${Date.now()}@example.test`;
  const { cookie } = await registerAndLink(email);
  const token = await alexaAccessToken(cookie);

  const res = await fetch(`${BASE}/v1/voice/alexa`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(acceptGrant('m3', 'some-grant-code', token)),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  // Reaches the "exchange with Amazon" step (so the grantee token resolved to a real customer),
  // but this test relay has no LWA client id/secret configured.
  assert.equal(body.event.header.name, 'ErrorResponse');
  assert.match(body.event.payload.message, /not configured/);
});
