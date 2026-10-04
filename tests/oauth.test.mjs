// End-to-end test of voice account linking against a local relay: consent, code exchange with PKCE,
// refresh, revoke, and the failure cases. Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8792;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const CLIENT_ID = 'google-test-client';
const CLIENT_SECRET = 'google-test-secret';
const REDIRECT = 'https://oauth-redirect.googleusercontent.com/r/REPLACE_WITH_GOOGLE_PROJECT_ID';
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
  // The local database needs the voice tables. Apply the migrations first.
  spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'mdtronix-customers', '--local'], { cwd, shell: true, stdio: 'ignore' });
  dev = spawn(
    'npx',
    [
      'wrangler', 'dev', '--port', String(PORT), '--local',
      '--var', 'DEV_LOGIN:true',
      '--var', `SESSION_SECRET:${'t'.repeat(32)}`,
      '--var', 'GOOGLE_CLIENT_ID:test',
      '--var', 'GOOGLE_CLIENT_SECRET:test',
      '--var', `GOOGLE_VOICE_CLIENT_ID:${CLIENT_ID}`,
      '--var', `GOOGLE_VOICE_CLIENT_SECRET:${CLIENT_SECRET}`,
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

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function signedInCookie() {
  const r = await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(`voice-${Date.now()}@example.test`)}`, {
    redirect: 'manual',
  });
  return r.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session=')).split(';')[0];
}

function authorizeParams(challenge, extra = {}) {
  return new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    response_type: 'code',
    state: 'state-123',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  });
}

/** Runs consent with Allow and returns the code the platform receives. */
async function getCode(cookie, challenge) {
  const params = authorizeParams(challenge);
  const page = await fetch(`${BASE}/oauth/authorize?${params}`, { headers: { cookie } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /name="decision" value="allow"/);

  const form = new URLSearchParams(params);
  form.set('decision', 'allow');
  const res = await fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.origin + location.pathname, REDIRECT);
  assert.equal(location.searchParams.get('state'), 'state-123');
  return location.searchParams.get('code');
}

async function tokenRequest(fields) {
  return fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  });
}

test('voice linking: consent, PKCE code exchange, refresh, revoke', async () => {
  const cookie = await signedInCookie();
  const { verifier, challenge } = pkce();
  const code = await getCode(cookie, challenge);
  assert.ok(code, 'code issued');

  // Exchange the code with the right verifier.
  const exchange = await tokenRequest({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(exchange.status, 200, await exchange.clone().text());
  const tokens = await exchange.json();
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.expires_in, 3600);
  assert.ok(tokens.access_token && tokens.refresh_token);

  // A code can be used once.
  const replay = await tokenRequest({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, 'invalid_grant');

  // A refresh token gives a new access token.
  const refresh = await tokenRequest({
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(refresh.status, 200);
  assert.ok((await refresh.json()).access_token);

  // Revoking the refresh token stops refresh from working.
  const revoke = await fetch(`${BASE}/oauth/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: tokens.refresh_token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }),
  });
  assert.equal(revoke.status, 200);
  const afterRevoke = await tokenRequest({
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(afterRevoke.status, 400);
  assert.equal((await afterRevoke.json()).error, 'invalid_grant');
});

test('voice linking: wrong verifier, wrong secret, unknown client and redirect are refused', async () => {
  const cookie = await signedInCookie();
  const { challenge } = pkce();
  const code = await getCode(cookie, challenge);

  const wrongVerifier = await tokenRequest({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: 'not-the-verifier',
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(wrongVerifier.status, 400);
  assert.equal((await wrongVerifier.json()).error, 'invalid_grant');

  const wrongSecret = await tokenRequest({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: 'x',
    client_id: CLIENT_ID, client_secret: 'wrong',
  });
  assert.equal(wrongSecret.status, 401);
  assert.equal((await wrongSecret.json()).error, 'invalid_client');

  const unknownClient = await fetch(`${BASE}/oauth/authorize?${authorizeParams(challenge, { client_id: 'nobody' })}`, {
    headers: { cookie },
  });
  assert.equal(unknownClient.status, 400);

  const badRedirect = await fetch(
    `${BASE}/oauth/authorize?${authorizeParams(challenge, { redirect_uri: 'https://evil.example/cb' })}`,
    { headers: { cookie } },
  );
  assert.equal(badRedirect.status, 400);

  const noPkce = await fetch(
    `${BASE}/oauth/authorize?${authorizeParams(challenge, { code_challenge_method: 'plain' })}`,
    { headers: { cookie } },
  );
  assert.equal(noPkce.status, 400);
});

test('voice linking: deny returns access_denied and issues no code', async () => {
  const cookie = await signedInCookie();
  const { challenge } = pkce();
  const params = authorizeParams(challenge);
  const form = new URLSearchParams(params);
  form.set('decision', 'deny');
  const res = await fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.searchParams.get('error'), 'access_denied');
  assert.equal(location.searchParams.get('code'), null);
});
