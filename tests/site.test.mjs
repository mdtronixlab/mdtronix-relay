// End-to-end test of the public site ("/" and "/account") against a local relay. Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8800;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const GOOGLE = { clientId: 'google-test-client', clientSecret: 'google-test-secret', redirect: 'https://oauth-redirect.googleusercontent.com/r/mdtronix-ha-85262' };
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
      '--var', `SESSION_SECRET:${'t'.repeat(32)}`,
      '--var', 'GOOGLE_CLIENT_ID:test',
      '--var', 'GOOGLE_CLIENT_SECRET:test',
      '--var', `GOOGLE_VOICE_CLIENT_ID:${GOOGLE.clientId}`,
      '--var', `GOOGLE_VOICE_CLIENT_SECRET:${GOOGLE.clientSecret}`,
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

// --- helpers --------------------------------------------------------------

async function login(email) {
  const r = await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });
  const cookie = r.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session='));
  assert.ok(cookie, 'dev login set a session cookie');
  return cookie.split(';')[0];
}

async function get(path, cookie) {
  return fetch(`${BASE}${path}`, { headers: cookie ? { cookie } : {}, redirect: 'manual' });
}

async function post(path, cookie, body = {}) {
  return fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
    redirect: 'manual',
  });
}

async function linkHome(cookie) {
  const d = await (await fetch(`${BASE}/v1/ha/device`, { method: 'POST' })).json();
  const approve = await fetch(`${BASE}/link`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ user_code: d.user_code }),
    redirect: 'manual',
  });
  assert.equal(approve.status, 200);
  const t = await fetch(`${BASE}/v1/ha/device/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ device_code: d.device_code }),
  });
  assert.equal(t.status, 200, await t.clone().text());
  return t.json();
}

/** Runs the Google Home consent flow and returns an access token, linking the platform to this customer. */
async function linkGoogleVoice(cookie) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: GOOGLE.clientId, redirect_uri: GOOGLE.redirect, response_type: 'code',
    state: 's', code_challenge: challenge, code_challenge_method: 'S256',
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
      grant_type: 'authorization_code', code, redirect_uri: GOOGLE.redirect, code_verifier: verifier,
      client_id: GOOGLE.clientId, client_secret: GOOGLE.clientSecret,
    }),
  });
  assert.equal(exchange.status, 200, await exchange.clone().text());
  return exchange.json();
}

// --- Homepage ----------------------------------------------------------

test('homepage: offers Google sign-in when signed out, and the account link when signed in', async () => {
  const signedOut = await get('/');
  assert.equal(signedOut.status, 200);
  const outText = await signedOut.text();
  assert.match(outText, /Get started with Google/);
  assert.match(outText, /Sign in/);

  const cookie = await login(`site-home-${Date.now()}@example.test`);
  const signedIn = await get('/', cookie);
  assert.equal(signedIn.status, 200);
  const inText = await signedIn.text();
  assert.match(inText, /Go to your account/);
  assert.doesNotMatch(inText, /Get started with Google/);
});

// --- Account: signed out --------------------------------------------------

test('account page sends a signed-out visitor to Google sign-in, with next=/account', async () => {
  const res = await get('/account');
  assert.equal(res.status, 302);
  const location = res.headers.get('location');
  assert.match(location, /^\/v1\/auth\/google\/start\?next=%2Faccount$/);
});

// --- Account: signed in, nothing linked -----------------------------------

test('account page shows no home and no subscription for a brand new customer', async () => {
  const cookie = await login(`site-blank-${Date.now()}@example.test`);
  const res = await get('/account', cookie);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /No Home Assistant connected yet/);
  assert.match(text, /No subscription yet/);
  assert.match(text, /Google Home: Not connected/);
  assert.match(text, /Alexa: Not connected/);
});

// --- Account: a linked home -------------------------------------------------

test('account page shows the remote URL, trial status, and disconnects on request', async () => {
  const cookie = await login(`site-home2-${Date.now()}@example.test`);
  const link = await linkHome(cookie);

  const res = await get('/account', cookie);
  const text = await res.text();
  assert.match(text, new RegExp(link.subdomain));
  assert.match(text, /Not connected right now/, 'no fake HA attached, so the tunnel is not up');
  assert.match(text, /Free trial/);

  // The CSRF guard refuses a mismatched origin.
  const noOrigin = await fetch(`${BASE}/account/unlink-home`, { method: 'POST', headers: { cookie } });
  assert.equal(noOrigin.status, 403);

  const unlink = await post('/account/unlink-home', cookie);
  assert.equal(unlink.status, 302);
  assert.equal(unlink.headers.get('location'), '/account');

  const after = await get('/account', cookie);
  const afterText = await after.text();
  assert.match(afterText, /This home was disconnected/);
  assert.match(afterText, new RegExp(link.subdomain), 'the reserved subdomain is still mentioned, for reconnecting');
  assert.doesNotMatch(afterText, /Not connected right now/, 'the live-status line is gone once disconnected');

  // The device's tunnel token no longer works.
  const token = await fetch(`${BASE}/v1/ha/unlink`, { method: 'POST', headers: { authorization: `Bearer ${link.tunnel_token}` } });
  assert.equal(token.status, 401);
});

// --- Account: voice linking --------------------------------------------------

test('account page shows a linked voice platform and unlinks it on request', async () => {
  const cookie = await login(`site-voice-${Date.now()}@example.test`);
  await linkGoogleVoice(cookie);

  const linked = await get('/account', cookie);
  const linkedText = await linked.text();
  assert.match(linkedText, /Google Home: <strong class="ok">Connected<\/strong>/);

  const bad = await post('/account/unlink-voice', cookie, { platform: 'carrier-pigeon' });
  assert.equal(bad.status, 400);

  const unlink = await post('/account/unlink-voice', cookie, { platform: 'google' });
  assert.equal(unlink.status, 302);
  assert.equal(unlink.headers.get('location'), '/account');

  const after = await get('/account', cookie);
  assert.match(await after.text(), /Google Home: Not connected/);
});

// --- Sign out ----------------------------------------------------------------

test('signing out clears the session, so the account page asks to sign in again', async () => {
  const cookie = await login(`site-signout-${Date.now()}@example.test`);
  assert.equal((await get('/account', cookie)).status, 200);

  const noOrigin = await fetch(`${BASE}/account/sign-out`, { method: 'POST', headers: { cookie } });
  assert.equal(noOrigin.status, 403);

  const out = await post('/account/sign-out', cookie);
  assert.equal(out.status, 302);
  assert.equal(out.headers.get('location'), '/');

  // The old cookie is revoked server-side, not just cleared client-side.
  const after = await get('/account', cookie);
  assert.equal(after.status, 302);
  assert.match(after.headers.get('location'), /^\/v1\/auth\/google\/start/);
});
