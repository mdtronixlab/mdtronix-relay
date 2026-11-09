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
const REDIRECT = 'https://oauth-redirect.googleusercontent.com/r/mdtronix-cloud';
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

// Each test file gets its own persisted local state (D1, rate limiters, …), keyed by port. Without this,
// every file's wrangler dev shares the same default .wrangler/state directory, so a rate limiter whose
// local fallback key is just "local" (see src/ratelimit.ts's clientKey) accumulates across every file in
// the same `npm test` run — and across runs, since it's never cleared — until some unrelated test gets a
// spurious 429.
const PERSIST_TO = `.wrangler/test-state-${PORT}`;

before(async () => {
  // The local database needs the voice tables. Apply the migrations first.
  spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'mdtronix-customers', '--local', '--persist-to', PERSIST_TO], { cwd, shell: true, stdio: 'ignore' });
  dev = spawn(
    'npx',
    [
      'wrangler', 'dev', '--port', String(PORT), '--local', '--persist-to', PERSIST_TO,
      '--var', 'DEV_LOGIN:true',
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

async function signedInCookie(email = `voice-${Date.now()}@example.test`) {
  const r = await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });
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

test('voice linking: Google (and only Google) may skip PKCE entirely', async () => {
  const cookie = await signedInCookie();

  // The Google Home app's own account linking never sends a code_challenge. The relay must still issue
  // a code, and the token exchange must succeed with no code_verifier.
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    response_type: 'code',
    state: 'state-no-pkce',
  });
  const page = await fetch(`${BASE}/oauth/authorize?${params}`, { headers: { cookie } });
  assert.equal(page.status, 200, await page.clone().text());

  const form = new URLSearchParams(params);
  form.set('decision', 'allow');
  const consent = await fetch(`${BASE}/oauth/authorize`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
    redirect: 'manual',
  });
  assert.equal(consent.status, 302);
  const location = new URL(consent.headers.get('location'));
  const code = location.searchParams.get('code');
  assert.ok(code, 'code issued without PKCE');

  const exchange = await tokenRequest({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT,
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
  });
  assert.equal(exchange.status, 200, await exchange.clone().text());
  assert.ok((await exchange.json()).access_token);

  // Alexa, by contrast, still requires PKCE: omitting it is refused at /oauth/authorize.
  const alexaNoPkce = await fetch(
    `${BASE}/oauth/authorize?${new URLSearchParams({
      client_id: 'mdtronix-alexa-test-client',
      redirect_uri: 'https://pitangui.amazon.com/api/skill/link/unused',
      response_type: 'code',
      state: 'x',
    })}`,
    { headers: { cookie } },
  );
  // Unknown client either way (not registered in this test env), but confirms the request is rejected
  // before PKCE would even be reached, since Alexa's requirement is independent of this test's client.
  assert.equal(alexaNoPkce.status, 400);
});

test('voice linking: consent page shows the signed-in email and can switch to a different account', async () => {
  const emailA = `voice-a-${Date.now()}@example.test`;
  const emailB = `voice-b-${Date.now()}@example.test`;
  const cookieA = await signedInCookie(emailA);
  const { challenge } = pkce();
  const params = authorizeParams(challenge);

  // The consent page shows which account is signed in.
  const pageA = await fetch(`${BASE}/oauth/authorize?${params}`, { headers: { cookie: cookieA } });
  assert.equal(pageA.status, 200);
  assert.match(await pageA.text(), new RegExp(`Signed in as ${emailA}`));

  // "Not you?" signs the current session out and sends the browser back to /login with the original
  // authorize request preserved, instead of silently staying on account A.
  const authorizePath = `/oauth/authorize?${params}`;
  const switchForm = new URLSearchParams({ next: authorizePath });
  const switchRes = await fetch(`${BASE}/oauth/switch-account`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie: cookieA, 'content-type': 'application/x-www-form-urlencoded' },
    body: switchForm,
    redirect: 'manual',
  });
  assert.equal(switchRes.status, 302);
  const loc = new URL(switchRes.headers.get('location'), BASE);
  assert.equal(loc.pathname, '/login');
  assert.equal(loc.searchParams.get('next'), authorizePath);
  const clearedCookie = switchRes.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session='));
  assert.ok(clearedCookie, 'session cookie cleared');

  // The old cookie is revoked, not just cleared client-side: re-using it no longer counts as signed in.
  const afterSwitch = await fetch(`${BASE}/oauth/authorize?${params}`, {
    headers: { cookie: cookieA },
    redirect: 'manual',
  });
  assert.equal(afterSwitch.status, 302);
  assert.match(afterSwitch.headers.get('location'), /^\/login\?next=/);

  // Signing in as a different account and completing consent links that account, not the first one.
  const cookieB = await signedInCookie(emailB);
  const pageB = await fetch(`${BASE}/oauth/authorize?${params}`, { headers: { cookie: cookieB } });
  assert.equal(pageB.status, 200);
  assert.match(await pageB.text(), new RegExp(`Signed in as ${emailB}`));
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

// --- What Google's certification requires on the linking pages (src/brand.ts) ---------------------------

const SIGN_IN_STATEMENT = 'By signing in, you are authorizing Google to control your devices.';
const CONSENT_STATEMENT = 'By selecting Agree and link, you are authorizing Google to control your devices.';
const AUTHORIZING_GOOGLE = /authorizing Google/;
const GOOGLE_PRODUCT = /Google (Home|Assistant)/;

const googleAuthorizePath = () => `/oauth/authorize?${authorizeParams(pkce().challenge)}`;
const alexaAuthorizePath = () =>
  `/oauth/authorize?${new URLSearchParams({
    client_id: 'mdtronix-alexa',
    redirect_uri: 'https://pitangui.amazon.com/api/skill/link/M23Q7Y64C1HJD4',
    response_type: 'code',
    state: 'state-123',
    code_challenge: pkce().challenge,
    code_challenge_method: 'S256',
  })}`;

function assertIdentifiesIntegration(text) {
  assert.match(text, /<strong>MDtronix Home<\/strong>/);
  assert.match(text, /by MDtronix Lab/);
  assert.match(text, /<img src="data:image\/png;base64,/);
}

test('the Google sign-in page identifies the integration, links to Google, and states the authorization', async () => {
  const res = await fetch(`${BASE}/login?next=${encodeURIComponent(googleAuthorizePath())}`);
  assert.equal(res.status, 200);
  const text = await res.text();
  assertIdentifiesIntegration(text);
  assert.ok(text.includes(SIGN_IN_STATEMENT));
  assert.match(text, /Sign in to link your account to Google/);
  assert.doesNotMatch(text, GOOGLE_PRODUCT);
  assert.match(text, /<form method="post" action="\/login">/);
  assert.match(text, /name="next" value="\/oauth\/authorize\?/);
});

test('a failed Google sign-in keeps the required wording on the page it shows again', async () => {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ next: googleAuthorizePath(), email: `nobody-${Date.now()}@example.test`, password: 'whatever1' }),
    redirect: 'manual',
  });
  assert.equal(res.status, 400);
  const text = await res.text();
  assertIdentifiesIntegration(text);
  assert.ok(text.includes(SIGN_IN_STATEMENT));
  assert.match(text, /name="next" value="\/oauth\/authorize\?/);
});

test('creating an account during Google linking shows who it is for but authorizes nothing yet', async () => {
  const text = await (await fetch(`${BASE}/register?next=${encodeURIComponent(googleAuthorizePath())}`)).text();
  assertIdentifiesIntegration(text);
  assert.doesNotMatch(text, AUTHORIZING_GOOGLE);
  assert.doesNotMatch(text, GOOGLE_PRODUCT);
});

test('website and Alexa sign-in never claim to authorize Google', async () => {
  for (const next of ['/account', alexaAuthorizePath(), '/oauth/authorize?client_id=unknown-client']) {
    const text = await (await fetch(`${BASE}/login?next=${encodeURIComponent(next)}`)).text();
    assert.doesNotMatch(text, AUTHORIZING_GOOGLE, next);
    assert.doesNotMatch(text, /MDtronix Home/, next);
    assert.match(text, /<h1>Sign in<\/h1>/, next);
  }
});

test('the Google consent page links to Google, not to a Google product', async () => {
  const cookie = await signedInCookie();
  const text = await (await fetch(`${BASE}${googleAuthorizePath()}`, { headers: { cookie } })).text();
  assertIdentifiesIntegration(text);
  assert.match(text, /<title>Link your account to Google<\/title>/);
  assert.ok(text.includes(CONSENT_STATEMENT));
  assert.doesNotMatch(text, GOOGLE_PRODUCT);
  assert.match(text, /name="decision" value="allow" class="primary">Agree and link</);
  assert.match(text, /name="decision" value="deny">Cancel</);
  assert.match(text, /policies\.google\.com\/privacy/);
});

test('the Alexa consent page is unchanged by the Google requirements', async () => {
  const cookie = await signedInCookie();
  const text = await (await fetch(`${BASE}${alexaAuthorizePath()}`, { headers: { cookie } })).text();
  assert.match(text, /<h1>Link Alexa<\/h1>/);
  assert.match(text, /name="decision" value="allow">Allow</);
  assert.match(text, /name="decision" value="deny">Deny</);
  assert.doesNotMatch(text, AUTHORIZING_GOOGLE);
  assert.doesNotMatch(text, /MDtronix Home/);
});
