// End-to-end test of customer registration and email/password sign-in against a local relay.
// Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8798;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const ADMIN_TOKEN = 'testadmin';
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

// Own persisted local state, keyed by port — otherwise this file's rate-limit counters (see
// src/ratelimit.ts's "local" fallback key) would leak into or inherit from every other test file.
const PERSIST_TO = `.wrangler/test-state-${PORT}`;

before(async () => {
  spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'mdtronix-customers', '--local', '--persist-to', PERSIST_TO], { cwd, shell: true, stdio: 'ignore' });
  dev = spawn(
    'npx',
    ['wrangler', 'dev', '--port', String(PORT), '--local', '--persist-to', PERSIST_TO, '--var', 'DEV_LOGIN:true', '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`],
    { cwd, shell: true, stdio: 'ignore' },
  );
  await waitForHealth();
});

after(() => {
  if (!dev) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(dev.pid), '/T', '/F']);
  else dev.kill();
});

function approve(email) {
  return fetch(`${BASE}/v1/admin/approved-emails`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, action: 'approve' }),
  });
}

function sessionCookie(res) {
  return res.headers.getSetCookie().find((c) => c.startsWith('__Host-mdt_session='))?.split(';')[0];
}

async function register(fields, extra = {}) {
  const form = new URLSearchParams({ email: '', password: '', password_confirm: '', next: '/account', ...fields });
  return fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded', ...extra.headers },
    body: form,
    redirect: 'manual',
  });
}

async function login(fields, extra = {}) {
  const form = new URLSearchParams({ email: '', password: '', next: '/account', ...fields });
  return fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded', ...extra.headers },
    body: form,
    redirect: 'manual',
  });
}

test('registering with an unapproved email creates the account but does not sign in', async () => {
  const email = `pending-${Date.now()}@example.test`;
  const res = await register({ email, password: 'correct horse', password_confirm: 'correct horse' });
  assert.equal(res.status, 200, await res.clone().text());
  assert.match(await res.text(), /waiting on MDtronix staff/);
  assert.equal(sessionCookie(res), undefined, 'no session until approved');

  const loginAttempt = await login({ email, password: 'correct horse' });
  assert.equal(loginAttempt.status, 403);
  assert.match(await loginAttempt.text(), /isn't approved/);
});

test('register, approve, then log in', async () => {
  const email = `flow-${Date.now()}@example.test`;
  const reg = await register({ email, password: 'correct horse', password_confirm: 'correct horse' });
  assert.equal(reg.status, 200);
  assert.equal(sessionCookie(reg), undefined);

  const approved = await approve(email);
  assert.equal(approved.status, 200);

  const ok = await login({ email, password: 'correct horse' });
  assert.equal(ok.status, 302, await ok.clone().text());
  assert.equal(ok.headers.get('location'), '/account');
  assert.ok(sessionCookie(ok), 'session cookie set');

  const cookie = sessionCookie(ok);
  const account = await fetch(`${BASE}/account`, { headers: { cookie } });
  assert.equal(account.status, 200);
  assert.match(await account.text(), new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('registering with an email that is already approved signs in immediately', async () => {
  const email = `preapproved-${Date.now()}@example.test`;
  assert.equal((await approve(email)).status, 200);

  const reg = await register({ email, password: 'correct horse', password_confirm: 'correct horse' });
  assert.equal(reg.status, 302, await reg.clone().text());
  assert.ok(sessionCookie(reg), 'pre-approved registration signs in right away');
});

test('login errors say specifically which of email or password was wrong', async () => {
  const email = `wrongpw-${Date.now()}@example.test`;
  await approve(email);
  await register({ email, password: 'correct horse', password_confirm: 'correct horse' });

  const wrongPassword = await login({ email, password: 'not the password' });
  const unknownEmail = await login({ email: `nobody-${Date.now()}@example.test`, password: 'whatever1' });
  assert.equal(wrongPassword.status, 400);
  assert.equal(unknownEmail.status, 400);
  const wrongPasswordText = await wrongPassword.text();
  const unknownEmailText = await unknownEmail.text();
  assert.match(wrongPasswordText, /Incorrect password\./);
  assert.doesNotMatch(wrongPasswordText, /No account exists/);
  assert.match(unknownEmailText, /No account exists with that email\./);
  assert.doesNotMatch(unknownEmailText, /Incorrect password/);
});

test('a passwordless legacy account gets its own specific login error', async () => {
  const email = `no-pw-${Date.now()}@example.test`;
  await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });
  await approve(email);

  const attempt = await login({ email, password: 'whatever it is' });
  assert.equal(attempt.status, 400);
  assert.match(await attempt.text(), /no password set yet/);
});

test('registration is refused for a short password, a mismatched confirmation, or a duplicate email', async () => {
  const email = `dupe-${Date.now()}@example.test`;
  const tooShort = await register({ email, password: 'short', password_confirm: 'short' });
  assert.equal(tooShort.status, 400);
  assert.match(await tooShort.text(), /at least 8 characters/);

  const mismatched = await register({ email, password: 'correct horse', password_confirm: 'different' });
  assert.equal(mismatched.status, 400);
  assert.match(await mismatched.text(), /do not match/);

  assert.equal((await register({ email, password: 'correct horse', password_confirm: 'correct horse' })).status, 200);
  const duplicate = await register({ email, password: 'correct horse', password_confirm: 'correct horse' });
  assert.equal(duplicate.status, 400);
  assert.match(await duplicate.text(), /already exists/);
});

test('registering over a passwordless existing row (e.g. a leftover Google sign-in account) is refused, not claimed', async () => {
  // Letting /register set a password on someone else's existing row would be an account takeover: just
  // knowing a customer's email would be enough to sign in as them. It must be refused exactly like any
  // other already-registered email, with no way to tell the two cases apart from the response.
  const email = `no-claim-${Date.now()}@example.test`;
  await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });

  const reg = await register({ email, password: 'correct horse', password_confirm: 'correct horse' });
  assert.equal(reg.status, 400);
  assert.match(await reg.text(), /already exists/);

  await approve(email);
  const attempt = await login({ email, password: 'correct horse' });
  assert.equal(attempt.status, 400, 'the password was never actually set, so this is not a valid login either');
  assert.match(await attempt.text(), /no password set yet/);
});

function setPassword(email, password, token = ADMIN_TOKEN) {
  return fetch(`${BASE}/v1/admin/set-password`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
}

test('admin set-password gives a passwordless legacy account (or a locked-out customer) a working login again', async () => {
  const email = `legacy-${Date.now()}@example.test`;
  await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });
  await approve(email);

  // Before: no password was ever set (the old Google sign-in didn't use one), so login fails.
  const before = await login({ email, password: 'new password here' });
  assert.equal(before.status, 400);

  const set = await setPassword(email, 'new password here');
  assert.equal(set.status, 200, await set.clone().text());
  assert.deepEqual(await set.json(), { ok: true });

  const after = await login({ email, password: 'new password here' });
  assert.equal(after.status, 302, await after.clone().text());
  assert.ok(sessionCookie(after));
});

test('admin set-password revokes the customer\'s existing sessions, not just the password', async () => {
  const email = `takeover-${Date.now()}@example.test`;
  await register({ email, password: 'original password', password_confirm: 'original password' });
  await approve(email);

  const signedIn = await login({ email, password: 'original password' });
  const cookie = sessionCookie(signedIn);
  assert.ok(cookie, 'signed in with a session cookie');

  // The session works before the reset.
  const before = await fetch(`${BASE}/account`, { headers: { cookie } });
  assert.equal(before.status, 200);

  await setPassword(email, 'a brand new password');

  // The old session is dead, even though it was never explicitly signed out.
  const after = await fetch(`${BASE}/account`, { headers: { cookie }, redirect: 'manual' });
  assert.equal(after.status, 302);
  assert.match(after.headers.get('location'), /^\/login\?next=/);

  // The new password works, and gets a fresh session.
  const reLogin = await login({ email, password: 'a brand new password' });
  assert.equal(reLogin.status, 302);
  assert.ok(sessionCookie(reLogin));
});

test('admin set-password requires the admin token and a real email and valid-length password', async () => {
  const email = `setpw-guard-${Date.now()}@example.test`;
  await fetch(`${BASE}/v1/dev/login?email=${encodeURIComponent(email)}`, { redirect: 'manual' });

  assert.equal((await setPassword(email, 'a long enough password', 'wrong')).status, 401);
  assert.equal((await setPassword('not-an-email', 'a long enough password')).status, 400);
  assert.equal((await setPassword(email, 'short')).status, 400);
  assert.equal((await setPassword(`unknown-${Date.now()}@example.test`, 'a long enough password')).status, 404);
});

test('register and login POSTs require the relay origin', async () => {
  const email = `noorigin-${Date.now()}@example.test`;
  const res = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password: 'correct horse', password_confirm: 'correct horse' }),
  });
  assert.equal(res.status, 403);
});

test('GET /login and /register render forms', async () => {
  const loginPage = await fetch(`${BASE}/login`);
  assert.equal(loginPage.status, 200);
  assert.match(await loginPage.text(), /name="password"/);

  const registerPage = await fetch(`${BASE}/register`);
  assert.equal(registerPage.status, 200);
  assert.match(await registerPage.text(), /name="password_confirm"/);
});

// --- Where sign-in may send a customer afterwards (safeNext in src/http.ts) -------------------------------

async function afterDevLogin(next) {
  const email = `next-${Date.now()}@example.test`;
  const res = await fetch(`${BASE}/v1/dev/login?${new URLSearchParams({ email, next })}`, { redirect: 'manual' });
  assert.equal(res.status, 302, JSON.stringify(next));
  return res.headers.get('location');
}

test('sign-in falls back to /account for a next that would leave the site', async () => {
  // Browsers read "\" as "/" and drop tabs and newlines, so every path-shaped one of these is a real redirect
  // off the site. The dev route shares safeNext and redirect with /login, without /login's rate limit.
  const attacks = [
    '//evil.example',
    '/\\evil.example',
    '/\\/evil.example',
    '\\\\evil.example',
    '/\t/evil.example',
    '/\n/evil.example',
    '/\r/evil.example',
    'https://evil.example',
    'javascript:alert(1)',
    '/\\[',
    '/acc\nount',
  ];
  for (const next of attacks) assert.equal(await afterDevLogin(next), '/account', JSON.stringify(next));
});

test('the password sign-in route refuses a next that would leave the site', async () => {
  const email = `next-login-${Date.now()}@example.test`;
  assert.equal((await approve(email)).status, 200);
  assert.equal((await register({ email, password: 'correct horse', password_confirm: 'correct horse' })).status, 302);

  const res = await login({ email, password: 'correct horse', next: '/\\evil.example' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/account');
});

test('sign-in keeps a same-site next exactly as it was given', async () => {
  const kept = [
    '/account',
    '/account#devices',
    '/oauth/authorize?client_id=x&redirect_uri=https%3A%2F%2Fa.example%2Fb&state=a%2Fb',
    // Normalizing this would turn it into "//evil.example", so it must go out untouched. As written, a browser
    // resolves it to a path on this site.
    '/.//evil.example',
  ];
  for (const next of kept) {
    const location = await afterDevLogin(next);
    assert.equal(location, next);
    assert.equal(new URL(location, ORIGIN).origin, ORIGIN, next);
  }
});
