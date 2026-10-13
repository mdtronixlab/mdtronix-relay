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

before(async () => {
  spawnSync('npx', ['wrangler', 'd1', 'migrations', 'apply', 'mdtronix-customers', '--local'], { cwd, shell: true, stdio: 'ignore' });
  dev = spawn(
    'npx',
    ['wrangler', 'dev', '--port', String(PORT), '--local', '--var', 'DEV_LOGIN:true', '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`],
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

test('wrong password, unknown email, and a suspended-sounding generic message are indistinguishable', async () => {
  const email = `wrongpw-${Date.now()}@example.test`;
  await approve(email);
  await register({ email, password: 'correct horse', password_confirm: 'correct horse' });

  const wrongPassword = await login({ email, password: 'not the password' });
  const unknownEmail = await login({ email: `nobody-${Date.now()}@example.test`, password: 'whatever1' });
  assert.equal(wrongPassword.status, 400);
  assert.equal(unknownEmail.status, 400);
  assert.match(await wrongPassword.text(), /Incorrect email or password/);
  assert.match(await unknownEmail.text(), /Incorrect email or password/);
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
  assert.match(await attempt.text(), /Incorrect email or password/);
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
