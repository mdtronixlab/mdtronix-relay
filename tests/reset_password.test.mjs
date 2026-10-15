// End-to-end test of the staff-generated password reset link (POST /v1/admin/generate-reset-link,
// GET/POST /reset-password) against a local relay. Split out from password_auth.test.mjs: these tests
// used to live there, but adding rate limiting to POST /reset-password (2026-10-14, a code-review fix for
// the same bypass this flow had to begin with) pushed that file's cumulative RL_LOGIN consumption past
// the local rate limiter's budget within a single run — this file gets its own isolated budget instead.
// Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8800;
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

function revokeApproval(email) {
  return fetch(`${BASE}/v1/admin/approved-emails`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, action: 'revoke' }),
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

function setPassword(email, password, token = ADMIN_TOKEN) {
  return fetch(`${BASE}/v1/admin/set-password`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
}

function generateLink(email, token = ADMIN_TOKEN) {
  return fetch(`${BASE}/v1/admin/generate-reset-link`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  });
}

function resetPasswordSubmit(fields) {
  const form = new URLSearchParams({ token: '', password: '', password_confirm: '', ...fields });
  return fetch(`${BASE}/reset-password`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
    redirect: 'manual',
  });
}

test('reset link: a staff-generated link lets the customer set their own password and signs them in', async () => {
  const email = `reset-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);

  const gen = await generateLink(email);
  assert.equal(gen.status, 200, await gen.clone().text());
  const { url } = await gen.json();
  const token = new URL(url).searchParams.get('token');
  assert.ok(token, 'the link carries a token');

  // The page renders the set-password form for a valid token.
  const page = await fetch(`${BASE}/reset-password?token=${token}`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Set a new password/);

  const submit = await resetPasswordSubmit({ token, password: 'the brand new password', password_confirm: 'the brand new password' });
  assert.equal(submit.status, 302, await submit.clone().text());
  assert.equal(submit.headers.get('location'), '/account');
  const cookie = sessionCookie(submit);
  assert.ok(cookie, 'submitting the reset signs the customer straight in');

  const account = await fetch(`${BASE}/account`, { headers: { cookie } });
  assert.equal(account.status, 200, 'the fresh session actually works');

  // The old password is gone; the new one works for a normal login too.
  const oldPassword = await login({ email, password: 'the original password' });
  assert.equal(oldPassword.status, 400);
  const newPassword = await login({ email, password: 'the brand new password' });
  assert.equal(newPassword.status, 302);
});

test('reset link: single-use, and generating a new one kills the old one', async () => {
  const email = `reset-reuse-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);

  const first = await (await generateLink(email)).json();
  const firstToken = new URL(first.url).searchParams.get('token');

  // A second link invalidates the first, even though neither has been used yet.
  const second = await (await generateLink(email)).json();
  const secondToken = new URL(second.url).searchParams.get('token');
  assert.notEqual(firstToken, secondToken);

  const firstPage = await fetch(`${BASE}/reset-password?token=${firstToken}`);
  assert.equal(firstPage.status, 400);
  assert.match(await firstPage.text(), /no longer valid/);

  // The second (current) link works once...
  const use = await resetPasswordSubmit({ token: secondToken, password: 'used once', password_confirm: 'used once' });
  assert.equal(use.status, 302);

  // ...and a replay of the same token is refused.
  const replay = await resetPasswordSubmit({ token: secondToken, password: 'used twice', password_confirm: 'used twice' });
  assert.equal(replay.status, 400);
  assert.match(await replay.text(), /no longer valid/);
});

test('reset link: a short password or a mismatched confirmation is refused without burning the token', async () => {
  const email = `reset-refuse-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);
  const { url } = await (await generateLink(email)).json();
  const token = new URL(url).searchParams.get('token');

  const tooShort = await resetPasswordSubmit({ token, password: 'short', password_confirm: 'short' });
  assert.equal(tooShort.status, 400);
  assert.match(await tooShort.text(), /at least 8 characters/);

  const mismatched = await resetPasswordSubmit({ token, password: 'a long enough password', password_confirm: 'different' });
  assert.equal(mismatched.status, 400);
  assert.match(await mismatched.text(), /do not match/);

  // The token is still good after both refusals.
  const finallyOk = await resetPasswordSubmit({ token, password: 'a long enough password', password_confirm: 'a long enough password' });
  assert.equal(finallyOk.status, 302);
});

test('reset link: an unknown or missing token shows the expired page, and generating for an unknown email 404s', async () => {
  const missing = await fetch(`${BASE}/reset-password`);
  assert.equal(missing.status, 400);
  assert.match(await missing.text(), /no longer valid/);

  const bogus = await fetch(`${BASE}/reset-password?token=not-a-real-token`);
  assert.equal(bogus.status, 400);

  const unknownEmail = await generateLink(`nobody-${Date.now()}@example.test`);
  assert.equal(unknownEmail.status, 404);
});

test('reset link: generating requires the admin token, and submitting requires the relay origin', async () => {
  const email = `reset-guard-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);

  assert.equal((await generateLink(email, 'wrong')).status, 401);

  const { url } = await (await generateLink(email)).json();
  const token = new URL(url).searchParams.get('token');
  const noOrigin = await fetch(`${BASE}/reset-password`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, password: 'a long enough password', password_confirm: 'a long enough password' }),
  });
  assert.equal(noOrigin.status, 403);
});

test('reset link: refused for an unapproved customer, so it can never grant access approval was meant to gate', async () => {
  const email = `reset-unapproved-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  // Deliberately not approved.

  const gen = await generateLink(email);
  assert.equal(gen.status, 403);
  assert.equal((await gen.json()).error, 'not_approved');
});

test('reset link: a link already sent stops working if approval is revoked before it is redeemed', async () => {
  const email = `reset-revoked-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);

  const { url } = await (await generateLink(email)).json();
  const token = new URL(url).searchParams.get('token');

  await revokeApproval(email);

  const page = await fetch(`${BASE}/reset-password?token=${token}`);
  assert.equal(page.status, 400);
  assert.match(await page.text(), /no longer valid/);

  const submit = await resetPasswordSubmit({ token, password: 'a long enough password', password_confirm: 'a long enough password' });
  assert.equal(submit.status, 400);
  assert.match(await submit.text(), /no longer valid/);
});

test('admin set-password invalidates any reset link sent earlier, so it cannot later overwrite the new password', async () => {
  const email = `reset-vs-setpw-${Date.now()}@example.test`;
  await register({ email, password: 'the original password', password_confirm: 'the original password' });
  await approve(email);

  const { url } = await (await generateLink(email)).json();
  const token = new URL(url).searchParams.get('token');

  const set = await setPassword(email, 'staff chose this one');
  assert.equal(set.status, 200);

  const page = await fetch(`${BASE}/reset-password?token=${token}`);
  assert.equal(page.status, 400);
  assert.match(await page.text(), /no longer valid/);
});
