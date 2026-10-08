// Tests the staff approval allowlist: the admin API that manages it, and that it reflects correctly
// through /v1/dev/approved (a dev-only read used here instead of driving real Google sign-in, which
// nothing in this relay's tests fakes — see src/google.ts for where the gate itself is wired in).
// Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const PORT = 8801;
const BASE = `http://127.0.0.1:${PORT}`;
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
    [
      'wrangler', 'dev', '--port', String(PORT), '--local',
      '--var', 'DEV_LOGIN:true',
      '--var', `SESSION_SECRET:${'t'.repeat(32)}`,
      '--var', 'GOOGLE_CLIENT_ID:test',
      '--var', 'GOOGLE_CLIENT_SECRET:test',
      '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`,
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

function isApproved(email) {
  return fetch(`${BASE}/v1/dev/approved?email=${encodeURIComponent(email)}`).then((r) => r.json());
}

function adminPost(body, token = ADMIN_TOKEN) {
  return fetch(`${BASE}/v1/admin/approved-emails`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function adminList(token = ADMIN_TOKEN) {
  return fetch(`${BASE}/v1/admin/approved-emails`, { headers: { authorization: `Bearer ${token}` } });
}

test('an email nobody has approved is not approved', async () => {
  const email = `nobody-${Date.now()}@example.test`;
  assert.deepEqual(await isApproved(email), { approved: false });
});

test('staff approving an email makes it approved, case-insensitively', async () => {
  const email = `customer-${Date.now()}@Example.Test`;
  const res = await adminPost({ email, action: 'approve', note: 'bought WTLC-200' });
  assert.equal(res.status, 200, await res.clone().text());

  assert.deepEqual(await isApproved(email.toLowerCase()), { approved: true });
  assert.deepEqual(await isApproved(email.toUpperCase()), { approved: true }, 'matching is case-insensitive');
});

test('approving the same email twice updates the note instead of erroring', async () => {
  const email = `repeat-${Date.now()}@example.test`;
  assert.equal((await adminPost({ email, action: 'approve', note: 'first' })).status, 200);
  assert.equal((await adminPost({ email, action: 'approve', note: 'second' })).status, 200);

  const list = await (await adminList()).json();
  const row = list.emails.find((e) => e.email === email.toLowerCase());
  assert.ok(row, 'the email is listed');
  assert.equal(row.note, 'second');
});

test('revoking removes approval, and revoking an unknown email is a 404', async () => {
  const email = `revoke-me-${Date.now()}@example.test`;
  await adminPost({ email, action: 'approve' });
  assert.deepEqual(await isApproved(email), { approved: true });

  const revoke = await adminPost({ email, action: 'revoke' });
  assert.equal(revoke.status, 200);
  assert.deepEqual(await isApproved(email), { approved: false });

  const revokeAgain = await adminPost({ email, action: 'revoke' });
  assert.equal(revokeAgain.status, 404);
});

test('the admin endpoints require the admin token', async () => {
  const email = `no-token-${Date.now()}@example.test`;
  assert.equal((await adminPost({ email, action: 'approve' }, 'wrong')).status, 401);
  assert.equal((await fetch(`${BASE}/v1/admin/approved-emails`)).status, 401);
  assert.deepEqual(await isApproved(email), { approved: false }, 'the rejected request had no effect');
});

test('a malformed email or an unknown action is refused', async () => {
  assert.equal((await adminPost({ email: 'not-an-email', action: 'approve' })).status, 400);
  assert.equal((await adminPost({ email: 'ok@example.test', action: 'delete' })).status, 400);
});

test('the admin list shows the newest approvals first', async () => {
  const first = `list-a-${Date.now()}@example.test`;
  const second = `list-b-${Date.now()}@example.test`;
  await adminPost({ email: first, action: 'approve' });
  await new Promise((r) => setTimeout(r, 1100)); // created_at has 1-second resolution
  await adminPost({ email: second, action: 'approve' });

  const { emails } = await (await adminList()).json();
  const indexOf = (email) => emails.findIndex((e) => e.email === email.toLowerCase());
  assert.ok(indexOf(second) < indexOf(first), 'the most recently approved email comes first');
});
