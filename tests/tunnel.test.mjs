// End-to-end test of the tunnel against a local relay. A fake Home Assistant client speaks
// the protocol in docs/remote-access/PROTOCOL.md. Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

const PORT = 8790;
const BASE = `http://127.0.0.1:${PORT}`;
const DOMAIN = 'mdtronix.online';
const ORIGIN = 'https://relay.mdtronix.online';
const OP_TEXT = 0x01;
const OP_BINARY = 0x02;

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
  // Secrets go in as --var flags. The .dev.vars file isn't reaching the handlers yet (see PHASE0.md).
  dev = spawn(
    'npx',
    [
      'wrangler', 'dev', '--port', String(PORT), '--local',
      '--var', 'DEV_LOGIN:true',
      '--var', 'ADMIN_TOKEN:testadmin',
    ],
    { cwd: fileURLToPath(new URL('..', import.meta.url)), shell: true, stdio: 'ignore' },
  );
  await waitForHealth();
});

after(() => {
  // npx spawns wrangler, which spawns workerd. Kill the whole tree, or the test process won't exit.
  if (!dev) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(dev.pid), '/T', '/F']);
  else dev.kill();
});

// --- helpers --------------------------------------------------------------

const HA_PASSWORD = 'correct horse battery staple';
const ADMIN_TOKEN = 'testadmin';

/**
 * Registers (or, on a second call for the same email, just reuses) a password-auth account, approves it,
 * then signs HA in directly with POST /v1/ha/login — the flow the mdtronix_cloud integration itself uses.
 */
async function linkHome(email, replace = false) {
  await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password: HA_PASSWORD, password_confirm: HA_PASSWORD, next: '/account' }),
    redirect: 'manual',
  }); // ignored: a relink's second call here just re-hits "already exists", which is fine.
  await fetch(`${BASE}/v1/admin/approved-emails`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, action: 'approve' }),
  });
  const res = await fetch(`${BASE}/v1/ha/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: HA_PASSWORD, replace }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  return res.json();
}

function connectHa(token) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/v1/tunnel`, {
      headers: { authorization: `Bearer ${token}`, 'x-mdt-protocol': '1' },
    });
    ws.on('unexpected-response', (_req, res) => reject(new Error(`status ${res.statusCode}`)));
    ws.on('error', reject);
    ws.on('open', () => {
      ws.send(JSON.stringify({ t: 'hello', v: 1 }));
      resolve(ws);
    });
  });
}

function frame(id, payload) {
  const out = Buffer.alloc(4 + payload.length);
  out.writeUInt32BE(id, 0);
  payload.copy(out, 4);
  return out;
}

function respond(ws, id, status, headers, chunks) {
  ws.send(JSON.stringify({ t: 'res', id, status, headers }));
  for (const c of chunks) ws.send(frame(id, Buffer.from(c)));
  ws.send(JSON.stringify({ t: 'end', id }));
}

/** A minimal Home Assistant: answers /api/hello, echoes /api/echo, and echoes text over /api/websocket. */
function fakeHa(ws) {
  const echoBodies = new Map();
  ws.on('message', (data, isBinary) => {
    if (isBinary) {
      const buf = Buffer.from(data);
      const id = buf.readUInt32BE(0);
      const payload = buf.subarray(4);
      if (echoBodies.has(id)) {
        echoBodies.get(id).push(Buffer.from(payload));
        return;
      }
      // WebSocket data from the browser: opcode byte, then the message.
      if (payload[0] === OP_TEXT && payload.subarray(1).toString() === 'ping') {
        const reply = Buffer.concat([Buffer.from([OP_TEXT]), Buffer.from('pong')]);
        ws.send(frame(id, reply));
      }
      return;
    }
    const msg = JSON.parse(data.toString());
    switch (msg.t) {
      case 'ping':
        ws.send(JSON.stringify({ t: 'pong' }));
        break;
      case 'req':
        if (msg.path === '/api/hello') {
          respond(ws, msg.id, 200, { 'content-type': 'text/plain', 'set-cookie': ['a=1', 'b=2'] }, [Buffer.from('hello from HA')]);
        } else if (msg.path === '/api/echo') {
          echoBodies.set(msg.id, []);
        }
        break;
      case 'end':
        if (echoBodies.has(msg.id)) {
          const chunks = echoBodies.get(msg.id);
          echoBodies.delete(msg.id);
          respond(ws, msg.id, 200, { 'content-type': 'application/octet-stream' }, chunks);
        }
        break;
      case 'ws_open':
        ws.send(JSON.stringify({ t: 'ws_accept', id: msg.id }));
        break;
      default:
        break;
    }
  });
}

/** A request with an explicit Host header, the way a customer's browser would send it through the relay. */
function publicRequest({ sub, path, method = 'GET', body }) {
  return new Promise((resolve, reject) => {
    const headers = { 'x-mdt-dev-host': `${sub}.${DOMAIN}` };
    if (body !== undefined) headers['content-length'] = Buffer.byteLength(body);
    const req = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }),
      );
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function once(emitter, event) {
  return new Promise((resolve) => emitter.once(event, resolve));
}

// --- the test ---------------------------------------------------------------

test('tunnel: link, proxy HTTP and WebSocket, unlink, relink', async () => {
  const email = `tunnel-${Date.now()}@example.test`;

  // 1. Link the home and connect HA.
  const first = await linkHome(email);
  const sub = first.subdomain;
  assert.match(sub, /^[a-z0-9]{10}$/);

  // 2. Before HA connects, the instance is offline.
  assert.equal((await publicRequest({ sub, path: '/api/hello' })).status, 503);

  const ha = await connectHa(first.tunnel_token);
  fakeHa(ha);
  await new Promise((r) => setTimeout(r, 300));

  // 3. HTTP GET, with repeated headers preserved.
  const hello = await publicRequest({ sub, path: '/api/hello' });
  assert.equal(hello.status, 200);
  assert.equal(hello.body, 'hello from HA');
  assert.deepEqual(hello.headers['set-cookie'], ['a=1', 'b=2']);

  // 4. HTTP POST body goes up and comes back.
  const echo = await publicRequest({ sub, path: '/api/echo', method: 'POST', body: 'abc123' });
  assert.equal(echo.status, 200);
  assert.equal(echo.body, 'abc123');

  // 5. WebSocket through the tunnel: text out, text back.
  const browser = new WebSocket(`ws://127.0.0.1:${PORT}/api/websocket`, { headers: { 'x-mdt-dev-host': `${sub}.${DOMAIN}` } });
  await once(browser, 'open');
  const reply = once(browser, 'message');
  browser.send('ping');
  const data = await reply;
  assert.equal(data.toString(), 'pong');
  browser.close();

  // 6. Unlink: the tunnel closes, the token stops working, and the instance goes offline.
  const haClosed = once(ha, 'close');
  const unlink = await fetch(`${BASE}/v1/ha/unlink`, {
    method: 'POST',
    headers: { authorization: `Bearer ${first.tunnel_token}` },
  });
  assert.equal(unlink.status, 200);
  const code = await haClosed;
  assert.equal(code, 4001);
  assert.equal((await publicRequest({ sub, path: '/api/hello' })).status, 503);
  await assert.rejects(connectHa(first.tunnel_token), /status 401/);

  // 7. Relink with Replace: a new token and the same subdomain, and HA works again.
  const second = await linkHome(email, true);
  assert.equal(second.subdomain, sub);
  assert.notEqual(second.tunnel_token, first.tunnel_token);
  const ha2 = await connectHa(second.tunnel_token);
  fakeHa(ha2);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal((await publicRequest({ sub, path: '/api/hello' })).body, 'hello from HA');
  ha2.close();
});

async function adminSubscription(token, body) {
  return fetch(`${BASE}/v1/admin/subscription`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("subscription: suspend blocks access, reconnect is refused, activate restores", async () => {
  const email = `billing-${Date.now()}@example.test`;
  const link = await linkHome(email);
  const sub = link.subdomain;

  // The trial starts at first link, so the home works right away.
  const ha = await connectHa(link.tunnel_token);
  fakeHa(ha);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal((await publicRequest({ sub, path: "/api/hello" })).status, 200);

  // Wrong admin token is refused.
  assert.equal((await adminSubscription("wrong", { email, action: "suspend" })).status, 401);

  // Operator suspends the home. Public traffic stops at once.
  const suspend = await adminSubscription("testadmin", { email, action: "suspend" });
  assert.equal(suspend.status, 200, await suspend.clone().text());
  assert.equal((await publicRequest({ sub, path: "/api/hello" })).status, 402);

  // Reconnecting after a suspension is refused.
  ha.close();
  await new Promise((r) => setTimeout(r, 300));
  await assert.rejects(connectHa(link.tunnel_token), /status 403/);

  // Operator activates the home with a paid-until date. Access returns.
  const paidUntil = Math.floor(Date.now() / 1000) + 30 * 86400;
  const activate = await adminSubscription("testadmin", { email, action: "activate", paid_until: paidUntil });
  assert.equal(activate.status, 200, await activate.clone().text());
  const ha2 = await connectHa(link.tunnel_token);
  fakeHa(ha2);
  await new Promise((r) => setTimeout(r, 300));
  assert.equal((await publicRequest({ sub, path: "/api/hello" })).status, 200);
  ha2.close();
});

test("admin: homes list needs the token and shows access status", async () => {
  const email = `homes-${Date.now()}@example.test`;
  const link = await linkHome(email);

  const denied = await fetch(`${BASE}/v1/admin/homes`, { headers: { authorization: "Bearer wrong" } });
  assert.equal(denied.status, 401);

  const res = await fetch(`${BASE}/v1/admin/homes`, { headers: { authorization: "Bearer testadmin" } });
  assert.equal(res.status, 200);
  const { homes } = await res.json();
  const row = homes.find((h) => h.subdomain === link.subdomain);
  assert.ok(row, "the new home is listed");
  assert.equal(row.email, email);
  assert.equal(row.subscription_status, "trialing");
  assert.ok(row.trial_ends_at > Date.now() / 1000, "trial runs into the future");
});
