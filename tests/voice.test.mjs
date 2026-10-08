// End-to-end test of voice fulfillment against a local relay. A fake Home Assistant answers the
// voice frames over the tunnel (PROTOCOL.md section 2.5), and the test calls the Google and Alexa
// routes the way the platforms do, with an OAuth access token from account linking. Run with `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

const PORT = 8796;
const BASE = `http://127.0.0.1:${PORT}`;
const ORIGIN = 'https://relay.mdtronix.online';
const ADMIN_TOKEN = 'testadmin';
const GOOGLE = {
  clientId: 'google-test-client',
  clientSecret: 'google-test-secret',
  redirect: 'https://oauth-redirect.googleusercontent.com/r/mdtronix-ha-85262',
};
const ALEXA = {
  clientId: 'alexa-test-client',
  clientSecret: 'alexa-test-secret',
  redirect: 'https://pitangui.amazon.com/api/skill/link/M23Q7Y64C1HJD4',
};
const cwd = fileURLToPath(new URL('..', import.meta.url));

let dev;
// One linked home for most tests (each still gets its own OAuth grant). Offline and suspension tests link their own.
let shared;

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
      '--var', `ALEXA_CLIENT_ID:${ALEXA.clientId}`,
      '--var', `ALEXA_CLIENT_SECRET:${ALEXA.clientSecret}`,
      '--var', `ADMIN_TOKEN:${ADMIN_TOKEN}`,
    ],
    { cwd, shell: true, stdio: 'ignore' },
  );
  await waitForHealth();
  const cookie = await login(`voice-shared-${Date.now()}@example.test`);
  shared = { cookie, link: await linkHome(cookie) };
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

async function linkHome(cookie) {
  const d = await (await fetch(`${BASE}/v1/ha/device`, { method: 'POST' })).json();
  const approve = await fetch(`${BASE}/link`, {
    method: 'POST',
    headers: { origin: ORIGIN, cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ user_code: d.user_code }),
    redirect: 'manual',
  });
  assert.equal(approve.status, 200, 'approval accepted');
  const t = await fetch(`${BASE}/v1/ha/device/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ device_code: d.device_code }),
  });
  assert.equal(t.status, 200, await t.clone().text());
  return t.json();
}

/** Runs the account linking consent and returns an OAuth access token for the platform. */
async function accessToken(cookie, platform) {
  const client = platform === 'google' ? GOOGLE : ALEXA;
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: client.redirect,
    response_type: 'code',
    state: 'state-voice',
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
  assert.ok(code, 'consent issued a code');

  const exchange = await fetch(`${BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: client.redirect,
      code_verifier: verifier,
      client_id: client.clientId,
      client_secret: client.clientSecret,
    }),
  });
  assert.equal(exchange.status, 200, await exchange.clone().text());
  return (await exchange.json()).access_token;
}

/**
 * A stand-in for Home Assistant on the tunnel. It answers voice frames with `reply(frame)`, which returns
 * {status, body}, or null to stay silent. `caps` controls whether the client announces voice support.
 */
function connectHome(tunnelToken, { caps = ['voice'], reply } = {}) {
  const received = [];
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/v1/tunnel`, {
      headers: { authorization: `Bearer ${tunnelToken}`, 'x-mdt-protocol': '1' },
    });
    ws.on('unexpected-response', (_req, res) => reject(new Error(`status ${res.statusCode}`)));
    ws.on('error', reject);
    ws.on('message', (data, isBinary) => {
      if (isBinary) return;
      const msg = JSON.parse(data.toString());
      if (msg.t === 'ping') ws.send(JSON.stringify({ t: 'pong' }));
      if (msg.t !== 'voice') return;
      received.push(msg);
      const answer = reply ? reply(msg) : { status: 200, body: JSON.stringify({ echoed: JSON.parse(msg.body) }) };
      if (answer) ws.send(JSON.stringify({ t: 'voice_res', id: msg.id, status: answer.status, body: answer.body }));
    });
    ws.on('open', () => {
      ws.send(JSON.stringify({ t: 'hello', v: 1, caps }));
      resolve({ ws, received, close: () => ws.close() });
    });
  });
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function voiceRequest(path, token, body) {
  return fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function googleIntent(intent, extra = {}) {
  return { requestId: `req-${intent}`, inputs: [{ intent, ...extra }] };
}

function alexaDiscovery(token) {
  return {
    directive: {
      header: { namespace: 'Alexa.Discovery', name: 'Discover', payloadVersion: '3', messageId: 'm-1' },
      payload: { scope: { type: 'BearerToken', token } },
    },
  };
}

function alexaTurnOn(token) {
  return {
    directive: {
      header: { namespace: 'Alexa.PowerController', name: 'TurnOn', payloadVersion: '3', messageId: 'm-2' },
      endpoint: { endpointId: 'switch.kitchen', scope: { type: 'BearerToken', token } },
      payload: {},
    },
  };
}

// --- Google Home ----------------------------------------------------------

test('google: SYNC is forwarded to the home, agentUserId is set by the relay, and no token leaves the relay', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token, {
    reply: () => ({ status: 200, body: JSON.stringify({ requestId: 'req-x', payload: { agentUserId: 'from-home', devices: [{ id: 'switch.kitchen' }] } }) }),
  });
  try {
    const token = await accessToken(cookie, 'google');
    const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
    assert.equal(res.status, 200, await res.clone().text());
    const doc = await res.json();
    assert.equal(doc.payload.agentUserId, link.subdomain, 'the relay overrides agentUserId');
    assert.deepEqual(doc.payload.devices, [{ id: 'switch.kitchen' }]);

    assert.equal(home.received.length, 1);
    assert.equal(home.received[0].platform, 'google');
    assert.deepEqual(JSON.parse(home.received[0].body), googleIntent('action.devices.SYNC'));
    assert.ok(!home.received[0].body.includes(token), 'the access token is not forwarded');
  } finally {
    home.close();
  }
});

test('google: QUERY and EXECUTE pass through unchanged', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token, {
    reply: () => ({ status: 200, body: JSON.stringify({ requestId: 'r', payload: { devices: { 'switch.kitchen': { on: true, online: true } } } }) }),
  });
  try {
    const token = await accessToken(cookie, 'google');
    const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.QUERY', { payload: { devices: [{ id: 'switch.kitchen' }] } }));
    assert.equal(res.status, 200);
    const doc = await res.json();
    assert.deepEqual(doc.payload.devices, { 'switch.kitchen': { on: true, online: true } });
    assert.equal(doc.payload.agentUserId, undefined, 'only SYNC gets agentUserId');
  } finally {
    home.close();
  }
});

test('google: missing, wrong-platform, and unknown tokens are refused', async () => {
  const { cookie } = shared;
  const alexaToken = await accessToken(cookie, 'alexa');

  const none = await fetch(`${BASE}/v1/voice/google`, { method: 'POST', body: '{}' });
  assert.equal(none.status, 401);
  assert.equal((await voiceRequest('/v1/voice/google', alexaToken, googleIntent('action.devices.SYNC'))).status, 401);
  assert.equal((await voiceRequest('/v1/voice/google', 'not-a-token', googleIntent('action.devices.SYNC'))).status, 401);
});

test('google: DISCONNECT revokes the grant, so the same token stops working', async () => {
  const { cookie } = shared;
  const token = await accessToken(cookie, 'google');

  const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.DISCONNECT'));
  assert.equal(res.status, 200);
  const after = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
  assert.equal(after.status, 401);
});

// --- Alexa ----------------------------------------------------------------

test('alexa: discovery token is removed before the home sees the directive', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token, {
    reply: () => ({ status: 200, body: JSON.stringify({ event: { header: { name: 'Discover.Response' }, payload: { endpoints: [] } } }) }),
  });
  try {
    const token = await accessToken(cookie, 'alexa');
    const res = await voiceRequest('/v1/voice/alexa', token, alexaDiscovery(token));
    assert.equal(res.status, 200, await res.clone().text());
    assert.equal((await res.json()).event.header.name, 'Discover.Response');

    assert.equal(home.received.length, 1);
    assert.equal(home.received[0].platform, 'alexa');
    const forwarded = JSON.parse(home.received[0].body);
    assert.equal(forwarded.directive.payload.scope.type, 'BearerToken');
    assert.equal('token' in forwarded.directive.payload.scope, false, 'the token is removed');
    assert.ok(!home.received[0].body.includes(token));
  } finally {
    home.close();
  }
});

test('alexa: a directive with the token in endpoint.scope is forwarded without it, and bad tokens are refused', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token);
  try {
    const token = await accessToken(cookie, 'alexa');
    const res = await voiceRequest('/v1/voice/alexa', token, alexaTurnOn(token));
    assert.equal(res.status, 200);
    const forwarded = JSON.parse(home.received[0].body);
    assert.equal('token' in forwarded.directive.endpoint.scope, false);
    assert.equal(forwarded.directive.endpoint.endpointId, 'switch.kitchen');

    const bad = await voiceRequest('/v1/voice/alexa', 'wrong', alexaTurnOn('wrong'));
    assert.equal(bad.status, 401);
    const noScope = await voiceRequest('/v1/voice/alexa', token, { directive: { header: { namespace: 'Alexa' } } });
    assert.equal(noScope.status, 401);
  } finally {
    home.close();
  }
});

// --- Failure cases shared by both platforms -------------------------------

test('voice: a malformed body is rejected with 400', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token);
  try {
    const token = await accessToken(cookie, 'google');
    const res = await fetch(`${BASE}/v1/voice/google`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: 'not json',
    });
    assert.equal(res.status, 400);
  } finally {
    home.close();
  }
});

test('voice: when the home is offline, the platform gets 503 home_offline', async () => {
  const cookie = await login(`voice-offline-${Date.now()}@example.test`);
  await linkHome(cookie);
  const token = await accessToken(cookie, 'google');
  const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'home_offline');
});

test('voice: a home without voice support gets 503 voice_unsupported', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token, { caps: [] });
  try {
    const token = await accessToken(cookie, 'google');
    const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, 'voice_unsupported');
    assert.equal(home.received.length, 0);
  } finally {
    home.close();
  }
});

test('voice: a home that does not answer in time gets 504 home_timeout', async () => {
  const { cookie, link } = shared;
  const home = await connectHome(link.tunnel_token, { reply: () => null });
  try {
    const token = await accessToken(cookie, 'google');
    const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
    assert.equal(res.status, 504);
    assert.equal((await res.json()).error, 'home_timeout');
  } finally {
    home.close();
  }
});

test('voice: a suspended home is refused with 402 and the platform sees no device data', async () => {
  const email = `voice-suspended-${Date.now()}@example.test`;
  const cookie = await login(email);
  const link = await linkHome(cookie);
  const home = await connectHome(link.tunnel_token);
  const token = await accessToken(cookie, 'google');

  const suspend = await fetch(`${BASE}/v1/admin/subscription`, {
    method: 'POST',
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ email, action: 'suspend' }),
  });
  assert.equal(suspend.status, 200, await suspend.clone().text());
  await wait(200);

  try {
    const res = await voiceRequest('/v1/voice/google', token, googleIntent('action.devices.SYNC'));
    assert.equal(res.status, 402);
    assert.equal(home.received.length, 0, 'nothing is sent to the home while suspended');
  } finally {
    home.close();
  }
});
