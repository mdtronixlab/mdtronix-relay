// Tests for the Alexa forwarding Lambda, with the relay replaced by a stub fetch. Run with `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handler, errorTypeForStatus } from './index.mjs';

const directive = {
  header: { namespace: 'Alexa.PowerController', name: 'TurnOn', payloadVersion: '3', messageId: 'm-1', correlationToken: 'tok' },
  endpoint: { endpointId: 'switch#kitchen' },
  payload: {},
};
const event = { directive };

function stubFetch(status, body) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
  };
  return { fn, calls };
}

test('forwards the directive to the relay and returns its answer', async () => {
  const reply = { event: { header: { name: 'Response' } } };
  const { fn, calls } = stubFetch(200, reply);
  const result = await handler(event, null, { fetch: fn, relayUrl: 'https://relay.example/v1/voice/alexa' });

  assert.deepEqual(result, reply);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://relay.example/v1/voice/alexa');
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), event);
});

test('uses the default relay URL when none is set', async () => {
  const { fn, calls } = stubFetch(200, { event: {} });
  await handler(event, null, { fetch: fn });
  assert.equal(calls[0].url, 'https://relay.mdtronix.online/v1/voice/alexa');
});

test('a 401 from the relay becomes INVALID_AUTHORIZATION_CREDENTIAL, keeping the request id and endpoint', async () => {
  const { fn } = stubFetch(401, { error: 'invalid_token' });
  const result = await handler(event, null, { fetch: fn });

  assert.equal(result.event.header.name, 'ErrorResponse');
  assert.equal(result.event.header.correlationToken, 'tok');
  assert.equal(result.event.header.messageId, 'm-1');
  assert.equal(result.event.payload.type, 'INVALID_AUTHORIZATION_CREDENTIAL');
  assert.deepEqual(result.event.endpoint, { endpointId: 'switch#kitchen' });
});

test('an unreachable home (503 or 504) becomes ENDPOINT_UNREACHABLE', async () => {
  for (const status of [503, 504]) {
    const { fn } = stubFetch(status, { error: 'home_offline' });
    const result = await handler(event, null, { fetch: fn });
    assert.equal(result.event.payload.type, 'ENDPOINT_UNREACHABLE');
  }
});

test('a network failure becomes ENDPOINT_UNREACHABLE', async () => {
  const fn = async () => {
    throw new TypeError('fetch failed');
  };
  const result = await handler(event, null, { fetch: fn });
  assert.equal(result.event.payload.type, 'ENDPOINT_UNREACHABLE');
});

test('an unreadable reply becomes INTERNAL_ERROR', async () => {
  const { fn } = stubFetch(200, 'not json');
  const result = await handler(event, null, { fetch: fn });
  assert.equal(result.event.payload.type, 'INTERNAL_ERROR');
});

test('a directive without a request id still gets an error with a message id', async () => {
  const { fn } = stubFetch(500, {});
  const result = await handler({ directive: {} }, null, { fetch: fn });
  assert.equal(result.event.payload.type, 'INTERNAL_ERROR');
  assert.equal(typeof result.event.header.messageId, 'string');
});

test('status mapping', () => {
  assert.equal(errorTypeForStatus(401), 'INVALID_AUTHORIZATION_CREDENTIAL');
  assert.equal(errorTypeForStatus(402), 'ENDPOINT_UNREACHABLE');
  assert.equal(errorTypeForStatus(500), 'INTERNAL_ERROR');
});
