// Voice fulfillment for Google Home and Alexa. The platforms call these routes with the OAuth access
// token from account linking. The relay checks the token and the platform, then hands the request to
// the customer's Home Assistant over its tunnel (PROTOCOL.md section 2.5). The home does the device
// translation, so this file doesn't know about entities.

import { MAX_VOICE_REQUEST_BYTES, type VoicePlatform } from './frames';
import type { Env } from './env';
import { json, jsonError } from './http';
import { bearer } from './tunnel';
import { customerForAccessToken, revokeGrantForAccessToken } from './oauth';
import { handleAcceptGrant, isAcceptGrant } from './alexa-events';

const GOOGLE_SYNC = 'action.devices.SYNC';
const GOOGLE_DISCONNECT = 'action.devices.DISCONNECT';

async function instanceFor(env: Env, customerId: string): Promise<string | null> {
  const row = await env.CUSTOMERS.prepare('SELECT subdomain FROM instances WHERE customer_id = ?')
    .bind(customerId)
    .first<{ subdomain: string }>();
  return row?.subdomain ?? null;
}

/** Reads a request body, or null when it is larger than a voice request may be. */
async function readBody(request: Request): Promise<string | null> {
  const text = await request.text();
  return new TextEncoder().encode(text).byteLength > MAX_VOICE_REQUEST_BYTES ? null : text;
}

/** Passes one request to the home's Durable Object, which sends it over the tunnel and answers with the home's reply. */
function askHome(env: Env, subdomain: string, platform: VoicePlatform, body: string): Promise<Response> {
  const stub = env.TUNNEL.get(env.TUNNEL.idFromName(subdomain));
  return stub.fetch('https://do.internal/__voice', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-mdt-instance': subdomain },
    body: JSON.stringify({ platform, body }),
  });
}

/** POST /v1/voice/google. Google sends SYNC, QUERY, EXECUTE, and DISCONNECT intents here. */
export async function googleFulfillment(request: Request, env: Env): Promise<Response> {
  const token = bearer(request);
  const customer = token ? await customerForAccessToken(env.CUSTOMERS, token) : null;
  if (!token || !customer || customer.platform !== 'google') return jsonError(401, 'invalid_token');

  const text = await readBody(request);
  if (text === null) return jsonError(413, 'request_too_large');
  let intent: unknown;
  try {
    intent = (JSON.parse(text) as { inputs?: Array<{ intent?: unknown }> }).inputs?.[0]?.intent;
  } catch {
    return jsonError(400, 'invalid_request');
  }

  // Google calls DISCONNECT when the user unlinks the account in the Google Home app.
  if (intent === GOOGLE_DISCONNECT) {
    await revokeGrantForAccessToken(env.CUSTOMERS, token);
    return new Response(null, { status: 200 });
  }

  const subdomain = await instanceFor(env, customer.customerId);
  if (!subdomain) return jsonError(404, 'no_instance');

  const reply = await askHome(env, subdomain, 'google', text);
  if (intent !== GOOGLE_SYNC || reply.status !== 200) return reply;

  // Google identifies the account by agentUserId. The relay sets it to the home's subdomain, which
  // never changes, so the home doesn't need to know which account it belongs to.
  let doc: { payload?: Record<string, unknown> };
  try {
    doc = (await reply.json()) as { payload?: Record<string, unknown> };
  } catch {
    return jsonError(502, 'bad_home_reply');
  }
  doc.payload = { ...doc.payload, agentUserId: subdomain };
  return json(200, doc);
}

interface AlexaScope {
  token?: unknown;
}

interface AlexaDirective {
  directive?: {
    header?: { namespace?: unknown; name?: unknown; messageId?: unknown };
    endpoint?: { scope?: AlexaScope };
    // `scope` is the shape every normal directive uses; `grant`/`grantee` only appear on AcceptGrant.
    payload?: { scope?: AlexaScope; grant?: { code?: unknown }; grantee?: { token?: unknown } };
  };
}

/** POST /v1/voice/alexa. Alexa sends every Smart Home directive here, including discovery. */
export async function alexaDirective(request: Request, env: Env): Promise<Response> {
  const text = await readBody(request);
  if (text === null) return jsonError(413, 'request_too_large');

  let doc: AlexaDirective;
  try {
    doc = JSON.parse(text) as AlexaDirective;
  } catch {
    return jsonError(400, 'invalid_request');
  }

  // Alexa sends this once, right after account linking, because the skill has the "Send Alexa
  // Events" permission. It carries its own bearer token (payload.grantee.token) rather than the
  // endpoint/payload.scope shape every other directive uses, and it's answered here directly —
  // the home has no part in it.
  if (isAcceptGrant(doc)) {
    return handleAcceptGrant(doc, env, (token) => customerForAccessToken(env.CUSTOMERS, token).then((c) => c?.customerId ?? null));
  }

  // Discovery carries the token in payload.scope, other directives in endpoint.scope.
  const scopes = [doc.directive?.endpoint?.scope, doc.directive?.payload?.scope];
  const tokenScope = scopes.find((s) => typeof s?.token === 'string');
  const token = typeof tokenScope?.token === 'string' ? tokenScope.token : null;
  const customer = token ? await customerForAccessToken(env.CUSTOMERS, token) : null;
  if (!token || !customer || customer.platform !== 'alexa') return jsonError(401, 'invalid_token');

  // The home doesn't need the token, so it doesn't leave the relay.
  for (const scope of scopes) {
    if (scope) delete scope.token;
  }

  const subdomain = await instanceFor(env, customer.customerId);
  if (!subdomain) return jsonError(404, 'no_instance');

  return askHome(env, subdomain, 'alexa', JSON.stringify(doc));
}
