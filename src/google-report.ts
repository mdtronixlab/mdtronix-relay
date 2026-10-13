// Proactive state reporting for Google Home (Home Graph reportStateAndNotification). Unlike Alexa, there's
// no per-customer grant: Google authorizes by which project the Smart Home Action belongs to, using one
// service account for the whole mdtronix-cloud project. The access token is shared across every home, not
// per-customer — cached in a single row, refreshed with Google's OAuth2 JWT-bearer grant when it's near
// expiry.
//
// The relay makes the actual Home Graph call itself, rather than handing HA the shared bearer token: Home
// Graph trusts whatever agentUserId is in the request body, and a home's own subdomain (its agentUserId)
// isn't a secret, so if HA held the token directly, any one compromised or malicious home could forge a
// state report for a *different* customer's agentUserId. Keeping the call here means agentUserId always
// comes from the authenticated tunnel token, never from anything the caller supplies.
//
// https://developers.google.com/assistant/smarthome/develop/report-state
// https://developers.google.com/identity/protocols/oauth2/service-account

import type { Env } from './env';
import { bearer, homeForTunnelToken } from './tunnel';
import { jsonError } from './http';
import { nowSeconds, randomId, signGoogleServiceAccountJwt } from './crypto';

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const HOMEGRAPH_SCOPE = 'https://www.googleapis.com/auth/homegraph';
const REPORT_STATE_URL = 'https://homegraph.googleapis.com/v1/devices:reportStateAndNotification';
const TOKEN_SINGLETON_ID = 'singleton';
// Refetch a bit before the token's real expiry, so a borrowed token never goes stale mid-request.
const EXPIRY_SAFETY_MARGIN_S = 60;
// A state report is just a handful of device traits; this is generous headroom, not a real limit in practice.
const MAX_REPORT_STATE_BYTES = 64 * 1024;

interface GoogleTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/** Signs a fresh JWT-bearer assertion and exchanges it with Google for a Home Graph access token. */
async function fetchHomegraphToken(env: Env): Promise<{ accessToken: string; expiresIn: number } | null> {
  const now = nowSeconds();
  const assertion = await signGoogleServiceAccountJwt(env.GOOGLE_HOMEGRAPH_PRIVATE_KEY as string, {
    iss: env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL,
    scope: HOMEGRAPH_SCOPE,
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600,
  });

  let data: GoogleTokenResponse;
  try {
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
    });
    if (!res.ok) {
      console.error('homegraph token exchange failed', res.status, await res.text());
      return null;
    }
    data = (await res.json()) as GoogleTokenResponse;
  } catch {
    return null;
  }
  return { accessToken: data.access_token, expiresIn: data.expires_in };
}

/** The shared Home Graph access token, from cache if still fresh, or refreshed and re-cached otherwise. */
async function homegraphToken(env: Env): Promise<string | null> {
  const row = await env.CUSTOMERS.prepare('SELECT access_token, expires_at FROM google_homegraph_token WHERE id = ?')
    .bind(TOKEN_SINGLETON_ID)
    .first<{ access_token: string; expires_at: number }>();

  const now = nowSeconds();
  if (row && row.expires_at - EXPIRY_SAFETY_MARGIN_S > now) return row.access_token;

  const fresh = await fetchHomegraphToken(env);
  if (!fresh) return null;

  await env.CUSTOMERS.prepare(
    `INSERT INTO google_homegraph_token (id, access_token, expires_at) VALUES (?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET access_token = excluded.access_token, expires_at = excluded.expires_at`,
  )
    .bind(TOKEN_SINGLETON_ID, fresh.accessToken, now + fresh.expiresIn)
    .run();
  return fresh.accessToken;
}

/**
 * POST /v1/ha/google-report-state. Authenticated by the home's own tunnel token (the same bearer it
 * already holds to attach the tunnel). Body: { payload: <Home Graph payload object>, requestId?: string }.
 * Calls Home Graph's reportStateAndNotification with agentUserId set to *this* authenticated home's own
 * subdomain — never read from the request body — and relays back Google's status code and body.
 */
export async function googleReportState(request: Request, env: Env): Promise<Response> {
  const token = bearer(request);
  const home = token ? await homeForTunnelToken(env, token) : null;
  if (!home) return jsonError(401, 'unauthorized');

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_REPORT_STATE_BYTES) return jsonError(413, 'request_too_large');
  let body: { payload?: unknown; requestId?: unknown };
  try {
    body = JSON.parse(raw) as { payload?: unknown; requestId?: unknown };
  } catch {
    return jsonError(400, 'invalid_request');
  }
  if (typeof body.payload !== 'object' || body.payload === null) return jsonError(400, 'invalid_request');
  const requestId = typeof body.requestId === 'string' && body.requestId ? body.requestId : randomId();

  if (!env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL || !env.GOOGLE_HOMEGRAPH_PRIVATE_KEY) {
    return jsonError(503, 'not_configured');
  }

  const accessToken = await homegraphToken(env);
  if (!accessToken) return jsonError(502, 'google_token_unavailable');

  let res: Response;
  try {
    res = await fetch(REPORT_STATE_URL, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ requestId, agentUserId: home.instance, payload: body.payload }),
    });
  } catch {
    return jsonError(502, 'homegraph_unreachable');
  }
  const text = await res.text();
  return new Response(text, { status: res.status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}
