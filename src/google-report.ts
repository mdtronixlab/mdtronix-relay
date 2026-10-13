// Proactive state reporting for Google Home (Home Graph reportStateAndNotification). Unlike Alexa, there's
// no per-customer grant: Google authorizes by which project the Smart Home Action belongs to, using one
// service account for the whole mdtronix-cloud project. So the access token is shared across every home,
// not per-customer — cached in a single row, refreshed with Google's OAuth2 JWT-bearer grant when it's
// near expiry. A home only needs to prove it's a real, active home (its tunnel token) to borrow it.
//
// https://developers.google.com/assistant/smarthome/develop/report-state
// https://developers.google.com/identity/protocols/oauth2/service-account

import type { Env } from './env';
import { bearer, homeForTunnelToken } from './tunnel';
import { json, jsonError } from './http';
import { nowSeconds, signGoogleServiceAccountJwt } from './crypto';

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const HOMEGRAPH_SCOPE = 'https://www.googleapis.com/auth/homegraph';
const TOKEN_SINGLETON_ID = 'singleton';
// Refetch a bit before the token's real expiry, so a borrowed token never goes stale mid-request.
const EXPIRY_SAFETY_MARGIN_S = 60;

interface GoogleTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/** Signs a fresh JWT-bearer assertion and exchanges it with Google for a Home Graph access token. */
async function fetchHomegraphToken(env: Env): Promise<{ accessToken: string; expiresIn: number } | null> {
  if (!env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL || !env.GOOGLE_HOMEGRAPH_PRIVATE_KEY) return null;

  const now = nowSeconds();
  const assertion = await signGoogleServiceAccountJwt(env.GOOGLE_HOMEGRAPH_PRIVATE_KEY, {
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

/**
 * GET /v1/ha/google-report-token. Authenticated by the home's own tunnel token (the same bearer it
 * already holds to attach the tunnel) — just to confirm the caller is a real, active home. The token
 * returned isn't scoped to that home: Home Graph authorizes by project, not by customer, so any active
 * home can borrow the one shared token. 503 if the service account secrets haven't been set yet.
 */
export async function googleReportToken(request: Request, env: Env): Promise<Response> {
  const token = bearer(request);
  const home = token ? await homeForTunnelToken(env, token) : null;
  if (!home) return jsonError(401, 'unauthorized');

  if (!env.GOOGLE_HOMEGRAPH_CLIENT_EMAIL || !env.GOOGLE_HOMEGRAPH_PRIVATE_KEY) {
    return jsonError(503, 'not_configured');
  }

  const row = await env.CUSTOMERS.prepare('SELECT access_token, expires_at FROM google_homegraph_token WHERE id = ?')
    .bind(TOKEN_SINGLETON_ID)
    .first<{ access_token: string; expires_at: number }>();

  const now = nowSeconds();
  if (row && row.expires_at - EXPIRY_SAFETY_MARGIN_S > now) {
    return json(200, { access_token: row.access_token, token_type: 'Bearer', expires_in: row.expires_at - now });
  }

  const fresh = await fetchHomegraphToken(env);
  if (!fresh) return jsonError(502, 'google_token_unavailable');

  await env.CUSTOMERS.prepare(
    `INSERT INTO google_homegraph_token (id, access_token, expires_at) VALUES (?, ?, ?)
     ON CONFLICT (id) DO UPDATE SET access_token = excluded.access_token, expires_at = excluded.expires_at`,
  )
    .bind(TOKEN_SINGLETON_ID, fresh.accessToken, now + fresh.expiresIn)
    .run();

  return json(200, { access_token: fresh.accessToken, token_type: 'Bearer', expires_in: fresh.expiresIn });
}
