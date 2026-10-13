// Proactive state reporting for Alexa (ChangeReport events). Two separate things happen here:
//
//  1. async_accept_grant handles the Alexa.Authorization/AcceptGrant directive Alexa sends after
//     account linking (because the skill has the "Send Alexa Events" permission). It exchanges the
//     one-time grant code for a per-customer refresh token, using the skill's LWA client id/secret,
//     and stores it. This is answered directly here and never reaches the home.
//  2. alexaReportToken hands Home Assistant a fresh access token for that same per-customer grant,
//     so it can call the Event Gateway directly when an exposed entity changes. Authenticated by
//     the home's own tunnel token, so HA never needs a separate credential for this.
//
// The skill's LWA client id/secret never leaves the relay. Per-customer refresh tokens are stored
// in full (not hashed), because the relay is the OAuth *client* here and must present them back to
// Amazon itself.
//
// https://developer.amazon.com/en-US/docs/alexa/device-apis/alexa-authorization.html
// https://developer.amazon.com/en-US/docs/alexa/smarthome/state-reporting-for-a-smart-home-skill.html

import type { Env } from './env';
import { homeForTunnelToken, bearer } from './tunnel';
import { json, jsonError } from './http';
import { nowSeconds } from './crypto';

const LWA_TOKEN_URL = 'https://api.amazon.com/auth/o2/token';
// Refetch a bit before the real expiry, so a borrowed token never goes stale mid-request.
const EXPIRY_SAFETY_MARGIN_S = 60;

interface LwaTokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
}

interface AcceptGrantDirective {
  directive?: {
    header?: { namespace?: unknown; name?: unknown; messageId?: unknown };
    payload?: { grant?: { code?: unknown }; grantee?: { token?: unknown } };
  };
}

/** True when this is the one-time grant Alexa sends after account linking, not a normal directive. */
export function isAcceptGrant(doc: AcceptGrantDirective): boolean {
  const header = doc.directive?.header;
  return header?.namespace === 'Alexa.Authorization' && header?.name === 'AcceptGrant';
}

function acceptGrantResponse(messageId: string): Record<string, unknown> {
  return {
    event: {
      header: { namespace: 'Alexa.Authorization', name: 'AcceptGrant.Response', messageId, payloadVersion: '3' },
      payload: {},
    },
  };
}

function acceptGrantError(messageId: string, message: string): Record<string, unknown> {
  return {
    event: {
      header: { namespace: 'Alexa.Authorization', name: 'ErrorResponse', messageId, payloadVersion: '3' },
      payload: { type: 'ACCEPT_GRANT_FAILED', message },
    },
  };
}

/**
 * Answers an Alexa.Authorization/AcceptGrant directive. `resolveCustomerId` looks up the customer
 * for the grantee's bearer token (the relay's own account-linking token, the same lookup every
 * other Alexa directive uses) — kept as a parameter so this module doesn't depend on oauth.ts.
 */
export async function handleAcceptGrant(
  doc: AcceptGrantDirective,
  env: Env,
  resolveCustomerId: (token: string) => Promise<string | null>,
): Promise<Response> {
  const messageId = typeof doc.directive?.header?.messageId === 'string' ? doc.directive.header.messageId : 'unknown';
  const code = doc.directive?.payload?.grant?.code;
  const granteeToken = doc.directive?.payload?.grantee?.token;
  if (typeof code !== 'string' || typeof granteeToken !== 'string') {
    return json(200, acceptGrantError(messageId, 'Malformed AcceptGrant directive.'));
  }

  const customerId = await resolveCustomerId(granteeToken);
  if (!customerId) return json(200, acceptGrantError(messageId, 'Unknown or expired account link.'));
  if (!env.ALEXA_LWA_CLIENT_ID || !env.ALEXA_LWA_CLIENT_SECRET) {
    return json(200, acceptGrantError(messageId, 'Proactive events are not configured.'));
  }

  let data: LwaTokenResponse;
  try {
    const res = await fetch(LWA_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: env.ALEXA_LWA_CLIENT_ID,
        client_secret: env.ALEXA_LWA_CLIENT_SECRET,
      }),
    });
    if (!res.ok) {
      console.error('accept grant exchange failed', res.status, await res.text());
      return json(200, acceptGrantError(messageId, 'Could not exchange the grant with Amazon.'));
    }
    data = (await res.json()) as LwaTokenResponse;
  } catch {
    return json(200, acceptGrantError(messageId, 'Could not reach Amazon to exchange the grant.'));
  }
  if (!data.refresh_token) return json(200, acceptGrantError(messageId, 'Amazon did not return a refresh token.'));

  const now = nowSeconds();
  await env.CUSTOMERS.prepare(
    `INSERT INTO alexa_proactive_grants (customer_id, refresh_token, access_token, access_token_expires_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (customer_id) DO UPDATE SET
       refresh_token = excluded.refresh_token,
       access_token = excluded.access_token,
       access_token_expires_at = excluded.access_token_expires_at,
       updated_at = excluded.updated_at`,
  )
    .bind(customerId, data.refresh_token, data.access_token, now + data.expires_in, now, now)
    .run();

  return json(200, acceptGrantResponse(messageId));
}

/** Refreshes a customer's proactive-events access token with Amazon, and stores the result. */
async function refreshProactiveToken(
  env: Env,
  customerId: string,
  refreshToken: string,
): Promise<{ accessToken: string; expiresIn: number } | null> {
  if (!env.ALEXA_LWA_CLIENT_ID || !env.ALEXA_LWA_CLIENT_SECRET) return null;
  let data: LwaTokenResponse;
  try {
    const res = await fetch(LWA_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: env.ALEXA_LWA_CLIENT_ID,
        client_secret: env.ALEXA_LWA_CLIENT_SECRET,
      }),
    });
    if (!res.ok) {
      console.error('proactive token refresh failed', res.status, await res.text());
      return null;
    }
    data = (await res.json()) as LwaTokenResponse;
  } catch {
    return null;
  }

  const now = nowSeconds();
  await env.CUSTOMERS.prepare(
    `UPDATE alexa_proactive_grants SET access_token = ?, access_token_expires_at = ?, refresh_token = ?, updated_at = ?
     WHERE customer_id = ?`,
  )
    .bind(data.access_token, now + data.expires_in, data.refresh_token ?? refreshToken, now, customerId)
    .run();
  return { accessToken: data.access_token, expiresIn: data.expires_in };
}

/**
 * GET /v1/ha/alexa-report-token. Authenticated by the home's own tunnel token (the same bearer it
 * already holds to attach the tunnel). Returns a per-customer access token for Alexa's Event
 * Gateway, refreshing it with Amazon first if it has expired. 404 if this customer hasn't linked
 * Alexa since the "Send Alexa Events" permission was enabled (no AcceptGrant has arrived yet) —
 * unlinking and relinking the skill resends it.
 */
export async function alexaReportToken(request: Request, env: Env): Promise<Response> {
  const token = bearer(request);
  const home = token ? await homeForTunnelToken(env, token) : null;
  if (!home) return jsonError(401, 'unauthorized');

  const row = await env.CUSTOMERS.prepare(
    'SELECT refresh_token, access_token, access_token_expires_at FROM alexa_proactive_grants WHERE customer_id = ?',
  )
    .bind(home.customerId)
    .first<{ refresh_token: string; access_token: string | null; access_token_expires_at: number | null }>();
  if (!row) return jsonError(404, 'no_proactive_grant');

  const now = nowSeconds();
  if (row.access_token && row.access_token_expires_at && row.access_token_expires_at - EXPIRY_SAFETY_MARGIN_S > now) {
    return json(200, { access_token: row.access_token, token_type: 'Bearer', expires_in: row.access_token_expires_at - now });
  }

  const fresh = await refreshProactiveToken(env, home.customerId, row.refresh_token);
  if (!fresh) return jsonError(502, 'lwa_token_unavailable');
  return json(200, { access_token: fresh.accessToken, token_type: 'Bearer', expires_in: fresh.expiresIn });
}
