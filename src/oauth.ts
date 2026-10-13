// OAuth 2.0 account linking for Google Home and Alexa: authorization code with PKCE (S256), refresh tokens,
// and revocation. The customer signs in with the relay's own session, then approves the platform on a
// consent page. Platforms then exchange the code for tokens at /oauth/token.
// Access tokens and refresh tokens are stored as hashes only.

import { base64UrlToBytes, constantTimeEqual, nowSeconds, randomId, randomToken, sha256Base64Url, sha256Hex } from './crypto';
import type { Env } from './env';
import { esc, html, json, jsonError, redirect } from './http';
import { PLATFORMS, platformForClientId, secretForPlatform, type Platform } from './oauth-clients';
import { signedInCustomer } from './web';

const CODE_TTL_SECONDS = 60;
export const ACCESS_TTL_SECONDS = 3600;

interface AuthParams {
  platform: Platform;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string | null;
}

type ParseResult = { ok: true; value: AuthParams } | { ok: false; message: string };

// Alexa's account linking sends PKCE and is required to. Google's own account-linking flow (the Google
// Home app, replacing the legacy Actions on Google redirect) authenticates with its client secret alone
// and never sends a code_challenge, so PKCE is accepted there but not required.
const PKCE_REQUIRED: Record<Platform, boolean> = { alexa: true, google: false };

/** Validates an authorization request. A bad client or redirect URI is never redirected to. */
function parseAuthParams(params: URLSearchParams, env: Env): ParseResult {
  const clientId = params.get('client_id') ?? '';
  const platform = platformForClientId(env, clientId);
  if (!platform) return { ok: false, message: 'Unknown client.' };

  const redirectUri = params.get('redirect_uri') ?? '';
  if (!PLATFORMS[platform].redirectUris.includes(redirectUri)) {
    return { ok: false, message: 'The redirect address does not match this platform.' };
  }
  if (params.get('response_type') !== 'code') return { ok: false, message: 'Only response_type=code is supported.' };

  // An empty string (e.g. a round-tripped hidden form field for a request that never had PKCE) counts
  // as absent, same as a missing param.
  const codeChallenge = params.get('code_challenge') || null;
  if (codeChallenge) {
    if (params.get('code_challenge_method') !== 'S256') {
      return { ok: false, message: 'PKCE with S256 is required.' };
    }
  } else if (PKCE_REQUIRED[platform]) {
    return { ok: false, message: 'PKCE with S256 is required.' };
  }
  return {
    ok: true,
    value: {
      platform,
      clientId,
      redirectUri,
      state: params.get('state') ?? '',
      codeChallenge,
    },
  };
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; color: #111; }
button { font-size: 1rem; padding: .6rem 1.2rem; margin: .5rem .5rem 0 0; }
.err { color: #b00020; }
</style></head><body>${body}</body></html>`;
}

function redirectWithParams(base: string, params: Record<string, string>): Response {
  const target = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    if (value) target.searchParams.set(key, value);
  }
  return redirect(target.toString());
}

/** GET /oauth/authorize: the consent page, or sign-in first. */
export async function authorizeGet(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const parsed = parseAuthParams(url.searchParams, env);
  if (!parsed.ok) return html(400, page('Cannot link', `<p class="err">${esc(parsed.message)}</p>`));

  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return redirect(`/login?next=${encodeURIComponent(url.pathname + url.search)}`);

  const v = parsed.value;
  const platformName = PLATFORMS[v.platform].name;
  return html(
    200,
    page(
      `Link ${platformName}`,
      `<h1>Link ${esc(platformName)}</h1>
<p>${esc(platformName)} will be able to control the devices in your Home Assistant through MDtronix.</p>
<form method="post" action="/oauth/authorize">
  <input type="hidden" name="client_id" value="${esc(v.clientId)}">
  <input type="hidden" name="redirect_uri" value="${esc(v.redirectUri)}">
  <input type="hidden" name="state" value="${esc(v.state)}">
  <input type="hidden" name="code_challenge" value="${esc(v.codeChallenge ?? '')}">
  <input type="hidden" name="code_challenge_method" value="${v.codeChallenge ? 'S256' : ''}">
  <input type="hidden" name="response_type" value="code">
  <button type="submit" name="decision" value="allow">Allow</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>`,
    ),
  );
}

/** POST /oauth/authorize: the customer's decision. Allowing creates a single-use code. */
export async function authorizePost(request: Request, env: Env): Promise<Response> {
  // The session cookie is SameSite=Lax, so this origin check is the CSRF guard.
  if (request.headers.get('origin') !== env.PUBLIC_ORIGIN) {
    return html(403, page('Not allowed', '<p class="err">This request came from another site.</p>'));
  }
  const form = await request.formData();
  const params = new URLSearchParams();
  for (const key of ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'response_type']) {
    params.set(key, String(form.get(key) ?? ''));
  }
  const parsed = parseAuthParams(params, env);
  if (!parsed.ok) return html(400, page('Cannot link', `<p class="err">${esc(parsed.message)}</p>`));
  const v = parsed.value;

  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return redirect(`/oauth/authorize?${params.toString()}`);

  if (form.get('decision') !== 'allow') {
    return redirectWithParams(v.redirectUri, { error: 'access_denied', state: v.state });
  }

  const code = randomToken(32);
  const now = nowSeconds();
  await env.CUSTOMERS.prepare(
    `INSERT INTO oauth_codes (id, code_hash, platform, customer_id, redirect_uri, code_challenge, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(randomId(), await sha256Hex(code), v.platform, customer.id, v.redirectUri, v.codeChallenge, now + CODE_TTL_SECONDS, now)
    .run();

  return redirectWithParams(v.redirectUri, { code, state: v.state });
}

/** Client authentication: HTTP Basic or form fields. Returns the platform, or null when it fails. */
async function authenticateClient(request: Request, form: FormData, env: Env): Promise<Platform | null> {
  let clientId = String(form.get('client_id') ?? '');
  let clientSecret = String(form.get('client_secret') ?? '');
  const header = request.headers.get('authorization') ?? '';
  if (header.startsWith('Basic ')) {
    const decoded = new TextDecoder().decode(base64UrlToBytes(header.slice(6).replace(/\+/g, '-').replace(/\//g, '_')));
    const idx = decoded.indexOf(':');
    if (idx > 0) {
      clientId = decodeURIComponent(decoded.slice(0, idx));
      clientSecret = decodeURIComponent(decoded.slice(idx + 1));
    }
  }
  const platform = platformForClientId(env, clientId);
  if (!platform) return null;
  const expected = secretForPlatform(env, platform);
  if (!expected || !(await constantTimeEqual(clientSecret, expected))) return null;
  return platform;
}

/** Issues an access token for a grant. Returns the raw token. */
async function issueAccessToken(env: Env, grantId: string): Promise<string> {
  const token = randomToken(32);
  const now = nowSeconds();
  await env.CUSTOMERS.prepare(
    'INSERT INTO oauth_access_tokens (id, grant_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(randomId(), grantId, await sha256Hex(token), now + ACCESS_TTL_SECONDS, now)
    .run();
  return token;
}

/** POST /oauth/token: authorization_code and refresh_token grants. */
export async function tokenEndpoint(request: Request, env: Env): Promise<Response> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return jsonError(400, 'invalid_request');
  }
  const platform = await authenticateClient(request, form, env);
  if (!platform) return jsonError(401, 'invalid_client');

  const grantType = String(form.get('grant_type') ?? '');
  if (grantType === 'authorization_code') return exchangeCode(form, platform, env);
  if (grantType === 'refresh_token') return refreshGrant(form, platform, env);
  return jsonError(400, 'unsupported_grant_type');
}

async function exchangeCode(form: FormData, platform: Platform, env: Env): Promise<Response> {
  const code = String(form.get('code') ?? '');
  const redirectUri = String(form.get('redirect_uri') ?? '');
  // Only Alexa's codes carry a PKCE challenge (see PKCE_REQUIRED in parseAuthParams); Google's don't, so
  // a verifier is only required when the stored code actually has a challenge to check it against.
  const verifier = form.get('code_verifier');
  if (!code) return jsonError(400, 'invalid_request');

  const now = nowSeconds();
  const row = await env.CUSTOMERS.prepare(
    'SELECT id, platform, customer_id, redirect_uri, code_challenge, expires_at, used_at FROM oauth_codes WHERE code_hash = ?',
  )
    .bind(await sha256Hex(code))
    .first<{
      id: string;
      platform: string;
      customer_id: string;
      redirect_uri: string;
      code_challenge: string | null;
      expires_at: number;
      used_at: number | null;
    }>();
  if (!row || row.platform !== platform || row.used_at !== null || row.expires_at <= now) {
    return jsonError(400, 'invalid_grant');
  }
  if (row.redirect_uri !== redirectUri) return jsonError(400, 'invalid_grant');
  if (row.code_challenge) {
    if (!verifier || (await sha256Base64Url(String(verifier))) !== row.code_challenge) {
      return jsonError(400, 'invalid_grant');
    }
  }

  // Mark the code used before issuing anything, so a replayed code can't get a second grant.
  const claim = await env.CUSTOMERS.prepare('UPDATE oauth_codes SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .bind(now, row.id)
    .run();
  if (claim.meta.changes !== 1) return jsonError(400, 'invalid_grant');

  // One active link per customer and platform. Linking again replaces the old grant.
  await env.CUSTOMERS.prepare(
    'UPDATE oauth_grants SET revoked_at = ? WHERE customer_id = ? AND platform = ? AND revoked_at IS NULL',
  )
    .bind(now, row.customer_id, platform)
    .run();
  const grantId = randomId();
  const refreshToken = randomToken(32);
  await env.CUSTOMERS.prepare(
    'INSERT INTO oauth_grants (id, customer_id, platform, refresh_token_hash, created_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(grantId, row.customer_id, platform, await sha256Hex(refreshToken), now)
    .run();

  return json(200, {
    access_token: await issueAccessToken(env, grantId),
    token_type: 'Bearer',
    expires_in: ACCESS_TTL_SECONDS,
    refresh_token: refreshToken,
  });
}

async function refreshGrant(form: FormData, platform: Platform, env: Env): Promise<Response> {
  const refreshToken = String(form.get('refresh_token') ?? '');
  if (!refreshToken) return jsonError(400, 'invalid_request');

  const row = await env.CUSTOMERS.prepare(
    `SELECT g.id, g.platform, g.revoked_at, c.status AS account_status
     FROM oauth_grants g JOIN customers c ON c.id = g.customer_id
     WHERE g.refresh_token_hash = ?`,
  )
    .bind(await sha256Hex(refreshToken))
    .first<{ id: string; platform: string; revoked_at: number | null; account_status: string }>();
  if (!row || row.platform !== platform || row.revoked_at !== null) return jsonError(400, 'invalid_grant');
  if (row.account_status !== 'active') return jsonError(400, 'invalid_grant');

  return json(200, {
    access_token: await issueAccessToken(env, row.id),
    token_type: 'Bearer',
    expires_in: ACCESS_TTL_SECONDS,
  });
}

/** POST /oauth/revoke. Always answers 200, as RFC 7009 asks, so it doesn't reveal which tokens exist. */
export async function revokeEndpoint(request: Request, env: Env): Promise<Response> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return jsonError(400, 'invalid_request');
  }
  const platform = await authenticateClient(request, form, env);
  if (!platform) return jsonError(401, 'invalid_client');

  const token = String(form.get('token') ?? '');
  if (token) {
    const hash = await sha256Hex(token);
    const now = nowSeconds();
    await env.CUSTOMERS.prepare(
      'UPDATE oauth_grants SET revoked_at = ? WHERE refresh_token_hash = ? AND platform = ? AND revoked_at IS NULL',
    )
      .bind(now, hash, platform)
      .run();
    await env.CUSTOMERS.prepare(
      `UPDATE oauth_access_tokens SET expires_at = ?
       WHERE token_hash = ? AND grant_id IN (SELECT id FROM oauth_grants WHERE platform = ?)`,
    )
      .bind(now, hash, platform)
      .run();
  }
  return new Response(null, { status: 200, headers: { 'cache-control': 'no-store' } });
}

/**
 * The customer behind an access token, for the voice fulfillment routes.
 * Null when the token is unknown, expired, revoked, or its account isn't active.
 */
export async function customerForAccessToken(
  db: D1Database,
  token: string,
): Promise<{ customerId: string; platform: Platform } | null> {
  const row = await db
    .prepare(
      `SELECT g.customer_id, g.platform FROM oauth_access_tokens a
       JOIN oauth_grants g ON g.id = a.grant_id
       JOIN customers c ON c.id = g.customer_id
       WHERE a.token_hash = ? AND a.expires_at > ? AND g.revoked_at IS NULL AND c.status = 'active'`,
    )
    .bind(await sha256Hex(token), nowSeconds())
    .first<{ customer_id: string; platform: Platform }>();
  return row ? { customerId: row.customer_id, platform: row.platform } : null;
}

/** Which voice platforms this customer currently has linked. Used by the account page. */
export async function linkedPlatforms(db: D1Database, customerId: string): Promise<Record<Platform, boolean>> {
  const rows = await db
    .prepare('SELECT DISTINCT platform FROM oauth_grants WHERE customer_id = ? AND revoked_at IS NULL')
    .bind(customerId)
    .all<{ platform: Platform }>();
  const linked: Record<Platform, boolean> = { google: false, alexa: false };
  for (const row of rows.results ?? []) linked[row.platform] = true;
  return linked;
}

/** Revokes this customer's grants for one platform. Used from the account page, not by the platform itself. */
export async function revokeGrantsForCustomer(db: D1Database, customerId: string, platform: Platform): Promise<void> {
  const now = nowSeconds();
  await db
    .prepare(
      `UPDATE oauth_grants SET revoked_at = ?
       WHERE customer_id = ? AND platform = ? AND revoked_at IS NULL`,
    )
    .bind(now, customerId, platform)
    .run();
  await db
    .prepare(
      `UPDATE oauth_access_tokens SET expires_at = ?
       WHERE grant_id IN (SELECT id FROM oauth_grants WHERE customer_id = ? AND platform = ?)`,
    )
    .bind(now, customerId, platform)
    .run();
}

/** Revokes the grant behind an access token. Used when the platform disconnects (Google's DISCONNECT intent). */
export async function revokeGrantForAccessToken(db: D1Database, token: string): Promise<void> {
  const hash = await sha256Hex(token);
  const now = nowSeconds();
  await db
    .prepare(
      `UPDATE oauth_grants SET revoked_at = ?
       WHERE revoked_at IS NULL AND id IN (SELECT grant_id FROM oauth_access_tokens WHERE token_hash = ?)`,
    )
    .bind(now, hash)
    .run();
  await db
    .prepare('UPDATE oauth_access_tokens SET expires_at = ? WHERE token_hash = ?')
    .bind(now, hash)
    .run();
}
