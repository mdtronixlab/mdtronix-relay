// Google sign-in for customers: OpenID Connect with authorization code and PKCE.
// No Firebase. The relay is a direct OAuth client of Google.

import { base64UrlToBytes, bytesToBase64Url, hmacSign, hmacVerify, nowSeconds, randomId, randomToken, sha256Base64Url } from './crypto';
import type { Env } from './env';
import { clearCookie, html, redirect, readCookie, safeNext, setCookie, STATE_COOKIE } from './http';
import { createSession, sessionCookie } from './web';
import { checkLimit, clientKey } from './ratelimit';

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const STATE_TTL_SECONDS = 600;

interface SignInState {
  state: string;
  nonce: string;
  verifier: string;
  next: string;
  exp: number;
}

interface IdTokenClaims {
  iss: string;
  aud: string;
  exp: number;
  nonce?: string;
  sub: string;
  email: string;
  email_verified: boolean;
}

function callbackUrl(env: Env): string {
  return `${env.PUBLIC_ORIGIN}/v1/auth/google/callback`;
}

/** GET /v1/auth/google/start. Sets a signed state cookie and redirects to Google. */
export async function startSignIn(request: Request, env: Env): Promise<Response> {
  const limited = await checkLimit(env, 'RL_LOGIN', clientKey(request));
  if (limited) return limited;
  const next = safeNext(new URL(request.url).searchParams.get('next'));
  const verifier = randomToken(32);
  const state: SignInState = {
    state: randomToken(16),
    nonce: randomToken(16),
    verifier,
    next,
    exp: nowSeconds() + STATE_TTL_SECONDS,
  };

  const encoded = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(state)));
  const cookieValue = `${encoded}.${await hmacSign(env.SESSION_SECRET, encoded)}`;

  const url = new URL(AUTH_URL);
  url.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: callbackUrl(env),
    response_type: 'code',
    scope: 'openid email profile',
    state: state.state,
    nonce: state.nonce,
    code_challenge: await sha256Base64Url(verifier),
    code_challenge_method: 'S256',
    prompt: 'select_account',
  }).toString();

  return redirect(url.toString(), [setCookie(STATE_COOKIE, cookieValue, STATE_TTL_SECONDS)]);
}

async function verifyIdToken(idToken: string, clientId: string, expectedNonce: string): Promise<IdTokenClaims> {
  const [headerPart, payloadPart, signaturePart] = idToken.split('.');
  if (!headerPart || !payloadPart || !signaturePart) throw new Error('malformed id_token');

  const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerPart))) as { alg?: string; kid?: string };
  if (header.alg !== 'RS256' || !header.kid) throw new Error('unexpected id_token header');

  const jwks = (await (await fetch(JWKS_URL)).json()) as { keys: Array<JsonWebKey & { kid?: string }> };
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown signing key');

  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    base64UrlToBytes(signaturePart),
    new TextEncoder().encode(`${headerPart}.${payloadPart}`),
  );
  if (!valid) throw new Error('bad id_token signature');

  const claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadPart))) as IdTokenClaims;
  if (claims.iss !== 'https://accounts.google.com' && claims.iss !== 'accounts.google.com') throw new Error('bad issuer');
  if (claims.aud !== clientId) throw new Error('bad audience');
  if (claims.exp <= nowSeconds()) throw new Error('expired id_token');
  if (claims.nonce !== expectedNonce) throw new Error('bad nonce');
  if (claims.email_verified !== true) throw new Error('email not verified');
  return claims;
}

function failure(): Response {
  return html(
    400,
    '<!doctype html><meta charset="utf-8"><title>Sign-in failed</title><p>Sign-in failed. Start again from Home Assistant.</p>',
    [clearCookie(STATE_COOKIE)],
  );
}

/** GET /v1/auth/google/callback. Exchanges the code, verifies the ID token, and starts a session. */
export async function finishSignIn(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  const raw = readCookie(request, STATE_COOKIE);
  const [encoded, signature] = raw?.split('.') ?? [];
  if (!encoded || !signature || !(await hmacVerify(env.SESSION_SECRET, encoded, signature))) return failure();

  const state = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encoded))) as SignInState;
  if (state.exp <= nowSeconds() || state.state !== url.searchParams.get('state')) return failure();

  const code = url.searchParams.get('code');
  if (!code) return failure();

  try {
    const tokenRes = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: callbackUrl(env),
        grant_type: 'authorization_code',
        code_verifier: state.verifier,
      }),
    });
    if (!tokenRes.ok) return failure();
    const tokens = (await tokenRes.json()) as { id_token?: string };
    if (!tokens.id_token) return failure();

    const claims = await verifyIdToken(tokens.id_token, env.GOOGLE_CLIENT_ID, state.nonce);

    const now = nowSeconds();
    await env.CUSTOMERS.prepare(
      `INSERT INTO customers (id, google_sub, email, email_verified, status, created_at, updated_at, last_login_at)
       VALUES (?, ?, ?, 1, 'active', ?, ?, ?)
       ON CONFLICT(google_sub) DO UPDATE SET
         email = excluded.email,
         updated_at = excluded.updated_at,
         last_login_at = excluded.last_login_at`,
    )
      .bind(randomId(), claims.sub, claims.email.toLowerCase(), now, now, now)
      .run();

    const customer = await env.CUSTOMERS.prepare('SELECT id, status FROM customers WHERE google_sub = ?')
      .bind(claims.sub)
      .first<{ id: string; status: string }>();
    if (!customer) return failure();
    if (customer.status !== 'active') {
      return html(403, '<!doctype html><meta charset="utf-8"><p>This account is suspended. Contact support.</p>', [
        clearCookie(STATE_COOKIE),
      ]);
    }

    const token = await createSession(env.CUSTOMERS, customer.id);
    return redirect(state.next, [clearCookie(STATE_COOKIE), sessionCookie(token)]);
  } catch (err) {
    // Log the reason for debugging. Never log tokens or cookies.
    console.warn('google sign-in failed:', err instanceof Error ? err.message : 'unknown');
    return failure();
  }
}
