// Browser side: customer sessions, the /link page where a customer approves an HA login,
// and the local-only dev login.

import { nowSeconds, normalizeUserCode, randomId, randomToken, sha256Hex } from './crypto';
import type { Env } from './env';
import { isApprovedEmail } from './approval';
import { esc, html, redirect, safeNext, SESSION_COOKIE, setCookie, clearCookie, readCookie, json } from './http';
import { checkLimit, clientKey } from './ratelimit';

const SESSION_DAYS = 14;

export async function createSession(db: D1Database, customerId: string): Promise<string> {
  const token = randomToken(32);
  const now = nowSeconds();
  await db
    .prepare('INSERT INTO web_sessions (id, customer_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(randomId(), customerId, await sha256Hex(token), now, now + SESSION_DAYS * 86400)
    .run();
  return token;
}

export function sessionCookie(token: string): string {
  return setCookie(SESSION_COOKIE, token, SESSION_DAYS * 86400);
}

/** The signed-in active customer, or null. */
export async function signedInCustomer(request: Request, db: D1Database): Promise<{ id: string; email: string } | null> {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await db
    .prepare(
      `SELECT c.id, c.email, c.status FROM web_sessions s
       JOIN customers c ON c.id = s.customer_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND s.revoked_at IS NULL`,
    )
    .bind(await sha256Hex(token), nowSeconds())
    .first<{ id: string; email: string; status: string }>();
  if (!row || row.status !== 'active') return null;
  return { id: row.id, email: row.email };
}

/** Ends the browser's session: revokes the session row, so a copied cookie stops working too. */
export async function signOut(request: Request, db: D1Database): Promise<string[]> {
  const token = readCookie(request, SESSION_COOKIE);
  if (token) {
    await db
      .prepare('UPDATE web_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
      .bind(nowSeconds(), await sha256Hex(token))
      .run();
  }
  return [clearCookie(SESSION_COOKIE)];
}

function signInRedirect(next: string): Response {
  return redirect(`/v1/auth/google/start?next=${encodeURIComponent(next)}`);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; color: #111; }
input[type=text] { font-size: 1.4rem; letter-spacing: .15em; text-transform: uppercase; padding: .5rem; width: 100%; box-sizing: border-box; }
button { font-size: 1rem; padding: .6rem 1.2rem; margin-top: 1rem; }
.err { color: #b00020; }
</style></head><body>${body}</body></html>`;
}

/** GET /link. Shows the code form, or sends the customer to Google sign-in first. */
export async function linkPage(request: Request, env: Env): Promise<Response> {
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return signInRedirect('/link');

  const prefill = esc(normalizeUserCode(new URL(request.url).searchParams.get('code') ?? '').slice(0, 8));
  return html(
    200,
    page(
      'Connect Home Assistant',
      `<h1>Connect Home Assistant</h1>
<p>Enter the code shown in Home Assistant.</p>
<form method="post" action="/link">
  <input type="text" name="user_code" value="${prefill}" autocomplete="off" maxlength="9" required>
  <p><label><input type="checkbox" name="replace"> Replace the Home Assistant I connected before</label></p>
  <button type="submit">Connect</button>
</form>`,
    ),
  );
}

/** POST /link. Approves a pending device code for the signed-in customer. */
export async function approveDevice(request: Request, env: Env): Promise<Response> {
  // The session cookie is SameSite=Lax, so this origin check is the CSRF guard for this POST.
  if (request.headers.get('origin') !== env.PUBLIC_ORIGIN) {
    return html(403, page('Not allowed', '<p class="err">This request came from another site.</p>'));
  }

  const limited = await checkLimit(env, 'RL_APPROVE', clientKey(request));
  if (limited) return limited;

  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return signInRedirect('/link');

  const form = await request.formData();
  const code = normalizeUserCode(String(form.get('user_code') ?? ''));
  const replace = form.get('replace') === 'on';
  const now = nowSeconds();

  const row = await env.CUSTOMERS.prepare(
    'SELECT id, status, expires_at FROM device_codes WHERE user_code_hash = ?',
  )
    .bind(await sha256Hex(code))
    .first<{ id: string; status: string; expires_at: number }>();
  if (!row || row.status !== 'pending' || row.expires_at <= now) {
    return html(400, page('Code not found', '<p class="err">That code is wrong or has expired. Start again in Home Assistant.</p>'));
  }

  const existing = await env.CUSTOMERS.prepare('SELECT 1 FROM instances WHERE customer_id = ?')
    .bind(customer.id)
    .first();
  if (existing && !replace) {
    return html(
      409,
      page(
        'Already connected',
        '<p class="err">This account already has a connected Home Assistant. Tick "Replace" to connect this one instead.</p>',
      ),
    );
  }

  await env.CUSTOMERS.prepare(
    "UPDATE device_codes SET status = 'approved', customer_id = ?, replace = ? WHERE id = ? AND status = 'pending'",
  )
    .bind(customer.id, replace ? 1 : 0, row.id)
    .run();

  return html(200, page('Approved', '<h1>Approved</h1><p>You can return to Home Assistant.</p>'));
}

/**
 * GET /v1/dev/login?email=…. Signs in a test customer with no Google account.
 * Returns 404 unless DEV_LOGIN is "true", which is only set in the local .dev.vars file.
 */
export async function devLogin(request: Request, env: Env): Promise<Response> {
  if (env.DEV_LOGIN !== 'true') return new Response('not found', { status: 404 });

  const email = (new URL(request.url).searchParams.get('email') ?? 'dev@example.test').toLowerCase();
  const now = nowSeconds();
  await env.CUSTOMERS.prepare(
    `INSERT INTO customers (id, google_sub, email, email_verified, status, created_at, updated_at, last_login_at)
     VALUES (?, ?, ?, 1, 'active', ?, ?, ?)
     ON CONFLICT(google_sub) DO UPDATE SET updated_at = excluded.updated_at, last_login_at = excluded.last_login_at`,
  )
    .bind(randomId(), `dev:${email}`, email, now, now, now)
    .run();
  const customer = await env.CUSTOMERS.prepare('SELECT id FROM customers WHERE google_sub = ?')
    .bind(`dev:${email}`)
    .first<{ id: string }>();
  if (!customer) return new Response('no customer', { status: 500 });

  const token = await createSession(env.CUSTOMERS, customer.id);
  return redirect(safeNext(new URL(request.url).searchParams.get('next')), [sessionCookie(token)]);
}

/**
 * GET /v1/dev/approved?email=…. Reads the approval allowlist so tests can check it without going
 * through Google sign-in. Dev login itself doesn't check this list, on purpose: it's a convenience
 * for signing in test accounts, not something that should also need pre-approval in every test.
 * Returns 404 unless DEV_LOGIN is "true", which is only set in the local .dev.vars file.
 */
export async function devApprovedCheck(request: Request, env: Env): Promise<Response> {
  if (env.DEV_LOGIN !== 'true') return new Response('not found', { status: 404 });
  const email = new URL(request.url).searchParams.get('email') ?? '';
  return json(200, { approved: await isApprovedEmail(env.CUSTOMERS, email) });
}
