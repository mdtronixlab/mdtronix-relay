// Browser side: customer sessions and the local-only dev login. HA's own login goes straight to
// src/ha_login.ts now, with no browser step.

import { nowSeconds, randomId, randomToken, sha256Hex } from './crypto';
import type { Env } from './env';
import { isApprovedEmail } from './approval';
import { redirect, safeNext, SESSION_COOKIE, setCookie, clearCookie, readCookie, json } from './http';

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
