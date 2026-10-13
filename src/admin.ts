// Operator API for activating and suspending homes. Called by the CRM with a secret bearer token.
//
//   POST /v1/admin/subscription
//   { "email": "...", "action": "activate", "paid_until": <unix seconds> }
//   { "email": "...", "action": "suspend" }

import { approveEmail, listApprovedEmails, revokeApprovedEmail } from './approval';
import { constantTimeEqual, nowSeconds } from './crypto';
import type { Env } from './env';
import { json, jsonError } from './http';
import { hashPassword } from './password';
import { MIN_PASSWORD_LENGTH } from './password_auth';

/** Checks the operator bearer token. Returns an error response, or null when the caller is allowed. */
async function requireAdmin(request: Request, env: Env): Promise<Response | null> {
  if (!env.ADMIN_TOKEN) return jsonError(500, 'server_misconfigured');
  const header = request.headers.get('authorization') ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!(await constantTimeEqual(presented, env.ADMIN_TOKEN))) return jsonError(401, 'unauthorized');
  return null;
}

/** GET /v1/admin/homes. Read-only list of linked homes and their access status, newest first. */
export async function handleAdminHomes(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  const rows = await env.CUSTOMERS.prepare(
    `SELECT c.email, c.status AS account_status, i.subdomain, i.created_at,
            s.status AS subscription_status, s.trial_ends_at, s.current_period_end
     FROM instances i
     JOIN customers c ON c.id = i.customer_id
     LEFT JOIN subscriptions s ON s.customer_id = c.id
     ORDER BY i.created_at DESC
     LIMIT 500`,
  ).all();
  return json(200, { homes: rows.results });
}

export async function handleAdminSubscription(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  let body: { email?: unknown; action?: unknown; paid_until?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_json');
  }
  if (typeof body.email !== 'string') return jsonError(400, 'invalid_request');
  const email = body.email.trim().toLowerCase();
  const now = nowSeconds();

  let result: D1Result;
  if (body.action === 'activate') {
    if (typeof body.paid_until !== 'number' || body.paid_until <= now) return jsonError(400, 'invalid_paid_until');
    result = await env.CUSTOMERS.prepare(
      `UPDATE subscriptions SET status = 'active', current_period_end = ?, updated_at = ?
       WHERE customer_id = (SELECT id FROM customers WHERE email = ?)`,
    )
      .bind(Math.floor(body.paid_until), now, email)
      .run();
  } else if (body.action === 'suspend') {
    result = await env.CUSTOMERS.prepare(
      `UPDATE subscriptions SET status = 'canceled', updated_at = ?
       WHERE customer_id = (SELECT id FROM customers WHERE email = ?)`,
    )
      .bind(now, email)
      .run();
  } else {
    return jsonError(400, 'invalid_action');
  }

  if (result.meta.changes !== 1) return jsonError(404, 'not_found');

  // Clear the cached access decision in the home's tunnel object, so the change applies at once.
  const home = await env.CUSTOMERS.prepare(
    'SELECT i.subdomain FROM instances i JOIN customers c ON c.id = i.customer_id WHERE c.email = ?',
  )
    .bind(email)
    .first<{ subdomain: string }>();
  if (home) {
    const stub = env.TUNNEL.get(env.TUNNEL.idFromName(home.subdomain));
    await stub.fetch('https://do.internal/__invalidate', { method: 'POST' });
  }
  return json(200, { ok: true });
}

/** GET /v1/admin/approved-emails. The current allowlist, newest first. */
export async function handleListApprovedEmails(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  return json(200, { emails: await listApprovedEmails(env.CUSTOMERS) });
}

/**
 * POST /v1/admin/approved-emails
 * { "email": "...", "action": "approve", "note": "..." }   note is optional
 * { "email": "...", "action": "revoke" }
 */
export async function handleSetApprovedEmail(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  let body: { email?: unknown; action?: unknown; note?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_json');
  }
  if (typeof body.email !== 'string' || !body.email.includes('@')) return jsonError(400, 'invalid_email');

  if (body.action === 'approve') {
    const note = typeof body.note === 'string' ? body.note : null;
    await approveEmail(env.CUSTOMERS, body.email, note);
    return json(200, { ok: true });
  }
  if (body.action === 'revoke') {
    const removed = await revokeApprovedEmail(env.CUSTOMERS, body.email);
    return json(removed ? 200 : 404, { ok: removed });
  }
  return jsonError(400, 'invalid_action');
}

/**
 * POST /v1/admin/set-password
 * { "email": "...", "password": "..." }
 *
 * Sets or replaces a customer's password directly — the only way to get a legacy (pre-password-auth,
 * Google-linked) account working, or to help a customer who's locked out, since there's no self-service
 * reset. Doesn't touch approval status; staff still approve the email separately, same as always.
 */
export async function handleSetPassword(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  let body: { email?: unknown; password?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_json');
  }
  if (typeof body.email !== 'string' || !body.email.includes('@')) return jsonError(400, 'invalid_email');
  if (typeof body.password !== 'string' || body.password.length < MIN_PASSWORD_LENGTH) {
    return jsonError(400, 'invalid_password');
  }

  const email = body.email.trim().toLowerCase();
  const result = await env.CUSTOMERS.prepare('UPDATE customers SET password_hash = ?, updated_at = ? WHERE email = ?')
    .bind(await hashPassword(body.password), nowSeconds(), email)
    .run();
  if (result.meta.changes !== 1) return jsonError(404, 'not_found');
  return json(200, { ok: true });
}
