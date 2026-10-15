// Operator API for activating and suspending homes. Called by the CRM with a secret bearer token.
//
//   POST /v1/admin/subscription
//   { "email": "...", "action": "activate", "paid_until": <unix seconds> }
//   { "email": "...", "action": "suspend" }

import { approveEmail, isApprovedEmail, listApprovedEmails, revokeApprovedEmail } from './approval';
import { constantTimeEqual, nowSeconds, randomId, randomToken, sha256Hex } from './crypto';
import type { Env } from './env';
import { json, jsonError } from './http';
import { hashPassword } from './password';
import { invalidatePendingResetTokens, MIN_PASSWORD_LENGTH } from './password_auth';
import { revokeAllSessions } from './web';

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

/**
 * GET /v1/admin/pending-customers. Registered customers who aren't on the approved_emails allowlist yet,
 * newest first. Without this, a customer who registers on the website before staff pre-approved them (the
 * normal flow — see approved_emails's comment) is invisible to the CRM: they have no instance yet (an
 * unapproved customer can never reach HA login to get one), so handleAdminHomes never shows them either.
 */
export async function handleAdminPendingCustomers(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  const rows = await env.CUSTOMERS.prepare(
    `SELECT c.email, c.status AS account_status, c.created_at
     FROM customers c
     WHERE NOT EXISTS (SELECT 1 FROM approved_emails a WHERE a.email = c.email)
     ORDER BY c.created_at DESC
     LIMIT 500`,
  ).all();
  return json(200, { customers: rows.results });
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
 * Sets or replaces a customer's password directly, with staff choosing and reading out the new password
 * themselves — the quickest path for a legacy (pre-password-auth, Google-linked) account or a locked-out
 * customer on a call. See handleGenerateResetLink below for the alternative where the customer sets their
 * own password instead of staff choosing it for them. Doesn't touch approval status; staff still approve
 * the email separately, same as always.
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
  const customer = await env.CUSTOMERS.prepare('SELECT id FROM customers WHERE email = ?').bind(email).first<{ id: string }>();
  if (!customer) return jsonError(404, 'not_found');

  await env.CUSTOMERS.prepare('UPDATE customers SET password_hash = ?, updated_at = ? WHERE id = ?')
    .bind(await hashPassword(body.password), nowSeconds(), customer.id)
    .run();
  // A reset should lock out whoever has the old session, not just whoever doesn't know the new password.
  await revokeAllSessions(env.CUSTOMERS, customer.id);
  // ...and invalidate any reset link staff sent earlier, so it can't later overwrite this password too.
  await invalidatePendingResetTokens(env.CUSTOMERS, customer.id);
  return json(200, { ok: true });
}

const RESET_TOKEN_TTL_SECONDS = 24 * 3600;

/**
 * POST /v1/admin/generate-reset-link. { "email": "..." }
 *
 * Staff confirm the request is really the customer's — outside this system, however staff normally reach
 * them — then generate a link here and send it themselves over that same channel. There's no email sending
 * anywhere in this relay, so the link is never dispatched automatically. It's valid once, for 24 hours.
 * Generating a new one invalidates any earlier unused link for the same customer, so only the latest one
 * staff actually sent is still live.
 *
 * Refuses an unapproved email (403 not_approved): a reset link signs the customer straight in once used,
 * so generating one is itself a way to grant access — it must respect the same approval gate as every
 * other way to sign in, not create a path around it. (validResetToken in password_auth.ts re-checks this
 * at redemption too, in case approval is revoked after the link is sent.)
 */
export async function handleGenerateResetLink(request: Request, env: Env): Promise<Response> {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;

  let body: { email?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_json');
  }
  if (typeof body.email !== 'string' || !body.email.includes('@')) return jsonError(400, 'invalid_email');

  const email = body.email.trim().toLowerCase();
  const customer = await env.CUSTOMERS.prepare('SELECT id FROM customers WHERE email = ?').bind(email).first<{ id: string }>();
  if (!customer) return jsonError(404, 'not_found');
  if (!(await isApprovedEmail(env.CUSTOMERS, email))) return jsonError(403, 'not_approved');

  const now = nowSeconds();
  await invalidatePendingResetTokens(env.CUSTOMERS, customer.id);

  const token = randomToken(32);
  await env.CUSTOMERS.prepare(
    'INSERT INTO password_reset_tokens (id, customer_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
  )
    .bind(randomId(), customer.id, await sha256Hex(token), now + RESET_TOKEN_TTL_SECONDS, now)
    .run();

  return json(200, { url: `${env.PUBLIC_ORIGIN}/reset-password?token=${token}` });
}
