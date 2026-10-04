// Operator API for activating and suspending homes. Called by the CRM with a secret bearer token.
//
//   POST /v1/admin/subscription
//   { "email": "...", "action": "activate", "paid_until": <unix seconds> }
//   { "email": "...", "action": "suspend" }

import { constantTimeEqual, nowSeconds } from './crypto';
import type { Env } from './env';
import { json, jsonError } from './http';

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
  return json(200, { ok: true });
}
