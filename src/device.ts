// HA login via device authorization (RFC 8628). HA never sees a password or a Google credential.
// Flow: HA POSTs /v1/ha/device, shows user_code, polls /v1/ha/device/token. The customer
// approves the code at /link in a browser.

import { nowSeconds, normalizeUserCode, randomId, randomToken, randomUserCode, sha256Hex } from './crypto';
import type { Env } from './env';
import { json, jsonError } from './http';
import { checkLimit, clientKey } from './ratelimit';
import { issueInstance } from './instance';

const CODE_TTL_SECONDS = 900;
const POLL_INTERVAL_SECONDS = 5;
const SLOW_DOWN_STEP_SECONDS = 5;

interface DeviceRow {
  id: string;
  status: 'pending' | 'approved' | 'used';
  customer_id: string | null;
  replace: number;
  interval_s: number;
  last_polled_at: number | null;
  expires_at: number;
}

/** POST /v1/ha/device */
export async function createDeviceCode(request: Request, env: Env): Promise<Response> {
  const limited = await checkLimit(env, 'RL_DEVICE', clientKey(request));
  if (limited) return limited;
  const deviceCode = randomToken(32);
  const userCode = randomUserCode();
  const now = nowSeconds();

  await env.CUSTOMERS.prepare(
    `INSERT INTO device_codes (id, device_code_hash, user_code_hash, status, replace, interval_s, last_polled_at, expires_at, created_at)
     VALUES (?, ?, ?, 'pending', 0, ?, NULL, ?, ?)`,
  )
    .bind(
      randomId(),
      await sha256Hex(deviceCode),
      await sha256Hex(normalizeUserCode(userCode)),
      POLL_INTERVAL_SECONDS,
      now + CODE_TTL_SECONDS,
      now,
    )
    .run();

  return json(200, {
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${env.PUBLIC_ORIGIN}/link`,
    verification_uri_complete: `${env.PUBLIC_ORIGIN}/link?code=${userCode}`,
    expires_in: CODE_TTL_SECONDS,
    interval: POLL_INTERVAL_SECONDS,
  });
}

/** POST /v1/ha/device/token. Returns the tunnel token once the customer has approved the code. */
export async function pollDeviceToken(request: Request, env: Env): Promise<Response> {
  let body: { device_code?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_request');
  }
  if (typeof body.device_code !== 'string') return jsonError(400, 'invalid_request');
  const deviceHash = await sha256Hex(body.device_code);
  const limited = await checkLimit(env, 'RL_POLL', deviceHash);
  if (limited) return limited;

  const db = env.CUSTOMERS;
  const now = nowSeconds();
  const row = await db
    .prepare(
      'SELECT id, status, customer_id, replace, interval_s, last_polled_at, expires_at FROM device_codes WHERE device_code_hash = ?',
    )
    .bind(deviceHash)
    .first<DeviceRow>();
  if (!row) return jsonError(400, 'invalid_grant');

  if (row.expires_at <= now) {
    await db.prepare('DELETE FROM device_codes WHERE id = ?').bind(row.id).run();
    return jsonError(400, 'expired_token');
  }

  // Polling faster than the interval gets slow_down and a longer interval, as RFC 8628 requires.
  if (row.last_polled_at !== null && now - row.last_polled_at < row.interval_s) {
    await db
      .prepare('UPDATE device_codes SET interval_s = ?, last_polled_at = ? WHERE id = ?')
      .bind(row.interval_s + SLOW_DOWN_STEP_SECONDS, now, row.id)
      .run();
    return jsonError(400, 'slow_down');
  }
  await db.prepare('UPDATE device_codes SET last_polled_at = ? WHERE id = ?').bind(now, row.id).run();

  if (row.status === 'pending') return jsonError(400, 'authorization_pending');
  if (row.status === 'used' || !row.customer_id) return jsonError(400, 'invalid_grant');

  // Claim the code before issuing, so two concurrent polls can't both get a token.
  const claim = await db
    .prepare("UPDATE device_codes SET status = 'used' WHERE id = ? AND status = 'approved'")
    .bind(row.id)
    .run();
  if (claim.meta.changes !== 1) return jsonError(400, 'invalid_grant');

  const customer = await db
    .prepare('SELECT status FROM customers WHERE id = ?')
    .bind(row.customer_id)
    .first<{ status: string }>();
  if (!customer || customer.status !== 'active') return jsonError(403, 'account_suspended');

  const issued = await issueInstance(env, row.customer_id, row.replace === 1);
  if (!issued.ok) return jsonError(issued.status, issued.error);
  return json(200, issued.body);
}
