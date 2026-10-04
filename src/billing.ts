// Access rule for a home's tunnel. Payment is manual: the operator activates or suspends from the admin API.
//
//   trialing  -> access until trial_ends_at (3 months from the first link)
//   active    -> access until current_period_end plus a 7-day grace period
//   canceled  -> suspended by the operator, no access

import { nowSeconds } from './crypto';

export const TRIAL_SECONDS = 90 * 86400;
export const GRACE_SECONDS = 7 * 86400;

export interface SubscriptionRow {
  status: string;
  trial_ends_at: number | null;
  current_period_end: number | null;
}

/** Whether a subscription allows the tunnel at `now`. Pure, so it's easy to test. */
export function allowsAccess(sub: SubscriptionRow | null, now: number): boolean {
  if (!sub) return false;
  if (sub.status === 'trialing') return sub.trial_ends_at !== null && now < sub.trial_ends_at;
  if (sub.status === 'active') return sub.current_period_end !== null && now < sub.current_period_end + GRACE_SECONDS;
  return false;
}

/** Statement that starts a 3-month trial for a newly linked customer. Runs in the same batch as the instance insert. */
export function startTrialStatement(db: D1Database, customerId: string, now: number): D1PreparedStatement {
  return db
    .prepare(
      `INSERT OR IGNORE INTO subscriptions (customer_id, status, trial_ends_at, updated_at)
       VALUES (?, 'trialing', ?, ?)`,
    )
    .bind(customerId, now + TRIAL_SECONDS, now);
}

/** Whether the home with this subdomain currently has access. */
export async function instanceHasAccess(db: D1Database, subdomain: string, now = nowSeconds()): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT s.status, s.trial_ends_at, s.current_period_end
       FROM instances i JOIN subscriptions s ON s.customer_id = i.customer_id
       WHERE i.subdomain = ?`,
    )
    .bind(subdomain)
    .first<SubscriptionRow>();
  return allowsAccess(row, now);
}
