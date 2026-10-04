// One instance per customer account. Used by both HA login paths, so the rules live in one place.

import { issueTunnelToken, nowSeconds, randomId, randomSubdomain } from './crypto';
import type { Env } from './env';
import { startTrialStatement } from './billing';
import { closeTunnel } from './tunnel';

export interface InstanceBody {
  remote_url: string;
  subdomain: string;
  tunnel_token: string;
  tunnel_url: string;
}

export type IssueResult = { ok: true; body: InstanceBody } | { ok: false; status: number; error: string };

async function uniqueSubdomain(db: D1Database): Promise<string> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = randomSubdomain();
    const taken = await db.prepare('SELECT 1 FROM instances WHERE subdomain = ?').bind(candidate).first();
    if (!taken) return candidate;
  }
  throw new Error('could not allocate a unique subdomain');
}

/**
 * Creates the account's instance on first link. A second link needs replace = true,
 * which revokes the old token. The old tunnel stays up until the Durable Object is
 * updated (not yet built).
 */
export async function issueInstance(env: Env, customerId: string, replace: boolean): Promise<IssueResult> {
  const db = env.CUSTOMERS;
  const now = nowSeconds();

  const existing = await db
    .prepare('SELECT subdomain FROM instances WHERE customer_id = ?')
    .bind(customerId)
    .first<{ subdomain: string }>();
  if (existing && !replace) return { ok: false, status: 409, error: 'instance_already_linked' };

  const subdomain = existing?.subdomain ?? (await uniqueSubdomain(db));
  const token = await issueTunnelToken();

  const statements: D1PreparedStatement[] = [];
  if (existing) {
    statements.push(
      db.prepare('UPDATE tunnel_tokens SET revoked_at = ? WHERE instance = ? AND revoked_at IS NULL').bind(now, subdomain),
    );
  } else {
    statements.push(
      db.prepare('INSERT INTO instances (subdomain, customer_id, created_at) VALUES (?, ?, ?)').bind(subdomain, customerId, now),
    );
    statements.push(startTrialStatement(db, customerId, now));
  }
  statements.push(
    db
      .prepare('INSERT INTO tunnel_tokens (id, instance, token_hash, created_at) VALUES (?, ?, ?, ?)')
      .bind(randomId(), subdomain, token.hash, now),
  );
  await db.batch(statements);

  // A replaced token must not keep a live tunnel open.
  if (existing) await closeTunnel(env, subdomain);

  return {
    ok: true,
    body: {
      remote_url: `https://${subdomain}.${env.INSTANCE_DOMAIN}`,
      subdomain,
      tunnel_token: token.token,
      tunnel_url: `wss://${env.TUNNEL_PUBLIC_HOST}/v1/tunnel`,
    },
  };
}
