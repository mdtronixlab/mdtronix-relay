// Tunnel routes: Home Assistant attaches, can unlink, and public traffic for an instance is
// proxied through its Durable Object.

import { nowSeconds, sha256Hex } from './crypto';
import type { Env } from './env';
import { json, jsonError } from './http';
import { PROTOCOL_VERSION } from './frames';
import { instanceHasAccess } from './billing';

const INSTANCE_LABEL = /^[a-z0-9]{10}$/;

export function bearer(request: Request): string | null {
  const header = request.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  return match ? match[1] : null;
}

/** Subdomain of a request host, or null if the host isn't an instance host. */
export function instanceFromHost(host: string, instanceDomain: string): string | null {
  const name = host.split(':')[0].toLowerCase();
  const suffix = `.${instanceDomain}`;
  if (!name.endsWith(suffix)) return null;
  const label = name.slice(0, -suffix.length);
  return INSTANCE_LABEL.test(label) ? label : null;
}

/** The instance a live, unrevoked token belongs to, if its customer is active. */
async function instanceForToken(env: Env, token: string): Promise<string | null> {
  const row = await env.CUSTOMERS.prepare(
    `SELECT t.instance FROM tunnel_tokens t
     JOIN instances i ON i.subdomain = t.instance
     JOIN customers c ON c.id = i.customer_id
     WHERE t.token_hash = ? AND t.revoked_at IS NULL AND c.status = 'active'`,
  )
    .bind(await sha256Hex(token))
    .first<{ instance: string }>();
  return row?.instance ?? null;
}

/** Closes the live tunnel for an instance, if one is connected. */
export async function closeTunnel(env: Env, subdomain: string): Promise<void> {
  const stub = env.TUNNEL.get(env.TUNNEL.idFromName(subdomain));
  await stub.fetch('https://do.internal/__close', { method: 'POST' });
}

/** GET /v1/tunnel (WebSocket upgrade). */
export async function attachTunnel(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
    return jsonError(426, 'expected_websocket');
  }
  if (request.headers.get('x-mdt-protocol') !== String(PROTOCOL_VERSION)) {
    return jsonError(426, 'unsupported_protocol');
  }
  const token = bearer(request);
  const instance = token ? await instanceForToken(env, token) : null;
  if (!instance) return jsonError(401, 'unauthorized');
  if (!(await instanceHasAccess(env.CUSTOMERS, instance))) return jsonError(403, 'subscription_inactive');

  const stub = env.TUNNEL.get(env.TUNNEL.idFromName(instance));
  return stub.fetch(
    new Request('https://do.internal/__attach', {
      headers: { upgrade: 'websocket', 'x-mdt-instance': instance },
    }),
  );
}

/** POST /v1/ha/unlink. Revokes the token, closes the tunnel, and keeps the subdomain reserved. */
export async function unlink(request: Request, env: Env): Promise<Response> {
  const token = bearer(request);
  const instance = token ? await instanceForToken(env, token) : null;
  if (!instance) return jsonError(401, 'unauthorized');

  await env.CUSTOMERS.prepare('UPDATE tunnel_tokens SET revoked_at = ? WHERE instance = ? AND revoked_at IS NULL')
    .bind(nowSeconds(), instance)
    .run();
  await closeTunnel(env, instance);
  return json(200, { ok: true });
}

/** Disconnects this customer's Home Assistant from the account page. True if one was connected. */
export async function unlinkForCustomer(env: Env, customerId: string): Promise<boolean> {
  const instance = await env.CUSTOMERS.prepare('SELECT subdomain FROM instances WHERE customer_id = ?')
    .bind(customerId)
    .first<{ subdomain: string }>();
  if (!instance) return false;

  await env.CUSTOMERS.prepare('UPDATE tunnel_tokens SET revoked_at = ? WHERE instance = ? AND revoked_at IS NULL')
    .bind(nowSeconds(), instance.subdomain)
    .run();
  await closeTunnel(env, instance.subdomain);
  return true;
}

/** Public traffic to <subdomain>.<INSTANCE_DOMAIN>, forwarded to Home Assistant over its tunnel. */
export async function proxyToInstance(request: Request, env: Env, subdomain: string): Promise<Response> {
  // Access is checked inside the tunnel object, where it is cached, so this path makes no database query.
  const url = new URL(request.url);
  const stub = env.TUNNEL.get(env.TUNNEL.idFromName(subdomain));
  const forwarded = new Request(`https://do.internal/__proxy${url.pathname}${url.search}`, request);
  forwarded.headers.set('x-mdt-instance', subdomain);
  return stub.fetch(forwarded);
}
