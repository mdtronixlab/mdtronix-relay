// Rate limits through Cloudflare's rate-limiting binding. Limits are set in wrangler.jsonc.
// Limits fail closed: a missing binding is a deployment fault, so it returns 500 rather than allowing traffic.

import type { Env } from './env';
import { jsonError } from './http';

export type Limiter = 'RL_DEVICE' | 'RL_APPROVE' | 'RL_POLL' | 'RL_LOGIN';

/** Client IP as Cloudflare reports it. Falls back to a shared key when running locally. */
export function clientKey(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'local';
}

/** Returns null when the request is allowed, or a 429 or 500 response to return. */
export async function checkLimit(env: Env, limiter: Limiter, key: string): Promise<Response | null> {
  const binding = env[limiter];
  if (!binding) return jsonError(500, 'server_misconfigured');
  const { success } = await binding.limit({ key: `${limiter}:${key}` });
  return success ? null : jsonError(429, 'rate_limited');
}
