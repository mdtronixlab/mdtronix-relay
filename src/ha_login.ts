// Direct email+password login for the HA integration. Replaces the old device-code flow: one POST with
// the customer's MDtronix Cloud credentials, one response with the instance's tunnel credentials, no
// browser step. See src/password_auth.ts for the shared credential check (also used by the website's
// own /login) and src/instance.ts for what issuing the instance actually does.

import type { Env } from './env';
import { json, jsonError } from './http';
import { issueInstance } from './instance';
import { authenticateCustomer } from './password_auth';
import { checkLimit, clientKey } from './ratelimit';

/** POST /v1/ha/login. Body: { email, password, replace? }. */
export async function haLogin(request: Request, env: Env): Promise<Response> {
  const limited = await checkLimit(env, 'RL_HA_LOGIN', clientKey(request));
  if (limited) return limited;

  let body: { email?: unknown; password?: unknown; replace?: unknown };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'invalid_request');
  }
  if (typeof body.email !== 'string' || typeof body.password !== 'string') return jsonError(400, 'invalid_request');

  const auth = await authenticateCustomer(env.CUSTOMERS, body.email, body.password);
  if (!auth.ok) return jsonError(auth.reason === 'invalid_credentials' ? 401 : 403, auth.reason);

  const issued = await issueInstance(env, auth.customerId, body.replace === true);
  if (!issued.ok) return jsonError(issued.status, issued.error);
  return json(200, issued.body);
}
