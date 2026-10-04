// Relay entry point. Protocol: docs/remote-access/PROTOCOL.md in the SmartHome repo.
//
// Two kinds of host:
//   relay.mdtronix.online       sign-in, device login, the tunnel endpoint
//   <subdomain>.mdtronix.online a customer's remote URL, proxied to their Home Assistant

import { pollDeviceToken, createDeviceCode } from './device';
import { finishSignIn, startSignIn } from './google';
import type { Env } from './env';
import { jsonError } from './http';
import { handleAdminHomes, handleAdminSubscription } from './admin';
import { authorizeGet, authorizePost, revokeEndpoint, tokenEndpoint } from './oauth';
import { attachTunnel, instanceFromHost, proxyToInstance, unlink } from './tunnel';
import { approveDevice, devLogin, linkPage } from './web';

export { TunnelDO } from './tunnel-do';

async function relayRoutes(request: Request, env: Env, pathname: string): Promise<Response> {
  const method = request.method;

  if (pathname === '/healthz') return new Response('ok');

  // HA login
  if (pathname === '/v1/ha/device' && method === 'POST') return createDeviceCode(request, env);
  if (pathname === '/v1/ha/device/token' && method === 'POST') return pollDeviceToken(request, env);
  if (pathname === '/v1/ha/unlink' && method === 'POST') return unlink(request, env);

  // Operator
  if (pathname === '/v1/admin/subscription' && method === 'POST') return handleAdminSubscription(request, env);
  if (pathname === '/v1/admin/homes' && method === 'GET') return handleAdminHomes(request, env);

  // Voice account linking (Google Home, Alexa)
  if (pathname === '/oauth/authorize' && method === 'GET') return authorizeGet(request, env);
  if (pathname === '/oauth/authorize' && method === 'POST') return authorizePost(request, env);
  if (pathname === '/oauth/token' && method === 'POST') return tokenEndpoint(request, env);
  if (pathname === '/oauth/revoke' && method === 'POST') return revokeEndpoint(request, env);

  // Tunnel
  if (pathname === '/v1/tunnel' && method === 'GET') return attachTunnel(request, env);

  // Customer browser
  if (pathname === '/link' && method === 'GET') return linkPage(request, env);
  if (pathname === '/link' && method === 'POST') return approveDevice(request, env);
  if (pathname === '/v1/auth/google/start' && method === 'GET') return startSignIn(request, env);
  if (pathname === '/v1/auth/google/callback' && method === 'GET') return finishSignIn(request, env);

  // Local development only. Returns 404 unless DEV_LOGIN is set.
  if (pathname === '/v1/dev/login' && method === 'GET') return devLogin(request, env);

  return new Response('not found', { status: 404 });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    // Local development only: wrangler dev rewrites Host to the route's domain, so tests pass the
    // intended host in x-mdt-dev-host. DEV_LOGIN is never set in production, so the header is ignored there.
    const devHost = env.DEV_LOGIN === 'true' ? request.headers.get('x-mdt-dev-host') : null;
    const host = devHost ?? request.headers.get('host') ?? url.host;

    const subdomain = instanceFromHost(host, env.INSTANCE_DOMAIN);
    if (subdomain) return proxyToInstance(request, env, subdomain);

    try {
      return await relayRoutes(request, env, url.pathname);
    } catch (err) {
      console.error('relay error:', err instanceof Error ? err.message : 'unknown');
      return jsonError(500, 'internal_error');
    }
  },
};
