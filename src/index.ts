// Relay entry point. Protocol: docs/remote-access/PROTOCOL.md in the SmartHome repo.
//
// Two kinds of host:
//   relay.mdtronix.online       sign-in, HA login, the tunnel endpoint
//   <subdomain>.mdtronix.online a customer's remote URL, proxied to their Home Assistant

import { haLogin } from './ha_login';
import { loginCustomer, loginPage, registerCustomer, registerPage } from './password_auth';
import type { Env } from './env';
import { jsonError } from './http';
import { handleAdminHomes, handleAdminSubscription, handleListApprovedEmails, handleSetApprovedEmail } from './admin';
import { authorizeGet, authorizePost, revokeEndpoint, tokenEndpoint } from './oauth';
import { attachTunnel, instanceFromHost, proxyToInstance, unlink } from './tunnel';
import { devApprovedCheck, devLogin } from './web';
import { alexaDirective, googleFulfillment } from './voice';
import { alexaReportToken } from './alexa-events';
import { googleReportState } from './google-report';
import { accountPage, accountSignOut, accountUnlinkHome, accountUnlinkVoice, homePage } from './site';
import { privacyPage, termsPage } from './legal';

export { TunnelDO } from './tunnel-do';

async function relayRoutes(request: Request, env: Env, pathname: string): Promise<Response> {
  const method = request.method;

  if (pathname === '/healthz') return new Response('ok');

  // Public site: the homepage and the account page a customer can reach on its own, outside HA.
  if (pathname === '/' && method === 'GET') return homePage(request, env);
  if (pathname === '/account' && method === 'GET') return accountPage(request, env);
  if (pathname === '/account/sign-out' && method === 'POST') return accountSignOut(request, env);
  if (pathname === '/account/unlink-home' && method === 'POST') return accountUnlinkHome(request, env);
  if (pathname === '/account/unlink-voice' && method === 'POST') return accountUnlinkVoice(request, env);
  if (pathname === '/privacy' && method === 'GET') return privacyPage(request, env);
  if (pathname === '/terms' && method === 'GET') return termsPage(request, env);

  // HA login
  if (pathname === '/v1/ha/login' && method === 'POST') return haLogin(request, env);
  if (pathname === '/v1/ha/unlink' && method === 'POST') return unlink(request, env);
  // Proactive state reporting, authenticated by the home's own tunnel token: a short-lived token for
  // Alexa's own Event Gateway call, but the relay makes Google's Home Graph call itself (see google-report.ts).
  if (pathname === '/v1/ha/alexa-report-token' && method === 'GET') return alexaReportToken(request, env);
  if (pathname === '/v1/ha/google-report-state' && method === 'POST') return googleReportState(request, env);

  // Operator
  if (pathname === '/v1/admin/subscription' && method === 'POST') return handleAdminSubscription(request, env);
  if (pathname === '/v1/admin/homes' && method === 'GET') return handleAdminHomes(request, env);
  if (pathname === '/v1/admin/approved-emails' && method === 'GET') return handleListApprovedEmails(request, env);
  if (pathname === '/v1/admin/approved-emails' && method === 'POST') return handleSetApprovedEmail(request, env);

  // Voice account linking (Google Home, Alexa)
  if (pathname === '/oauth/authorize' && method === 'GET') return authorizeGet(request, env);
  if (pathname === '/oauth/authorize' && method === 'POST') return authorizePost(request, env);
  if (pathname === '/oauth/token' && method === 'POST') return tokenEndpoint(request, env);
  if (pathname === '/oauth/revoke' && method === 'POST') return revokeEndpoint(request, env);

  // Voice fulfillment. Authenticated by the OAuth access token, and answered by the home (PROTOCOL.md 2.5).
  if (pathname === '/v1/voice/google' && method === 'POST') return googleFulfillment(request, env);
  if (pathname === '/v1/voice/alexa' && method === 'POST') return alexaDirective(request, env);

  // Tunnel
  if (pathname === '/v1/tunnel' && method === 'GET') return attachTunnel(request, env);

  // Customer browser
  if (pathname === '/login' && method === 'GET') return loginPage(request, env);
  if (pathname === '/login' && method === 'POST') return loginCustomer(request, env);
  if (pathname === '/register' && method === 'GET') return registerPage(request, env);
  if (pathname === '/register' && method === 'POST') return registerCustomer(request, env);

  // Local development only. Returns 404 unless DEV_LOGIN is set.
  if (pathname === '/v1/dev/login' && method === 'GET') return devLogin(request, env);
  if (pathname === '/v1/dev/approved' && method === 'GET') return devApprovedCheck(request, env);

  return new Response('not found', { status: 404 });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    // Local development only: wrangler dev rewrites Host to the route's domain, so tests pass the
    // intended host in x-mdt-dev-host. DEV_LOGIN is never set in production, so the header is ignored there.
    const devHost = env.DEV_LOGIN === 'true' ? request.headers.get('x-mdt-dev-host') : null;
    const host = devHost ?? request.headers.get('host') ?? url.host;

    const subdomain = instanceFromHost(host, env.INSTANCE_DOMAIN);
    if (subdomain) return proxyToInstance(request, env, subdomain, ctx);

    try {
      return await relayRoutes(request, env, url.pathname);
    } catch (err) {
      console.error('relay error:', err instanceof Error ? err.message : 'unknown');
      return jsonError(500, 'internal_error');
    }
  },
};
