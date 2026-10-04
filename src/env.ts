export interface Env {
  CUSTOMERS: D1Database;
  TUNNEL: DurableObjectNamespace;
  /** Public origin of the relay, e.g. https://relay.mdtronix.online. Used for redirects, the link page, and the origin check. */
  PUBLIC_ORIGIN: string;
  /** Host HA connects to for the tunnel, e.g. relay.mdtronix.online. */
  TUNNEL_PUBLIC_HOST: string;
  /** Parent domain for customer remote URLs, e.g. mdtronix.online. */
  INSTANCE_DOMAIN: string;
  /** Google OAuth client ID (public). */
  GOOGLE_CLIENT_ID: string;
  /** Secret: `wrangler secret put GOOGLE_CLIENT_SECRET`. */
  GOOGLE_CLIENT_SECRET: string;
  /** Secret: HMAC key for the short-lived sign-in state cookie. */
  SESSION_SECRET: string;
  /** Local development only. Must never be set in production, because it enables a login with no Google account. */
  DEV_LOGIN?: string;
  /** Secret: bearer token for the operator API (/v1/admin/subscription). Set with `wrangler secret put ADMIN_TOKEN`. */
  ADMIN_TOKEN: string;
  /** Rate-limit bindings, declared in wrangler.jsonc. */
  RL_DEVICE: RateLimit;
  RL_APPROVE: RateLimit;
  RL_POLL: RateLimit;
  RL_LOGIN: RateLimit;
}
