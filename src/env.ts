export interface Env {
  CUSTOMERS: D1Database;
  TUNNEL: DurableObjectNamespace;
  /** Public origin of the relay, e.g. https://relay.mdtronix.online. Used for redirects and the origin check. */
  PUBLIC_ORIGIN: string;
  /** Host HA connects to for the tunnel, e.g. relay.mdtronix.online. */
  TUNNEL_PUBLIC_HOST: string;
  /** Parent domain for customer remote URLs, e.g. mdtronix.online. */
  INSTANCE_DOMAIN: string;
  /** Local development only. Must never be set in production, because it enables a login with no password. */
  DEV_LOGIN?: string;
  /** Secret: bearer token for the operator API (/v1/admin/subscription). Set with `wrangler secret put ADMIN_TOKEN`. */
  ADMIN_TOKEN: string;
  /** Voice platform client IDs and secrets (set when the platform consoles are configured). */
  GOOGLE_VOICE_CLIENT_ID?: string;
  GOOGLE_VOICE_CLIENT_SECRET?: string;
  ALEXA_CLIENT_ID?: string;
  ALEXA_CLIENT_SECRET?: string;
  /** The skill's "Send Alexa Events" LWA client ID (public). Used with ALEXA_LWA_CLIENT_SECRET to get a
   *  client-credentials token for proactive ChangeReport events. */
  ALEXA_LWA_CLIENT_ID?: string;
  /** Secret: `wrangler secret put ALEXA_LWA_CLIENT_SECRET`. */
  ALEXA_LWA_CLIENT_SECRET?: string;
  /** Rate-limit bindings, declared in wrangler.jsonc. */
  RL_LOGIN: RateLimit;
  RL_HA_LOGIN: RateLimit;
}
