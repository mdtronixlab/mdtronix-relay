// Platforms allowed to link a home's account: Google Home and Alexa. Client IDs and secrets come from
// the environment, and redirect URIs must match exactly.
//
// Before this works for real, two values need filling in from the platforms' consoles:
//   - GOOGLE_PROJECT_ID: the Actions project ID. Google's redirect URI contains it.
//   - the platform client ID and secret: GOOGLE_VOICE_CLIENT_ID/SECRET and ALEXA_CLIENT_ID/SECRET.

import type { Env } from './env';

export const GOOGLE_PROJECT_ID = 'REPLACE_WITH_GOOGLE_PROJECT_ID';
export const ALEXA_VENDOR_ID = 'M23Q7Y64C1HJD4';

export type Platform = 'google' | 'alexa';

export const PLATFORMS: Record<Platform, { name: string; redirectUris: string[] }> = {
  google: {
    name: 'Google Home',
    redirectUris: [
      `https://oauth-redirect.googleusercontent.com/r/${GOOGLE_PROJECT_ID}`,
      `https://oauth-redirect-sandbox.googleusercontent.com/r/${GOOGLE_PROJECT_ID}`,
    ],
  },
  alexa: {
    name: 'Alexa',
    redirectUris: [
      `https://pitangui.amazon.com/api/skill/link/${ALEXA_VENDOR_ID}`,
      `https://layla.amazon.com/api/skill/link/${ALEXA_VENDOR_ID}`,
      `https://alexa.amazon.co.jp/api/skill/link/${ALEXA_VENDOR_ID}`,
    ],
  },
};

/** The platform that owns a client ID, or null for an unknown client. */
export function platformForClientId(env: Env, clientId: string): Platform | null {
  if (!clientId) return null;
  if (clientId === env.GOOGLE_VOICE_CLIENT_ID) return 'google';
  if (clientId === env.ALEXA_CLIENT_ID) return 'alexa';
  return null;
}

/** The secret the platform must present at the token endpoint, or null when it isn't configured. */
export function secretForPlatform(env: Env, platform: Platform): string | null {
  const secret = platform === 'google' ? env.GOOGLE_VOICE_CLIENT_SECRET : env.ALEXA_CLIENT_SECRET;
  return secret ? secret : null;
}
