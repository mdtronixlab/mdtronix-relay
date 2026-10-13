// Platforms allowed to link a home's account: Google Home and Alexa. Client IDs and secrets come from
// the environment, and redirect URIs must match exactly.
//
// Before this works for real, two values need filling in from the platforms' consoles:
//   - the platform client ID and secret: GOOGLE_VOICE_CLIENT_ID/SECRET and ALEXA_CLIENT_ID/SECRET.
// The Google project ID (Home Developer Console > Project info) is set below, for the legacy
// Actions-on-Google redirect URI. Google is retiring that flow in favor of the Google Home app's own
// account linking, which redirects to a fixed URI that doesn't depend on the project ID at all. See
// https://developers.home.google.com/cloud-to-cloud/account-linking-migration.

import type { Env } from './env';

export const GOOGLE_PROJECT_ID = 'mdtronix-cloud';
export const ALEXA_VENDOR_ID = 'M23Q7Y64C1HJD4';

export type Platform = 'google' | 'alexa';

export const PLATFORMS: Record<Platform, { name: string; redirectUris: string[] }> = {
  google: {
    name: 'Google Home',
    redirectUris: [
      // The Google Home app's own account linking (current).
      'https://oauth-redirect.googleusercontent.com/a/com.google.Chromecast',
      // Legacy Actions-on-Google redirect, kept for compatibility while Google's migration is in progress.
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
