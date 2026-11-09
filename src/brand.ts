// What Google requires on its account-linking pages for Works with Google Home certification
// (https://developers.home.google.com/cloud-to-cloud/project/authorization): the integration identified,
// the account shown as linked to Google rather than to "Google Home" or "Google Assistant", and an
// authorization statement. Alexa and the website share the same pages, so all of this appears only in
// Google's flow: see isGoogleLink in oauth-clients.ts.

export const INTEGRATION_NAME = 'MDtronix Home';
export const INTEGRATION_COMPANY = 'MDtronix Lab';

export const GOOGLE_SIGN_IN_STATEMENT = 'By signing in, you are authorizing Google to control your devices.';
// The customer is already signed in on the consent page, so this one names the button they press instead.
export const GOOGLE_CONSENT_STATEMENT = 'By selecting Agree and link, you are authorizing Google to control your devices.';

// 144x144 PNG of the app icon. Inline because the Worker has no assets binding.
const ICON_DATA_URI = 'data:image/png;base64,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';

export const LINK_CSS = `
.link-brand { display: flex; align-items: center; gap: .85rem; margin-bottom: 1.5rem; }
.link-brand img { width: 56px; height: 56px; flex: none; }
.link-brand strong { display: block; font-size: 1.15rem; }
.link-brand span { color: #555; font-size: .9rem; }
.link-brand + h1 { font-size: 1.35rem; margin: 0 0 1rem; }
.statement { color: #111; font-size: .95rem; margin: 1.25rem 0 0; }
.link-brand ~ form button { font-family: inherit; border-radius: .4rem; cursor: pointer; }
button.primary { background: #1a5fb4; color: #fff; border: 1px solid #1a5fb4; font-weight: 600; }
`;

/** The header of every page in Google's linking flow. */
export function linkBrand(): string {
  return `<div class="link-brand"><img src="${ICON_DATA_URI}" alt="" width="56" height="56"><div><strong>${INTEGRATION_NAME}</strong><span>by ${INTEGRATION_COMPANY}</span></div></div>`;
}
