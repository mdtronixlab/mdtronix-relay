// Privacy policy and terms of use. Plain static content, not generated from the database, so these
// routes are cheap and don't need a customer lookup.
//
// NOTE for the owner: this describes what the code actually does as of 2026-10, for the Alexa skill
// certification's required Privacy Policy / Terms of Use URLs. It is not legal advice — have it
// reviewed before relying on it for certification or for customers.

import type { Env } from './env';
import { html } from './http';
import { shell } from './site';
import { signedInCustomer } from './web';

const LAST_UPDATED = '2026-10-12';

const PRIVACY_BODY = `
<h1>Privacy Policy</h1>
<p class="fine">Last updated ${LAST_UPDATED}</p>

<h2>What MDtronix Cloud is</h2>
<p>MDtronix Cloud connects your own Home Assistant instance to the internet and, if you choose, to Google Home and Alexa. It is a relay: it proxies requests to your Home Assistant and forwards voice commands to it. It does not run or store your Home Assistant's data itself.</p>

<h2>What we collect</h2>
<ul>
<li><strong>Account:</strong> the email address and account identifier from your Google sign-in.</li>
<li><strong>Home Assistant connection:</strong> a tunnel token and your instance's subdomain, used to route traffic to your Home Assistant. We don't see your Home Assistant's own login credentials.</li>
<li><strong>Voice assistant links:</strong> if you link Google Home or Alexa, we store the OAuth tokens needed to authenticate their requests and, for Alexa's proactive state updates, a token Amazon issues us for your account. We store these as hashes where we only need to verify them again, and in full where we need to present them back to Google or Amazon ourselves.</li>
<li><strong>Device exposure and PIN:</strong> which entities you've chosen to expose to each voice assistant, and the PIN you set for locks and alarms, are stored in your own Home Assistant, not on MDtronix Cloud's servers.</li>
<li><strong>Subscription status:</strong> your trial or paid period, so we know whether your account has access.</li>
</ul>

<h2>What we don't do</h2>
<ul>
<li>We don't sell your data.</li>
<li>We don't read or store the contents of requests proxied through the tunnel (web traffic to your Home Assistant, or voice directives) beyond what's needed to deliver them and keep the connection working.</li>
<li>Nothing is exposed to Google Home or Alexa until you explicitly choose it in your Home Assistant's MDtronix Cloud integration settings.</li>
</ul>

<h2>Where data lives</h2>
<p>Account, connection, and voice-linking data is stored in Cloudflare's infrastructure (D1 and Workers), which MDtronix Cloud runs on.</p>

<h2>Your choices</h2>
<p>You can disconnect your Home Assistant or unlink a voice assistant at any time from <a href="/account">your account page</a> or from that platform's own app. Unlinking revokes the related tokens.</p>

<h2>Contact</h2>
<p>Questions about this policy: <a href="mailto:support@mdtronix.online">support@mdtronix.online</a>.</p>
`;

const TERMS_BODY = `
<h1>Terms of Use</h1>
<p class="fine">Last updated ${LAST_UPDATED}</p>

<h2>The service</h2>
<p>MDtronix Cloud provides remote access to your own Home Assistant instance and, if you choose to link them, lets Google Home and Alexa control the devices you expose. You need a working Home Assistant instance with the MDtronix Cloud integration installed; MDtronix Cloud does not provide Home Assistant itself.</p>

<h2>Your responsibilities</h2>
<ul>
<li>You're responsible for what you expose to Google Home and Alexa, and for setting a PIN if you expose locks or alarm panels.</li>
<li>You're responsible for keeping your Google account, and any account you use to sign in, secure.</li>
<li>Don't use the service to access or control a Home Assistant instance you don't own or have permission to use.</li>
</ul>

<h2>Trial and billing</h2>
<p>New connections start with a free trial. Continued access after the trial requires an active subscription, as shown on your account page.</p>

<h2>Availability</h2>
<p>MDtronix Cloud is provided as-is. We aim to keep the relay and tunnel available, but don't guarantee uninterrupted service, and aren't responsible for the availability or behavior of your own Home Assistant instance, Google, or Amazon's services.</p>

<h2>Changes</h2>
<p>We may update these terms or the privacy policy; the "Last updated" date above reflects the latest revision.</p>

<h2>Contact</h2>
<p>Questions about these terms: <a href="mailto:support@mdtronix.online">support@mdtronix.online</a>.</p>
`;

/** GET /privacy. Public. */
export async function privacyPage(request: Request, env: Env): Promise<Response> {
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  return html(200, shell('Privacy Policy · MDtronix Cloud', customer, PRIVACY_BODY));
}

/** GET /terms. Public. */
export async function termsPage(request: Request, env: Env): Promise<Response> {
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  return html(200, shell('Terms of Use · MDtronix Cloud', customer, TERMS_BODY));
}
