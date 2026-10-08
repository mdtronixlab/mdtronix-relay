// The public site: the "/" landing page and "/account", where a customer signs in on their own,
// outside the Home Assistant device-login flow (that flow is in web.ts). There's no separate sign-up:
// Google sign-in creates the account on first use, the same as it does from /link.

import { nowSeconds } from './crypto';
import type { Env } from './env';
import { esc, html, jsonError, redirect } from './http';
import { GRACE_SECONDS, type SubscriptionRow } from './billing';
import { linkedPlatforms, revokeGrantsForCustomer } from './oauth';
import { unlinkForCustomer } from './tunnel';
import { signedInCustomer, signOut } from './web';

const SITE_CSS = `
:root { color-scheme: light; }
body { font-family: system-ui, sans-serif; margin: 0; color: #15181d; background: #fafafa; }
a { color: #1a5fb4; }
.bar { display: flex; align-items: center; justify-content: space-between; padding: 1rem 1.5rem; background: #fff; border-bottom: 1px solid #e5e5e5; }
.brand { font-weight: 700; text-decoration: none; color: #15181d; font-size: 1.1rem; }
.bar nav { display: flex; align-items: center; gap: 1rem; font-size: .95rem; }
.who { color: #555; }
main { max-width: 40rem; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
.hero h1 { font-size: 2rem; line-height: 1.2; margin-bottom: .5rem; }
.hero p { color: #444; font-size: 1.05rem; }
.btn { display: inline-block; background: #1a5fb4; color: #fff; text-decoration: none; padding: .7rem 1.3rem; border-radius: .4rem; font-weight: 600; margin-top: .5rem; }
.fine { color: #777; font-size: .85rem; }
.features { display: grid; gap: 1.2rem; margin: 2.5rem 0; }
.features h2 { font-size: 1.05rem; margin-bottom: .25rem; }
.features p { margin: 0; color: #444; }
.steps ol { padding-left: 1.2rem; color: #333; }
.card { background: #fff; border: 1px solid #e5e5e5; border-radius: .5rem; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
.card h2 { margin-top: 0; font-size: 1.05rem; }
.ok { color: #1a7f37; }
.warn { color: #b3541e; }
.voice-row { display: flex; align-items: center; justify-content: space-between; padding: .3rem 0; }
form.inline { display: inline; margin: 0; }
button { font: inherit; cursor: pointer; }
button.link { background: none; border: none; color: #1a5fb4; padding: 0; text-decoration: underline; }
button.danger { background: #fff; border: 1px solid #c4281b; color: #c4281b; border-radius: .4rem; padding: .5rem 1rem; }
`;

function shell(title: string, customer: { email: string } | null, body: string): string {
  const nav = customer
    ? `<span class="who">${esc(customer.email)}</span> <a href="/account">Account</a> ` +
      `<form method="post" action="/account/sign-out" class="inline"><button class="link" type="submit">Sign out</button></form>`
    : `<a href="/v1/auth/google/start?next=${encodeURIComponent('/account')}">Sign in</a>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${SITE_CSS}</style></head>
<body>
<header class="bar"><a class="brand" href="/">MDtronix Cloud</a><nav>${nav}</nav></header>
<main>${body}</main>
</body></html>`;
}

function errorPage(status: number, message: string): Response {
  return html(status, shell('Not allowed', null, `<p class="warn">${esc(message)}</p>`), []);
}

/** CSRF guard for the account page's POST actions. The session cookie is SameSite=Lax. */
function checkOrigin(request: Request, env: Env): Response | null {
  if (request.headers.get('origin') !== env.PUBLIC_ORIGIN) return errorPage(403, 'This request came from another site.');
  return null;
}

/** GET /. Public, whether signed in or not. */
export async function homePage(request: Request, env: Env): Promise<Response> {
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  const cta = customer
    ? `<a class="btn" href="/account">Go to your account</a>`
    : `<a class="btn" href="/v1/auth/google/start?next=${encodeURIComponent('/account')}">Get started with Google</a>`;

  const body = `
<section class="hero">
  <h1>Remote access and voice control for your Home Assistant</h1>
  <p>MDtronix Cloud connects your Home Assistant to the internet, with no port to open on your router, and lets Google Home and Alexa control the devices you choose.</p>
  ${cta}
  <p class="fine">Free trial. No credit card needed to start.</p>
</section>
<section class="features">
  <div><h2>Remote access</h2><p>A private web address for your home, reachable from anywhere, protected by your Home Assistant login.</p></div>
  <div><h2>Google Home &amp; Alexa</h2><p>Control the lights, switches, thermostats, and more that you choose to expose, by voice.</p></div>
  <div><h2>Your choice, your PIN</h2><p>Nothing is exposed until you pick it in Home Assistant. Locks and alarms also need your PIN to unlock or disarm by voice.</p></div>
</section>
<section class="steps">
  <h2>How it works</h2>
  <ol>
    <li>Install the <strong>MDtronix Cloud</strong> integration in Home Assistant, from HACS or manually.</li>
    <li>Start setup. Home Assistant shows a short code and a link.</li>
    <li>Sign in with Google and enter the code to connect.</li>
  </ol>
</section>`;
  return html(200, shell('MDtronix Cloud', customer, body));
}

function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().slice(0, 10);
}

function subscriptionSummary(sub: SubscriptionRow | null, now: number): { label: string; detail: string; ok: boolean } {
  if (!sub) {
    return { label: 'No subscription yet', detail: 'Starts automatically when you connect a Home Assistant.', ok: false };
  }
  if (sub.status === 'trialing' && sub.trial_ends_at !== null) {
    const ok = now < sub.trial_ends_at;
    return { label: ok ? 'Free trial' : 'Trial ended', detail: `${ok ? 'Ends' : 'Ended'} ${formatDate(sub.trial_ends_at)}`, ok };
  }
  if (sub.status === 'active' && sub.current_period_end !== null) {
    const ok = now < sub.current_period_end + GRACE_SECONDS;
    return { label: ok ? 'Active' : 'Payment overdue', detail: `Paid through ${formatDate(sub.current_period_end)}`, ok };
  }
  return { label: 'Suspended', detail: 'Contact support to reactivate.', ok: false };
}

/** GET /account. Signs the customer in first if they aren't already. */
export async function accountPage(request: Request, env: Env): Promise<Response> {
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return redirect(`/v1/auth/google/start?next=${encodeURIComponent('/account')}`);

  const instance = await env.CUSTOMERS.prepare('SELECT subdomain FROM instances WHERE customer_id = ?')
    .bind(customer.id)
    .first<{ subdomain: string }>();
  // Unlinking (here or from Home Assistant) revokes the tunnel token but keeps the instance row, so the
  // subdomain is reserved for reconnecting. A row with no live token means "disconnected", not "connected".
  const hasToken = instance
    ? !!(await env.CUSTOMERS.prepare('SELECT 1 FROM tunnel_tokens WHERE instance = ? AND revoked_at IS NULL')
        .bind(instance.subdomain)
        .first())
    : false;
  const sub = await env.CUSTOMERS.prepare(
    'SELECT status, trial_ends_at, current_period_end FROM subscriptions WHERE customer_id = ?',
  )
    .bind(customer.id)
    .first<SubscriptionRow>();
  const linked = await linkedPlatforms(env.CUSTOMERS, customer.id);

  let connected = false;
  if (instance && hasToken) {
    const stub = env.TUNNEL.get(env.TUNNEL.idFromName(instance.subdomain));
    const res = await stub.fetch('https://do.internal/__status');
    if (res.ok) connected = ((await res.json()) as { connected: boolean }).connected;
  }

  const remoteUrl = instance ? `${instance.subdomain}.${env.INSTANCE_DOMAIN}` : '';
  let homeCard: string;
  if (!instance) {
    homeCard = `<p>No Home Assistant connected yet.</p>
<p>Install the <strong>MDtronix Cloud</strong> integration from HACS, start setup, and enter the code at <a href="/link">/link</a>.</p>`;
  } else if (!hasToken) {
    homeCard = `<p>This home was disconnected.</p>
<p>Start setup again in Home Assistant to reconnect it. It will reuse <a href="https://${esc(remoteUrl)}">${esc(remoteUrl)}</a>.</p>`;
  } else {
    homeCard = `<p>Remote URL: <a href="https://${esc(remoteUrl)}">${esc(remoteUrl)}</a></p>
<p>Status: <strong class="${connected ? 'ok' : 'warn'}">${connected ? 'Connected' : 'Not connected right now'}</strong></p>
<form method="post" action="/account/unlink-home" onsubmit="return confirm('Disconnect this Home Assistant? You can connect it again from Home Assistant.');">
<button class="danger" type="submit">Disconnect</button></form>`;
  }

  const subInfo = subscriptionSummary(sub, nowSeconds());
  const subCard = `<p class="${subInfo.ok ? 'ok' : 'warn'}">${esc(subInfo.label)}</p><p>${esc(subInfo.detail)}</p>`;

  const voiceCard = (['google', 'alexa'] as const)
    .map((platform) => {
      const name = platform === 'google' ? 'Google Home' : 'Alexa';
      if (!linked[platform]) return `<div class="voice-row"><span>${name}: Not connected</span></div>`;
      return `<div class="voice-row"><span>${name}: <strong class="ok">Connected</strong></span>
<form method="post" action="/account/unlink-voice" class="inline" onsubmit="return confirm('Unlink ${name}? You can link it again from the ${name} app.');">
<input type="hidden" name="platform" value="${platform}"><button class="link" type="submit">Unlink</button></form></div>`;
    })
    .join('');

  const body = `
<h1>Your account</h1>
<section class="card"><h2>Home Assistant</h2>${homeCard}</section>
<section class="card"><h2>Subscription</h2>${subCard}</section>
<section class="card"><h2>Voice assistants</h2>${voiceCard}
<p class="fine">Link Google Home or Alexa from their own app. Choose which devices they can control, and set a PIN for locks and alarms, from the MDtronix Cloud integration's options in Home Assistant.</p></section>`;

  return html(200, shell('Your account · MDtronix Cloud', customer, body));
}

/** POST /account/sign-out. */
export async function accountSignOut(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const cookies = await signOut(request, env.CUSTOMERS);
  return redirect('/', cookies);
}

/** POST /account/unlink-home. Disconnects the signed-in customer's Home Assistant. */
export async function accountUnlinkHome(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return redirect(`/v1/auth/google/start?next=${encodeURIComponent('/account')}`);
  await unlinkForCustomer(env, customer.id);
  return redirect('/account');
}

/** POST /account/unlink-voice. Unlinks one voice platform from the signed-in customer. */
export async function accountUnlinkVoice(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const customer = await signedInCustomer(request, env.CUSTOMERS);
  if (!customer) return redirect(`/v1/auth/google/start?next=${encodeURIComponent('/account')}`);

  const form = await request.formData();
  const platform = form.get('platform');
  if (platform !== 'google' && platform !== 'alexa') return jsonError(400, 'invalid_platform');
  await revokeGrantsForCustomer(env.CUSTOMERS, customer.id, platform);
  return redirect('/account');
}
