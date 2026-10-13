// Customer sign-in: native email + password, replacing Google OAuth. A customer registers, staff approve
// their email from the CRM (src/approval.ts, unchanged), and only then does /login actually start a session.
// This is also what the Alexa/Google Home account-linking web view shows when a customer isn't signed in yet
// (see authorizeGet in oauth.ts) — it's the same session mechanism /oauth/authorize already relies on.

import { nowSeconds, randomId } from './crypto';
import { hashPassword, verifyPassword } from './password';
import type { Env } from './env';
import { esc, html, redirect, safeNext } from './http';
import { isApprovedEmail } from './approval';
import { createSession, sessionCookie } from './web';
import { checkLimit, clientKey } from './ratelimit';

const MIN_PASSWORD_LENGTH = 8;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// A syntactically valid but unusable hash, compared against when there's no real one — so an unknown
// email or an unclaimed legacy row still pays the same PBKDF2 cost as a wrong password against a real
// account. Without this, those cases return measurably faster, which leaks which emails exist via
// response timing even though the response body and status code are identical either way.
const DUMMY_HASH = 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 3rem auto; padding: 0 1rem; color: #111; }
input { font-size: 1rem; padding: .5rem; width: 100%; box-sizing: border-box; margin-top: .25rem; }
label { display: block; margin-top: 1rem; font-size: .9rem; color: #333; }
button { font-size: 1rem; padding: .6rem 1.2rem; margin-top: 1.25rem; }
.err { color: #b00020; }
.fine { color: #666; font-size: .85rem; margin-top: 1rem; }
</style></head><body>${body}</body></html>`;
}

function authForm(kind: 'login' | 'register', next: string, error: string | null, email: string): string {
  const action = kind === 'login' ? '/login' : '/register';
  const title = kind === 'login' ? 'Sign in' : 'Create your account';
  const confirmField =
    kind === 'register'
      ? `<label>Confirm password<input type="password" name="password_confirm" autocomplete="new-password" required></label>`
      : '';
  const swap =
    kind === 'login'
      ? `<p class="fine">No account yet? <a href="/register?next=${encodeURIComponent(next)}">Create one</a>.</p>`
      : `<p class="fine">Already have an account? <a href="/login?next=${encodeURIComponent(next)}">Sign in</a>.</p>`;
  return `<h1>${esc(title)}</h1>
${error ? `<p class="err">${esc(error)}</p>` : ''}
<form method="post" action="${action}">
  <input type="hidden" name="next" value="${esc(next)}">
  <label>Email<input type="email" name="email" value="${esc(email)}" autocomplete="username" required></label>
  <label>Password<input type="password" name="password" autocomplete="${kind === 'login' ? 'current-password' : 'new-password'}" required></label>
  ${confirmField}
  <button type="submit">${kind === 'login' ? 'Sign in' : 'Create account'}</button>
</form>
${swap}`;
}

function readNext(request: Request, form: FormData): string {
  const fromForm = form.get('next');
  return safeNext(typeof fromForm === 'string' && fromForm ? fromForm : new URL(request.url).searchParams.get('next'));
}

export async function loginPage(request: Request, env: Env): Promise<Response> {
  const next = safeNext(new URL(request.url).searchParams.get('next'));
  return html(200, page('Sign in · MDtronix Cloud', authForm('login', next, null, '')));
}

export async function registerPage(request: Request, env: Env): Promise<Response> {
  const next = safeNext(new URL(request.url).searchParams.get('next'));
  return html(200, page('Create account · MDtronix Cloud', authForm('register', next, null, '')));
}

/** The session cookie is SameSite=Lax, so this origin check is the CSRF guard for these POSTs. */
function checkOrigin(request: Request, env: Env): Response | null {
  if (request.headers.get('origin') !== env.PUBLIC_ORIGIN) {
    return html(403, page('Not allowed', '<p class="err">This request came from another site.</p>'));
  }
  return null;
}

/** POST /register. Creates the account; signs in immediately only if the email is already approved. */
export async function registerCustomer(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const limited = await checkLimit(env, 'RL_LOGIN', clientKey(request));
  if (limited) return limited;

  const form = await request.formData();
  const next = readNext(request, form);
  const email = normalizeEmail(String(form.get('email') ?? ''));
  const password = String(form.get('password') ?? '');
  const confirm = String(form.get('password_confirm') ?? '');

  const reRender = (message: string) => html(400, page('Create account · MDtronix Cloud', authForm('register', next, message, email)));

  if (!EMAIL_RE.test(email)) return reRender('Enter a valid email address.');
  if (password.length < MIN_PASSWORD_LENGTH) return reRender(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (password !== confirm) return reRender('Passwords do not match.');

  // Any existing row blocks registration — including one with no password yet (a leftover from the old
  // Google sign-in). Letting /register set a password on someone else's existing row with no proof of
  // ownership would be an account takeover: just knowing a customer's email would be enough to sign in as
  // them. A customer in that state needs staff to migrate their account, not a self-service path here.
  const existing = await env.CUSTOMERS.prepare('SELECT 1 FROM customers WHERE email = ?').bind(email).first();
  if (existing) return reRender('An account with that email already exists. Sign in instead, or contact MDtronix if you can\'t.');

  const now = nowSeconds();
  const id = randomId();
  // google_sub is still NOT NULL UNIQUE (see migrations/0007_password_auth.sql); password accounts get a
  // synthetic placeholder instead of a real Google subject id, the same trick web.ts's dev login uses.
  await env.CUSTOMERS.prepare(
    `INSERT INTO customers (id, google_sub, email, email_verified, password_hash, status, created_at, updated_at, last_login_at)
     VALUES (?, ?, ?, 1, ?, 'active', ?, ?, NULL)`,
  )
    .bind(id, `local:${id}`, email, await hashPassword(password), now, now)
    .run();

  if (await isApprovedEmail(env.CUSTOMERS, email)) {
    const token = await createSession(env.CUSTOMERS, id);
    return redirect(next, [sessionCookie(token)]);
  }

  return html(
    200,
    page(
      'Account created · MDtronix Cloud',
      `<h1>Account created</h1><p>Thanks — your account is waiting on MDtronix staff to approve ${esc(email)}. You'll be able to sign in once that's done.</p>`,
    ),
  );
}

export type AuthResult =
  | { ok: true; customerId: string }
  | { ok: false; reason: 'invalid_credentials' | 'not_approved' | 'account_suspended' };

/**
 * Verifies email+password and the approval gate. Shared by POST /login (this file, a browser session) and
 * the HA integration's direct login (src/ha_login.ts, a tunnel token instead of a session) — both are
 * "prove you're this customer," just with a different thing issued at the end.
 */
export async function authenticateCustomer(db: D1Database, email: string, password: string): Promise<AuthResult> {
  const normalized = normalizeEmail(email);
  const row = await db
    .prepare('SELECT id, password_hash, status FROM customers WHERE email = ?')
    .bind(normalized)
    .first<{ id: string; password_hash: string | null; status: string }>();

  // Always run verifyPassword, against the real hash if there is one or the dummy if not, so this takes
  // the same time either way — same reason whether the email is unknown or the password is wrong, so a
  // failed attempt doesn't reveal which account exists, including through response timing.
  const passwordOk = await verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
  if (!row || !row.password_hash || !passwordOk) {
    return { ok: false, reason: 'invalid_credentials' };
  }
  if (row.status !== 'active') return { ok: false, reason: 'account_suspended' };

  // The repo this integration comes from is public, so this is what keeps a stranger who registers an
  // account from getting a working trial. Staff approve emails through the admin API / CRM.
  if (!(await isApprovedEmail(db, normalized))) return { ok: false, reason: 'not_approved' };

  return { ok: true, customerId: row.id };
}

/** POST /login. */
export async function loginCustomer(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const limited = await checkLimit(env, 'RL_LOGIN', clientKey(request));
  if (limited) return limited;

  const form = await request.formData();
  const next = readNext(request, form);
  const email = normalizeEmail(String(form.get('email') ?? ''));
  const password = String(form.get('password') ?? '');

  const reRender = (message: string) => html(400, page('Sign in · MDtronix Cloud', authForm('login', next, message, email)));

  const auth = await authenticateCustomer(env.CUSTOMERS, email, password);
  if (!auth.ok) {
    if (auth.reason === 'not_approved') {
      return html(
        403,
        page(
          'Not approved · MDtronix Cloud',
          `<p>${esc(email)} isn't approved for MDtronix Cloud yet. Contact MDtronix to get access.</p>`,
        ),
      );
    }
    if (auth.reason === 'account_suspended') return reRender('This account is suspended. Contact support.');
    return reRender('Incorrect email or password.');
  }

  await env.CUSTOMERS.prepare('UPDATE customers SET last_login_at = ? WHERE id = ?').bind(nowSeconds(), auth.customerId).run();
  const token = await createSession(env.CUSTOMERS, auth.customerId);
  return redirect(next, [sessionCookie(token)]);
}
