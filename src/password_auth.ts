// Customer sign-in: native email + password, replacing Google OAuth. A customer registers, staff approve
// their email from the CRM (src/approval.ts, unchanged), and only then does /login actually start a session.
// This is also what the Alexa/Google Home account-linking web view shows when a customer isn't signed in yet
// (see authorizeGet in oauth.ts) — it's the same session mechanism /oauth/authorize already relies on.

import { nowSeconds, randomId, sha256Hex } from './crypto';
import { hashPassword, verifyPassword } from './password';
import type { Env } from './env';
import { esc, formString, html, redirect, safeNext } from './http';
import { isApprovedEmail } from './approval';
import { createSession, revokeAllSessions, sessionCookie } from './web';
import { checkLimit, clientKey } from './ratelimit';

export const MIN_PASSWORD_LENGTH = 8;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// A syntactically valid but unusable hash, compared against when there's no real one — so an unknown
// email or an unclaimed legacy row still pays the same PBKDF2 cost as a wrong password against a real
// account. Without this, those cases return measurably faster, which leaks which emails exist via
// response timing even though the response body and status code are identical either way. Exported so
// site.ts's accountChangePassword can pay the same cost for a legacy no-password account.
export const DUMMY_HASH = 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

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
  const fromForm = formString(form, 'next');
  return safeNext(fromForm || new URL(request.url).searchParams.get('next'));
}

export async function loginPage(request: Request, env: Env): Promise<Response> {
  const next = safeNext(new URL(request.url).searchParams.get('next'));
  return html(200, page('Sign in · MDtronix Cloud', authForm('login', next, null, '')));
}

export async function registerPage(request: Request, env: Env): Promise<Response> {
  const next = safeNext(new URL(request.url).searchParams.get('next'));
  return html(200, page('Create account · MDtronix Cloud', authForm('register', next, null, '')));
}

// A function, not a module-scope constant: Workers forbids constructing a Response outside a handler.
function expiredLinkPage(): Response {
  return html(
    400,
    page(
      'Link expired · MDtronix Cloud',
      `<h1>This link is no longer valid</h1><p>It may have expired or already been used. Contact MDtronix for a new one.</p>`,
    ),
  );
}

function resetForm(token: string, error: string | null): string {
  return `<h1>Set a new password</h1>
${error ? `<p class="err">${esc(error)}</p>` : ''}
<form method="post" action="/reset-password">
  <input type="hidden" name="token" value="${esc(token)}">
  <label>New password<input type="password" name="password" autocomplete="new-password" required></label>
  <label>Confirm new password<input type="password" name="password_confirm" autocomplete="new-password" required></label>
  <button type="submit">Set password</button>
</form>`;
}

/**
 * The token's row, if it exists, is unused, hasn't expired, and its customer is still approved — null
 * otherwise. Approval is re-checked here, not just at generation (handleGenerateResetLink in admin.ts):
 * it could have been revoked after the link was sent, and this is also what stops the link from ever
 * signing in a customer who was never approved in the first place.
 */
async function validResetToken(db: D1Database, token: string): Promise<{ id: string; customerId: string } | null> {
  if (!token) return null;
  const row = await db
    .prepare(
      `SELECT t.id, t.customer_id, c.email
       FROM password_reset_tokens t JOIN customers c ON c.id = t.customer_id
       WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ?`,
    )
    .bind(await sha256Hex(token), nowSeconds())
    .first<{ id: string; customer_id: string; email: string }>();
  if (!row || !(await isApprovedEmail(db, row.email))) return null;
  return { id: row.id, customerId: row.customer_id };
}

/** Invalidates any pending reset link for a customer. Called whenever their password changes through a
 * different path (admin set-password, self-service change-password), so an old unused link can't later
 * overwrite that deliberate change. */
export async function invalidatePendingResetTokens(db: D1Database, customerId: string): Promise<void> {
  await db
    .prepare('UPDATE password_reset_tokens SET used_at = ? WHERE customer_id = ? AND used_at IS NULL')
    .bind(nowSeconds(), customerId)
    .run();
}

/** GET /reset-password?token=…. Staff generate this link (POST /v1/admin/generate-reset-link) and send it
 * to the customer themselves — there's no email sending in this relay, and no public "forgot password"
 * form; the customer contacts staff directly, outside this system. */
export async function resetPasswordPage(request: Request, env: Env): Promise<Response> {
  const token = new URL(request.url).searchParams.get('token') ?? '';
  if (!(await validResetToken(env.CUSTOMERS, token))) return expiredLinkPage();
  return html(200, page('Set a new password · MDtronix Cloud', resetForm(token, null)));
}

/** POST /reset-password. Consumes the token, sets the password, and signs the customer straight in. */
export async function resetPasswordSubmit(request: Request, env: Env): Promise<Response> {
  const denied = checkOrigin(request, env);
  if (denied) return denied;
  const limited = await checkLimit(env, 'RL_LOGIN', clientKey(request));
  if (limited) return limited;

  const form = await request.formData();
  const token = formString(form, 'token');
  const password = formString(form, 'password');
  const passwordConfirm = formString(form, 'password_confirm');

  const valid = await validResetToken(env.CUSTOMERS, token);
  if (!valid) return expiredLinkPage();

  const reRender = (message: string) => html(400, page('Set a new password · MDtronix Cloud', resetForm(token, message)));
  if (password.length < MIN_PASSWORD_LENGTH) return reRender(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  if (password !== passwordConfirm) return reRender('Passwords do not match.');

  const now = nowSeconds();
  // Claim the token before issuing anything, so a replayed submit (two tabs, a double click) can't both succeed.
  const claim = await env.CUSTOMERS.prepare('UPDATE password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .bind(now, valid.id)
    .run();
  if (claim.meta.changes !== 1) return expiredLinkPage();

  await env.CUSTOMERS.prepare('UPDATE customers SET password_hash = ?, updated_at = ? WHERE id = ?')
    .bind(await hashPassword(password), now, valid.customerId)
    .run();
  // A reset should lock out whoever has an old session, not just whoever doesn't know the new password.
  await revokeAllSessions(env.CUSTOMERS, valid.customerId);

  const session = await createSession(env.CUSTOMERS, valid.customerId);
  return redirect('/account', [sessionCookie(session)]);
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
  const email = normalizeEmail(formString(form, 'email'));
  const password = formString(form, 'password');
  const confirm = formString(form, 'password_confirm');

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
  | { ok: false; reason: 'unknown_email' | 'no_password' | 'wrong_password' | 'not_approved' | 'account_suspended' };

/**
 * Verifies email+password and the approval gate. Shared by POST /login (this file, a browser session) and
 * the HA integration's direct login (src/ha_login.ts, a tunnel token instead of a session) — both are
 * "prove you're this customer," just with a different thing issued at the end.
 *
 * Deliberately reveals which of email/password was wrong (2026-10-14, the owner's call): this trades away
 * the account-enumeration protection the single "invalid_credentials" reason used to give, in exchange for
 * a login page that can say what's actually wrong — including the passwordless-legacy-account case, which
 * a generic "wrong password" would otherwise misstate.
 */
export async function authenticateCustomer(db: D1Database, email: string, password: string): Promise<AuthResult> {
  const normalized = normalizeEmail(email);
  const row = await db
    .prepare('SELECT id, password_hash, status FROM customers WHERE email = ?')
    .bind(normalized)
    .first<{ id: string; password_hash: string | null; status: string }>();

  if (!row) {
    // Still pay PBKDF2's cost even for an unknown email, so this path isn't trivially cheaper to probe.
    await verifyPassword(password, DUMMY_HASH);
    return { ok: false, reason: 'unknown_email' };
  }
  if (!row.password_hash) return { ok: false, reason: 'no_password' };
  if (!(await verifyPassword(password, row.password_hash))) return { ok: false, reason: 'wrong_password' };
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
  const email = normalizeEmail(formString(form, 'email'));
  const password = formString(form, 'password');

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
    if (auth.reason === 'unknown_email') return reRender('No account exists with that email.');
    if (auth.reason === 'no_password') return reRender('This account has no password set yet. Contact MDtronix to get one set.');
    return reRender('Incorrect password.');
  }

  await env.CUSTOMERS.prepare('UPDATE customers SET last_login_at = ? WHERE id = ?').bind(nowSeconds(), auth.customerId).run();
  const token = await createSession(env.CUSTOMERS, auth.customerId);
  return redirect(next, [sessionCookie(token)]);
}
