// Staff approval for sign-in. The relay's GitHub repo is public, so without this, anyone who finds it
// could sign in with Google and start a free trial. finishSignIn (google.ts) checks isApprovedEmail
// before creating an account; staff manage the list through the admin API below.

import { nowSeconds } from './crypto';

function normalize(email: string): string {
  return email.trim().toLowerCase();
}

export async function isApprovedEmail(db: D1Database, email: string): Promise<boolean> {
  const row = await db.prepare('SELECT 1 FROM approved_emails WHERE email = ?').bind(normalize(email)).first();
  return row !== null;
}

/** Adds an email to the allowlist, or updates its note if it's already there. */
export async function approveEmail(db: D1Database, email: string, note: string | null): Promise<void> {
  await db
    .prepare(
      `INSERT INTO approved_emails (email, note, created_at) VALUES (?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET note = excluded.note`,
    )
    .bind(normalize(email), note, nowSeconds())
    .run();
}

/** Removes an email from the allowlist. Anyone who already signed in keeps their existing session and
 * account; this only stops a *future* sign-in from succeeding. */
export async function revokeApprovedEmail(db: D1Database, email: string): Promise<boolean> {
  const result = await db.prepare('DELETE FROM approved_emails WHERE email = ?').bind(normalize(email)).run();
  return result.meta.changes === 1;
}

export interface ApprovedEmailRow {
  email: string;
  note: string | null;
  created_at: number;
}

export async function listApprovedEmails(db: D1Database): Promise<ApprovedEmailRow[]> {
  const rows = await db
    .prepare('SELECT email, note, created_at FROM approved_emails ORDER BY created_at DESC LIMIT 1000')
    .all<ApprovedEmailRow>();
  return rows.results ?? [];
}
