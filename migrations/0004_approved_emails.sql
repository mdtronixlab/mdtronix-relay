-- 0004: staff must approve an email before Google sign-in creates an account (docs/remote-access/PHASE0.md).
-- The relay's GitHub repo is public, so this is the gate on who can actually get a working trial.

CREATE TABLE approved_emails (
  email       TEXT PRIMARY KEY COLLATE NOCASE,
  note        TEXT,
  created_at  INTEGER NOT NULL
);

-- Grandfather in everyone already signed in, so this migration doesn't lock out an existing customer.
INSERT INTO approved_emails (email, note, created_at)
SELECT DISTINCT email, 'already a customer when approval was introduced', strftime('%s', 'now')
FROM customers;
