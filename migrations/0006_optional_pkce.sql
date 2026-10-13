-- 0006: Google's own account-linking flow (replacing the legacy Actions on Google redirect) doesn't send
-- PKCE parameters, only a client-secret-authenticated authorization code exchange. Alexa still does, and
-- PKCE stays required there. SQLite can't drop a NOT NULL constraint directly, so the table is recreated.
-- oauth_codes is short-lived (60s TTL), so there's nothing worth preserving across the rebuild.

CREATE TABLE oauth_codes_new (
  id              TEXT PRIMARY KEY,
  code_hash       TEXT NOT NULL UNIQUE,
  platform        TEXT NOT NULL CHECK (platform IN ('google', 'alexa')),
  customer_id     TEXT NOT NULL REFERENCES customers(id),
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER,
  created_at      INTEGER NOT NULL
);

DROP TABLE oauth_codes;
ALTER TABLE oauth_codes_new RENAME TO oauth_codes;
