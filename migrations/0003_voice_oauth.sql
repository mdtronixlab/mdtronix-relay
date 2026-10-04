-- 0003: OAuth account linking for Google Home and Alexa (docs/remote-access/PROTOCOL.md, voice section).
-- oauth_grants already exists from 0001: one row per linked platform, with the refresh token stored hashed.

-- Short-lived authorization codes. Only the hash is stored, and a code is single-use.
CREATE TABLE oauth_codes (
  id              TEXT PRIMARY KEY,
  code_hash       TEXT NOT NULL UNIQUE,
  platform        TEXT NOT NULL CHECK (platform IN ('google', 'alexa')),
  customer_id     TEXT NOT NULL REFERENCES customers(id),
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER,
  created_at      INTEGER NOT NULL
);

-- Access tokens are short-lived and belong to a grant. Only their hashes are stored.
CREATE TABLE oauth_access_tokens (
  id          TEXT PRIMARY KEY,
  grant_id    TEXT NOT NULL REFERENCES oauth_grants(id),
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_oauth_access_tokens_grant ON oauth_access_tokens(grant_id);
