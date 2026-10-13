-- 0005: Per-customer Alexa grant for proactive state reporting (ChangeReport events).
--
-- Separate from oauth_grants (the relay's own account-linking tokens that Alexa uses to call us).
-- This is the other direction: a grant Alexa gives us, via the Alexa.Authorization/AcceptGrant
-- directive, so we can call Alexa's Event Gateway on our own initiative when a device changes.
-- Unlike oauth_grants, we store the real refresh token (not just its hash), because we are the
-- OAuth client here and need it to ask Amazon for fresh access tokens ourselves.

CREATE TABLE alexa_proactive_grants (
  customer_id              TEXT PRIMARY KEY REFERENCES customers(id),
  refresh_token            TEXT NOT NULL,
  access_token             TEXT,
  access_token_expires_at  INTEGER,
  created_at                INTEGER NOT NULL,
  updated_at                INTEGER NOT NULL
);
