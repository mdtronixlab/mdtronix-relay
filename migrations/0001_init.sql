-- mdtronix-customers schema, v1. Draft pending review (see docs/remote-access/PHASE0.md).
-- Times are Unix epoch seconds (INTEGER).

CREATE TABLE customers (
  id            TEXT PRIMARY KEY,                       -- opaque account id; also used as the voice agentUserId
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  firebase_uid  TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- One instance per account (customer_id is UNIQUE).
CREATE TABLE instances (
  subdomain          TEXT PRIMARY KEY,                  -- random 10-char label; also the instance id
  customer_id        TEXT NOT NULL UNIQUE REFERENCES customers(id),
  name               TEXT,
  created_at         INTEGER NOT NULL,
  last_connected_at  INTEGER
);

-- Only SHA-256 hashes of tunnel tokens are stored.
CREATE TABLE tunnel_tokens (
  id          TEXT PRIMARY KEY,
  instance    TEXT NOT NULL REFERENCES instances(subdomain),
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER
);
CREATE INDEX idx_tunnel_tokens_instance ON tunnel_tokens(instance);

CREATE TABLE subscriptions (
  customer_id             TEXT PRIMARY KEY REFERENCES customers(id),
  stripe_customer_id      TEXT UNIQUE,
  stripe_subscription_id  TEXT UNIQUE,
  status                  TEXT NOT NULL
                          CHECK (status IN ('trialing', 'active', 'past_due', 'canceled')),
  trial_ends_at           INTEGER,
  current_period_end      INTEGER,
  updated_at              INTEGER NOT NULL
);

-- Voice account links (Google Home, Alexa). Added with the voice phase; kept here so the schema is reviewed once.
CREATE TABLE oauth_grants (
  id                   TEXT PRIMARY KEY,
  customer_id          TEXT NOT NULL REFERENCES customers(id),
  platform             TEXT NOT NULL CHECK (platform IN ('google', 'alexa')),
  refresh_token_hash   TEXT NOT NULL UNIQUE,
  created_at           INTEGER NOT NULL,
  revoked_at           INTEGER
);
CREATE INDEX idx_oauth_grants_customer ON oauth_grants(customer_id);
