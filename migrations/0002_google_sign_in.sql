-- 0002: Google sign-in replaces email accounts (docs/remote-access/PHASE0.md).
-- customers is rebuilt because firebase_uid carries a UNIQUE constraint and can't be dropped in place.
-- That's safe because 0001 was applied to an empty database on 2026-10-04.

CREATE TABLE customers_new (
  id             TEXT PRIMARY KEY,
  google_sub     TEXT NOT NULL UNIQUE,                   -- Google's stable account id; the account key
  email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email_verified INTEGER NOT NULL DEFAULT 1 CHECK (email_verified = 1),  -- Google only issues verified emails here
  status         TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'suspended', 'deleted')),
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  last_login_at  INTEGER
);

DROP TABLE customers;
ALTER TABLE customers_new RENAME TO customers;

-- Browser sessions after Google sign-in. Only the hash of the cookie token is stored.
CREATE TABLE web_sessions (
  id          TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  revoked_at  INTEGER
);
CREATE INDEX idx_web_sessions_customer ON web_sessions(customer_id);

-- Device authorization for the HA login (RFC 8628). HA polls with device_code. The customer enters user_code in a browser.
CREATE TABLE device_codes (
  id              TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash   TEXT NOT NULL UNIQUE,                 -- hash of the normalised code, e.g. BCDF-GHJK -> BCDFGHJK
  status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'used')),
  customer_id     TEXT REFERENCES customers(id),         -- set when approved
  replace         INTEGER NOT NULL DEFAULT 0,            -- customer chose to replace an existing home
  interval_s      INTEGER NOT NULL DEFAULT 5,            -- polling interval; raised on slow_down
  last_polled_at  INTEGER,
  expires_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);
