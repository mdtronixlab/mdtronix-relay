-- 0010: Staff-initiated password reset links (docs: the owner's 2026-10-14 decision — the customer
-- contacts staff directly, there's no public "forgot password" form, and no email sending anywhere in
-- this system). Staff generate a link in the CRM and send it to the customer themselves, over whatever
-- channel they already use. Only the token's hash is stored, same as every other token in this schema.

CREATE TABLE password_reset_tokens (
  id          TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_password_reset_tokens_customer ON password_reset_tokens(customer_id);
