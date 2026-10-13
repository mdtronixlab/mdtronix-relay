-- 0007: Customer login switches from Google OAuth to native email+password (google.ts is removed).
-- Just one nullable column is added, no rebuild: google_sub stays NOT NULL UNIQUE and password_auth.ts
-- fills it with a synthetic unique placeholder for password accounts (same trick web.ts's dev login already
-- uses), and email_verified keeps its CHECK(=1) and is simply always written as 1 — nothing reads that
-- column's value today, it only ever documented that Google had verified the address. Several tables carry
-- a REFERENCES customers(id) FK (instances, subscriptions, oauth_grants, web_sessions, device_codes,
-- oauth_codes, alexa_proactive_grants) with real rows in production, so rebuilding customers the way 0002
-- and 0006 rebuilt their tables isn't worth the FK-ordering risk when a plain ADD COLUMN does the job.

ALTER TABLE customers ADD COLUMN password_hash TEXT;
