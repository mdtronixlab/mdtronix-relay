-- 0009: Cache for the Home Graph API access token used for Google Home proactive state reporting
-- (src/google-report.ts). Unlike Alexa's alexa_proactive_grants, this isn't per-customer: Google
-- authorizes by the project the Smart Home Action belongs to, using one shared service account, so
-- there's only ever one row (id = 'singleton').

CREATE TABLE google_homegraph_token (
  id           TEXT PRIMARY KEY,
  access_token TEXT NOT NULL,
  expires_at   INTEGER NOT NULL
);
