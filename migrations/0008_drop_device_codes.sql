-- 0008: The device-code login flow is replaced by the HA integration logging in directly with the
-- customer's email and password (src/ha_login.ts). Nothing writes to device_codes any more, and nothing
-- else references it as a parent, so it's safe to drop outright.

DROP TABLE device_codes;
