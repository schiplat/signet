-- MFA hardening: a per-challenge attempt throttle and TOTP replay protection.
--
-- `failed_attempts` bounds code guessing on one challenge. The only brake on
-- `/mfa/verify` used to be the global per-IP rate limit, and a correct password
-- never charges the account lockout — so a holder of a stolen password could
-- hold a challenge, guess codes up to the IP budget, re-login for a fresh
-- challenge, and keep going indefinitely.
--
-- `users.totp_last_step` records the newest accepted timestep so a verified
-- code cannot be replayed across challenges within (and slightly beyond) its
-- 30-second step. NULL before the first verification; the comparison is
-- "strictly newer", so the write doubles as the atomic single-use claim.
ALTER TABLE mfa_challenges
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;

ALTER TABLE users
    ADD COLUMN totp_last_step BIGINT;
