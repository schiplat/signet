-- Records which first factor opened an MFA challenge, so the session issued at
-- the end of the continuation is attributed to the same path that started it.
--
-- Federated sign-in now runs through the same MFA gates as a password login
-- (forced password change, TOTP challenge, forced enrollment). The shared
-- continuation endpoints (`/mfa/verify`, `/mfa/enroll/confirm`,
-- `/login/password-change`) used to hard-code the `password` via when they
-- finally issue the session, which would mislabel an SSO-continued sign-in in
-- the `auth.sign_in_blocked` audit trail. Defaults to `password` so rows from
-- before this column existed keep their current meaning.
ALTER TABLE mfa_challenges
    ADD COLUMN via TEXT NOT NULL DEFAULT 'password';
