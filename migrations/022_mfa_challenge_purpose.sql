-- 022 Extend mfa_challenges.purpose to cover the forced password-change flow.
--
-- `challenge_password_change` (crates/signet/src/mfa/mod.rs) issues a
-- 'change_password' challenge after first-factor authentication when
-- `users.must_change_password` is set. Migration 004 declared the column as
-- CHECK (purpose IN ('login', 'enroll')), so that insert was rejected and the
-- forced-password-change path could never complete.
--
-- The constraint is dropped by looking its name up rather than assuming the
-- auto-generated `<table>_<column>_check` form: if the guessed name were wrong
-- the drop would silently no-op and the old constraint would keep rejecting
-- 'change_password' while a second, redundant constraint was added alongside it.

DO $$
DECLARE
    cname TEXT;
BEGIN
    SELECT conname
      INTO cname
      FROM pg_constraint
     WHERE conrelid = 'mfa_challenges'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) ILIKE '%purpose%';

    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE mfa_challenges DROP CONSTRAINT %I', cname);
    END IF;
END $$;

ALTER TABLE mfa_challenges
    ADD CONSTRAINT mfa_challenges_purpose_check
    CHECK (purpose IN ('login', 'enroll', 'change_password'));
