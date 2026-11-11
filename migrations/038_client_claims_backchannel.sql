-- Per-client protocol extensions (v0.5.x feature batch):
--
-- `extra_claims`: static or `$field`-resolved claims merged into every
-- id_token/access token this client receives. Kills the most common
-- integration friction ("our app reads employee_id from the token") without a
-- full protocol-mapper engine.
--
-- `backchannel_logout_uri`: OIDC Back-Channel Logout (1.0). When Signet ends
-- the user's sessions, a signed logout token is POSTed here so the RP can
-- clear its own session without a browser round trip.
ALTER TABLE client_apps
    ADD COLUMN extra_claims JSONB,
    ADD COLUMN backchannel_logout_uri TEXT;

-- authorize stores the authentication time on the code so the token exchange
-- can carry `auth_time` in the id_token without another lookup.
ALTER TABLE auth_codes ADD COLUMN auth_time TIMESTAMPTZ;
