-- Klucze bezpieczeństwa i passkeys (WebAuthn, wersja 1.7.3) – drugi
-- składnik obok aplikacji TOTP (konto musi mieć TOTP: kody zapasowe
-- i aplikacja zostają drogą awaryjną). Klucz publiczny w PKIX DER,
-- rp_id – nazwa panelu, dla której klucz zarejestrowano.
CREATE TABLE user_webauthn (
    id            bigserial   PRIMARY KEY,
    user_id       bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea       NOT NULL UNIQUE,
    public_key    bytea       NOT NULL,
    alg           integer     NOT NULL,
    rp_id         text        NOT NULL,
    name          text        NOT NULL,
    aaguid        bytea,
    sign_count    bigint      NOT NULL DEFAULT 0,
    uv            boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL,
    last_used_at  timestamptz
);
CREATE INDEX user_webauthn_user ON user_webauthn (user_id);
