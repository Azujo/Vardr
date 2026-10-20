-- Drugi składnik logowania (TOTP) i ustawienia panelu.

-- Sekret TOTP zaszyfrowany kluczem z pliku na serwerze (certs/mfa.key);
-- last_step: krok ostatnio przyjętego kodu (ten sam kod nie zaloguje dwa razy).
CREATE TABLE user_mfa (
    user_id    bigint      PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_enc bytea       NOT NULL,
    enabled_at timestamptz NOT NULL,
    last_step  bigint      NOT NULL DEFAULT 0
);

-- Jednorazowe kody zapasowe (tylko skrót SHA-256).
CREATE TABLE user_recovery_codes (
    user_id   bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash text   NOT NULL,
    used_at   timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

-- Sesja z potwierdzonym drugim składnikiem (wymóg MFA odcina pozostałe).
ALTER TABLE sessions ADD COLUMN mfa boolean NOT NULL DEFAULT false;

-- Ustawienia panelu (np. mfa_policy: all | admins | none).
CREATE TABLE panel_settings (
    key        text        PRIMARY KEY,
    value      text        NOT NULL,
    changed_by text        NOT NULL,
    changed_at timestamptz NOT NULL
);
