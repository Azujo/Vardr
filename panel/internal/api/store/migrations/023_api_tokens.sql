-- Tokeny API (wersja 1.1): dostęp programów do /api/v1 nagłówkiem
-- Authorization: Bearer. Token ma profil uprawnień jak konto; w bazie
-- tylko skrót SHA-256 – pełny token pokazywany raz, przy utworzeniu.
-- Bez klucza obcego do profiles: unieważnione tokeny nie blokują usunięcia
-- profilu (aktywne – blokuje kod, DeleteProfile).
CREATE TABLE api_tokens (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text        NOT NULL CHECK (name ~ '^[a-zA-Z0-9._-]{2,64}$'),
    description  text        NOT NULL DEFAULT '',
    token_hash   text        NOT NULL UNIQUE,
    prefix       text        NOT NULL,
    profile      text        NOT NULL,
    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    last_used_ip text        NOT NULL DEFAULT '',
    revoked_at   timestamptz,
    revoked_by   text        NOT NULL DEFAULT ''
);
-- Nazwa jest częścią aktora w audycie (api:<nazwa>) – unikalna wśród aktywnych.
CREATE UNIQUE INDEX api_tokens_name_active ON api_tokens (lower(name)) WHERE revoked_at IS NULL;
