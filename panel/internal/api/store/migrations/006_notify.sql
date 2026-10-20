-- Kanały powiadomień (Discord, webhook): dokąd Vardr wysyła wiadomości –
-- alerty zdrowia systemu z Grafany, codzienną kotwicę archiwum, a później
-- alerty detekcji. Adres webhooka jest sekretem: API go nie zwraca.
CREATE TABLE notify_channels (
    id          bigserial   PRIMARY KEY,
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind        text        NOT NULL CHECK (kind IN ('discord', 'webhook')),
    url         text        NOT NULL CHECK (url LIKE 'https://%' AND length(url) <= 2000),
    events      text[]      NOT NULL DEFAULT '{}',
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    last_ok_at  timestamptz,
    last_error  text        NOT NULL DEFAULT '',
    last_error_at timestamptz
);
CREATE UNIQUE INDEX notify_channels_name ON notify_channels (lower(name));

-- Dziennik wysyłek (ostatnie tygodnie; kotwice zostają – to dowód, co i kiedy
-- wyszło poza system).
CREATE TABLE notify_log (
    id          bigserial   PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    channel_id  bigint      REFERENCES notify_channels (id) ON DELETE SET NULL,
    channel     text        NOT NULL,
    event       text        NOT NULL,
    title       text        NOT NULL,
    ok          boolean     NOT NULL,
    error       text        NOT NULL DEFAULT '',
    anchor_seq  bigint,
    anchor_sha256 text
);
CREATE INDEX notify_log_at ON notify_log (at DESC);
CREATE INDEX notify_log_anchor ON notify_log (at DESC) WHERE event = 'anchor' AND ok;
