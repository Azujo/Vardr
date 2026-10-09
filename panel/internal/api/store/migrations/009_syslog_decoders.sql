-- Dekodery syslog zmienione w panelu (etap 6c): własne definicje (nowy
-- dekoder albo zastąpienie wbudowanego o tym samym id) i wyłączenia.
-- Panel przekazuje je normalizatorom przez NATS KV (SIEM_DECODERS); baza
-- jest źródłem prawdy, a historia wersji pokazuje, kto i co zmienił.
CREATE TABLE syslog_decoders (
    id          text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9._-]{1,63}$'),
    source      text        NOT NULL DEFAULT '' CHECK (length(source) <= 65536),
    enabled     boolean     NOT NULL DEFAULT true,
    revision    integer     NOT NULL DEFAULT 1,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL
);

CREATE TABLE syslog_decoder_versions (
    id          bigserial   PRIMARY KEY,
    decoder_id  text        NOT NULL,
    revision    integer     NOT NULL,
    action      text        NOT NULL CHECK (action IN ('saved', 'enabled', 'disabled', 'reverted')),
    source      text        NOT NULL,
    enabled     boolean     NOT NULL,
    note        text        NOT NULL DEFAULT '',
    changed_at  timestamptz NOT NULL DEFAULT now(),
    changed_by  text        NOT NULL
);
CREATE INDEX syslog_decoder_versions_id ON syslog_decoder_versions (decoder_id, id DESC);
