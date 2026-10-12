-- Tożsamości osób (etap 7a): domeny organizacji (konta spoza nich zostają
-- osobnymi tożsamościami) i aliasy kont (np. login VPN inny niż w AD).
-- Panel przekazuje konfigurację normalizatorom przez NATS KV (SIEM_IDENTITY).
CREATE TABLE identity_domains (
    domain      text        PRIMARY KEY CHECK (domain = lower(domain) AND length(domain) BETWEEN 1 AND 255),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL
);

CREATE TABLE identity_aliases (
    alias       text        PRIMARY KEY CHECK (alias = lower(alias) AND length(alias) BETWEEN 1 AND 320),
    identity    text        NOT NULL CHECK (identity = lower(identity) AND length(identity) BETWEEN 1 AND 320),
    note        text        NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL
);
