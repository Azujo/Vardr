-- Huginn: agenci znani panelowi i ich ostatni heartbeat.

CREATE TABLE agents (
    id             text        PRIMARY KEY, -- identyfikator z certyfikatu (CN)
    hostname       text        NOT NULL DEFAULT '',
    os             text        NOT NULL DEFAULT '',
    version        text        NOT NULL DEFAULT '',
    remote_ip      text        NOT NULL DEFAULT '',
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL,        -- czas przyjęcia ostatniego heartbeatu
    started_at     timestamptz,                 -- start procesu agenta
    cert_not_after timestamptz,
    cert_serial    text        NOT NULL DEFAULT '',
    status         jsonb       NOT NULL DEFAULT '{}' -- jak `siem_agent status`
);
CREATE INDEX agents_last_seen ON agents (last_seen);
