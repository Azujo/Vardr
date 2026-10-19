-- Przywracanie z kopii w panelu: lista kopii (lokalnych i w miejscu
-- docelowym) z zawartością oraz zlecenia z parametrami (list, inspect,
-- restore). Samo przywrócenie wykonuje restore.sh na serwerze (cron),
-- bo wymaga zatrzymania usług.
ALTER TABLE backup_requests ADD COLUMN params jsonb NOT NULL DEFAULT '{}';
ALTER TABLE backup_requests DROP CONSTRAINT backup_requests_action_check;
ALTER TABLE backup_requests ADD CONSTRAINT backup_requests_action_check
    CHECK (action IN ('run', 'test', 'genkey', 'list', 'inspect', 'restore'));

CREATE TABLE backup_files (
    location    text        NOT NULL CHECK (location IN ('local', 'remote')),
    name        text        NOT NULL,
    size_bytes  bigint      NOT NULL DEFAULT 0,
    modified    timestamptz,
    contents    text[],                     -- po sprawdzeniu: saga, config, grafana
    note        text        NOT NULL DEFAULT '',
    listed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (location, name)
);
