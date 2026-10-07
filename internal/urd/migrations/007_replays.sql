-- Odtworzenia z archiwum (replay) do osobnej ścieżki i tabeli siem.events_replay.
-- Panel (urd_reader) może tylko złożyć zlecenie (wybrane kolumny) i czytać stan.
CREATE TABLE urd.replays (
    id           bigserial PRIMARY KEY,
    requested_at timestamptz NOT NULL DEFAULT now(),
    requested_by text NOT NULL,
    reason       text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
    from_hour    timestamptz NOT NULL,
    to_hour      timestamptz NOT NULL CHECK (to_hour > from_hour AND to_hour - from_hour <= interval '31 days'),
    agents       text[] NOT NULL DEFAULT '{}' CHECK (cardinality(agents) <= 100),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'failed')),
    started_at   timestamptz,
    finished_at  timestamptz,
    error        text NOT NULL DEFAULT '',
    batches      bigint NOT NULL DEFAULT 0,
    skipped      bigint NOT NULL DEFAULT 0,
    bytes        bigint NOT NULL DEFAULT 0
);
CREATE INDEX replays_pending ON urd.replays (id) WHERE status = 'pending';

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT SELECT ON urd.replays TO urd_reader;
        GRANT INSERT (requested_by, reason, from_hour, to_hour, agents) ON urd.replays TO urd_reader;
        GRANT USAGE ON SEQUENCE urd.replays_id_seq TO urd_reader;
    END IF;
END
$$;
