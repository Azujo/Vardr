-- Eksporty dla audytora. Panel (urd_reader) może tylko złożyć zlecenie
-- (wybrane kolumny) i czytać stan; resztę wypełnia archiwizator.
CREATE TABLE urd.exports (
    id           bigserial PRIMARY KEY,
    requested_at timestamptz NOT NULL DEFAULT now(),
    requested_by text NOT NULL,
    reason       text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
    from_hour    timestamptz NOT NULL,
    to_hour      timestamptz NOT NULL CHECK (to_hour > from_hour AND to_hour - from_hour <= interval '31 days'),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'failed', 'expired')),
    started_at   timestamptz,
    finished_at  timestamptz,
    error        text NOT NULL DEFAULT '',
    file_name    text NOT NULL DEFAULT '',
    bytes        bigint NOT NULL DEFAULT 0,
    sha256       text NOT NULL DEFAULT '',
    manifests    integer NOT NULL DEFAULT 0,
    segments     integer NOT NULL DEFAULT 0,
    records      bigint NOT NULL DEFAULT 0
);
CREATE INDEX exports_pending ON urd.exports (id) WHERE status = 'pending';

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT SELECT ON urd.exports TO urd_reader;
        GRANT INSERT (requested_by, reason, from_hour, to_hour) ON urd.exports TO urd_reader;
        GRANT USAGE ON SEQUENCE urd.exports_id_seq TO urd_reader;
    END IF;
END
$$;
