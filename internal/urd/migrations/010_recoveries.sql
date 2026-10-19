-- Obsługa niezgodności archiwum (np. po przywróceniu kopii bazy Saga):
-- uzgodnienie spisu z plikami na dysku. Każda operacja jest wpisem tutaj
-- (i plikiem w katalogu archiwum recoveries/ – wpis przetrwa kolejne
-- przywrócenie bazy). Nic nie jest usuwane: pliki są przyjmowane do spisu
-- po sprawdzeniu sum albo odkładane do kwarantanny (archive/quarantine/).
--
--   kind = 'restore'    – po przywróceniu kopii (restore.sh): pliki zapisane
--                         między zrzutem bazy a przywróceniem, okno czasu
--                         window_from..window_to
--   kind = 'adopt'      – decyzja administratora: przyjęcie wskazanych plików
--   kind = 'quarantine' – decyzja administratora: odłożenie plików
CREATE TABLE urd.recoveries (
    id              bigserial PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('restore', 'adopt', 'quarantine')),
    requested_by    text NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    reason          text NOT NULL,
    paths           jsonb NOT NULL DEFAULT '[]',
    backup          text NOT NULL DEFAULT '',
    window_from     timestamptz,
    window_to       timestamptz,
    verification_id bigint,
    processed_at    timestamptz,
    ok              boolean,
    result          jsonb,
    error           text NOT NULL DEFAULT ''
);
CREATE INDEX recoveries_pending ON urd.recoveries (id) WHERE processed_at IS NULL;

-- Pliki na dysku nieznane spisowi (z ostatniej weryfikacji) – lista do
-- decyzji administratora w panelu.
ALTER TABLE urd.verifications ADD COLUMN unknown jsonb NOT NULL DEFAULT '[]';

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT SELECT ON urd.recoveries TO urd_reader;
        GRANT INSERT (kind, requested_by, reason, paths, verification_id) ON urd.recoveries TO urd_reader;
        GRANT USAGE ON SEQUENCE urd.recoveries_id_seq TO urd_reader;
    END IF;
END
$$;
