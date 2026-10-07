-- Stan archiwizatora widoczny w panelu (jeden wiersz) i zlecenie weryfikacji z panelu.
CREATE TABLE urd.archiver_state (
    id                  integer PRIMARY KEY CHECK (id = 1),
    version             text NOT NULL,
    retention_days      integer NOT NULL,
    segment_max_mb      integer NOT NULL,
    segment_max_age_s   integer NOT NULL,
    verify_every_s      integer NOT NULL,
    started_at          timestamptz NOT NULL,
    heartbeat_at        timestamptz NOT NULL,
    verify_requested_at timestamptz,
    verify_requested_by text
);
