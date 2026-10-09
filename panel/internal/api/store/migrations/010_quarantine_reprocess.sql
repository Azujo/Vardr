-- Ponowne przetwarzanie kwarantanny (etap 6d): zlecenia z panelu i wynik
-- dla każdego wpisu (odzyskany – zdarzenie zapisane, albo nadal błędny
-- z nowym powodem). Wpisy w ClickHouse się nie zmieniają; panel ukrywa
-- odzyskane na podstawie quarantine_outcomes.
CREATE TABLE quarantine_jobs (
    id          bigserial   PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,
    filter      jsonb       NOT NULL DEFAULT '{}',
    status      text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
    total       integer     NOT NULL DEFAULT 0,
    recovered   integer     NOT NULL DEFAULT 0,
    failed      integer     NOT NULL DEFAULT 0,
    finished_at timestamptz,
    error       text        NOT NULL DEFAULT ''
);

CREATE TABLE quarantine_outcomes (
    event_id    text        PRIMARY KEY,
    job_id      bigint      NOT NULL REFERENCES quarantine_jobs (id) ON DELETE CASCADE,
    recovered   boolean     NOT NULL,
    reason      text        NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX quarantine_outcomes_job ON quarantine_outcomes (job_id);
