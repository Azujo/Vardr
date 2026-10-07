-- Polityka archiwum ustawiana w panelu: włączenie, retencja, źródła wyłączone
-- z archiwum (grupy agentów i pojedynczy agenci).
--
-- Panel (urd_reader) składa tylko zlecenia zmian (urd.policy_changes) i może
-- je anulować; zlecenie rozpatruje archiwizator. Osłabienie (wyłączenie,
-- krótsza retencja, wyłączenie źródła) wchodzi w życie po karencji
-- (SIEM_ARCHIVE_POLICY_GRACE), a retencja musi mieścić się w granicach
-- z konfiguracji serwera – przejęcie panelu nie pozwala więc skasować archiwum.
CREATE TABLE urd.policy (
    id              integer PRIMARY KEY CHECK (id = 1),
    enabled         boolean NOT NULL,
    retention_days  integer NOT NULL CHECK (retention_days > 0),
    excluded_groups bigint[] NOT NULL DEFAULT '{}',
    excluded_agents text[] NOT NULL DEFAULT '{}',
    change_id       bigint,
    updated_at      timestamptz NOT NULL,
    updated_by      text NOT NULL
);

CREATE TABLE urd.policy_changes (
    id              bigserial PRIMARY KEY,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    requested_by    text NOT NULL,
    reason          text NOT NULL CHECK (length(reason) BETWEEN 5 AND 1000),
    enabled         boolean NOT NULL,
    retention_days  integer NOT NULL CHECK (retention_days > 0),
    excluded_groups bigint[] NOT NULL DEFAULT '{}' CHECK (cardinality(excluded_groups) <= 1000),
    excluded_agents text[] NOT NULL DEFAULT '{}' CHECK (cardinality(excluded_agents) <= 1000),
    reauth          boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'scheduled', 'applied', 'rejected', 'cancelled', 'superseded')),
    weakening       text[] NOT NULL DEFAULT '{}',
    effective_at    timestamptz,
    applied_at      timestamptz,
    cancelled_at    timestamptz,
    cancelled_by    text,
    error           text NOT NULL DEFAULT ''
);
CREATE INDEX policy_changes_open ON urd.policy_changes (id) WHERE status IN ('pending', 'scheduled');

-- Granice z konfiguracji serwera i źródła wyłączone na stałe (prefiksy agentów
-- z SIEM_ARCHIVE_EXCLUDE_AGENTS) – do pokazania w panelu.
ALTER TABLE urd.archiver_state
    ADD COLUMN min_retention_days integer NOT NULL DEFAULT 0,
    ADD COLUMN max_retention_days integer NOT NULL DEFAULT 0,
    ADD COLUMN policy_grace_s     integer NOT NULL DEFAULT 0,
    ADD COLUMN exclude_prefixes   text[] NOT NULL DEFAULT '{}';

-- Eksport ograniczony do wybranych agentów (część czytelna).
ALTER TABLE urd.exports
    ADD COLUMN agents text[] NOT NULL DEFAULT '{}' CHECK (cardinality(agents) <= 1000);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') THEN
        GRANT SELECT ON urd.policy, urd.policy_changes TO urd_reader;
        GRANT INSERT (requested_by, reason, enabled, retention_days, excluded_groups, excluded_agents, reauth)
            ON urd.policy_changes TO urd_reader;
        GRANT UPDATE (cancelled_at, cancelled_by) ON urd.policy_changes TO urd_reader;
        GRANT USAGE ON SEQUENCE urd.policy_changes_id_seq TO urd_reader;
        GRANT INSERT (agents) ON urd.exports TO urd_reader;
    END IF;
END
$$;
