-- Grupy agentów: profil zdarzeń i limity zasobów ustawiane w panelu
-- (konfiguracja agentów z serwera, etap 2).

CREATE TABLE agent_groups (
    id          bigserial   PRIMARY KEY,
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    description text        NOT NULL DEFAULT '',
    profile     text        NOT NULL CHECK (profile IN ('workstation', 'server', 'dc')),
    limits      jsonb       NOT NULL DEFAULT '{}',
    is_default  boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_groups_name ON agent_groups (lower(name));
-- Dokładnie jedna grupa domyślna (dla agentów bez przypisania).
CREATE UNIQUE INDEX agent_groups_one_default ON agent_groups (is_default) WHERE is_default;

INSERT INTO agent_groups (name, description, profile, is_default)
VALUES ('Domyślna', 'Agenci bez przypisanej grupy', 'workstation', true);

-- Przypisanie agenta do grupy (niezależne od heartbeatu – agent może być
-- przypisany, zanim pierwszy raz się zgłosi).
CREATE TABLE agent_assignments (
    agent_id   text        PRIMARY KEY,
    group_id   bigint      NOT NULL REFERENCES agent_groups (id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_assignments_group ON agent_assignments (group_id);

-- Token rejestracyjny przypisuje nowych agentów do grupy.
ALTER TABLE enrollment_tokens ADD COLUMN group_id bigint REFERENCES agent_groups (id) ON DELETE SET NULL;
