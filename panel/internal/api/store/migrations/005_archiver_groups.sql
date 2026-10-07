-- Archiwizator (rola siem_archiver) czyta przypisania agentów do grup, żeby
-- stosować wykluczenia grup z polityki archiwum (panel, moduł Urd).
-- Bez tej roli (np. w testach) uprawnienia są pomijane.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_archiver') THEN
        GRANT USAGE ON SCHEMA public TO siem_archiver;
        GRANT SELECT (id, is_default) ON agent_groups TO siem_archiver;
        GRANT SELECT (agent_id, group_id) ON agent_assignments TO siem_archiver;
    END IF;
END
$$;
