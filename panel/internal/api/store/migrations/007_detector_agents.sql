-- Detektor (rola siem_detector, Gjallarhorn) czyta heartbeat agentów, ich
-- grupy (próg alarmu po utracie łączności) i certyfikaty (agent wycofany –
-- wszystkie certyfikaty unieważnione – nie wywołuje alarmu).
-- Bez tej roli (np. w testach) uprawnienia są pomijane.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_detector') THEN
        GRANT USAGE ON SCHEMA public TO siem_detector;
        GRANT SELECT (id, hostname, remote_ip, version, last_seen) ON agents TO siem_detector;
        GRANT SELECT (id, name, limits, is_default) ON agent_groups TO siem_detector;
        GRANT SELECT (agent_id, group_id) ON agent_assignments TO siem_detector;
        GRANT SELECT (agent_id, revoked_at) ON agent_certs TO siem_detector;
    END IF;
END
$$;
