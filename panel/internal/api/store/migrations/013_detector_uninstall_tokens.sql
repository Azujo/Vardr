-- Detektor sprawdza, czy zatrzymanie albo deinstalację „tokenem” wykonano
-- tokenem wydanym przez panel – inaczej konfigurację agenta (skrót tokenu)
-- podrobił administrator komputera.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_detector') THEN
        GRANT SELECT (agent_id, token_id) ON agent_uninstall_tokens TO siem_detector;
    END IF;
END
$$;
