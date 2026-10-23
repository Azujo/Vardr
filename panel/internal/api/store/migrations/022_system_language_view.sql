-- Język systemu dla usług serwera (archiwizator, usługa kopii): komunikaty
-- widoczne w panelu powstają w tym języku. Widok pokazuje tylko to jedno
-- ustawienie – reszta panel_settings (np. hasło konta LDAP) zostaje
-- niedostępna dla ról usług.
CREATE OR REPLACE VIEW system_language AS
    SELECT value AS language FROM panel_settings WHERE key = 'system_language';

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_archiver') THEN
        GRANT USAGE ON SCHEMA public TO siem_archiver;
        GRANT SELECT ON system_language TO siem_archiver;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_detector') THEN
        GRANT USAGE ON SCHEMA public TO siem_detector;
        GRANT SELECT ON system_language TO siem_detector;
    END IF;
END
$$;
