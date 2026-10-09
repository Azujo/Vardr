-- Instrukcja dla analityka z wartościami ze zdarzenia (zmienne {{Pole}}
-- w heimdall.instructions reguły są podstawiane przy tworzeniu alertu).
ALTER TABLE gjallarhorn.alerts ADD COLUMN instructions text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT ON gjallarhorn.alerts TO siem_api;
    END IF;
END
$$;
