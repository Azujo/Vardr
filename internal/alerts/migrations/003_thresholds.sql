-- Reguły progowe: parametry progu w opisie reguły i stan progów detektora
-- (zdarzenia z ostatniego okna – restart detektora nie gubi licznika).
ALTER TABLE gjallarhorn.rules ADD COLUMN threshold jsonb;

CREATE TABLE gjallarhorn.threshold_events (
    rule_id      text NOT NULL,
    event_id     text NOT NULL,
    sig          text NOT NULL,             -- parametry progu (zmiana = stan od nowa)
    group_key    text NOT NULL,
    group_fields jsonb NOT NULL DEFAULT '{}',
    event_time   timestamptz NOT NULL,
    value        text NOT NULL DEFAULT '',  -- wartość pola distinct
    agent_id     text NOT NULL DEFAULT '',
    host_name    text NOT NULL DEFAULT '',
    user_name    text NOT NULL DEFAULT '',
    source_ip    text NOT NULL DEFAULT '',
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX threshold_events_expires ON gjallarhorn.threshold_events (expires_at);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT ON gjallarhorn.rules TO siem_api;
    END IF;
END
$$;
