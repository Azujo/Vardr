-- Praca analityka z alertami (etap 5a): przypisanie i oś czasu alertu
-- (notatki, zmiany stanu i przypisania – także automatyczne, np. powrót agenta).
ALTER TABLE gjallarhorn.alerts ADD COLUMN assignee text NOT NULL DEFAULT '';

CREATE TABLE gjallarhorn.alert_activity (
    id       bigserial PRIMARY KEY,
    alert_id bigint NOT NULL REFERENCES gjallarhorn.alerts (id) ON DELETE CASCADE,
    at       timestamptz NOT NULL DEFAULT now(),
    actor    text NOT NULL,                 -- login albo „system”
    kind     text NOT NULL CHECK (kind IN ('note', 'status', 'assign')),
    text     text NOT NULL DEFAULT '',      -- notatka albo powód
    details  jsonb NOT NULL DEFAULT '{}'    -- np. {"from": "open", "to": "closed"}
);
CREATE INDEX alert_activity_alert ON gjallarhorn.alert_activity (alert_id, id);

-- Filtry listy i alerty powiązane (ten sam komputer albo konto).
CREATE INDEX alerts_host ON gjallarhorn.alerts (lower(host_name), first_seen) WHERE host_name <> '';
CREATE INDEX alerts_user ON gjallarhorn.alerts (lower(user_name), first_seen) WHERE user_name <> '';

-- Dotychczasowe zamknięcia na osi czasu.
INSERT INTO gjallarhorn.alert_activity (alert_id, at, actor, kind, text, details)
SELECT id, closed_at, coalesce(closed_by, 'system'), 'status', coalesce(close_reason, ''),
       jsonb_build_object('to', 'closed')
FROM gjallarhorn.alerts WHERE status = 'closed' AND closed_at IS NOT NULL;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT, INSERT ON gjallarhorn.alert_activity TO siem_api;
        GRANT USAGE ON SEQUENCE gjallarhorn.alert_activity_id_seq TO siem_api;
        GRANT UPDATE (assignee) ON gjallarhorn.alerts TO siem_api;
    END IF;
END
$$;
