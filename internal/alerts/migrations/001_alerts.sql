-- Gjallarhorn: reguły, alerty i outbox powiadomień. Właściciel: siem_detector.
-- Panel (siem_api) czyta wszystko i obsługuje outbox (wysyłka na kanały
-- powiadomień, których adresy zna tylko panel).

-- Reguły wczytane przez detektor (stan do pokazania w panelu).
CREATE TABLE gjallarhorn.rules (
    id          text PRIMARY KEY,
    title       text NOT NULL,
    level       text NOT NULL,
    description text NOT NULL DEFAULT '',
    tags        text[] NOT NULL DEFAULT '{}',
    file        text NOT NULL,
    source      text NOT NULL,
    mode        text NOT NULL,
    enabled     boolean NOT NULL,
    group_by    text[] NOT NULL DEFAULT '{}',
    suppress_s  integer NOT NULL DEFAULT 0,
    instructions text NOT NULL DEFAULT '',
    loaded_at   timestamptz NOT NULL,
    removed_at  timestamptz
);

-- Błędy wczytania reguł (ostatni przebieg).
CREATE TABLE gjallarhorn.rule_errors (
    file      text PRIMARY KEY,
    error     text NOT NULL,
    seen_at   timestamptz NOT NULL
);

CREATE TABLE gjallarhorn.alerts (
    id             bigserial PRIMARY KEY,
    rule_id        text NOT NULL,
    rule_title     text NOT NULL,
    level          text NOT NULL,
    engine         text NOT NULL,             -- stream | index_query
    group_key      text NOT NULL,             -- wartości group_by albo id zdarzenia
    group_fields   jsonb NOT NULL DEFAULT '{}',
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed')),
    hits           integer NOT NULL DEFAULT 1,
    first_seen     timestamptz NOT NULL,      -- czas pierwszego zdarzenia
    last_seen      timestamptz NOT NULL,      -- czas ostatniego zdarzenia
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    agent_id       text NOT NULL DEFAULT '',
    host_name      text NOT NULL DEFAULT '',
    user_name      text NOT NULL DEFAULT '',
    source_ip      text NOT NULL DEFAULT '',
    first_event_id text NOT NULL,
    summary        text NOT NULL DEFAULT '',
    closed_at      timestamptz,
    closed_by      text,
    close_reason   text
);
CREATE INDEX alerts_open ON gjallarhorn.alerts (rule_id, group_key, last_seen DESC) WHERE status <> 'closed';
CREATE INDEX alerts_created ON gjallarhorn.alerts (id DESC);

-- Zdarzenia przypisane do alertów: (reguła, zdarzenie) najwyżej raz –
-- ponowne dostarczenie albo restart detektora nie dubluje alertów.
CREATE TABLE gjallarhorn.alert_events (
    rule_id    text NOT NULL,
    event_id   text NOT NULL,
    alert_id   bigint REFERENCES gjallarhorn.alerts (id) ON DELETE CASCADE, -- NULL tylko w trakcie zapisu
    event_time timestamptz NOT NULL,
    PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX alert_events_alert ON gjallarhorn.alert_events (alert_id, event_time);

-- Outbox: powiadomienie zapisywane w tej samej transakcji co alert.
CREATE TABLE gjallarhorn.outbox (
    id              bigserial PRIMARY KEY,
    alert_id        bigint NOT NULL REFERENCES gjallarhorn.alerts (id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts        integer NOT NULL DEFAULT 0,
    sent_at         timestamptz,
    last_error      text NOT NULL DEFAULT ''
);
CREATE INDEX outbox_pending ON gjallarhorn.outbox (next_attempt_at) WHERE sent_at IS NULL;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT USAGE ON SCHEMA gjallarhorn TO siem_api;
        GRANT SELECT ON ALL TABLES IN SCHEMA gjallarhorn TO siem_api;
        GRANT UPDATE (next_attempt_at, attempts, sent_at, last_error) ON gjallarhorn.outbox TO siem_api;
        GRANT UPDATE (status, closed_at, closed_by, close_reason, updated_at) ON gjallarhorn.alerts TO siem_api;
    END IF;
END
$$;
