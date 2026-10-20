-- Incydenty: grupa alertów z osią czasu, obsługą i – dla incydentów
-- poważnych w rozumieniu NIS2 (art. 23) – terminami zgłoszeń do CSIRT.
CREATE TABLE incidents (
    id           bigserial   PRIMARY KEY,
    title        text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    severity     text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status       text        NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    assignee     text        NOT NULL DEFAULT '',
    -- NIS2: incydent poważny i chwila jego stwierdzenia (początek terminów).
    significant  boolean     NOT NULL DEFAULT false,
    aware_at     timestamptz,
    -- Treść zgłoszeń: podejrzenie działania bezprawnego lub złośliwego,
    -- wpływ transgraniczny (tak / nie / nieustalone), skutki, przyczyna,
    -- działania ograniczające, wskaźniki naruszenia (IoC).
    malicious    text        NOT NULL DEFAULT 'unknown' CHECK (malicious IN ('yes', 'no', 'unknown')),
    cross_border text        NOT NULL DEFAULT 'unknown' CHECK (cross_border IN ('yes', 'no', 'unknown')),
    impact       text        NOT NULL DEFAULT '',
    root_cause   text        NOT NULL DEFAULT '',
    mitigation   text        NOT NULL DEFAULT '',
    iocs         text        NOT NULL DEFAULT '',
    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    closed_at    timestamptz
);
CREATE INDEX incidents_status ON incidents (status, updated_at DESC);

-- Alerty incydentu – migawka (alert może zniknąć z Gjallarhorna po retencji).
CREATE TABLE incident_alerts (
    incident_id bigint      NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    alert_id    bigint      NOT NULL,
    rule_id     text        NOT NULL,
    rule_title  text        NOT NULL,
    level       text        NOT NULL,
    host_name   text        NOT NULL DEFAULT '',
    agent_id    text        NOT NULL DEFAULT '',
    user_name   text        NOT NULL DEFAULT '',
    summary     text        NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    added_by    text        NOT NULL,
    added_at    timestamptz NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE INDEX incident_alerts_alert ON incident_alerts (alert_id);

-- Oś czasu incydentu (notatki, zmiany, zgłoszenia) – tylko dopisywanie.
CREATE TABLE incident_activity (
    id          bigserial   PRIMARY KEY,
    incident_id bigint      NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL,
    username    text        NOT NULL,
    kind        text        NOT NULL,
    text        text        NOT NULL DEFAULT '',
    details     jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX incident_activity_incident ON incident_activity (incident_id, at);

-- Zgłoszenia do CSIRT: szkic (do edycji), po wysłaniu – zamrożony, z numerem sprawy.
CREATE TABLE incident_reports (
    incident_id  bigint      NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    kind         text        NOT NULL CHECK (kind IN ('early_warning', 'notification', 'intermediate', 'final')),
    content      text        NOT NULL,
    updated_by   text        NOT NULL,
    updated_at   timestamptz NOT NULL,
    submitted_at timestamptz,
    submitted_by text        NOT NULL DEFAULT '',
    reference    text        NOT NULL DEFAULT '',
    PRIMARY KEY (incident_id, kind)
);

-- Wysłane przypomnienia o terminach (bez powtórzeń).
CREATE TABLE incident_reminders (
    incident_id bigint      NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    deadline    text        NOT NULL,
    stage       text        NOT NULL,
    sent_at     timestamptz NOT NULL,
    PRIMARY KEY (incident_id, deadline, stage)
);
