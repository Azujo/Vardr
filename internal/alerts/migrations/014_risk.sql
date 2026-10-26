-- Scoring ryzyka osób i komputerów (wersja 1.3).
--
-- Rozstrzygnięcie zamkniętego alertu: prawdziwy, uzasadnione działanie albo
-- fałszywy alarm – dwa ostatnie nie liczą się do ryzyka. Puste – bez
-- rozstrzygnięcia (alerty sprzed 1.3, zamknięcia automatyczne).
ALTER TABLE gjallarhorn.alerts ADD COLUMN resolution text NOT NULL DEFAULT ''
    CHECK (resolution IN ('', 'true_positive', 'benign', 'false_positive'));

-- Ustawienia scoringu (jeden wiersz; zmienia panel, czyta detektor).
CREATE TABLE gjallarhorn.risk_config (
    id         integer     PRIMARY KEY CHECK (id = 1),
    config     jsonb       NOT NULL,
    updated_by text        NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Wyniki (liczy detektor co 5 minut; panel tylko czyta). level_since –
-- od kiedy encja ma obecny poziom.
CREATE TABLE gjallarhorn.risk_scores (
    entity_type   text             NOT NULL CHECK (entity_type IN ('user', 'host')),
    entity        text             NOT NULL,
    display       text             NOT NULL,
    score         double precision NOT NULL,
    level         text             NOT NULL,
    alerts        integer          NOT NULL,
    elevated      boolean          NOT NULL DEFAULT false,
    last_alert_at timestamptz      NOT NULL,
    top           jsonb            NOT NULL DEFAULT '[]',
    level_since   timestamptz      NOT NULL,
    updated_at    timestamptz      NOT NULL,
    PRIMARY KEY (entity_type, entity)
);
CREATE INDEX risk_scores_rank ON gjallarhorn.risk_scores (entity_type, score DESC);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT UPDATE (resolution) ON gjallarhorn.alerts TO siem_api;
        GRANT SELECT, INSERT, UPDATE ON gjallarhorn.risk_config TO siem_api;
        GRANT SELECT ON gjallarhorn.risk_scores TO siem_api;
    END IF;
END
$$;
