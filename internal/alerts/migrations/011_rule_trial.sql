-- Tryb próbny reguł: reguła liczy trafienia (silnik w locie), ale nie tworzy
-- alertów ani powiadomień – do oceny, czy można ją włączyć (np. reguły
-- zaimportowane z SigmaHQ). Ustawienie z panelu: rule_overrides.trial
-- (enabled = false); początek próby = changed_at.
ALTER TABLE gjallarhorn.rule_overrides ADD COLUMN trial boolean NOT NULL DEFAULT false;

-- Trafienia reguł próbnych zliczane godzinami i komputerami (z przykładem
-- ostatniego zdarzenia). Detektor dopisuje co 30 s i usuwa wpisy starsze
-- niż 35 dni; panel czyści wpisy reguły przy rozpoczęciu próby.
CREATE TABLE gjallarhorn.rule_trial_hits (
    rule_id         text NOT NULL,
    hour            timestamptz NOT NULL,
    host_name       text NOT NULL,
    hits            bigint NOT NULL,
    first_at        timestamptz NOT NULL,
    last_at         timestamptz NOT NULL,
    sample_event_id text NOT NULL,
    sample_summary  text NOT NULL,
    PRIMARY KEY (rule_id, hour, host_name)
);
CREATE INDEX rule_trial_hits_hour ON gjallarhorn.rule_trial_hits (hour);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT, DELETE ON gjallarhorn.rule_trial_hits TO siem_api;
    END IF;
END
$$;
