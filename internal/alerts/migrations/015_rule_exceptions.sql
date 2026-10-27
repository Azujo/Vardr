-- Wyjątki reguł (wersja 1.5.3): warunek w składni selekcji Sigma (pole
-- [|modyfikator] → wartość albo lista); zdarzenia spełniające warunek nie
-- trafiają w regułę – w obu silnikach. Wyjątek osłabia wykrywanie, więc ma
-- powód, autora, opcjonalną datę wygaśnięcia (po niej detektor go pomija)
-- i znacznik, czy zaproponował go asystent AI.
CREATE TABLE gjallarhorn.rule_exceptions (
    id          bigserial   PRIMARY KEY,
    rule_id     text        NOT NULL,
    match       jsonb       NOT NULL,
    reason      text        NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz,
    ai_proposed boolean     NOT NULL DEFAULT false
);
CREATE INDEX rule_exceptions_rule ON gjallarhorn.rule_exceptions (rule_id);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON gjallarhorn.rule_exceptions TO siem_api;
        GRANT USAGE ON SEQUENCE gjallarhorn.rule_exceptions_id_seq TO siem_api;
    END IF;
END
$$;
