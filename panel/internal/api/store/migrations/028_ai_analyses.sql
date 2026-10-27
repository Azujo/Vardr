-- Analizy AI alertów i incydentów (wersja 1.5.2): jedna tabela zamiast
-- alert_ai_analyses (1.5.0) – cel (alert albo incydent) i propozycje pól
-- incydentu do zgłoszenia NIS2 (opis, skutki, IoC, przyczyna, środki),
-- które analityk przegląda i przenosi do incydentu.
CREATE TABLE ai_analyses (
    id          bigserial   PRIMARY KEY,
    target      text        NOT NULL CHECK (target IN ('alert', 'incident')),
    target_id   bigint      NOT NULL,
    created_at  timestamptz NOT NULL,
    created_by  text        NOT NULL,
    model       text        NOT NULL,
    question    text        NOT NULL DEFAULT '',
    answer      text        NOT NULL,
    proposal    jsonb,
    steps       integer     NOT NULL DEFAULT 0,
    tools       text[]      NOT NULL DEFAULT '{}',
    tokens      integer     NOT NULL DEFAULT 0,
    took_ms     integer     NOT NULL DEFAULT 0
);
CREATE INDEX ai_analyses_target ON ai_analyses (target, target_id, created_at DESC);

INSERT INTO ai_analyses (target, target_id, created_at, created_by, model, question, answer, steps, tools, tokens, took_ms)
SELECT 'alert', alert_id, created_at, created_by, model, question, answer, steps, tools, tokens, took_ms
FROM alert_ai_analyses ORDER BY id;

DROP TABLE alert_ai_analyses;
