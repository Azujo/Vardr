-- Analizy AI alertów (wersja 1.5): odpowiedź asystenta na „Analiza AI”
-- zapisana przy alercie – widoczna na stronie alertu po zamknięciu czatu.
-- Treść jest taka, jaką zobaczył model: przy maskowaniu – z pseudonimami.
CREATE TABLE alert_ai_analyses (
    id          bigserial   PRIMARY KEY,
    alert_id    bigint      NOT NULL,
    created_at  timestamptz NOT NULL,
    created_by  text        NOT NULL,
    model       text        NOT NULL,
    question    text        NOT NULL DEFAULT '',
    answer      text        NOT NULL,
    steps       integer     NOT NULL DEFAULT 0,
    tools       text[]      NOT NULL DEFAULT '{}',
    tokens      integer     NOT NULL DEFAULT 0,
    took_ms     integer     NOT NULL DEFAULT 0
);
CREATE INDEX alert_ai_analyses_alert ON alert_ai_analyses (alert_id, created_at DESC);
