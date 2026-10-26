-- Dostęp AI przez MCP (wersja 1.4).
--
-- Rodzaj tokenu API: integracja (programy, skrypty) albo AI (serwer MCP
-- vardr-mcp). Tokeny AI podlegają dodatkowo polityce AI z panelu
-- (narzędzia, zakres danych, maskowanie) – egzekwowanej przy każdym
-- zapytaniu, także z pominięciem vardr-mcp.
ALTER TABLE api_tokens ADD COLUMN kind text NOT NULL DEFAULT 'integration' CHECK (kind IN ('integration', 'ai'));

-- Pseudonimy danych maskowanych dla AI (np. USER-7f3a12bc → login):
-- odwracalne w panelu z uprawnieniem i wpisem w audycie. Pseudonim jest
-- skrótem HMAC wartości (klucz instalacji), więc ta sama wartość ma zawsze
-- ten sam pseudonim – model widzi, że to ta sama osoba, ale nie wie, kto to.
CREATE TABLE ai_pseudonyms (
    pseudonym  text        PRIMARY KEY,
    kind       text        NOT NULL,
    value      text        NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL
);
