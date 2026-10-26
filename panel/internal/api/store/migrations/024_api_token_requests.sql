-- Historia zapytań tokenów API: co program robił w API (metoda, ścieżka
-- z parametrami, wynik, czas, adres). Zapis paczkami w tle (siem-api),
-- retencja SIEM_API_TOKEN_LOG_DAYS (domyślnie 30 dni).
CREATE TABLE api_token_requests (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_id    bigint      NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    at          timestamptz NOT NULL,
    method      text        NOT NULL,
    path        text        NOT NULL,
    status      integer     NOT NULL,
    duration_ms integer     NOT NULL,
    ip          text        NOT NULL DEFAULT ''
);
CREATE INDEX api_token_requests_token ON api_token_requests (token_id, id DESC);
CREATE INDEX api_token_requests_at ON api_token_requests (at);
