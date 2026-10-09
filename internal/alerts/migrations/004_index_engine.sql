-- Silnik zapytań (index_query): punkt kontrolny – zdarzenia przyjęte
-- (kolumna ingested w ClickHouse) do tej chwili są już ocenione.
CREATE TABLE gjallarhorn.index_state (
    id         integer PRIMARY KEY CHECK (id = 1),
    checkpoint timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT ON gjallarhorn.index_state TO siem_api;
    END IF;
END
$$;
