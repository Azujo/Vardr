-- Reguły zapisane w panelu (kreator korelacji): treść YAML (korelacja
-- z regułami bazowymi), wczytywana przez detektor razem z katalogiem reguł
-- jako panel/<id>.yml. Historia treści – jak dla plików, w rule_versions.
CREATE TABLE gjallarhorn.panel_rules (
    id         text PRIMARY KEY,
    source     text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL
);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON gjallarhorn.panel_rules TO siem_api;
    END IF;
END
$$;
