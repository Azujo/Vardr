-- Reguły w panelu (etap 5c): historia wersji (treść pliku przy każdej zmianie)
-- i włączanie/wyłączanie reguły z panelu ponad ustawienie w pliku.
ALTER TABLE gjallarhorn.rules ADD COLUMN version integer NOT NULL DEFAULT 0;
ALTER TABLE gjallarhorn.rules ADD COLUMN file_enabled boolean NOT NULL DEFAULT true;

CREATE TABLE gjallarhorn.rule_versions (
    rule_id   text NOT NULL,
    version   integer NOT NULL,
    sha256    text NOT NULL,
    file      text NOT NULL,
    source    text NOT NULL,
    loaded_at timestamptz NOT NULL,
    PRIMARY KEY (rule_id, version)
);

-- Ustawienie z panelu (administrator, z powodem i ponownym podaniem hasła).
CREATE TABLE gjallarhorn.rule_overrides (
    rule_id    text PRIMARY KEY,
    enabled    boolean NOT NULL,
    reason     text NOT NULL,
    changed_by text NOT NULL,
    changed_at timestamptz NOT NULL
);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT SELECT ON gjallarhorn.rule_versions TO siem_api;
        GRANT SELECT, INSERT, UPDATE, DELETE ON gjallarhorn.rule_overrides TO siem_api;
        GRANT SELECT ON gjallarhorn.rules TO siem_api;
    END IF;
END
$$;
