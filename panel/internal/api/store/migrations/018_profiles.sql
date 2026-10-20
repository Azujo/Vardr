-- Profile uprawnień (macierz moduł → poziom) zamiast stałych ról. Wartości
-- users.role to identyfikatory profili; dawne role to profile wbudowane
-- (ich uprawnienia definiuje kod – kolumna permissions jest dla nich pusta).
CREATE TABLE profiles (
    id          text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,39}$'),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    permissions jsonb       NOT NULL DEFAULT '{}',
    builtin     boolean     NOT NULL DEFAULT false,
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX profiles_name_lower ON profiles (lower(name));

INSERT INTO profiles (id, name, description, builtin) VALUES
    ('admin', 'Administrator', 'pełny dostęp, także do kont, profili i ustawień bezpieczeństwa', true),
    ('analyst', 'Analityk', 'praca z alertami i danymi, bez administracji', true),
    ('viewer', 'Obserwator', 'tylko odczyt', true);

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_profile FOREIGN KEY (role) REFERENCES profiles (id);
