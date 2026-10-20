-- Konta domenowe (logowanie przez LDAPS): źródło konta, SID z AD (stały
-- identyfikator – zmiana loginu w AD nie tworzy drugiego konta) i DN
-- (sprawdzanie hasła przy ponownym podaniu). Hasło kont domenowych sprawdza
-- AD – password_hash jest dla nich nieużywalny.
ALTER TABLE users ADD COLUMN source text NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'ldap'));
ALTER TABLE users ADD COLUMN external_id text;
ALTER TABLE users ADD COLUMN ldap_dn text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_external_id ON users (external_id) WHERE external_id IS NOT NULL;
