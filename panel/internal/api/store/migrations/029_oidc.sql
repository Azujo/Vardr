-- Logowanie przez dostawcę tożsamości OIDC – Entra ID (wersja 1.6.1):
-- konta „oidc” (external_id = „oidc:” + identyfikator obiektu konta, hasło
-- nieużywalne) i potwierdzenie tożsamości u dostawcy w sesji (reauth_at) –
-- zamiast hasła przy operacjach chronionych.
ALTER TABLE users DROP CONSTRAINT users_source_check;
ALTER TABLE users ADD CONSTRAINT users_source_check CHECK (source IN ('local', 'ldap', 'oidc'));
ALTER TABLE sessions ADD COLUMN reauth_at timestamptz;
