-- Kanał Power Automate / Microsoft Teams (wersja 1.2) i podpis HMAC
-- wiadomości: sekret wspólny z odbiorcą (pusty – bez podpisu). Sekret,
-- jak adres kanału, nie wychodzi z API po utworzeniu.
ALTER TABLE notify_channels DROP CONSTRAINT IF EXISTS notify_channels_kind_check;
ALTER TABLE notify_channels ADD CONSTRAINT notify_channels_kind_check CHECK (kind IN ('discord', 'webhook', 'teams'));
ALTER TABLE notify_channels ADD COLUMN signing_secret text NOT NULL DEFAULT '';
