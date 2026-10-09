-- Filtr alertów detekcji na kanale powiadomień: minimalny poziom i wybór
-- reguł (wszystkie / tylko wybrane / wszystkie poza wybranymi). Pusty
-- obiekt = wszystkie alerty.
ALTER TABLE notify_channels ADD COLUMN alert_filter jsonb NOT NULL DEFAULT '{}';
