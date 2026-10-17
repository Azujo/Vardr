-- Osoba w alercie (przegląd etapu 7): „Powiązane alerty” szukały po koncie,
-- więc alert z Entra (UPN jan@azujo.pl) nie pokazywał alertów AD tej samej
-- osoby (AZUJO\jan). Tożsamość ze zdarzenia (user.identity) zapisuje detektor.
ALTER TABLE gjallarhorn.alerts ADD COLUMN user_identity text NOT NULL DEFAULT '';

-- Dotychczasowe alerty grupowane po osobie (korelacje) – z klucza grupy.
UPDATE gjallarhorn.alerts SET user_identity = group_fields->>'user.identity'
    WHERE group_fields ? 'user.identity' AND group_fields->>'user.identity' <> '';

CREATE INDEX alerts_identity_idx ON gjallarhorn.alerts (user_identity, first_seen) WHERE user_identity <> '';
