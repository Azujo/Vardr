-- Język panelu wybrany przez użytkownika (kod BCP 47, np. pl, en);
-- pusty – panel bierze język z przeglądarki.
ALTER TABLE users ADD COLUMN language text NOT NULL DEFAULT '';
