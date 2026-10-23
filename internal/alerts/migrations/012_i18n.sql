-- Tłumaczenia (kod języka → teksty): reguły – tytuł, opis i instrukcja
-- z vardr.i18n albo z reguł wbudowanych; alerty – tytuł, opis i instrukcja
-- z podstawionymi wartościami, liczone przez detektor przy powstaniu
-- alertu. Dotychczasowe kolumny zostają w języku źródłowym (polskim).
ALTER TABLE gjallarhorn.rules ADD COLUMN i18n jsonb NOT NULL DEFAULT '{}';
ALTER TABLE gjallarhorn.alerts ADD COLUMN i18n jsonb NOT NULL DEFAULT '{}';
