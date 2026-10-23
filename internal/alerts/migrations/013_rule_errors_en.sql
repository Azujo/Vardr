-- Błąd reguły po angielsku (panel w innym języku niż polski).
ALTER TABLE gjallarhorn.rule_errors ADD COLUMN error_en text NOT NULL DEFAULT '';
