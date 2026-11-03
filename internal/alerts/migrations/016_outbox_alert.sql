-- Klucz obcy outbox → alerts ma ON DELETE CASCADE: bez indeksu każdy usuwany
-- alert (retencja, sprzątanie po teście) skanował całą tabelę outbox.
CREATE INDEX outbox_alert ON gjallarhorn.outbox (alert_id);
