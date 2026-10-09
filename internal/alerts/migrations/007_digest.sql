-- Burza alertów (etap 5b): ponad limit osobnych powiadomień na regułę
-- alert jest „wstrzymany” (held) i trafia do wiadomości zbiorczej.
ALTER TABLE gjallarhorn.outbox ADD COLUMN held boolean NOT NULL DEFAULT false;
ALTER TABLE gjallarhorn.outbox ADD COLUMN digest_sent_at timestamptz;
CREATE INDEX outbox_held ON gjallarhorn.outbox (sent_at) WHERE held AND digest_sent_at IS NULL;
CREATE INDEX outbox_sent ON gjallarhorn.outbox (sent_at) WHERE sent_at IS NOT NULL AND NOT held;

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') THEN
        GRANT UPDATE (held, digest_sent_at) ON gjallarhorn.outbox TO siem_api;
    END IF;
END
$$;
