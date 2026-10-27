-- Kopia archiwum poza serwerem (S3 z Object Lock): czas wysłania godziny.
-- Godziny sprzed włączenia kopii wysyłane są od najstarszej w retencji.
ALTER TABLE urd.manifests ADD COLUMN offsite_at timestamptz;
CREATE INDEX manifests_offsite_pending ON urd.manifests (seq) WHERE offsite_at IS NULL AND expired_at IS NULL;
