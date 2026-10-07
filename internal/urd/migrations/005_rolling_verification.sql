-- Weryfikacja z budżetem: znacznik pełnego sprawdzenia manifestu i pokrycie.
ALTER TABLE urd.manifests ADD COLUMN verified_at timestamptz;
ALTER TABLE urd.verifications
    ADD COLUMN full_manifests    integer NOT NULL DEFAULT 0,
    ADD COLUMN unverified        integer NOT NULL DEFAULT 0,
    ADD COLUMN oldest_full_check timestamptz;
