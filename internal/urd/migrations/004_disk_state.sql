-- Stan dysku archiwum i wstrzymanie archiwizacji (panel).
ALTER TABLE urd.archiver_state
    ADD COLUMN disk_free_bytes  bigint NOT NULL DEFAULT 0,
    ADD COLUMN disk_total_bytes bigint NOT NULL DEFAULT 0,
    ADD COLUMN paused_reason    text NOT NULL DEFAULT '';
