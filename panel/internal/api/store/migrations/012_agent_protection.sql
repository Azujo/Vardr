-- Ochrona agenta (etap 8): jednorazowe tokeny deinstalacji. Panel pokazuje
-- token raz (przy wygenerowaniu); w bazie i na komputerze jest tylko skrót
-- (contract.UninstallHash). Agent zgłasza użycie tokenu w heartbeacie.
CREATE TABLE agent_uninstall_tokens (
    id          bigserial   PRIMARY KEY,
    agent_id    text        NOT NULL,
    token_id    text        NOT NULL UNIQUE,   -- pierwsze 12 znaków skrótu
    hash        text        NOT NULL CHECK (length(hash) = 64),
    reason      text        NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_action text        NOT NULL DEFAULT '', -- stop_token | uninstall_token
    used_by     text        NOT NULL DEFAULT '', -- konto Windows z raportu agenta
    revoked_at  timestamptz,
    revoked_by  text        NOT NULL DEFAULT ''
);
CREATE INDEX agent_uninstall_tokens_agent ON agent_uninstall_tokens (agent_id, created_at DESC);

-- Detektor czyta zdarzenia ochrony agentów (status.protection.events) i powód
-- zatrzymania (status.stopping) – alerty sabotażu.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_detector') THEN
        GRANT SELECT (status, started_at) ON agents TO siem_detector;
    END IF;
END
$$;
