-- Bifröst: rejestracja agentów tokenem i wydane certyfikaty.

-- Token przechowujemy wyłącznie jako skrót SHA-256 – sam token widzi
-- administrator raz, przy tworzeniu.
CREATE TABLE enrollment_tokens (
    id         bigserial   PRIMARY KEY,
    name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    token_hash text        NOT NULL UNIQUE,
    profile    text        NOT NULL CHECK (profile IN ('workstation', 'server', 'dc')),
    max_uses   integer     NOT NULL DEFAULT 0 CHECK (max_uses >= 0), -- 0 = bez limitu
    uses       integer     NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text        NOT NULL DEFAULT '',
    revoked_at timestamptz
);

-- Certyfikaty wystawione agentom (rejestracja i odnowienia).
CREATE TABLE agent_certs (
    serial        text        PRIMARY KEY, -- szesnastkowo, jak w heartbeacie
    agent_id      text        NOT NULL,
    issued_at     timestamptz NOT NULL DEFAULT now(),
    not_after     timestamptz NOT NULL,
    token_id      bigint      REFERENCES enrollment_tokens (id) ON DELETE SET NULL,
    renewed_from  text        NOT NULL DEFAULT '',
    hostname      text        NOT NULL DEFAULT '',
    remote_ip     text        NOT NULL DEFAULT '',
    revoked_at    timestamptz,
    revoke_reason text        NOT NULL DEFAULT ''
);
CREATE INDEX agent_certs_agent_id ON agent_certs (agent_id);
CREATE INDEX agent_certs_revoked ON agent_certs (revoked_at) WHERE revoked_at IS NOT NULL;
