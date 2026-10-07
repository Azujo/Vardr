-- Saga (PostgreSQL): konta panelu, sesje i dziennik audytu.

CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    username             text        NOT NULL CHECK (username ~ '^[a-zA-Z0-9._-]{2,64}$'),
    display_name         text        NOT NULL DEFAULT '',
    password_hash        text        NOT NULL,
    role                 text        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    disabled             boolean     NOT NULL DEFAULT false,
    must_change_password boolean     NOT NULL DEFAULT true,
    failed_logins        integer     NOT NULL DEFAULT 0,
    locked_until         timestamptz,
    last_login_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_username_lower ON users (lower(username));

-- Sesje: identyfikator to SHA-256 tokenu z ciasteczka (sam token zna tylko
-- przeglądarka).
CREATE TABLE sessions (
    id           text        PRIMARY KEY,
    user_id      bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf         text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    ip           text        NOT NULL DEFAULT '',
    user_agent   text        NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

-- Dziennik audytu: kto, kiedy, co i na czym.
CREATE TABLE audit_log (
    id       bigserial   PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    user_id  bigint      REFERENCES users (id) ON DELETE SET NULL,
    username text        NOT NULL DEFAULT '',
    action   text        NOT NULL,
    target   text        NOT NULL DEFAULT '',
    ip       text        NOT NULL DEFAULT '',
    details  jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at ON audit_log (at DESC);
