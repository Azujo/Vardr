-- Kopie zapasowe sterowane z panelu (siem-backup). Panel zapisuje ustawienia
-- i zlecenia, usługa kopii (rola saga_admin – i tak robi pg_dump całej bazy)
-- wykonuje kopie i zapisuje stan oraz wyniki.

-- Ustawienia (jeden wiersz): JSON internal/backupcfg.Config.
CREATE TABLE backup_config (
    id          integer     PRIMARY KEY CHECK (id = 1),
    config      jsonb       NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL
);

-- Sekrety zaszyfrowane kluczem publicznym usługi kopii (NaCl sealed box) –
-- panel ich nie odczyta. key_id: klucz, którym zaszyfrowano (po zmianie
-- klucza usługi sekret trzeba wpisać ponownie).
CREATE TABLE backup_secrets (
    name        text        PRIMARY KEY CHECK (name IN ('password', 'private_key', 's3_secret')),
    sealed      bytea       NOT NULL,
    key_id      text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL
);

-- Stan usługi kopii (jeden wiersz, pisze siem-backup).
CREATE TABLE backup_runner (
    id              integer     PRIMARY KEY CHECK (id = 1),
    box_public_key  text        NOT NULL DEFAULT '',
    ssh_public_key  text        NOT NULL DEFAULT '',
    host_key        text        NOT NULL DEFAULT '',  -- odcisk klucza serwera SFTP zapisany przy teście
    pass_id         text        NOT NULL DEFAULT '',  -- identyfikator hasła szyfrowania kopii (k + 8 znaków)
    local_dir       text        NOT NULL DEFAULT '',
    local_free      bigint      NOT NULL DEFAULT 0,
    version         text        NOT NULL DEFAULT '',
    seen_at         timestamptz
);

-- Wykonane kopie.
CREATE TABLE backup_runs (
    id           bigserial   PRIMARY KEY,
    kind         text        NOT NULL CHECK (kind IN ('scheduled', 'manual')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text        NOT NULL CHECK (status IN ('running', 'ok', 'partial', 'error')),
    file         text        NOT NULL DEFAULT '',
    size_bytes   bigint      NOT NULL DEFAULT 0,
    remote       text        NOT NULL DEFAULT '',  -- wynik wysyłki: '' (bez), ok, error
    message      text        NOT NULL DEFAULT ''
);
CREATE INDEX backup_runs_started ON backup_runs (started_at DESC);

-- Zlecenia z panelu: kopia teraz, test połączenia, nowy klucz SSH.
CREATE TABLE backup_requests (
    id            bigserial   PRIMARY KEY,
    action        text        NOT NULL CHECK (action IN ('run', 'test', 'genkey')),
    requested_at  timestamptz NOT NULL DEFAULT now(),
    requested_by  text        NOT NULL,
    started_at    timestamptz,
    done_at       timestamptz,
    ok            boolean,
    message       text        NOT NULL DEFAULT ''
);
CREATE INDEX backup_requests_pending ON backup_requests (id) WHERE done_at IS NULL;
