-- Urd – katalog archiwum NIS2: segmenty, łańcuch manifestów, weryfikacje.

CREATE TABLE urd.segments (
    path              text PRIMARY KEY,
    hour              timestamptz NOT NULL,
    sha256            text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    bytes             bigint NOT NULL,
    records           integer NOT NULL,
    first_received_at timestamptz,
    last_received_at  timestamptz,
    created_at        timestamptz NOT NULL,
    manifest_seq      bigint
);
CREATE INDEX segments_open ON urd.segments (created_at) WHERE manifest_seq IS NULL;
CREATE INDEX segments_manifest ON urd.segments (manifest_seq);

-- Wpisy manifestów nie są usuwane po retencji (tylko expired_at), więc
-- ciągłość łańcucha da się sprawdzić od początku archiwum.
CREATE TABLE urd.manifests (
    seq         bigint PRIMARY KEY CHECK (seq > 0),
    hour        timestamptz NOT NULL UNIQUE,
    sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    prev_sha256 text NOT NULL CHECK (prev_sha256 ~ '^[0-9a-f]{64}$'),
    segments    integer NOT NULL,
    records     bigint NOT NULL,
    bytes       bigint NOT NULL,
    created_at  timestamptz NOT NULL,
    expired_at  timestamptz,
    body        bytea NOT NULL
);

CREATE TABLE urd.verifications (
    id          bigserial PRIMARY KEY,
    started_at  timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    ok          boolean NOT NULL,
    manifests   integer NOT NULL,
    segments    integer NOT NULL,
    records     bigint NOT NULL,
    bytes       bigint NOT NULL,
    problems    jsonb NOT NULL DEFAULT '[]'
);
