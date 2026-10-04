-- EML archive schema. Identity columns are intentionally NOT unique:
-- duplicate Message-IDs from distinct sources are retained as conflicts.

CREATE TABLE IF NOT EXISTS ingests (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_name     TEXT,
    status          TEXT NOT NULL CHECK (status IN ('ok','defective','failed')),
    raw_sha256      TEXT NOT NULL,
    raw_size        BIGINT NOT NULL,
    raw_path        TEXT,
    fatal_error     TEXT,
    defect_count    INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ingest_id       BIGINT NOT NULL REFERENCES ingests(id) ON DELETE CASCADE,
    message_id      TEXT,                       -- nullable: missing ids allowed
    subject         TEXT,
    raw_subject     TEXT,
    date            TIMESTAMPTZ,
    from_json       JSONB NOT NULL DEFAULT '[]',
    to_json         JSONB NOT NULL DEFAULT '[]',
    cc_json         JSONB NOT NULL DEFAULT '[]',
    bcc_json        JSONB NOT NULL DEFAULT '[]',
    reply_to_json   JSONB NOT NULL DEFAULT '[]',
    sender_json     JSONB NOT NULL DEFAULT '[]',
    tree_json       JSONB NOT NULL,
    raw_sha256      TEXT NOT NULL,
    raw_path        TEXT,
    thread_key      TEXT,
    missing_id      BOOLEAN NOT NULL DEFAULT FALSE,
    search_tsv      TSVECTOR,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_key);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date DESC);
CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING GIN(search_tsv);

CREATE TABLE IF NOT EXISTS message_headers (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id      BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    ordinal         INT NOT NULL,
    name            TEXT NOT NULL,
    value           TEXT NOT NULL,
    raw_value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_headers_name_value ON message_headers(name, value);

CREATE TABLE IF NOT EXISTS message_identifiers (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_pk      BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('references','in_reply_to','message_id')),
    value           TEXT NOT NULL,
    ordinal         INT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ident_value ON message_identifiers(value);
CREATE INDEX IF NOT EXISTS idx_ident_pk ON message_identifiers(message_pk);

CREATE TABLE IF NOT EXISTS bodies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_pk      BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    mime_path       TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    charset         TEXT,
    declared_charset TEXT,
    disposition     TEXT NOT NULL,
    content_id      TEXT,
    content_location TEXT,
    byte_size       BIGINT NOT NULL,
    text            TEXT,
    safe_html       TEXT,
    escaped_html    TEXT,
    plain_text      TEXT,
    referenced_cids JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_bodies_message ON bodies(message_pk);
CREATE INDEX IF NOT EXISTS idx_bodies_cid ON bodies(content_id);

CREATE TABLE IF NOT EXISTS attachments (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_pk      BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    mime_path       TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    charset         TEXT,
    disposition     TEXT NOT NULL,
    filename        TEXT,
    raw_filename    TEXT,
    content_id      TEXT,
    content_location TEXT,
    byte_size       BIGINT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    storage_path    TEXT,
    stored          BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_attach_message ON attachments(message_pk);
CREATE INDEX IF NOT EXISTS idx_attach_sha ON attachments(checksum_sha256);

CREATE TABLE IF NOT EXISTS defects (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ingest_id       BIGINT NOT NULL REFERENCES ingests(id) ON DELETE CASCADE,
    message_pk      BIGINT REFERENCES messages(id) ON DELETE CASCADE,
    stage           TEXT NOT NULL,
    level           TEXT NOT NULL,
    message         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_defects_ingest ON defects(ingest_id);

CREATE TABLE IF NOT EXISTS thread_runs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ran_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    duplicate_ids   JSONB NOT NULL DEFAULT '{}',
    dangling        JSONB NOT NULL DEFAULT '[]',
    cycles          JSONB NOT NULL DEFAULT '[]',
    weak_suggestions JSONB NOT NULL DEFAULT '[]'
);

-- Provenance link: raw EML digest -> every ingest/parse result of that bytes.
CREATE INDEX IF NOT EXISTS idx_ingests_sha ON ingests(raw_sha256);
