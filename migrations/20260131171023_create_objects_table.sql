-- Add migration script here
CREATE TABLE IF NOT EXISTS objects (
    id UUID PRIMARY KEY,                -- internal unique file_id
    user_id UUID NOT NULL,              -- bucket / owner
    object_key TEXT NOT NULL,           -- RustFS key, e.g. "/shawarma/potato.txt"

    size BIGINT NOT NULL,               -- content_length
    etag TEXT NOT NULL,                 -- e_tag
    mime_type TEXT,                     -- nullable
    last_modified TIMESTAMPTZ NOT NULL, -- from RustFS

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    visibility TEXT NOT NULL CHECK (visibility IN ('Public','Private')),
    status TEXT NOT NULL CHECK (status IN ('Active','Deleted')),

    checksum_sha256 CHAR(64) NOT NULL,   -- sha256 hex string
    custom_metadata JSONB,               -- optional dynamic metadata

    constraint objects_user_id_fk FOREIGN KEY (user_id) references users(id) on delete cascade

);
