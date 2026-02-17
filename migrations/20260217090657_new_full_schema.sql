-- Add migration script here
BEGIN;
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'deleting';
COMMIT;

CREATE TABLE folders (
    id UUID PRIMARY KEY ,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status object_status DEFAULT 'active',
    visibility visibility DEFAULT 'private',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ

);

CREATE TABLE files (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    size BIGINT NOT NULL,
    etag TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    last_modified TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    metadata JSONB,
    status object_status DEFAULT 'active',
    visibility visibility DEFAULT 'private'
);
-- For folder listing (most common query)
CREATE INDEX idx_files_parent_owner_status ON files(parent_id, owner_id, status);

-- For owner-level queries (dashboard, storage usage, etc.)
CREATE INDEX idx_files_owner ON files(owner_id);

-- Enforce unique active filenames per folder
CREATE UNIQUE INDEX uniq_active_files_per_folder ON files(parent_id, owner_id, name) WHERE status = 'active';

-- Optimized worker lookup for deletion jobs
CREATE INDEX idx_files_deleting ON files(id) WHERE status = 'deleting';

-- For folder listing
CREATE INDEX idx_folders_parent_owner_status ON folders(parent_id, owner_id, status);

-- Enforce unique active folder names per parent
CREATE UNIQUE INDEX uniq_active_folders_per_parent ON folders(parent_id, owner_id, name) WHERE status = 'active';

-- Optional: owner-level queries (keep only if needed)
CREATE INDEX idx_folders_owner ON folders(owner_id);
