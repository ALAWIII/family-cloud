-- Add migration script here
BEGIN;
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'active';
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'uploading';
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'deleted';
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'deleting';
ALTER TYPE object_status ADD VALUE IF NOT EXISTS 'copying';
COMMIT;

CREATE TYPE JobType AS ENUM ('delete','copy');
CREATE TYPE JobStatus AS  ENUM ('failed','pending');
CREATE TABLE jobs (
    id UUID PRIMARY KEY,
    job_type JobType NOT NULL, -- 'copy', 'delete'
    file_id UUID NOT NULL, -- references files.id (no FK or ON DELETE CASCADE)
    target_parent_id UUID NULL, -- for copy jobs (destination folder)
    status JobStatus NOT NULL DEFAULT 'pending', -- 'pending', 'failed'
    attempts INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_jobs_pending ON jobs(created_at) WHERE status = 'pending';
CREATE INDEX idx_jobs_failed ON jobs(updated_at) WHERE status = 'failed';
