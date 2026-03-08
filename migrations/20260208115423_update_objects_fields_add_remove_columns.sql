-- migration/20260208_add_folder_support.sql

-- Add is_folder column
ALTER TABLE objects ADD COLUMN is_folder BOOLEAN NOT NULL DEFAULT FALSE;

-- Make file-specific fields nullable
ALTER TABLE objects ALTER COLUMN size Drop NOT NUll;
ALTER TABLE objects ALTER COLUMN etag DROP NOT NULL;
ALTER TABLE objects ALTER COLUMN last_modified DROP NOT NULL;
ALTER TABLE objects ALTER COLUMN checksum_sha256 DROP NOT NULL;

-- Drop old object_kind column
ALTER TABLE objects DROP COLUMN object_kind;
DROP type object_kind_type;
-- Add constraint ensuring folders have null file metadata
ALTER TABLE objects
ADD CONSTRAINT check_folder_consistency
CHECK (
    (is_folder = FALSE) OR
    (is_folder = TRUE AND size IS NULL  AND etag IS NULL AND mime_type IS NULL AND last_modified IS NULL AND checksum_sha256 IS NULL)
);
