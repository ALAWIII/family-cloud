-- Add migration script here
CREATE TYPE object_kind_type AS ENUM ('File', 'Folder');

-- Alter table to add the column with the enum type
ALTER TABLE objects
ADD COLUMN object_kind object_kind_type NOT NULL DEFAULT 'File';
