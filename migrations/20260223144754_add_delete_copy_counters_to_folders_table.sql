-- Add migration script here
ALTER TABLE folders ADD COLUMN copying_children_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN deleting_children_count INTEGER NOT NULL DEFAULT 0;
