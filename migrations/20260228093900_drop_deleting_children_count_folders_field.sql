-- Add migration script here

ALTER TABLE folders
DROP COLUMN IF EXISTS deleting_children_count;
