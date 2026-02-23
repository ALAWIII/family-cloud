-- Add migration script here
ALTER TABLE users DROP COLUMN IF EXISTS root_folder_id;

ALTER TABLE users
ADD COLUMN root_folder UUID UNIQUE REFERENCES folders(id) ON DELETE RESTRICT;
