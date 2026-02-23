-- Add migration script here
ALTER TABLE users
ADD COLUMN root_folder_id UUID NOT NULL UNIQUE REFERENCES folders(id)
ON DELETE RESTRICT;
