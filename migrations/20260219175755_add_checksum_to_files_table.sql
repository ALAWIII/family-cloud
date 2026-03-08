-- Add migration script here
ALTER TABLE files ADD COLUMN checksum TEXT;
