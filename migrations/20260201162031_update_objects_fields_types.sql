-- Add migration script here
ALTER TABLE objects
    DROP COLUMN status,
    DROP COLUMN visibility,
    ADD COLUMN status object_status NOT NULL DEFAULT 'active',
    ADD COLUMN visibility visibility NOT NULL DEFAULT 'private';
