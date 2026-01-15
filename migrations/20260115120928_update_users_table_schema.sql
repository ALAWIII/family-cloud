-- Add migration script here
ALTER TABLE users
    ALTER COLUMN created_at SET NOT NULL,
    ALTER COLUMN created_at SET DEFAULT NOW(),
    ALTER COLUMN storage_quota_bytes SET NOT NULL,
    ALTER COLUMN storage_quota_bytes SET DEFAULT 2147483648,
    ALTER COLUMN storage_used_bytes SET NOT NULL,
    ALTER COLUMN storage_used_bytes SET DEFAULT 0;
