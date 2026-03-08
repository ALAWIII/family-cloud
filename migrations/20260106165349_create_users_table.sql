-- Add migration script here
CREATE TABLE IF NOT EXISTS users (
  id UUID CONSTRAINT user_pk PRIMARY KEY,
  username VARCHAR(50) constraint users_username_nn NOT NULL, -- set on signup for the first time
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  storage_quota_bytes BIGINT DEFAULT 2147483648, -- 2GB default
  storage_used_bytes BIGINT DEFAULT 0
);
