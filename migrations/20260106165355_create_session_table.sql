-- Add migration script here

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255),
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
