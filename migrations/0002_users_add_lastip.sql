-- Migration number: 0002 	 2024-06-25T18:19:54.313Z

-- Add lastip column to users table
ALTER TABLE users ADD COLUMN lastip VARCHAR(39);
-- Add unique index
CREATE UNIQUE INDEX lastip ON users (lastip);
