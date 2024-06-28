-- Migration number: 0001 	 2024-06-25T18:14:17.868Z

-- Add regip column to users table
ALTER TABLE users ADD COLUMN regip VARCHAR(39);
-- Add unique index
CREATE UNIQUE INDEX users_regip ON users (regip);
