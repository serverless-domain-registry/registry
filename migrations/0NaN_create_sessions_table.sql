-- Migration number: 0NaN 	 2024-06-17T13:22:32.656Z
CREATE TABLE [sessions] ("id" text PRIMARY KEY,"user_id" integer,"expires_at" integer);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);