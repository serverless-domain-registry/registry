-- Migration number: 0NaN 	 2024-06-17T13:20:58.873Z
CREATE TABLE [users] ("id" text PRIMARY KEY,"email" text,"mfa_secret" text,"credit" integer DEFAULT 0,"total_spent" integer DEFAULT 0,"created_at" integer,"updated_at" integer);
CREATE UNIQUE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_mfa_secret ON users(mfa_secret);
CREATE INDEX idx_users_created_at ON users(created_at);
