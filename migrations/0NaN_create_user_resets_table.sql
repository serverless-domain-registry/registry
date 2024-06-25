-- Migration number: 0NaN 	 2024-06-24T02:30:58.873Z
CREATE TABLE [user_resets] ("id" text PRIMARY KEY,"user_id" text,"used_at" integer,"created_at" integer,"updated_at" integer);
CREATE INDEX idx_user_resets_user_id ON user_resets(user_id);
