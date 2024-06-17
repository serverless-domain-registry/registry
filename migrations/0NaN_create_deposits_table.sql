-- Migration number: 0NaN 	 2024-06-17T13:22:59.212Z
CREATE TABLE [deposits] ("id" text PRIMARY KEY,"user_id" text,"amount" text,"usdt_address" text,"usdt_amount" text, `status` integer AFTER `amount` COMMENT "0:Unpaid 1:Paid", `created_at` integer, `paid_at` integer);
CREATE INDEX idx_deposits_created_at ON deposits(created_at);
CREATE INDEX idx_deposits_user_id ON deposits(user_id);
CREATE INDEX idx_deposits_usdt_address ON deposits(usdt_address);
CREATE INDEX idx_deposits_amount ON deposits(amount);
CREATE INDEX idx_deposits_status ON deposits(status);
CREATE INDEX idx_deposits_paid_at ON deposits(paid_at);
