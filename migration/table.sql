CREATE TABLE [users] ("id" text PRIMARY KEY,"email" text,"mfa_secret" text,"credit" integer DEFAULT 0,"total_spent" integer DEFAULT 0,"created_at" integer,"updated_at" integer);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_mfa_secret ON users(mfa_secret);
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE TABLE [domains] ("id" text PRIMARY KEY,"user_id" integer,"domain" text,"status" integer,"ns_servers" text,"expires_at" integer,"created_at" integer,"updated_at" integer, type text COMMENT "free: Free domain, vip: Paid domain");
CREATE INDEX idx_domains_domain ON domains(domain);
CREATE INDEX idx_domains_status ON domains(status);
CREATE INDEX idx_domains_expires_at ON domains(expires_at);
CREATE INDEX idx_domains_created_at ON domains(created_at);
CREATE INDEX idx_domains_type ON domains(type);

CREATE TABLE [sessions] ("id" text PRIMARY KEY,"user_id" integer,"expires_at" integer);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE [deposits] ("id" text PRIMARY KEY,"user_id" text,"amount" text,"usdt_address" text,"usdt_amount" text, `status` integer AFTER `amount` COMMENT "0:Unpaid 1:Paid", `created_at` integer, `paid_at` integer);
CREATE INDEX idx_deposits_created_at ON deposits(created_at);
CREATE INDEX idx_deposits_user_id ON deposits(user_id);
CREATE INDEX idx_deposits_usdt_address ON deposits(usdt_address);
CREATE INDEX idx_deposits_amount ON deposits(amount);
CREATE INDEX idx_deposits_status ON deposits(status);
CREATE INDEX idx_deposits_paid_at ON deposits(paid_at);
