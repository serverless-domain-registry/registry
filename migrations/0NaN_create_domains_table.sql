-- Migration number: 0NaN 	 2024-06-17T13:21:24.687Z
CREATE TABLE [domains] ("id" text PRIMARY KEY,"user_id" integer,"domain" text,"status" integer,"ns_servers" text,"expires_at" integer,"created_at" integer,"updated_at" integer, type text COMMENT "free: Free domain, vip: Paid domain");
CREATE INDEX idx_domains_domain ON domains(domain);
CREATE INDEX idx_domains_status ON domains(status);
CREATE INDEX idx_domains_expires_at ON domains(expires_at);
CREATE INDEX idx_domains_created_at ON domains(created_at);
CREATE INDEX idx_domains_type ON domains(type);
