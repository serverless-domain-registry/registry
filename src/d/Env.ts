import { Sender } from "./Models";

export interface Env {
  // If you set another name in wrangler.toml as the value for 'binding',
  // replace "DB" with the variable name you defined.
  DB: D1Database;
  APP_ENV: 'dev' | 'production';
  APP_URL: string;
  DNSPOD_API_ID: string;
  DNSPOD_API_TOKEN: string;
  DNSPOD_DOMAIN_ID: string;
  AES_KEY: string;
  EPUSDT_API_KEY: string;
  EPUSDT_API_URL: string;
  RECAPTCHA_SITE_KEY: string;
  RECAPTCHA_SECRET_KEY: string;
  BREVO: Sender[];
  BREVO_PREFER: 1 | 2 | 'auto';
  BREVO_API_KEY: string;
  MAIL_SENDER_ADDRESS: string;
  MAIL_SENDER_NAME: string;
  BREVO_API_KEY_2: string;
  MAIL_SENDER_ADDRESS_2: string;
  MAIL_SENDER_NAME_2: string;
}
