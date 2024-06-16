# Opensource Domain-Name Registry

An opensource domain-name registry based on cloudflare workers + d1 database + dnspod.com API!

## Nodejs + Yarn Install

```
yarn
```

## Install wrangler

https://developers.cloudflare.com/workers/wrangler/install-and-update/


## Local development

```
wrangler d1 execute DB --local --file=migration/table.sql
```


```
yarn dev
```


## Deploy to production

### D1 Database

Create a database, import `migration/table.sql`. change db id and other informations in `wrangler.toml`.

### Workers

Create a worker.

import those variables into secrets:
```
APP_ENV="production"
AES_KEY="random aes key"
APP_URL="https://your-domain" 
BREVO_API_KEY="get it at BREVO.com"
DNSPOD_API_ID="get it at DNSPOD.com"
DNSPOD_API_TOKEN=""
DNSPOD_DOMAIN_ID=""
EPUSDT_API_KEY=""
EPUSDT_API_URL=""
MAIL_SENDER_ADDRESS=""
MAIL_SENDER_NAME=""
RECAPTCHA_SECRET_KEY="get it at www.google.com/recaptcha"
RECAPTCHA_SITE_KEY=""
```

### Deploy


and bash execute 
```
yarn deploy
```

## License

MIT
