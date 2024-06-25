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
wrangler d1 migrations apply DB
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
DNSPOD_API_ID="get it at DNSPOD.com"
DNSPOD_API_TOKEN=""
DNSPOD_DOMAIN_ID=""
EPUSDT_API_KEY=""
EPUSDT_API_URL=""
RECAPTCHA_SITE_KEY="get it at www.google.com/recaptcha"
RECAPTCHA_SECRET_KEY=""
BREVO_PREFER="auto"
BREVO=[ {"apiKey": "get it at BREVO.com", "senderName": "No reply", "senderAddress": "**"}, {"apiKey": "get it at BREVO.com", "senderName": "No reply", "senderAddress": "**"} ]
```

### Deploy


and bash execute 
```
yarn deploy
```

## License

MIT
