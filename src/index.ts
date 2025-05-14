import { Router } from 'itty-router'
import { Env } from './d/Env.ts';
import { generateSecret, validateTotp } from './lib/totp.ts';
import { bufferToHex, decryptData, encryptData, hexToBuffer, } from './lib/aes.ts';
import { createNsRecord, deleteNsRecord } from './lib/dnspod.ts';
import { Domain, DomainRenewPeriodOptions, DomainRenewPeriodOptionsType, DomainStatus, User } from './d/Models';
import recaptchaChallange from './lib/recaptchaChallange.ts';
import readRequestBody from './lib/readRequestBody.ts';
import badwords from './Badwords.ts';
import uuid from './lib/uuid.ts';
import loginSession from './lib/loginSession.ts';
import logout from './pages/dashboard/logout.ts';
import readRequestQuery from './lib/readRequestQuery.ts';
import Epusdt from './lib/epusdt.ts';
import sendmail from './lib/sendmail.ts';

// @ts-ignore
import headerTpl from 'template/common/header.html';
// @ts-ignore
import footerTpl from 'template/common/footer.html';
// @ts-ignore
import authHeaderTpl from 'template/common/auth/header.html';
// @ts-ignore
import authFooterTpl from 'template/common/auth/footer.html';
// @ts-ignore
import recaptchaTpl from 'template/common/recaptcha.html';
// @ts-ignore
import dashboardBannerTpl from 'template/dashboard/common/banner.html';
// @ts-ignore
import indexTpl from 'template/index.html';
// @ts-ignore
import authLoginTpl from 'template/auth/login.html';
// @ts-ignore
import authLoginMfaTpl from 'template/auth/login-mfa.html';
// @ts-ignore
import authRegisterTpl from 'template/auth/register.html';
// @ts-ignore
import authResetTpl from 'template/auth/reset.html';
// @ts-ignore
import authMfaRecoveryTpl from 'template/auth/mfa-recovery.html';
// @ts-ignore
import whoisLookupTpl from 'template/whois-lookup.html';
// @ts-ignore
import resourcesNewsTpl from 'template/resources/news.html';
// @ts-ignore
import resourcesTermOfServiceTpl from 'template/resources/term-of-service.html';
// @ts-ignore
import resourcesPrivacyTpl from 'template/resources/privacy.html';
// @ts-ignore
import resourcesUseCasesTpl from 'template/resources/use-cases.html';
// @ts-ignore
import resourcesRegistrarsTpl from 'template/resources/registrars.html';
// @ts-ignore
import supportReportAbuseTpl from 'template/support/report-abuse.html';
// @ts-ignore
import emailActivationTpl from 'template/email/activation.html';
// @ts-ignore
import emailMfaRecoveryTpl from 'template/email/mfa-recovery.html';
// @ts-ignore
import dashboardTpl from 'template/dashboard/index.html';
// @ts-ignore
import dashboardRegDomainTpl from 'template/dashboard/reg-domain.html';
// @ts-ignore
import dashboardDomainsTpl from 'template/dashboard/domains.html';
// @ts-ignore
import dashboardCreditTpl from 'template/dashboard/credit.html';
// @ts-ignore
import livechatTpl from 'template/dashboard/livechat.html';

const maxFreeDomainNumber = 10;
const maxFreeDomainDuration = 180;
const headers = new Headers();
headers.set('content-type', 'text/html');

const get_session_id = (request: Request) => {
  const cookie = request.headers.get('cookie');
  if (!cookie) {
    return false;
  }
  const matches = cookie.match(/session_id=([^\;]+)/);
  if (!matches || matches.length === 1 || !matches[1]) {
    return false;
  }
  const session_id = matches[1];

  return session_id;
}

const get_user = async (env: Env, session_id: string | false): Promise<false | User> => {
  if (!session_id) {
    return false;
  }
  const session = await env.DB.prepare(`SELECT * FROM sessions WHERE id=?`).bind(session_id).first();
  if (!session) {
    return false;
  }
  return <User>await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(session.user_id).first();
}

const router = Router()

router.get('/', async (request: Request, env: Env, ctx: ExecutionContext) => {
  return new Response(indexTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), { headers, });
});

router.get('/whois-lookup', async (request: Request, env: Env, ctx: ExecutionContext) => {
  var query = <{ domain?: string; }>await readRequestQuery(request);
  return new Response(whoisLookupTpl.replace(/\%\%DOMAIN\%\%/g, query.domain ? query.domain : '').replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), {
    headers,
  });
});

router.post('/whois-lookup', async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    if (!await recaptchaChallange(env, request)) {
      return Response.json({
        success: false,
        message: 'Captcha challenge fail',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `Captcha challenge fail: ${err}`,
    });
  }

  const post = <{ domain: string }>await readRequestBody(request);
  const domain = post.domain.trim().toLowerCase();

  if (!domain.endsWith(`.com.mp`)) {
    return Response.json({
      success: false,
      message: 'Domain name must ends with `.com.mp`',
    });
  }

  if (domain.length > 7 + 64) {
    return Response.json({
      success: false,
      message: 'Domain name length exeeded',
    });
  }

  const r = domain.match(/\./g);
  if (!r || r?.length > 2) {
    return Response.json({
      success: false,
      message: 'Subdomain not allowed to query WHOIS',
    });
  }
  if (
    domain.startsWith(`-`) || domain.endsWith(`-`) || domain.startsWith(`_`) || domain.endsWith(`_`) ||
    domain.startsWith(`.`) || domain.endsWith(`.`) ||
    domain.includes(`@`) || !domain.match(/^[\.\-\_\w\d]+$/)
  ) {
    return Response.json({
      success: false,
      message: `Invalid domain ${domain}`,
    });
  }

  if (badwords.includes(domain) || badwords.includes(domain.replace(/\.com\.mp$/, ''))) {
    return Response.json({
      success: false,
      message: 'Reserved domain',
    });
  }

  const domainExists = <Domain>await env.DB.prepare(`SELECT * FROM domains WHERE domain=?`)
    .bind(domain)
    .first();

  if (domainExists) {
    if (domainExists.ns_servers) {
      domainExists.ns_servers = JSON.parse(domainExists.ns_servers);
    }

    domainExists.contact = domainExists.id.trim() + '@privacy.com.mp';
    delete (domainExists.id);
    delete (domainExists.user_id);
  }

  return Response.json({
    success: true,
    data: {
      exists: !!domainExists,
      domain: domainExists,
    }
  });
});

router.get('/resources/news', async () => {
  return new Response(resourcesNewsTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), {
    headers,
  });
});

router.get('/resources/term-of-service', async () => {
  return new Response(resourcesTermOfServiceTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), {
    headers,
  });
});

router.get('/resources/privacy', async () => {
  return new Response(resourcesPrivacyTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), {
    headers,
  });
});

router.get('/resources/use-cases', async () => {
  return new Response(resourcesUseCasesTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), {
    headers,
  });
});

router.get('/resources/registrars', async () => {
  return new Response(resourcesRegistrarsTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl), {
    headers,
  });
});

router.get('/support/report-abuse', async (request: Request, env: Env, ctx: ExecutionContext) => {
  return new Response(supportReportAbuseTpl.replace(/\%\%HEADER\%\%/g, headerTpl).replace(/\%\%FOOTER\%\%/g, footerTpl).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), {
    headers,
  });
});

// @TODO: report abuse process

router.get('/auth/login', async (request: Request, env: Env, ctx: ExecutionContext) => {
  return new Response(authLoginTpl.replace(/\%\%HEADER\%\%/g, authHeaderTpl).replace(/\%\%FOOTER\%\%/g, authFooterTpl), { headers, });
});

router.post('/auth/login', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const post = <{ email: string; token: string; secret: string; }>await readRequestBody(request);
  const user = <User>await env.DB.prepare(`SELECT * FROM users WHERE email=?`)
    .bind(post.email)
    .first();

  if (!user) {
    // not registered
    const secret = generateSecret();
    var tpl = authRegisterTpl;
    return Response.redirect(`${(new URL(request.url)).origin}/auth/register?email=${encodeURIComponent(post.email)}`);
  }

  return Response.redirect(`${(new URL(request.url)).origin}/auth/login/auth-factor?email=${encodeURIComponent(post.email)}`)
});

router.get('/auth/login/auth-factor', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const get = await readRequestQuery(request);
  if (!get.email) {
    return Response.redirect(`${(new URL(request.url)).origin}/auth/login`);
  }
  return new Response(authLoginMfaTpl.replace(/\%\%HEADER\%\%/g, authHeaderTpl).replace(/\%\%FOOTER\%\%/g, authFooterTpl).replace(/\%\%EMAIL\%\%/g, get.email).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/auth/login/auth-factor', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const post = <{ email: string; token: string; secret: string; }>await readRequestBody(request);

  try {
    if (!await recaptchaChallange(env, request)) {
      return Response.json({
        success: false,
        message: 'Captcha challenge fail',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `Captcha challenge fail: ${err}`,
    });
  }

  const token = post.token;
  const user = <User>await env.DB.prepare(`SELECT * FROM users WHERE email=?`)
    .bind(post.email.toLowerCase())
    .first();

  if (!user) {
    return Response.json({
      success: false,
      message: 'Email is not registered',
    });
  }

  const secret = user.mfa_secret;

  if (!secret) {
    return Response.json({
      success: false,
      message: 'MFA is not enabled for this account',
    });
  }

  if (!token) {
    return Response.json({
      success: false,
      message: 'MFA code is required',
    });
  }

  try {
    if (!(await validateTotp(token, secret))) {
      return Response.json({
        success: false,
        message: 'MFA code is invalid, try to calibrate the OTP device sys time?',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `MFA code is invalid, try to calibrate the OTP device sys time?\n${err}`,
    });
  }

  const user_id = user.id;
  const ip = request.headers.get('cf-connecting-ip');

  await env.DB.prepare(`UPDATE users SET lastip=?2 WHERE id=?1`).bind(user_id, ip).run();

  return await loginSession(request, env.DB, user_id, 'json');
});

router.get('/auth/register', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const get = await readRequestQuery(request);
  if (!get.email) {
    return Response.redirect(`${(new URL(request.url)).origin}/auth/login`);
  }
  const secret = generateSecret();
  return new Response(authRegisterTpl.replace(/\%\%HEADER\%\%/g, authHeaderTpl).replace(/\%\%FOOTER\%\%/g, authFooterTpl).replace(/\%\%EMAIL\%\%/g, get.email).replace(/\%\%SECRET\%\%/g, secret).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/auth/register', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const post = <{ email: string; token: string; secret: string;}>await readRequestBody(request);
  const ip = request.headers.get('cf-connecting-ip');

  try {
    if (!await recaptchaChallange(env, request)) {
      return Response.json({
        success: false,
        message: 'Captcha challenge fail',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `Captcha challenge fail: ${err}`,
    });
  }

  const user = await env.DB.prepare(`SELECT * FROM users WHERE email=?1 or regip=?2 or lastip=?3`)
    .bind(post.email, ip, ip)
    .first();

  if (user && user.email === post.email) {
    return Response.json({
      success: false,
      message: 'Another account with the email address already exists',
    });
  }
  if (user && (user.regip === ip || user.lastip === ip)) {
    return Response.json({
      success: false,
      message: 'Register fail, please try again later',
    });
  }

  const secret = post.secret;
  if (!secret) {
    return Response.json({
      success: false,
      message: 'MFA secret is required',
    });
  }

  const token = post.token;
  if (!token) {
    return Response.json({
      success: false,
      message: 'MFA code is required',
    });
  }
  try {
    if (!(await validateTotp(token, secret))) {
      return Response.json({
        success: false,
        message: 'MFA code is invalid, try to calibrate the OTP device sys time?',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `MFA code is invalid, try to calibrate the OTP device sys time?\n${err}`,
    });
  }
  const expiration = new Date().getTime() + 86400 * 1000;

  // Sample data to encrypt
  const { iv, data: encryptedData } = await encryptData(env.AES_KEY, JSON.stringify({
    sub: post.email.toLowerCase(),
    exp: expiration,
    iat: new Date().getTime(),
    sec: secret,
  }));

  const encryptedDataHex = bufferToHex(encryptedData);
  const ivHex = bufferToHex(iv);
  const activation_link = `${env.APP_URL}/auth/register/activation?data=${encryptedDataHex}&sign=${ivHex}`;

  try {
    await sendmail(
      post.email.toLowerCase(),
      'Activate your registry.com.mp account',
      emailActivationTpl.replace(/\%\%EMAIL\%\%/g, post.email).replace(/\%\%ACTIVATION_LINK\%\%/g, activation_link),
      env
    );

    return Response.json({
      success: true,
      message: `Email sent, Please check inbox(including spam fold) for activation link. If nothing found, add our sender mail address to the whitelist: no-reply@registry.com.mp, and refill the register form.`,
    });
  } catch (err) {
    return Response.json({
      success: false,
      message: `Failed to send email: ${err}`,
    });
  }
});

router.get('/auth/register/activation', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const encryptData = new URL(request.url).searchParams.get('data');
  const ivData = new URL(request.url).searchParams.get('sign');
  if (!encryptData || !ivData) {
    return new Response(`Invalid activation link`, { headers, });
  }
  let email: string, expiration: number, signupTime: number, secret: string;
  let ip = request.headers.get('cf-connecting-ip');

  try {
    const decrypted = JSON.parse(await decryptData(env.AES_KEY, hexToBuffer(encryptData), hexToBuffer(ivData)));
    email = decrypted.sub.toLowerCase();
    expiration = decrypted.exp;
    signupTime = decrypted.iat;
    secret = decrypted.sec;
  } catch (err) {
    return new Response(`Invalid activation link: ${err}`, { headers, });
  }

  if (expiration < (new Date).getTime() || await env.DB.prepare(`SELECT * FROM users WHERE mfa_secret=?1 AND created_at=?2`).bind(secret, signupTime).first()) {
    return new Response(`Link expired`, { headers, });
  }

  // do register db insert
  const user_id = uuid();
  await env.DB.prepare(`INSERT INTO users (id, email, mfa_secret, credit, total_spent, regip, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`).bind(user_id, email.toLowerCase(), secret, 0, 0, ip, signupTime).run();

  return await loginSession(request, env.DB, user_id, 'Your account has been activated successfully! Redirecting...');
});

router.get('/auth/reset', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const get = await readRequestQuery(request);

  return new Response(authResetTpl.replace(/\%\%HEADER\%\%/g, authHeaderTpl).replace(/\%\%FOOTER\%\%/g, authFooterTpl).replace(/\%\%EMAIL\%\%/g, get.email || ``).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/auth/reset', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const post = await readRequestBody(request);

  const user = <User>await env.DB.prepare(`SELECT * FROM users WHERE email=?`)
    .bind(post.email)
    .first();

  if (!user) {
    return Response.json({
      success: false,
      message: `An user with email ${post.email} doesn't exists.`,
    });
  }

  const reset_id = uuid();
  await env.DB.prepare(`INSERT INTO user_resets (id, user_id, used_at, created_at) VALUES (?1, ?2, ?3, ?4)`).bind(reset_id, user.id, null, (new Date).getTime()).run();

  const expiration = new Date().getTime() + 86400 * 1000;

  const { iv, data: encryptedData } = await encryptData(env.AES_KEY, JSON.stringify({
    sub: reset_id,
    exp: expiration,
    iat: new Date().getTime(),
  }));
  const encryptedDataHex = bufferToHex(encryptedData);
  const ivHex = bufferToHex(iv);
  const reset_link = `${env.APP_URL}/auth/recovery-mfa?data=${encryptedDataHex}&sign=${ivHex}`;
  const message = emailMfaRecoveryTpl.replace(/\%\%EMAIL\%\%/g, post.email).replace(/\%\%RESET_LINK\%\%/g, reset_link);

  await sendmail(user.email, 'Recovery your Com.mp Registry account\'s MFA', message, env);

  return Response.json({
    success: true,
    message: `Please continue reset process followiing the instruction which sent to your email ${post.email}.<br/>If unable to receive, try to whitelist our email addresses: <br/>no-reply@registry.com.mp,  <br/>no-reply@nic.com.mp,  <br/>no-reply@support.com.mp`,
  });
});

router.get('/auth/recovery-mfa', async(request: Request, env: Env, ctx: ExecutionContext) => {
  const encryptData = new URL(request.url).searchParams.get('data');
  const ivData = new URL(request.url).searchParams.get('sign');
  if (!encryptData || !ivData) {
    return new Response(`Invalid activation link`, { headers, });
  }
  let expiration: number;
  let reset_id: string;

  try {
    const decrypted = JSON.parse(await decryptData(env.AES_KEY, hexToBuffer(encryptData), hexToBuffer(ivData)));
    reset_id = decrypted.sub;
    expiration = decrypted.exp;
  } catch (err) {
    return new Response(`Invalid activation link: ${err}`, { headers, });
  }

  const user_reset = await env.DB.prepare(`SELECT * FROM user_resets WHERE id=?`).bind(reset_id).first();
  if (!user_reset) {
    return new Response('User_resets not found', { headers, });
  }

  if (expiration < (new Date).getTime() || user_reset.used_at) {
    return new Response(`Link expired`, { headers, });
  }

  const user = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(user_reset.user_id).first();
  if (!user) {
    return new Response('User not found', { headers, });
  }

  const email = user.email;
  const secret = generateSecret();
  const tpl = authMfaRecoveryTpl;
  return new Response(tpl.replace(/\%\%HEADER\%\%/, authHeaderTpl).replace(/\%\%FOOTER\%\%/, authFooterTpl).replace(/\%\%EMAIL\%\%/g, email).replace(/\%\%SECRET\%\%/g, secret).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/auth/recovery-mfa', async(request: Request, env: Env, ctx: ExecutionContext) => {
  const {secret, token} = await readRequestBody(request);

  const encryptData = new URL(request.url).searchParams.get('data');
  const ivData = new URL(request.url).searchParams.get('sign');
  if (!encryptData || !ivData) {
    return Response.json({
      success: false,
      message: `Invalid activation link`,
    });
  }
  let expiration: number;
  let reset_id: string;

  try {
    const decrypted = JSON.parse(await decryptData(env.AES_KEY, hexToBuffer(encryptData), hexToBuffer(ivData)));
    reset_id = decrypted.sub;
    expiration = decrypted.exp;
  } catch (err) {
    return Response.json({
      success: false,
      message: `Invalid activation link: ${err}`,
    });
  }

  const user_reset = await env.DB.prepare(`SELECT * FROM user_resets WHERE id=?`).bind(reset_id).first();
  if (!user_reset) {
    return Response.json({
      success: false,
      message: 'User_resets not found',
    });
  }

  if (expiration < (new Date).getTime() || user_reset.used_at) {
    return Response.json({
      success: false,
      message: `Link expired`,
    });
  }

  const user = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(user_reset.user_id).first();
  if (!user) {
    return Response.json({
      success: false,
      message: 'User not found',
    });
  }

  try {
    if (!(await validateTotp(token, secret))) {
      return Response.json({
        success: false,
        message: 'MFA code is invalid, try to calibrate the OTP device sys time?',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `MFA code is invalid, try to calibrate the OTP device sys time?\n${err}`,
    });
  }

  await env.DB.prepare(`UPDATE user_resets SET used_at=?2 WHERE id=?1`).bind(reset_id, (new Date).getTime()).run();
  await env.DB.prepare(`UPDATE users SET mfa_secret=?2, updated_at=?3 WHERE id=?1`).bind(user.id, secret, (new Date).getTime()).run();

  return Response.json({
    success: false,
    message: 'MFA recovery successfully',
  });
});

router.any('/deposit-callback/*', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const epusdt = new Epusdt(env.EPUSDT_API_URL, env.EPUSDT_API_KEY);
  return await epusdt.notify(request, async (request) => {
    const post = await readRequestBody(request);
    if (post.status != 2) {
      return new Response('Request not paid', { headers, });
    }
    if (!post.order_id) {
      return new Response('Deposit order id [order_id] is required', { headers, });
    }

    // await env.DB.transaction(async (txn) => {
    const deposit = await env.DB.prepare(`SELECT * FROM deposits WHERE id=?`).bind(post.order_id).first();
    if (!deposit) {
      // await txn.rollback();
      return new Response('Deposit order not found', { headers, });
    }
    if (deposit.status === 2) {
      // await txn.rollback();
      return new Response('Deposit ordder is already paid', { headers, });
    }

    await env.DB.prepare(`UPDATE deposits SET paid_at=?1, status=?2 WHERE id=?3`).bind(post.order_id, 1, (new Date).getTime()).run();
    await env.DB.prepare(`UPDATE users SET credit=credit+${deposit.amount} WHERE id=?1`).bind(deposit.user_id).run();

    // await txn.commit();
    // });
    return true;
  });
});

router.get('/dashboard', async (request: Request, env: Env, ctx: ExecutionContext) => {
  let tpl = dashboardTpl;

  if (tpl === dashboardTpl) {
    return new Response(`<script>location.href = '/dashboard/domains';</script>`, { headers, });
  }

  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  for (const key in user) {
    let value = <any>user[key];
    if (key === 'credit') {
      value = value.toFixed(2);
    }
    tpl = tpl.replace(new RegExp(`\%\%USER\.${key.toUpperCase()}\%\%`, 'g'), value);
  }
  return new Response(tpl.replace(/\%\%LIVECHAT\%\%/g, livechatTpl.replace(/\%\%USER.CREDIT%%/g, user.credit)).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.get('/dashboard/logout', async (request: Request, env: Env, ctx: ExecutionContext) => {
  return await logout(request, env.DB, get_session_id(request));
});

router.get('/dashboard/domains', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  let tpl = dashboardDomainsTpl;
  for (const key in user) {
    let value = <any>user[key];
    if (key === 'credit') {
      value = value.toFixed(2);
    }
    tpl = tpl.replace(new RegExp(`\%\%USER\.${key.toUpperCase()}\%\%`, 'g'), value);
  }
  return new Response(tpl.replace(/%%BANNER%%/g, dashboardBannerTpl).replace(/\%\%LIVECHAT\%\%/g, livechatTpl.replace(/\%\%USER.CREDIT%%/g, user.credit)).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/dashboard/domains', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  // list data with pagniate
  const post = await readRequestBody(request);

  const sort = ['domain', 'created_at', 'expires_at',].includes(post.sort) ? post.sort : 'created_at';
  const order = ['ASC', 'DESC',].includes(post.order) ? post.order : 'DESC';
  const page = Number(post.page || 1);
  const page_size = Number(post.page_size || 10);
  const search = (post.search || '').trim();
  const start = (page - 1) * page_size;

  const total = <number>await env.DB.prepare(`SELECT count(*) AS total FROM domains WHERE user_id=?1 ${search.length ? ` AND (domain LIKE "${search}%" OR domain LIKE "%${search}%")` : ``}`).bind(user.id).first('total');
  const all = <D1Result<Domain>>await env.DB.prepare(`SELECT * FROM domains WHERE user_id=?1 ${search.length ? ` AND (domain LIKE "${search}%" OR domain LIKE "%${search}%")` : ``} ORDER BY ${sort} ${order} LIMIT ?2, ?3`).bind(user.id, start, page_size).all();
  const list = all.results.map(domain => {
    domain.ns_servers = domain.ns_servers ? JSON.parse(domain.ns_servers) : domain.ns_servers;
    delete (domain.user_id);
    return domain;
  });

  const paginate = {
    page,
    page_size,
    total,
    total_page: Math.ceil(total / page_size),
    first: 1,
    last: Math.max(1, Math.ceil(total / page_size)),
    prev: page > 1 ? page - 1 : null,
    next: page < Math.ceil(total / page_size) ? page + 1 : null,
  };

  return Response.json({
    success: true,
    data: {
      list,
      paginate,
      search,
      sort,
      order,
    },
  });
});

router.get('/dashboard/balance', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }
  let tpl = dashboardCreditTpl;
  for (const key in user) {
    let value = <any>user[key];
    if (key === 'credit') {
      value = value.toFixed(2);
    }
    tpl = tpl.replace(new RegExp(`\%\%USER\.${key.toUpperCase()}\%\%`, 'g'), value);
  }
  return new Response(tpl.replace(/%%BANNER%%/g, dashboardBannerTpl).replace(/\%\%LIVECHAT\%\%/g, livechatTpl.replace(/\%\%USER.CREDIT%%/g, user.credit)).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/dashboard/balance', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  const post = <{ action: 'purchase'; amount: number }>await readRequestBody(request);

  if (post.action != 'purchase') {
    return Response.json({
      success: false,
      message: 'Invalid action'
    });
  }
  if (post.amount < 0.99) {
    return Response.json({
      success: false,
      message: 'Invalid amount. Minimal 0.99 USD!'
    });
  }

  let json;
  let exchangeRate;
  let exchangeRateRes;

  // await env.DB.transaction(async (txn) => {
  const epusdt = new Epusdt(env.EPUSDT_API_URL, env.EPUSDT_API_KEY);

  const id = uuid().replace(/[\w\W]{4}$/, '');
  await env.DB.prepare(`INSERT INTO deposits (id, user_id, amount, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5)`).bind(id, user.id, post.amount, 0, (new Date).getTime()).run();
  try {
    const exchangeRateUrl = `http://api.coinmarketcap.com.mp/data-api/v3/cryptocurrency/detail/chart?id=825&range=1H&convertId=2787`;
    exchangeRateRes = await fetch(exchangeRateUrl, {
      method: `GET`,
      headers: {
        'User-Agent': `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0`,
      },
    });
    exchangeRate = (<any>Object.values(<any>(<any>(<any>await exchangeRateRes.clone().json()).data).points)).reverse()[0].c[0];
  } catch (err) {
    // await txn.rollback();
    return Response.json({
      success: false,
      message: 'Exchange Rate Fetch Exception: ' + err,
      data: exchangeRateRes ? await exchangeRateRes.clone().text() : null,
    });
  }
  try {
    json = await epusdt.createTransaction(id, post.amount * exchangeRate, `${env.APP_URL}/deposit-callback/${id}`);
  } catch (err) {
    // await txn.rollback();
    return Response.json({
      success: false,
      message: 'Payment Gateway Exception: ' + err,
    });
  }

  await env.DB.prepare(`UPDATE deposits SET usdt_address=?1, usdt_amount=?2 WHERE id=?3`).bind(json.token, json.actual_amount, id).run();
  // await txn.commit();
  // });

  return Response.json({
    success: true,
    data: {
      address: json.token,
      usdtAmount: json.actual_amount,
    },
  });
});

router.get('/dashboard/reg-domain', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  const domain = new URL(request.url).searchParams.get('domain');
  // if (!domain) {
  //   return new Response('Domain is required', {
  //     headers,
  //   });
  // }
  if (domain) {
    let res = <Domain>await env.DB.prepare(`SELECT * FROM domains WHERE domain=?`).bind(domain).first();
    if (res) {
      return new Response('Domain is already registered', {
        headers,
      });
    }
  }

  let tpl = dashboardRegDomainTpl;
  for (const key in user) {
    let value = <any>user[key];
    if (key === 'credit') {
      value = value.toFixed(2);
    }
    tpl = tpl.replace(new RegExp(`\%\%USER\.${key.toUpperCase()}\%\%`, 'g'), value);
  }
  return new Response(tpl.replace(/%%BANNER%%/g, dashboardBannerTpl).replace(new RegExp(`\%\%DOMAIN\%\%`, 'g'), domain && domain?.trim() ? domain.trim() + `\n` : '').replace(/\%\%LIVECHAT\%\%/g, livechatTpl.replace(/\%\%USER.CREDIT%%/g, user.credit)).replace(/\%\%RECAPTCHA\%\%/g, recaptchaTpl.replace(/\%\%SITE_KEY\%\%/g, env.RECAPTCHA_SITE_KEY)), { headers, });
});

router.post('/dashboard/reg-domain', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  try {
    if (!await recaptchaChallange(env, request)) {
      return Response.json({
        success: false,
        message: 'Captcha challenge fail',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `Captcha challenge fail: ${err}`,
    });
  }

  const post = <{ domains: string[]; dnsServers: string[] }>await readRequestBody(request);
  let domains = post.domains.map(domain => domain.toLowerCase());
  const dnsServers = post.dnsServers.map((dnsServer) => {
    if (dnsServer.replace(/\.$/, '').toLowerCase().endsWith('.cloudflare.com')) {
      return Response.json({
        success: false,
        message: `Sorry. Cloudflare doesn't accept our com.mp domain, please try another DNS providers.`,
      });
    }
    return dnsServer.toLowerCase()
  });

  if (domains.length > maxFreeDomainNumber) {
    if (user.credit < 0.99 * (domains.length - maxFreeDomainNumber)) {
      return Response.json({
        success: false,
        message: `InsufficientBalance.`
      });
    }
  }

  for (const domain of domains) {
    if (
      domain.startsWith(`-`) || domain.endsWith(`-`) || domain.startsWith(`_`) || domain.endsWith(`_`) ||
      domain.startsWith(`.`) || domain.endsWith(`.`) ||
      domain.includes(`@`) || !domain.match(/^[\.\-\_\w\d]+$/)
    ) {
      return Response.json({
        success: false,
        message: `Invalid domain ${domain}`,
      });
    }
    if (!domain.endsWith(`.com.mp`)) {
      return Response.json({
        success: false,
        message: `Domain name ${domain} must ends with .com.mp`,
      });
    }
  
    if (domain.length > 7 + 64) {
      return Response.json({
        success: false,
        message: `Domain name ${domain} length exeeded`,
      });
    }
  
    const r = domain.match(/\./g);
    if (!r || r?.length > 2) {
      return Response.json({
        success: false,
        message: `Subdomain ${domain} not allowed`,
      });
    }
    if (
      domain.startsWith(`-`) || domain.endsWith(`-`) || domain.startsWith(`_`) || domain.endsWith(`_`) ||
      domain.startsWith(`.`) || domain.endsWith(`.`) ||
      domain.includes(`@`) || !domain.match(/^[\.\-\_\w\d]+$/)
    ) {
      return Response.json({
        success: false,
        message: `Invalid domain ${domain}`,
      });
    }
  }

  if (!domains || !dnsServers || !domains.length || !dnsServers.length) {
    return Response.json({
      success: false,
      message: 'Domains and DNS servers are required'
    });
  }

  if (domains.length > 1000) {
    return Response.json({
      success: false,
      message: 'Domains limit exceeded, max 1000 once allowed'
    })
  }

  if (dnsServers.length > 8) {
    return Response.json({
      success: false,
      message: 'DNS servers limit exceeded, max 8 once allowed'
    })
  }


  let userRegistered = <number>await env.DB.prepare(`SELECT count(id) AS total FROM domains WHERE user_id=?1`).bind(user.id).first('total');
  if (user.credit < 0.99 * (userRegistered + domains.length - maxFreeDomainNumber)) {
    return Response.json({
      success: false,
      message: `Your credit is ${user.credit} & consumed ${maxFreeDomainNumber} free quota. <br/><br/>Try purchase credit to register more (USDT allowed).`
    })
  }

  let res = <Domain>await env.DB.prepare(`SELECT * FROM domains WHERE domain IN ` + JSON.stringify(domains).replace(/\[/, '(').replace(/\]/, ')')).first();
  if (res) {
    return Response.json({
      success: false,
      message: 'One of domains is already registered'
    });
  }

  for (const domain of domains) {
    // await env.DB.transaction(async (txn) => {
    if (badwords.includes(domain) || badwords.includes(domain.replace(/\.com\.mp$/, ''))) {
      // await txn.rollback();
      return Response.json({
        success: false,
        message: `Reserved domain ${domain}`,
      });
    }

    const created = await createNsRecord(env, domain.replace(/\.com\.mp$/, ''), dnsServers)

    const domain_id = uuid();
    let expiration = (new Date).getTime() + 86400 * 1000 * maxFreeDomainDuration;
    if (userRegistered != 0) {
      expiration = (new Date).getTime() + 86400 * 1000 * 365;
    }
    const { count, duration } = (await env.DB.prepare(`INSERT INTO domains (id, user_id, domain, status, ns_servers, expires_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`).bind(domain_id, user.id, domain, 1, JSON.stringify(dnsServers), expiration, (new Date).getTime(), null).run()).meta;
    if (!duration) {
      // await txn.rollback();
      return Response.json({
        success: false,
        message: `Domain ${domain} insert failed`,
      });
    }

    if (userRegistered > maxFreeDomainNumber) {
      await env.DB.prepare(`UPDATE users SET credit=credit-0.99 WHERE id=?`).bind(user.id).run();
    }
    userRegistered++;
    // await txn.commit();
    // });
  };

  return Response.json({
    success: true,
    message: 'Domains registration success [' + domains.join(',') + ']',
  });
});

router.post('/dashboard/renew-domain', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  try {
    if (!await recaptchaChallange(env, request)) {
      return Response.json({
        success: false,
        message: 'Captcha challenge fail',
      });
    }
  } catch (err) {
    return Response.json({
      success: false,
      message: `Captcha challenge fail: ${err}`,
    });
  }

  const post = <{ domain: string; domains?: string[]; period: DomainRenewPeriodOptionsType }>await readRequestBody(request);
  let domains: string[] = []
  if (post.domains && post.domains.length) {
    post.domains.map(domain => domain.toLowerCase());
  } else {
    domains = [post.domain.toLowerCase()];
  }
  const period = <DomainRenewPeriodOptionsType>parseInt(<any>post.period);

  if (!DomainRenewPeriodOptions.includes(period)) {
    return Response.json({
      success: false,
      message: `Invalid period ${period}`,
    });
  }

  for (const domain of domains) {
    if (
      domain.startsWith(`-`) || domain.endsWith(`-`) || domain.startsWith(`_`) || domain.endsWith(`_`) ||
      domain.startsWith(`.`) || domain.endsWith(`.`) ||
      domain.includes(`@`) || !domain.match(/^[\.\-\_\w\d]+$/)
    ) {
      return Response.json({
        success: false,
        message: `Invalid domain ${domain}`,
      });
    }
  }

  if (!domains || !domains.length) {
    return Response.json({
      success: false,
      message: 'Domains is required'
    });
  }

  if (domains.length > 1000) {
    return Response.json({
      success: false,
      message: 'Domains limit exceeded, max 1000 once allowed'
    })
  }

  let price = 0;
  if (period > maxFreeDomainDuration) {
    price = 0.99 * domains.length * (period / 365);
    if (user.credit < price) {
      return Response.json({
        success: false,
        message: `InsufficientBalance. Your credit is ${user.credit}, and this transaction will spend ${price}.`
      })
    }
  }

  const allDomainsQuery = <D1Result<Domain>>await env.DB.prepare(`SELECT * FROM domains WHERE domain IN ` + JSON.stringify(domains).replace(/\[/, '(').replace(/\]/, ')')).all();
  const allDomains = allDomainsQuery.results;
  let notRegistered = [];
  if (!allDomains.length || allDomains.length !== domains.length) {
    notRegistered = allDomains.map(item => item.domain).filter(domain => !domains.includes(domain));
    return Response.json({
      success: false,
      message: `Domain${notRegistered.length > 1 ? `s` : ``} ${notRegistered.join(`,`)} is not registered`
    });
  }

  for (const domain of allDomains) {
    // Domains status is Redemption, PendingDelete or PendingRenewal
    if ([DomainStatus.Redemption, DomainStatus.PendingDelete, DomainStatus.PendingRenewal,].includes(parseInt(<any>domain.status))) {
      const dnsServers = JSON.parse(domain.ns_servers);
      if (dnsServers.length) {
        await deleteNsRecord(env, domain.domain.replace(/\.com\.mp$/, ''));
        const created = await createNsRecord(env, domain.domain.replace(/\.com\.mp$/, ''), dnsServers);
      }
    }
    let expiration = Number(domain.expires_at) + 86400 * 1000 * Number(period);

    if (Number(period) >= maxFreeDomainDuration) {
      expiration = (new Date).getTime() + 86400 * 1000 * maxFreeDomainDuration;

      if (expiration < domain.expires_at) {
        if (domains.length === 1) {
          return Response.json({
            success: false,
            message: `Domain ${domain.domain}'s expiration is more than ${maxFreeDomainDuration} days. no need to extend.`,
          });
        }
        continue;
      }
    }

    if (expiration > (new Date).getTime() + 86400 * 1000 * 365 * 10) {
      return Response.json({
        success: false,
        message: `${domain.domain}'s expiration can\'t be more than 10 years.`,
      });
    }

    // await env.DB.transaction(async (txn) => {
    const { count, duration } = (await env.DB.prepare(`UPDATE domains SET expires_at=?2, updated_at=?3 WHERE id=?1`).bind(domain.id, expiration, (new Date).getTime()).run()).meta;
    if (!duration) {
      // await txn.rollback();
      return Response.json({
        success: false,
        message: `Domain ${domain} renew failed`,
      });
    }

    if (price > 0) {
      await env.DB.prepare(`UPDATE users SET credit=credit-${price} WHERE id=?`).bind(user.id).run();
    }
    // await txn.commit();
    // });
  };

  if (Number(period) == maxFreeDomainDuration) {
    return Response.json({
      success: true,
      message: `Domain${domains.length > 1 ? `s` : ``}\'s expiration has been extended ${maxFreeDomainDuration} days from today! <br/><ol>\n${domains.map(domain => `<li>${domain}</li>`).join(`<br/>\n`)}</ol>`,
    });
  }

  return Response.json({
    success: true,
    message: `Domains renew success <br/><ol>\n${domains.map(domain => `<li>${domain}</li>`).join(`<br/>\n`)}</ol>`,
  });
});

router.post('/dashboard/dns-servers', async (request: Request, env: Env, ctx: ExecutionContext) => {
  const user = await get_user(env, get_session_id(request));
  if (!user) {
    return new Response(
      `
          <script>location.href = '/auth/login';</script>
      `, {
      headers: {
        'Content-type': 'text/html; charset=utf-8',
        'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
      },
    }
    );
  }

  const post = <{ domain: string; dns_servers?: string[]; }>await readRequestBody(request);
  const domain = post.domain;
  const dnsServers = post.dns_servers && post.dns_servers.length ? post.dns_servers.map(dnsServer => {
    if (dnsServer.replace(/\.$/, '').toLowerCase().endsWith('.cloudflare.com')) {
      return Response.json({
        success: false,
        message: `Sorry. Cloudflare doesn't accept our com.mp domain, please try another DNS providers.`,
      });
    }
    return dnsServer.toLowerCase();
  }) : [];

  if (!domain || !dnsServers) {
    return Response.json({
      success: false,
      message: `domain and dns_servers parameter are both required`,
    });
  }

  const domainInfo = <Domain>await env.DB.prepare(`SELECT * FROM domains WHERE domain=?1`).bind(domain.toLocaleLowerCase()).first();
  if (!domainInfo) {
    return Response.json({
      success: false,
      message: `Domain ${domain} not found`,
    });
  }
  if (domainInfo.user_id !== user.id) {
    return Response.json({
      success: false,
      message: `You don't have permission to update ${domain}`,
    });
  }

  if (domainInfo.status != DomainStatus.OK) {
    return Response.json({
      success: false,
      message: `Domain ${domain}'s status is not active`,
    });
  }
  const oldDnsServers = domainInfo.ns_servers ? (<string[]>JSON.parse(domainInfo.ns_servers)) : [];
  if (JSON.stringify(dnsServers.sort()) === JSON.stringify(oldDnsServers.sort())) {
    return Response.json({
      success: false,
      message: `DNS servers of ${domain} are unchanged`,
    });
  }

  await deleteNsRecord(env, domain.replace(/\.com\.mp$/, ''));
  await createNsRecord(env, domain.replace(/\.com\.mp$/, ''), dnsServers);

  const { count, duration } = (await env.DB.prepare(`UPDATE domains SET ns_servers=?2, updated_at=?3 WHERE id=?1`).bind(domainInfo.id, JSON.stringify(dnsServers), (new Date).getTime()).run()).meta;
  if (!duration) {
    return Response.json({
      success: false,
      message: `Update DNS servers of ${domain} failed`,
    });
  }

  return Response.json({
    success: true,
    message: `Update DNS servers of ${domain} success`,
  });
});

router.post('/dashboard/domains/grab-one-year-free', async (request: Request, env: Env, ctx: ExecutionContext) => {
  try {
    const user = await get_user(env, get_session_id(request));
    if (!user) {
      return new Response(
        `
            <script>location.href = '/auth/login';</script>
        `, {
        headers: {
          'Content-type': 'text/html; charset=utf-8',
          'Set-cookie': 'session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
        },
      }
      );
    }

    const post = <{ domain: string; url: string }>await readRequestBody(request);
    const domain = post.domain;
    const url = post.url;

    if (!domain || !url) {
      return Response.json({
        success: false,
        message: `domain and url parameter are both required`,
      });
    }

    const domainInfo = <Domain>await env.DB.prepare(`SELECT * FROM domains WHERE domain=?1`).bind(domain.toLocaleLowerCase()).first();
    if (!domainInfo) {
      return Response.json({
        success: false,
        message: `Domain ${domain} not found`,
      });
    }
    if (domainInfo.user_id !== user.id) {
      return Response.json({
        success: false,
        message: `You don't have permission to update ${domain}`,
      });
    }
    if (domainInfo.status != DomainStatus.OK) {
      return Response.json({
        success: false,
        message: `Domain ${domain}'s status is not active`,
      });
    }
    let hasInsert = false;
    const has_grab = <Domain>await env.DB.prepare(`SELECT * FROM free_one_year WHERE domain=?1`).bind(domain.toLocaleLowerCase()).first();
    if (has_grab) {
      return Response.json({
        success: false,
        message: `Domain ${domain} already grab before.`,
      });
    }

    hasInsert = true;
    await env.DB.prepare(`INSERT INTO free_one_year (domain, created_at) VALUES (?1, ?2)`).bind(domainInfo.domain, (new Date).getTime()).run();
    const fetchRequest = await fetch(url);
    const html = await fetchRequest.text();
    if (!html || !html.length || html.includes(`error code:`)) {
      if (hasInsert) {
        await env.DB.prepare(`DELETE FROM free_one_year WHERE domain=?1 `).bind(domainInfo.domain).run();
      }
      throw new Error(`Fail to fetch ${url}${html&&html.length ? ` ${html}` : ''}`);
    }

    let expiration = (new Date(domainInfo.expires_at)).getTime() + 86400 * 1000 * 365;
    const { count, duration } = (await env.DB.prepare(`UPDATE domains SET expires_at=?2, updated_at=?3 WHERE id=?1`).bind(domainInfo.id, expiration, (new Date).getTime()).run()).meta;

    return Response.json({
      success: true,
      message: `Grab +1 year success for ${domain} with ${html}`,
    });
  } catch (err) {
    return Response.json({
      success: false,
      message: `${err}`,
    });
  }
});

router.get('/**', async (request: Request) => {
  return new Response(`${(new URL(request.url)).pathname} is 404`, { status: 404, headers, });
});

export default {
  async scheduled(controller, env, ctx) {
    console.log("Update expiration");
    const query = <D1Result<Domain>>await env.DB.prepare(`SELECT * FROM domains WHERE expires_at < ?1`).bind((new Date).getTime()).all();
    const expiredDomains = query.results;
    // Delete NS Servers
    for (const domain of expiredDomains) {
      try {
        await deleteNsRecord(env, domain.domain);
      } catch (e) {
        console.error(e);
        // @todo: log failed domains
      }
    }

    await env.DB.prepare(`UPDATE domains SET status=5 WHERE expires_at < ?1 AND expires_at > ?2`).bind((new Date).getTime(), (new Date).getTime() - 86400 * 1000 * 30).run();
    await env.DB.prepare(`UPDATE domains SET status=6 WHERE expires_at < ?1 AND expires_at > ?2`).bind((new Date).getTime() - 86400 * 1000 * 30, (new Date).getTime() - 86400 * 1000 * 60).run();
    await env.DB.prepare(`DELETE FROM domains WHERE expires_at < ?1 `).bind((new Date).getTime() - 86400 * 1000 * 60).run();

    console.log("cron processed");
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const parsed = new URL(env.APP_URL);
    if (env.APP_ENV === 'production') {
      if (url.protocol != parsed.protocol || url.hostname != parsed.hostname) {
        const target = 'https://' + parsed.hostname + url.pathname + url.search + url.hash;
        return new Response(`Redirecting to <a href="${target}">${target}</a>`, {
          status: 301,
          headers: {
            'Location': target,
          },
        });
      }
    }

    return router.handle(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;;
