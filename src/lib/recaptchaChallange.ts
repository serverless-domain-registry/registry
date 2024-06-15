import { Env } from '../Env.ts';
import readRequestBody from './readRequestBody.ts';

const recaptchaChallange = async function(env: Env, request: Request): Promise<boolean> {
  return new Promise(async (resolve, reject) => {
    const body = await readRequestBody(request);
    const ip = <string> request.headers.get('CF-Connecting-IP');

    const formData = new FormData();
    formData.append('secret', env.RECAPTCHA_SECRET_KEY);
    formData.append('response', body['g-recaptcha-response']);
    formData.append('remoteip', ip);

    const url = 'https://www.recaptcha.net/recaptcha/api/siteverify';
    const result = await fetch(url, {
      body: formData,
      method: 'POST'
    });

    const outcome = await result.json();
    // this is the conditional block that you can customize to fit your specific use-case
    if (outcome.success) {
      return resolve(true);
    } else {
      return reject(outcome['error-codes'].join(','));
    }
  });
};

export default recaptchaChallange;
