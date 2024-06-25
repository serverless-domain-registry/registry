import { Env } from "../d/Env";

const sendmail = async (receiptEmail: string, mailSubject: string, mailBody: string, env: Env) => {
  const senders = (typeof env.BREVO === 'string' ? JSON.parse(env.BREVO) : env.BREVO);

  let seed: number;
  switch (env.BREVO_PREFER) {
    case "auto":
      seed = ~~(Math.random() * senders.length);
      break;

    default:
      seed = env.BREVO_PREFER;
      break;
  }

  const sender = senders[seed];
  const url = 'https://api.brevo.com/v3/smtp/email';
  const params = {
    sender: {
      name: sender.senderName,
      email: sender.senderAddress,
    },
    to: [
      {
        email: receiptEmail,
        name: null
      }
    ],
    subject: mailSubject,
    htmlContent: mailBody,
  };

  const options = {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': sender.apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify(params)
  };

  try {
    const send = <Response> await fetch(url, options);
    const json = <{messageId: string; message: string;}> await send.json();
    if (send.status === 201) {
      return json.messageId;
    }

    throw new Error(json.message);
  } catch (err) {
    throw err;
  }
};

export default sendmail;
