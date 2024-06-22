import { Env } from "../d/Env";

const sendmail = async (receiptEmail: string, mailSubject: string, mailBody: string, env: Env) => {
  let seed: number;
  switch (env.BREVO_PREFER) {
    case "auto":
      seed = ~~(Math.random() * env.BREVO.length);
      break;

    default:
      seed = env.BREVO_PREFER;
      break;
  }

  const sender = (typeof env.BREVO === 'string' ? JSON.parse(env.BREVO) : env.BREVO)[seed];
  console.log(sender);
  const url = 'https://api.brevo.com/v3/smtp/email';
  const options = {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': sender.apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
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
    })
  };

  const send = <Response> await fetch(url, options);
  try {
    const json = <{messageId: string; message: string;}> await send.json();
    console.log(json);

    if (send.status === 201) {
      return json.messageId;
    }

    throw new Error(json.message);
  } catch (err) {
    console.log(err);
  }
};

export default sendmail;
