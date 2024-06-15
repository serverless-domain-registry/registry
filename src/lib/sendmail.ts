import { Env } from "../d/Env";

const sendmail = async (receiptEmail: string, mailSubject: string, mailBody: string, env: Env) => {
  const url = 'https://api.brevo.com/v3/smtp/email';
  const options = {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': env.BREVO_API_KEY,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: {
        name: env.MAIL_SENDER_NAME,
        email: env.MAIL_SENDER_ADDRESS,
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
  const json = <{messageId: string; message: string;}> await send.json();
  if (send.status === 201) {
    return json.messageId;
  }

  throw new Error(json.message);
};

export default sendmail;
