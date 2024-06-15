const sendmail = async (receiptEmail: string, mailSubject: string, mailBody: string, apiKey: string) => {
  const url = 'https://api.brevo.com/v3/smtp/email';
  const options = {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: {
        name: 'Com.MP Registry',
        email: 'no-reply@registry.com.mp'
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
  const json = await send.json();
  if (send.status === 201) {
    return json.messageId;
  }

  throw new Error(json.message);
};

export default sendmail;
