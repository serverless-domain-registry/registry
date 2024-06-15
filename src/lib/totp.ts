export const validateTotp = async (token, secret): Promise<boolean> => {
  const timeStep = 30;
  const tolerance = 1;
  const currentTime = Math.floor(Date.now() / 1000);

  for (let i = -tolerance; i <= tolerance; i++) {
    let timeCounter = Math.floor((currentTime + i * timeStep) / timeStep);
    let generatedToken = await generateToken(timeCounter, secret);
    if (generatedToken === token.toString()) {
      return true;
    }
  }

  return false;
}

export const generateToken = async (timeCounter, secret): Promise<string> => {
  const timeCounterHex = timeCounter.toString(16).padStart(16, '0');
  const keyHex = base32tohex(secret);
  const hmacHex = await jsSHA1HMAC(keyHex, timeCounterHex);
  const offset = parseInt(hmacHex.slice(-1), 16);
  const truncatedHash = parseInt(hmacHex.slice(offset * 2, offset * 2 + 8), 16) & 0x7fffffff;
  let generatedToken = (truncatedHash % 1000000).toString();
  generatedToken = generatedToken.padStart(6, "0");
  return generatedToken;
}

export const generateSecret = (length = 16) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    secret += alphabet[randomIndex];
  }
  return secret;
}

const jsSHA1HMAC = async (keyHex, messageHex) => {
  const key = new Uint8Array(keyHex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
  const message = new Uint8Array(messageHex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
  const signatureArray = new Uint8Array(signature);
  const hmacHex = Array.from(signatureArray).map(b => b.toString(16).padStart(2, '0')).join('');
  return hmacHex;
}

const base32tohex = (base32: string): string => {
  var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var bits = "";
  var hex = "";

  for (var i = 0; i < base32.length; i++) {
    var val = base32chars.indexOf(base32.charAt(i).toUpperCase());
    bits += leftpad(val.toString(2), 5, '0');
  }

  for (var i = 0; i + 4 <= bits.length; i += 4) {
    var chunk = bits.substr(i, 4);
    hex = hex + parseInt(chunk, 2).toString(16);
  }
  return hex;
}

const leftpad = (str, len, pad): string => {
  if (len + 1 >= str.length) {
    str = Array(len + 1 - str.length).join(pad) + str;
  }
  return str;
}
