export async function encryptData(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization Vector
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);

    const encryptedData = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        await importKeyFromString(key, `encryptData()`),
        encodedData
    );

    return {
        iv: iv,
        data: new Uint8Array(encryptedData),
    };
}

export async function decryptData(key, encryptedData, iv) {
    const decryptedData = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        await importKeyFromString(key, `decryptData()`),
        encryptedData
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
}

export function bufferToHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

export function hexToBuffer(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }

    const buffer = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        buffer[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return buffer;
}

export async function exportKeyToString(key) {
    const exportedKey = await crypto.subtle.exportKey('raw', key);
    return bufferToHex(exportedKey);
}

export async function importKeyFromString(keyString, caller) {
    const keyBuffer = hexToBuffer(keyString);
    const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
            name: 'AES-GCM',
        },
        true,
        ['encrypt', 'decrypt']
    );
    return key;
}
