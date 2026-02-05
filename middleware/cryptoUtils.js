const crypto = require('crypto');

// For Lab Eval: accessing a fixed key. 
// In prod, this should be in .env and rotated.
// Using a 32-byte key for AES-256
const ALGORITHM = 'aes-256-cbc';
const SECRET_KEY = crypto.scryptSync(process.env.SESSION_SECRET || 'lab-secret', 'salt', 32);
const IV_LENGTH = 16;

function encrypt(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    // Store IV with the encrypted text (convential: iv:ciphertext)
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return text;
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        return "[Decryption Failed]";
    }
}

// --- Digital Signatures ---
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

function signData(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'hex');
}

function verifySignature(data, signature, publicKey) {
    try {
        const verify = crypto.createVerify('SHA256');
        verify.update(data);
        verify.end();
        return verify.verify(publicKey, signature, 'hex');
    } catch (e) {
        return false;
    }
}

// --- Hash Chaining ---
function calculateLogHash(prevHash, entryData) {
    // entryData should be a string (e.g., JSON.stringify({ user_id, action, details, timestamp }))
    // Chain: Hash(prevHash + entryData)
    const hash = crypto.createHash('sha256');
    hash.update((prevHash || '') + entryData);
    return hash.digest('hex');
}

module.exports = { encrypt, decrypt, generateKeyPair, signData, verifySignature, calculateLogHash };
