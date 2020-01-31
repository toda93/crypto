import crypto from 'crypto';
import url from 'url';

export function md5(value) {
    return crypto.createHash('md5').update(value.toString()).digest('hex');
}
export function sha1(value) {
    return crypto.createHash('sha1').update(value.toString()).digest('hex');
}

export function encyptAES(key, value) {
    let cipher = crypto.createCipher('aes-256-cbc', key);
    let crypted = cipher.update(value.toString(), 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

export function decryptAES(key, hash) {
    let decipher = crypto.createDecipher('aes-256-cbc', key);
    let dec = decipher.update(hash.toString(), 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}
function removeWebSafe(safeEncodedString) {
    return safeEncodedString.replace(/-/g, '+').replace(/_/g, '/');
}

function makeWebSafe(encodedString) {
    return encodedString.replace(/\+/g, '-').replace(/\//g, '_');
}

function decodeBase64Hash(code) {
    return Buffer.from ? Buffer.from(code, 'base64') : new Buffer(code, 'base64');
}

function encodeBase64Hash(key, data) {
    return crypto.createHmac('sha1', key).update(data).digest('base64');
}
export function sign(path, secret) {
    const uri = url.parse(path);
    const safeSecret = decodeBase64Hash(removeWebSafe(secret));
    const hashedSignature = makeWebSafe(encodeBase64Hash(safeSecret, uri.path));
    return url.format(uri) + '&sign=' + hashedSignature;
}