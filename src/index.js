import crypto from 'crypto';
import url from 'url';

export function md5(text) {
    return crypto.createHash('md5').update(text).digest('hex');
}
export function sha1(text) {
    return crypto.createHash('sha1').update(text).digest('hex');
}
export function sha1Secret(text, key) {
    return crypto.createHmac('sha1', key).update(text).digest('hex');
}


export function encyptAES(text, key) {
    let cipher = crypto.createCipher('aes-256-cbc', key);
    let crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

export function decryptAES(key, hash) {
    let decipher = crypto.createDecipher('aes-256-cbc', key);
    let dec = decipher.update(hash, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}


export function toSign(path, secret) {

    if (path.includes('?')) {
        path += '&time=';
    } else {
        path += '?time=';
    }

    path += Math.floor(Date.now() / 1000);

    const uri = url.parse(path);
    const hashedSignature = sha1Secret(secret, uri.path);
    return url.format(uri) + '&sign=' + hashedSignature;
}