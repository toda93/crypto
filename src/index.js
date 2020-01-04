import crypto from 'crypto';

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