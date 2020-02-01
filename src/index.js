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



function floorToMinute(time, minutes) {
    const roundSecond = minutes * 60;
    time = time - (time % (Math.floor(time / roundSecond) * roundSecond));
    return time;
}

export function toSign(path, secret) {

    if (path.includes('?')) {
        path += '&stime=';
    } else {
        path += '?stime=';
    }

    path += floorToMinutes(Math.floor(Date.now() / 1000), 5);

    const uri = url.parse(path);
    const hashedSignature = sha1Secret(secret, uri.path);
    return url.format(uri) + '&sign=' + hashedSignature;
}

export function isValidSign(path, secret, timeout = 300) {
    const timeNow = floorToMinutes(Math.floor(Date.now() / 1000), 5);
    const uri = url.parse(path);

    const urlParams = new URLSearchParams(uri.search);
    const sign = urlParams.get('sign');
    const stime = urlParams.get('stime');


    if (sign && stime && timeNow - Number(stime) < timeout) {
        const hashedSignature = sha1Secret(secret, uri.path.replace(/&sign=(.*)/, ''));
        if (hashedSignature === sign) {
            return true;
        }
    }
    return false;
}