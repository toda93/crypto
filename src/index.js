const crypto = require('crypto');
const url = require('url');
const speakeasy = require('speakeasy');

function md5(text) {
    return crypto.createHash('md5').update(String(text)).digest('hex');
}

function sha1(text) {
    return crypto.createHash('sha1').update(String(text)).digest('hex');
}

function sha1Secret(text, key) {
    return crypto.createHmac('sha1', key).update(String(text)).digest('hex');
}


function encryptAES(text, key) {
    let cipher = crypto.createCipher('aes-256-cbc', String(key));
    let crypted = cipher.update(String(text), 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

function decryptAES(hash, key) {
    let decipher = crypto.createDecipher('aes-256-cbc', String(key));
    let dec = decipher.update(String(hash), 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}



function floorToMinute(time, minutes) {
    const roundSecond = minutes * 60;
    time = time - (time % (Math.floor(time / roundSecond) * roundSecond));
    return time;
}

function toSign(path, secret, mTimeout = 5) {

    if (path.includes('?')) {
        path += '&stime=';
    } else {
        path += '?stime=';
    }

    path += floorToMinute(Math.floor(Date.now() / 1000), mTimeout);

    const uri = url.parse(path);
    const hashedSignature = sha1Secret(secret, uri.path);
    return url.format(uri) + '&sign=' + hashedSignature;
}

function isValidSign(path, secret, mTimeout = 5) {
    const timeNow = Math.floor(Date.now() / 1000);
    const uri = url.parse(path);

    const urlParams = new URLSearchParams(uri.search);
    const sign = urlParams.get('sign');
    const stime = urlParams.get('stime');


    if (sign && stime && timeNow - (Number(stime) + mTimeout * 60) < mTimeout) {
        const hashedSignature = sha1Secret(secret, uri.path.replace(/&sign=(.*)/, ''));
        if (hashedSignature === sign) {
            return true;
        }
    }
    return false;
}



function generateSecretKeyOTP() {
    const secret = speakeasy.generateSecret();
    return secret.base32;
}

function generateOTP(secret, ttlMinutes = 5) {
    return speakeasy.totp({
        secret,
        step: 60,
        window: ttlMinutes,
        encoding: 'base32'
    });
}

function verifyOTP(secret, token, ttlMinutes = 5) {
    return speakeasy.totp.verify({
        secret,
        token,
        step: 60,
        window: ttlMinutes,
        encoding: 'base32',
    });
}



module.exports = {
    md5,
    sha1,
    sha1Secret,
    encryptAES,
    decryptAES,
    toSign,
    isValidSign,
};