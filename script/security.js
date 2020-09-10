const keyGen = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const publicKeyGen = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
const privateKey = 'pjruXsb/faildoW+=xmtnvgkyzeYwhZcq';
const strCode = String.fromCharCode;

function ue(o) {
    let u = o.replace(/\r\n/g, '\n'), r = '', i = 0, c;
    while (i < u.length) {
        c = u.charCodeAt(i);
        i++;
        if (c < 128) {
            r += strCode(c);
        } else if ((c > 127) && (c < 2048)) {
            r += strCode((c >> 6) | 192);
            r += strCode((c & 63) | 128);
        } else {
            r += strCode((c >> 12) | 224);
            r += strCode(((c >> 6) & 63) | 128);
            r += strCode((c & 63) | 128);
        }
    }
    return r;
}

function ud(o) {
    let r = '', i = 0, c1 = 0, c2 = 0, c3 = 0;
    while (i < o.length) {
        c1 = o.charCodeAt(i);
        if (c1 < 128) {
            r += strCode(c1);
        } else if (c1 > 191 && c1 < 224) {
            c2 = o.charCodeAt(++i);
            r += strCode(((c1 & 31) << 6) | (c2 & 63));
        } else {
            c2 = o.charCodeAt(++i);
            c3 = o.charCodeAt(++i);
            r += strCode(((c1 & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
        }
        i++;
    }
    return r;
}

export function encode(o, key) {
    key = key || keyGen;
    let r = '', c1, c2, c3, e1, e2, e3, e4, i = 0, u = ue('' + o);

    while (i < u.length) {
        c1 = u.charCodeAt(i++);
        c2 = u.charCodeAt(i++);
        c3 = u.charCodeAt(i++);
        e1 = c1 >> 2;
        e2 = ((c1 & 3) << 4) | (c2 >> 4);
        e3 = ((c2 & 15) << 2) | (c3 >> 6);
        e4 = c3 & 63;
        if (isNaN(c2)) e3 = e4 = 64;
        else if (isNaN(c3)) e4 = 64;
        r += key.charAt(e1) + key.charAt(e2) + key.charAt(e3) + key.charAt(e4);
    }
    return r;
}

export function decode(o, key) {
    key = key || keyGen;
    if (!(o && o.replace)) return '';
    let r = '', c1, c2, c3, d1, d2, d3, d4, i = 0, u = o.replace(/[^A-Za-z0-9+\/=]/g, '');
    while (i < u.length) {
        d1 = key.indexOf(u.charAt(i++));
        d2 = key.indexOf(u.charAt(i++));
        d3 = key.indexOf(u.charAt(i++));
        d4 = key.indexOf(u.charAt(i++));
        c1 = (d1 << 2) | (d2 >> 4);
        c2 = ((d2 & 15) << 4) | (d3 >> 2);
        c3 = ((d3 & 3) << 6) | d4;
        r += strCode(c1);
        if (d3 !== 64) r += strCode(c2);
        if(d4 !== 64) r += strCode(c3);
    }
    return ud(r);
}

export function encrypt(keygen, o) {
    o = typeof o === 'string' ? o : JSON.stringify(o);
    return encode(o, keygen)
}

export function decrypt(keygen, o) {
    return decode(o, keygen)
}

export function createCryStr(keygen) {
    keygen = keygen || keyGen;
    function randomNum(max) {
        return Math.floor(Math.random() * max);
    }
    let len = keygen.length;
    let cryptMap = Array(len).fill(null);
    let remain = [];
    let cryptStr = '';
    for (let i = 0; i < len; i++) {
        remain.push(i);
    }
    for (let i = 0; i < len; i++) {
        let r = randomNum(remain.length);
        cryptMap[remain[r]] = i;
        remain.splice(r, 1);
    }

    for (let i = 0; i < len; i++) {
        cryptStr += keygen[cryptMap[i]];
    }

    return cryptStr;
}

export function createPublicKey() {
    return createCryStr(publicKeyGen);
}

export function encodeCrypt(info) {
    info = typeof info === 'object' ? JSON.stringify(info) : info.toString();
    let keygen = createCryStr();
    return keygen + encrypt(keygen, info);

}

export function decodeCrypt(cryptStr) {
    let keygen = cryptStr.slice(0, 65);
    let confStr = cryptStr.slice(65);
    return decrypt(keygen, confStr);
}

export function encodeTSL(publicKey, info) {
    info = typeof info === 'object' ? JSON.stringify(info) : info.toString();
    let keygen = privateKey + publicKey;
    return encrypt(keygen, info);
}

export function decodeTSL(publicKey, tslStr) {
    let keygen = privateKey + publicKey;
    return decrypt(keygen, tslStr);
}