// Hook AES / DES / RSA / MAC / MessageDigest — intercepts keys, IVs, plaintexts, ciphertexts
// Original: https://www.codenong.com/jsecbee028022b/
// Source: https://github.com/Magpol/MiscFrida
// Usage: frida -U -f com.target.app -l hook_AESDESRSA.js

var N_ENCRYPT_MODE = 1;
var N_DECRYPT_MODE = 2;

function showStacks() {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();
    if (!straces) return;
    console.log("============================= Stack start =======================");
    for (var i = 0; i < straces.length; i++) {
        console.log("   " + straces[i].toString());
    }
    console.log("============================= Stack end =======================\r\n");
    Exception.$dispose();
}

var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var base64DecodeChars = new Array((-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),(-1),62,(-1),(-1),(-1),63,52,53,54,55,56,57,58,59,60,61,(-1),(-1),(-1),(-1),(-1),(-1),(-1),0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,(-1),(-1),(-1),(-1),(-1),(-1),26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,(-1),(-1),(-1),(-1),(-1));

function bytesToHex(arr) {
    var str = '';
    for (var i = 0; i < arr.length; i++) {
        var k = arr[i];
        var j = k < 0 ? k + 256 : k;
        if (j < 16) str += "0";
        str += j.toString(16);
    }
    return str;
}
function bytesToString(arr) {
    var str = '';
    arr = new Uint8Array(arr);
    for (var i in arr) str += String.fromCharCode(arr[i]);
    return str;
}
function bytesToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) { r += base64EncodeChars.charAt(h >> 2); r += base64EncodeChars.charAt((3 & h) << 4); r += '=='; break; }
        if (o = e[a++], a == c) { r += base64EncodeChars.charAt(h >> 2); r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4); r += base64EncodeChars.charAt((15 & o) << 2); r += '='; break; }
        t = e[a++]; r += base64EncodeChars.charAt(h >> 2); r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4); r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6); r += base64EncodeChars.charAt(63 & t);
    }
    return r;
}

Java.perform(function () {
    // SecretKeySpec
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
        showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        console.log("SecretKeySpec algo: " + b + " | str: " + bytesToString(a));
        console.log("SecretKeySpec algo: " + b + " | hex: " + bytesToHex(a));
        return result;
    };

    // DESKeySpec
    var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
    DESKeySpec.$init.overload('[B').implementation = function (a) {
        showStacks();
        var result = this.$init(a);
        var bytes_key_des = this.getKey();
        console.log("======================================");
        console.log("DES key | str: " + bytesToString(bytes_key_des));
        console.log("DES key | hex: " + bytesToHex(bytes_key_des));
        return result;
    };

    // IvParameterSpec
    var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    ivParameterSpec.$init.overload('[B').implementation = function (a) {
        var result = this.$init(a);
        console.log("======================================");
        console.log("IV | str: " + bytesToString(a));
        console.log("IV | hex: " + bytesToHex(a));
        return result;
    };

    // Cipher
    var cipher = Java.use('javax.crypto.Cipher');
    cipher.getInstance.overload('java.lang.String').implementation = function (a) {
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("Cipher.getInstance: " + a);
        return result;
    };
    cipher.init.overload('int', 'java.security.Key').implementation = function (a, b) {
        var result = this.init(a, b);
        var bytes_key = b.getEncoded();
        console.log("======================================");
        console.log("Cipher.init mode: " + (a == 1 ? "ENCRYPT" : "DECRYPT"));
        console.log("Cipher.init key | str: " + bytesToString(bytes_key));
        console.log("Cipher.init key | hex: " + bytesToHex(bytes_key));
        return result;
    };
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
        var result = this.init(a, b, c);
        var bytes_key = b.getEncoded();
        console.log("======================================");
        console.log("Cipher.init mode: " + (a == 1 ? "ENCRYPT" : "DECRYPT"));
        console.log("Cipher.init key | str: " + bytesToString(bytes_key));
        console.log("Cipher.init key | hex: " + bytesToHex(bytes_key));
        return result;
    };
    cipher.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        console.log("======================================");
        console.log("Cipher.doFinal | str:    " + bytesToString(result));
        console.log("Cipher.doFinal | hex:    " + bytesToHex(result));
        console.log("Cipher.doFinal | base64: " + bytesToBase64(result));
        return result;
    };
    cipher.doFinal.overload('[B').implementation = function (a) {
        var result = this.doFinal(a);
        console.log("======================================");
        console.log("Cipher.doFinal input | str:    " + bytesToString(a));
        console.log("Cipher.doFinal result | hex:   " + bytesToHex(result));
        console.log("Cipher.doFinal result | base64:" + bytesToBase64(result));
        return result;
    };

    // Mac (HMAC)
    var mac = Java.use('javax.crypto.Mac');
    mac.getInstance.overload('java.lang.String').implementation = function (a) {
        showStacks();
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("Mac.getInstance: " + a);
        return result;
    };
    mac.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        console.log("======================================");
        console.log("Mac.doFinal | str:    " + bytesToString(result));
        console.log("Mac.doFinal | hex:    " + bytesToHex(result));
        console.log("Mac.doFinal | base64: " + bytesToBase64(result));
        return result;
    };

    // MessageDigest
    var md = Java.use('java.security.MessageDigest');
    md.getInstance.overload('java.lang.String').implementation = function (a) {
        console.log("======================================");
        console.log("MessageDigest.getInstance: " + a);
        return this.getInstance(a);
    };
    md.digest.overload().implementation = function () {
        var result = this.digest();
        console.log("======================================");
        console.log("MessageDigest.digest | hex:    " + bytesToHex(result));
        console.log("MessageDigest.digest | base64: " + bytesToBase64(result));
        return result;
    };

    // RSA
    var x509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');
    x509EncodedKeySpec.$init.overload('[B').implementation = function (a) {
        var result = this.$init(a);
        console.log("======================================");
        console.log("RSA X509EncodedKeySpec | base64: " + bytesToBase64(a));
        return result;
    };

    var rSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
    rSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (a, b) {
        var result = this.$init(a, b);
        console.log("======================================");
        console.log("RSAPublicKeySpec N: " + a.toString(16));
        console.log("RSAPublicKeySpec E: " + b.toString(16));
        return result;
    };

    // KeyPairGenerator
    var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
    KeyPairGenerator.generateKeyPair.implementation = function () {
        var result = this.generateKeyPair();
        console.log("======================================");
        console.log("KeyPairGenerator.generateKeyPair public  | hex: " + bytesToHex(result.getPublic().getEncoded()));
        console.log("KeyPairGenerator.generateKeyPair private | hex: " + bytesToHex(result.getPrivate().getEncoded()));
        return result;
    };
});
