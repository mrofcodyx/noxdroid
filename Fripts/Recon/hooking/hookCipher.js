// hookCipher.js
// Hooks Cipher.doFinal to intercept and print decrypted/encrypted data as string
// Usage: frida -U -n <app> -l hookCipher.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);

        try {
            var inputStr = Java.use("java.lang.String").$new(input, "UTF-8");
            var resultStr = Java.use("java.lang.String").$new(result, "UTF-8");
            console.log("[Cipher.doFinal]");
            console.log("  Algorithm : " + this.getAlgorithm());
            console.log("  Input     : " + inputStr);
            console.log("  Output    : " + resultStr);
        } catch (e) {
            // Fallback to hex if not valid UTF-8
            var toHex = function (bytes) {
                return Array.from(bytes).map(function (b) {
                    return ('0' + (b & 0xff).toString(16)).slice(-2);
                }).join(' ');
            };
            console.log("[Cipher.doFinal] (hex)");
            console.log("  Algorithm : " + this.getAlgorithm());
            console.log("  Input     : " + toHex(input));
            console.log("  Output    : " + toHex(result));
        }

        return result;
    };

    console.log("[*] Cipher.doFinal hook active.");
});
