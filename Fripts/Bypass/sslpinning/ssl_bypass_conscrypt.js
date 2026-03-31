// Bypass SSL via TrustManagerImpl (Conscrypt/Android internal)
// Source: https://github.com/lautarovculic/fridaScripts
// Usage: frida -U -f com.target.app -l ssl_bypass_conscrypt.js

Java.perform(function() {
    const ArrayList = Java.use('java.util.ArrayList');
    const ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    ApiClient.checkTrustedRecursive.implementation = function() {
        console.log('[*] TrustManagerImpl.checkTrustedRecursive → bypassed');
        return ArrayList.$new();
    };
});
