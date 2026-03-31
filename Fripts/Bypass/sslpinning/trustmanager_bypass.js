// Bypass SSL Pinning via custom TrustManager + OkHttpClient
// Source: https://github.com/lautarovculic/fridaScripts
// Usage: frida -U -f com.target.app -l trustmanager_bypass.js

Java.perform(function () {
    function bypassSSL() {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'org.frida.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContextInit = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        console.log('[*] SSL TrustManager bypass active');
    }

    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = OkHttpClient.Builder;
        Builder.sslSocketFactory.overload(
            'javax.net.ssl.SSLSocketFactory',
            'javax.net.ssl.X509TrustManager'
        ).implementation = function (sslSocketFactory, trustManager) {
            console.log('[*] OkHttpClient.Builder.sslSocketFactory → bypassed');
            return this.sslSocketFactory.call(this, sslSocketFactory, trustManager);
        };
    } catch (e) {
        console.log('[!] OkHttpClient bypass failed: ' + e);
    }

    try {
        bypassSSL();
    } catch (e) {
        console.log('[!] TrustManager bypass failed: ' + e);
    }
});
