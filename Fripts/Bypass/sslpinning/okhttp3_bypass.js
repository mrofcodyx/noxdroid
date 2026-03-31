// Bypass OkHttp3 / com.android.okhttp CertificatePinner
// Source: https://github.com/lautarovculic/fridaScripts
// Usage: frida -U -f com.target.app -l okhttp3_bypass.js

Java.perform(function () {
    var CertificatePinner = Java.use("com.android.okhttp.CertificatePinner");

    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
        .implementation = function(p0, p1) {
        console.log('[*] CertificatePinner.check(Certificate[]) → bypassed for: ' + p0);
    };

    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function(p0, p1) {
        console.log('[*] CertificatePinner.check(List) → bypassed for: ' + p0);
    };
});
