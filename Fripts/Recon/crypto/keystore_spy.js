setTimeout(function() {
    Java.perform(function() {
        console.log('')
        console.log('======')
        console.log('[#] Android Keystore Spy [#]')
        console.log('======')
        /* This tool allows to dynamically analyze the Android Keystore calls performed by the target app.
           It helps to determine which Keystore is related to biometric authentication for Android apps 
           that use multiple keystores.
           
           HINT: 
           the Keystore item related to biometric authentication is the one printed-out:
           - after the call to the custom BiometricActivity (if you specify it), alternatively after the call to "Keystore.getKey()" 
           - and before the call to any of the biometric "authenticate()" methods.
        */
        
        // NOTE:
        // Replace the placeholder value "com.example.app.BiometricActivity" with
        // the name of the custom biometric activity class of the target app
        var customBiometricActivity = 'com.example.app.BiometricActivity';
        
        // Starting the Biometric Keystore hunt 
        //hookKeystoreGetKey();
        hookCipherInits();
        //hookBiometricAuth();
        //hookCustomBiometricactivity(customBiometricActivity);
        // Ending the Biometric Keystore hunt 

    });
},0);


function hookKeystoreGetKey() {
    try {
        // Hooking the Keystore.getKey(...) calls
        var keystore = Java.use('java.security.KeyStore');
        var keystoreObj = keystore.getKey.overload('java.lang.String', '[C');
        keystoreObj.implementation = function(alias,password) {
            var psw = 'null';
            if (password !== null) {
                psw = password.join('');
            }
            console.log('[+] Hooked KeyStore.getKey(alias,password) method');
            console.log('[+] Keystore item "'+alias+'" has password: '+psw);
            //hookCryptoInit();
            var retval = this.getKey.overload('java.lang.String', '[C').call(this,alias,password);
            return retval;
        }
    } catch (err) {
        //console.log('[-] Method KeyStore.getKey(alias,password) not found');
    }  
}



function hookCustomBiometricactivity(customBiometricActivity) {
    try {
        if (customBiometricActivity=='com.example.app.BiometricActivity') {
            console.log('[W] Warning, you have not set the "customBiometricActivity" value, proceeding without it...')
        } else {
            // Hooking custom BiometricActivity 
            var biometricactivityClass = Java.use(customBiometricActivity);
            biometricactivityClass.onCreate.overload('android.os.Bundle').implementation = function(param) {
                console.log('\x1b[36m'+'[o] Biometric Authentication starting...'+'\x1b[0m');
                console.log('\x1b[36m'+'[o] Hooked custom BiometricActivity class: "'+customBiometricActivity+'"\x1b[0m');
                this.onCreate.overload('android.os.Bundle').call(this,param); 
            }
        } 
    } catch (err) {
        console.log('[-] Custom BiometricActivity class not found');
    }
}


function hookBiometricAuth() {
    // Hooking the various Biometric authenticate(...) calls
    try {
        // BiometricPrompt authenticate(cancel,executor,callback) method
        var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        var biometricPrompt_auth = biometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        biometricPrompt_auth.implementation = function(cancel,executor,callback) {
            console.log('\x1b[36m'+'[o] Biometric Authentication occurring...'+'\x1b[0m');
            console.log('\x1b[36m'+'[o] called BiometricPrompt.authenticate(cancel,executor,callback)'+'\x1b[0m');
            this.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').call(this,cancel,executor,callback);
        }
    } catch (err) {
        //console.log('[-] BiometricPrompt.authenticate(cancel,executor,callback) not found');
    }

    // BiometricPrompt authenticate(crypto,cancel,executor,callback) method
    try {
        var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        var biometricPrompt_auth = biometricPrompt.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        biometricPrompt_auth.implementation = function(crypto,cancel,executor,callback) {
            console.log('\x1b[36m'+'[o] Biometric Authentication occurring...'+'\x1b[0m');
            console.log('\x1b[36m'+'[o] called BiometricPrompt.authenticate(crypto,cancel,executor,callback)'+'\x1b[0m');
            this.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').call(this,crypto,cancel,executor,callback);
        }
    } catch (err) {
        //console.log('[-] BiometricPrompt.authenticate(crypto,cancel,executor,callback)) not found');
    }

    // FingerprintManager authenticate method (deprecated)
    try {
        // Trying to hook each FingerprintManager classes
        try {
            fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        } catch (err) {
            try {
                fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
            } catch (err) { 
                //console.log('[-] FingerprintManager class not found');
            }
        }
        var fingerprintManager_auth = fingerprintManager.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
        fingerprintManager_auth.implementation = function(crypto,cancel,flags,callback,handler) {
            console.log('\x1b[36m'+'[o] Biometric Authentication occurring...'+'\x1b[0m');
            console.log('\x1b[36m'+'[o] called FingerprintManager.authenticate(crypto,cancel,flags,callback,handler)'+'\x1b[0m');
            this.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler').call(this,crypto,cancel,flags,callback,handler);
        }
    } catch (err) {
        //console.log('[-] FingerprintManager not found');
    }

    // FingerprintManagerCompat authenticate method (deprecated)
    try {
        try {
            fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
        } catch (err) {
            try {
                fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
            } catch (err) {
                //console.log('[-] FingerprintManagerCompat class not found');
            }
        }
        var fingerprintManagerCompat_auth = fingerprintManagerCompat.authenticate.overload('android.hardware.fingerprint.FingerprintManagerCompat$CryptoObject', 'int', 'android.os.CancellationSignal', 'android.hardware.fingerprint.FingerprintManagerCompat$AuthenticationCallback', 'android.os.Handler');
        fingerprintManagerCompat_auth.implementation = function(crypto,flags,cancel,callback,handler) {
            console.log('\x1b[36m'+'[o] Biometric Authentication occurring...'+'\x1b[0m');
            console.log('\x1b[36m'+'[o] called FingerprintManagerCompat.authenticate(crypto,flags,cancel,callback,handler)'+'\x1b[0m');
            this.authenticate.overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'int', 'android.os.CancellationSignal', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler').call(this,crypto,flags,cancel,callback,handler);
        }
    } catch (err) {
        //console.log('[-] FingerprintManagerCompat not found');
    }
}



function hookCipherInits() {
    // Hooking the various Cipher.init(...) calls
    const targetCls = Java.use('javax.crypto.Cipher');
    const targetFunc = 'init';
    var keystoreList = [];
    var overloads = targetCls[targetFunc].overloads;
    var params = [];
    for (var i=0; i<overloads.length; i++) {
        for (var j in overloads[i].argumentTypes) {
            params.push(overloads[i].argumentTypes[j].className);
        }
        var argLog = generateLogs(params);
        targetCls[targetFunc].overloads[i].implementation = function() {
            var opmodeString = this.getOpmodeString(arguments[0]);
            var algo = this.getAlgorithm();
            // Debugging logs
            console.log('[+] Hooked Cipher.init('+argLog+') call');
            console.log('[+] opmode: '+opmodeString);
            //console.log('[+] key: '+key.$className);
            fcTracer(arguments, keystoreList, algo);
            var retval;
            // Re-calling the original method
            retval = this[targetFunc].apply(this, arguments);
        }
    }
}


function generateLogs(params) {
    var argLog = 'opcode';
    // Check if the second parameter is a certificate
    if (params[1].toString() === 'java.security.cert.Certificate') {
        params.length === 3 ? argLog=argLog.concat(',certificate,random') : argLog=argLog.concat(',certificate');
    } else {
        // Then the second parameter is a key
        argLog = argLog.concat(',key');
        if (params.length === 4) {
            if (params[2].toString() === 'java.security.spec.AlgorithmParameterSpec') {
                argLog = argLog.concat('key,paramspec,random');
            } else {
                argLog = argLog.concat('key,param,random');
            }
        } else if (params.length === 3) {
            if (params[2].toString() === 'java.security.spec.AlgorithmParameterSpec') {
                argLog = argLog.concat('key,paramspec');
            } if (params[2].toString() === 'java.security.spec.AlgorithmParameters') {
                argLog = argLog.concat('key,param');
            } else {
                argLog = argLog.concat('key,random');
            }
        }
    }
    return argLog;
}


function fcTracer(args, keystoreList, algo) {
    const keyFactoryCls = Java.use('java.security.KeyFactory');
    const keyInfoCls = Java.use('android.security.keystore.KeyInfo');
    const keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
    let keystores = ['android.security.keystore.AndroidKeyStoreSecretKey', 'android.security.keystore2.AndroidKeyStoreSecretKey', 
        'android.security.keystore2.AndroidKeyStorePrivateKey', 'android.security.keystore2.AndroidKeyStoreRSAPrivateKey', 
        'android.security.keystore2.AndroidKeyStoreECPrivateKey', 'android.security.keystore2.AndroidKeyStoreEdECPrivateKey',
        'android.security.keystore2.AndroidKeyStoreXDHPrivateKey'];
    // Check for Android Keystore usage 
    if (keystores.includes(args[1].$className)) {
        var keyFactoryObj = null;
        try {
                keyFactoryObj = keyFactoryCls.getInstance(args[1].getAlgorithm(), 'AndroidKeyStore');
        } catch (err) {
                keyFactoryObj = keySecretKeyFactoryCls.getInstance(args[1].getAlgorithm(), 'AndroidKeyStore');
        }
        var keyInfo = keyFactoryObj.getKeySpec(args[1], keyInfoCls.class);
        var keyInfoObj = Java.cast(keyInfo, keyInfoCls);
        var keystoreAlias = keyInfoObj.getKeystoreAlias();
        // Printing keystore data
        if (keystoreList.includes(keystoreAlias)) {
            printKeystoreData(keystoreAlias, keyInfoObj, algo, true);
        } else {
            keystoreList.push(keystoreAlias);
            printKeystoreData(keystoreAlias, keyInfoObj, algo, false);
        }
    }
    //console.log('[!] Found the class: '+args[1].$className); 
}


// Keystore data printer
function printKeystoreData(keystoreAlias, keyInfoObj, algorithm, alreadyCalled) {
    // LEGENDA KEY-PROPERTIES:
    // Main Origin values: 
    // 1=GENERATED-IN-KEYSTORE, 2=IMPORTED-PLAINTEXT, 4=UNKNOWN, 8=SECURELY-IMPORTED
    // Main Purposes values: 
    // 1=ENCRYPT, 2=DECRYPT, 4=SIGN-MAC, 8=VERIFY-MAC
    // Main Security-Level values: 
    // 2=SECURITY_LEVEL_STRONGBOX, 1=SECURITY_LEVEL_TRUSTED_ENVIRONMENT, 0=SECURITY_LEVEL_SOFTWARE, -1=SECURITY_LEVEL_UNKNOWN_SECURE, -2=SECURITY_LEVEL_UNKNOWN 
    // Main User-Authentication-Type values: 
    // 0=UNDEFINED, 1=AUTH_DEVICE_CREDENTIAL, 2=AUTH_BIOMETRIC_STRONG
    // Special value of remainingUsageCount: 
    // -1=UNRESTRICTED_USAGE_COUNT
    // References: https://developer.android.com/reference/android/security/keystore/KeyProperties
    if (alreadyCalled==true){
        console.log('*****************************');
        console.log('[+] Hooked an already called keystore item: '+ keystoreAlias);
        console.log('*****************************');
    } else {
        console.log('\x1b[34m'+'*****************************'+'\x1b[0m');            
        console.log('\x1b[34m'+'[+] Hooked keystore with alias: \x1b[0m'+keystoreAlias);
        console.log('\x1b[34m'+'[+] Algorithm: \x1b[0m'+algorithm);
        console.log('\x1b[34m'+'[+] Keysize: \x1b[0m'+keyInfoObj.getKeySize().toString());
        console.log('\x1b[34m'+'[+] BlockModes: \x1b[0m'+keyInfoObj.getBlockModes().toString());
        var digests = keyInfoObj.getDigests().toString();
        if (digests == '') digests = '[]';
        console.log('\x1b[34m'+'[+] Digests: \x1b[0m'+digests);
        console.log('\x1b[34m'+'[+] EncryptionPaddings: \x1b[0m'+keyInfoObj.getEncryptionPaddings().toString());
        var keyValidityForConsumptionEnd = keyInfoObj.getKeyValidityForConsumptionEnd();
        if (keyValidityForConsumptionEnd != null) keyValidityForConsumptionEnd = keyValidityForConsumptionEnd.toString();
        console.log('\x1b[34m'+'[+] keyValidityForConsumptionEnd: \x1b[0m'+keyValidityForConsumptionEnd);
        var keyValidityForOriginationEnd = keyInfoObj.getKeyValidityForOriginationEnd();
        if (keyValidityForOriginationEnd != null) keyValidityForOriginationEnd = keyValidityForOriginationEnd.toString();
        console.log('\x1b[34m'+'[+] keyValidityForOriginationEnd: \x1b[0m'+keyValidityForOriginationEnd);
        var keyValidityStart = keyInfoObj.getKeyValidityStart();
        if (keyValidityStart != null) keyValidityStart = keyValidityStart.toString();
        console.log('\x1b[34m'+'[+] keyValidityStart: \x1b[0m'+keyValidityStart);
        console.log('\x1b[34m'+'[+] Origin: \x1b[0m'+keyInfoObj.getOrigin().toString());
        console.log('\x1b[34m'+'[+] Purposes: \x1b[0m'+keyInfoObj.getPurposes().toString());
        var signaturePaddings = keyInfoObj.getSignaturePaddings().toString();
        if (signaturePaddings == '') signaturePaddings = '[]';
        console.log('\x1b[34m'+'[+] signaturePaddings: \x1b[0m'+signaturePaddings);
        console.log('\x1b[34m'+'[+] userAuthenticationValidityDurationSeconds: \x1b[0m'+keyInfoObj.getUserAuthenticationValidityDurationSeconds().toString());
        // The isInsideSecureHardware is deprecated and superseded by getSecurityLevel
        
        var value_color = keyInfoObj.isInsideSecureHardware() ? '\x1b[32m' : '\x1b[31m';
        console.log('\x1b[34m'+'[+] isInsideSecureHardware: '+value_color+keyInfoObj.isInsideSecureHardware().toString()+'\x1b[34m');


        value_color = keyInfoObj.isInvalidatedByBiometricEnrollment() ? '\x1b[32m' : '\x1b[31m';
        console.log('\x1b[34m'+'[+] isInvalidatedByBiometricEnrollment: '+value_color+keyInfoObj.isInvalidatedByBiometricEnrollment().toString()+'\x1b[34m');
        
        try { var isTrustedUserPresenceRequired = keyInfoObj.isTrustedUserPresenceRequired(); } catch (err) { }
        if (isTrustedUserPresenceRequired != null) {
            value_color = isTrustedUserPresenceRequired ? '\x1b[32m' : '\x1b[31m';
            console.log('\x1b[34m'+'[+] isTrustedUserPresenceRequired: '+value_color+isTrustedUserPresenceRequired.toString()+'\x1b[34m'); 
        }

        value_color = keyInfoObj.isUserAuthenticationRequired() ? '\x1b[32m' : '\x1b[31m';
        console.log('\x1b[34m'+'[+] isUserAuthenticationRequired: '+value_color+keyInfoObj.isUserAuthenticationRequired().toString()+'\x1b[34m');
        
        value_color = keyInfoObj.isUserAuthenticationRequirementEnforcedBySecureHardware() ? '\x1b[32m' : '\x1b[31m';
        console.log('\x1b[34m'+'[+] isUserAuthenticationRequirementEnforcedBySecureHardware: '+value_color+keyInfoObj.isUserAuthenticationRequirementEnforcedBySecureHardware().toString()+'\x1b[34m');
        
        value_color = keyInfoObj.isUserAuthenticationValidWhileOnBody() ? '\x1b[32m' : '\x1b[31m';
        console.log('\x1b[34m'+'[+] isUserAuthenticationValidWhileOnBody: '+value_color+keyInfoObj.isUserAuthenticationValidWhileOnBody().toString()+'\x1b[34m');

        try { var isUserConfirmationRequired = keyInfoObj.isUserConfirmationRequired(); } catch (err) { }

        if (isUserConfirmationRequired != null) {
            value_color = isUserConfirmationRequired ? '\x1b[32m' : '\x1b[31m';
            console.log('\x1b[34m'+'[+] isUserConfirmationRequired: '+value_color+isUserConfirmationRequired.toString()+'\x1b[34m');
        }

        try { var securityLevel = keyInfoObj.getSecurityLevel(); } catch (err) { }
        if (securityLevel != null) console.log('\x1b[34m'+'[+] securityLevel: \x1b[0m'+securityLevel.toString());
        try { var remainingUsageCount = keyInfoObj.getRemainingUsageCount(); } catch (err) { }
        if (remainingUsageCount != null) console.log('\x1b[34m'+'[+] remainingUsageCount: \x1b[0m'+remainingUsageCount.toString());
        // The user authentication types, it is only applied for private/secret keys when isUserAuthenticationRequired is enabled
        try { var userAuthenticationType = keyInfoObj.getUserAuthenticationType(); } catch (err) { }
        if (userAuthenticationType != null) console.log('\x1b[34m'+'[+] userAuthenticationType: \x1b[0m'+userAuthenticationType.toString());
        console.log('\x1b[34m'+'*****************************'+'\x1b[0m');
    }
}