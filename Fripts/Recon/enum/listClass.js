// listClass.js
// Enumerates all loaded classes matching a given package name
// Usage: frida -U -n <app> -l listClass.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var targetPackage = "com.example"; // Change to target package

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.indexOf(targetPackage) !== -1) {
                console.log("[+] " + className);
            }
        },
        onComplete: function () {
            console.log("[*] Class enumeration complete.");
        }
    });
});
