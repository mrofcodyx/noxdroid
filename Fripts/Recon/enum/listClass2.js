// listClass2.js
// Enumerates classes and their methods for a target package
// Usage: frida -U -n <app> -l listClass2.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var targetPackage = "com.example"; // Change to target package

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.indexOf(targetPackage) !== -1) {
                try {
                    var clazz = Java.use(className);
                    var methods = clazz.class.getDeclaredMethods();
                    console.log("\n[Class] " + className);
                    methods.forEach(function (method) {
                        console.log("  [Method] " + method.getName() + " -> " + method.toString());
                    });
                } catch (e) {
                    console.log("[-] Could not inspect: " + className + " (" + e + ")");
                }
            }
        },
        onComplete: function () {
            console.log("\n[*] Enumeration complete.");
        }
    });
});
