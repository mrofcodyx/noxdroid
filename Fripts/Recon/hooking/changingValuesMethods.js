// changingValuesMethods.js
// Template for overriding method return values at runtime
// Usage: frida -U -n <app> -l changingValuesMethods.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var targetClass  = "com.example.TargetClass";  // Change to target class
    var targetMethod = "isFeatureEnabled";          // Change to target method

    try {
        var Clazz = Java.use(targetClass);

        // Example: force boolean return to true
        Clazz[targetMethod].overloads.forEach(function (overload) {
            overload.implementation = function () {
                var original = this[targetMethod].apply(this, arguments);
                var forced   = true; // Change to desired return value

                console.log("[" + targetClass + "." + targetMethod + "]");
                console.log("  original = " + original);
                console.log("  forced   = " + forced);

                return forced;
            };
        });

        console.log("[*] Return value override active for " + targetClass + "." + targetMethod);
    } catch (e) {
        console.log("[-] Hook failed: " + e);
    }
});
