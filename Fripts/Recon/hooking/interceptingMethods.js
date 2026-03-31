// interceptingMethods.js
// Template for intercepting method calls and inspecting arguments/return values
// Usage: frida -U -n <app> -l interceptingMethods.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var targetClass  = "com.example.TargetClass";  // Change to target class
    var targetMethod = "targetMethod";              // Change to target method

    try {
        var Clazz = Java.use(targetClass);

        // Hook all overloads
        Clazz[targetMethod].overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.from(arguments);
                console.log("\n[" + targetClass + "." + targetMethod + "]");
                args.forEach(function (arg, i) {
                    console.log("  arg[" + i + "] = " + arg);
                });

                var result = this[targetMethod].apply(this, args);
                console.log("  return = " + result);
                return result;
            };
        });

        console.log("[*] Hooked " + targetClass + "." + targetMethod);
    } catch (e) {
        console.log("[-] Hook failed: " + e);
    }
});
