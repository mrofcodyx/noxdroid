// logs.js
// Hooks android.util.Log (d/v/i/e/w) to intercept all app log output at runtime
// Useful for capturing debug info that doesn't appear in logcat (obfuscated apps)
// Usage: frida -U -n <app> -l logs.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var Log = Java.use("android.util.Log");

    var levels = {
        d: "DEBUG",
        v: "VERBOSE",
        i: "INFO",
        e: "ERROR",
        w: "WARN"
    };

    Object.keys(levels).forEach(function (level) {
        try {
            Log[level].overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
                console.log("[Log." + levels[level] + "] [" + tag + "] " + msg);
                return this[level](tag, msg);
            };
        } catch (e) {
            console.log("[-] Could not hook Log." + level + ": " + e);
        }
    });

    console.log("[*] android.util.Log hooks active (d/v/i/e/w).");
});
