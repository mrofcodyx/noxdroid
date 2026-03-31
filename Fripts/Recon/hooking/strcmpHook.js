// strcmpHook.js
// Hooks native strcmp in libc.so to log all string comparisons
// Useful for finding hardcoded secrets, license checks, etc.
// Usage: frida -U -n <app> -l strcmpHook.js
// Source: https://github.com/lautarovculic/fridaScripts

var strcmp = Module.findExportByName("libc.so", "strcmp");

if (strcmp) {
    Interceptor.attach(strcmp, {
        onEnter: function (args) {
            try {
                var s1 = Memory.readCString(args[0]);
                var s2 = Memory.readCString(args[1]);
                if (s1 && s2 && s1.length > 0 && s2.length > 0) {
                    console.log("[strcmp] \"" + s1 + "\" == \"" + s2 + "\"");
                }
            } catch (e) {
                // Skip unreadable pointers
            }
        }
    });
    console.log("[*] strcmp hook active.");
} else {
    console.log("[-] strcmp not found in libc.so");
}
