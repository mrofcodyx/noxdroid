// earlyInstr_Sqlcipher.js
// Hooks sqlite3_key in libsqlcipher.so at app launch to capture the DB encryption key
// Usage: frida -U -f com.myapp -l earlyInstr_Sqlcipher.js
// Source: https://github.com/Magpol/MiscFrida

function tryHookSqlcipher() {
    var baseAddr = Module.findBaseAddress("libsqlcipher.so");
    if (baseAddr) {
        console.log("[*] libsqlcipher.so loaded at: " + baseAddr);
        hookSqlcipherFunctions(baseAddr);
    } else {
        setTimeout(tryHookSqlcipher, 100);
    }
}

function hookSqlcipherFunctions(baseAddr) {
    var targetFunc = Module.findExportByName("libsqlcipher.so", "sqlite3_key");
    if (targetFunc) {
        console.log("[*] Hooking sqlite3_key at: " + targetFunc);
        Interceptor.attach(targetFunc, {
            onEnter: function (args) {
                console.log("[Database] -> " + args[0]);
                console.log(hexdump(args[1], {
                    offset: 0,
                    length: args[2].toInt32(),
                    header: true,
                    ansi: true
                }));
                console.log("[length] -> " + args[2].toInt32());
                console.log("sqlite3_key called from:\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n") + "\n");
            },
            onLeave: function (retval) {
                console.log("[*] sqlite3_key returned: " + retval);
            }
        });
    } else {
        console.log("[-] sqlite3_key not found in libsqlcipher.so");
    }
}

tryHookSqlcipher();
