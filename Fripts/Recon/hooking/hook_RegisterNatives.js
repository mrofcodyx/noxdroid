// hook_RegisterNatives.js
// Hooks RegisterNatives in libart.so to reveal JNI method mappings at runtime
// Useful for finding native method implementations in obfuscated apps
// Usage: frida -U -f <app> -l hook_RegisterNatives.js
// Source: https://github.com/lautarovculic/fridaScripts

var libart = Process.findModuleByName("libart.so");

if (libart) {
    var symbols = libart.enumerateSymbols();
    var registerNativesAddr = null;

    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name.indexOf("RegisterNatives") !== -1 &&
            symbols[i].name.indexOf("CheckJNI") === -1) {
            registerNativesAddr = symbols[i].address;
            console.log("[*] Found RegisterNatives at: " + registerNativesAddr + " (" + symbols[i].name + ")");
            break;
        }
    }

    if (registerNativesAddr) {
        Interceptor.attach(registerNativesAddr, {
            onEnter: function (args) {
                // args[0] = JNIEnv*, args[1] = jclass, args[2] = JNINativeMethod*, args[3] = nMethods
                var env = args[0];
                var clazz = args[1];
                var methods = args[2];
                var nMethods = args[3].toInt32();

                try {
                    // Get class name via JNI
                    var jclassName = Java.vm.tryGetEnv().getClassName(clazz);
                    console.log("\n[RegisterNatives] Class: " + jclassName + " (" + nMethods + " methods)");
                } catch (e) {
                    console.log("\n[RegisterNatives] (" + nMethods + " methods)");
                }

                for (var i = 0; i < nMethods; i++) {
                    // JNINativeMethod struct: { char* name, char* signature, void* fnPtr }
                    var structPtr = methods.add(i * Process.pointerSize * 3);
                    try {
                        var name = Memory.readCString(Memory.readPointer(structPtr));
                        var sig  = Memory.readCString(Memory.readPointer(structPtr.add(Process.pointerSize)));
                        var fnPtr = Memory.readPointer(structPtr.add(Process.pointerSize * 2));
                        console.log("  [+] " + name + sig + " -> " + fnPtr + " (" + DebugSymbol.fromAddress(fnPtr) + ")");
                    } catch (e) {
                        console.log("  [-] Could not read method " + i);
                    }
                }
            }
        });
        console.log("[*] RegisterNatives hook active.");
    } else {
        console.log("[-] RegisterNatives symbol not found in libart.so");
    }
} else {
    console.log("[-] libart.so not found");
}
