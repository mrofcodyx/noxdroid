// fieldModifier-GENERIC.js
// Modifies Il2Cpp field values via method hook — generic template for Unity games
// Requires: frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)
// Usage: frida -U -f com.unity.game -l fieldModifier-GENERIC.js
// Source: https://github.com/lautarovculic/fridaScripts

Il2Cpp.perform(() => {
    var targetClass  = "TargetClass";   // Change to target class name
    var targetMethod = "Update";        // Method to hook as trigger
    var targetField  = "someField";     // Field to modify
    var newValue     = 9999;            // New value to set

    var klass = Il2Cpp.Domain.assemblies
        .flatMap(a => a.image.classes)
        .find(c => c.name === targetClass);

    if (!klass) {
        console.log("[-] Class not found: " + targetClass);
        return;
    }

    var method = klass.tryMethod(targetMethod);
    if (!method) {
        console.log("[-] Method not found: " + targetMethod);
        return;
    }

    method.implementation = function () {
        var field = this.field(targetField);
        if (field) {
            var current = field.value;
            field.value = newValue;
            console.log("[FieldModifier] " + targetField + ": " + current + " -> " + newValue);
        }
        return this[targetMethod]();
    };

    console.log("[*] Field modifier active for " + targetClass + "." + targetField);
});
