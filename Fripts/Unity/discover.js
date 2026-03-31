// discover.js
// Enumerates Il2Cpp classes, fields, and methods for Unity games
// Requires: frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)
// Usage: frida -U -f com.unity.game -l discover.js
// Source: https://github.com/lautarovculic/fridaScripts

Il2Cpp.perform(() => {
    var targetNamespace = ""; // Filter by namespace, or leave empty for all

    Il2Cpp.Domain.assemblies.forEach(assembly => {
        assembly.image.classes.forEach(klass => {
            if (targetNamespace && klass.namespace !== targetNamespace) return;

            console.log("\n[Class] " + klass.namespace + "." + klass.name);

            klass.fields.forEach(field => {
                console.log("  [Field]  " + field.name + " : " + field.type.name);
            });

            klass.methods.forEach(method => {
                var params = method.parameters.map(p => p.type.name + " " + p.name).join(", ");
                console.log("  [Method] " + method.name + "(" + params + ") -> " + method.returnType.name);
            });
        });
    });

    console.log("\n[*] Il2Cpp discovery complete.");
});
