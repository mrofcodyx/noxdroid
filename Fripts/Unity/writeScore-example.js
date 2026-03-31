// writeScore-example.js
// Example: writes the score field in a Unity game using Il2Cpp bridge
// Requires: frida-il2cpp-bridge (https://github.com/vfsfitvnm/frida-il2cpp-bridge)
// Usage: frida -U -f com.unity.game -l writeScore-example.js
// Source: https://github.com/lautarovculic/fridaScripts

Il2Cpp.perform(() => {
    var scoreClass  = "GameManager"; // Change to the class holding the score
    var scoreField  = "score";       // Change to the score field name
    var scoreMethod = "AddScore";    // Method to hook as trigger
    var targetScore = 999999;        // Score to set

    var klass = Il2Cpp.Domain.assemblies
        .flatMap(a => a.image.classes)
        .find(c => c.name === scoreClass);

    if (!klass) {
        console.log("[-] Class not found: " + scoreClass);
        return;
    }

    var method = klass.tryMethod(scoreMethod);
    if (!method) {
        console.log("[-] Method not found: " + scoreMethod + " — trying Update as fallback");
        method = klass.tryMethod("Update");
    }

    if (!method) {
        console.log("[-] No suitable hook method found.");
        return;
    }

    var patched = false;
    method.implementation = function () {
        if (!patched) {
            var field = this.field(scoreField);
            if (field) {
                field.value = targetScore;
                console.log("[WriteScore] " + scoreField + " set to " + targetScore);
                patched = true;
            }
        }
        return this[method.name]();
    };

    console.log("[*] Score writer active — waiting for " + scoreMethod + " call...");
});
