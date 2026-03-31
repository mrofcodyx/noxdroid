// listClassAndMethods.js
// Lists ALL loaded classes and their declared methods and fields
// Usage: frida -U -n <app> -l listClassAndMethods.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                var fields = clazz.class.getDeclaredFields();

                if (methods.length > 0 || fields.length > 0) {
                    console.log("\n[Class] " + className);

                    methods.forEach(function (method) {
                        console.log("  [Method] " + method.getName());
                    });

                    fields.forEach(function (field) {
                        console.log("  [Field]  " + field.getName() + " : " + field.getType().getName());
                    });
                }
            } catch (e) {
                // Skip classes that can't be reflected
            }
        },
        onComplete: function () {
            console.log("\n[*] Full class/method/field enumeration complete.");
        }
    });
});
