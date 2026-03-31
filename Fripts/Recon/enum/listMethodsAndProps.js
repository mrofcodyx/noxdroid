// listMethodsAndProps.js
// Lists all methods and properties of a specific class
// Usage: frida -U -n <app> -l listMethodsAndProps.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var targetClass = "com.example.TargetClass"; // Change to target class

    try {
        var clazz = Java.use(targetClass);
        var jClass = clazz.class;

        console.log("\n[*] Class: " + targetClass);

        console.log("\n[Methods]");
        jClass.getDeclaredMethods().forEach(function (method) {
            var params = Array.from(method.getParameterTypes()).map(function (p) { return p.getName(); }).join(", ");
            console.log("  " + method.getName() + "(" + params + ") -> " + method.getReturnType().getName());
        });

        console.log("\n[Fields]");
        jClass.getDeclaredFields().forEach(function (field) {
            console.log("  " + field.getName() + " : " + field.getType().getName());
        });

        console.log("\n[Constructors]");
        jClass.getDeclaredConstructors().forEach(function (ctor) {
            var params = Array.from(ctor.getParameterTypes()).map(function (p) { return p.getName(); }).join(", ");
            console.log("  <init>(" + params + ")");
        });

    } catch (e) {
        console.log("[-] Error: " + e);
    }
});
