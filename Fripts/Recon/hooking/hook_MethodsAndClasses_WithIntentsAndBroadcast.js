// hook_MethodsAndClasses_WithIntentsAndBroadcast.js
// Example script: hooks app methods + intercepts Intent/Broadcast activity
// Usage: frida -U -n <app> -l hook_MethodsAndClasses_WithIntentsAndBroadcast.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {

    // ── Intent interception ──────────────────────────────────────────────────
    var Intent = Java.use("android.content.Intent");

    Intent.$init.overload("android.content.Context", "java.lang.Class").implementation = function (ctx, cls) {
        console.log("[Intent] new Intent -> " + cls.getName());
        return this.$init(ctx, cls);
    };

    Intent.setAction.implementation = function (action) {
        console.log("[Intent.setAction] " + action);
        return this.setAction(action);
    };

    Intent.putExtra.overload("java.lang.String", "java.lang.String").implementation = function (key, value) {
        console.log("[Intent.putExtra] " + key + " = " + value);
        return this.putExtra(key, value);
    };

    // ── Broadcast interception ───────────────────────────────────────────────
    var ContextWrapper = Java.use("android.content.ContextWrapper");

    ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
        console.log("[sendBroadcast] action=" + intent.getAction());
        return this.sendBroadcast(intent);
    };

    ContextWrapper.startActivity.overload("android.content.Intent").implementation = function (intent) {
        console.log("[startActivity] action=" + intent.getAction() + " component=" + intent.getComponent());
        return this.startActivity(intent);
    };

    // ── Example: hook a specific app method ─────────────────────────────────
    // Uncomment and adapt to your target:
    /*
    var TargetClass = Java.use("com.example.TargetClass");
    TargetClass.targetMethod.implementation = function (arg1) {
        console.log("[TargetClass.targetMethod] arg1=" + arg1);
        var result = this.targetMethod(arg1);
        console.log("[TargetClass.targetMethod] result=" + result);
        return result;
    };
    */

    console.log("[*] Intent/Broadcast hooks active.");
});
