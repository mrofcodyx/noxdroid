/**
 * Method Tracer — NoxDroid
 * Hooks Java methods via Frida (sem Stalker — mais estável).
 *
 * Modos:
 *   sensitive — classes críticas: crypto, auth, network, storage
 *   package   — todos os métodos do package do app
 *   class     — uma classe específica
 *
 * Config injetada pelo launcher Python via __TRACE_CONFIG__.
 */

"use strict";

var CFG = (typeof __TRACE_CONFIG__ !== "undefined")
    ? __TRACE_CONFIG__
    : {
        mode:           "sensitive",
        target:         "",
        maxDepth:       4,
        showArgs:       true,
        showReturn:     true,
        filterInternal: true,
        maxEvents:      2000
    };

// ─── Classes sensíveis — NÃO inclui reflect.Method (causa loop) ───────────────
var SENSITIVE_CLASSES = [
    // Crypto
    "javax.crypto.Cipher",
    "javax.crypto.Mac",
    "javax.crypto.KeyGenerator",
    "javax.crypto.SecretKeyFactory",
    "java.security.MessageDigest",
    "java.security.KeyPairGenerator",
    "java.security.Signature",
    "javax.crypto.spec.SecretKeySpec",
    "javax.crypto.spec.IvParameterSpec",
    // Auth / Prefs
    "android.accounts.AccountManager",
    "android.content.SharedPreferences$Editor",
    // Network
    "java.net.URL",
    "javax.net.ssl.HttpsURLConnection",
    "java.net.HttpURLConnection",
    "okhttp3.OkHttpClient$Builder",
    "okhttp3.Request$Builder",
    // Storage / DB
    "android.database.sqlite.SQLiteDatabase",
    "java.io.FileOutputStream",
    "java.io.FileInputStream",
    // Dynamic loading / exec
    "dalvik.system.DexClassLoader",
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    // WebView
    "android.webkit.WebView",
    "android.webkit.WebSettings",
];

// ─── Prefixos a ignorar sempre (evita loops e spam) ──────────────────────────
var IGNORE_PREFIXES = [
    "java.lang.Object",
    "java.lang.Class",
    "java.lang.reflect.",      // CRÍTICO — causa loop se hookado
    "sun.reflect.",
    "com.android.internal.",
    "android.os.Handler",
    "android.os.Looper",
    "android.os.MessageQueue",
    "android.os.Binder",
    "android.os.Parcel",
    "dalvik.system.VMRuntime",
    "libcore.",
];

// ─── Métodos a ignorar por nome (muito frequentes, sem valor) ─────────────────
var IGNORE_METHODS = [
    "hashCode", "equals", "toString", "getClass", "notify",
    "notifyAll", "wait", "finalize", "clone", "compareTo",
    "ordinal", "name", "values",
];

// ─── Estado ───────────────────────────────────────────────────────────────────
var _depth    = 0;
var _count    = 0;
var _maxEvt   = CFG.maxEvents || 2000;
var _maxDepth = CFG.maxDepth  || 4;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _indent(d) {
    return "  ".repeat(Math.min(d, 10));
}

function _str(v) {
    if (v === null || v === undefined) return "null";
    try {
        var s = String(v);
        return s.length > 100 ? s.substring(0, 100) + "…" : s;
    } catch (e) { return "[?]"; }
}

function _args(a) {
    if (!CFG.showArgs || !a || a.length === 0) return "()";
    var parts = [];
    for (var i = 0; i < Math.min(a.length, 5); i++) parts.push(_str(a[i]));
    if (a.length > 5) parts.push("+" + (a.length - 5) + " more");
    return "(" + parts.join(", ") + ")";
}

function _shouldIgnoreClass(cls) {
    for (var i = 0; i < IGNORE_PREFIXES.length; i++) {
        if (cls.startsWith(IGNORE_PREFIXES[i])) return true;
    }
    return false;
}

function _shouldIgnoreMethod(name) {
    return IGNORE_METHODS.indexOf(name) !== -1;
}

// ─── Hook de um overload específico ──────────────────────────────────────────

function _hookOverload(cls, method, ol) {
    try {
        ol.implementation = function () {
            if (_count >= _maxEvt) {
                if (_count === _maxEvt) {
                    _count++;
                    console.log("\n[!] Limite de " + _maxEvt + " eventos atingido. Parando trace.");
                    console.log("[!] Use Ctrl+C para salvar ou aumente maxEvents na config.\n");
                }
                return ol.apply(this, arguments);
            }

            if (_depth >= _maxDepth) {
                return ol.apply(this, arguments);
            }

            _count++;
            _depth++;

            var ind  = _indent(_depth);
            var args = _args(arguments);
            var line = ind + "→ " + cls + "." + method + args;
            console.log(line);

            // Stack trace opcional (apenas no nível 1 para não poluir)
            if (_depth === 1 && typeof logJavaStack === "function") {
                logJavaStack(method);
            }

            var ret;
            try {
                ret = ol.apply(this, arguments);
            } catch (ex) {
                console.log(ind + "✖ " + cls + "." + method + " threw: " + ex);
                _depth--;
                throw ex;
            }

            if (CFG.showReturn && ret !== undefined && ret !== null) {
                console.log(ind + "← " + _str(ret));
            }
            _depth--;
            return ret;
        };
    } catch (e) {
        // overload não hookável — ignora silenciosamente
    }
}

// ─── Hook de uma classe inteira ───────────────────────────────────────────────

function _hookClass(className) {
    if (_shouldIgnoreClass(className)) return 0;
    try {
        var clazz   = Java.use(className);
        var methods = clazz.class.getDeclaredMethods();
        var hooked  = 0;
        methods.forEach(function (m) {
            var name = m.getName();
            if (_shouldIgnoreMethod(name)) return;
            try {
                var ols = clazz[name] && clazz[name].overloads;
                if (!ols) return;
                ols.forEach(function (ol) {
                    _hookOverload(className, name, ol);
                    hooked++;
                });
            } catch (e) {}
        });
        if (hooked > 0) {
            console.log("[Tracer] Hooked " + hooked + " métodos em " + className);
        }
        return hooked;
    } catch (e) {
        return 0;
    }
}

// ─── Modos ────────────────────────────────────────────────────────────────────

function modeSensitive() {
    console.log("[NoxDroid] Modo: Sensível — " + SENSITIVE_CLASSES.length + " classes");
    console.log("[NoxDroid] MaxDepth: " + _maxDepth + "  MaxEvents: " + _maxEvt + "\n");
    var total = 0;
    SENSITIVE_CLASSES.forEach(function (cls) {
        total += _hookClass(cls);
    });
    console.log("\n[NoxDroid] " + total + " métodos hookados. Interaja com o app.\n");
}

function modePackage(prefix) {
    console.log("[NoxDroid] Modo: Package — prefix: " + prefix);
    console.log("[NoxDroid] Enumerando classes carregadas...\n");
    var total = 0;
    Java.enumerateLoadedClasses({
        onMatch: function (cls) {
            if (cls.startsWith(prefix) && !_shouldIgnoreClass(cls)) {
                total += _hookClass(cls);
            }
        },
        onComplete: function () {
            console.log("\n[NoxDroid] " + total + " métodos hookados. Interaja com o app.\n");
        }
    });
}

function modeClass(className) {
    console.log("[NoxDroid] Modo: Classe — " + className + "\n");
    var n = _hookClass(className);
    console.log("\n[NoxDroid] " + n + " métodos hookados. Interaja com o app.\n");
}

// ─── Entry point ──────────────────────────────────────────────────────────────

Java.perform(function () {
    console.log("════════════════════════════════════════════════════════");
    console.log("  NoxDroid ◆ Method Tracer");
    console.log("  Modo    : " + CFG.mode);
    console.log("  Target  : " + (CFG.target || "(automático)"));
    console.log("  MaxDepth: " + _maxDepth + "  MaxEvents: " + _maxEvt);
    console.log("════════════════════════════════════════════════════════\n");

    switch (CFG.mode) {
        case "package":
            if (CFG.target) { modePackage(CFG.target); break; }
            // fallthrough
        case "class":
            if (CFG.mode === "class" && CFG.target) { modeClass(CFG.target); break; }
            // fallthrough
        default:
            modeSensitive();
    }
});
