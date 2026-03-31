/**
 * Crypto Monitor — NoxDroid (v2)
 * Correlaciona init → update → doFinal em uma única entrada legível.
 * Mostra plaintext decifrado quando disponível.
 */

"use strict";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toHex(bytes) {
    if (!bytes) return null;
    try {
        var arr = Java.array("byte", bytes);
        var h = "";
        for (var i = 0; i < arr.length; i++)
            h += ("0" + (arr[i] & 0xff).toString(16)).slice(-2);
        return h;
    } catch (e) { return null; }
}

function toStr(bytes) {
    if (!bytes) return null;
    try {
        var arr = Java.array("byte", bytes);
        var s = "";
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i] & 0xff;
            if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
            else return null;  // não é string printável
        }
        return s.length >= 2 ? s : null;
    } catch (e) { return null; }
}

function display(bytes, maxBytes) {
    if (!bytes) return "(null)";
    try {
        var arr = Java.array("byte", bytes);
        var len = arr.length;
        var cap = maxBytes || 256;

        // Tenta string printável primeiro
        var s = "";
        var printable = true;
        for (var i = 0; i < Math.min(len, cap); i++) {
            var b = arr[i] & 0xff;
            if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
            else { printable = false; break; }
        }
        if (printable && s.length >= 2) {
            return '"' + s + (len > cap ? "…" : "") + '"  (' + len + ' bytes)';
        }

        // Hex
        var h = "";
        for (var j = 0; j < Math.min(len, cap); j++)
            h += ("0" + (arr[j] & 0xff).toString(16)).slice(-2);
        return h + (len > cap ? "…" : "") + "  (" + len + " bytes)";
    } catch (e) { return "(erro)"; }
}

// getStack() — wrapper de compatibilidade → usa stack.js se disponível
function getStack() {
    try {
        var lines = (typeof javaStackToLines === "function")
            ? javaStackToLines()
            : (function () {
                var frames = Java.use("java.lang.Exception").$new().getStackTrace();
                var out = [];
                var SKIP = ["java.", "javax.", "android.", "com.android.", "dalvik.", "sun."];
                for (var i = 2; i < Math.min(frames.length, 10); i++) {
                    var f = frames[i].toString();
                    var skip = false;
                    for (var s = 0; s < SKIP.length; s++)
                        if (f.startsWith(SKIP[s])) { skip = true; break; }
                    if (!skip) out.push("    \u21b3 " + f);
                }
                return out;
            })();
        return lines.join("\n");
    } catch (e) { return ""; }
}

// ─── Sessões de Cipher (correlaciona init → doFinal) ─────────────────────────
// Chave: threadId → { algo, mode, key, iv, inputChunks[] }

var _sessions = {};

function _sessionKey() {
    return Java.use("java.lang.Thread").currentThread().getId().toString();
}

// ─── Formatação de saída ──────────────────────────────────────────────────────

var SEP  = "─".repeat(64);
var SEP2 = "═".repeat(64);

function _printOp(tag, fields, stack) {
    console.log("\n" + SEP);
    console.log("[" + tag + "]");
    for (var k in fields) {
        if (fields[k] !== null && fields[k] !== undefined && fields[k] !== "")
            console.log("  " + (k + "          ").slice(0, 10) + ": " + fields[k]);
    }
    if (stack) console.log(stack);
    send({ type: "crypto", tag: tag, fields: fields });
}

// ─── Cipher ───────────────────────────────────────────────────────────────────

Java.perform(function () {

    var Cipher = Java.use("javax.crypto.Cipher");

    // init(int, Key)
    Cipher.init.overload("int", "java.security.Key").implementation = function (op, key) {
        var tid = _sessionKey();
        _sessions[tid] = {
            algo: this.getAlgorithm(),
            mode: op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" : "WRAP(" + op + ")",
            key:  key.getEncoded ? display(key.getEncoded()) : "(sem encoded)",
            iv:   null,
            chunks: []
        };
        return this.init(op, key);
    };

    // init(int, Key, AlgorithmParameterSpec)
    Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (op, key, params) {
        var tid = _sessionKey();
        var iv = null;
        try {
            var IvSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            iv = display(Java.cast(params, IvSpec).getIV());
        } catch (e) {
            try {
                var GcmSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
                iv = display(Java.cast(params, GcmSpec).getIV());
            } catch (e2) {}
        }
        _sessions[tid] = {
            algo: this.getAlgorithm(),
            mode: op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" : "WRAP(" + op + ")",
            key:  key.getEncoded ? display(key.getEncoded()) : "(sem encoded)",
            iv:   iv,
            chunks: []
        };
        return this.init(op, key, params);
    };

    // update([B) — acumula chunks
    Cipher.update.overload("[B").implementation = function (input) {
        var tid = _sessionKey();
        var result = this.update(input);
        if (_sessions[tid] && input) _sessions[tid].chunks.push(input);
        return result;
    };

    // doFinal([B)
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);
        var tid    = _sessionKey();
        var sess   = _sessions[tid] || {};
        var stack  = getStack();

        _printOp("Cipher", {
            "Algoritmo": sess.algo || this.getAlgorithm(),
            "Modo":      sess.mode || "?",
            "Chave":     sess.key  || null,
            "IV":        sess.iv   || null,
            "Input":     display(input),
            "Output":    display(result),
        }, stack);

        delete _sessions[tid];
        return result;
    };

    // doFinal()
    Cipher.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        var tid    = _sessionKey();
        var sess   = _sessions[tid] || {};
        var stack  = getStack();

        // Junta chunks acumulados via update()
        var inputDisplay = null;
        if (sess.chunks && sess.chunks.length > 0) {
            // Tenta mostrar o último chunk como string
            var last = sess.chunks[sess.chunks.length - 1];
            inputDisplay = display(last);
        }

        _printOp("Cipher", {
            "Algoritmo": sess.algo || this.getAlgorithm(),
            "Modo":      sess.mode || "?",
            "Chave":     sess.key  || null,
            "IV":        sess.iv   || null,
            "Input":     inputDisplay || "(via update)",
            "Output":    display(result),
        }, stack);

        delete _sessions[tid];
        return result;
    };

    // doFinal([B, int, int)
    Cipher.doFinal.overload("[B", "int", "int").implementation = function (input, off, len) {
        var result = this.doFinal(input, off, len);
        var tid    = _sessionKey();
        var sess   = _sessions[tid] || {};
        var stack  = getStack();

        _printOp("Cipher", {
            "Algoritmo": sess.algo || this.getAlgorithm(),
            "Modo":      sess.mode || "?",
            "Chave":     sess.key  || null,
            "IV":        sess.iv   || null,
            "Input":     display(input),
            "Output":    display(result),
        }, stack);

        delete _sessions[tid];
        return result;
    };

    // ─── Mac ──────────────────────────────────────────────────────────────────

    var Mac = Java.use("javax.crypto.Mac");

    Mac.init.overload("java.security.Key").implementation = function (key) {
        var tid = _sessionKey();
        _sessions["mac_" + tid] = {
            algo: this.getAlgorithm(),
            key:  key.getEncoded ? display(key.getEncoded()) : null
        };
        return this.init(key);
    };

    Mac.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);
        var tid    = _sessionKey();
        var sess   = _sessions["mac_" + tid] || {};
        _printOp("Mac", {
            "Algoritmo": sess.algo || this.getAlgorithm(),
            "Chave":     sess.key  || null,
            "Input":     display(input),
            "HMAC":      display(result),
        }, getStack());
        delete _sessions["mac_" + tid];
        return result;
    };

    Mac.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        var tid    = _sessionKey();
        var sess   = _sessions["mac_" + tid] || {};
        _printOp("Mac", {
            "Algoritmo": sess.algo || this.getAlgorithm(),
            "Chave":     sess.key  || null,
            "HMAC":      display(result),
        }, getStack());
        delete _sessions["mac_" + tid];
        return result;
    };

    // ─── MessageDigest ────────────────────────────────────────────────────────

    var MessageDigest = Java.use("java.security.MessageDigest");

    MessageDigest.digest.overload("[B").implementation = function (input) {
        var result = this.digest(input);
        _printOp("MessageDigest", {
            "Algoritmo": this.getAlgorithm(),
            "Input":     display(input),
            "Hash":      display(result),
        }, getStack());
        return result;
    };

    MessageDigest.digest.overload().implementation = function () {
        var result = this.digest();
        _printOp("MessageDigest", {
            "Algoritmo": this.getAlgorithm(),
            "Hash":      display(result),
        }, getStack());
        return result;
    };

    // ─── SecretKeySpec ────────────────────────────────────────────────────────

    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
        _printOp("SecretKeySpec", {
            "Algoritmo": algo,
            "Chave":     display(key),
        }, getStack());
        return this.$init(key, algo);
    };

    // ─── KeyGenerator ─────────────────────────────────────────────────────────

    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");

    KeyGenerator.generateKey.implementation = function () {
        var key = this.generateKey();
        _printOp("KeyGenerator", {
            "Algoritmo": this.getAlgorithm(),
            "Chave":     display(key.getEncoded()),
        }, getStack());
        return key;
    };

    console.log(SEP2);
    console.log("  NoxDroid — Crypto Monitor v2");
    console.log("  Hooks: Cipher (init+doFinal), Mac, MessageDigest,");
    console.log("         SecretKeySpec, KeyGenerator");
    console.log("  Mostra: algoritmo, modo, chave, IV, input, output");
    console.log(SEP2 + "\n");
});
