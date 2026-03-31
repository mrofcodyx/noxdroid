/**
 * stack.js — NoxDroid Stack Utilities
 * Módulo compartilhado de stack trace para todos os scripts Frida.
 *
 * Injetado automaticamente pelo launcher Python antes de qualquer script.
 * Config injetável via __STACK_CONFIG__ (pelo launcher) ou defaults abaixo.
 *
 * Exports (globais):
 *   logJavaStack(tag)          — backtrace Java via java.lang.Exception
 *   logNativeStack(ctx, tag)   — backtrace nativo via Thread.backtrace
 *   logStack(ctx, tag)         — Java + nativo (quando ctx disponível)
 *   stackToLines(ctx)          — retorna array de strings (sem print)
 *   javaStackToLines()         — retorna array de strings Java
 */

(function () {
    "use strict";

    // ── Config ────────────────────────────────────────────────────────────────
    var _cfg = (typeof __STACK_CONFIG__ !== "undefined") ? __STACK_CONFIG__ : {};

    var STACK_ENABLED   = _cfg.enabled   !== undefined ? _cfg.enabled   : true;
    var MAX_DEPTH       = _cfg.maxDepth  !== undefined ? _cfg.maxDepth  : 12;
    var SKIP_SYSTEM     = _cfg.skipSystem !== undefined ? _cfg.skipSystem : true;
    var BACKTRACER_MODE = _cfg.accurate  !== undefined
        ? (_cfg.accurate ? Backtracer.ACCURATE : Backtracer.FUZZY)
        : Backtracer.ACCURATE;

    // Prefixos de frames a filtrar quando skipSystem=true
    var SYSTEM_PREFIXES = [
        "java.", "javax.", "android.", "com.android.", "dalvik.",
        "sun.", "libcore.", "com.google.android.", "androidx.",
    ];

    // Libs nativas a filtrar
    var NATIVE_SKIP = [
        "libc.so", "libdvm.so", "libandroid_runtime.so",
        "libart.so", "libfrida", "libglib", "libgobject",
    ];

    // ── Helpers internos ──────────────────────────────────────────────────────

    function _isSystemFrame(frame) {
        if (!SKIP_SYSTEM) return false;
        var s = frame.toString();
        for (var i = 0; i < SYSTEM_PREFIXES.length; i++) {
            if (s.indexOf(SYSTEM_PREFIXES[i]) === 0) return true;
        }
        return false;
    }

    function _isNativeSkip(sym) {
        var s = sym.toString().toLowerCase();
        for (var i = 0; i < NATIVE_SKIP.length; i++) {
            if (s.indexOf(NATIVE_SKIP[i]) !== -1) return true;
        }
        return false;
    }

    // ── Java stack ────────────────────────────────────────────────────────────

    function javaStackToLines() {
        try {
            var frames = Java.use("java.lang.Exception").$new().getStackTrace();
            var out = [];
            for (var i = 2; i < Math.min(frames.length, MAX_DEPTH + 2); i++) {
                var f = frames[i].toString();
                if (!_isSystemFrame(f)) {
                    out.push("  \u21b3 " + f);
                }
            }
            return out;
        } catch (e) {
            return [];
        }
    }

    function logJavaStack(tag) {
        if (!STACK_ENABLED) return;
        var lines = javaStackToLines();
        if (lines.length === 0) return;
        console.log("  [stack" + (tag ? ":" + tag : "") + "]");
        lines.forEach(function (l) { console.log(l); });
    }

    // ── Native stack ──────────────────────────────────────────────────────────

    function nativeStackToLines(ctx) {
        try {
            var frames = Thread.backtrace(ctx, BACKTRACER_MODE)
                .map(DebugSymbol.fromAddress);
            var out = [];
            for (var i = 0; i < Math.min(frames.length, MAX_DEPTH); i++) {
                var sym = frames[i];
                if (!_isNativeSkip(sym)) {
                    out.push("  \u21b3 " + sym.toString());
                }
            }
            return out;
        } catch (e) {
            return [];
        }
    }

    function logNativeStack(ctx, tag) {
        if (!STACK_ENABLED || !ctx) return;
        var lines = nativeStackToLines(ctx);
        if (lines.length === 0) return;
        console.log("  [native-stack" + (tag ? ":" + tag : "") + "]");
        lines.forEach(function (l) { console.log(l); });
    }

    // ── Combined ──────────────────────────────────────────────────────────────

    function stackToLines(ctx) {
        var java   = javaStackToLines();
        var native = ctx ? nativeStackToLines(ctx) : [];
        return java.concat(native);
    }

    function logStack(ctx, tag) {
        if (!STACK_ENABLED) return;
        // Dentro de Java.perform → usa Java stack
        // ctx disponível → adiciona native stack
        logJavaStack(tag);
        if (ctx) logNativeStack(ctx, tag);
    }

    // ── Expõe globalmente ─────────────────────────────────────────────────────
    var _g = (typeof globalThis !== "undefined") ? globalThis : this;
    _g.logJavaStack      = logJavaStack;
    _g.logNativeStack    = logNativeStack;
    _g.logStack          = logStack;
    _g.stackToLines      = stackToLines;
    _g.javaStackToLines  = javaStackToLines;

}).call(this);
