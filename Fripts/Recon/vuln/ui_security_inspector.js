/**
 * UI Security Inspector — NoxDroid Vuln Scanner
 * Detecta em runtime:
 *   - FLAG_SECURE ausente em activities sensíveis (Tapjacking / Screenshot)
 *   - setFilterTouchesWhenObscured ausente em views críticas
 *   - Clipboard com dados sensíveis (ClipboardManager.setPrimaryClip)
 *   - Activities com overlay permitido (não usa FLAG_SECURE)
 */

(function () {
    "use strict";

    var secureActivities = {};    // activityName → true/false
    var sensitiveViews   = {};    // viewClass → filterTouches

    function emit(type, severity, detail) {
        send(JSON.stringify({ type: type, severity: severity, detail: detail, ts: Date.now() }));
    }

    function currentActivity() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var app = ActivityThread.currentApplication();
            if (!app) return "unknown";
            // Tenta pegar a activity em foreground via reflection
            return "unknown";
        } catch (e) { return "unknown"; }
    }

    // ── FLAG_SECURE ───────────────────────────────────────────────────────────
    try {
        var Window = Java.use("android.view.Window");

        Window.setFlags.implementation = function (flags, mask) {
            var FLAG_SECURE = 0x2000;
            var hasSecure = (flags & FLAG_SECURE) !== 0;
            // Tenta obter o nome da activity via context
            var actName = "unknown";
            try {
                var ctx = this.getContext();
                if (ctx) actName = ctx.getClass().getName();
            } catch (e) {}

            if (hasSecure) {
                secureActivities[actName] = true;
                emit("flag_secure_set", "INFO",
                    "FLAG_SECURE ATIVO em: " + actName);
            } else if ((mask & FLAG_SECURE) !== 0) {
                // Mask inclui FLAG_SECURE mas flags não — está sendo removido
                secureActivities[actName] = false;
                emit("flag_secure_removed", "HIGH",
                    "FLAG_SECURE REMOVIDO em: " + actName +
                    " — screenshots e gravação de tela permitidos");
            }
            return this.setFlags(flags, mask);
        };

        // addFlags também pode setar FLAG_SECURE
        Window.addFlags.implementation = function (flags) {
            var FLAG_SECURE = 0x2000;
            if ((flags & FLAG_SECURE) !== 0) {
                emit("flag_secure_added", "INFO", "FLAG_SECURE adicionado via addFlags");
            }
            return this.addFlags(flags);
        };
    } catch (e) {}

    // ── Activity.onCreate — detecta activities sem FLAG_SECURE ────────────────
    try {
        var Activity = Java.use("android.app.Activity");
        var SENSITIVE_KW = ["login", "password", "payment", "transfer", "pin",
                            "otp", "wallet", "checkout", "credit", "auth", "confirm"];

        Activity.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
            var name = this.getClass().getName().toLowerCase();
            var isSensitive = SENSITIVE_KW.some(function (kw) { return name.indexOf(kw) !== -1; });

            this.onCreate(bundle);

            // Verifica após onCreate se FLAG_SECURE foi setado
            Java.scheduleOnMainThread(function () {
                try {
                    var win = this.getWindow ? this.getWindow() : null;
                    if (!win) return;
                    var attrs = win.getAttributes();
                    var FLAG_SECURE = 0x2000;
                    var hasSecure = (attrs.flags.value & FLAG_SECURE) !== 0;

                    if (isSensitive && !hasSecure) {
                        emit("missing_flag_secure", "HIGH",
                            "Activity sensível SEM FLAG_SECURE: " + this.getClass().getName() +
                            "\n  Vulnerável a screenshots, gravação de tela e Tapjacking");
                    }
                } catch (e2) {}
            }.bind(this));
        };
    } catch (e) {}

    // ── setFilterTouchesWhenObscured ──────────────────────────────────────────
    try {
        var View = Java.use("android.view.View");
        View.setFilterTouchesWhenObscured.implementation = function (enabled) {
            var cls = this.getClass().getName();
            if (enabled) {
                emit("filter_touches_enabled", "INFO",
                    "setFilterTouchesWhenObscured(true) em: " + cls + " — proteção contra Tapjacking ativa");
            }
            return this.setFilterTouchesWhenObscured(enabled);
        };
    } catch (e) {}

    // ── Clipboard — dados sensíveis ───────────────────────────────────────────
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        var ClipData = Java.use("android.content.ClipData");

        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            try {
                var item = clip.getItemAt(0);
                var text = item.getText();
                if (text !== null) {
                    var str = text.toString();
                    var SENSITIVE = ["password", "token", "secret", "key", "auth",
                                     "eyJ", "AKIA", "sk-", "ghp_"];
                    var isSensitive = SENSITIVE.some(function (kw) {
                        return str.toLowerCase().indexOf(kw.toLowerCase()) !== -1;
                    });
                    if (isSensitive) {
                        emit("clipboard_sensitive", "HIGH",
                            "Dado sensível copiado para Clipboard: '" +
                            str.substring(0, 80) + (str.length > 80 ? "..." : "") + "'");
                    } else {
                        emit("clipboard_write", "INFO",
                            "Clipboard.setPrimaryClip: '" +
                            str.substring(0, 80) + (str.length > 80 ? "..." : "") + "'");
                    }
                }
            } catch (e2) {}
            return this.setPrimaryClip(clip);
        };
    } catch (e) {}

    // ── WindowManager.LayoutParams — detecta overlay TYPE_APPLICATION_OVERLAY ─
    try {
        var LayoutParams = Java.use("android.view.WindowManager$LayoutParams");
        LayoutParams.$init.overload("int", "int", "int", "int", "int").implementation =
            function (w, h, type, flags, format) {
                // TYPE_APPLICATION_OVERLAY = 2038, TYPE_SYSTEM_ALERT = 2003
                if (type === 2038 || type === 2003) {
                    emit("overlay_window", "MEDIUM",
                        "App cria janela overlay (type=" + type + ") — pode ser usado para Tapjacking");
                }
                return this.$init(w, h, type, flags, format);
            };
    } catch (e) {}

    emit("ready", "INFO", "UI Security Inspector ativo — navegue pelo app para capturar eventos");
})();
