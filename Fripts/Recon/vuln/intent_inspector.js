/**
 * Intent Inspector — NoxDroid Vuln Scanner
 * Hooks para detectar o que o app FAZ com os extras recebidos via Intent:
 *   - getStringExtra / getIntExtra / getBooleanExtra
 *   - uso em WebView.loadUrl (XSS/LFI)
 *   - uso em Runtime.exec / ProcessBuilder (RCE)
 *   - uso em openFileInput / FileInputStream (LFI)
 *   - uso em SQLiteDatabase.rawQuery (SQLi)
 *   - uso em startActivity com dados do intent original (redirect)
 *
 * Diferente de só enviar o intent — aqui confirmamos se o valor chegou ao sink.
 */

(function () {
    "use strict";

    var trackedExtras = {};  // key → value rastreado

    function emit(type, severity, detail, withStack) {
        send(JSON.stringify({ type: type, severity: severity, detail: detail, ts: Date.now() }));
        if (withStack && typeof logJavaStack === "function") logJavaStack(type);
    }

    // ── Captura extras lidos pelo app ─────────────────────────────────────────
    try {
        var Intent = Java.use("android.content.Intent");

        Intent.getStringExtra.implementation = function (name) {
            var val = this.getStringExtra(name);
            if (val !== null) {
                trackedExtras[name] = val;
                emit("extra_read", "INFO",
                    "getStringExtra('" + name + "') = '" + val.substring(0, 100) + "'");
            }
            return val;
        };

        Intent.getIntExtra.overload("java.lang.String", "int").implementation = function (name, def) {
            var val = this.getIntExtra(name, def);
            trackedExtras[name] = String(val);
            emit("extra_read", "INFO", "getIntExtra('" + name + "') = " + val);
            return val;
        };

        Intent.getBooleanExtra.overload("java.lang.String", "boolean").implementation = function (name, def) {
            var val = this.getBooleanExtra(name, def);
            trackedExtras[name] = String(val);
            emit("extra_read", "INFO", "getBooleanExtra('" + name + "') = " + val);
            return val;
        };

        Intent.getDataString.implementation = function () {
            var val = this.getDataString();
            if (val !== null) {
                trackedExtras["__data__"] = val;
                emit("intent_data_read", "INFO", "getDataString() = '" + val.substring(0, 200) + "'");
            }
            return val;
        };
    } catch (e) {}

    // ── Sink: WebView.loadUrl ─────────────────────────────────────────────────
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            if (url) {
                for (var k in trackedExtras) {
                    if (url.indexOf(trackedExtras[k]) !== -1) {
                        var sev = url.startsWith("javascript:") ? "CRITICAL" :
                                  url.startsWith("file://") ? "HIGH" : "HIGH";
                        emit("sink_webview", sev,
                            "CONFIRMADO: extra '" + k + "' chegou ao WebView.loadUrl\n" +
                            "  valor: '" + trackedExtras[k].substring(0, 100) + "'\n" +
                            "  url: '" + url.substring(0, 200) + "'", true);
                    }
                }
            }
            return this.loadUrl(url);
        };
    } catch (e) {}

    // ── Sink: SQLiteDatabase.rawQuery ─────────────────────────────────────────
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;")
            .implementation = function (sql, args) {
                for (var k in trackedExtras) {
                    if (sql.indexOf(trackedExtras[k]) !== -1) {
                        emit("sink_sqli", "CRITICAL",
                            "CONFIRMADO: extra '" + k + "' chegou ao rawQuery sem sanitização\n" +
                            "  valor: '" + trackedExtras[k].substring(0, 100) + "'\n" +
                            "  sql: '" + sql.substring(0, 300) + "'", true);
                    }
                }
                return this.rawQuery(sql, args);
            };

        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
            for (var k in trackedExtras) {
                if (sql.indexOf(trackedExtras[k]) !== -1) {
                    emit("sink_sqli_exec", "CRITICAL",
                        "CONFIRMADO: extra '" + k + "' chegou ao execSQL\n" +
                        "  sql: '" + sql.substring(0, 300) + "'");
                }
            }
            return this.execSQL(sql);
        };
    } catch (e) {}

    // ── Sink: Runtime.exec (RCE) ──────────────────────────────────────────────
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            for (var k in trackedExtras) {
                if (cmd.indexOf(trackedExtras[k]) !== -1) {
                    emit("sink_rce", "CRITICAL",
                        "CONFIRMADO: extra '" + k + "' chegou ao Runtime.exec\n" +
                        "  cmd: '" + cmd.substring(0, 200) + "'", true);
                }
            }
            emit("runtime_exec", "HIGH", "Runtime.exec chamado: '" + cmd.substring(0, 200) + "'");
            return this.exec(cmd);
        };
    } catch (e) {}

    // ── Sink: FileInputStream / openFileInput (LFI) ───────────────────────────
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
            for (var k in trackedExtras) {
                if (path.indexOf(trackedExtras[k]) !== -1) {
                    emit("sink_lfi", "HIGH",
                        "CONFIRMADO: extra '" + k + "' chegou ao FileInputStream\n" +
                        "  path: '" + path.substring(0, 200) + "'");
                }
            }
            return this.$init(path);
        };
    } catch (e) {}

    // ── Sink: startActivity com dados do intent (Open Redirect) ──────────────
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
            var data = intent.getDataString ? intent.getDataString() : null;
            if (data) {
                for (var k in trackedExtras) {
                    if (data.indexOf(trackedExtras[k]) !== -1) {
                        emit("sink_redirect", "HIGH",
                            "CONFIRMADO: extra '" + k + "' usado em startActivity (Open Redirect)\n" +
                            "  data: '" + data.substring(0, 200) + "'");
                    }
                }
            }
            return this.startActivity(intent);
        };
    } catch (e) {}

    emit("ready", "INFO", "Intent Inspector ativo — envie intents com am start para capturar fluxo");
})();
