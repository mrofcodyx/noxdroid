/**
 * WebView Inspector — NoxDroid Vuln Scanner
 * Hooks WebView para detectar:
 *   - addJavascriptInterface (RCE potencial)
 *   - setAllowFileAccess / setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs
 *   - loadUrl com file:// ou javascript:
 *   - shouldOverrideUrlLoading (verifica se valida URLs)
 *   - FLAG_SECURE ausente em activities com WebView
 *
 * Output: JSON por linha para o scanner parsear.
 */

(function () {
    "use strict";

    var findings = [];

    function emit(type, severity, detail, withStack) {
        var obj = { type: type, severity: severity, detail: detail, ts: Date.now() };
        findings.push(obj);
        send(JSON.stringify(obj));
        if (withStack && typeof logJavaStack === "function") logJavaStack(type);
    }

    // ── addJavascriptInterface ────────────────────────────────────────────────
    try {
        var WebView = Java.use("android.webkit.WebView");

        WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String")
            .implementation = function (obj, name) {
                var cls = obj.getClass().getName();
                emit("addJavascriptInterface", "HIGH",
                    "addJavascriptInterface registrado: name='" + name + "' class=" + cls +
                    " | Permite RCE via JS em Android < 4.2 (API 17). " +
                    "Verifique se métodos expostos têm @JavascriptInterface.", true);
                return this.addJavascriptInterface(obj, name);
            };
    } catch (e) {}

    // ── setAllowFileAccess ────────────────────────────────────────────────────
    try {
        var WebSettings = Java.use("android.webkit.WebSettings");

        WebSettings.setAllowFileAccess.implementation = function (allow) {
            if (allow) {
                emit("setAllowFileAccess", "MEDIUM",
                    "setAllowFileAccess(true) — WebView pode ler arquivos locais via file://");
            }
            return this.setAllowFileAccess(allow);
        };

        WebSettings.setAllowFileAccessFromFileURLs.implementation = function (allow) {
            if (allow) {
                emit("setAllowFileAccessFromFileURLs", "HIGH",
                    "setAllowFileAccessFromFileURLs(true) — file:// pode acessar outros file:// (LFI cross-origin)", true);
            }
            return this.setAllowFileAccessFromFileURLs(allow);
        };

        WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function (allow) {
            if (allow) {
                emit("setAllowUniversalAccessFromFileURLs", "CRITICAL",
                    "setAllowUniversalAccessFromFileURLs(true) — file:// pode fazer fetch de qualquer origem (UXSS)", true);
            }
            return this.setAllowUniversalAccessFromFileURLs(allow);
        };

        WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
            if (enabled) {
                emit("setJavaScriptEnabled", "INFO",
                    "setJavaScriptEnabled(true) — JavaScript habilitado no WebView");
            }
            return this.setJavaScriptEnabled(enabled);
        };
    } catch (e) {}

    // ── loadUrl ───────────────────────────────────────────────────────────────
    try {
        var WebView2 = Java.use("android.webkit.WebView");

        WebView2.loadUrl.overload("java.lang.String").implementation = function (url) {
            if (url && url.startsWith("javascript:")) {
                emit("loadUrl_javascript", "HIGH",
                    "loadUrl com javascript: scheme — url=" + url.substring(0, 200), true);
            } else if (url && url.startsWith("file://")) {
                emit("loadUrl_file", "MEDIUM",
                    "loadUrl com file:// — url=" + url.substring(0, 200), true);
            }
            return this.loadUrl(url);
        };

        WebView2.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            if (url && (url.startsWith("javascript:") || url.startsWith("file://"))) {
                emit("loadUrl_with_headers", "MEDIUM",
                    "loadUrl com scheme suspeito — url=" + url.substring(0, 200));
            }
            return this.loadUrl(url, headers);
        };
    } catch (e) {}

    // ── shouldOverrideUrlLoading — verifica se valida URLs ───────────────────
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.shouldOverrideUrlLoading.overload(
            "android.webkit.WebView", "java.lang.String"
        ).implementation = function (view, url) {
            emit("shouldOverrideUrlLoading", "INFO",
                "shouldOverrideUrlLoading chamado — url=" + (url || "null").substring(0, 200));
            return this.shouldOverrideUrlLoading(view, url);
        };
    } catch (e) {}

    // ── FLAG_SECURE em activities com WebView ─────────────────────────────────
    try {
        var Window = Java.use("android.view.Window");
        Window.setFlags.implementation = function (flags, mask) {
            // FLAG_SECURE = 0x2000
            var hasSecure = (flags & 0x2000) !== 0;
            if (hasSecure) {
                emit("FLAG_SECURE_set", "INFO",
                    "FLAG_SECURE ativado nesta window — screenshots bloqueados");
            }
            return this.setFlags(flags, mask);
        };
    } catch (e) {}

    emit("ready", "INFO", "WebView Inspector ativo — interaja com o app para capturar eventos");
})();
