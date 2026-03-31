/**
 * URL Interceptor — NoxDroid
 * Intercepta URLs: java.net.URL, OkHttp, WebView, HttpURLConnection,
 * Apache HTTP, SSL_write.
 * Stack traces via stack.js (injetado pelo launcher).
 */

"use strict";

var SEP = "─".repeat(60);

function _tag(label, url) {
    console.log("\n" + SEP);
    console.log("[URL] " + label + ": " + url);
    if (typeof logJavaStack === "function") logJavaStack("url");
    send(JSON.stringify({ type: "url", label: label, url: url, ts: Date.now() }));
}

// ── java.net.URL ──────────────────────────────────────────────────────────────
Java.perform(function () {
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function (str) {
            _tag("java.net.URL", str);
            return this.$init(str);
        };
    } catch (e) {}

    // openConnection
    try {
        var URL2 = Java.use("java.net.URL");
        URL2.openConnection.implementation = function () {
            _tag("URL.openConnection", this.toString());
            return this.openConnection();
        };
    } catch (e) {}
});

// ── OkHttp ────────────────────────────────────────────────────────────────────
Java.perform(function () {
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.url.overload("java.lang.String").implementation = function (str) {
            _tag("OkHttp.url", str);
            return this.url(str);
        };
    } catch (e) {}
});

// ── WebView ───────────────────────────────────────────────────────────────────
Java.perform(function () {
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            _tag("WebView.loadUrl", url);
            return this.loadUrl(url);
        };
    } catch (e) {}
});

// ── Apache HTTP (legacy) ──────────────────────────────────────────────────────
Java.perform(function () {
    try {
        var HttpClient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
        HttpClient.execute.overload("org.apache.http.client.methods.HttpUriRequest")
            .implementation = function (req) {
                _tag("Apache.HTTP", req.getURI().toString());
                return this.execute(req);
            };
    } catch (e) {}
});

// ── SSL_write (nativo) ────────────────────────────────────────────────────────
try {
    var sslWrite = Module.findExportByName("libssl.so", "SSL_write");
    if (sslWrite) {
        Interceptor.attach(sslWrite, {
            onEnter: function (args) {
                try {
                    var data = Memory.readUtf8String(args[1], args[2].toInt32());
                    if (data && data.length > 0) {
                        console.log("\n" + SEP);
                        console.log("[URL] SSL_write (" + args[2].toInt32() + " bytes):");
                        console.log(data.substring(0, 512));
                        if (typeof logNativeStack === "function") logNativeStack(this.context, "ssl_write");
                        send(JSON.stringify({ type: "ssl_write", size: args[2].toInt32(), ts: Date.now() }));
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {}

console.log("═".repeat(60));
console.log("  NoxDroid — URL Interceptor");
console.log("  Hooks: java.net.URL, OkHttp, WebView, Apache, SSL_write");
console.log("═".repeat(60) + "\n");
