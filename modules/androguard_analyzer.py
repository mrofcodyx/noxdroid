"""
Androguard Analyzer — análise estática profunda de APKs via Androguard.
O usuário escolhe quais módulos executar (ou todos de uma vez).
"""
import os
import sys
import webbrowser
import html as _html_mod
import json as _json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_SEL_BG = "\033[30;46m"

RESULTS_DIR = Path("results")

# ── Permissões de alto risco ───────────────────────────────────────────────────
_DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_MMS",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.WRITE_SETTINGS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.INSTALL_PACKAGES", "android.permission.DELETE_PACKAGES",
    "android.permission.CHANGE_NETWORK_STATE", "android.permission.INTERNET",
    "android.permission.READ_LOGS", "android.permission.DUMP",
}

# ── APIs perigosas ─────────────────────────────────────────────────────────────
_DANGEROUS_APIS = [
    ("Ljava/lang/Runtime;",                    "exec",                    "Command Execution"),
    ("Ljava/lang/ProcessBuilder;",             "<init>",                  "Command Execution"),
    ("Ldalvik/system/DexClassLoader;",         "<init>",                  "Dynamic Code Loading"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>",                  "Dynamic Code Loading"),
    ("Ldalvik/system/PathClassLoader;",        "<init>",                  "Dynamic Code Loading"),
    ("Ljava/lang/reflect/Method;",             "invoke",                  "Reflection"),
    ("Ljava/lang/Class;",                      "forName",                 "Reflection"),
    ("Landroid/webkit/WebView;",               "addJavascriptInterface",  "WebView XSS"),
    ("Landroid/webkit/WebSettings;",           "setJavaScriptEnabled",    "WebView JS"),
    ("Landroid/webkit/WebSettings;",           "setAllowFileAccess",      "WebView File Access"),
    ("Landroid/webkit/WebSettings;",           "setAllowFileAccessFromFileURLs", "WebView LFI"),
    ("Landroid/webkit/WebSettings;",           "setAllowUniversalAccessFromFileURLs", "WebView UXSS"),
    ("Ljava/io/ObjectInputStream;",            "readObject",              "Insecure Deserialization"),
    ("Landroid/content/Context;",              "sendBroadcast",           "Broadcast"),
    ("Landroid/app/ActivityManager;",          "getRunningAppProcesses",  "Process Enumeration"),
    ("Ljava/net/URL;",                         "openConnection",          "Network"),
    ("Ljavax/net/ssl/SSLContext;",             "init",                    "SSL/TLS"),
    ("Ljavax/net/ssl/TrustManagerFactory;",    "init",                    "TrustManager"),
    ("Landroid/telephony/SmsManager;",         "sendTextMessage",         "SMS"),
    ("Landroid/location/LocationManager;",     "requestLocationUpdates",  "Location"),
    ("Landroid/hardware/Camera;",              "open",                    "Camera"),
    ("Landroid/media/MediaRecorder;",          "setAudioSource",          "Microphone"),
    ("Ljava/lang/System;",                     "loadLibrary",             "Native Library Load"),
    ("Landroid/content/ContentResolver;",      "query",                   "Content Provider Query"),
    ("Landroid/app/NotificationManager;",      "notify",                  "Notification"),
    ("Landroid/content/ClipboardManager;",     "setPrimaryClip",          "Clipboard Write"),
]

# ── Módulos disponíveis ────────────────────────────────────────────────────────
MODULES = [
    ("metadata",        "Metadados & Flags de Segurança",   "Package, versão, SDK, debuggable, backup, cleartext"),
    ("certificate",     "Certificado de Assinatura",        "Subject, issuer, validade, SHA-256"),
    ("permissions",     "Permissões",                       "Todas as permissões, marcando as perigosas"),
    ("components",      "Componentes & Intent Filters",     "Activities, services, receivers, providers + intent filters"),
    ("exported",        "Exported sem Permissão",           "Componentes exported sem proteção de permissão"),
    ("dangerous_apis",  "APIs Perigosas (xref)",            "Chamadas a APIs críticas com callers"),
    ("strings",         "Strings Suspeitas",                "URLs, chaves, tokens, senhas, URIs"),
    ("native_libs",     "Bibliotecas Nativas",              "Arquivos .so embutidos no APK"),
    ("embedded_files",  "Arquivos Embutidos Suspeitos",     "DEX em assets, JARs, arquivos ocultos"),
    ("obfuscation",     "Detecção de Ofuscação",            "Classes/métodos com nomes curtos (a/b/c)"),
    ("crypto_usage",    "Uso de Criptografia",              "Classes javax.crypto.* e java.security.* usadas"),
    ("network_config",  "Network Security Config",          "Analisa network_security_config.xml se presente"),
]


# ─── Menu de seleção de módulos ────────────────────────────────────────────────

def _clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def _pick_modules() -> list[str] | None:
    """Menu interativo para selecionar quais módulos executar."""
    import msvcrt
    selected = set(range(len(MODULES)))  # todos selecionados por padrão
    cursor   = 0

    while True:
        _clear()
        print(f"{_CYAN}{'═'*64}{_RESET}")
        print(f"{_CYAN}{_BOLD}  Androguard — Selecionar Módulos{_RESET}")
        print(f"{_CYAN}{'═'*64}{_RESET}")
        print(f"  {_DIM}↑↓=navegar  Espaço=toggle  A=todos  N=nenhum  Enter=executar  Esc=cancelar{_RESET}\n")

        for i, (key, name, desc) in enumerate(MODULES):
            check = f"{_GREEN}✔{_RESET}" if i in selected else f"{_DIM}○{_RESET}"
            if i == cursor:
                print(f"  {_SEL_BG} {check} {name:<38} {_RESET}  {_DIM}{desc}{_RESET}")
            else:
                print(f"  {check} {_WHITE}{name:<38}{_RESET}  {_DIM}{desc}{_RESET}")

        print(f"\n  {_DIM}{'─'*60}{_RESET}")
        print(f"  {_CYAN}{len(selected)}/{len(MODULES)} módulos selecionados{_RESET}")

        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            arrow = msvcrt.getch()
            if arrow == b"H":   cursor = max(0, cursor - 1)
            elif arrow == b"P": cursor = min(len(MODULES) - 1, cursor + 1)
        elif ch == b"\r":
            if not selected:
                continue
            return [MODULES[i][0] for i in sorted(selected)]
        elif ch == b"\x1b":
            return None
        elif ch == b" ":
            if cursor in selected: selected.discard(cursor)
            else: selected.add(cursor)
        elif ch in (b"a", b"A"):
            selected = set(range(len(MODULES)))
        elif ch in (b"n", b"N"):
            selected.clear()


# ─── Funções de análise individuais ───────────────────────────────────────────

def _mod_metadata(a, d, dx) -> dict:
    ns = "http://schemas.android.com/apk/res/android"
    flags = {}
    try:
        manifest = a.get_android_manifest_axml().get_xml()
        root = ET.fromstring(manifest)
        app = root.find("application")
        if app is not None:
            flags["debuggable"]        = app.get(f"{{{ns}}}debuggable", "false")
            flags["allowBackup"]       = app.get(f"{{{ns}}}allowBackup", "true")
            flags["usesCleartextTraffic"] = app.get(f"{{{ns}}}usesCleartextTraffic", "?")
            flags["networkSecurityConfig"] = app.get(f"{{{ns}}}networkSecurityConfig", None)
            flags["requestLegacyExternalStorage"] = app.get(f"{{{ns}}}requestLegacyExternalStorage", "false")
    except Exception:
        pass
    return {
        "package":       a.get_package(),
        "version_name":  a.get_androidversion_name() or "?",
        "version_code":  a.get_androidversion_code() or "?",
        "min_sdk":       a.get_min_sdk_version() or "?",
        "target_sdk":    a.get_target_sdk_version() or "?",
        "main_activity": a.get_main_activity() or "?",
        "libraries":     list(a.get_libraries() or []),
        "flags":         flags,
    }


def _mod_certificate(a, d, dx) -> dict:
    certs = []
    try:
        for cert in a.get_certificates():
            certs.append({
                "subject":    str(cert.subject.human_friendly),
                "issuer":     str(cert.issuer.human_friendly),
                "serial":     str(cert.serial_number),
                "not_before": str(cert.not_valid_before),
                "not_after":  str(cert.not_valid_after),
                "sha256":     cert.sha256_fingerprint.replace(":", "").lower(),
            })
    except Exception:
        pass
    return {"certificates": certs}


def _mod_permissions(a, d, dx) -> dict:
    perms = a.get_permissions() or []
    return {"permissions": [
        {"name": p, "dangerous": p in _DANGEROUS_PERMS}
        for p in sorted(perms)
    ]}


def _mod_components(a, d, dx) -> dict:
    ns = "http://schemas.android.com/apk/res/android"
    intent_filters: list[dict] = []
    try:
        manifest = a.get_android_manifest_axml().get_xml()
        root = ET.fromstring(manifest)
        for tag in ("activity", "service", "receiver", "provider"):
            for el in root.iter(tag):
                name = el.get(f"{{{ns}}}name", "")
                for ifilter in el.findall("intent-filter"):
                    actions    = [c.get(f"{{{ns}}}name", "") for c in ifilter.findall("action")]
                    categories = [c.get(f"{{{ns}}}name", "") for c in ifilter.findall("category")]
                    data_els   = []
                    for de in ifilter.findall("data"):
                        scheme = de.get(f"{{{ns}}}scheme", "")
                        host   = de.get(f"{{{ns}}}host", "")
                        path   = de.get(f"{{{ns}}}pathPrefix", "") or de.get(f"{{{ns}}}path", "")
                        if scheme or host:
                            data_els.append(f"{scheme}://{host}{path}".strip(":/"))
                    if actions:
                        intent_filters.append({
                            "component": name, "type": tag,
                            "actions": actions, "categories": categories,
                            "data": data_els,
                        })
    except Exception:
        pass
    return {
        "activities":     sorted(a.get_activities() or []),
        "services":       sorted(a.get_services() or []),
        "receivers":      sorted(a.get_receivers() or []),
        "providers":      sorted(a.get_providers() or []),
        "intent_filters": intent_filters,
    }


def _mod_exported(a, d, dx) -> dict:
    ns = "http://schemas.android.com/apk/res/android"
    exported = []
    try:
        manifest = a.get_android_manifest_axml().get_xml()
        root = ET.fromstring(manifest)
        for tag in ("activity", "service", "receiver", "provider"):
            for el in root.iter(tag):
                exp  = el.get(f"{{{ns}}}exported", "").lower()
                perm = el.get(f"{{{ns}}}permission", "")
                name = el.get(f"{{{ns}}}name", "")
                if exp == "true" and not perm:
                    exported.append({"type": tag, "name": name})
    except Exception:
        pass
    return {"exported_no_perm": exported}


def _mod_dangerous_apis(a, d, dx) -> dict:
    print(f"  {_YELLOW}→ Analisando xrefs de APIs perigosas...{_RESET}", flush=True)
    calls: list[dict] = []
    for cls_name, method_name, label in _DANGEROUS_APIS:
        try:
            for meth in dx.get_method_analysis_by_name(cls_name, method_name):
                callers = list(meth.get_xref_from())
                if callers:
                    calls.append({
                        "api":     f"{cls_name}->{method_name}",
                        "label":   label,
                        "callers": [str(c[1]) for c in callers[:15]],
                    })
        except Exception:
            pass
    return {"dangerous_apis": calls}


def _mod_strings(a, d, dx) -> dict:
    print(f"  {_YELLOW}→ Extraindo strings suspeitas...{_RESET}", flush=True)
    patterns = [
        (re.compile(r'https?://[^\s"\'<>]{8,}'),                    "URL"),
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                     "Google API Key"),
        (re.compile(r'-----BEGIN [A-Z ]+(?:PRIVATE KEY|CERTIFICATE)-----'), "Private Key/Cert"),
        (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*\S+', re.I), "Password"),
        (re.compile(r'(?:secret|token|api_?key)\s*[=:]\s*\S+', re.I), "Secret/Token"),
        (re.compile(r'mongodb(\+srv)?://[^\s"\']+'),                 "MongoDB URI"),
        (re.compile(r'jdbc:\w+://[^\s"\']+'),                        "JDBC URI"),
        (re.compile(r'(?:aws_?access_?key|AKIA)[A-Z0-9]{16,}'),     "AWS Key"),
        (re.compile(r'(?:firebase|firebaseio)\.com'),                "Firebase URL"),
        (re.compile(r'(?:Authorization|Bearer)\s+[A-Za-z0-9\-._~+/]+=*', re.I), "Auth Header"),
        (re.compile(r'[0-9a-f]{32,64}'),                             "Hash/Key (hex)"),
    ]
    found: list[dict] = []
    seen: set[str] = set()
    try:
        for dex in d:
            for s in dex.get_strings():
                val = str(s.get_value())
                if val in seen or len(val) < 8:
                    continue
                for pat, label in patterns:
                    if pat.search(val):
                        seen.add(val)
                        found.append({"value": val[:300], "type": label})
                        break
    except Exception:
        pass
    return {"suspicious_strings": found[:500]}


def _mod_native_libs(a, d, dx) -> dict:
    libs = []
    try:
        for fname, ftype in a.get_files_types().items():
            if fname.endswith(".so") or "lib/" in fname:
                libs.append({"name": fname, "type": ftype})
    except Exception:
        pass
    return {"native_libs": libs}


def _mod_embedded_files(a, d, dx) -> dict:
    suspicious_exts = {".dex", ".jar", ".apk", ".zip", ".enc", ".bin", ".db", ".sqlite"}
    suspicious_paths = ["assets/", "res/raw/"]
    files = []
    try:
        for fname, ftype in a.get_files_types().items():
            ext = Path(fname).suffix.lower()
            in_suspicious_path = any(fname.startswith(p) for p in suspicious_paths)
            if ext in suspicious_exts or (in_suspicious_path and ext not in (".png", ".jpg", ".xml", ".json")):
                files.append({"name": fname, "type": ftype})
    except Exception:
        pass
    return {"embedded_files": files}


def _mod_obfuscation(a, d, dx) -> dict:
    print(f"  {_YELLOW}→ Detectando ofuscação...{_RESET}", flush=True)
    short_pat = re.compile(r'^[a-z]{1,3}$')
    obf_classes: list[str] = []
    total = 0
    obf_count = 0
    try:
        for cls in dx.get_classes():
            name = cls.name.split("/")[-1].rstrip(";")
            total += 1
            if short_pat.match(name):
                obf_count += 1
                if len(obf_classes) < 50:
                    obf_classes.append(cls.name)
    except Exception:
        pass
    ratio = round(obf_count / total * 100, 1) if total > 0 else 0
    return {
        "obfuscation": {
            "total_classes": total,
            "obfuscated_count": obf_count,
            "ratio_pct": ratio,
            "likely_obfuscated": ratio > 30,
            "sample_classes": obf_classes,
        }
    }


def _mod_crypto_usage(a, d, dx) -> dict:
    print(f"  {_YELLOW}→ Mapeando uso de criptografia...{_RESET}", flush=True)
    crypto_prefixes = [
        "Ljavax/crypto/", "Ljava/security/", "Landroid/security/",
        "Lorg/bouncycastle/", "Lcom/google/crypto/",
    ]
    used: dict[str, list[str]] = {}
    try:
        for cls in dx.get_classes():
            name = cls.name
            for prefix in crypto_prefixes:
                if name.startswith(prefix):
                    short = name[len(prefix):].split("/")[0].rstrip(";")
                    callers_set: set[str] = set()
                    for meth in cls.get_methods():
                        for _, caller, _ in meth.get_xref_from():
                            callers_set.add(str(caller).split("->")[0])
                    if callers_set:
                        used[name] = list(callers_set)[:10]
                    break
    except Exception:
        pass
    return {"crypto_usage": [{"class": k, "used_by": v} for k, v in used.items()]}


def _mod_network_config(a, d, dx) -> dict:
    content = None
    try:
        raw = a.get_file("res/xml/network_security_config.xml")
        if raw:
            content = raw.decode("utf-8", errors="replace")
    except Exception:
        pass
    issues: list[str] = []
    if content:
        if "cleartextTrafficPermitted" in content and 'true' in content:
            issues.append("cleartextTrafficPermitted=true — tráfego HTTP permitido")
        if "<trust-anchors>" in content and "user" in content:
            issues.append("Ancora de confiança do usuário — certificados de usuário aceitos")
        if "<debug-overrides>" in content:
            issues.append("debug-overrides presente — configuração diferente em debug")
        if "<pin-set>" in content:
            issues.append("Certificate pinning configurado via network_security_config")
    return {"network_config": {"raw": content, "issues": issues}}


# ── Mapa de módulos ────────────────────────────────────────────────────────────
_MODULE_FN = {
    "metadata":       _mod_metadata,
    "certificate":    _mod_certificate,
    "permissions":    _mod_permissions,
    "components":     _mod_components,
    "exported":       _mod_exported,
    "dangerous_apis": _mod_dangerous_apis,
    "strings":        _mod_strings,
    "native_libs":    _mod_native_libs,
    "embedded_files": _mod_embedded_files,
    "obfuscation":    _mod_obfuscation,
    "crypto_usage":   _mod_crypto_usage,
    "network_config": _mod_network_config,
}


def _analyze(apk_path: str, modules: list[str]) -> dict:
    from androguard.misc import AnalyzeAPK
    print(f"  {_YELLOW}→ Carregando APK com Androguard...{_RESET}", flush=True)
    a, d, dx = AnalyzeAPK(apk_path)
    result: dict = {"_modules_run": modules}
    for mod in modules:
        fn = _MODULE_FN.get(mod)
        if fn:
            try:
                result.update(fn(a, d, dx))
            except Exception as e:
                result[f"_error_{mod}"] = str(e)
    return result


# ─── HTML ──────────────────────────────────────────────────────────────────────

def _h(s) -> str:
    return _html_mod.escape(str(s))


def _save_html(data: dict, out: Path, apk_path: str, ts: str):
    ran = set(data.get("_modules_run", []))

    # ── Metadados ──────────────────────────────────────────────────────────
    meta     = data
    pkg      = _h(meta.get("package", "?"))
    ver_name = _h(meta.get("version_name", "?"))
    ver_code = _h(meta.get("version_code", "?"))
    min_sdk  = _h(meta.get("min_sdk", "?"))
    tgt_sdk  = _h(meta.get("target_sdk", "?"))
    main_act = _h(meta.get("main_activity", "?"))
    flags    = meta.get("flags", {})
    libs     = meta.get("libraries", [])

    def _flag_badge(val, danger_val="true"):
        color = "sev-high" if str(val).lower() == danger_val else "sev-low"
        return f'<span class="badge {color}">{_h(val)}</span>'

    flags_html = ""
    if flags:
        for k, v in flags.items():
            if v is None: continue
            flags_html += f'<tr><td class="mono">{_h(k)}</td><td>{_flag_badge(v)}</td></tr>'

    libs_html = "".join(f'<tr><td class="mono">{_h(l)}</td></tr>' for l in libs)

    # ── Certificado ────────────────────────────────────────────────────────
    cert_html = ""
    for c in data.get("certificates", []):
        cert_html += f"""<div class="cert-card">
          <div class="cert-row"><span class="cert-lbl">Subject</span><span class="mono">{_h(c.get('subject','?'))}</span></div>
          <div class="cert-row"><span class="cert-lbl">Issuer</span><span class="mono">{_h(c.get('issuer','?'))}</span></div>
          <div class="cert-row"><span class="cert-lbl">Serial</span><span class="mono">{_h(c.get('serial','?'))}</span></div>
          <div class="cert-row"><span class="cert-lbl">Válido de</span><span class="mono">{_h(c.get('not_before','?'))}</span></div>
          <div class="cert-row"><span class="cert-lbl">Válido até</span><span class="mono">{_h(c.get('not_after','?'))}</span></div>
          <div class="cert-row"><span class="cert-lbl">SHA-256</span><span class="mono small">{_h(c.get('sha256','?'))}</span></div>
        </div>"""

    # ── Permissões ─────────────────────────────────────────────────────────
    perms = data.get("permissions", [])
    n_dp  = sum(1 for p in perms if p["dangerous"])
    perm_rows = "".join(
        f'<tr><td><span class="badge {"sev-high" if p["dangerous"] else "sev-low"}">'
        f'{"PERIGOSA" if p["dangerous"] else "normal"}</span></td>'
        f'<td class="mono">{_h(p["name"])}</td></tr>'
        for p in perms
    )

    # ── Componentes ────────────────────────────────────────────────────────
    activities = data.get("activities", [])
    services   = data.get("services", [])
    receivers  = data.get("receivers", [])
    providers  = data.get("providers", [])
    comp_rows  = ""
    for tag, items in [("activity", activities), ("service", services),
                       ("receiver", receivers), ("provider", providers)]:
        for i in items:
            comp_rows += f'<tr><td class="tag-badge">{tag}</td><td class="mono">{_h(i)}</td></tr>'

    # ── Intent Filters ─────────────────────────────────────────────────────
    ifilters = data.get("intent_filters", [])
    ifilter_rows = ""
    for f in ifilters:
        actions = ", ".join(_h(a) for a in f["actions"])
        data_s  = ", ".join(_h(d) for d in f["data"]) if f["data"] else ""
        ifilter_rows += (
            f'<tr><td class="tag-badge">{_h(f["type"])}</td>'
            f'<td class="mono">{_h(f["component"])}</td>'
            f'<td class="mono small">{actions}</td>'
            f'<td class="mono small">{data_s}</td></tr>'
        )

    # ── Exported ───────────────────────────────────────────────────────────
    exported  = data.get("exported_no_perm", [])
    n_exp     = len(exported)
    exp_rows  = "".join(
        f'<tr><td><span class="badge sev-high">{_h(e["type"])}</span></td>'
        f'<td class="mono">{_h(e["name"])}</td></tr>'
        for e in exported
    )

    # ── APIs perigosas ─────────────────────────────────────────────────────
    apis   = data.get("dangerous_apis", [])
    n_apis = len(apis)
    api_rows = ""
    for a in apis:
        callers_html = "<br>".join(_h(c) for c in a["callers"])
        api_rows += (
            f'<tr><td class="cat-name">{_h(a["label"])}</td>'
            f'<td class="mono">{_h(a["api"])}</td>'
            f'<td class="mono small">{callers_html}</td></tr>'
        )

    # ── Strings ────────────────────────────────────────────────────────────
    strings  = data.get("suspicious_strings", [])
    n_str    = len(strings)
    str_rows = "".join(
        f'<tr><td><span class="badge sev-med">{_h(s["type"])}</span></td>'
        f'<td class="mono">{_h(s["value"])}</td></tr>'
        for s in strings
    )

    # ── Native libs ────────────────────────────────────────────────────────
    native_libs = data.get("native_libs", [])
    native_rows = "".join(
        f'<tr><td class="mono">{_h(l["name"])}</td><td class="mono small">{_h(l["type"])}</td></tr>'
        for l in native_libs
    )

    # ── Embedded files ─────────────────────────────────────────────────────
    emb_files = data.get("embedded_files", [])
    emb_rows  = "".join(
        f'<tr><td class="mono">{_h(f["name"])}</td><td class="mono small">{_h(f["type"])}</td></tr>'
        for f in emb_files
    )

    # ── Ofuscação ──────────────────────────────────────────────────────────
    obf = data.get("obfuscation", {})
    obf_html = ""
    if obf:
        color = "sev-high" if obf.get("likely_obfuscated") else "sev-low"
        obf_html = f"""
        <div class="cert-card">
          <div class="cert-row"><span class="cert-lbl">Total de classes</span><span class="mono">{obf.get('total_classes',0)}</span></div>
          <div class="cert-row"><span class="cert-lbl">Classes ofuscadas</span><span class="mono">{obf.get('obfuscated_count',0)}</span></div>
          <div class="cert-row"><span class="cert-lbl">Ratio</span><span class="mono"><span class="badge {color}">{obf.get('ratio_pct',0)}%</span></span></div>
          <div class="cert-row"><span class="cert-lbl">Provável ofuscação</span><span class="mono"><span class="badge {color}">{'SIM' if obf.get('likely_obfuscated') else 'NÃO'}</span></span></div>
        </div>
        <div class="section-title" style="margin-top:14px">Amostra de classes ofuscadas</div>
        <table><tbody>{"".join(f'<tr><td class="mono">{_h(c)}</td></tr>' for c in obf.get("sample_classes",[]))}</tbody></table>
        """

    # ── Crypto usage ───────────────────────────────────────────────────────
    crypto = data.get("crypto_usage", [])
    crypto_rows = ""
    for c in crypto:
        used_by = "<br>".join(_h(u) for u in c["used_by"])
        crypto_rows += f'<tr><td class="mono">{_h(c["class"])}</td><td class="mono small">{used_by}</td></tr>'

    # ── Network config ─────────────────────────────────────────────────────
    nc = data.get("network_config", {})
    nc_issues = nc.get("issues", [])
    nc_raw    = nc.get("raw", "")
    nc_html   = ""
    if nc_issues:
        nc_html += "<div class='section-title'>Problemas detectados</div><ul style='padding-left:20px;margin-bottom:14px'>"
        for issue in nc_issues:
            nc_html += f'<li class="mono" style="color:var(--orange);padding:3px 0">{_h(issue)}</li>'
        nc_html += "</ul>"
    if nc_raw:
        nc_html += f'<div class="section-title">Conteúdo</div><pre class="mono small" style="background:var(--card);padding:12px;border-radius:6px;overflow:auto;max-height:400px">{_h(nc_raw)}</pre>'
    if not nc_html:
        nc_html = '<div class="empty">network_security_config.xml não encontrado ou não analisado.</div>'

    # ── Tabs dinâmicas (só mostra as que foram executadas) ─────────────────
    tabs_def = [
        ("metadata",       f"Metadados",                    "metadata"),
        ("certificate",    f"Certificado",                  "cert"),
        ("permissions",    f"Permissões ({len(perms)})",    "perms"),
        ("components",     f"Componentes ({len(activities)+len(services)+len(receivers)+len(providers)})", "components"),
        ("components",     f"Intent Filters ({len(ifilters)})", "ifilters"),
        ("exported",       f"Exported s/ Perm ({n_exp})",   "exported"),
        ("dangerous_apis", f"APIs Perigosas ({n_apis})",    "apis"),
        ("strings",        f"Strings ({n_str})",            "strings"),
        ("native_libs",    f"Libs Nativas ({len(native_libs)})", "native"),
        ("embedded_files", f"Arquivos Embutidos ({len(emb_files)})", "embedded"),
        ("obfuscation",    f"Ofuscação",                    "obfuscation"),
        ("crypto_usage",   f"Crypto ({len(crypto)})",       "crypto"),
        ("network_config", f"Network Config",               "netconfig"),
    ]
    active_tabs = [(label, tab_id) for mod_key, label, tab_id in tabs_def if mod_key in ran]

    tab_bar = ""
    for i, (label, tab_id) in enumerate(active_tabs):
        cls = "active" if i == 0 else ""
        tab_bar += f'<div class="tab {cls}" onclick="showTab(\'{tab_id}\')">{label}</div>'

    def _tab(tab_id, content, first=False):
        cls = "tab-content active" if first else "tab-content"
        return f'<div id="tab-{tab_id}" class="{cls} section">{content}</div>'

    first_tab = active_tabs[0][1] if active_tabs else "metadata"

    tab_contents = ""
    for i, (label, tab_id) in enumerate(active_tabs):
        first = (i == 0)
        if tab_id == "metadata":
            content = f"""
            <table><thead><tr><th>Flag</th><th>Valor</th></tr></thead>
            <tbody>{flags_html if flags_html else '<tr><td colspan="2" class="empty">Não analisado.</td></tr>'}</tbody></table>
            {'<div class="section-title" style="margin-top:16px">Bibliotecas compartilhadas</div><table><tbody>' + libs_html + '</tbody></table>' if libs_html else ''}
            """
        elif tab_id == "cert":
            content = cert_html or '<div class="empty">Certificado não disponível.</div>'
        elif tab_id == "perms":
            content = f'<table><thead><tr><th style="width:120px">Tipo</th><th>Permissão</th></tr></thead><tbody>{perm_rows or "<tr><td colspan=2 class=empty>Nenhuma.</td></tr>"}</tbody></table>'
        elif tab_id == "components":
            content = f'<table><thead><tr><th style="width:100px">Tipo</th><th>Nome</th></tr></thead><tbody>{comp_rows or "<tr><td colspan=2 class=empty>Nenhum.</td></tr>"}</tbody></table>'
        elif tab_id == "ifilters":
            content = f'<table><thead><tr><th>Tipo</th><th>Componente</th><th>Actions</th><th>Data/Scheme</th></tr></thead><tbody>{ifilter_rows or "<tr><td colspan=4 class=empty>Nenhum intent filter.</td></tr>"}</tbody></table>'
        elif tab_id == "exported":
            content = f'<table><thead><tr><th style="width:100px">Tipo</th><th>Componente</th></tr></thead><tbody>{exp_rows or "<tr><td colspan=2 class=empty>Nenhum.</td></tr>"}</tbody></table>'
        elif tab_id == "apis":
            content = f'<table><thead><tr><th style="width:180px">Categoria</th><th>API</th><th>Chamado por</th></tr></thead><tbody>{api_rows or "<tr><td colspan=3 class=empty>Nenhuma.</td></tr>"}</tbody></table>'
        elif tab_id == "strings":
            content = f'<table><thead><tr><th style="width:140px">Tipo</th><th>Valor</th></tr></thead><tbody>{str_rows or "<tr><td colspan=2 class=empty>Nenhuma.</td></tr>"}</tbody></table>'
        elif tab_id == "native":
            content = f'<table><thead><tr><th>Arquivo</th><th>Tipo</th></tr></thead><tbody>{native_rows or "<tr><td colspan=2 class=empty>Nenhuma lib nativa.</td></tr>"}</tbody></table>'
        elif tab_id == "embedded":
            content = f'<table><thead><tr><th>Arquivo</th><th>Tipo</th></tr></thead><tbody>{emb_rows or "<tr><td colspan=2 class=empty>Nenhum arquivo suspeito.</td></tr>"}</tbody></table>'
        elif tab_id == "obfuscation":
            content = obf_html or '<div class="empty">Não analisado.</div>'
        elif tab_id == "crypto":
            content = f'<table><thead><tr><th>Classe</th><th>Usado por</th></tr></thead><tbody>{crypto_rows or "<tr><td colspan=2 class=empty>Nenhum uso detectado.</td></tr>"}</tbody></table>'
        elif tab_id == "netconfig":
            content = nc_html
        else:
            content = '<div class="empty">—</div>'
        tab_contents += _tab(tab_id, content, first)

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NoxDroid — Androguard — {pkg}</title>
<style>
  :root{{--bg:#0d0f14;--surface:#13161e;--card:#1a1e2a;--border:#252a38;--cyan:#00e5ff;--cyan2:#00b8d4;--yellow:#ffd740;--red:#ff5252;--orange:#ff9800;--green:#69ff47;--dim:#5a6070;--text:#cdd6f4;--text2:#8892a4}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}}
  header{{background:var(--surface);border-bottom:1px solid var(--border);padding:18px 32px}}
  .logo{{font-size:22px;font-weight:700;color:var(--cyan);letter-spacing:2px}}
  .logo span{{color:var(--text2);font-weight:400;font-size:13px;margin-left:8px}}
  .subtitle{{color:var(--text2);font-size:12px;margin-top:2px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;padding:20px 32px}}
  .meta-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px}}
  .meta-card .lbl{{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px}}
  .meta-card .val{{font-size:14px;color:var(--cyan);font-weight:600;margin-top:4px;word-break:break-all}}
  .stats{{display:flex;gap:14px;padding:0 32px 20px;flex-wrap:wrap}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 22px;min-width:130px}}
  .stat-card .val{{font-size:28px;font-weight:700}}
  .stat-card .lbl{{font-size:11px;color:var(--text2);margin-top:2px;text-transform:uppercase;letter-spacing:1px}}
  .stat-card.danger .val{{color:var(--red)}}
  .stat-card.warn .val{{color:var(--orange)}}
  .stat-card.info .val{{color:var(--cyan)}}
  .section{{padding:0 32px 32px}}
  .section-title{{font-size:13px;font-weight:700;color:var(--cyan2);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border)}}
  table{{width:100%;border-collapse:collapse;margin-bottom:8px}}
  thead th{{background:var(--surface);color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid var(--border);text-align:left}}
  tbody tr{{border-bottom:1px solid var(--border);transition:background .1s}}
  tbody tr:hover{{background:var(--card)}}
  tbody td{{padding:8px 12px;vertical-align:top}}
  .badge{{display:inline-block;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:.5px}}
  .sev-high{{background:#ff525222;color:var(--red);border:1px solid #ff525244}}
  .sev-med{{background:#ff980022;color:var(--orange);border:1px solid #ff980044}}
  .sev-low{{background:#ffffff11;color:var(--text2);border:1px solid var(--border)}}
  .tag-badge{{color:var(--cyan2);font-size:11px;font-weight:600;white-space:nowrap}}
  .cat-name{{color:var(--cyan2);font-weight:500;white-space:nowrap}}
  .mono{{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;word-break:break-all;color:var(--text)}}
  .small{{font-size:11px;color:var(--text2)}}
  .cert-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 18px;margin-bottom:10px}}
  .cert-row{{display:flex;gap:12px;padding:4px 0;border-bottom:1px solid var(--border)}}
  .cert-row:last-child{{border-bottom:none}}
  .cert-lbl{{min-width:90px;font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;flex-shrink:0}}
  .empty{{color:var(--dim);font-size:13px;padding:12px 0}}
  footer{{text-align:center;padding:20px;color:var(--dim);font-size:11px;border-top:1px solid var(--border)}}
  .tab-bar{{display:flex;gap:4px;padding:0 32px;margin-bottom:0;border-bottom:1px solid var(--border);flex-wrap:wrap}}
  .tab{{padding:10px 16px;cursor:pointer;font-size:12px;color:var(--text2);border-bottom:2px solid transparent;transition:color .15s,border-color .15s;white-space:nowrap}}
  .tab:hover{{color:var(--text)}}
  .tab.active{{color:var(--cyan);border-bottom-color:var(--cyan)}}
  .tab-content{{display:none;padding-top:20px}}
  .tab-content.active{{display:block}}
</style>
</head>
<body>
<header>
  <div class="logo">NoxDroid <span>Androguard</span></div>
  <div class="subtitle">APK: {_h(apk_path)} &nbsp;·&nbsp; {_h(ts)}</div>
</header>

<div class="meta-grid">
  <div class="meta-card"><div class="lbl">Package</div><div class="val">{pkg}</div></div>
  <div class="meta-card"><div class="lbl">Versão</div><div class="val">{ver_name} ({ver_code})</div></div>
  <div class="meta-card"><div class="lbl">Min SDK</div><div class="val">{min_sdk}</div></div>
  <div class="meta-card"><div class="lbl">Target SDK</div><div class="val">{tgt_sdk}</div></div>
  <div class="meta-card"><div class="lbl">Main Activity</div><div class="val">{main_act}</div></div>
</div>

<div class="stats">
  <div class="stat-card danger"><div class="val">{n_dp}</div><div class="lbl">Perms Perigosas</div></div>
  <div class="stat-card danger"><div class="val">{n_exp}</div><div class="lbl">Exported s/ Perm</div></div>
  <div class="stat-card warn"><div class="val">{n_apis}</div><div class="lbl">APIs Perigosas</div></div>
  <div class="stat-card info"><div class="val">{n_str}</div><div class="lbl">Strings Suspeitas</div></div>
</div>

<div class="tab-bar">{tab_bar}</div>
{tab_contents}

<footer>NoxDroid · Androguard · {_h(ts)}</footer>
<script>
function showTab(name){{
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  event.target.classList.add('active');
}}
</script>
</body>
</html>"""
    out.write_text(html, encoding="utf-8")


# ─── Runner ────────────────────────────────────────────────────────────────────

def run_androguard(apk_path: str):
    _clear()
    print(f"{_CYAN}{'═'*64}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Androguard — Análise Estática Profunda{_RESET}")
    print(f"{_CYAN}{'═'*64}{_RESET}\n")

    apk = Path(apk_path)
    if not apk.exists():
        print(f"  {_RED}✖ Arquivo não encontrado: {apk_path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    print(f"  {_DIM}APK: {apk_path}{_RESET}\n")

    # Seleção de módulos
    modules = _pick_modules()
    if not modules:
        return

    _clear()
    print(f"{_CYAN}{'═'*64}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Androguard — Executando {len(modules)} módulo(s){_RESET}")
    print(f"{_CYAN}{'═'*64}{_RESET}\n")
    print(f"  {_DIM}APK: {apk_path}{_RESET}")
    print(f"  {_DIM}Módulos: {', '.join(modules)}{_RESET}\n")

    try:
        data = _analyze(apk_path, modules)
    except ImportError:
        print(f"  {_RED}✖ Androguard não está instalado.{_RESET}")
        input(f"\n  → Enter para continuar...")
        return
    except Exception as e:
        print(f"  {_RED}✖ Erro na análise: {e}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    # Resumo terminal
    if "metadata" in modules:
        print(f"  {_GREEN}✔ Package    : {data.get('package','?')}{_RESET}")
        print(f"  {_GREEN}✔ Versão     : {data.get('version_name','?')} ({data.get('version_code','?')}){_RESET}")
        print(f"  {_GREEN}✔ Target SDK : {data.get('target_sdk','?')}{_RESET}")

    if "permissions" in modules:
        n_dp = sum(1 for p in data.get("permissions", []) if p["dangerous"])
        print(f"  {_YELLOW}→ Perms perigosas    : {n_dp}{_RESET}")

    if "exported" in modules:
        print(f"  {_YELLOW}→ Exported s/ perm   : {len(data.get('exported_no_perm', []))}{_RESET}")

    if "dangerous_apis" in modules:
        print(f"  {_YELLOW}→ APIs perigosas     : {len(data.get('dangerous_apis', []))}{_RESET}")

    if "strings" in modules:
        print(f"  {_YELLOW}→ Strings suspeitas  : {len(data.get('suspicious_strings', []))}{_RESET}")

    if "obfuscation" in modules:
        obf = data.get("obfuscation", {})
        flag = f"{_RED}SIM{_RESET}" if obf.get("likely_obfuscated") else f"{_GREEN}NÃO{_RESET}"
        print(f"  {_YELLOW}→ Ofuscação detectada: {flag}")

    if "native_libs" in modules:
        print(f"  {_YELLOW}→ Libs nativas       : {len(data.get('native_libs', []))}{_RESET}")

    if "network_config" in modules:
        nc_issues = data.get("network_config", {}).get("issues", [])
        if nc_issues:
            print(f"  {_RED}→ Network config issues: {len(nc_issues)}{_RESET}")

    # Salva HTML
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    pkg = data.get("package") or apk.stem
    parts = apk.parts
    for i, part in enumerate(parts):
        if part == "results" and i + 1 < len(parts):
            pkg = parts[i + 1]
            break

    from core.report_paths import static_dir
    out_dir = static_dir(pkg)
    out_html = out_dir / "androguard.html"

    _save_html(data, out_html, apk_path, ts)
    print(f"\n  {_GREEN}✔ Relatório salvo em: {out_html}{_RESET}")

    if input(f"\n  Abrir no navegador? [S/n]: ").strip().lower() != "n":
        webbrowser.open(out_html.resolve().as_uri())

    input(f"\n  → Enter para continuar...")
