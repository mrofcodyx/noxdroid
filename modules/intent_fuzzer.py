# -*- coding: utf-8 -*-
"""
intent_fuzzer.py -- Intent Fuzzer interativo estilo Drozer
"""
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from core.env_check import _adb_exe
from core.adb_guard import require_device

# --- Cores -------------------------------------------------------------------
_R  = "\033[0m"
_B  = "\033[1m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_M  = "\033[95m"
_BL = "\033[94m"
_D  = "\033[90m"
_W  = "\033[97m"

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_W_TOTAL   = 70

# --- Payloads ----------------------------------------------------------------
# (categoria, badge, flag, key, value)
_PAYLOADS = [
    ("XSS / WebView",  "XSS",      "--es", "url",      "javascript:alert(1)"),
    ("XSS / WebView",  "XSS",      "--es", "uri",      "javascript:alert(1)"),
    ("LFI",            "LFI",      "--es", "file",     "../../../../etc/passwd"),
    ("LFI",            "LFI",      "--es", "load",     "file:///data/data/__PKG__/databases/"),
    ("LFI",            "LFI",      "--es", "path",     "../../../../etc/passwd"),
    ("Open Redirect",  "REDIRECT", "--es", "redirect", "http://evil.attacker.com"),
    ("Open Redirect",  "REDIRECT", "--es", "next",     "http://evil.attacker.com"),
    ("SQL Injection",  "SQLi",     "--es", "id",       "1' OR '1'='1"),
    ("SQL Injection",  "SQLi",     "--es", "query",    "' UNION SELECT * FROM sqlite_master--"),
    ("SQL Injection",  "SQLi",     "--es", "search",   "' OR 1=1--"),
    ("IDOR",           "IDOR",     "--ez", "admin",    "true"),
    ("IDOR",           "IDOR",     "--ez", "is_root",  "true"),
    ("IDOR",           "IDOR",     "--ei", "user_id",  "-1"),
    ("IDOR",           "IDOR",     "--ei", "role",     "0"),
    ("Custom",         "CUSTOM",   None,   None,       None),
]

_BADGE_COLOR = {
    "XSS":      _RE,
    "LFI":      _M,
    "REDIRECT": _Y,
    "SQLi":     _RE,
    "IDOR":     _Y,
    "CUSTOM":   _C,
}

_KIND_COLOR = {
    "Activity": _C,
    "Service":  _Y,
    "Receiver": _M,
    "Deeplink": _BL,
}


# --- Helpers visuais ---------------------------------------------------------

def _cls():
    import os
    os.system("cls" if os.name == "nt" else "clear")


def _sep(color: str = _D) -> str:
    return f"  {color}{'─' * _W_TOTAL}{_R}"


def _header(title: str, subtitle: str = ""):
    _cls()
    print(f"\n  {_C}{_B}{'─' * _W_TOTAL}{_R}")
    print(f"  {_C}{_B}  >> {title}{_R}")
    if subtitle:
        print(f"  {_D}     {subtitle}{_R}")
    print(f"  {_C}{'─' * _W_TOTAL}{_R}\n")


def _badge(text: str, color: str) -> str:
    return f"{color}{_B}[{text:<8}]{_R}"


def _box(label: str, color: str, lines: list):
    bar = "─" * (_W_TOTAL - len(label) - 5)
    print(f"\n  {color}{_B}+-- {label} {bar}+{_R}")
    for line in lines:
        trunc = str(line)[:_W_TOTAL - 4]
        print(f"  {color}|{_R}  {_W}{trunc}{_R}")
    print(f"  {color}+{'─' * (_W_TOTAL - 1)}+{_R}")


# --- ADB ---------------------------------------------------------------------

def _adb(args: list, timeout: int = 12) -> str:
    try:
        r = subprocess.run([_adb_exe()] + args,
                           capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return str(e)


# --- Parsing -----------------------------------------------------------------

def _attr(elem, name: str) -> str:
    return elem.get(f"{{{ANDROID_NS}}}{name}", "")


def _parse_exported(apk_folder: Path, pkg: str) -> list:
    manifest = apk_folder / "AndroidManifest.xml"
    if not manifest.exists():
        return []
    try:
        root = ET.parse(str(manifest)).getroot()
    except Exception:
        return []

    app = root.find("application")
    if app is None:
        return []

    components = []
    for tag, kind in (("activity", "Activity"), ("service", "Service"), ("receiver", "Receiver")):
        for comp in app.findall(tag):
            name       = _attr(comp, "name")
            exported   = _attr(comp, "exported")
            perm       = _attr(comp, "permission")
            has_filter = comp.find("intent-filter") is not None
            is_exp     = exported.lower() == "true" or (
                has_filter and exported.lower() != "false"
            )
            if not is_exp or perm:
                continue
            full = name if name.startswith(pkg) else f"{pkg}{name}"
            components.append({
                "kind":  kind,
                "name":  full,
                "short": name.split(".")[-1],
            })
            for ifilter in comp.findall("intent-filter"):
                has_view = any(_attr(a, "name") == "android.intent.action.VIEW"
                               for a in ifilter.findall("action"))
                has_browsable = any(_attr(c, "name") == "android.intent.category.BROWSABLE"
                                    for c in ifilter.findall("category"))
                if has_view and has_browsable:
                    for data in ifilter.findall("data"):
                        scheme = _attr(data, "scheme")
                        host   = _attr(data, "host")
                        if scheme:
                            components.append({
                                "kind":   "Deeplink",
                                "name":   full,
                                "short":  f"{scheme}://{host or '*'}",
                                "scheme": scheme,
                                "host":   host,
                            })
    return components


def _get_components_via_dumpsys(pkg: str) -> list:
    out  = _adb(["shell", "dumpsys", "package", pkg], timeout=15)
    seen = set()
    components = []
    for line in out.splitlines():
        line = line.strip()
        if f"{pkg}/" not in line:
            continue
        for part in line.split():
            if f"{pkg}/" not in part:
                continue
            name = part.strip("{}")
            if name in seen:
                continue
            seen.add(name)
            kind = ("Activity" if "Activity" in line
                    else "Service" if "Service" in line
                    else "Receiver")
            components.append({
                "kind":  kind,
                "name":  name,
                "short": name.split("/")[-1].split(".")[-1],
            })
    return components


# --- Envio -------------------------------------------------------------------

def _send_payload(comp: dict, flag: str, key: str, value: str, pkg: str) -> dict:
    val  = value.replace("__PKG__", pkg)
    kind = comp["kind"].lower()

    if kind == "activity":
        cmd = ["shell", "am", "start", "-n", comp["name"], flag, key, val]
    elif kind == "service":
        cmd = ["shell", "am", "startservice", "-n", comp["name"], flag, key, val]
    elif kind == "receiver":
        cmd = ["shell", "am", "broadcast", "-n", comp["name"], flag, key, val]
    elif kind == "deeplink":
        uri = f"{comp.get('scheme', 'http')}://{comp.get('host', 'x')}/{val}"
        cmd = ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", uri]
    else:
        return {"out": "", "crash": False, "launched": False, "val": val}

    out      = _adb(cmd, timeout=10)
    crash    = any(k in out for k in ("Exception", "FATAL", "crash", "ANR", "died"))
    launched = any(k in out for k in ("Starting:", "Broadcast completed", "result=0", "Warning:"))
    error    = any(k in out for k in ("Permission Denial", "not found", "does not exist",
                                       "SecurityException", "Unable to find"))
    return {"out": out, "crash": crash, "launched": launched and not error, "val": val}


# --- Relatorio ---------------------------------------------------------------

def _save_report(pkg: str, log: list) -> Path:
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import dynamic_dir
    out_dir = dynamic_dir(pkg)
    out = out_dir / "intent_fuzzer.txt"
    out.write_text("\n".join(log), encoding="utf-8")
    return out


# --- Telas -------------------------------------------------------------------

def _screen_components(pkg: str, components: list):
    _header("Intent Fuzzer", pkg)

    counts = {}
    for c in components:
        counts[c["kind"]] = counts.get(c["kind"], 0) + 1

    summary_parts = []
    for k, v in counts.items():
        kc = _KIND_COLOR.get(k, _D)
        summary_parts.append(f"{kc}{_B}{k}s{_R} {_D}({v}){_R}")
    print("  " + "  |  ".join(summary_parts) + "\n")

    print(f"  {_D}{'#':>3}  {'Tipo':<12}  Componente{_R}")
    print(_sep())

    for i, comp in enumerate(components, 1):
        kc    = _KIND_COLOR.get(comp["kind"], _D)
        kind  = f"{kc}{comp['kind']:<12}{_R}"
        short = comp["short"]
        if len(short) > _W_TOTAL - 20:
            short = short[:_W_TOTAL - 23] + "..."
        print(f"  {_D}{i:>3}{_R}  {kind}  {_W}{short}{_R}")

    print(_sep())
    print(f"\n  {_D}0 -> sair{_R}")


def _screen_payloads(comp: dict, pkg: str):
    kc = _KIND_COLOR.get(comp["kind"], _D)
    _header(
        f"Payloads  ->  {comp['short']}",
        f"[{comp['kind']}]  {comp['name']}"
    )

    print(f"  {_D}{'#':>3}  {'Badge':<10}  {'Flag':<6}  {'Key':<12}  Valor{_R}")
    print(_sep())

    for i, (category, badge, flag, key, value) in enumerate(_PAYLOADS, 1):
        bc = _BADGE_COLOR.get(badge, _D)
        b  = f"{bc}{_B}{badge:<10}{_R}"
        if value:
            val = value.replace("__PKG__", pkg)
            print(f"  {_D}{i:>3}{_R}  {b}  {_D}{flag:<6}{_R}  {_C}{key:<12}{_R}  {_W}{val[:28]}{_R}")
        else:
            print(f"  {_D}{i:>3}{_R}  {b}  {_D}digitar manualmente{_R}")

    print(_sep())
    print(f"\n  {_D}0 -> voltar{_R}")


def _screen_result(comp: dict, flag: str, key: str, result: dict):
    if result["crash"]:
        sc    = _RE
        label = "[!!] CRASH DETECTADO"
    elif result["launched"]:
        sc    = _Y
        label = "[>>] COMPONENTE RESPONDEU"
    else:
        sc    = _G
        label = "[OK] SEM RESPOSTA ANOMALA"

    print(f"\n  {sc}{_B}{'─' * _W_TOTAL}{_R}")
    print(f"  {sc}{_B}  {label}{_R}")
    print(f"  {sc}{'─' * _W_TOTAL}{_R}")

    _box("Detalhes", sc, [
        f"Componente : {comp['name']}",
        f"Tipo       : {comp['kind']}",
        f"Payload    : {flag}  {key} = {result['val'][:55]}",
    ])

    out_lines = [l for l in result["out"].splitlines() if l.strip()][:8]
    if out_lines:
        _box("Output ADB", _D, out_lines)


# --- Entry point -------------------------------------------------------------

def run_intent_fuzzer(pkg: str, apk_folder: Path = None):
    if not require_device("Intent Fuzzer"):
        return

    components = []
    if apk_folder and (apk_folder / "AndroidManifest.xml").exists():
        components = _parse_exported(apk_folder, pkg)
    if not components:
        components = _get_components_via_dumpsys(pkg)

    if not components:
        print(f"\n  {_Y}Nenhum componente exportado encontrado.{_R}")
        print(f"  {_D}Forneça a pasta descompilada (apktool) para analise completa.{_R}")
        input(f"\n  {_D}-> Enter para continuar...{_R}")
        return

    log = [
        f"Intent Fuzzer -- {pkg}",
        f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "=" * 60,
    ]

    while True:
        _screen_components(pkg, components)
        choice = input(f"\n{_C}->{_R} Componente: ").strip()

        if choice == "0":
            break
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(components)):
                continue
        except ValueError:
            continue

        comp = components[idx]

        while True:
            _screen_payloads(comp, pkg)
            pchoice = input(f"\n{_C}->{_R} Payload: ").strip()

            if pchoice == "0":
                break
            try:
                pidx = int(pchoice) - 1
                if not (0 <= pidx < len(_PAYLOADS)):
                    continue
            except ValueError:
                continue

            category, badge, flag, key, value = _PAYLOADS[pidx]

            if value is None:
                print()
                flag  = input(f"  {_C}->{_R} Flag  (ex: --es, --ei, --ez): ").strip() or "--es"
                key   = input(f"  {_C}->{_R} Key  : ").strip() or "data"
                value = input(f"  {_C}->{_R} Valor: ").strip() or "test"

            print(f"\n  {_D}-> Enviando intent...{_R}", end="", flush=True)
            result = _send_payload(comp, flag, key, value, pkg)
            print(f"\r  {_D}{'─' * 40}{_R}")

            _screen_result(comp, flag, key, result)

            log.append(
                f"\n[{comp['kind']}] {comp['name']}\n"
                f"  Payload : {flag} {key} = {result['val']}\n"
                f"  Status  : {'CRASH' if result['crash'] else 'RESPONDEU' if result['launched'] else 'sem anomalia'}\n"
                f"  Output  : {result['out'][:300]}"
            )

            input(f"\n  {_D}-> Enter para continuar...{_R}")

    if len(log) > 3:
        out = _save_report(pkg, log)
        _cls()
        print(f"\n  {_G}[OK] Log salvo em: {out}{_R}\n")
        input(f"  {_D}-> Enter para continuar...{_R}")
