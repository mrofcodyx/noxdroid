import sys
import os
from pathlib import Path

from core.banner import display_banner
from core.env_check import _adb_exe

# ─── Constantes de cor ────────────────────────────────────────────────────────

_R  = "\033[0m"
_C  = "\033[96m"   # cyan
_G  = "\033[92m"   # green
_Y  = "\033[93m"   # yellow
_D  = "\033[90m"   # dim
_W  = "\033[97m"   # white
_B  = "\033[1m"    # bold
_RE = "\033[91m"   # red
_BL = "\033[94m"   # blue

EMULATOR_MODE = "nox"  # mantido para compatibilidade com kitsune.py
TAB_SETUP = 0
TAB_TOOLS = 1
_TABS = ["  SETUP  ", "  TOOLS  "]


# ─── UI helpers ───────────────────────────────────────────────────────────────

def _cls():
    os.system("cls" if sys.platform == "win32" else "clear")
    os.system("")  # habilita ANSI no Windows


def _header(subtitle: str = ""):
    _cls()
    display_banner()
    from core.device_detect import DEVICE
    dtype = DEVICE.get("type")
    label = DEVICE.get("label") or "Nenhum dispositivo"
    if dtype == "nox":
        device_str = f"{_C}Nox Player{_R}"
    elif dtype == "emulator":
        device_str = f"{_Y}Emulador{_R}"
    elif dtype == "physical":
        device_str = f"{_G}Dispositivo Fisico{_R}"
    else:
        device_str = f"{_D}Sem dispositivo{_R}"

    if subtitle:
        print(f"  {_C}{'─' * 62}{_R}")
        print(f"  {_C}{_B}  {subtitle}{_R}")
        print(f"  {_C}{'─' * 62}{_R}\n")
    else:
        print(f"  {_D}Android Pentest Toolkit  |  {_R}{device_str}  {_D}{label}{_R}\n")


def _tabs(active: int):
    parts = []
    for i, label in enumerate(_TABS):
        if i == active:
            parts.append(f"\033[1;96;40m{label}{_R}")
        else:
            parts.append(f"{_D}{label}{_R}")
    print("  " + f"  {_D}│{_R}  ".join(parts))
    print(f"  {_D}" + "─" * 42 + _R)


def _sep():
    print(f"  {_D}" + "─" * 42 + _R)


def _opt(key: str, label: str, hint: str = "", color: str = _C):
    hint_str = f"  {_D}{hint}{_R}" if hint else ""
    print(f"  {color}{_B}{key}.{_R} {_W}{label}{_R}{hint_str}")


def _nav(*hints: str):
    print(f"\n  {_D}{'  │  '.join(hints)}{_R}")


def _ask(prompt: str = "") -> str:
    return input(f"\n{_C}→{_R} {prompt}").strip()


def _pause():
    input(f"\n{_D}→ Enter para continuar...{_R}")


# ─── Helper: fonte de APK ─────────────────────────────────────────────────────

def _get_apk(adb: str, allow_folder: bool = False) -> str | None:
    """Pede ao usuário a fonte do APK. Retorna path ou None."""
    from modules.pkg_picker import pick_package
    print(f"\n  {_D}Fonte:{_R}")
    _opt("a", "APK local", "caminho no PC", _D)
    _opt("b", "Baixar do dispositivo", "lista apps instalados", _D)
    src = _ask().lower()

    if src == "a":
        label = "Caminho do APK ou pasta: " if allow_folder else "Caminho do APK: "
        path = _ask(label).strip('"')
        return path or None
    elif src == "b":
        pkg = pick_package(adb, "Selecionar App — Baixar APK")
        if not pkg:
            return None
        from modules.apk_analyzer import pull_apk_from_device
        apk = pull_apk_from_device(adb, pkg)
        if not apk:
            _pause()
        return apk
    return None


def _get_pkg(adb: str) -> str | None:
    """Pede package name via lista do dispositivo ou extrai de APK local."""
    from modules.pkg_picker import pick_package
    print(f"\n  {_D}Fonte:{_R}")
    _opt("a", "App do dispositivo", "lista apps instalados", _D)
    _opt("b", "APK local", "extrai package do arquivo", _D)
    src = _ask().lower()

    if src == "a":
        return pick_package(adb, "Selecionar App") or None
    elif src == "b":
        path = _ask("Caminho do APK: ").strip('"')
        if path:
            from modules.apk_analyzer import _pkg_from_apk
            return _pkg_from_apk(path)
    return None


# ─── TAB SETUP ────────────────────────────────────────────────────────────────

def _menu_setup() -> int:
    from core.device_detect import DEVICE
    from modules.magisk_modules import install_magisk_modules

    _header()
    _tabs(TAB_SETUP)
    print()

    is_nox = DEVICE.get("type") == "nox"

    if is_nox:
        from modules.kitsune import install_kitsune_magisk
        _opt("1", "Instalar Kitsune", "Magisk para Nox Player")
        _opt("2", "Setup Completo",   "MaFrida + Modulos Magisk + Certificado CA")
    else:
        _opt("1", "Setup Completo",   "MaFrida + Modulos Magisk + Certificado CA")

    _nav("t -> Tools", "q -> sair")

    c = _ask()
    if is_nox:
        if   c == "1":
            from modules.kitsune import install_kitsune_magisk
            install_kitsune_magisk(emulator="nox")
        elif c == "2": install_magisk_modules()
    else:
        if c == "1": install_magisk_modules()

    if c == "t": return TAB_TOOLS
    if c == "q": sys.exit(0)
    return TAB_SETUP


# ─── TAB TOOLS ────────────────────────────────────────────────────────────────

def _menu_tools() -> int:
    _header()
    _tabs(TAB_TOOLS)
    print()
    _opt("1", "Análise Estática",  "APK, secrets, decompiladores, APKLeaks")
    _opt("2", "Análise Dinâmica",  "Vuln Scanner, Objection, Frida")
    _opt("3", "Interceptação",     "Proxy Switch, Certificado CA")
    _opt("4", "Dispositivo",       "ADB Shell, Magisk Monitor")
    _opt("5", "Relatórios",        "visualiza relatórios gerados")
    _nav("s → Setup", "q → sair")

    c = _ask()
    if   c == "1": _menu_static()
    elif c == "2": _menu_dynamic()
    elif c == "3": _menu_intercept()
    elif c == "4": _menu_device()
    elif c == "5":
        from modules.results_viewer import results_viewer_menu
        results_viewer_menu()
    elif c == "s": return TAB_SETUP
    elif c == "q": sys.exit(0)
    return TAB_TOOLS


# ─── 1. Análise Estática ──────────────────────────────────────────────────────

def _menu_static():
    adb = _adb_exe()
    while True:
        _header("Análise Estática")
        _opt("1", "Análise Completa", "pinning + root + anti-debug + crypto + webview + injection + ...")
        _opt("2", "APK Check",       "proteção, root, emu, debug, proxy, SDKs")
        _opt("3", "Secrets Finder",  "API keys, tokens, credenciais em código")
        _opt("4", "APKLeaks",        "URIs, endpoints e secrets via regex")
        _opt("5", "Native Scanner",  "analisa .so — RCE, secrets, JNI, URLs")
        _opt("6", "Abrir jadx-gui",  "decompilador visual")
        _opt("7", "APKiD",           "identifica compiladores, packers, obfuscators")
        _opt("8", "Androguard",      "análise profunda: perms, APIs, componentes, cert")
        _opt("9", "MobSFScan",       "análise de código fonte: Java, Kotlin, XML — regras MobSF")
        _opt("10", "Beautifest",    "componentes exportados, deep links, comandos ADB")
        _nav("0 → Voltar")

        c = _ask()
        if c == "0":
            break

        elif c == "1":
            apk = _get_apk(adb)
            if apk:
                from modules.apk_analyzer import analyze_apk_full
                analyze_apk_full(apk)

        elif c == "2":
            apk = _get_apk(adb, allow_folder=True)
            if apk:
                from modules.apk_check import run_apk_check
                hc = _ask("Incluir hardcode? (s/N): ").lower() == "s"
                run_apk_check(apk, check_hardcode=hc)
                _pause()

        elif c == "3":
            from modules.secrets_finder import secrets_finder_menu
            print(f"\n  {_D}Fonte:{_R}")
            _opt("a", "Pasta descompilada local", "", _D)
            _opt("b", "Baixar APK do dispositivo", "", _D)
            src = _ask().lower()
            if src == "a":
                path = _ask("Caminho da pasta: ").strip('"')
                secrets_finder_menu(path or None)
            elif src == "b":
                from modules.pkg_picker import pick_package
                pkg = pick_package(adb, "Secrets Finder — Selecionar App")
                if pkg:
                    from modules.apk_analyzer import pull_apk_from_device, decompile_apktool
                    apk = pull_apk_from_device(adb, pkg)
                    if apk:
                        folder = decompile_apktool(apk)
                        if folder:
                            secrets_finder_menu(str(folder))

        elif c == "4":
            apk = _get_apk(adb)
            if apk:
                from modules.apk_analyzer import run_apkleaks
                run_apkleaks(apk)

        elif c == "5":
            apk = _get_apk(adb)
            if apk:
                from modules.native_scanner import run_native_scanner
                run_native_scanner(apk)

        elif c == "6":
            apk = _get_apk(adb)
            if apk:
                from modules.apk_analyzer import decompile_jadx
                decompile_jadx(apk)
                _pause()

        elif c == "7":
            apk = _get_apk(adb)
            if apk:
                from modules.apkid_analyzer import run_apkid
                run_apkid(apk)

        elif c == "8":
            apk = _get_apk(adb)
            if apk:
                from modules.androguard_analyzer import run_androguard
                run_androguard(apk)

        elif c == "9":
            apk = _get_apk(adb)
            if apk:
                from modules.mobsfscan_analyzer import run_mobsfscan
                run_mobsfscan(apk)

        elif c == "10":
            apk = _get_apk(adb)
            if apk:
                from modules.beautifest import run_beautifest
                run_beautifest(apk)


# ─── 2. Análise Dinâmica ──────────────────────────────────────────────────────

def _run_crypto_monitor(pkg: str):
    """Executa o crypto_monitor.js via Frida e salva output em results/."""
    import subprocess as _sp
    import shutil
    from core.report_paths import dynamic_dir

    frida_bin = shutil.which("frida") or "frida"
    script = Path(__file__).parent / "Fripts" / "Recon" / "crypto" / "crypto_monitor.js"

    if not script.exists():
        print(f"\n{_RE}✖ Script não encontrado: {script}{_R}")
        _pause()
        return

    out_dir  = dynamic_dir(pkg)
    out_file = out_dir / "crypto_monitor.txt"

    print(f"\n{_C}{'─'*60}{_R}")
    print(f"{_C}{_B}  Crypto Monitor — {pkg}{_R}")
    print(f"{_C}{'─'*60}{_R}")
    print(f"\n  {_D}Script  : {script.name}{_R}")
    print(f"  {_D}Output  : {out_file}{_R}")
    print(f"\n  {_Y}Certifique-se que o app está aberto no dispositivo.{_R}")
    print(f"  {_D}Pressione Ctrl+C para parar e salvar o relatório.{_R}\n")

    lines = []
    try:
        proc = _sp.Popen(
            [frida_bin, "-U", "-n", pkg, "-l", str(script)],
            stdout=_sp.PIPE, stderr=_sp.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )
        # Se attach falhar (processo não encontrado), tenta spawn
        first_line = proc.stdout.readline()
        if first_line and ("Unable to find" in first_line or "Failed to attach" in first_line
                           or "process with name" in first_line.lower()):
            proc.terminate()
            print(f"  {_Y}App não encontrado em execução — usando spawn...{_R}\n")
            proc = _sp.Popen(
                [frida_bin, "-U", "-f", pkg, "-l", str(script)],
                stdout=_sp.PIPE, stderr=_sp.STDOUT,
                text=True, encoding="utf-8", errors="replace"
            )
        else:
            if first_line:
                print(f"  {first_line}", end="")
                lines.append(first_line)
        for line in proc.stdout:
            print(f"  {line}", end="")
            lines.append(line)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    if lines:
        out_file.write_text("".join(lines), encoding="utf-8")
        print(f"\n{_G}✔ Relatório salvo em: {out_file}{_R}")
    _pause()


def _menu_dynamic():
    adb = _adb_exe()
    while True:
        _header("Análise Dinâmica")
        _opt("1", "Vuln Scanner",          "testa componentes, providers, intents, logs via ADB")
        _opt("2", "Objection",             "hooking, memory, filesystem, bypass")
        _opt("3", "Frida Tools",           "scripts, codeshare, custom hooks")
        _opt("4", "Traffic Monitor",       "captura HTTP/HTTPS em tempo real via logcat")
        _opt("5", "Crypto Monitor",        "intercepta Cipher, Mac, MessageDigest via Frida")
        _opt("6", "Network Connections",   "conexões TCP/UDP ativas via /proc/net")
        _opt("7", "Method Tracer",         "rastreia chamadas Java em runtime via Frida Stalker")
        _opt("8", "Intent Fuzzer",         "envia intents maliciosos em componentes exportados")
        _nav("0 → Voltar")

        c = _ask()
        if c == "0":
            break

        elif c == "1":
            from core.adb_guard import require_device
            if not require_device("Vuln Scanner"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Vuln Scanner — Selecionar App")
            if pkg:
                from modules.vuln_scanner import run_vuln_scanner
                smali = Path("results") / pkg / "decompiled" / "smali"
                run_vuln_scanner(pkg, adb, smali_folder=smali if smali.exists() else None)

        elif c == "2":
            from core.adb_guard import require_device
            if not require_device("Objection"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Objection — Selecionar App")
            if pkg:
                from modules.objection_menu import objection_menu
                objection_menu(pkg)

        elif c == "3":
            from modules.frida_tools import frida_tool_options
            frida_tool_options()

        elif c == "4":
            from core.adb_guard import require_device
            if not require_device("Traffic Monitor"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Traffic Monitor — Selecionar App")
            if pkg:
                import subprocess as _sp
                from pathlib import Path as _P
                script = str(_P(__file__).parent / "modules" / "_traffic_monitor.py")
                _sp.Popen(
                    ["cmd", "/c", "start", f"Traffic Monitor - {pkg}", "cmd", "/k",
                     sys.executable, script, adb, pkg],
                    cwd=str(_P(__file__).parent)
                )
                print(f"\n{_C}✔ Traffic Monitor aberto em nova janela para {pkg}{_R}")
                _pause()

        elif c == "5":
            from core.adb_guard import require_device
            if not require_device("Crypto Monitor"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Crypto Monitor — Selecionar App")
            if pkg:
                _run_crypto_monitor(pkg)

        elif c == "6":
            from core.adb_guard import require_device
            if not require_device("Network Connections"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Network Connections — Selecionar App")
            if pkg:
                import subprocess as _sp
                from pathlib import Path as _P
                script = str(_P(__file__).parent / "modules" / "_net_monitor.py")
                _sp.Popen(
                    ["cmd", "/c", "start", f"Network Connections - {pkg}", "cmd", "/k",
                     sys.executable, script, adb, pkg],
                    cwd=str(_P(__file__).parent)
                )
                print(f"\n{_C}✔ Network Monitor aberto em nova janela para {pkg}{_R}")
                _pause()

        elif c == "7":
            from core.adb_guard import require_device
            if not require_device("Method Tracer"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Method Tracer — Selecionar App")
            if pkg:
                from modules.method_tracer import run_method_tracer
                run_method_tracer(pkg)

        elif c == "8":
            from core.adb_guard import require_device
            if not require_device("Intent Fuzzer"): continue
            from modules.pkg_picker import pick_package
            pkg = pick_package(adb, "Intent Fuzzer — Selecionar App")
            if pkg:
                from modules.intent_fuzzer import run_intent_fuzzer
                # Tenta usar pasta descompilada existente
                apk_folder = Path("results") / pkg / "decompiled"
                run_intent_fuzzer(pkg, apk_folder if apk_folder.exists() else None)


# ─── 3. Interceptação ─────────────────────────────────────────────────────────

def _menu_intercept():
    while True:
        _header("Interceptação")
        _opt("1", "Proxy Switch",    "Burp Suite / mitmproxy / custom")
        _opt("2", "Certificado CA",  "instala cert no dispositivo")
        _nav("0 → Voltar")

        c = _ask()
        if c == "0":
            break
        elif c == "1":
            from modules.proxy_switch import proxy_switch_menu
            proxy_switch_menu()
        elif c == "2":
            from modules.cert_setup import setup_cert_nox
            setup_cert_nox()


# ─── 4. Dispositivo ───────────────────────────────────────────────────────────

def _menu_device():
    adb = _adb_exe()
    while True:
        _header("Dispositivo")
        _opt("1", "ADB Shell",        "shell interativo com root e autocomplete")
        _opt("2", "Magisk Monitor",   "monitora logs do Magisk em nova janela")
        _opt("3", "DB Browser",       "navega bancos SQLite do dispositivo")
        _opt("4", "File Browser",     "navega sistema de arquivos do dispositivo")
        _nav("0 → Voltar")

        c = _ask()
        if c == "0":
            break
        elif c == "1":
            from core.adb_guard import require_device
            if not require_device("ADB Shell"): continue
            from modules.adb_shell import interactive_adb_shell
            interactive_adb_shell(adb)
        elif c == "2":
            from core.adb_guard import require_device
            if not require_device("Magisk Monitor"): continue
            import subprocess, time
            print(f"{_C}→ Abrindo Monitor Magisk em nova janela...{_R}")
            subprocess.Popen(
                'start "NoxDroid — Monitor Magisk" cmd /k python -m modules.magisk_monitor',
                shell=True, cwd=str(Path(__file__).parent)
            )
            time.sleep(1)
        elif c == "3":
            from core.adb_guard import require_device
            if not require_device("DB Browser"): continue
            try:
                from modules.db_browser import db_browser_menu
                from modules.pkg_picker import pick_package
                pkg = pick_package(adb, "DB Browser — Selecionar App")
                if pkg:
                    db_browser_menu(adb, pkg)
            except Exception as e:
                print(f"{_RE}✖ DB Browser erro: {e}{_R}")
                _pause()
        elif c == "4":
            from core.adb_guard import require_device
            if not require_device("File Browser"): continue
            try:
                from modules._file_browser import file_browser
                print(f"\n  {_D}Caminho inicial:{_R}")
                _opt("a", "App do dispositivo", "seleciona da lista de apps", _D)
                _opt("b", "/sdcard",            "armazenamento externo", _D)
                _opt("c", "custom",             "digitar caminho", _D)
                src = _ask().lower()
                if src == "a":
                    from modules.pkg_picker import pick_package
                    pkg = pick_package(adb, "File Browser — Selecionar App")
                    start = f"/data/data/{pkg}" if pkg else None
                elif src == "b":
                    start = "/sdcard"
                elif src == "c":
                    start = _ask("Caminho: ") or "/data"
                else:
                    continue
                if start:
                    file_browser(adb, start)
            except Exception as e:
                print(f"{_RE}✖ File Browser erro: {e}{_R}")
                _pause()


# ─── Entry point ──────────────────────────────────────────────────────────────

def display_main_menu():
    active = TAB_SETUP
    while True:
        active = _menu_setup() if active == TAB_SETUP else _menu_tools()


if __name__ == "__main__":
    from core.env_check import initial_environment_check
    initial_environment_check(emulator="nox")
    display_main_menu()
