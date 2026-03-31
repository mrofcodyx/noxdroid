"""
Frida Tools — navegação com setas (msvcrt, Windows).
Layout 3 níveis: Categoria → Subcategoria → Scripts
Scripts espelham exatamente a estrutura de Fripts/.
"""
import sys
import os
import shutil
import subprocess
from pathlib import Path

FRIPTS_DIR  = Path(__file__).parent.parent / "Fripts"
STACK_JS    = FRIPTS_DIR / "stack.js"

# Scripts que realmente usam as funções do stack.js (logJavaStack, logNativeStack, etc.)
# Todos os outros são injetados diretamente sem o stack para evitar conflitos.
_STACK_SCRIPTS = {
    "url_interceptor.js",
    "webview_inspector.js",
    "intent_inspector.js",
    "method_tracer.js",
}


def _source_uses_stack(source: str) -> bool:
    """
    Detecta automaticamente se um script usa funções do stack.js.
    Funciona para scripts do catálogo, CodeShare, custom e qualquer futuro script.
    """
    markers = ("logJavaStack", "logNativeStack", "logStack", "stackToLines",
               "javaStackToLines", "__STACK_CONFIG__")
    return any(m in source for m in markers)


def _load_with_stack(script_path: Path, stack_config: dict | None = None) -> Path:
    """
    Prepend stack.js apenas se o script realmente usa suas funções.
    Detecta automaticamente via inspeção do source — sem lista manual.
    """
    import tempfile, json

    source = script_path.read_text(encoding="utf-8")
    use_stack = _source_uses_stack(source)

    prefix = ""
    if use_stack:
        if stack_config:
            prefix += f"var __STACK_CONFIG__ = {json.dumps(stack_config)};\n"
        if STACK_JS.exists():
            prefix += STACK_JS.read_text(encoding="utf-8") + "\n\n"

    tmp = Path(tempfile.mktemp(suffix=".js"))
    tmp.write_text(prefix + source, encoding="utf-8")
    return tmp


def _wrap_source_with_stack(source: str) -> str:
    """
    Versão para source em memória (CodeShare, custom script).
    Retorna source final — com ou sem stack.js prefixado.
    """
    if not _source_uses_stack(source):
        return source
    prefix = ""
    if STACK_JS.exists():
        prefix = STACK_JS.read_text(encoding="utf-8") + "\n\n"
    return prefix + source

# ─── Catálogo ─────────────────────────────────────────────────────────────────
# Estrutura: [ (categoria, desc, [ (subcategoria, desc, [ (label, script, action, desc) ]) ]) ]
# label  = nome exato do arquivo .js (sem extensão) ou label descritivo para actions
# script = path relativo a FRIPTS_DIR, ou None para actions nativas
# action = string de action, ou None para scripts

CATEGORIES = [
    ("Recon", "Ferramentas de análise e reconhecimento de apps Android", [
        ("builtin", "Ferramentas nativas ADB", [
            ("Logcat — monitor app",
             None, "recon_logcat",
             "Abre janela externa monitorando todos os logs do app em tempo real"),
            ("Logcat — erros/crashes",
             None, "recon_crashes",
             "Monitora exceções, crashes e erros fatais em nova janela"),
            ("Logcat — tráfego de rede",
             None, "recon_network",
             "Filtra logs de OkHttp, Retrofit, SSL para ver requisições HTTP"),
            ("Traffic Monitor",
             None, "recon_traffic",
             "Captura e formata tráfego HTTP/HTTPS em tempo real: URLs, métodos, status, dados sensíveis"),
            ("Network Connections",
             None, "recon_netconn",
             "Monitora conexões TCP/UDP ativas do app via /proc/net — IPs, portas, estado, hostname"),
            ("Info do app  (dumpsys)",
             None, "recon_dumpsys",
             "Exibe informações completas do package: versão, paths, providers, receivers"),
            ("Permissões do app",
             None, "recon_perms",
             "Lista todas as permissões solicitadas e seu status (granted/denied)"),
            ("Atividades declaradas",
             None, "recon_activities",
             "Extrai todas as Activities declaradas no AndroidManifest via dumpsys"),
            ("Arquivos internos  (/data/data)",
             None, "recon_files",
             "Navega arquivos internos do app com File Browser (requer root)"),
            ("Memory Info  (dumpsys meminfo)",
             None, "recon_memdump",
             "Exibe uso de memória: heap, PSS, objetos Java, databases abertas"),
            ("List installed apps",
             None, "recon_apps",
             "Lista todos os apps instalados via frida-ps"),
        ]),
        ("network", "Interceptação de tráfego de rede", [
            ("url_interceptor",
             "Recon/network/url_interceptor.js", None,
             "Intercepta URLs: java.net.URL, OkHttp, WebView, HttpURLConnection, Apache HTTP, SSL_write"),
            ("logs",
             "Recon/network/logs.js", None,
             "Hooks android.util.Log (d/v/i/e/w) — intercepta todos os logs do app em runtime"),
        ]),
        ("crypto", "Análise de criptografia e keystores", [
            ("keystore_spy",
             "Recon/crypto/keystore_spy.js", None,
             "Monitora Android Keystore: alias, algoritmo, segurança, autenticação biométrica, Cipher.init"),
            ("crypto_monitor",
             "Recon/crypto/crypto_monitor.js", None,
             "Intercepta Cipher, Mac, MessageDigest, SecretKeySpec, IvParameterSpec, KeyGenerator em runtime"),
            ("frida_crypto_hooks",
             "Recon/crypto/frida_crypto_hooks.js", None,
             "Hooks Java + Native crypto: SecretKeySpec, IvParameterSpec, GCM, PBE, Cipher, Mac, BoringSSL, PBKDF2, HKDF"),
            ("hook_AESDESRSA",
             "Recon/crypto/hook_AESDESRSA.js", None,
             "Hooks AES, DES e RSA — captura chaves, IVs e dados cifrados em runtime"),
            ("dumpSqlcipher",
             "Recon/crypto/sqlcipher/dumpSqlcipher.js", None,
             "Exporta banco SQLCipher para plaintext via sqlcipher_export()"),
            ("earlyInstr_Sqlcipher",
             "Recon/crypto/sqlcipher/earlyInstr_Sqlcipher.js", None,
             "Hook precoce em sqlite3_key (libsqlcipher.so) — captura chave de criptografia na inicialização"),
        ]),
        ("enum", "Enumeração de classes e métodos", [
            ("listClass",
             "Recon/enum/listClass.js", None,
             "Enumera todas as classes carregadas que correspondem a um package name"),
            ("listClass2",
             "Recon/enum/listClass2.js", None,
             "Enumera classes + métodos de um package alvo"),
            ("listClassAndMethods",
             "Recon/enum/listClassAndMethods.js", None,
             "Lista todas as classes carregadas com seus métodos e campos"),
            ("listMethodsAndProps",
             "Recon/enum/listMethodsAndProps.js", None,
             "Lista métodos, campos e construtores de uma classe específica"),
        ]),
        ("hooking", "Hooking de métodos e JNI", [
            ("hookCipher",
             "Recon/hooking/hookCipher.js", None,
             "Hooks Cipher.doFinal — imprime dados cifrados/decifrados como string ou hex"),
            ("strcmpHook",
             "Recon/hooking/strcmpHook.js", None,
             "Hooks native strcmp (libc.so) — loga todas as comparações de strings"),
            ("hook_RegisterNatives",
             "Recon/hooking/hook_RegisterNatives.js", None,
             "Hooks RegisterNatives (libart.so) — revela mapeamentos JNI em runtime"),
            ("hook_MethodsAndClasses_WithIntentsAndBroadcast",
             "Recon/hooking/hook_MethodsAndClasses_WithIntentsAndBroadcast.js", None,
             "Exemplo: hooks de métodos + interceptação de Intent e Broadcast"),
            ("interceptingMethods",
             "Recon/hooking/interceptingMethods.js", None,
             "Template para interceptar chamadas de métodos e inspecionar args/retorno"),
            ("changingValuesMethods",
             "Recon/hooking/changingValuesMethods.js", None,
             "Template para sobrescrever valores de retorno de métodos em runtime"),
        ]),
        ("tracer", "Method Tracer — Frida Stalker", [
            ("Method Tracer",
             None, "recon_method_tracer",
             "Rastreia chamadas de métodos Java: sensíveis, por package prefix ou classe específica"),
        ]),
        ("vuln", "Vuln Inspector — confirma vulnerabilidades em runtime", [
            ("WebView Inspector",
             "Recon/vuln/webview_inspector.js", None,
             "Confirma addJavascriptInterface, setAllowFileAccess, loadUrl com file:// e javascript: em runtime"),
            ("Intent Inspector",
             "Recon/vuln/intent_inspector.js", None,
             "Rastreia extras de Intent até sinks: WebView, SQLite, Runtime.exec, FileInputStream (confirma XSS/SQLi/LFI/RCE)"),
            ("UI Security Inspector",
             "Recon/vuln/ui_security_inspector.js", None,
             "Confirma FLAG_SECURE, setFilterTouchesWhenObscured e dados sensíveis no Clipboard em runtime"),
            ("gps_spoof",
             "Recon/vuln/gps_spoof.js", None,
             "Falsifica coordenadas GPS via Location.getLatitude/getLongitude"),
        ]),
        ("other", "Utilitários e outros scripts", [
            ("createNotification",
             "Recon/other/createNotification.js", None,
             "Cria uma notificação do sistema via Frida — confirma execução de código"),
        ]),
    ]),
    ("Bypass", "Scripts de bypass para proteções do app", [
        ("sslpinning", "Bypass de SSL Pinning", [
            ("basic_sslpinning",
             "Bypass/sslpinning/basic_sslpinning.js", None,
             "Bypass via TrustManagerImpl.checkTrustedRecursive (Conscrypt)"),
            ("bypass_sslpinning",
             "Bypass/sslpinning/bypass_sslpinning.js", None,
             "Bypass abrangente: TrustManager, OkHttp, Conscrypt, nativo + root + emulador"),
            ("flutter_tls_bypass",
             "Bypass/sslpinning/flutter/flutter_tls_bypass.js", None,
             "Desativa ssl_verify_peer_cert em libflutter.so — arm64, arm, x64"),
        ]),
        ("rootdetection", "Bypass de detecção de root", [
            ("rootdetec",
             "Bypass/rootdetection/rootdetec.js", None,
             "Oculta su, binários root, packages Magisk/SuperSU, props do sistema, fopen/system nativos"),
            ("antiRoot_1",
             "Bypass/rootdetection/antiRoot_1.js", None,
             "Bypass completo: PackageManager, File.exists, Runtime.exec, SystemProperties, fopen, ProcessBuilder"),
            ("antiRoot_2",
             "Bypass/rootdetection/antiRoot_2.js", None,
             "Bypass alternativo de root detection — variante com cobertura adicional"),
            ("rootBeerBypass",
             "Bypass/rootdetection/rootBeerBypass.js", None,
             "Bypass específico para a biblioteca RootBeer"),
            ("cordova_root_bypass",
             "Bypass/rootdetection/cordova_root_bypass.js", None,
             "Bypass para apps Cordova com cordova.plugin.devicecompile"),
        ]),
        ("sslpinning_extra", "SSL Pinning — scripts adicionais", [
            ("okhttp3_bypass",
             "Bypass/sslpinning/okhttp3_bypass.js", None,
             "Bypass específico para OkHttp3 CertificatePinner"),
            ("ssl_bypass_conscrypt",
             "Bypass/sslpinning/ssl_bypass_conscrypt.js", None,
             "Bypass via Conscrypt — TrustManagerImpl.checkTrustedRecursive"),
            ("trustmanager_bypass",
             "Bypass/sslpinning/trustmanager_bypass.js", None,
             "Bypass via X509TrustManager customizado — checkServerTrusted retorna vazio"),
        ]),
        ("biometric", "Bypass de autenticação biométrica", [
            ("biometricBypass",
             "Bypass/biometric/biometricBypass.js", None,
             "Bypassa BiometricPrompt e FingerprintManager — força autenticação bem-sucedida"),
        ]),
        ("developerdetection", "Bypass de detecção de modo desenvolvedor", [
            ("developer_mode_bypass",
             "Bypass/developerdetection/developer_mode_bypass.js", None,
             "Falsifica Settings: adb_enabled, development_settings_enabled, play_protect_enabled"),
        ]),
        ("screenprotection", "Bypass de proteção de tela", [
            ("Remove_flag_secure",
             "Bypass/screenprotection/Remove_flag_secure.js", None,
             "Remove FLAG_SECURE de Window e Activity — permite screenshots e gravação"),
        ]),
    ]),
    ("AllInOne", "Scripts all-in-one — bypass completo", [
        ("allInOne", "Bypass completo NoxDroid — tudo em um script", [
            ("noxdroid_priv",
             "Bypass/noxdroid_priv.js", None,
             "Root + Native + ADB + Emulator + Keystore + SSL + HTTP + Screen — API 28 · Zygisk-safe"),
        ]),
    ]),
    ("Unity", "Scripts para jogos e apps Unity (Il2Cpp)", [
        ("il2cpp", "Il2Cpp — enumeração e modificação", [
            ("discover",
             "Unity/discover.js", None,
             "Enumera classes, campos e métodos Il2Cpp — requer frida-il2cpp-bridge"),
            ("fieldModifier-GENERIC",
             "Unity/fieldModifier-GENERIC.js", None,
             "Template genérico para modificar campos Il2Cpp via hook de método"),
            ("writeScore-example",
             "Unity/writeScore-example.js", None,
             "Exemplo: escreve o campo score em um jogo Unity via Il2Cpp"),
        ]),
    ]),
]

# ─── Índice plano: lista de (cat, subcat, scripts[]) para navegação ───────────
_NAV: list[tuple[str, str, list]] = []
for _c, _cd, _subs in CATEGORIES:
    for _s, _sd, _scripts in _subs:
        _NAV.append((_c, _s, _scripts))

_CAT_DESC = {c[0]: c[1] for c in CATEGORIES}
_SUB_DESC = {s: sd for _, _, subs in CATEGORIES for s, sd, _ in subs}


# ─── Cores ────────────────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_SEL_BG = "\033[30;46m"
_ACT    = "\033[96;1m"

SEP    = f"{_DIM}│{_RESET}"
LEFT_W = 28   # largura do painel esquerdo (cat/subcat)

# ─── Teclas ───────────────────────────────────────────────────────────────────
_UP    = b"H"
_DOWN  = b"P"
_LEFT  = b"K"
_RIGHT = b"M"
_ENTER = b"\r"
_ESC   = b"\x1b"
_TAB   = b"\t"
_Q     = b"q"


def _getch():
    import msvcrt
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):
        return ("special", msvcrt.getch())
    return ("char", ch)


def _clear():
    os.system("cls")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _frida_bin(tool: str = "frida") -> str:
    found = shutil.which(tool)
    if found:
        return found
    try:
        r = subprocess.run([sys.executable, "-m", "site", "--user-base"],
                           capture_output=True, text=True)
        base = r.stdout.strip()
        for sub in ["Scripts",
                    f"Python{sys.version_info.major}{sys.version_info.minor}\\Scripts"]:
            c = Path(base) / sub / f"{tool}.exe"
            if c.exists():
                return str(c)
    except Exception:
        pass
    return tool


def _list_apps() -> list[tuple[str, str]]:
    try:
        r = subprocess.run([_frida_bin("frida-ps"), "-Uai"],
                           capture_output=True, text=True, timeout=10)
        lines = r.stdout.splitlines()
        header_idx = sep_idx = None
        for i, line in enumerate(lines):
            if "Name" in line and "Identifier" in line:
                header_idx = i
            if line.strip().startswith("----"):
                sep_idx = i
                break
        if header_idx is None or sep_idx is None:
            return []
        header    = lines[header_idx]
        name_col  = header.index("Name")
        ident_col = header.index("Identifier")
        apps = []
        for line in lines[sep_idx + 1:]:
            if len(line) <= ident_col:
                continue
            name  = line[name_col:ident_col].strip()
            ident = line[ident_col:].strip()
            if ident and name:
                apps.append((ident, name))
        return apps
    except Exception:
        return []


def _pick_package() -> str | None:
    print(f"\n{_CYAN}→ Carregando apps instalados...{_RESET}", end="", flush=True)
    apps = _list_apps()
    if not apps:
        print(f"\r{_DIM}  (não foi possível listar — digite manualmente){_RESET}      ")
        pkg = input("→ Package name: ").strip()
        return pkg or None

    query    = ""
    selected = 0

    while True:
        _clear()
        filtered = [a for a in apps
                    if query.lower() in a[0].lower() or query.lower() in a[1].lower()
                    ] if query else apps

        print(f"{_CYAN}{_BOLD}  Selecionar App{_RESET}  "
              f"{_DIM}↑↓=navegar  Enter=selecionar  Esc=cancelar{_RESET}")
        print(f"{_DIM}{'─' * 78}{_RESET}")
        print(f"  {_WHITE}Busca:{_RESET} {_CYAN}{query}{_RESET}▌\n")

        max_visible = 20
        if selected >= len(filtered):
            selected = max(0, len(filtered) - 1)
        start   = max(0, selected - max_visible // 2)
        visible = filtered[start:start + max_visible]

        if not filtered:
            print(f"  {_DIM}Nenhum app encontrado.{_RESET}")
        else:
            for i, (pkg, name) in enumerate(visible):
                if start + i == selected:
                    print(f"  {_SEL_BG} {pkg:<45} {name:<25} {_RESET}")
                else:
                    print(f"  {_DIM}{pkg:<45}{_RESET} {_WHITE}{name}{_RESET}")

        if len(filtered) > max_visible:
            print(f"\n  {_DIM}({len(filtered)} apps — continue digitando para filtrar){_RESET}")
        print(f"\n{_DIM}{'─' * 78}{_RESET}")

        kind, ch = _getch()
        if kind == "char":
            if ch == _ESC:
                return None
            elif ch == _ENTER:
                return filtered[selected][0] if filtered else None
            elif ch == b"\x08":
                query = query[:-1]; selected = 0
            else:
                try:
                    c = ch.decode("utf-8")
                    if c.isprintable():
                        query += c; selected = 0
                except Exception:
                    pass
        elif kind == "special":
            if ch == _UP:
                selected = max(0, selected - 1)
            elif ch == _DOWN:
                selected = min(len(filtered) - 1, selected + 1) if filtered else 0


# ─── Memory Info ──────────────────────────────────────────────────────────────

def _do_memdump(adb: str, pkg: str):
    from datetime import datetime
    _clear()
    print(f"{_CYAN}{_BOLD}  Memory Info — {pkg}{_RESET}")
    print(f"{_DIM}{'─' * 60}{_RESET}\n")
    print(f"  {_CYAN}1.{_RESET} App em execução  {_DIM}(já está aberto){_RESET}")
    print(f"  {_CYAN}2.{_RESET} Iniciar app e capturar  {_DIM}(usa monkey para abrir){_RESET}")
    print(f"\n  {_DIM}0. Cancelar{_RESET}")
    choice = input(f"\n  → Escolha: ").strip()
    if choice == "0" or not choice:
        return
    if choice == "2":
        print(f"\n  {_CYAN}→ Iniciando {pkg}...{_RESET}")
        subprocess.run([adb, "shell", "monkey", "-p", pkg, "-v", "1"],
                       capture_output=True, timeout=10)
        import time; time.sleep(2)
    print(f"  {_CYAN}→ Coletando meminfo de {pkg}...{_RESET}\n")
    r = subprocess.run([adb, "shell", "dumpsys", "meminfo", pkg],
                       capture_output=True, text=True, timeout=15)
    output = r.stdout.strip()
    if not output or "No process found" in output:
        print(f"  {_RED}✖ Processo não encontrado. O app está em execução?{_RESET}")
        input(f"\n  → Enter para continuar...")
        return
    _clear()
    print(f"{_CYAN}{_BOLD}  Memory Info — {pkg}{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")
    for line in output.splitlines():
        low = line.lower()
        if any(k in low for k in ("total pss", "total rss", "heap size",
                                   "heap alloc", "heap free", "native heap",
                                   "dalvik heap", "views:", "activities:")):
            print(f"  {_YELLOW}{line}{_RESET}")
        elif line.strip().startswith("**"):
            print(f"  {_CYAN}{line}{_RESET}")
        else:
            print(f"  {_WHITE}{line}{_RESET}")
    from core.report_paths import dynamic_dir
    out_dir = dynamic_dir(pkg)
    out = out_dir / "meminfo.txt"
    out.write_text(output, encoding="utf-8")
    print(f"\n{_DIM}{'─' * 78}{_RESET}")
    print(f"  {_GREEN}✔ Salvo em: {out}{_RESET}")
    input(f"\n  -> Enter para continuar...")


# ─── Configuração interativa de scripts ──────────────────────────────────────

# Mapa: nome_do_arquivo → lista de (variável_js, label_pt, default)
_SCRIPT_CONFIG: dict[str, list[tuple[str, str, str]]] = {
    # Enum
    "listClass.js": [
        ("targetPackage", "Package alvo (ex: com.example.app)", "com.example"),
    ],
    "listClass2.js": [
        ("targetPackage", "Package alvo (ex: com.example.app)", "com.example"),
    ],
    "listMethodsAndProps.js": [
        ("targetClass", "Classe alvo completa (ex: com.example.MyClass)", "com.example.TargetClass"),
    ],
    # Hooking
    "interceptingMethods.js": [
        ("targetClass",  "Classe alvo completa (ex: com.example.MyClass)", "com.example.TargetClass"),
        ("targetMethod", "Nome do método a interceptar",                    "targetMethod"),
    ],
    "changingValuesMethods.js": [
        ("targetClass",  "Classe alvo completa (ex: com.example.MyClass)", "com.example.TargetClass"),
        ("targetMethod", "Nome do método a sobrescrever",                   "isFeatureEnabled"),
        ("forced",       "Valor forçado de retorno (true/false/número)",    "true"),
    ],
    # SQLCipher
    "dumpSqlcipher.js": [
        ("com.random", "Package name do app alvo (para o path do DB)", "com.example.app"),
    ],
    # GPS
    "gps_spoof.js": [
        ("spoofLat", "Latitude  (ex: -23.5505)", "-23.5505"),
        ("spoofLon", "Longitude (ex: -46.6333)", "-46.6333"),
    ],
    # Unity
    "fieldModifier-GENERIC.js": [
        ("TargetClass", "Nome da classe Il2Cpp alvo",    "TargetClass"),
        ("Update",      "Método gatilho (ex: Update)",   "Update"),
        ("someField",   "Campo a modificar",             "someField"),
        ("9999",        "Novo valor do campo",           "9999"),
    ],
    "writeScore-example.js": [
        ("GameManager", "Classe que contém o score",     "GameManager"),
        ("score",       "Nome do campo score",           "score"),
        ("AddScore",    "Método gatilho",                "AddScore"),
        ("999999",      "Valor do score a definir",      "999999"),
    ],
}


def _prompt_script_config(script_path: Path, pkg: str) -> str | None:
    """
    Se o script tiver configurações interativas, exibe um formulário,
    substitui os valores no source e retorna o source patchado.
    Retorna None se o script não precisar de configuração.
    """
    name = script_path.name
    fields = _SCRIPT_CONFIG.get(name)
    if not fields:
        return None

    source = script_path.read_text(encoding="utf-8")

    _clear()
    print(f"  {_CYAN}{_BOLD}Configurar: {name}{_RESET}")
    print(f"  {_DIM}{'─' * 60}{_RESET}")
    print(f"  {_DIM}Package selecionado: {_RESET}{_WHITE}{pkg}{_RESET}")
    print(f"  {_DIM}Deixe em branco para usar o valor padrão.{_RESET}\n")

    replacements: list[tuple[str, str]] = []
    for old_val, label, default in fields:
        # Sugere o package selecionado como default para campos de package
        smart_default = pkg if ("package" in label.lower() or "app alvo" in label.lower()) else default
        print(f"  {_YELLOW}{label}{_RESET}")
        print(f"  {_DIM}  padrão: {smart_default}{_RESET}")
        val = input(f"  {_CYAN}→{_RESET} ").strip()
        if not val:
            val = smart_default
        replacements.append((old_val, val))
        print()

    patched = source
    for old, new in replacements:
        patched = patched.replace(f'"{old}"', f'"{new}"', 1)
        # também tenta substituição numérica sem aspas (ex: 9999, 999999)
        if old.lstrip("-").isdigit():
            patched = patched.replace(f' {old};', f' {new};', 1)
            patched = patched.replace(f' {old},', f' {new},', 1)

    print(f"  {_GREEN}✔ Configuração aplicada.{_RESET}")
    import time; time.sleep(0.6)
    return patched


# ─── Execução ─────────────────────────────────────────────────────────────────

def _resolve_pid(pkg: str) -> str | None:
    """
    Resolve o PID do processo via 'adb shell pidof <pkg>' (mais confiavel).
    Fallback: frida-ps -U se pidof nao retornar nada.
    Retorna o PID como string, ou None se o processo nao estiver rodando.
    """
    from core.device_detect import get_adb
    adb = get_adb()

    # 1. adb shell pidof — direto e confiavel
    try:
        r = subprocess.run(
            [adb, "shell", "pidof", pkg],
            capture_output=True, text=True, timeout=6
        )
        pid = r.stdout.strip().split()[0] if r.stdout.strip() else None
        if pid and pid.isdigit():
            return pid
    except Exception:
        pass

    # 2. adb shell ps — fallback para ROMs sem pidof
    try:
        r = subprocess.run(
            [adb, "shell", "ps", "-A"],
            capture_output=True, text=True, timeout=8
        )
        for line in r.stdout.splitlines():
            if pkg in line:
                parts = line.split()
                # formato: USER PID PPID ... NAME
                if len(parts) >= 2 and parts[1].isdigit():
                    return parts[1]
    except Exception:
        pass

    # 3. frida-ps -U — ultimo recurso
    try:
        r = subprocess.run(
            [_frida_bin("frida-ps"), "-U"],
            capture_output=True, text=True, timeout=8
        )
        for line in r.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and pkg in parts[1]:
                return parts[0].strip()
    except Exception:
        pass

    return None


def _frida_attach_args(frida: str, pkg: str, script: str) -> list | None:
    """
    Monta args para attach usando PID (-p).
    Retorna None se o processo nao estiver rodando (nao faz spawn).
    """
    pid = _resolve_pid(pkg)
    if pid:
        print(f"  {_DIM}-> PID: {pid}  ({pkg}){_RESET}")
        return [frida, "-U", "-p", pid, "-l", script]

    print(f"\n  {_YELLOW}[!] Processo nao encontrado: {pkg}{_RESET}")
    print(f"  {_DIM}    Abra o app no dispositivo e tente novamente.{_RESET}")
    return None

    if action == "recon_apps":
        subprocess.run([_frida_bin("frida-ps"), "-Uai"])
        input("\n→ Enter para continuar...")
        return

    if action in ("recon_logcat", "recon_crashes", "recon_network",
                  "recon_dumpsys", "recon_perms", "recon_activities",
                  "recon_files", "recon_memdump", "recon_traffic",
                  "recon_netconn", "recon_method_tracer"):
        pkg = _pick_package()
        if not pkg:
            return
        adb = _adb_exe()
        cwd = str(Path(__file__).parent.parent)

        if action == "recon_logcat":
            monitor_script = str(Path(__file__).parent / "_logcat_monitor.py")
            subprocess.Popen(["cmd", "/c", "start", f"Logcat - {pkg}", "cmd", "/k",
                               sys.executable, monitor_script, adb, pkg, "app"], cwd=cwd)
            print(f"{_CYAN}✔ Monitor aberto em nova janela para {pkg}{_RESET}")

        elif action == "recon_crashes":
            monitor_script = str(Path(__file__).parent / "_logcat_monitor.py")
            subprocess.Popen(["cmd", "/c", "start", f"Crashes - {pkg}", "cmd", "/k",
                               sys.executable, monitor_script, adb, pkg, "crashes"], cwd=cwd)
            print(f"{_CYAN}✔ Monitor de crashes aberto em nova janela{_RESET}")

        elif action == "recon_network":
            monitor_script = str(Path(__file__).parent / "_logcat_monitor.py")
            subprocess.Popen(["cmd", "/c", "start", f"Network - {pkg}", "cmd", "/k",
                               sys.executable, monitor_script, adb, pkg, "network"], cwd=cwd)
            print(f"{_CYAN}✔ Monitor de rede aberto em nova janela{_RESET}")

        elif action == "recon_traffic":
            traffic_script = str(Path(__file__).parent / "_traffic_monitor.py")
            subprocess.Popen(["cmd", "/c", "start", f"Traffic Monitor - {pkg}", "cmd", "/k",
                               sys.executable, traffic_script, adb, pkg], cwd=cwd)
            print(f"{_CYAN}✔ Traffic Monitor aberto em nova janela para {pkg}{_RESET}")

        elif action == "recon_netconn":
            net_script = str(Path(__file__).parent / "_net_monitor.py")
            subprocess.Popen(["cmd", "/c", "start", f"Network Connections - {pkg}", "cmd", "/k",
                               sys.executable, net_script, adb, pkg], cwd=cwd)
            print(f"{_CYAN}✔ Network Monitor aberto em nova janela para {pkg}{_RESET}")

        elif action == "recon_method_tracer":
            from modules.method_tracer import run_method_tracer
            run_method_tracer(pkg)
            return  # já tem pause interno

        elif action == "recon_dumpsys":
            _clear()
            print(f"{_CYAN}→ dumpsys package {pkg}{_RESET}\n")
            subprocess.run([adb, "shell", "dumpsys", "package", pkg])

        elif action == "recon_perms":
            _clear()
            print(f"{_CYAN}→ Permissões de {pkg}{_RESET}\n")
            r = subprocess.run([adb, "shell", "dumpsys", "package", pkg],
                               capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if "granted=true" in line or "granted=false" in line:
                    ok   = "granted=true" in line
                    icon = f"{_CYAN}✔{_RESET}" if ok else f"{_RED}✖{_RESET}"
                    perm = line.strip().split(":")[0].strip()
                    print(f"  {icon} {perm}")
                elif "requested permissions:" in line.lower():
                    print(f"\n{_CYAN}Permissões solicitadas:{_RESET}")
                elif "install permissions:" in line.lower():
                    print(f"\n{_CYAN}Permissões de instalação:{_RESET}")

        elif action == "recon_activities":
            _clear()
            print(f"{_CYAN}→ Atividades de {pkg}{_RESET}\n")
            r3 = subprocess.run([adb, "shell", "dumpsys", "package", pkg],
                                capture_output=True, text=True)
            activities = set()
            for line in r3.stdout.splitlines():
                stripped = line.strip()
                if f"{pkg}/" in stripped:
                    for p in stripped.split():
                        if f"{pkg}/" in p:
                            act = p.split("{")[-1].split("}")[0].strip()
                            if "/" in act and len(act) > 5:
                                activities.add(act)
            if activities:
                for act in sorted(activities):
                    print(f"  {_WHITE}{act}{_RESET}")
            else:
                print(f"  {_DIM}Nenhuma atividade encontrada.{_RESET}")

        elif action == "recon_files":
            from modules._file_browser import file_browser
            file_browser(adb, f"/data/data/{pkg}")

        elif action == "recon_memdump":
            _do_memdump(adb, pkg)

        input("\n→ Enter para continuar...")
        return

    if script_file:
        path = FRIPTS_DIR / script_file
        if not path.exists():
            print(f"{_RED}✖ Script não encontrado: {path}{_RESET}")
            input("\n→ Enter para continuar...")
            return
        pkg = _pick_package()
        if not pkg:
            return

        # ── Configuração interativa antes de injetar ──────────────────────────
        patched_source = _prompt_script_config(path, pkg)

        # Pergunta attach vs spawn
        _clear()
        print(f"{_CYAN}{_BOLD}  {Path(script_file).name}  →  {pkg}{_RESET}")
        print(f"{_DIM}{'─' * 60}{_RESET}\n")
        print(f"  {_CYAN}Modo de execução:{_RESET}")
        print(f"  {_GREEN}1.{_RESET} Attach  {_DIM}(app já está aberto — recomendado){_RESET}")
        print(f"  {_GREEN}2.{_RESET} Spawn   {_DIM}(Frida reinicia o app){_RESET}")
        print(f"\n  {_DIM}0. Cancelar{_RESET}")
        mode = input(f"\n  → ").strip()
        if mode == "0" or not mode:
            return
        use_spawn = mode == "2"

        # Prepend stack.js (usando source patchado se houve config)
        if patched_source is not None:
            import tempfile
            tmp_patched = Path(tempfile.mktemp(suffix=".js"))
            tmp_patched.write_text(patched_source, encoding="utf-8")
            tmp = _load_with_stack(tmp_patched)
            tmp_patched.unlink(missing_ok=True)
        else:
            tmp = _load_with_stack(path)
        _clear()
        print(f"{_CYAN}→ Executando {Path(script_file).name} em {pkg}...{_RESET}\n")
        try:
            if use_spawn:
                frida_args = [_frida_bin("frida"), "-U", "-f", pkg, "-l", str(tmp)]
            else:
                frida_args = _frida_attach_args(_frida_bin("frida"), pkg, str(tmp))
                if frida_args is None:
                    input("\n-> Enter para continuar...")
                    return
            subprocess.run(frida_args)
        finally:
            try: tmp.unlink()
            except Exception: pass
        input("\n-> Enter para continuar...")


# ─── CodeShare ────────────────────────────────────────────────────────────────

_CS_BASE    = "https://codeshare.frida.re"
_CS_BROWSE  = f"{_CS_BASE}/browse"
_CS_API     = f"{_CS_BASE}/api/project"


def _cs_parse_page(html: str) -> list[dict]:
    """Extrai scripts de uma página HTML do CodeShare."""
    import re
    articles = re.findall(r'<article>(.*?)</article>', html, re.DOTALL)
    scripts  = []
    for block in articles:
        m_link = re.search(
            r'href="https://codeshare\.frida\.re/@([\w\-]+)/([\w\-]+)/"[^>]*>(.*?)</a>',
            block, re.DOTALL
        )
        if not m_link:
            continue
        owner = m_link.group(1)
        slug  = m_link.group(2)
        title = re.sub(r'<[^>]+>', '', m_link.group(3)).strip()

        m_desc  = re.search(r'<p>(.*?)</p>', block, re.DOTALL)
        desc    = re.sub(r'<[^>]+>', '', m_desc.group(1)).strip() if m_desc else ""

        m_likes = re.search(r'fa-thumbs-o-up.*?</i>\s*(\d+)', block, re.DOTALL)
        likes   = int(m_likes.group(1)) if m_likes else 0

        scripts.append({"title": title, "owner": owner, "slug": slug,
                        "desc": desc, "likes": likes})
    return scripts


def _cs_total_pages(html: str) -> int:
    """Detecta o número total de páginas a partir da paginação."""
    import re
    # Paginação: links como ?page=42
    nums = re.findall(r'\?page=(\d+)', html)
    return max((int(n) for n in nums), default=1)


def _cs_fetch_page(page: int) -> str | None:
    import urllib.request
    url = _CS_BROWSE if page == 1 else f"{_CS_BROWSE}?page={page}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _cs_fetch_list(progress_cb=None) -> list[dict]:
    """Scrape todas as páginas do /browse e retorna lista completa de scripts."""
    html1 = _cs_fetch_page(1)
    if not html1:
        return []

    total   = _cs_total_pages(html1)
    scripts = _cs_parse_page(html1)

    if progress_cb:
        progress_cb(1, total)

    for page in range(2, total + 1):
        html = _cs_fetch_page(page)
        if html:
            scripts.extend(_cs_parse_page(html))
        if progress_cb:
            progress_cb(page, total)

    return scripts


def _cs_fetch_source(owner: str, slug: str) -> str | None:
    """Busca o source do script via API."""
    import urllib.request, json
    url = f"{_CS_API}/{owner}/{slug}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("source")
    except Exception:
        return None


def _codeshare_browser():
    """Navega e executa scripts do Frida CodeShare."""
    _clear()
    print(f"{_CYAN}{_BOLD}  Frida CodeShare{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")
    print(f"  {_CYAN}→ Carregando scripts...{_RESET}  {_DIM}(pode levar alguns segundos){_RESET}\n")

    # Carrega com barra de progresso inline
    _progress_buf = [0, 0]

    def _on_progress(page, total):
        _progress_buf[0] = page
        _progress_buf[1] = total
        pct  = int(page / total * 40)
        bar  = "█" * pct + "░" * (40 - pct)
        print(f"\r  [{bar}] {page}/{total} páginas ", end="", flush=True)

    scripts = _cs_fetch_list(progress_cb=_on_progress)
    print()  # quebra linha após barra

    if not scripts:
        print(f"\n  {_RED}✖ Não foi possível carregar o CodeShare. Verifique sua conexão.{_RESET}")
        input("\n→ Enter para continuar...")
        return

    print(f"\n  {_GREEN}✔ {len(scripts)} scripts carregados{_RESET}")
    import time; time.sleep(0.6)

    query    = ""
    selected = 0

    while True:
        _clear()
        print(f"{_CYAN}{_BOLD}  Frida CodeShare{_RESET}  "
              f"{_DIM}↑↓=navegar  Enter=executar  Esc=voltar{_RESET}")
        print(f"{_DIM}{'─' * 78}{_RESET}")
        print(f"  {_WHITE}Busca:{_RESET} {_CYAN}{query}{_RESET}▌\n")

        filtered = [s for s in scripts
                    if query.lower() in s["title"].lower()
                    or query.lower() in s["owner"].lower()
                    or query.lower() in s["slug"].lower()
                    ] if query else scripts

        if selected >= len(filtered):
            selected = max(0, len(filtered) - 1)

        max_vis = 18
        start   = max(0, selected - max_vis // 2)
        visible = filtered[start:start + max_vis]

        if not filtered:
            print(f"  {_DIM}Nenhum script encontrado.{_RESET}")
        else:
            for i, s in enumerate(visible):
                idx   = start + i
                label = s["title"]
                meta  = f"@{s['owner']}"
                likes = f"♥{s.get('likes', 0)}"
                if idx == selected:
                    print(f"  {_SEL_BG} {label:<46} {meta:<18} {likes:<7} {_RESET}")
                else:
                    print(f"  {_DIM}›{_RESET} {_WHITE}{label:<46}{_RESET} {_DIM}{meta:<18} {_CYAN}{likes}{_RESET}")

        if len(filtered) > max_vis:
            print(f"\n  {_DIM}({len(filtered)} scripts — filtre para refinar){_RESET}")
        print(f"\n{_DIM}{'─' * 78}{_RESET}")
        if filtered and selected < len(filtered):
            desc = filtered[selected].get("desc", "")
            if desc:
                print(f"  {_YELLOW}ℹ  {desc[:120]}{_RESET}")

        kind, ch = _getch()
        if kind == "char":
            if ch == _ESC:
                break
            elif ch == _Q and not query:
                break
            elif ch == _ENTER:
                if not filtered:
                    continue
                s = filtered[selected]
                _clear()
                print(f"{_CYAN}{_BOLD}  CodeShare  ›  {s['title']}{_RESET}")
                print(f"  {_DIM}@{s['owner']}  ·  {_CS_BASE}/@{s['owner']}/{s['slug']}{_RESET}")
                print(f"{_DIM}{'─' * 78}{_RESET}\n")
                print(f"  {_CYAN}→ Baixando script...{_RESET}", end="", flush=True)
                source = _cs_fetch_source(s["owner"], s["slug"])
                if not source:
                    print(f"\r  {_RED}✖ Falha ao baixar o script.{_RESET}          ")
                    input("\n→ Enter para continuar...")
                    continue
                print(f"\r  {_GREEN}✔ Script carregado ({len(source)} bytes){_RESET}          ")

                # Salva em temp e executa via frida --codeshare ou -l
                import tempfile
                tmp = Path(tempfile.mktemp(suffix=".js"))
                tmp.write_text(_wrap_source_with_stack(source), encoding="utf-8")

                pkg = _pick_package()
                if pkg:
                    _clear()
                    print(f"{_CYAN}{_BOLD}  CodeShare  ›  {s['title']}  →  {pkg}{_RESET}")
                    print(f"{_DIM}{'─' * 60}{_RESET}\n")
                    print(f"  {_CYAN}Modo de execução:{_RESET}")
                    print(f"  {_GREEN}1.{_RESET} Attach  {_DIM}(app já está aberto — recomendado){_RESET}")
                    print(f"  {_GREEN}2.{_RESET} Spawn   {_DIM}(Frida reinicia o app){_RESET}")
                    print(f"\n  {_DIM}0. Cancelar{_RESET}")
                    cs_mode = input(f"\n  → ").strip()
                    if cs_mode == "0" or not cs_mode:
                        try: tmp.unlink()
                        except Exception: pass
                        continue
                    use_spawn = cs_mode == "2"
                    _clear()
                    print(f"{_CYAN}-> Executando '{s['title']}' em {pkg}...{_RESET}\n")
                    if use_spawn:
                        frida_args = [_frida_bin("frida"), "-U", "-f", pkg, "-l", str(tmp)]
                    else:
                        frida_args = _frida_attach_args(_frida_bin("frida"), pkg, str(tmp))
                        if frida_args is None:
                            input("\n-> Enter para continuar...")
                            try: tmp.unlink()
                            except Exception: pass
                            continue
                    subprocess.run(frida_args)
                    input("\n-> Enter para continuar...")
                try:
                    tmp.unlink()
                except Exception:
                    pass

            elif ch == b"\x08":
                query = query[:-1]; selected = 0
            else:
                try:
                    c = ch.decode("utf-8")
                    if c.isprintable():
                        query += c; selected = 0
                except Exception:
                    pass
        elif kind == "special":
            if ch == _UP:
                selected = max(0, selected - 1)
            elif ch == _DOWN:
                selected = min(len(filtered) - 1, selected + 1) if filtered else 0


# ─── Renderização — navegação estilo explorador de pastas ────────────────────
# Nível 0: lista de categorias
# Nível 1: lista de subcategorias da categoria selecionada
# Nível 2: lista de scripts da subcategoria selecionada

_BREADCRUMB = f"{_DIM}↑↓=navegar  Enter=entrar  ←/q=voltar  Esc=sair{_RESET}"
_W = 60  # largura da lista


def _print_header(breadcrumb: str):
    _clear()
    print(f"{_CYAN}{_BOLD}  Frida Tools{_RESET}  {_DIM}{breadcrumb}{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")


def _print_list(items: list[tuple[str, str]], selected: int, title: str = ""):
    """items = [(label, desc), ...]"""
    if title:
        print(f"  {_CYAN}{title}{_RESET}\n")
    for i, (label, desc) in enumerate(items):
        if i == selected:
            print(f"  {_SEL_BG} {label:<54} {_RESET}")
        else:
            print(f"  {_DIM}{'›':>2}{_RESET} {_WHITE}{label}{_RESET}")
    print(f"\n{_DIM}{'─' * 78}{_RESET}")
    if items:
        _, desc = items[selected]
        print(f"  {_YELLOW}ℹ  {desc}{_RESET}")


# ─── Script Customizado ───────────────────────────────────────────────────────

def _custom_script():
    """Permite colar um script Frida e executá-lo diretamente."""
    import tempfile

    _clear()
    print(f"{_CYAN}{_BOLD}  Script Customizado{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")
    print(f"  {_WHITE}Cole o código do script Frida abaixo.{_RESET}")
    print(f"  {_DIM}Quando terminar, digite uma linha contendo apenas:{_RESET} {_CYAN}END{_RESET}")
    print(f"  {_DIM}Para cancelar, deixe vazio e pressione Enter duas vezes.{_RESET}")
    print(f"\n{_DIM}{'─' * 78}{_RESET}\n")

    lines      = []
    empty_count = 0
    try:
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            if line.strip() == "" and not lines:
                # cancelar se ainda não digitou nada
                empty_count += 1
                if empty_count >= 2:
                    break
            else:
                empty_count = 0
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass

    code = "\n".join(lines).strip()
    if not code:
        print(f"\n  {_DIM}Cancelado.{_RESET}")
        input("\n→ Enter para continuar...")
        return

    print(f"\n  {_GREEN}✔ Script recebido ({len(code)} bytes, {len(lines)} linhas){_RESET}")

    pkg = _pick_package()
    if not pkg:
        return

    tmp = Path(tempfile.mktemp(suffix=".js"))
    tmp.write_text(_wrap_source_with_stack(code), encoding="utf-8")

    _clear()
    print(f"{_CYAN}{_BOLD}  Script Customizado  →  {pkg}{_RESET}")
    print(f"{_DIM}{'─' * 60}{_RESET}\n")
    print(f"  {_CYAN}Modo de execução:{_RESET}")
    print(f"  {_GREEN}1.{_RESET} Attach  {_DIM}(app já está aberto — recomendado){_RESET}")
    print(f"  {_GREEN}2.{_RESET} Spawn   {_DIM}(Frida reinicia o app){_RESET}")
    print(f"\n  {_DIM}0. Cancelar{_RESET}")
    mode = input(f"\n  → ").strip()
    if mode == "0" or not mode:
        try: tmp.unlink()
        except Exception: pass
        return
    use_spawn = mode == "2"

    _clear()
    print(f"{_CYAN}{_BOLD}  Script Customizado  ->  {pkg}{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")
    try:
        if use_spawn:
            subprocess.run([_frida_bin("frida"), "-U", "-f", pkg, "-l", str(tmp)])
        else:
            frida_args = _frida_attach_args(_frida_bin("frida"), pkg, str(tmp))
            if frida_args is None:
                return
            subprocess.run(frida_args)
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass

    input("\n→ Enter para continuar...")


def frida_tool_options():
    try:
        import msvcrt  # noqa
    except ImportError:
        _fallback_menu()
        return

    # estado: nível atual e índices selecionados em cada nível
    level    = 0   # 0=categorias, 1=subcategorias, 2=scripts
    cat_idx  = 0
    sub_idx  = 0
    scr_idx  = 0

    # lista plana de categorias + entradas especiais
    cats = [(c, cd, subs) for c, cd, subs in CATEGORIES]

    # índices das entradas especiais (após as categorias reais)
    _IDX_CODESHARE = len(cats)
    _IDX_CUSTOM    = len(cats) + 1

    def _all_items():
        items = [(c, cd) for c, cd, _ in cats]
        items.append(("__codeshare__", "Navega e executa scripts diretamente do Frida CodeShare (internet)"))
        items.append(("__custom__",    "Cole qualquer script Frida e execute diretamente"))
        return items

    while True:
        # ── Nível 0: Categorias ──────────────────────────────────────────────
        if level == 0:
            _print_header("↑↓=navegar  Enter=entrar  q=sair")
            items = _all_items()
            # label de exibição
            display = []
            for label, desc in items:
                if label == "__codeshare__":
                    display.append(("🌐  CodeShare  (frida.re)", desc))
                elif label == "__custom__":
                    display.append(("✏️   Script Customizado", desc))
                else:
                    display.append((label, desc))
            _print_list(display, cat_idx, "CATEGORIAS")

            kind, ch = _getch()
            if kind == "char":
                if ch in (_Q, _ESC):
                    break
                elif ch == _ENTER:
                    if cat_idx == _IDX_CODESHARE:
                        _codeshare_browser()
                    elif cat_idx == _IDX_CUSTOM:
                        _custom_script()
                    else:
                        level   = 1
                        sub_idx = 0
            elif kind == "special":
                if ch == _UP:
                    cat_idx = (cat_idx - 1) % len(display)
                elif ch == _DOWN:
                    cat_idx = (cat_idx + 1) % len(display)
                elif ch == _RIGHT:
                    if cat_idx == _IDX_CODESHARE:
                        _codeshare_browser()
                    elif cat_idx == _IDX_CUSTOM:
                        _custom_script()
                    else:
                        level   = 1
                        sub_idx = 0

        # ── Nível 1: Subcategorias ───────────────────────────────────────────
        elif level == 1:
            cat_name, cat_desc, subs = cats[cat_idx]
            _print_header(f"↑↓=navegar  Enter=entrar  ←/q=voltar")
            print(f"  {_DIM}Frida Tools  ›  {_RESET}{_CYAN}{_BOLD}{cat_name}{_RESET}\n")
            items = [(s, sd) for s, sd, _ in subs]
            _print_list(items, sub_idx)

            kind, ch = _getch()
            if kind == "char":
                if ch in (_Q, _ESC):
                    level = 0
                elif ch == _ENTER:
                    level   = 2
                    scr_idx = 0
            elif kind == "special":
                if ch == _UP:
                    sub_idx = (sub_idx - 1) % len(subs)
                elif ch == _DOWN:
                    sub_idx = (sub_idx + 1) % len(subs)
                elif ch == _RIGHT:
                    level   = 2
                    scr_idx = 0
                elif ch == _LEFT:
                    level = 0

        # ── Nível 2: Scripts ─────────────────────────────────────────────────
        elif level == 2:
            cat_name, _, subs   = cats[cat_idx]
            sub_name, sub_desc, scripts = subs[sub_idx]
            _print_header(f"↑↓=navegar  Enter=executar  ←/q=voltar")
            print(f"  {_DIM}Frida Tools  ›  {cat_name}  ›  {_RESET}{_CYAN}{_BOLD}{sub_name}{_RESET}\n")
            items = [(e[0], e[3] if len(e) > 3 else "") for e in scripts]
            _print_list(items, scr_idx)

            kind, ch = _getch()
            if kind == "char":
                if ch in (_Q, _ESC):
                    level = 1
                elif ch == _ENTER:
                    entry = scripts[scr_idx]
                    _run_action(entry[2], entry[1])
            elif kind == "special":
                if ch == _UP:
                    scr_idx = (scr_idx - 1) % len(scripts)
                elif ch == _DOWN:
                    scr_idx = (scr_idx + 1) % len(scripts)
                elif ch == _LEFT:
                    level = 1


# ─── Fallback sem msvcrt ──────────────────────────────────────────────────────

def _fallback_menu():
    while True:
        os.system("cls")
        print("\n\033[96mFrida Tools\033[0m\n")
        for i, (cat, sub, scripts) in enumerate(_NAV, 1):
            print(f"  \033[96m{i}.\033[0m \033[97m{cat}\033[0m / \033[90m{sub}\033[0m  ({len(scripts)})")
        print("\n  \033[90m0. Voltar\033[0m")
        choice = input("\n→ Subcategoria: ").strip()
        if choice == "0":
            break
        try:
            cat, sub, scripts = _NAV[int(choice) - 1]
        except (ValueError, IndexError):
            continue

        while True:
            os.system("cls")
            print(f"\n\033[96mFrida Tools\033[0m  ›  \033[97m{cat}\033[0m / \033[96m{sub}\033[0m\n")
            for i, entry in enumerate(scripts, 1):
                desc = entry[3] if len(entry) > 3 else ""
                print(f"  \033[96m{i}.\033[0m {entry[0]}")
                print(f"     \033[90m{desc}\033[0m")
            print("\n  \033[90m0. Voltar\033[0m")
            choice2 = input("\n→ Script: ").strip()
            if choice2 == "0":
                break
            try:
                entry = scripts[int(choice2) - 1]
                _run_action(entry[2], entry[1])
            except (ValueError, IndexError):
                continue
