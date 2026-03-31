# -*- coding: utf-8 -*-
import os
import sys
import shutil
import time
import zipfile
import subprocess
import urllib.request
from pathlib import Path

from utils.common import clear_screen

ADB_TOOLS_URL = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

_LOCAL_APPDATA = Path.home() / "AppData" / "Local"
ADB_INSTALL_DIR = _LOCAL_APPDATA / "NoxDroid" / "platform-tools"

# Nox usa porta 62025 (instância principal), 62001, 62026 para extras
EMULATOR_PORTS = {
    "nox": [62025, 62001, 62026],
}

_NOX_SEARCH_PATHS = [
    Path(os.environ.get("PROGRAMFILES",      "C:/Program Files"))       / "Nox" / "bin",
    Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Nox" / "bin",
    Path("C:/Program Files/Nox/bin"),
    Path("C:/Program Files (x86)/Nox/bin"),
    Path("D:/Program Files/Nox/bin"),
    Path("D:/Nox/bin"),
]

_ADB_COMMON_PATHS = [
    _LOCAL_APPDATA / "NoxDroid" / "platform-tools",
    _LOCAL_APPDATA / "Android" / "Sdk" / "platform-tools",
]

# Cache para evitar re-detecção a cada chamada
_nox_adb_cache: str | None = None
_adb_cache:     str | None = None

# Emulador ativo — setado por initial_environment_check
_active_emulator: str = "nox"


# ─── Interface pública ────────────────────────────────────────────────────────

def _adb_exe(emulator: str | None = None) -> str:
    """Retorna o executavel ADB para o dispositivo ativo."""
    from core.device_detect import get_adb
    return get_adb()


def _persist_path(directory: str):
    """Adiciona directory ao PATH do usuário via PowerShell (fire-and-forget)."""
    ps = (
        f'$p = [Environment]::GetEnvironmentVariable("PATH","User");'
        f'if ($p -notlike "*{directory}*") {{'
        f'  [Environment]::SetEnvironmentVariable("PATH", $p + ";{directory}", "User")'
        f'}}'
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
    except Exception:
        pass


def _open_env_vars_panel(directory: str, label: str):
    """Mostra instruções e abre o painel de Variáveis de Ambiente."""
    print()
    print("\033[93m" + "=" * 64 + "\033[0m")
    print(f"\033[93m   AÇÃO NECESSÁRIA: Adicione o {label} ao PATH do sistema\033[0m")
    print("\033[93m" + "=" * 64 + "\033[0m")
    print(f"\n  \033[96mCaminho:\033[0m  \033[92m{directory}\033[0m")
    print("  \033[90m(copiado para a área de transferência)\033[0m")
    print()
    print("  1. Na janela que vai abrir → 'Variáveis do Sistema'")
    print("  2. Selecione  Path  → Editar → Novo → cole o caminho")
    print("  3. OK em tudo → feche este terminal → abra um novo → rode o script")
    print()
    input("  -> Pressione Enter para abrir as Variáveis de Ambiente...")
    try:
        subprocess.Popen(["rundll32.exe", "sysdm.cpl,EditEnvironmentVariables"])
    except Exception:
        print("  Abra manualmente: Painel de Controle → Sistema → Variáveis de Ambiente")
    input("\n  -> Pressione Enter para sair...")
    sys.exit(0)

def _download_adb():
    """Baixa e extrai o platform-tools via urllib (fallback se nox_adb não for encontrado)."""
    ADB_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = ADB_INSTALL_DIR.parent / "platform-tools.zip"
    adb_exe  = ADB_INSTALL_DIR / "adb.exe"

    if not adb_exe.exists():
        print("\n\033[96m-> Baixando Android Platform-Tools (Google)...\033[0m")
        print(f"\033[90m   Destino: {ADB_INSTALL_DIR}\033[0m\n")

        try:
            def _progress(block, block_size, total):
                if total > 0:
                    done = min(block * block_size, total)
                    pct  = int(done * 40 / total)
                    bar  = "#" * pct + "." * (40 - pct)
                    print(f"\r   [{bar}] {done // 1024}KB / {total // 1024}KB", end="", flush=True)
            urllib.request.urlretrieve(ADB_TOOLS_URL, zip_path, reporthook=_progress)
            print()
        except Exception as e:
            print(f"\n\033[91m[ERRO] Falha no download: {e}\033[0m")
            input("\n-> Pressione Enter para sair...")
            sys.exit(1)

        if not zip_path.exists() or zip_path.stat().st_size < 1_000_000:
            print("\033[91m[ERRO] Download inválido ou incompleto.\033[0m")
            zip_path.unlink(missing_ok=True)
            input("\n-> Pressione Enter para sair...")
            sys.exit(1)

        print("\033[96m-> Extraindo...\033[0m")
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(ADB_INSTALL_DIR.parent)
            zip_path.unlink(missing_ok=True)
        except zipfile.BadZipFile:
            print("\033[91m[ERRO] Arquivo zip corrompido.\033[0m")
            zip_path.unlink(missing_ok=True)
            input("\n-> Pressione Enter para sair...")
            sys.exit(1)

        if not adb_exe.exists():
            print(f"\033[91m[ERRO] adb.exe não encontrado após extração em: {ADB_INSTALL_DIR}\033[0m")
            input("\n-> Pressione Enter para sair...")
            sys.exit(1)

        print(f"\033[92m[OK] ADB extraído em: {ADB_INSTALL_DIR}\033[0m")
    else:
        print(f"\033[92m[OK] ADB já extraído em: {ADB_INSTALL_DIR}\033[0m")

    _persist_path(str(ADB_INSTALL_DIR))
    _open_env_vars_panel(str(ADB_INSTALL_DIR), "ADB")


def _fix_nox_adb_path():
    """
    Detecta o diretório do nox_adb.exe e persiste no PATH do sistema.
    Abre o painel de Variáveis de Ambiente para o usuário confirmar.
    """
    nox_adb = _find_nox_adb()
    if not nox_adb:
        return

    nox_dir = str(Path(nox_adb).parent)

    # Já está no PATH — nada a fazer
    if shutil.which("nox_adb"):
        return

    print(f"\n\033[96m→ Adicionando nox_adb ao PATH do sistema...\033[0m")
    print(f"  \033[90mCaminho detectado: {nox_dir}\033[0m")

    _persist_path(nox_dir)
    _open_env_vars_panel(nox_dir, "nox_adb")


# ─── Checks de sistema ────────────────────────────────────────────────────────

def check_python() -> tuple[bool, str]:
    if "Microsoft\\WindowsApps\\python.exe" in sys.executable:
        return False, "Instale o Python em python.org (não pela Microsoft Store)."
    return True, "Python instalado."


def check_python_path() -> tuple[bool, str]:
    if not shutil.which("python"):
        return False, "Adicione o Python ao PATH do sistema."
    return True, "Python no PATH."


def _find_frida_scripts_dir() -> Path | None:
    """Localiza o diretório Scripts onde frida/frida-ps estão instalados."""
    # 1. Já no PATH
    if shutil.which("frida"):
        return None  # já ok, sem necessidade de corrigir

    # 2. user-base/Scripts (pip install --user / Microsoft Store Python)
    try:
        r = subprocess.run(
            [sys.executable, "-m", "site", "--user-base"],
            capture_output=True, text=True, timeout=5
        )
        user_base = Path(r.stdout.strip())
        for sub in [
            f"Python{sys.version_info.major}{sys.version_info.minor}\\Scripts",
            "Scripts",
        ]:
            candidate = user_base / sub / "frida.exe"
            if candidate.exists():
                return candidate.parent
    except Exception:
        pass

    # 3. site-packages/../Scripts (instalação global)
    try:
        import site
        for sp in site.getsitepackages():
            candidate = Path(sp).parent / "Scripts" / "frida.exe"
            if candidate.exists():
                return candidate.parent
    except Exception:
        pass

    return None


def _fix_frida_path() -> bool:
    """
    Adiciona o diretório Scripts do frida ao PATH da sessão atual e
    persiste no PATH do usuário via PowerShell.
    Retorna True se corrigiu, False se não encontrou.
    """
    scripts_dir = _find_frida_scripts_dir()
    if scripts_dir is None:
        return shutil.which("frida") is not None  # já estava no PATH

    scripts_str = str(scripts_dir)

    # Adiciona na sessão atual
    os.environ["PATH"] = scripts_str + os.pathsep + os.environ.get("PATH", "")

    # Persiste no PATH do usuário (fire-and-forget)
    ps = (
        f'$p = [Environment]::GetEnvironmentVariable("PATH","User");'
        f'if ($p -notlike "*{scripts_str}*") {{'
        f'  [Environment]::SetEnvironmentVariable("PATH", $p + ";{scripts_str}", "User")'
        f'}}'
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000
        )
    except Exception:
        pass

    return shutil.which("frida") is not None


def check_frida_cli() -> tuple[bool, str]:
    """Verifica se frida/frida-ps estão acessíveis no PATH. Tenta corrigir e instalar automaticamente."""
    if shutil.which("frida"):
        import importlib.metadata
        try:
            ver = importlib.metadata.version("frida-tools")
            return True, f"frida-tools v{ver}"
        except Exception:
            return True, "frida-tools ok"

    # Tenta corrigir o PATH primeiro
    fixed = _fix_frida_path()
    if fixed:
        import importlib.metadata
        try:
            ver = importlib.metadata.version("frida-tools")
            return True, f"frida-tools v{ver} (PATH corrigido)"
        except Exception:
            return True, "frida-tools ok (PATH corrigido)"

    # Tenta instalar automaticamente via pip
    try:
        import importlib.metadata
        importlib.metadata.version("frida-tools")
        # Está instalado mas não no PATH — tenta corrigir de novo após import
        _fix_frida_path()
        if shutil.which("frida"):
            ver = importlib.metadata.version("frida-tools")
            return True, f"frida-tools v{ver} (PATH corrigido)"
    except importlib.metadata.PackageNotFoundError:
        pass

    # Instala agora
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "frida-tools"],
        capture_output=True
    )
    if result.returncode == 0:
        _fix_frida_path()
        import importlib.metadata
        try:
            ver = importlib.metadata.version("frida-tools")
            return True, f"frida-tools v{ver} (instalado automaticamente)"
        except Exception:
            return True, "frida-tools instalado"

    return False, "frida-tools: falha na instalação automática"


def check_adb_for(emulator: str = "nox") -> tuple[bool, str]:
    from core.device_detect import _find_nox_adb, _find_generic_adb
    nox = _find_nox_adb()
    if nox:
        return True, f"nox_adb: {nox}"
    generic = _find_generic_adb()
    if generic and generic != "adb":
        return True, f"adb: {generic}"
    # adb no PATH?
    if shutil.which("adb"):
        return True, f"adb: {shutil.which('adb')}"
    return False, "ADB nao encontrado (instale platform-tools ou Nox Player)"


def _run_system_checks(emulator: str) -> bool:
    spinner = ["|", "/", "-", "\\"]
    checks = [
        ("Python",      check_python),
        ("Python PATH", check_python_path),
        ("frida-tools", check_frida_cli),
        ("ADB",         lambda: check_adb_for(emulator)),
    ]
    results = []
    for i, (name, chk) in enumerate(checks):
        for j in range(6):
            sys.stdout.write(f"\r  \033[96m{name:<15}\033[0m {spinner[(i * 2 + j) % len(spinner)]}")
            sys.stdout.flush()
            time.sleep(0.1)
        ok, det = chk()
        results.append((name, ok, det))
        icon = "\033[92m[OK]\033[0m" if ok else "\033[91m[X]\033[0m"
        print(f"\r  {icon} \033[96m{name:<15}\033[0m {det}")
    return all(ok for _, ok, _ in results)


# ─── Entry point ─────────────────────────────────────────────────────────────

def initial_environment_check(emulator: str = "auto"):
    global _active_emulator
    _active_emulator = emulator

    # ── Termo de uso — exibe uma unica vez ────────────────────────────────────
    from core.banner import show_terms, terms_already_accepted, mark_terms_accepted
    if not terms_already_accepted():
        show_terms()
        mark_terms_accepted()

    clear_screen()
    print("\033[96m" + "=" * 46 + "\033[0m")
    print("\033[96m\033[1m     NoxDroid  --  Inicializando\033[0m")
    print("\033[96m" + "=" * 46 + "\033[0m\n")

    # ── [1/3] Dependencias Python ─────────────────────────────────────────────
    print("\033[96m[1/3] Dependencias\033[0m")
    from core.deps import check_and_update_all_deps, install_external_tools
    check_and_update_all_deps()
    install_external_tools()

    # ── [2/3] Sistema ─────────────────────────────────────────────────────────
    print("\n\033[96m[2/3] Sistema\033[0m")
    _run_system_checks(emulator)

    frida_ok, _ = check_frida_cli()
    if not frida_ok:
        print("\n\033[93m-> frida-tools nao encontrado no PATH -- instalando...\033[0m")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "frida-tools"],
            capture_output=True
        )
        _fix_frida_path()
        frida_ok, _ = check_frida_cli()
        if not frida_ok:
            print("\033[91m[ERRO] Nao foi possivel instalar frida-tools automaticamente.\033[0m")
            print("\033[93m  Execute manualmente: pip install frida-tools\033[0m")
            input("\n-> Pressione Enter para sair...")
            sys.exit(1)

    adb_ok, _ = check_adb_for(emulator)
    if not adb_ok:
        print("\n\033[93m[!] ADB nao encontrado — baixando platform-tools...\033[0m")
        _download_adb()

    # ── [3/3] Dispositivo ─────────────────────────────────────────────────────
    print("\n\033[96m[3/3] Dispositivo\033[0m")
    from core.device_detect import select_device, DEVICE

    connected = select_device()

    if connected:
        dtype = DEVICE.get("type", "")
        # Debloat apenas para Nox
        if dtype == "nox":
            from modules.debloat import debloat_already_done, run_debloat
            if not debloat_already_done():
                run_debloat(emulator="nox")

        # Verifica/atualiza frida-server apenas no Nox (usa mafrida)
        # Dispositivo fisico usa MagiskFrida — gerenciado pelo proprio modulo Magisk
        if dtype == "nox":
            from modules.frida_magisk import check_frida_update
            check_frida_update()
    else:
        print("\033[93m  Continuando sem dispositivo — funcionalidades dinamicas indisponiveis.\033[0m")

    print("\n\033[96m-> Carregando menu...\033[0m")
    input("\033[90m   (Pressione Enter para continuar)\033[0m")
    time.sleep(0.3)
