import subprocess
import tempfile
import requests
from pathlib import Path
from core.env_check import _adb_exe

BLOATWARE = [
    "/system/app/AmazeFileManager",
    "/system/app/AppStore",
    "/system/app/CtsShimPrebuilt",
    "/system/app/EasterEgg",
    "/system/app/Facebook",
    "/system/app/Helper",
    "/system/app/LiveWallpapersPicker",
    "/system/app/PrintRecommendationService",
    "/system/app/PrintSpooler",
    "/system/app/WallpaperBackup",
    "/system/app/newAppNameEn",
]

FILE_MANAGER_URL = "https://aggressiveuser.github.io/food/fmanager.apk"
LAUNCHER_URL     = "https://aggressiveuser.github.io/food/rootless.apk"
AURORA_STORE_URL = "https://gitlab.com/api/v4/projects/AuroraOSS%2FAuroraStore/releases"

# Flag salva na raiz do projeto — persiste entre execuções
_FLAG_FILE = Path(__file__).parent.parent / ".debloat_done"


def _get_aurora_apk_url() -> str | None:
    """Busca a URL do APK mais recente da Aurora Store no GitLab."""
    try:
        r = requests.get(AURORA_STORE_URL, timeout=10)
        r.raise_for_status()
        for release in r.json():
            for asset in release.get("assets", {}).get("links", []):
                if asset["name"].endswith(".apk") and "preload" not in asset["name"]:
                    return asset["url"]
    except Exception:
        pass
    return "https://gitlab.com/AuroraOSS/AuroraStore/-/releases/permalink/latest/downloads/app-release.apk"


def debloat_already_done() -> bool:
    return _FLAG_FILE.exists()


def _mark_done():
    _FLAG_FILE.touch()


def _adb(args: list) -> int:
    return subprocess.run([_adb_exe()] + args).returncode


def _adb_shell(cmd: str) -> int:
    r = subprocess.run([_adb_exe(), "shell", cmd], capture_output=True, text=True)
    return r.returncode


def _step(label: str):
    print(f"\n\033[96m→ {label}\033[0m")


def _download_apk(url: str, name: str) -> str | None:
    dest = Path(tempfile.gettempdir()) / name
    if dest.exists():
        return str(dest)
    print(f"  Baixando {name}...", end="", flush=True)
    try:
        r = requests.get(url, timeout=30, stream=True)
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        print(f" \033[92m✔\033[0m")
        return str(dest)
    except Exception as e:
        print(f" \033[91m✖ {e}\033[0m")
        return None


def _install_apk_from_pc(url: str, filename: str, remote_path: str) -> bool:
    local = _download_apk(url, filename)
    if not local:
        return False
    adb = _adb_exe()
    r = subprocess.run([adb, "push", local, remote_path])
    if r.returncode != 0:
        print(f"  \033[91m✖ Falha no push para {remote_path}\033[0m")
        return False
    r = subprocess.run([adb, "shell", "pm", "install", "-r", remote_path])
    if r.returncode == 0:
        print(f"  \033[92m✔ Instalado com sucesso.\033[0m")
        return True
    print(f"  \033[91m✖ Falha ao instalar.\033[0m")
    return False


def run_debloat(emulator: str = "nox"):
    """Executa o debloat. Chamado automaticamente na primeira inicialização."""
    from utils.common import clear_screen
    from core.banner import display_banner

    clear_screen()
    display_banner()

    print(f"\n\033[96m[ Configuração Inicial — Debloat ]\033[0m")
    print(f"\033[90m  Esta etapa é executada uma única vez.\033[0m\n")
    print(f"  Emulador: Nox Player")
    print("  - Remove bloatware e anúncios do sistema")
    print("  - Instala File Manager e Rootless Launcher")
    print()
    print("\033[93mPré-requisitos:\033[0m")
    print("  - Root ativado no emulador")
    print("  - Conexão com a internet")
    print()
    print("\033[91mAtenção: remove apps do sistema permanentemente.\033[0m")

    confirm = input("\n→ Executar agora? [s/N]: ").strip().lower()
    if confirm != "s":
        print("\033[93m  Pulado. Você pode executar depois pelo menu se necessário.\033[0m")
        # Marca como feito mesmo se pulado — não pergunta de novo
        _mark_done()
        input("\n→ Pressione Enter para continuar...")
        return

    _step("Obtendo root e remontando /system...")
    _adb(["root"])
    _adb(["remount"])

    _step("Removendo bloatware e anúncios...")
    removed = 0
    for path in BLOATWARE:
        if _adb_shell(f"rm -rf {path}") == 0:
            removed += 1
            print(f"  \033[90m✔ {path}\033[0m")
    print(f"  \033[92m✔ {removed}/{len(BLOATWARE)} entradas removidas.\033[0m")

    _step("Instalando File Manager...")
    _install_apk_from_pc(FILE_MANAGER_URL, "fmanager.apk", "/data/local/tmp/fmanager.apk")

    _step("Instalando Rootless Launcher...")
    _install_apk_from_pc(LAUNCHER_URL, "rootless.apk", "/data/local/tmp/rootless.apk")

    _step("Instalando Aurora Store...")
    aurora_url = _get_aurora_apk_url()
    if aurora_url:
        _install_apk_from_pc(aurora_url, "aurora.apk", "/data/local/tmp/aurora.apk")
    else:
        print("  \033[91m✖ Não foi possível obter URL da Aurora Store.\033[0m")

    _step("Reiniciando emulador...")
    print("  \033[93m→ Reinicie o emulador manualmente agora.\033[0m")
    print("  \033[90m  Após reiniciar, selecione o Rootless Launcher como padrão.\033[0m")

    _mark_done()
    print("\n\033[92m✔ Debloat concluído. Esta etapa não será repetida.\033[0m")
    input("\n→ Pressione Enter para continuar...")
