import subprocess
from pathlib import Path
from utils.common import clear_screen
from core.env_check import _adb_exe

LOCAL_APK      = Path(__file__).parent.parent / "kitsune.apk"
MT_MANAGER_APK = Path(__file__).parent.parent / "MT Manager.apk"


def _adb(args: list) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe()] + args, capture_output=True, text=True)


def _install_mt():
    """Instala o MT Manager silenciosamente (usado como pré-requisito do Magisk no Nox)."""
    if not MT_MANAGER_APK.exists():
        print(f"  \033[91m✖ MT Manager.apk não encontrado na raiz do projeto.\033[0m")
        return False
    result = subprocess.run([_adb_exe(), "install", "-r", str(MT_MANAGER_APK)],
                            capture_output=True, text=True)
    if result.returncode == 0:
        print("  \033[92m✔ MT Manager instalado.\033[0m")
        return True
    print(f"  \033[91m✖ Falha ao instalar MT Manager (código {result.returncode})\033[0m")
    return False


def _prepare_sbin_nox():
    """
    Prepara o /sbin para instalação do Magisk no Nox.
    O /sbin é um tmpfs separado — precisa remontar o rootfs como rw,
    limpar o conteúdo e recriar vazio.
    """
    print("\033[96m→ Preparando /sbin para o Magisk...\033[0m")

    r = _adb(["root"])
    if r.returncode != 0 and "already running as root" not in r.stdout:
        print(f"  \033[91m✖ Falha ao obter root ADB: {r.stdout.strip()}\033[0m")
        return False
    print("  \033[92m✔ Root ADB ativo\033[0m")

    # Remontar / e /system como rw
    _adb(["remount"])
    _adb(["shell", "mount -o rw,remount /"])
    _adb(["shell", "mount -o rw,remount /system"])
    print("  \033[92m✔ Partições remontadas\033[0m")

    # Apagar conteúdo do /sbin (não o diretório — pode ser mountpoint)
    r = _adb(["shell", "ls /sbin"])
    files = r.stdout.strip().splitlines()
    if files:
        for f in files:
            f = f.strip()
            if f:
                _adb(["shell", f"rm -f /sbin/{f}"])
        print(f"  \033[92m✔ Conteúdo de /sbin limpo ({len(files)} itens)\033[0m")
    else:
        print("  \033[92m✔ /sbin já está vazio\033[0m")

    # Garantir permissões corretas no diretório
    _adb(["shell", "chmod 755 /sbin"])
    print("  \033[92m✔ /sbin pronto\033[0m")

    return True


def _install_apk(apk_path: str):
    adb = _adb_exe()
    print(f"\n\033[96m→ Instalando APK no emulador...\033[0m")
    result = subprocess.run([adb, "install", "-r", apk_path])
    if result.returncode != 0:
        print(f"\033[91m✖ Falha ao instalar APK (código {result.returncode})\033[0m")
        return False

    print("\n\033[92m✔ Magisk instalado com sucesso!\033[0m\n")
    print("\033[93m→ Próximos passos:\033[0m")
    print("  1. Abra o app 'Magisk' no emulador")
    print("  2. Toque em 'Instalar Magisk'")
    print("  3. Escolha 'Direct Install (modify/system direct)'")
    print("  4. Após instalar, DESATIVE o Root nas configurações do Nox")
    print("  5. Reinicie o emulador\n")
    return True


def install_kitsune_magisk(emulator: str = "nox"):
    clear_screen()
    print(f"\033[96m→ Instalando Magisk (Kitsune) no Nox Player\033[0m\n")

    print("\033[93mPré-requisitos:\033[0m")
    print("  - Root ativado nas configurações do emulador")
    print("  - MT Manager instalado e com permissão root concedida\n")

    input("→ Pressione Enter para continuar...")

    print()
    print("\033[96m→ Passo 1/3: Instalando MT Manager...\033[0m")
    _install_mt()
    print()
    print("\033[93m→ Abra o MT Manager no emulador, conceda root e feche.\033[0m")
    input("→ Pressione Enter quando estiver pronto...")
    print()
    print("\033[96m→ Passo 2/3: Preparando /sbin...\033[0m")
    ok = _prepare_sbin_nox()
    if not ok:
        print("\033[91m✖ Falha na preparação. Verifique se o Root está ativado no Nox.\033[0m")
        input("\n→ Pressione Enter para voltar...")
        return
    print()
    print("\033[96m→ Passo 3/3: Instalando Magisk...\033[0m")

    if not LOCAL_APK.exists():
        print(f"\033[91m✖ kitsune.apk não encontrado na raiz do projeto.\033[0m")
        print(f"\033[93m→ Coloque o arquivo 'kitsune.apk' em: {LOCAL_APK.parent}\033[0m")
        input("\n→ Pressione Enter para voltar...")
        return

    print(f"\033[92m✔ Usando APK local: {LOCAL_APK.name}\033[0m")
    _install_apk(str(LOCAL_APK))

    input("→ Pressione Enter para continuar...")
    clear_screen()

