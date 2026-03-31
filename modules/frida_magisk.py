import sys
import time
import subprocess
import requests
from pathlib import Path
from utils.common import clear_screen
from core.env_check import _adb_exe


def _adb(args: list) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe()] + args, capture_output=True, text=True)


def _adb_shell(cmd: str) -> subprocess.CompletedProcess:
    """Executa via adb shell direto (já root após adb root)."""
    return subprocess.run([_adb_exe(), "shell", cmd], capture_output=True, text=True)


def _wait_for_boot(timeout: int = 180):
    """
    Aguarda o boot completo verificando múltiplos sinais:
    - sys.boot_completed = 1
    - init.svc.bootanim = stopped  (animação de boot terminou)
    - dev.bootcomplete = 1
    Mais confiável que tempo fixo — evita problemas de input/UI no Nox.
    """
    spinner = ["|", "/", "-", "\\"]
    elapsed = 0

    # Primeiro aguarda o ADB responder (emulador pode estar offline logo após reboot)
    print("  \033[90mAguardando ADB ficar disponível...\033[0m")
    for _ in range(40):
        try:
            r = subprocess.run([_adb_exe(), "devices"], capture_output=True, text=True, timeout=5)
            if "device" in r.stdout and "offline" not in r.stdout:
                break
        except Exception:
            pass
        time.sleep(2)

    # Aguarda todos os sinais de boot
    print("  \033[90mAguardando boot completo...\033[0m")
    while elapsed < timeout:
        spin = spinner[(elapsed // 2) % len(spinner)]
        sys.stdout.write(f"\r  {spin} {elapsed}s / {timeout}s máx")
        sys.stdout.flush()

        try:
            def _prop(p):
                r = subprocess.run(
                    [_adb_exe(), "shell", "getprop", p],
                    capture_output=True, text=True, timeout=5
                )
                return r.stdout.strip()

            boot_done    = _prop("sys.boot_completed") == "1"
            bootanim     = _prop("init.svc.bootanim") == "stopped"
            dev_boot     = _prop("dev.bootcomplete") == "1"

            if boot_done and bootanim and dev_boot:
                print(f"\r  \033[92m✔ Boot completo em {elapsed}s                \033[0m")
                # Aguarda extra para o InputMethodService e SurfaceFlinger estabilizarem
                print("  \033[90mAguardando UI estabilizar...\033[0m", end="", flush=True)
                time.sleep(12)
                print(f"\r  \033[92m✔ UI pronta.                              \033[0m")
                return
        except Exception:
            pass

        time.sleep(2)
        elapsed += 2

    print(f"\r  \033[93m⚠ Timeout ({timeout}s) — continuando mesmo assim\033[0m")
    # Mesmo no timeout, aguarda um pouco mais para a UI
    time.sleep(10)


def _check_frida_running() -> bool:
    """
    Verifica se o frida-server está rodando no dispositivo.
    Tenta até 3 vezes com intervalo de 3s (pode demorar para subir).
    """
    print("\033[96m→ Verificando frida-server...\033[0m")
    for attempt in range(1, 4):
        r = _adb_shell("pgrep -x frida-server")
        pid = r.stdout.strip()
        if pid:
            print(f"  \033[92m✔ frida-server rodando (PID: {pid})\033[0m")
            return True
        if attempt < 3:
            print(f"  \033[90m  tentativa {attempt}/3 — aguardando 3s...\033[0m")
            time.sleep(3)

    # Não está rodando — tentar iniciar manualmente
    print("  \033[93m⚠ frida-server não detectado. Tentando iniciar manualmente...\033[0m")
    _adb_shell("mafrida start")
    time.sleep(3)
    r = _adb_shell("pgrep -x frida-server")
    if r.stdout.strip():
        print(f"  \033[92m✔ frida-server iniciado (PID: {r.stdout.strip()})\033[0m")
        return True

    print("  \033[91m✖ frida-server não iniciou.\033[0m")
    print("  \033[90m  Verifique: Magisk → Módulos → MaFrida está ativo?\033[0m")
    print("  \033[90m  Tente: adb shell mafrida start\033[0m")
    return False


def _get_latest_frida_version() -> str:
    try:
        r = requests.get("https://api.github.com/repos/frida/frida/releases/latest", timeout=10)
        r.raise_for_status()
        return r.json()["tag_name"].lstrip("v")
    except Exception:
        return "16.7.0"


def _get_local_frida_version() -> str | None:
    """Retorna a versão do frida-server rodando no dispositivo, ou None se não estiver rodando."""
    r = _adb_shell("frida-server --version 2>/dev/null")
    ver = r.stdout.strip()
    if ver and ver[0].isdigit():
        return ver
    return None


def check_frida_update():
    """
    Verifica se o frida-server está desatualizado.
    Se estiver, atualiza automaticamente via mafrida e confirma que subiu.
    Chamado no início do script, após o boot do emulador.
    """
    # Só verifica se o frida-server está rodando
    r = _adb_shell("pgrep -x frida-server")
    if not r.stdout.strip():
        return  # Não instalado ainda — sem ação

    print("\033[96m→ Verificando atualização do frida-server...\033[0m", end="", flush=True)

    local_ver  = _get_local_frida_version()
    latest_ver = _get_latest_frida_version()

    if not local_ver:
        print(f" \033[90mversão local não detectada\033[0m")
        return

    if local_ver == latest_ver:
        print(f" \033[92m✔ {local_ver} (atualizado)\033[0m")
        return

    print(f"\n  \033[93m⚠ Desatualizado: {local_ver} → {latest_ver}\033[0m")
    print("  \033[96m→ Atualizando frida-server...\033[0m")

    cmds = [
        ("mafrida kill",                "Parando frida-server"),
        (f"mafrida --set {latest_ver}", f"Definindo versão {latest_ver}"),
        ("mafrida download",            "Baixando frida-server"),
        ("mafrida start",               "Iniciando frida-server"),
    ]
    for cmd, label in cmds:
        print(f"  \033[90m→ {label}...\033[0m", end="", flush=True)
        _adb_shell(cmd)
        print(" \033[92m✔\033[0m")

    # Confirma que o novo frida-server subiu corretamente
    print()
    _check_frida_running()


def install_magisk_frida_module():
    clear_screen()
    print("\033[96m→ Instalando Módulo MaFrida\033[0m\n")
    print("\033[93mPré-requisitos:\033[0m")
    print("  - Magisk (Kitsune) já instalado e ativo")
    print("  - Zygisk ativado nas configurações do Magisk\n")
    input("→ Pressione Enter para continuar...")

    try:
        # 1. Baixar MaFrida
        print("\n\033[96m→ Buscando versão mais recente do MaFrida...\033[0m")
        response = requests.get(
            "https://api.github.com/repos/theShinigami/MaFrida/releases/latest",
            timeout=10
        )
        response.raise_for_status()
        latest = response.json()
        version = latest['tag_name']
        zip_name = ""
        download_url = ""

        for asset in latest['assets']:
            if asset['name'].endswith(".zip"):
                zip_name = asset['name']
                download_url = asset['browser_download_url']
                break

        if not download_url:
            raise Exception("Módulo .zip não encontrado na release.")

        print(f"\033[96m→ Baixando MaFrida {version}...\033[0m")
        r = requests.get(download_url, timeout=60)
        r.raise_for_status()
        zip_path = Path(zip_name)
        zip_path.write_bytes(r.content)
        print(f"  \033[92m✔ Download concluído: {zip_name}\033[0m")

        # 2. Push para o dispositivo
        print("\033[96m→ Enviando para o dispositivo...\033[0m")
        result = subprocess.run([_adb_exe(), "push", str(zip_path), f"/sdcard/Download/{zip_name}"])
        if result.returncode != 0:
            raise Exception("Falha no adb push.")
        print("  \033[92m✔ Arquivo enviado\033[0m")

        # 3. Instalar módulo via Magisk
        print("\033[96m→ Instalando módulo no Magisk...\033[0m")
        r2 = _adb_shell(f"magisk --install-module /sdcard/Download/{zip_name}")
        if r2.returncode != 0 and "Success" not in r2.stdout:
            print(f"  \033[93m⚠ {r2.stdout.strip() or r2.stderr.strip()}\033[0m")
        else:
            print("  \033[92m✔ Módulo instalado\033[0m")

        # 4. Reboot manual
        print("\n\033[93m→ Reinicie o emulador manualmente para ativar o módulo.\033[0m")
        input("→ Pressione Enter após reiniciar e o boot estiver completo...")

        # 6. Configurar frida-server via mafrida
        print("\n\033[96m→ Obtendo versão mais recente do Frida...\033[0m")
        frida_ver = _get_latest_frida_version()
        print(f"  \033[92m✔ Versão: {frida_ver}\033[0m")

        print("\033[96m→ Configurando MaFrida...\033[0m")
        cmds = [
            ("mafrida kill",               "Parando frida-server anterior"),
            (f"mafrida --set {frida_ver}", f"Definindo versão {frida_ver}"),
            ("mafrida download",           "Baixando frida-server"),
            ("mafrida start",              "Iniciando frida-server"),
            ("mafrida enable",             "Ativando auto-start"),
        ]
        for cmd, label in cmds:
            print(f"  \033[90m→ {label}...\033[0m", end="", flush=True)
            _adb_shell(cmd)
            print(f" \033[92m✔\033[0m")

        # 7. Verificar se frida-server está rodando
        print()
        _check_frida_running()

        print("\n\033[92m✔ MaFrida configurado com sucesso!\033[0m")
        print("\033[90m  frida-server iniciará automaticamente a cada boot.\033[0m")

        zip_path.unlink(missing_ok=True)

    except Exception as e:
        print(f"\n\033[91m✖ Falha: {e}\033[0m")

    input("\n→ Pressione Enter para continuar...")
    clear_screen()
