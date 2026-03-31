"""
proxy_switch.py — Gerencia proxy HTTP no emulador Android (Nox Player)

Auto-detecta o IP local do PC para facilitar interceptação com Burp Suite.
Aplica o proxy via múltiplos métodos para garantir compatibilidade com Nox.
"""
import socket
import subprocess
from core.env_check import _adb_exe

_R  = "\033[0m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[90m"
_W  = "\033[97m"
_B  = "\033[1m"


def _adb(args: list) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe()] + args, capture_output=True, text=True)


def _adb_su(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe(), "shell", "su", "-c", cmd],
                          capture_output=True, text=True)


def _get_local_ip() -> str:
    """Detecta o IP local do PC na rede (não loopback)."""
    try:
        # Abre socket UDP sem enviar nada — só para descobrir a interface de saída
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_current_proxy() -> str | None:
    r = _adb(["shell", "settings", "get", "global", "http_proxy"])
    val = r.stdout.strip()
    if val and val not in ("null", ":0", ""):
        return val
    return None


def _set_proxy(host: str, port: str) -> bool:
    addr = f"{host}:{port}"

    # 1. settings put global (padrão Android)
    _adb(["shell", "settings", "put", "global", "http_proxy", addr])

    # 2. via su (garante permissão em builds restritos)
    _adb_su(f"settings put global http_proxy {addr}")

    # 3. setprop — Nox usa isso internamente para roteamento
    _adb_su(f"setprop net.gprs.http-proxy {addr}")
    _adb_su(f"setprop net.eth0.http-proxy {addr}")
    _adb_su(f"setprop http.proxyHost {host}")
    _adb_su(f"setprop http.proxyPort {port}")

    # 4. WiFi proxy via settings (Android 4.3+)
    _adb_su(f"settings put global global_http_proxy_host {host}")
    _adb_su(f"settings put global global_http_proxy_port {port}")
    _adb_su("settings put global global_http_proxy_exclusion_list \"\"")

    # 5. Notifica apps da mudança de proxy
    _adb(["shell", "am", "broadcast",
          "-a", "android.intent.action.PROXY_CHANGE",
          "--es", "proxy.host", host,
          "--ei", "proxy.port", port])

    current = _get_current_proxy()
    return current == addr


def _clear_proxy() -> bool:
    # Limpa via settings global (Android padrão)
    _adb_su("settings put global http_proxy :0")
    _adb_su("settings delete global http_proxy")

    # Limpa campos de proxy global explícitos
    _adb_su("settings put global global_http_proxy_host \"\"")
    _adb_su("settings put global global_http_proxy_port 0")
    _adb_su("settings put global global_http_proxy_exclusion_list \"\"")
    _adb_su("settings delete global global_http_proxy_host")
    _adb_su("settings delete global global_http_proxy_port")

    # Limpa setprop (Nox usa isso para roteamento interno)
    _adb_su("setprop net.gprs.http-proxy ''")
    _adb_su("setprop net.eth0.http-proxy ''")
    _adb_su("setprop http.proxyHost ''")
    _adb_su("setprop http.proxyPort ''")

    # Força proxy_type = none no Wi-Fi salvo (VirtWifi / wlan0)
    # O Nox usa WifiManager interno — resetar via content provider
    _adb_su("content delete --uri content://settings/global --where \"name='http_proxy'\"")

    # Notifica o sistema da mudança
    _adb(["shell", "am", "broadcast", "-a", "android.intent.action.PROXY_CHANGE"])

    # Reinicia o serviço de conectividade para forçar aplicação
    _adb_su("cmd connectivity airplane-mode enable")
    import time; time.sleep(1)
    _adb_su("cmd connectivity airplane-mode disable")

    current = _get_current_proxy()
    return current is None


def _apply_and_report(label: str, host: str, port: str):
    print(f"\n  {_D}→ Aplicando {label} ({host}:{port})...{_R}", end="", flush=True)
    ok = _set_proxy(host, port)
    if ok:
        print(f"\r  {_G}✔ Proxy ativado: {label} ({host}:{port})          {_R}")
    else:
        # Mesmo sem confirmação via settings, os setprop podem ter funcionado
        print(f"\r  {_Y}⚠ Comandos enviados — verifique no emulador:          {_R}")
        print(f"  {_D}  Configurações → Wi-Fi → (rede ativa) → Proxy manual{_R}")
        print(f"  {_D}  Host: {host}  Porta: {port}{_R}")


def proxy_switch_menu():
    from utils.common import clear_screen
    from core.banner import display_banner

    local_ip = _get_local_ip()

    # Presets com IP local já preenchido para Burp/mitmproxy/Charles
    presets = {
        "1": ("Burp Suite",  local_ip, "8080"),
        "2": ("mitmproxy",   local_ip, "8081"),
        "3": ("Charles",     local_ip, "8888"),
    }

    while True:
        clear_screen()
        display_banner()
        current = _get_current_proxy()
        status = f"{_G}{current}{_R}" if current else f"{_D}Desativado{_R}"
        print(f"\n{_C}Proxy Switch{_R}  [atual: {status}]\n")
        print(f"  {_D}IP local detectado: {_W}{local_ip}{_R}\n")

        print(f"  {_C}1.{_R} Burp Suite   {_D}{local_ip}:8080{_R}")
        print(f"  {_C}2.{_R} mitmproxy    {_D}{local_ip}:8081{_R}")
        print(f"  {_C}3.{_R} Charles      {_D}{local_ip}:8888{_R}")
        print(f"  {_C}4.{_R} Custom       {_D}digitar manualmente{_R}")
        print(f"  {_C}5.{_R} Desativar proxy")
        print(f"  {_D}0. Voltar{_R}")

        choice = input(f"\n{_C}→{_R} ").strip()

        if choice in presets:
            label, host, port = presets[choice]
            _apply_and_report(label, host, port)

        elif choice == "4":
            raw = input(f"\n  {_C}→{_R} Host:Porta (ex: 192.168.1.10:8080): ").strip()
            if ":" in raw:
                host, port = raw.rsplit(":", 1)
                _apply_and_report("Custom", host, port)
            else:
                print(f"\n  {_RE}✖ Formato inválido. Use host:porta{_R}")

        elif choice == "5":
            print(f"\n  {_D}→ Desativando proxy...{_R}", end="", flush=True)
            ok = _clear_proxy()
            if ok:
                print(f"\r  {_G}✔ Proxy desativado.          {_R}")
            else:
                print(f"\r  {_Y}⚠ Comandos enviados — proxy pode ainda estar ativo{_R}")

        elif choice == "0":
            break
        else:
            continue

        input(f"\n  {_D}→ Enter para continuar...{_R}")
