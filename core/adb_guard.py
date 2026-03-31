"""
adb_guard.py — Verificação centralizada de conexão ADB.
"""
import subprocess

_R  = "\033[0m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[90m"


def device_connected() -> bool:
    """Retorna True se houver pelo menos um dispositivo ADB conectado e online."""
    from core.device_detect import get_adb, DEVICE
    # Se ja temos um dispositivo selecionado, verifica ele especificamente
    serial = DEVICE.get("serial")
    adb    = get_adb()
    try:
        r = subprocess.run(
            [adb, "devices"],
            capture_output=True, text=True, timeout=6
        )
        lines = r.stdout.splitlines()
        if serial:
            return any(
                serial in line and "device" in line
                and "offline" not in line and "unauthorized" not in line
                for line in lines
            )
        return any(
            "device" in line
            and not line.startswith("List")
            and "offline"      not in line
            and "unauthorized" not in line
            for line in lines
        )
    except Exception:
        return False


def require_device(action: str = "") -> bool:
    """
    Verifica se há dispositivo conectado.
    Se não houver, imprime mensagem de erro e retorna False.
    Use no início de qualquer função que precise do emulador:

        if not require_device("Vuln Scanner"):
            return
    """
    if device_connected():
        return True

    label = f" — {action}" if action else ""
    print(f"\n  {_RE}✖ Nenhum dispositivo ADB conectado{label}{_R}")
    print(f"  {_Y}→ Conecte um dispositivo ou inicie o emulador.{_R}")
    print(f"  {_D}  Verifique: adb devices{_R}")
    input(f"\n  {_D}→ Enter para continuar...{_R}")
    return False
