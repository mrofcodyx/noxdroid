"""
Monitor de logs do Magisk em tempo real.
Executado em janela separada via: python -m modules.magisk_monitor
"""
import sys
import subprocess
from datetime import datetime
from core.env_check import _adb_exe

# Tags relevantes do Magisk
TAGS = [
    "Magisk", "MagiskHide", "MagiskSU", "Zygisk",
    "magiskd", "magisk", "zygisk", "su",
]

# Categorias por palavra-chave no log
CATEGORIES = {
    "hide":     ("\033[93m", "HIDE   "),   # amarelo
    "deny":     ("\033[91m", "DENY   "),   # vermelho
    "allow":    ("\033[92m", "ALLOW  "),   # verde
    "inject":   ("\033[96m", "INJECT "),   # ciano
    "mount":    ("\033[94m", "MOUNT  "),   # azul
    "su":       ("\033[95m", "SU     "),   # magenta
    "error":    ("\033[91m", "ERROR  "),   # vermelho
    "fail":     ("\033[91m", "FAIL   "),   # vermelho
    "zygisk":   ("\033[96m", "ZYGISK "),   # ciano
    "module":   ("\033[94m", "MODULE "),   # azul
}

RESET  = "\033[0m"
DIM    = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


def _categorize(line: str) -> tuple[str, str]:
    """Retorna (cor, label) baseado no conteúdo da linha."""
    low = line.lower()
    for keyword, (color, label) in CATEGORIES.items():
        if keyword in low:
            return color, label
    return DIM, "INFO   "


def _parse_line(raw: str) -> str | None:
    """
    Formata uma linha do logcat:
    Input:  03-16 19:00:36.128  1504  1500 D Magisk  : some message
    Output: [19:00:36] HIDE   │ Magisk │ some message
    """
    raw = raw.strip()
    if not raw or raw.startswith("-----"):
        return None

    parts = raw.split(None, 6)
    if len(parts) < 7:
        return None

    try:
        time_str = parts[1].split(".")[0]   # HH:MM:SS
        tag      = parts[5].rstrip(":")     # tag
        message  = parts[6].strip()
    except IndexError:
        return None

    # Filtrar só tags relevantes
    if not any(t.lower() in tag.lower() for t in TAGS):
        return None

    color, label = _categorize(raw)

    return (
        f"{DIM}[{time_str}]{RESET} "
        f"{color}{BOLD}{label}{RESET} "
        f"{DIM}│{RESET} "
        f"{WHITE}{tag:<14}{RESET} "
        f"{DIM}│{RESET} "
        f"{color}{message}{RESET}"
    )


def _header(adb: str):
    print("\033[2J\033[H", end="")  # clear
    print(f"\033[96m{'═' * 70}\033[0m")
    print(f"\033[96m  NoxDroid — Monitor Magisk\033[0m")
    print(f"\033[90m  Iniciado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\033[0m")
    print(f"\033[90m  ADB: {adb}\033[0m")
    print(f"\033[96m{'═' * 70}\033[0m")
    print()
    print(f"  {DIM}Legenda:{RESET}")
    print(f"  \033[92m{'ALLOW  '}\033[0m permissão root concedida")
    print(f"  \033[91m{'DENY   '}\033[0m permissão root negada / detecção bloqueada")
    print(f"  \033[93m{'HIDE   '}\033[0m MagiskHide ocultando root")
    print(f"  \033[96m{'INJECT '}\033[0m Zygisk injetando em processo")
    print(f"  \033[94m{'MOUNT  '}\033[0m operação de montagem")
    print(f"  \033[95m{'SU     '}\033[0m solicitação de SuperUsuário")
    print(f"  \033[91m{'ERROR  '}\033[0m erro / falha")
    print()
    print(f"\033[96m{'─' * 70}\033[0m\n")


def run():
    adb = _adb_exe()
    _header(adb)

    # Limpar buffer antigo e iniciar stream
    subprocess.run([adb, "logcat", "-c"], capture_output=True)

    logcat_filter = " ".join(f"{t}:V" for t in TAGS) + " *:S"

    proc = None
    try:
        proc = subprocess.Popen(
            [adb, "logcat", "-v", "threadtime"] + logcat_filter.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        print(f"  {DIM}Aguardando eventos...{RESET}\n")

        for raw_line in proc.stdout:
            formatted = _parse_line(raw_line)
            if formatted:
                print(formatted)

    except KeyboardInterrupt:
        print(f"\n\n{DIM}  Monitor encerrado.{RESET}\n")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    run()
