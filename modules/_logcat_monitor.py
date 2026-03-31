"""
Monitor de logcat formatado — executado em janela externa.
Uso: python _logcat_monitor.py <adb_path> <package> <mode>
mode: app | crashes | network
"""
import sys
import subprocess
from datetime import datetime

# ─── Cores ANSI ───────────────────────────────────────────────────────────────
R  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[90m"
WHITE  = "\033[97m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
MAGENTA= "\033[95m"
BLUE   = "\033[94m"

# Nível → cor
LEVEL_COLOR = {
    "V": DIM,
    "D": WHITE,
    "I": GREEN,
    "W": YELLOW,
    "E": RED,
    "F": f"{RED}{BOLD}",
    "S": DIM,
}

# Tags de rede relevantes
NETWORK_TAGS = {
    "OkHttp", "Retrofit", "HttpURLConnection", "NetworkSecurityConfig",
    "SSLHandshakeException", "ConnectivityService", "NetworkMonitor",
    "okhttp3", "Volley", "HttpClient", "WebViewClient",
}

CRASH_TAGS = {
    "AndroidRuntime", "ActivityManager", "DEBUG", "FATAL", "libc",
    "art", "Signal Catcher",
}


def _header(adb: str, pkg: str, mode: str):
    mode_label = {"app": "App Monitor", "crashes": "Crashes & Errors",
                  "network": "Network Traffic"}.get(mode, mode)
    print(f"\033[2J\033[H", end="")  # clear
    print(f"{CYAN}{'═' * 80}{R}")
    print(f"{CYAN}{BOLD}  NoxDroid — Logcat  │  {mode_label}{R}")
    print(f"{DIM}  Package : {WHITE}{pkg}{R}")
    print(f"{DIM}  ADB     : {adb}{R}")
    print(f"{DIM}  Iniciado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{R}")
    print(f"{CYAN}{'═' * 80}{R}\n")
    print(f"  {DIM}{'Hora':<10} {'Nível':<6} {'Tag':<22} Mensagem{R}")
    print(f"  {DIM}{'─'*10} {'─'*6} {'─'*22} {'─'*35}{R}\n")


def _parse_line(raw: str) -> str | None:
    """
    Formato threadtime:
    MM-DD HH:MM:SS.mmm  PID  TID  LEVEL  TAG  : message
    """
    raw = raw.rstrip()
    if not raw or raw.startswith("-----"):
        return None

    parts = raw.split(None, 6)
    if len(parts) < 7:
        return None

    try:
        time_str = parts[1][:8]   # HH:MM:SS
        level    = parts[4]       # V/D/I/W/E/F
        tag      = parts[5].rstrip(":")
        message  = parts[6].strip()
    except IndexError:
        return None

    color = LEVEL_COLOR.get(level, WHITE)
    tag_c = f"{CYAN}{tag:<22}{R}" if level in ("I", "D") else f"{color}{tag:<22}{R}"

    return (
        f"  {DIM}{time_str}{R}  "
        f"{color}{BOLD}{level:<6}{R}"
        f"{tag_c} "
        f"{color}{message}{R}"
    )


def _get_pid(adb: str, pkg: str) -> str | None:
    try:
        r = subprocess.run([adb, "shell", "pidof", pkg],
                           capture_output=True, text=True, timeout=5)
        pid = r.stdout.strip().split()[0]
        return pid if pid.isdigit() else None
    except Exception:
        return None


def run(adb: str, pkg: str, mode: str):
    _header(adb, pkg, mode)

    # Limpa buffer
    subprocess.run([adb, "logcat", "-c"], capture_output=True)

    # Prepara arquivo de log
    from pathlib import Path
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import network_dir
    out_dir  = network_dir(pkg)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{ts}_{mode}.txt"
    print(f"  {DIM}Log: {out_file}{R}\n")

    # Monta comando logcat
    if mode == "app":
        pid = _get_pid(adb, pkg)
        if pid:
            cmd = [adb, "logcat", "-v", "threadtime", f"--pid={pid}"]
            print(f"  {GREEN}✔ PID detectado: {pid}{R}\n")
        else:
            cmd = [adb, "logcat", "-v", "threadtime"]
            print(f"  {YELLOW}⚠ App não está rodando — monitorando todos os logs{R}\n")

    elif mode == "crashes":
        cmd = [adb, "logcat", "-v", "threadtime",
               "AndroidRuntime:E", "ActivityManager:E",
               "DEBUG:E", "libc:F", "art:E", "*:F"]

    elif mode == "network":
        tags = " ".join(f"{t}:V" for t in NETWORK_TAGS)
        cmd = [adb, "logcat", "-v", "threadtime"] + tags.split()

    else:
        cmd = [adb, "logcat", "-v", "threadtime"]

    import re as _re
    raw_lines = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print(f"  {DIM}Aguardando eventos... (Ctrl+C para parar){R}\n")

        for raw_line in proc.stdout:
            # Filtro extra para modo network
            if mode == "network":
                tag_part = raw_line.split(None, 6)
                if len(tag_part) >= 6:
                    tag = tag_part[5].rstrip(":")
                    if not any(t.lower() in tag.lower() for t in NETWORK_TAGS):
                        continue

            formatted = _parse_line(raw_line)
            if formatted:
                print(formatted)
                raw_lines.append(_re.sub(r"\033\[[0-9;]*m", "", formatted))

    except KeyboardInterrupt:
        print(f"\n\n{DIM}  Monitor encerrado.{R}\n")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    # Salva log
    if raw_lines:
        header = [
            f"Logcat Monitor — {pkg}",
            f"Modo      : {mode}",
            f"Timestamp : {ts}",
            f"Linhas    : {len(raw_lines)}",
            "─" * 70,
            "",
        ]
        out_file.write_text("\n".join(header) + "\n".join(raw_lines), encoding="utf-8")
        print(f"  {GREEN}✔ Log salvo em: {out_file}{R}\n")
    else:
        print(f"  {DIM}Nenhuma linha capturada — arquivo não salvo.{R}\n")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: python _logcat_monitor.py <adb> <package> <mode>")
        sys.exit(1)

    # Habilita cores ANSI no Windows
    import os
    os.system("")

    run(sys.argv[1], sys.argv[2], sys.argv[3])
    input("\n→ Enter para fechar...")
