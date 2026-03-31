"""
Traffic Monitor — captura tráfego HTTP/HTTPS em tempo real via logcat.
Executado em janela externa.
Uso: python _traffic_monitor.py <adb_path> <package>

Detecta:
  - OkHttp3 (interceptor de log)
  - Retrofit / Volley
  - HttpURLConnection
  - WebView requests
  - SSL errors / handshake
  - URLs brutas em qualquer log do app
"""
import sys
import re
import subprocess
from datetime import datetime

# ─── Cores ────────────────────────────────────────────────────────────────────
R       = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[90m"
WHITE   = "\033[97m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
BG_DARK = "\033[40m"

# ─── Padrões de detecção ──────────────────────────────────────────────────────

# Tags que costumam carregar tráfego HTTP
HTTP_TAGS = {
    "OkHttp", "okhttp3", "okhttp", "Retrofit", "Volley",
    "HttpURLConnection", "HttpsURLConnection", "WebViewClient",
    "WebView", "NetworkSecurityConfig", "SSLHandshakeException",
    "SSLPeerUnverifiedException", "CertificateException",
    "ConnectivityService", "NetworkMonitor", "HttpClient",
    "DefaultHttpClient", "AndroidHttpClient", "URLConnection",
}

# Regex para extrair URLs de qualquer linha
URL_RE = re.compile(r'https?://[^\s\'"<>]{6,}')

# Regex para detectar método HTTP
METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')

# Regex para detectar status code HTTP
STATUS_RE = re.compile(r'\b([1-5]\d{2})\b')

# Padrões de dados sensíveis em requests
SENSITIVE_RE = [
    (re.compile(r'(?i)authorization:\s*\S+'),          "Authorization Header"),
    (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]+'),   "Bearer Token"),
    (re.compile(r'(?i)x-api-key:\s*\S+'),              "API Key Header"),
    (re.compile(r'(?i)password["\s:=]+[^\s"&]{3,}'),   "Password"),
    (re.compile(r'(?i)token["\s:=]+[A-Za-z0-9\-_]{8,}'), "Token"),
    (re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'), "JWT"),
    (re.compile(r'(?i)cookie:\s*\S+'),                 "Cookie"),
]

# ─── Contadores ───────────────────────────────────────────────────────────────
_stats = {"requests": 0, "responses": 0, "errors": 0, "sensitive": 0}


def _header(pkg: str):
    print("\033[2J\033[H", end="")
    print(f"{CYAN}{'═' * 80}{R}")
    print(f"{CYAN}{BOLD}  NoxDroid — Traffic Monitor{R}")
    print(f"{DIM}  Package : {WHITE}{pkg}{R}")
    print(f"{DIM}  Iniciado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{R}")
    print(f"{DIM}  Fonte   : logcat (OkHttp, Retrofit, Volley, WebView, URLConnection){R}")
    print(f"{CYAN}{'═' * 80}{R}\n")
    print(f"  {DIM}Aguardando tráfego... (Ctrl+C para parar){R}\n")
    print(f"  {DIM}{'─' * 78}{R}\n")


def _status_color(code: str) -> str:
    c = int(code)
    if c < 300:   return GREEN
    if c < 400:   return CYAN
    if c < 500:   return YELLOW
    return RED


def _method_color(method: str) -> str:
    return {
        "GET":     GREEN,
        "POST":    CYAN,
        "PUT":     YELLOW,
        "DELETE":  RED,
        "PATCH":   MAGENTA,
        "HEAD":    DIM,
        "OPTIONS": DIM,
    }.get(method, WHITE)


def _format_line(raw: str, pkg: str) -> list[str]:
    """
    Processa uma linha de logcat e retorna lista de linhas formatadas.
    Retorna [] se a linha não for relevante.
    """
    raw = raw.rstrip()
    if not raw or raw.startswith("-----"):
        return []

    parts = raw.split(None, 6)
    if len(parts) < 7:
        return []

    try:
        time_str = parts[1][:12]   # HH:MM:SS.mmm
        level    = parts[4]
        tag      = parts[5].rstrip(":")
        message  = parts[6].strip()
    except IndexError:
        return []

    output = []
    ts = f"{DIM}{time_str}{R}"

    # ── Detecta método HTTP ───────────────────────────────────────────────────
    m_method = METHOD_RE.search(message)
    m_url    = URL_RE.search(message)
    m_status = STATUS_RE.search(message)

    is_http_tag = any(t.lower() in tag.lower() for t in HTTP_TAGS)

    if not is_http_tag and not m_url:
        return []

    # ── Linha com URL ─────────────────────────────────────────────────────────
    if m_url:
        url = m_url.group()
        method = m_method.group() if m_method else "→"
        mc = _method_color(method) if m_method else CYAN

        _stats["requests"] += 1
        output.append(
            f"\n  {ts}  {mc}{BOLD}{method:<8}{R}  {WHITE}{url}{R}"
        )

        # Resto da mensagem (headers, body snippet)
        rest = message[m_url.end():].strip()
        if rest:
            output.append(f"  {DIM}{'':>22}{rest[:120]}{R}")

    # ── Linha com status code ─────────────────────────────────────────────────
    elif m_status and is_http_tag:
        code = m_status.group()
        sc   = _status_color(code)
        _stats["responses"] += 1
        output.append(
            f"  {ts}  {sc}{BOLD}HTTP {code}{R}  {DIM}{message[:100]}{R}"
        )

    # ── SSL / TLS errors ──────────────────────────────────────────────────────
    elif level in ("E", "W") and any(k in tag for k in ("SSL", "Certificate", "Handshake", "Trust")):
        _stats["errors"] += 1
        output.append(
            f"  {ts}  {RED}{BOLD}SSL ERR{R}  {RED}{message[:120]}{R}"
        )

    # ── Linha genérica de tag HTTP ────────────────────────────────────────────
    elif is_http_tag:
        output.append(
            f"  {ts}  {DIM}{tag:<14}{R}  {WHITE}{message[:120]}{R}"
        )

    # ── Dados sensíveis ───────────────────────────────────────────────────────
    for pattern, label in SENSITIVE_RE:
        if pattern.search(message):
            _stats["sensitive"] += 1
            output.append(
                f"  {ts}  {RED}{BOLD}⚠ SENSITIVE [{label}]{R}  {RED}{message[:150]}{R}"
            )
            break

    return output


def _get_pid(adb: str, pkg: str) -> str | None:
    try:
        r = subprocess.run([adb, "shell", "pidof", pkg],
                           capture_output=True, text=True, timeout=5)
        pid = r.stdout.strip().split()[0]
        return pid if pid.isdigit() else None
    except Exception:
        return None


def run(adb: str, pkg: str):
    _header(pkg)

    subprocess.run([adb, "logcat", "-c"], capture_output=True)

    # Prepara arquivo de log
    from pathlib import Path
    from datetime import datetime
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import network_dir
    out_dir = network_dir(pkg)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{ts}_traffic.txt"

    pid = _get_pid(adb, pkg)
    if pid:
        cmd = [adb, "logcat", "-v", "threadtime", f"--pid={pid}"]
        print(f"  {GREEN}✔ PID: {pid} — filtrando logs do processo{R}")
    else:
        cmd = [adb, "logcat", "-v", "threadtime"]
        print(f"  {YELLOW}⚠ App não detectado — monitorando todos os logs{R}")

    print(f"  {DIM}Log: {out_file}{R}\n")

    raw_lines = []  # linhas brutas para salvar no arquivo

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        for raw_line in proc.stdout:
            lines = _format_line(raw_line, pkg)
            for line in lines:
                print(line)
                # Remove escape codes ANSI para o arquivo
                import re as _re
                raw_lines.append(_re.sub(r"\033\[[0-9;]*m", "", line))

    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    # Resumo final
    print(f"\n\n{CYAN}{'─' * 60}{R}")
    print(f"  {BOLD}Resumo da sessão:{R}")
    print(f"  {GREEN}Requests  : {_stats['requests']}{R}")
    print(f"  {CYAN}Responses : {_stats['responses']}{R}")
    print(f"  {RED}SSL Errors: {_stats['errors']}{R}")
    print(f"  {RED}Sensíveis : {_stats['sensitive']}{R}")
    print(f"{CYAN}{'─' * 60}{R}\n")

    # Salva log
    if raw_lines:
        header = [
            f"Traffic Monitor — {pkg}",
            f"Timestamp : {ts}",
            f"PID       : {pid or 'N/A'}",
            f"Requests  : {_stats['requests']}",
            f"Responses : {_stats['responses']}",
            f"SSL Errors: {_stats['errors']}",
            f"Sensíveis : {_stats['sensitive']}",
            "─" * 60,
            "",
        ]
        out_file.write_text("\n".join(header) + "\n".join(raw_lines), encoding="utf-8")
        print(f"  {GREEN}✔ Log salvo em: {out_file}{R}\n")
    else:
        print(f"  {DIM}Nenhum tráfego capturado — arquivo não salvo.{R}\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python _traffic_monitor.py <adb> <package>")
        sys.exit(1)

    import os
    os.system("")  # habilita ANSI no Windows

    run(sys.argv[1], sys.argv[2])
    input("\n→ Enter para fechar...")
