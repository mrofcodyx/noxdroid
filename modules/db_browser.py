"""
DB Browser — varre /data/data/<pkg>/databases/, puxa os .db para o PC
e abre com DB Browser SQLite portátil.
"""
import subprocess
import os
import shutil
from pathlib import Path
from datetime import datetime

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_SEL_BG = "\033[30;46m"

RESULTS_DIR = Path("results")
TOOLS_DIR   = Path(__file__).parent.parent / "tools"


def _dbbrowser_exe() -> str | None:
    """Localiza o DB Browser SQLite (portátil ou instalado)."""
    # 1. Portátil na pasta tools/ ou tools/db-browser/
    for name in ("DB Browser for SQLite.exe", "DB Browser for SQLCipher.exe",
                 "DBBrowserForSQLite.exe", "sqlitebrowser.exe"):
        for search_dir in (TOOLS_DIR, TOOLS_DIR / "db-browser"):
            p = search_dir / name
            if p.exists():
                return str(p)
    # 2. No PATH
    found = shutil.which("sqlitebrowser") or shutil.which("DB Browser for SQLite")
    if found:
        return found
    # 3. Instalação padrão Windows
    for base in (
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")),
    ):
        for name in ("DB Browser for SQLite\\DB Browser for SQLite.exe",
                     "SQLiteBrowser\\sqlitebrowser.exe"):
            p = base / name
            if p.exists():
                return str(p)
    return None


def _adb_su(adb: str, cmd: str) -> str:
    try:
        r = subprocess.run([adb, "shell", "su", "-c", cmd],
                           capture_output=True, timeout=15)
        return r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
    except Exception:
        return ""


def _list_databases(adb: str, pkg: str) -> list[str]:
    """Lista arquivos .db em /data/data/<pkg>/databases/."""
    db_path = f"/data/data/{pkg}/databases"
    out = _adb_su(adb, f"ls '{db_path}' 2>/dev/null")
    dbs = []
    for line in out.splitlines():
        name = line.strip()
        if name and not name.startswith("ls:"):
            dbs.append(name)
    return dbs


def _pull_db(adb: str, pkg: str, db_name: str, out_dir: Path) -> Path | None:
    """Copia um .db do dispositivo para out_dir via /sdcard."""
    remote = f"/data/data/{pkg}/databases/{db_name}"
    tmp    = f"/sdcard/_nd_db_{db_name}"
    local  = out_dir / db_name

    subprocess.run([adb, "shell", "su", "-c", f"cp '{remote}' '{tmp}'"],
                   capture_output=True, timeout=10)
    r = subprocess.run([adb, "pull", tmp, str(local)], capture_output=True, timeout=15)
    subprocess.run([adb, "shell", "rm", "-f", tmp], capture_output=True)

    if r.returncode == 0 and local.exists():
        return local
    return None


def _getch():
    import msvcrt
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):
        return ("special", msvcrt.getch())
    return ("char", ch)


def _render(dbs: list[str], selected: int, pulled: set[str], pkg: str, status: str = ""):
    os.system("cls")
    print(f"{_CYAN}{'═' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  DB Browser — {pkg}{_RESET}")
    print(f"{_DIM}  ↑↓=navegar  Enter=baixar+abrir  p=baixar  q=voltar{_RESET}")
    print(f"{_CYAN}{'═' * 70}{_RESET}\n")

    if not dbs:
        print(f"  {_DIM}Nenhum banco de dados encontrado em /data/data/{pkg}/databases/{_RESET}")
    else:
        for i, db in enumerate(dbs):
            tag = f"{_GREEN}[baixado]{_RESET}" if db in pulled else ""
            if i == selected:
                print(f"  {_SEL_BG} > {db:<50} {_RESET} {tag}")
            else:
                print(f"  {_DIM}   {_RESET}{_WHITE}{db:<50}{_RESET} {tag}")

    print(f"\n{_DIM}{'─' * 70}{_RESET}")
    if status:
        print(f"  {_YELLOW}{status}{_RESET}")


def db_browser_menu(adb: str, pkg: str):
    """Menu interativo para listar, baixar e abrir bancos de dados do app."""
    os.system("cls")
    print(f"{_CYAN}→ Listando bancos de dados de {pkg}...{_RESET}")

    dbs = _list_databases(adb, pkg)
    out_dir = RESULTS_DIR / pkg / "databases"
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = 0
    pulled: set[str] = set()
    status = ""

    # Marca os que já foram baixados anteriormente
    for f in out_dir.iterdir():
        if f.suffix in (".db", ".sqlite", ".sqlite3", ""):
            pulled.add(f.name)

    dbbrowser = _dbbrowser_exe()
    if not dbbrowser:
        status = "DB Browser não encontrado — instale via Setup → Instalar Ferramentas"

    while True:
        _render(dbs, selected, pulled, pkg, status)
        status = ""

        if not dbs:
            input(f"\n  {_DIM}→ Enter para voltar...{_RESET}")
            return

        kind, ch = _getch()

        if kind == "char":
            if ch in (b"q", b"\x1b"):
                return
            elif ch == b"p":
                # Baixar sem abrir
                db = dbs[selected]
                status = f"Baixando {db}..."
                _render(dbs, selected, pulled, pkg, status)
                local = _pull_db(adb, pkg, db, out_dir)
                if local:
                    pulled.add(db)
                    status = f"✔ Salvo em: {local}"
                else:
                    status = f"✖ Falha ao baixar {db}"

        elif kind == "special":
            if ch == b"H" and selected > 0:
                selected -= 1
            elif ch == b"P" and selected < len(dbs) - 1:
                selected += 1
            elif ch in (b"M", b"\r"):
                # Enter ou seta direita — baixar e abrir
                db = dbs[selected]
                status = f"Baixando {db}..."
                _render(dbs, selected, pulled, pkg, status)
                local = _pull_db(adb, pkg, db, out_dir)
                if local:
                    pulled.add(db)
                    if dbbrowser:
                        subprocess.Popen([dbbrowser, str(local)])
                        status = f"✔ Aberto no DB Browser: {db}"
                    else:
                        status = f"✔ Salvo em: {local}  (DB Browser não encontrado)"
                else:
                    status = f"✖ Falha ao baixar {db}"
