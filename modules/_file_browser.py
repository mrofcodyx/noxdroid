"""
Navegador de arquivos do dispositivo Android via ADB + root.
Navegação com setas, Enter para entrar em pastas ou visualizar arquivos.
Arquivos .db/.sqlite abrem automaticamente no DB Browser SQLite.
"""
import subprocess
import os
from pathlib import Path

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_SEL_BG = "\033[30;46m"

_UP    = b"H"
_DOWN  = b"P"
_LEFT  = b"K"
_RIGHT = b"M"
_ENTER = b"\r"
_ESC   = b"\x1b"
_Q     = b"q"

_DB_EXTENSIONS  = {".db", ".sqlite", ".sqlite3", ".db3", ".sdb"}
_TEXT_EXTENSIONS = {
    ".txt", ".log", ".json", ".xml", ".html", ".htm", ".js", ".ts",
    ".py", ".java", ".kt", ".sh", ".conf", ".cfg", ".ini", ".yaml",
    ".yml", ".properties", ".pref", ".csv", ".md", ".gradle", ".toml",
}
_SQLITE_MAGIC = b"SQLite format 3"


def _getch():
    import msvcrt
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):
        return ("special", msvcrt.getch())
    return ("char", ch)


def _clear():
    os.system("cls")


def _adb_su(adb: str, cmd: str) -> str:
    """Executa comando via su no dispositivo."""
    try:
        r = subprocess.run(
            [adb, "shell", "su", "-c", cmd],
            capture_output=True, timeout=10
        )
        return r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
    except Exception:
        return ""


def _ls(adb: str, path: str) -> list[dict]:
    """Lista entradas de um diretório."""
    out = _adb_su(adb, f"ls -la '{path}' 2>/dev/null")
    entries = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or line.startswith("total"):
            continue
        perms   = parts[0]
        is_dir  = perms.startswith("d")
        is_link = perms.startswith("l")
        if len(parts) < 8:
            continue
        name = parts[-1] if "->" not in parts else parts[parts.index("->") - 1]
        if name in (".", ".."):
            continue
        size = parts[4] if len(parts) > 4 else ""
        date = f"{parts[5]} {parts[6]}" if len(parts) > 6 else ""
        entries.append({
            "name":    name,
            "is_dir":  is_dir or is_link,
            "is_link": is_link,
            "size":    size,
            "date":    date,
            "perms":   perms,
        })
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return entries


def _is_sqlite(data: bytes) -> bool:
    return data[:15] == _SQLITE_MAGIC


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    if _is_sqlite(data):
        return True  # trata como DB, não como binário genérico
    sample = data[:2048]
    printable = sum(1 for b in sample if 0x09 <= b <= 0x0D or 0x20 <= b <= 0x7E)
    return (printable / len(sample)) < 0.70


def _decode_best(raw: bytes) -> str:
    """Tenta decodificar bytes com múltiplos encodings, retorna o melhor resultado."""
    for enc in ("utf-8", "latin-1", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _format_text(text: str, ext: str) -> str:
    """Formata texto denso (JSON, XML) para melhor leitura."""
    stripped = text.strip()
    if ext == ".json" or (stripped.startswith("{") or stripped.startswith("[")):
        try:
            import json
            obj = json.loads(stripped)
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception:
            pass
    if ext == ".xml" or stripped.startswith("<"):
        try:
            import xml.dom.minidom
            dom = xml.dom.minidom.parseString(stripped.encode("utf-8", errors="replace"))
            return dom.toprettyxml(indent="  ")
        except Exception:
            pass
    return text


def _read_file(adb: str, path: str) -> tuple[str, bool]:
    """
    Lê conteúdo de um arquivo.
    Retorna (conteúdo, is_sqlite).
    - SQLite → sinaliza para abrir no DB Browser
    - Texto  → decodifica + formata
    - Binário → hexdump
    """
    try:
        r = subprocess.run(
            [adb, "shell", "su", "-c", f"cat '{path}' 2>/dev/null | head -c 131072"],
            capture_output=True, timeout=20
        )
        raw = r.stdout if r.stdout else b""
    except Exception:
        raw = b""

    if not raw:
        return "[arquivo vazio ou sem permissão]", False

    # SQLite — sinaliza para abrir no DB Browser
    if _is_sqlite(raw):
        return "[sqlite]", True

    ext = Path(path).suffix.lower()

    # Força leitura de texto para extensões conhecidas
    force_text = ext in _TEXT_EXTENSIONS

    if not force_text and _is_binary(raw):
        out = _adb_su(adb, f"xxd '{path}' 2>/dev/null | head -60")
        return (f"[binário — hexdump]\n\n{out}" if out.strip()
                else "[arquivo binário — xxd não disponível]"), False

    text = _decode_best(raw)
    text = _format_text(text, ext)
    lines = text.splitlines()
    return "\n".join(lines[:500]), False


def _open_with_dbbrowser(adb: str, remote_path: str, name: str) -> str:
    """Puxa o arquivo para temp local e abre no DB Browser."""
    from modules.db_browser import _dbbrowser_exe
    dbbrowser = _dbbrowser_exe()
    if not dbbrowser:
        return f"{_RED}✖ DB Browser não encontrado — instale via Setup → Instalar Ferramentas{_RESET}"

    tmp_dir = Path(os.environ.get("TEMP", ".")) / "noxdroid_db"
    tmp_dir.mkdir(exist_ok=True)
    local = tmp_dir / name

    tmp_remote = f"/sdcard/_nd_fb_{name}"
    subprocess.run(
        [adb, "shell", "su", "-c", f"cp '{remote_path}' '{tmp_remote}'"],
        capture_output=True, timeout=10
    )
    r = subprocess.run([adb, "pull", tmp_remote, str(local)], capture_output=True, timeout=15)
    subprocess.run([adb, "shell", "rm", "-f", tmp_remote], capture_output=True)

    if r.returncode != 0 or not local.exists():
        return f"{_RED}✖ Falha ao baixar {name}{_RESET}"

    subprocess.Popen([dbbrowser, str(local)])
    return f"{_GREEN}✔ Aberto no DB Browser: {name}{_RESET}"


def _render(path: str, entries: list[dict], selected: int, scroll: int, status: str = ""):
    _clear()
    max_visible = 22

    print(f"{_CYAN}{_BOLD}  File Browser{_RESET}  "
          f"{_DIM}↑↓=navegar  Enter/→=abrir  ←/Esc=voltar  q=sair{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}")
    print(f"  {_DIM}Caminho:{_RESET} {_CYAN}{path}{_RESET}")
    print(f"{_DIM}{'─' * 78}{_RESET}\n")

    if not entries:
        print(f"  {_DIM}(diretório vazio ou sem permissão){_RESET}")
    else:
        visible = entries[scroll:scroll + max_visible]
        for i, e in enumerate(visible):
            real_idx = scroll + i
            is_db    = (not e["is_dir"]) and Path(e["name"]).suffix.lower() in _DB_EXTENSIONS
            if e["is_dir"]:
                icon = f"{_CYAN}📁{_RESET}"
            elif is_db:
                icon = f"{_YELLOW}🗄{_RESET}"
            else:
                icon = f"{_WHITE}📄{_RESET}"

            size_str = e["size"].rjust(8) if not e["is_dir"] else "       -"
            date_str = e["date"]
            db_tag   = f" {_YELLOW}[DB]{_RESET}" if is_db else ""

            if real_idx == selected:
                hl = f"  > {e['name']:<35} {size_str}  {date_str}"
                print(f"{_SEL_BG}{hl:<78}{_RESET}{db_tag}")
            else:
                print(f"  {icon} {e['name']:<35} {size_str}  {_DIM}{date_str}{_RESET}{db_tag}")

        if len(entries) > max_visible:
            shown_end = scroll + max_visible
            print(f"\n  {_DIM}({scroll + 1}–{min(shown_end, len(entries))} de {len(entries)}){_RESET}")

    print(f"\n{_DIM}{'─' * 78}{_RESET}")
    if status:
        print(f"  {status}")


def _view_file(adb: str, path: str, name: str) -> str:
    """
    Exibe conteúdo de um arquivo com scroll.
    Se for SQLite, oferece abrir no DB Browser.
    Retorna status string para o browser principal.
    """
    content, is_sqlite = _read_file(adb, path)

    if is_sqlite:
        _clear()
        ext = Path(name).suffix.lower()
        print(f"\n  {_YELLOW}🗄  {name}{_RESET}  {_DIM}— banco SQLite detectado{_RESET}\n")
        print(f"  {_DIM}[D]{_RESET} Abrir no DB Browser")
        print(f"  {_DIM}[H]{_RESET} Ver hexdump")
        print(f"  {_DIM}[Q]{_RESET} Voltar")
        print()
        try:
            ch_raw = input(f"  {_CYAN}→{_RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ch_raw = "q"

        if ch_raw == "d":
            return _open_with_dbbrowser(adb, path, name)
        elif ch_raw == "h":
            out = _adb_su(adb, f"xxd '{path}' 2>/dev/null | head -60")
            content = f"[SQLite — hexdump]\n\n{out}" if out.strip() else "[SQLite — xxd não disponível]"
            # cai no viewer normal abaixo
        else:
            return ""

    lines  = content.splitlines()
    scroll = 0
    page   = 30

    while True:
        _clear()
        print(f"  {_CYAN}{_BOLD}{name}{_RESET}  {_DIM}{path}{_RESET}")
        print(f"  {_DIM}{'─' * 74}{_RESET}\n")
        chunk = lines[scroll:scroll + page]
        for i, line in enumerate(chunk):
            # trunca linhas muito longas para não quebrar o terminal
            display = line[:160] + (f"  {_DIM}…{_RESET}" if len(line) > 160 else "")
            print(f"  {_DIM}{scroll + i + 1:>4}{_RESET}  {display}")
        print(f"\n  {_DIM}{'─' * 74}{_RESET}")
        total = len(lines)
        print(f"  {_DIM}↑↓=scroll  q/Esc=voltar  "
              f"({scroll+1}–{min(scroll+page, total)} de {total} linhas){_RESET}")

        kind, ch = _getch()
        if kind == "char" and ch in (_Q, _ESC):
            break
        elif kind == "special":
            if ch == _UP:
                scroll = max(0, scroll - 1)
            elif ch == _DOWN:
                scroll = min(max(0, len(lines) - page), scroll + 1)
            elif ch == _LEFT:
                break

    return ""


def file_browser(adb: str, start_path: str):
    """Entry point — navegador interativo de arquivos."""
    history  = []
    path     = start_path
    selected = 0
    scroll   = 0
    status   = ""

    while True:
        entries = _ls(adb, path)
        _render(path, entries, selected, scroll, status)
        status = ""

        kind, ch = _getch()

        if kind == "char":
            if ch in (_Q, _ESC):
                break

        elif kind == "special":
            if ch == _UP:
                if selected > 0:
                    selected -= 1
                    if selected < scroll:
                        scroll = selected

            elif ch == _DOWN:
                if selected < len(entries) - 1:
                    selected += 1
                    if selected >= scroll + 22:
                        scroll += 1

            elif ch in (_ENTER, _RIGHT):
                if not entries:
                    continue
                entry = entries[selected]
                if entry["is_dir"]:
                    history.append((path, selected, scroll))
                    path     = f"{path}/{entry['name']}"
                    selected = 0
                    scroll   = 0
                else:
                    full_path = f"{path}/{entry['name']}"
                    result = _view_file(adb, full_path, entry["name"])
                    if result:
                        status = result

            elif ch == _LEFT:
                if history:
                    path, selected, scroll = history.pop()
                else:
                    break
