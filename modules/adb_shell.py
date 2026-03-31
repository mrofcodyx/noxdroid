"""
Shell interativo ADB com root.
- Cores: pastas (azul/bold), executáveis (verde), links (ciano), arquivos (branco)
- Autocomplete com Tab: completa comandos e caminhos remotos
- Suporte a: cd, ls colorido, download, upload, clear, exit/quit, help
"""
import subprocess
import sys
import os
import msvcrt
from pathlib import Path

_RESET   = "\033[0m"
_CYAN    = "\033[96m"
_BLUE    = "\033[94m"
_WHITE   = "\033[97m"
_DIM     = "\033[90m"
_BOLD    = "\033[1m"
_YELLOW  = "\033[93m"
_RED     = "\033[91m"
_GREEN   = "\033[92m"
_MAGENTA = "\033[95m"

# Extensões → cor
_EXT_COLORS = {
    # executáveis / scripts
    frozenset({".sh", ".py", ".rb", ".pl", ".bat", ".exe", ".so"}): _GREEN,
    # arquivos de dados / config
    frozenset({".json", ".xml", ".yaml", ".yml", ".conf", ".cfg",
               ".properties", ".ini", ".toml"}): _YELLOW,
    # bancos de dados
    frozenset({".db", ".sqlite", ".sqlite3", ".db3"}): _MAGENTA,
    # imagens / mídia
    frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp",
               ".mp4", ".mp3", ".ogg", ".wav"}): _CYAN,
}

_BUILTIN_CMDS = [
    "ls", "cd", "pwd", "cat", "echo", "grep", "find", "ps", "top",
    "chmod", "chown", "cp", "mv", "rm", "mkdir", "rmdir", "touch",
    "stat", "file", "du", "df", "mount", "umount", "id", "whoami",
    "getprop", "setprop", "pm", "am", "dumpsys", "logcat", "su",
    "download", "upload", "clear", "help", "exit", "quit",
]

_HELP = f"""
  {_CYAN}Comandos especiais:{_RESET}
  {_WHITE}download{_RESET} {_DIM}<path_remoto> [path_local]{_RESET}   — copia arquivo do dispositivo para PC
  {_WHITE}upload{_RESET}   {_DIM}<path_local> [path_remoto]{_RESET}   — envia arquivo do PC para dispositivo
  {_WHITE}clear{_RESET}                                — limpa a tela
  {_WHITE}exit{_RESET} / {_WHITE}quit{_RESET}                         — sai do shell
  {_WHITE}help{_RESET}                                 — mostra esta ajuda
  {_DIM}Tab                                  — autocomplete de comandos e caminhos{_RESET}
"""


# ─── ADB helpers ──────────────────────────────────────────────────────────────

def _run_adb(adb: str, stdin_data: str, timeout: int = 30) -> tuple[str, str]:
    try:
        r = subprocess.run(
            [adb, "shell"],
            input=stdin_data.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
        )
        out = r.stdout.decode("utf-8", errors="replace").strip()
        err = r.stderr.decode("utf-8", errors="replace").strip()
        return out, err
    except subprocess.TimeoutExpired:
        return "", "[timeout]"
    except Exception as e:
        return "", str(e)


def _adb_su(adb: str, cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            [adb, "shell", "su", "-c", cmd],
            capture_output=True, timeout=timeout
        )
        return r.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _get_context(adb: str) -> tuple[str, str]:
    out, _ = _run_adb(adb, "whoami\npwd\n", timeout=8)
    lines = out.splitlines()
    if len(lines) >= 2:
        return lines[0].strip(), lines[1].strip()
    return "shell", "/sdcard"


# ─── Listagem colorida ────────────────────────────────────────────────────────

def _file_color(name: str, perms: str) -> str:
    """Retorna código de cor baseado em permissões e extensão."""
    if perms.startswith("d"):
        return _BLUE + _BOLD
    if perms.startswith("l"):
        return _CYAN
    # Executável (x bit)
    if "x" in perms[1:4]:
        return _GREEN
    ext = Path(name).suffix.lower()
    for exts, color in _EXT_COLORS.items():
        if ext in exts:
            return color
    return _WHITE


def _ls_colored(adb: str, path: str) -> str:
    """Executa ls -la e retorna output colorido."""
    raw = _adb_su(adb, f"ls -la '{path}' 2>/dev/null")
    lines = raw.splitlines()
    out_lines = []
    for line in lines:
        if not line.strip() or line.startswith("total"):
            out_lines.append(f"  {_DIM}{line}{_RESET}")
            continue
        parts = line.split()
        if len(parts) < 8:
            out_lines.append(f"  {line}")
            continue
        perms = parts[0]
        size  = parts[4].rjust(8)
        date  = f"{parts[5]} {parts[6]}"
        name  = " ".join(parts[7:])
        # Link: "name -> target"
        if "->" in name:
            fname, _, target = name.partition(" -> ")
            color = _file_color(fname, perms)
            out_lines.append(
                f"  {_DIM}{perms}  {size}  {date}  {_RESET}"
                f"{color}{fname}{_RESET}{_DIM} -> {target}{_RESET}"
            )
        else:
            color = _file_color(name, perms)
            out_lines.append(
                f"  {_DIM}{perms}  {size}  {date}  {_RESET}"
                f"{color}{name}{_RESET}"
            )
    return "\n".join(out_lines)


# ─── Autocomplete ─────────────────────────────────────────────────────────────

def _list_remote(adb: str, path: str) -> list[str]:
    """Lista entradas de um diretório remoto (nomes apenas)."""
    raw = _adb_su(adb, f"ls -1a '{path}' 2>/dev/null", timeout=5)
    return [l.strip() for l in raw.splitlines() if l.strip() not in (".", "..")]


def _complete(adb: str, cwd: str, text: str) -> list[str]:
    """
    Retorna lista de completions para `text`.
    - Se text não contém espaço: completa comandos builtin
    - Se text contém espaço: completa o último token como caminho remoto
    """
    if " " not in text:
        # Completa comando
        prefix = text.lower()
        return [c for c in _BUILTIN_CMDS if c.startswith(prefix)]

    # Completa caminho (último token)
    tokens = text.split()
    partial = tokens[-1] if tokens else ""

    if "/" in partial:
        dir_part  = partial.rsplit("/", 1)[0] or "/"
        name_part = partial.rsplit("/", 1)[1]
        base = dir_part if dir_part.startswith("/") else f"{cwd}/{dir_part}"
    else:
        dir_part  = ""
        name_part = partial
        base = cwd

    entries = _list_remote(adb, base)
    matches = [e for e in entries if e.startswith(name_part)]

    if dir_part:
        return [f"{dir_part}/{m}" for m in matches]
    return matches


def _common_prefix(options: list[str]) -> str:
    if not options:
        return ""
    prefix = options[0]
    for o in options[1:]:
        while not o.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


# ─── Input com Tab e histórico ────────────────────────────────────────────────

def _readline(prompt_str: str, adb: str, cwd: str) -> str:
    """
    Lê uma linha com suporte a:
    - Tab: autocomplete
    - Backspace: apaga caractere
    - Setas ←→: move cursor
    - ↑↓: histórico
    - Ctrl+C: retorna 'exit'
    """
    # Habilita ANSI no Windows
    os.system("")

    sys.stdout.write(prompt_str)
    sys.stdout.flush()

    buf      = []
    cursor   = 0
    hist_idx = len(_history)

    def _redraw():
        line = "".join(buf)
        # Volta ao início da linha e redesenha
        sys.stdout.write(f"\r{prompt_str}{line}  \r{prompt_str}{''.join(buf[:cursor])}")
        sys.stdout.flush()

    while True:
        ch = msvcrt.getwch()

        if ch == "\r":  # Enter
            sys.stdout.write("\n")
            sys.stdout.flush()
            return "".join(buf)

        elif ch == "\x03":  # Ctrl+C
            sys.stdout.write("\n")
            return "exit"

        elif ch == "\x08":  # Backspace
            if cursor > 0:
                buf.pop(cursor - 1)
                cursor -= 1
                _redraw()

        elif ch == "\t":  # Tab — autocomplete
            text    = "".join(buf[:cursor])
            options = _complete(adb, cwd, text)
            if not options:
                pass
            elif len(options) == 1:
                # Completa o token atual
                tokens  = text.split(" ")
                tokens[-1] = options[0]
                new_text = " ".join(tokens)
                buf    = list(new_text)
                cursor = len(buf)
                _redraw()
            else:
                # Mostra opções e completa prefixo comum
                prefix = _common_prefix(options)
                sys.stdout.write(f"\n")
                # Colorir pastas na lista de completions
                cols = []
                for o in options:
                    if not Path(o).suffix:  # provavelmente pasta
                        cols.append(f"{_BLUE}{_BOLD}{o}{_RESET}")
                    else:
                        cols.append(f"{_WHITE}{o}{_RESET}")
                sys.stdout.write("  " + "  ".join(cols) + "\n")
                sys.stdout.flush()
                if prefix:
                    tokens = text.split(" ")
                    tokens[-1] = prefix
                    new_text = " ".join(tokens)
                    buf    = list(new_text)
                    cursor = len(buf)
                sys.stdout.write(prompt_str + "".join(buf))
                sys.stdout.flush()

        elif ch == "\x00" or ch == "\xe0":  # tecla especial
            ch2 = msvcrt.getwch()
            if ch2 == "K":  # ←
                if cursor > 0:
                    cursor -= 1
                    _redraw()
            elif ch2 == "M":  # →
                if cursor < len(buf):
                    cursor += 1
                    _redraw()
            elif ch2 == "H":  # ↑ histórico
                if _history and hist_idx > 0:
                    hist_idx -= 1
                    buf    = list(_history[hist_idx])
                    cursor = len(buf)
                    _redraw()
            elif ch2 == "P":  # ↓ histórico
                if hist_idx < len(_history) - 1:
                    hist_idx += 1
                    buf    = list(_history[hist_idx])
                    cursor = len(buf)
                    _redraw()
                elif hist_idx == len(_history) - 1:
                    hist_idx += 1
                    buf    = []
                    cursor = 0
                    _redraw()
            elif ch2 == "S":  # Delete
                if cursor < len(buf):
                    buf.pop(cursor)
                    _redraw()
            elif ch2 == "G":  # Home
                cursor = 0
                _redraw()
            elif ch2 == "O":  # End
                cursor = len(buf)
                _redraw()

        elif ch >= " ":  # caractere imprimível
            buf.insert(cursor, ch)
            cursor += 1
            _redraw()


_history: list[str] = []


# ─── Download / Upload ────────────────────────────────────────────────────────

def _download(adb: str, mobile_path: str, local_path: str = "."):
    print(f"{_CYAN}→ Download: {mobile_path} → {local_path}{_RESET}")
    r = subprocess.run([adb, "pull", mobile_path, local_path], capture_output=True)
    if r.returncode == 0:
        print(f"{_GREEN}✔ Concluído{_RESET}")
        return
    tmp = f"/sdcard/_noxdroid_tmp_{Path(mobile_path).name}"
    subprocess.run([adb, "shell", "su", "-c", f"cp '{mobile_path}' '{tmp}'"])
    r2 = subprocess.run([adb, "pull", tmp, local_path], capture_output=True)
    subprocess.run([adb, "shell", "rm", "-f", tmp], capture_output=True)
    if r2.returncode == 0:
        print(f"{_GREEN}✔ Concluído (via /sdcard){_RESET}")
    else:
        print(f"{_RED}✖ Falha: {r2.stderr.decode(errors='replace')}{_RESET}")


def _upload(adb: str, local_path: str, mobile_path: str):
    if not Path(local_path).exists():
        print(f"{_RED}✖ Arquivo local não encontrado: {local_path}{_RESET}")
        return
    print(f"{_CYAN}→ Upload: {local_path} → {mobile_path}{_RESET}")
    tmp = f"/sdcard/_noxdroid_up_{Path(local_path).name}"
    r = subprocess.run([adb, "push", local_path, tmp], capture_output=True)
    if r.returncode != 0:
        print(f"{_RED}✖ Push falhou: {r.stderr.decode(errors='replace')}{_RESET}")
        return
    r2 = subprocess.run(
        [adb, "shell", "su", "-c", f"mv '{tmp}' '{mobile_path}'"],
        capture_output=True
    )
    if r2.returncode == 0:
        print(f"{_GREEN}✔ Concluído{_RESET}")
    else:
        print(f"{_YELLOW}⚠ Arquivo em /sdcard (sem permissão para mover): {tmp}{_RESET}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def interactive_adb_shell(adb: str):
    os.system("cls")
    # Habilita ANSI no Windows
    os.system("")

    print(f"{_CYAN}{'═' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  NoxDroid — ADB Shell{_RESET}")
    print(f"{_DIM}  Conectando ao dispositivo...{_RESET}")
    print(f"{_CYAN}{'═' * 70}{_RESET}\n")

    user, cwd = _get_context(adb)
    if not user:
        print(f"{_RED}✖ Não foi possível conectar ao dispositivo via ADB.{_RESET}")
        input("\n→ Enter para voltar...")
        return

    print(f"  {_GREEN}✔ Conectado{_RESET}  usuário: {_WHITE}{user}{_RESET}  dir: {_CYAN}{cwd}{_RESET}")
    print(f"  {_DIM}Tab=autocomplete  ↑↓=histórico  help=ajuda  exit=sair{_RESET}\n")
    print(f"  {_DIM}Cores: {_BLUE}{_BOLD}pasta{_RESET}  {_GREEN}executável{_RESET}  "
          f"{_CYAN}link{_RESET}  {_MAGENTA}banco de dados{_RESET}  "
          f"{_YELLOW}config/json{_RESET}  {_WHITE}arquivo{_RESET}\n")

    while True:
        user_color  = _RED if user in ("root", "su") else _GREEN
        prompt_str  = (
            f"{user_color}{_BOLD}{user}{_RESET}"
            f"{_DIM}@device{_RESET}:"
            f"{_BLUE}{_BOLD}{cwd}{_RESET}$ "
        )

        try:
            cmd = _readline(prompt_str, adb, cwd).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue

        # Histórico
        if not _history or _history[-1] != cmd:
            _history.append(cmd)

        if cmd == "clear":
            os.system("cls")
            os.system("")
            print(f"{_CYAN}{_BOLD}  NoxDroid — ADB Shell{_RESET}  {_DIM}exit para sair{_RESET}\n")
            continue

        if cmd in ("exit", "quit"):
            print()
            break

        if cmd == "help":
            print(_HELP)
            continue

        words = cmd.split()

        # ls — intercepta para colorir
        if words[0] == "ls":
            target = cwd
            for w in words[1:]:
                if not w.startswith("-"):
                    target = w if w.startswith("/") else f"{cwd}/{w}"
                    break
            print(_ls_colored(adb, target))
            continue

        if words[0] == "download":
            if len(words) < 2:
                print(f"{_YELLOW}  Uso: download <path_remoto> [path_local]{_RESET}")
            else:
                mp = words[1] if words[1].startswith("/") else f"{cwd}/{words[1]}"
                lp = words[2] if len(words) > 2 else "."
                _download(adb, mp, lp)
            continue

        if words[0] == "upload":
            if len(words) < 2:
                print(f"{_YELLOW}  Uso: upload <path_local> [path_remoto]{_RESET}")
            else:
                lp = words[1]
                mp = words[2] if len(words) > 2 else cwd
                if not mp.startswith("/"):
                    mp = f"{cwd}/{mp}"
                _upload(adb, lp, mp)
            continue

        # Comando normal — mantém contexto via separador
        stdin_data = f"su\ncd '{cwd}'\n{cmd}\necho __SEP__\nwhoami\npwd\n"
        out, err = _run_adb(adb, stdin_data)

        lines   = out.splitlines()
        sep_idx = next((i for i, l in enumerate(lines) if l.strip() == "__SEP__"), None)

        if sep_idx is not None:
            output_lines = lines[:sep_idx]
            tail = lines[sep_idx + 1:]
            if len(tail) >= 2:
                user = tail[-2].strip()
                cwd  = tail[-1].strip()
        else:
            output_lines = lines

        if output_lines:
            print("\n".join(output_lines))
        if err:
            print(f"{_RED}{err}{_RESET}")
