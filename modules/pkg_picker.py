"""
Package Picker — lista interativa de apps instalados no dispositivo.
Navegação com ↑↓, busca com digitação, Enter para selecionar.
"""
import subprocess
import os
import sys
import msvcrt

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_SEL_BG = "\033[30;46m"
_RED    = "\033[91m"

MAX_VISIBLE = 20


def _adb_list_packages(adb: str, filter_flag: str = "-3") -> list[str]:
    """
    Lista packages instalados.
    filter_flag: -3 = terceiros, -e = habilitados, "" = todos
    """
    try:
        r = subprocess.run(
            [adb, "shell", "pm", "list", "packages", filter_flag],
            capture_output=True, timeout=15
        )
        out = r.stdout.decode("utf-8", errors="replace")
        pkgs = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                pkgs.append(line[len("package:"):].strip())
        return sorted(pkgs)
    except Exception:
        return []


def _render(pkgs: list[str], selected: int, scroll: int, query: str, title: str, total_all: int):
    os.system("cls")
    os.system("")
    print(f"\n{_CYAN}{'═' * 65}{_RESET}")
    print(f"{_CYAN}{_BOLD}  {title}{_RESET}")
    print(f"{_DIM}  ↑↓ navegar  Enter selecionar  Esc cancelar  digitar para filtrar{_RESET}")
    print(f"{_CYAN}{'═' * 65}{_RESET}\n")

    # Barra de busca
    print(f"  {_CYAN}Busca:{_RESET} {_WHITE}{query}{_CYAN}▌{_RESET}  "
          f"{_DIM}({len(pkgs)} de {total_all} apps){_RESET}\n")

    if not pkgs:
        print(f"  {_DIM}Nenhum app encontrado.{_RESET}")
    else:
        visible = pkgs[scroll:scroll + MAX_VISIBLE]
        for i, pkg in enumerate(visible):
            real_idx = scroll + i
            # Destaca a parte que bate com a query
            if query and query.lower() in pkg.lower():
                idx = pkg.lower().index(query.lower())
                display = (
                    pkg[:idx]
                    + f"{_YELLOW}{pkg[idx:idx+len(query)]}{_RESET}"
                    + pkg[idx+len(query):]
                )
            else:
                display = pkg

            if real_idx == selected:
                # Linha selecionada — sem highlight de query para não quebrar o bg
                print(f"  {_SEL_BG} › {pkg:<58} {_RESET}")
            else:
                print(f"  {_DIM}  {_RESET}{display}")

    print(f"\n{_CYAN}{'─' * 65}{_RESET}")
    if pkgs and 0 <= selected < len(pkgs):
        print(f"  {_DIM}Selecionado: {_RESET}{_WHITE}{pkgs[selected]}{_RESET}")


def pick_package(adb: str, title: str = "Selecionar App",
                 filter_flag: str = "-3") -> str | None:
    """
    Exibe lista navegável de apps instalados.
    Retorna o package name selecionado ou None se cancelado.

    filter_flag:
      -3  = apenas apps de terceiros (padrão)
      -e  = todos os apps habilitados
      ""  = todos (incluindo sistema)
    """
    print(f"\n  {_DIM}Carregando lista de apps...{_RESET}", end="", flush=True)
    all_pkgs = _adb_list_packages(adb, filter_flag)

    if not all_pkgs:
        print(f"\r  {_RED}✖ Nenhum app encontrado ou dispositivo não conectado.{_RESET}")
        input(f"\n  {_DIM}→ Enter para continuar...{_RESET}")
        return None

    query    = ""
    filtered = all_pkgs[:]
    selected = 0
    scroll   = 0

    while True:
        _render(filtered, selected, scroll, query, title, len(all_pkgs))

        kind, ch = _getch()

        if kind == "char":
            if ch == b"\r":  # Enter
                if filtered:
                    return filtered[selected]
                return None

            elif ch in (b"\x1b", b"\x03"):  # Esc / Ctrl+C
                return None

            elif ch == b"\x08":  # Backspace
                if query:
                    query = query[:-1]
                    filtered = [p for p in all_pkgs if query.lower() in p.lower()]
                    selected = 0
                    scroll   = 0

            elif ch == b"\t":  # Tab — alterna entre -3 / -e / todos
                pass

            elif 0x20 <= ch[0] <= 0x7e:  # caractere imprimível
                query   += ch.decode("utf-8", errors="replace")
                filtered = [p for p in all_pkgs if query.lower() in p.lower()]
                selected = 0
                scroll   = 0

        elif kind == "special":
            if ch == b"H":  # ↑
                if selected > 0:
                    selected -= 1
                    if selected < scroll:
                        scroll = selected

            elif ch == b"P":  # ↓
                if selected < len(filtered) - 1:
                    selected += 1
                    if selected >= scroll + MAX_VISIBLE:
                        scroll += 1

            elif ch == b"I":  # Page Up
                selected = max(0, selected - MAX_VISIBLE)
                scroll   = max(0, scroll - MAX_VISIBLE)

            elif ch == b"Q":  # Page Down
                selected = min(len(filtered) - 1, selected + MAX_VISIBLE)
                scroll   = min(max(0, len(filtered) - MAX_VISIBLE), scroll + MAX_VISIBLE)


def _getch():
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):
        return ("special", msvcrt.getch())
    return ("char", ch)
