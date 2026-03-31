"""
results_viewer.py — Visualizador de relatórios gerados pelo NoxDroid

Lista todos os relatórios em results/ organizados por package,
permite abrir arquivos .txt no terminal ou .html no navegador.
"""
import os
import subprocess
import webbrowser
from datetime import datetime
from pathlib import Path

_R  = "\033[0m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[90m"
_W  = "\033[97m"
_B  = "\033[1m"

RESULTS_DIR = Path("results")

# Categoria por subpasta
_FOLDER_LABEL = {
    "static":   "Estatica",
    "dynamic":  "Dinamica",
    "network":  "Rede",
    "databases":"Databases",
    "apk":      "APK",
}

# Icones por nome de arquivo
_ICONS = {
    "native_scan":    "[NAT]",
    "intent_fuzzer":  "[INT]",
    "crypto_monitor": "[CRY]",
    "androguard":     "[AND]",
    "secrets":        "[SEC]",
    "apkid":          "[APK]",
    "mobsfscan":      "[MOB]",
    "vuln":           "[VUL]",
    "meminfo":        "[MEM]",
    "traffic":        "[TRF]",
    "method_trace":   "[TRC]",
    "beautifest":     "[BEA]",
    "hardcode":       "[HRD]",
    "cert_pinning":   "[PIN]",
    "root_detection": "[ROT]",
    "antidebug":      "[DBG]",
    "connections":    "[NET]",
    "logcat":         "[LOG]",
}


def _icon_for(name: str) -> str:
    low = name.lower()
    for key, icon in _ICONS.items():
        if key in low:
            return icon
    return "[---]"


def _category_for(path: Path) -> str:
    """Retorna o label da categoria baseado na subpasta."""
    parts = path.parts
    for i, part in enumerate(parts):
        if part in _FOLDER_LABEL:
            return _FOLDER_LABEL[part]
    return ""


def _fmt_size(path: Path) -> str:
    try:
        size = path.stat().st_size
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size // 1024}KB"
        return f"{size // (1024*1024)}MB"
    except Exception:
        return "?"


def _fmt_date(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
        return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return "?"


def _collect_reports() -> dict:
    """Retorna {package: {categoria: [arquivos]}} ordenado por data."""
    if not RESULTS_DIR.exists():
        return {}

    reports = {}
    for pkg_dir in sorted(RESULTS_DIR.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg = pkg_dir.name
        by_cat: dict[str, list] = {}

        for f in pkg_dir.rglob("*"):
            if not f.is_file() or f.suffix not in (".txt", ".html", ".json"):
                continue
            # Determina categoria pela subpasta imediata de pkg_dir
            try:
                rel   = f.relative_to(pkg_dir)
                cat   = _FOLDER_LABEL.get(rel.parts[0], "Outros")
            except Exception:
                cat   = "Outros"
            by_cat.setdefault(cat, []).append(f)

        if by_cat:
            # Ordena cada categoria por data desc
            for cat in by_cat:
                by_cat[cat].sort(key=lambda p: p.stat().st_mtime, reverse=True)
            reports[pkg] = by_cat

    return reports


def _open_file(path: Path):
    """Abre o arquivo no terminal (txt) ou navegador (html)."""
    if path.suffix == ".html":
        print(f"\n  {_C}→ Abrindo no navegador...{_R}")
        webbrowser.open(path.resolve().as_uri())
        return

    # .txt / .json — exibe no terminal com paginação simples
    os.system("cls" if os.name == "nt" else "clear")
    print(f"{_C}{'─'*70}{_R}")
    print(f"{_C}{_B}  {path.name}{_R}  {_D}{path}{_R}")
    print(f"{_C}{'─'*70}{_R}\n")

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        lines   = content.splitlines()
        page    = 40
        start   = 0

        while start < len(lines):
            chunk = lines[start:start + page]
            for line in chunk:
                # Coloriza linhas de severidade
                low = line.lower()
                if "[critical]" in low or "[high]" in low:
                    print(f"  {_RE}{line}{_R}")
                elif "[medium]" in low:
                    print(f"  {_Y}{line}{_R}")
                elif "[low]" in low or "[info]" in low:
                    print(f"  {_D}{line}{_R}")
                elif line.startswith("=") or line.startswith("─"):
                    print(f"  {_C}{line}{_R}")
                else:
                    print(f"  {line}")

            start += page
            if start < len(lines):
                remaining = len(lines) - start
                cont = input(f"\n  {_D}[{remaining} linhas restantes — Enter para continuar, q para sair]{_R} ").strip().lower()
                if cont == "q":
                    break
    except Exception as e:
        print(f"  {_RE}✖ Erro ao ler arquivo: {e}{_R}")

    input(f"\n  {_D}→ Enter para voltar...{_R}")


def results_viewer_menu():
    from utils.common import clear_screen
    from core.banner import display_banner

    while True:
        clear_screen()
        display_banner()

        reports = _collect_reports()

        print(f"\n{_C}Relatorios Gerados{_R}\n")

        if not reports:
            print(f"  {_D}Nenhum relatorio encontrado em results/{_R}")
            print(f"  {_D}Execute analises para gerar relatorios.{_R}")
            input(f"\n  {_D}-> Enter para voltar...{_R}")
            return

        pkgs = list(reports.keys())
        for i, pkg in enumerate(pkgs, 1):
            total  = sum(len(v) for v in reports[pkg].values())
            cats   = "  ".join(
                f"{_C}{cat}{_R}{_D}({len(files)}){_R}"
                for cat, files in reports[pkg].items()
            )
            print(f"  {_C}{i}.{_R} {_W}{pkg}{_R}")
            print(f"       {cats}  {_D}| {total} arquivo(s){_R}")

        print(f"\n  {_D}0. Voltar{_R}")

        choice = input(f"\n{_C}->{_R} ").strip()
        if choice == "0":
            break
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(pkgs)):
                continue
        except ValueError:
            continue

        pkg    = pkgs[idx]
        by_cat = reports[pkg]

        # ── Nivel 2: categorias ───────────────────────────────────────────────
        while True:
            clear_screen()
            display_banner()
            print(f"\n{_C}Relatorios — {pkg}{_R}\n")

            cat_list = list(by_cat.keys())
            for i, cat in enumerate(cat_list, 1):
                files  = by_cat[cat]
                latest = _fmt_date(files[0])
                print(f"  {_C}{i}.{_R} {_W}{cat:<12}{_R}  "
                      f"{_D}{len(files)} arquivo(s)  ultimo: {latest}{_R}")

            print(f"\n  {_D}0. Voltar{_R}")

            csel = input(f"\n{_C}->{_R} ").strip()
            if csel == "0":
                break
            try:
                cidx = int(csel) - 1
                if not (0 <= cidx < len(cat_list)):
                    continue
            except ValueError:
                continue

            cat       = cat_list[cidx]
            cat_files = by_cat[cat]

            # ── Nivel 3: arquivos da categoria ────────────────────────────────
            while True:
                clear_screen()
                display_banner()
                print(f"\n{_C}{pkg}  /  {cat}{_R}\n")
                print(f"  {_D}{'#':>3}  {'Tipo':<7}  {'Arquivo':<35}  {'Tam':>6}  Data{_R}")
                print(f"  {_D}{'─' * 68}{_R}")

                for i, f in enumerate(cat_files, 1):
                    icon = _icon_for(f.name)
                    size = _fmt_size(f)
                    date = _fmt_date(f)
                    name = f.name
                    if len(name) > 34:
                        name = name[:31] + "..."
                    print(f"  {_C}{i:>3}{_R}  {_Y}{icon:<7}{_R}  {_W}{name:<35}{_R}  "
                          f"{_D}{size:>6}  {date}{_R}")

                print(f"\n  {_D}0. Voltar{_R}")

                fsel = input(f"\n{_C}->{_R} ").strip()
                if fsel == "0":
                    break
                try:
                    fidx = int(fsel) - 1
                    if 0 <= fidx < len(cat_files):
                        _open_file(cat_files[fidx])
                except ValueError:
                    continue
