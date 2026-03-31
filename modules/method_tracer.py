"""
Method Tracer — launcher para o Frida Stalker / Method Tracer.
Configura o modo de trace, injeta config no script JS e salva output.
"""
import sys
import os
import shutil
import subprocess
import json
import tempfile
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

SCRIPT_PATH = Path(__file__).parent.parent / "Fripts" / "Recon" / "method_tracer.js"
STACK_JS    = Path(__file__).parent.parent / "Fripts" / "stack.js"
RESULTS_DIR = Path("results")


def _clear():
    os.system("cls" if sys.platform == "win32" else "clear")
    os.system("")


def _frida_bin() -> str:
    found = shutil.which("frida")
    if found:
        return found
    try:
        r = subprocess.run([sys.executable, "-m", "site", "--user-base"],
                           capture_output=True, text=True)
        base = r.stdout.strip()
        for sub in ["Scripts", f"Python{sys.version_info.major}{sys.version_info.minor}\\Scripts"]:
            c = Path(base) / sub / "frida.exe"
            if c.exists():
                return str(c)
    except Exception:
        pass
    return "frida"


def _header():
    _clear()
    print(f"{_CYAN}{'═' * 60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Method Tracer — Frida Stalker{_RESET}")
    print(f"{_CYAN}{'═' * 60}{_RESET}\n")


def _pick_mode(pkg: str) -> dict | None:
    """Apresenta menu de configuração do trace e retorna config dict."""
    _header()
    print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")

    # ── Modo de attach ────────────────────────────────────────────────────────
    print(f"  {_CYAN}Modo de execução:{_RESET}")
    print(f"  {_GREEN}1.{_RESET} Attach  {_DIM}(app já está aberto — recomendado){_RESET}")
    print(f"  {_GREEN}2.{_RESET} Spawn   {_DIM}(Frida reinicia o app){_RESET}")
    print(f"\n  {_DIM}0. Cancelar{_RESET}")
    attach_choice = input(f"\n{_CYAN}→{_RESET} ").strip()
    if attach_choice == "0" or not attach_choice:
        return None
    use_spawn = attach_choice == "2"

    # ── Modo de trace ─────────────────────────────────────────────────────────
    _header()
    print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
    print(f"  {_CYAN}Modo de trace:{_RESET}")
    print(f"  {_GREEN}1.{_RESET} Métodos sensíveis  {_DIM}(crypto, auth, network, storage — recomendado){_RESET}")
    print(f"  {_GREEN}2.{_RESET} Por package prefix  {_DIM}(todos os métodos do app){_RESET}")
    print(f"  {_GREEN}3.{_RESET} Por classe específica  {_DIM}(uma classe Java){_RESET}")
    print(f"\n  {_DIM}0. Cancelar{_RESET}")
    choice = input(f"\n{_CYAN}→{_RESET} ").strip()
    if choice == "0" or not choice:
        return None

    config = {
        "mode":           "sensitive",
        "target":         "",
        "maxDepth":       4,
        "showArgs":       True,
        "showReturn":     True,
        "filterInternal": True,
        "maxEvents":      2000,
        "_spawn":         use_spawn,   # usado pelo launcher, não pelo JS
    }

    if choice == "1":
        config["mode"] = "sensitive"

    elif choice == "2":
        config["mode"] = "package"
        default = ".".join(pkg.split(".")[:3])
        target = input(f"\n  Package prefix [{default}]: ").strip()
        config["target"] = target or default

    elif choice == "3":
        config["mode"] = "class"
        target = input(f"\n  Nome completo da classe (ex: com.example.LoginActivity): ").strip()
        if not target:
            return None
        config["target"] = target

    else:
        return None

    # ── Opções extras ─────────────────────────────────────────────────────────
    print(f"\n  {_DIM}Mostrar argumentos? (S/n):{_RESET} ", end="")
    ans = input().strip().lower()
    config["showArgs"] = ans != "n"

    print(f"  {_DIM}Mostrar retorno? (S/n):{_RESET} ", end="")
    ans = input().strip().lower()
    config["showReturn"] = ans != "n"

    print(f"  {_DIM}Max eventos [{config['maxEvents']}]: {_RESET}", end="")
    ans = input().strip()
    if ans.isdigit():
        config["maxEvents"] = int(ans)

    print(f"  {_DIM}Mostrar stack trace nos hooks? (s/N):{_RESET} ", end="")
    ans = input().strip().lower()
    config["_stackEnabled"] = ans == "s"

    return config


def _inject_config(js_source: str, config: dict) -> str:
    """Injeta a config como variável global no início do script JS.
    Também prepend stack.js se disponível, com __STACK_CONFIG__ ativado."""
    stack_enabled = config.pop("_stackEnabled", False)
    stack_cfg = json.dumps({"enabled": stack_enabled, "maxDepth": 8, "skipSystem": True, "accurate": True})
    stack_src = ""
    if STACK_JS.exists():
        stack_src = STACK_JS.read_text(encoding="utf-8")
    config_js = (
        f"var __STACK_CONFIG__ = {stack_cfg};\n"
        f"var __TRACE_CONFIG__ = {json.dumps(config, indent=2)};\n\n"
    )
    return config_js + stack_src + "\n\n" + js_source


def run_method_tracer(pkg: str):
    if not SCRIPT_PATH.exists():
        print(f"{_RED}✖ Script não encontrado: {SCRIPT_PATH}{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    config = _pick_mode(pkg)
    if not config:
        return

    # Prepara script com config injetada (remove chave interna _spawn)
    js_config = {k: v for k, v in config.items() if not k.startswith("_")}
    js_source  = SCRIPT_PATH.read_text(encoding="utf-8")
    js_patched = _inject_config(js_source, js_config)

    tmp = Path(tempfile.mktemp(suffix=".js"))
    tmp.write_text(js_patched, encoding="utf-8")

    # Prepara output
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import dynamic_dir
    out_dir = dynamic_dir(pkg)
    out_file = out_dir / "method_trace.txt"

    use_spawn = config.get("_spawn", False)
    attach_mode = "spawn (reinicia app)" if use_spawn else "attach (app já aberto)"

    _header()
    print(f"  {_WHITE}Package : {_CYAN}{pkg}{_RESET}")
    print(f"  {_WHITE}Modo    : {_CYAN}{config['mode']}{_RESET}")
    if config["target"]:
        print(f"  {_WHITE}Target  : {_CYAN}{config['target']}{_RESET}")
    print(f"  {_WHITE}Attach  : {_CYAN}{attach_mode}{_RESET}")
    print(f"  {_WHITE}Output  : {_DIM}{out_file}{_RESET}")
    if not use_spawn:
        print(f"\n  {_YELLOW}Certifique-se que o app está aberto no dispositivo.{_RESET}")
    print(f"  {_DIM}Pressione Ctrl+C para parar e salvar o relatório.{_RESET}\n")
    print(f"{_CYAN}{'─' * 60}{_RESET}\n")

    frida = _frida_bin()

    # -n = attach ao processo já em execução
    # -f = spawn (mata e reinicia o app)
    if use_spawn:
        frida_args = [frida, "-U", "-f", pkg, "-l", str(tmp)]
    else:
        frida_args = [frida, "-U", "-n", pkg, "-l", str(tmp)]

    lines = []

    try:
        proc = subprocess.Popen(
            frida_args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )
        for line in proc.stdout:
            stripped = line.rstrip()
            # Filtra linhas de protocolo interno do Frida (send/payload JSON)
            if stripped.startswith("{'type': 'send'") or stripped.startswith('{"type": "send"'):
                continue
            if stripped.startswith("message:") or stripped.startswith("data:"):
                continue
            # Coloriza output limpo
            if "→" in stripped:
                depth = (len(stripped) - len(stripped.lstrip())) // 2
                color = _CYAN if depth <= 1 else _WHITE if depth <= 3 else _DIM
                print(f"{color}{stripped}{_RESET}")
            elif "←" in stripped:
                print(f"{_GREEN}{stripped}{_RESET}")
            elif stripped.startswith("[NoxDroid]") or stripped.startswith("[Tracer]"):
                print(f"{_YELLOW}{stripped}{_RESET}")
            elif stripped.startswith("[!]") or "Error" in stripped or "error" in stripped:
                print(f"{_RED}{stripped}{_RESET}")
            elif stripped.startswith("════") or stripped.startswith("────"):
                print(f"{_CYAN}{stripped}{_RESET}")
            else:
                print(f"{_DIM}{stripped}{_RESET}")
            lines.append(line)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            tmp.unlink()
        except Exception:
            pass

    # Salva relatório
    if lines:
        header_lines = [
            f"Method Tracer — {pkg}",
            f"Timestamp : {ts}",
            f"Modo      : {config['mode']}",
            f"Target    : {config.get('target', '')}",
            f"ShowArgs  : {config['showArgs']}",
            f"ShowReturn: {config['showReturn']}",
            "",
            "─" * 60,
            "",
        ]
        out_file.write_text("\n".join(header_lines) + "".join(lines), encoding="utf-8")
        print(f"\n{_CYAN}{'─' * 60}{_RESET}")
        print(f"{_GREEN}✔ Relatório salvo: {out_file}{_RESET}")
        print(f"{_DIM}  {len(lines)} linhas capturadas{_RESET}")

    input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
