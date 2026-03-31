"""
Objection Menu — interface interativa para comandos do Objection.
Categorias:
  - Hooking (métodos, classes, atividades)
  - Memory (dump, search, write)
  - Filesystem (ls, cat, download, upload)
  - SSL Pinning Bypass
  - Root Detection Bypass
  - Clipboard
  - Keystore
  - Intents
"""
import subprocess
import sys
from pathlib import Path

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"


def _clear():
    import os
    os.system("cls" if sys.platform == "win32" else "clear")


def _header(title: str):
    _clear()
    print(f"\n{_CYAN}{'═' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Objection — {title}{_RESET}")
    print(f"{_CYAN}{'═' * 70}{_RESET}\n")


def _objection_bin() -> str:
    """Retorna o caminho completo do executável objection.exe."""
    import shutil, sysconfig

    if shutil.which("objection"):
        return "objection"

    scripts = sysconfig.get_path("scripts")
    if scripts:
        ext = ".exe" if sys.platform == "win32" else ""
        candidate = Path(scripts) / f"objection{ext}"
        if candidate.exists():
            return str(candidate)

    # Fallback: caminho fixo Python 3.13 no Windows
    fallback = Path(r"C:\Users\User\AppData\Local\Programs\Python\Python313\Scripts\objection.exe")
    if fallback.exists():
        return str(fallback)

    return "objection"




def _frida_device_id() -> str | None:
    """
    Detecta o device ID que o frida usa para o dispositivo Android conectado.
    Usa get_usb_device() que é o mesmo que frida-ps -U usa.
    """
    try:
        import frida
        dev = frida.get_usb_device(timeout=3)
        if dev:
            return dev.id
    except Exception:
        pass
    return None


def _run_objection(pkg: str, cmd: str):
    """
    Executa um comando objection usando a API Python diretamente.
    Evita o CLI que usa frida.get_device() sem timeout e falha com Nox.
    """
    print(f"\n{_DIM}→ objection [{pkg}] {cmd}{_RESET}\n")
    print(f"{_CYAN}{'─' * 70}{_RESET}\n")

    agent = None
    try:
        import frida
        from objection.state.connection import state_connection
        from objection.state.app import app_state
        from objection.utils.agent import Agent, AgentConfig
        from objection.console.repl import COMMANDS, get_tokens

        # Resolve o device USB com timeout adequado
        device = frida.get_usb_device(timeout=10)

        # Cria o agent com device_id explícito
        config = AgentConfig(
            name=pkg,
            device_id=device.id,
            device_type=None,
        )
        agent = Agent(config)
        agent.run()
        state_connection.set_agent(agent)

        # Localiza e executa o método do comando sem instanciar o Repl
        tokens = get_tokens(cmd)

        def _find_exec(tokens, commands=COMMANDS):
            token_matches = 0
            exec_method = None
            current = commands
            for token in tokens:
                if token in current:
                    token_matches += 1
                    if "exec" in current[token]:
                        exec_method = current[token]["exec"]
                    if "commands" in current[token]:
                        current = current[token]["commands"]
                    else:
                        break
            return token_matches, exec_method

        n, exec_method = _find_exec(tokens)

        if exec_method is None:
            print(f"{_YELLOW}⚠ Comando não reconhecido: {cmd}{_RESET}")
        else:
            args = tokens[n:]
            exec_method(args)

    except ImportError as e:
        print(f"{_RED}✖ Dependência não encontrada: {e}{_RESET}")
        print(f"{_DIM}  Instale via: pip install objection{_RESET}")
    except KeyboardInterrupt:
        print(f"\n{_YELLOW}⚠ Interrompido pelo usuário{_RESET}")
    except Exception as e:
        err = str(e)
        if "Unable to find a device" in err or "device not found" in err:
            print(f"{_RED}✖ Dispositivo não encontrado.{_RESET}")
            print(f"{_DIM}  Verifique se o frida-server está rodando: mafrida status{_RESET}")
        elif "spawn" in err.lower() or "attach" in err.lower():
            print(f"{_RED}✖ Não foi possível anexar ao processo '{pkg}'.{_RESET}")
            print(f"{_DIM}  Certifique-se que o app está aberto no dispositivo.{_RESET}")
        else:
            print(f"{_RED}✖ Erro: {e}{_RESET}")
    finally:
        if agent:
            try:
                agent.teardown()
            except Exception:
                pass

    print(f"\n{_CYAN}{'─' * 70}{_RESET}")


# ─── Menu: Hooking ────────────────────────────────────────────────────────────

def _menu_hooking(pkg: str):
    while True:
        _header("Hooking")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} Listar classes carregadas")
        print(f"  {_GREEN}2.{_RESET} Buscar classe por nome")
        print(f"  {_GREEN}3.{_RESET} Listar métodos de uma classe")
        print(f"  {_GREEN}4.{_RESET} Hook em método específico")
        print(f"  {_GREEN}5.{_RESET} Hook em todos os métodos de uma classe")
        print(f"  {_GREEN}6.{_RESET} Watch class (monitora instanciação)")
        print(f"  {_GREEN}7.{_RESET} Hook em Activity lifecycle")
        print(f"  {_GREEN}8.{_RESET} Listar activities")
        print(f"  {_GREEN}9.{_RESET} Listar services")
        print(f"\n  {_DIM}0. Voltar{_RESET}")
        
        choice = input(f"\n{_CYAN}→{_RESET} ").strip()
        
        if choice == "0":
            break
        elif choice == "1":
            _run_objection(pkg, "android hooking list classes")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            pattern = input(f"  Padrão de busca (ex: MainActivity): ").strip()
            if pattern:
                _run_objection(pkg, f"android hooking search classes {pattern}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            classname = input(f"  Nome completo da classe: ").strip()
            if classname:
                _run_objection(pkg, f"android hooking list class_methods {classname}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            classname = input(f"  Classe: ").strip()
            method = input(f"  Método: ").strip()
            if classname and method:
                _run_objection(pkg, f"android hooking watch class_method {classname}.{method} --dump-args --dump-return --dump-backtrace")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "5":
            classname = input(f"  Classe: ").strip()
            if classname:
                _run_objection(pkg, f"android hooking watch class {classname} --dump-args --dump-return")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "6":
            classname = input(f"  Classe: ").strip()
            if classname:
                _run_objection(pkg, f"android hooking watch class {classname}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "7":
            _run_objection(pkg, "android hooking watch activity")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "8":
            _run_objection(pkg, "android hooking list activities")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "9":
            _run_objection(pkg, "android hooking list services")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu: Memory ─────────────────────────────────────────────────────────────

def _menu_memory(pkg: str):
    while True:
        _header("Memory")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} Listar módulos carregados")
        print(f"  {_GREEN}2.{_RESET} Dump de memória (heap)")
        print(f"  {_GREEN}3.{_RESET} Buscar string na memória")
        print(f"  {_GREEN}4.{_RESET} Buscar bytes na memória")
        print(f"  {_GREEN}5.{_RESET} Listar instâncias de uma classe")
        print(f"  {_GREEN}6.{_RESET} Dump de instância específica")
        print(f"\n  {_DIM}0. Voltar{_RESET}")
        
        choice = input(f"\n{_CYAN}→{_RESET} ").strip()
        
        if choice == "0":
            break
        elif choice == "1":
            _run_objection(pkg, "memory list modules")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            out_file = input(f"  Arquivo de saída (ex: heap.bin): ").strip() or "heap.bin"
            _run_objection(pkg, f"memory dump all {out_file}")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            pattern = input(f"  String para buscar: ").strip()
            if pattern:
                _run_objection(pkg, f"memory search \"{pattern}\" --string")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            pattern = input(f"  Bytes (hex, ex: 414243): ").strip()
            if pattern:
                _run_objection(pkg, f"memory search \"{pattern}\"")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "5":
            classname = input(f"  Classe: ").strip()
            if classname:
                _run_objection(pkg, f"android heap print instances {classname}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "6":
            classname = input(f"  Classe: ").strip()
            if classname:
                _run_objection(pkg, f"android heap print fields {classname}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu: Filesystem ─────────────────────────────────────────────────────────

def _menu_filesystem(pkg: str):
    while True:
        _header("Filesystem")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} pwd (diretório atual)")
        print(f"  {_GREEN}2.{_RESET} ls (listar arquivos)")
        print(f"  {_GREEN}3.{_RESET} cat (ler arquivo)")
        print(f"  {_GREEN}4.{_RESET} Download arquivo do dispositivo")
        print(f"  {_GREEN}5.{_RESET} Upload arquivo para dispositivo")
        print(f"  {_GREEN}6.{_RESET} env (diretórios do app)")
        print(f"\n  {_DIM}0. Voltar{_RESET}")

        choice = input(f"\n{_CYAN}→{_RESET} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            _run_objection(pkg, "pwd")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            path = input(f"  Caminho (Enter = diretório atual): ").strip()
            cmd = f"ls {path}" if path else "ls"
            _run_objection(pkg, cmd)
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            path = input(f"  Caminho do arquivo: ").strip()
            if path:
                _run_objection(pkg, f"filesystem cat {path}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            remote = input(f"  Arquivo remoto: ").strip()
            local = input(f"  Destino local (Enter = .): ").strip() or "."
            if remote:
                _run_objection(pkg, f"filesystem download {remote} {local}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "5":
            local = input(f"  Arquivo local: ").strip()
            remote = input(f"  Destino remoto: ").strip()
            if local and remote:
                _run_objection(pkg, f"filesystem upload {local} {remote}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "6":
            _run_objection(pkg, "env")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu: Bypass ─────────────────────────────────────────────────────────────

def _menu_bypass(pkg: str):
    while True:
        _header("Bypass")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} SSL Pinning Bypass")
        print(f"  {_GREEN}2.{_RESET} Root Detection Bypass")
        print(f"  {_GREEN}3.{_RESET} Root Simulate (simula root)")
        print(f"  {_GREEN}4.{_RESET} Screenshot Protection Bypass (FLAG_SECURE)")
        print(f"\n  {_DIM}0. Voltar{_RESET}")

        choice = input(f"\n{_CYAN}→{_RESET} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            _run_objection(pkg, "android sslpinning disable")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            _run_objection(pkg, "android root disable")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            _run_objection(pkg, "android root simulate")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            _run_objection(pkg, "android ui FLAG_SECURE")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu: Keystore & Crypto ──────────────────────────────────────────────────

def _adb_shared_prefs(pkg: str, dump_file: str = ""):
    """Lê SharedPreferences via ADB (su) — objection não tem esse comando."""
    from core.env_check import _adb_exe
    adb = _adb_exe()
    sp_dir = f"/data/data/{pkg}/shared_prefs"

    if not dump_file:
        # Lista arquivos
        r = subprocess.run([adb, "shell", "su", "-c", f"ls {sp_dir}"],
                           capture_output=True, text=True, timeout=10)
        out = r.stdout.strip()
        if not out or "No such file" in out or "Permission denied" in out:
            print(f"\n{_YELLOW}⚠ Nenhum arquivo encontrado em {sp_dir}{_RESET}")
            print(f"{_DIM}  (requer root no dispositivo){_RESET}")
        else:
            print(f"\n{_CYAN}SharedPreferences em {sp_dir}:{_RESET}\n")
            for line in out.splitlines():
                print(f"  {_WHITE}{line}{_RESET}")
    else:
        path = f"{sp_dir}/{dump_file}"
        r = subprocess.run([adb, "shell", "su", "-c", f"cat '{path}'"],
                           capture_output=True, text=True, timeout=10)
        out = r.stdout.strip()
        if not out or "No such file" in out or "Permission denied" in out:
            print(f"\n{_RED}✖ Não foi possível ler: {path}{_RESET}")
            print(f"{_DIM}  (requer root no dispositivo){_RESET}")
        else:
            print(f"\n{_CYAN}Conteúdo de {dump_file}:{_RESET}\n")
            for line in out.splitlines():
                # Destaca valores que parecem sensíveis
                low = line.lower()
                if any(k in low for k in ("password", "token", "secret", "key", "auth", "credential")):
                    print(f"  {_RED}{line}{_RESET}")
                else:
                    print(f"  {_WHITE}{line}{_RESET}")


def _adb_list_databases(pkg: str):
    """Lista databases SQLite via ADB (su)."""
    from core.env_check import _adb_exe
    adb = _adb_exe()
    db_dir = f"/data/data/{pkg}/databases"
    r = subprocess.run([adb, "shell", "su", "-c", f"ls -la {db_dir}"],
                       capture_output=True, text=True, timeout=10)
    out = r.stdout.strip()
    if not out or "No such file" in out or "Permission denied" in out:
        print(f"\n{_YELLOW}⚠ Nenhum banco encontrado em {db_dir}{_RESET}")
        print(f"{_DIM}  (requer root no dispositivo){_RESET}")
    else:
        print(f"\n{_CYAN}Databases em {db_dir}:{_RESET}\n")
        for line in out.splitlines():
            if line.strip():
                print(f"  {_WHITE}{line}{_RESET}")


def _menu_keystore(pkg: str):
    while True:
        _header("Keystore & Crypto")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} Listar aliases do Keystore")
        print(f"  {_GREEN}2.{_RESET} Detalhes do Keystore")
        print(f"  {_GREEN}3.{_RESET} Watch Keystore (monitora operações)")
        print(f"  {_GREEN}4.{_RESET} Listar SharedPreferences  {_DIM}(via ADB){_RESET}")
        print(f"  {_GREEN}5.{_RESET} Dump de SharedPreferences  {_DIM}(via ADB){_RESET}")
        print(f"  {_GREEN}6.{_RESET} Listar databases SQLite  {_DIM}(via ADB){_RESET}")
        print(f"  {_GREEN}7.{_RESET} Conectar a database SQLite  {_DIM}(via Objection){_RESET}")
        print(f"  {_GREEN}8.{_RESET} env (paths de dados do app)")
        print(f"\n  {_DIM}0. Voltar{_RESET}")

        choice = input(f"\n{_CYAN}→{_RESET} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            _run_objection(pkg, "android keystore list")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            _run_objection(pkg, "android keystore detail")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            _run_objection(pkg, "android keystore watch")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            _adb_shared_prefs(pkg)
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "5":
            _adb_shared_prefs(pkg)  # lista primeiro
            name = input(f"\n  Nome do arquivo (ex: settings.xml): ").strip()
            if name:
                _adb_shared_prefs(pkg, name)
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "6":
            _adb_list_databases(pkg)
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "7":
            db = input(f"  Caminho do .db (ex: /data/data/{pkg}/databases/app.db): ").strip()
            if db:
                _run_objection(pkg, f"sqlite connect {db}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "8":
            _run_objection(pkg, "env")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu: Intents & Clipboard ───────────────────────────────────────────────

def _menu_intents(pkg: str):
    while True:
        _header("Intents & Clipboard")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} Lançar Activity")
        print(f"  {_GREEN}2.{_RESET} Lançar Service")
        print(f"  {_GREEN}3.{_RESET} Implicit Intents (monitora)")
        print(f"  {_GREEN}4.{_RESET} Monitorar Clipboard")
        print(f"\n  {_DIM}0. Voltar{_RESET}")

        choice = input(f"\n{_CYAN}→{_RESET} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            activity = input(f"  Activity (ex: com.example.MainActivity): ").strip()
            if activity:
                _run_objection(pkg, f"android intent launch_activity {activity}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "2":
            service = input(f"  Service (ex: com.example.MyService): ").strip()
            if service:
                _run_objection(pkg, f"android intent launch_service {service}")
                input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "3":
            _run_objection(pkg, "android intent implicit_intents")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        elif choice == "4":
            _run_objection(pkg, "android clipboard monitor")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Menu Principal ───────────────────────────────────────────────────────────

def objection_menu(pkg: str):
    """
    Menu interativo do Objection.
    pkg: package name do app (ex: com.example.app)
    """
    # Verifica se objection está instalado
    try:
        import objection  # noqa
    except ImportError:
        print(f"{_RED}✖ Objection não encontrado.{_RESET}")
        print(f"{_DIM}  Instale via: pip install objection{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return
    
    while True:
        _header("Menu Principal")
        print(f"  {_WHITE}Package: {_CYAN}{pkg}{_RESET}\n")
        print(f"  {_GREEN}1.{_RESET} Hooking  {_DIM}(classes, métodos, activities){_RESET}")
        print(f"  {_GREEN}2.{_RESET} Memory   {_DIM}(dump, search, instâncias){_RESET}")
        print(f"  {_GREEN}3.{_RESET} Filesystem  {_DIM}(ls, cat, download, upload){_RESET}")
        print(f"  {_GREEN}4.{_RESET} Bypass   {_DIM}(SSL pinning, root, emulator){_RESET}")
        print(f"  {_GREEN}5.{_RESET} Keystore & Crypto  {_DIM}(keystore, prefs, sqlite){_RESET}")
        print(f"  {_GREEN}6.{_RESET} Intents & Clipboard")
        print(f"  {_GREEN}7.{_RESET} Shell interativo do Objection")
        print(f"\n  {_DIM}0. Voltar{_RESET}")
        
        choice = input(f"\n{_CYAN}→{_RESET} ").strip()
        
        if choice == "0":
            break
        elif choice == "1":
            _menu_hooking(pkg)
        elif choice == "2":
            _menu_memory(pkg)
        elif choice == "3":
            _menu_filesystem(pkg)
        elif choice == "4":
            _menu_bypass(pkg)
        elif choice == "5":
            _menu_keystore(pkg)
        elif choice == "6":
            _menu_intents(pkg)
        elif choice == "7":
            print(f"\n{_DIM}→ Abrindo shell interativo do Objection...{_RESET}")
            print(f"{_DIM}  Digite 'exit' para voltar ao menu.{_RESET}\n")
            obj = _objection_bin()
            device_id = _frida_device_id()
            if device_id:
                args = [obj, "-S", device_id, "-n", pkg, "start"]
            else:
                args = [obj, "-n", pkg, "start"]
            try:
                subprocess.run(args)
            except KeyboardInterrupt:
                print(f"\n{_YELLOW}⚠ Shell fechado{_RESET}")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
