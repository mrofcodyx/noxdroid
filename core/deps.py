"""
Gerenciador de dependências do NoxDroid.
Verifica, instala e atualiza automaticamente todas as ferramentas necessárias
toda vez que o script é iniciado.

Quando frida-tools é atualizado, sinaliza para que o frida-server no emulador
também seja sincronizado via MaFrida.
"""

import os
import sys
import subprocess
import importlib.metadata
import requests

PIP_PACKAGES = [
    ("requests",             "HTTP client"),
    ("colorama",             "ANSI colors (Windows)"),
    ("pyOpenSSL",            "Certificate handling"),
    ("psutil",               "Process detection (Nox)"),
    ("frida-tools",          "Frida CLI tools"),
    ("objection",            "Runtime mobile explorer"),
    ("beautifulsoup4",       "HTML parsing"),
    ("apkleaks",             "APK URIs, endpoints & secrets scanner"),
    ("apkid",                "APK compiler/packer/obfuscator identifier"),
    ("androguard",           "APK static analysis & reverse engineering"),
    ("mobsfscan",            "Android/iOS source code security scanner"),
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_installed_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _get_pypi_latest(package: str) -> str | None:
    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=8)
        r.raise_for_status()
        return r.json()["info"]["version"]
    except Exception:
        return None


def _pip_install(package: str, upgrade: bool = False) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", "--quiet"]
    if upgrade:
        cmd.append("--upgrade")
    cmd.append(package)
    return subprocess.run(cmd, capture_output=True).returncode == 0


def _version_tuple(v: str):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0,)


# ─── Verificação individual ───────────────────────────────────────────────────

def _check_and_update_package(pkg_pip: str) -> tuple[str, bool, str]:
    """
    Retorna: (status, is_ok, version)
    status: "ok" | "installed" | "updated" | "failed" | "update_failed"
    """
    installed = _get_installed_version(pkg_pip)

    if not installed:
        print(f"  \033[93m↓ {pkg_pip:<20}\033[0m instalando...", end="", flush=True)
        ok = _pip_install(pkg_pip)
        ver = _get_installed_version(pkg_pip) or "?"
        if ok:
            print(f"\r  \033[92m✔ {pkg_pip:<20}\033[0m instalado   v{ver}        ")
            return ("installed", True, ver)
        print(f"\r  \033[91m✖ {pkg_pip:<20}\033[0m falha na instalação    ")
        return ("failed", False, "")

    latest = _get_pypi_latest(pkg_pip)
    if latest and _version_tuple(latest) > _version_tuple(installed):
        print(f"  \033[93m↑ {pkg_pip:<20}\033[0m v{installed} → v{latest} atualizando...", end="", flush=True)
        ok = _pip_install(pkg_pip, upgrade=True)
        new_ver = _get_installed_version(pkg_pip) or installed
        if ok:
            print(f"\r  \033[92m✔ {pkg_pip:<20}\033[0m atualizado  v{new_ver}        ")
            return ("updated", True, new_ver)
        print(f"\r  \033[93m⚠ {pkg_pip:<20}\033[0m falha ao atualizar (mantendo v{installed})")
        return ("update_failed", True, installed)

    print(f"  \033[92m✔ {pkg_pip:<20}\033[0m v{installed:<14} ok")
    return ("ok", True, installed)


# ─── Sincronização do frida-server via MaFrida ───────────────────────────────

def _adb_device_connected() -> bool:
    """Verifica se há algum dispositivo ADB conectado e autorizado."""
    try:
        from core.env_check import _adb_exe
        adb = _adb_exe()
        r = subprocess.run(
            [adb, "devices", "-l"],
            capture_output=True, text=True, timeout=5
        )
        return any(
            "device" in line and "offline" not in line and "unauthorized" not in line
            for line in r.stdout.splitlines()
            if not line.startswith("List")
        )
    except Exception:
        return False


def _get_mafrida_server_version() -> str | None:
    """Lê a versão do frida-server atualmente configurada no MaFrida."""
    try:
        from core.env_check import _adb_exe
        adb = _adb_exe()
        r = subprocess.run(
            [adb, "shell", "mafrida -g"],
            capture_output=True, text=True, timeout=8
        )
        out = r.stdout.strip()
        for token in out.split():
            # Versão válida: só dígitos e pontos, ex: 14.6.1
            if token.replace(".", "").isdigit() and "." in token:
                return token
        return None  # "no Frida version set yet" e similares → None
    except Exception:
        return None


def _sync_frida_server(new_version: str):
    """Atualiza o frida-server no emulador via MaFrida para new_version."""
    if not _adb_device_connected():
        print(f"  \033[93m⚠ frida-server\033[0m não sincronizado (emulador offline)")
        print(f"    \033[90m→ Quando conectar, o script sincronizará automaticamente.\033[0m")
        return

    server_ver = _get_mafrida_server_version()
    if server_ver and _version_tuple(server_ver) >= _version_tuple(new_version):
        print(f"  \033[92m✔ frida-server         \033[0m v{server_ver:<14} ok")
        return

    from_label = f"v{server_ver}" if server_ver else "?"
    print(f"  \033[93m↑ frida-server        \033[0m {from_label} → v{new_version} sincronizando...", end="", flush=True)

    from core.env_check import _adb_exe
    adb = _adb_exe()
    cmds = [
        f"mafrida kill",
        f"mafrida --set {new_version}",
        f"mafrida download",
        f"mafrida start",
        f"mafrida enable",
    ]
    for cmd in cmds:
        subprocess.run([adb, "shell", cmd], capture_output=True)

    print(f"\r  \033[92m✔ frida-server        \033[0m sincronizado v{new_version}        ")


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def check_and_update_all_deps() -> bool:
    """
    Verifica e atualiza todas as dependências.
    Se frida-tools for atualizado, sincroniza o frida-server via MaFrida.
    Retorna True se tudo ok.
    """
    print("\n\033[96m→ Verificando dependências...\033[0m\n")

    all_ok = True
    updated_count = 0
    installed_count = 0
    frida_new_version: str | None = None

    for pkg_pip, _ in PIP_PACKAGES:
        status, ok, ver = _check_and_update_package(pkg_pip)
        if not ok:
            all_ok = False
        if status in ("updated", "installed"):
            if pkg_pip == "frida-tools":
                frida_new_version = ver
            if status == "updated":
                updated_count += 1
            else:
                installed_count += 1

    # Sincronizar frida-server se frida-tools foi atualizado ou instalado
    if frida_new_version:
        print(f"\n  \033[96m→ frida-tools atualizado para v{frida_new_version} — sincronizando frida-server...\033[0m")
        _sync_frida_server(frida_new_version)
    else:
        # Mesmo sem atualização, verificar se o server está na versão correta
        current_frida = _get_installed_version("frida-tools")
        if current_frida and _adb_device_connected():
            server_ver = _get_mafrida_server_version()
            if server_ver and _version_tuple(server_ver) < _version_tuple(current_frida):
                print(f"\n  \033[93m→ frida-server desatualizado (v{server_ver} < v{current_frida}) — sincronizando...\033[0m")
                _sync_frida_server(current_frida)
            elif server_ver:
                print(f"  \033[92m✔ frida-server         \033[0m v{server_ver:<14} ok")

    print()
    if installed_count:
        print(f"  \033[92m✔ {installed_count} pacote(s) instalado(s)\033[0m")
    if updated_count:
        print(f"  \033[92m✔ {updated_count} pacote(s) atualizado(s)\033[0m")
    if all_ok and not installed_count and not updated_count:
        print("  \033[92m✔ Tudo atualizado.\033[0m")
    elif not all_ok:
        print("  \033[91m✖ Algumas dependências falharam. Verifique sua conexão.\033[0m")

    return all_ok


# ─── Ferramentas externas (jadx, apktool, dex-tools, apkeditor, DB Browser) ──

import json as _json
import zipfile as _zipfile
import urllib.request as _urllib
import urllib.error as _urllib_error
from pathlib import Path as _Path
import shutil as _shutil
import re as _re

TOOLS_DIR  = _Path(__file__).parent.parent / "tools"
_VER_FILE  = TOOLS_DIR / ".versions.json"   # cache de versões instaladas

# Wrapper .bat para JARs — usa java.exe absoluto se disponível, fallback para "java"
_BAT_TEMPLATE = "@echo off\n\"{java}\" -jar \"%~dp0{jar}\" %*\n"


def _make_bat(wrapper_path: _Path, jar_name: str):
    """Gera wrapper .bat usando o java.exe absoluto encontrado."""
    java = _java_exe()
    java_cmd = str(java).replace("\\", "\\\\") if java else "java"
    wrapper_path.write_text(
        f'@echo off\n"{java_cmd}" -jar "%~dp0{jar_name}" %*\n',
        encoding="utf-8"
    )

# ─── Catálogo de ferramentas ──────────────────────────────────────────────────
# github_repo: "owner/repo" → usa GitHub Releases API para obter latest tag
# asset_pattern: regex para escolher o asset certo na release
# url_static: usado quando não há GitHub Releases (DB Browser)
# type: "jar" | "zip"
# dest: nome do arquivo baixado
# extract_to: pasta de extração (zip)
# wrapper: nome do .bat gerado (jar)

_TOOLS: dict[str, dict] = {
    "apktool": {
        "github_repo":    "iBotPeaches/Apktool",
        "asset_pattern":  r"^apktool_[\d.]+\.jar$",
        "type":           "jar",
        "dest":           "apktool.jar",
        "wrapper":        "apktool.bat",
    },
    "jadx": {
        "github_repo":    "skylot/jadx",
        "asset_pattern":  r"^jadx-[\d.]+\.zip$",
        "type":           "zip",
        "dest":           "jadx.zip",
        "extract_to":     "jadx",
    },
    "apkeditor": {
        "github_repo":    "REAndroid/APKEditor",
        "asset_pattern":  r"^APKEditor-[\d.]+\.jar$",
        "type":           "jar",
        "dest":           "APKEditor.jar",
        "wrapper":        "apkeditor.bat",
    },
    "db-browser": {
        "github_repo":    "sqlitebrowser/sqlitebrowser",
        "asset_pattern":  r"^DB\.Browser\.for\.SQLite-v[\d.]+-win64\.zip$",
        "type":           "zip",
        "dest":           "db-browser.zip",
        "extract_to":     "db-browser",
    },
}


# ─── Versões instaladas (cache em disco) ─────────────────────────────────────

def _load_versions() -> dict:
    try:
        return _json.loads(_VER_FILE.read_text()) if _VER_FILE.exists() else {}
    except Exception:
        return {}


def _save_versions(versions: dict):
    try:
        TOOLS_DIR.mkdir(exist_ok=True)
        _VER_FILE.write_text(_json.dumps(versions, indent=2))
    except Exception:
        pass


def _installed_version(name: str) -> str | None:
    return _load_versions().get(name)


def _set_installed_version(name: str, version: str):
    v = _load_versions()
    v[name] = version
    _save_versions(v)


# ─── GitHub Releases API ──────────────────────────────────────────────────────

def _gh_latest_release(repo: str) -> tuple[str, list[dict]] | tuple[None, None]:
    """Retorna (tag_name, assets) da última release do repo, ou (None, None)."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = _urllib.Request(url, headers={"User-Agent": "NoxDroid/1.0"})
        with _urllib.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())
        return data.get("tag_name", "").lstrip("v"), data.get("assets", [])
    except Exception:
        return None, None


def _pick_asset(assets: list[dict], pattern: str) -> str | None:
    """Escolhe o asset cujo nome bate com o pattern regex."""
    rx = _re.compile(pattern)
    for asset in assets:
        if rx.match(asset["name"]):
            return asset["browser_download_url"]
    return None


# ─── Download + extração ──────────────────────────────────────────────────────

def _download_file(url: str, dest: _Path, label: str) -> bool:
    print(f"  \033[93m↓ {label:<22}\033[0m baixando...", end="", flush=True)
    try:
        def _prog(b, bs, total):
            if total > 0:
                pct = min(int(b * bs * 20 / total), 20)
                print(f"\r  \033[93m↓ {label:<22}\033[0m [{'#'*pct}{'.'*(20-pct)}]",
                      end="", flush=True)
        _urllib.urlretrieve(url, dest, reporthook=_prog)
        print(f"\r  \033[92m✔ {label:<22}\033[0m baixado                    ")
        return True
    except Exception as e:
        print(f"\r  \033[91m✖ {label:<22}\033[0m falha: {e}")
        return False


def _extract_zip(dest: _Path, extract_dir: _Path, label: str) -> bool:
    extract_dir.mkdir(exist_ok=True)
    try:
        with _zipfile.ZipFile(dest, "r") as z:
            members = z.namelist()
            # Achata um nível de pasta raiz se todos os membros tiverem o mesmo prefixo
            prefix = members[0] if (members and members[0].endswith("/")) else ""
            for member in members:
                target = member[len(prefix):] if prefix else member
                if not target:
                    continue
                out_path = extract_dir / target
                if member.endswith("/"):
                    out_path.mkdir(parents=True, exist_ok=True)
                else:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(member) as src, open(out_path, "wb") as dst:
                        dst.write(src.read())
        dest.unlink(missing_ok=True)
        return True
    except Exception as e:
        print(f"  \033[91m✖ {label:<22}\033[0m erro ao extrair: {e}")
        return False


def _install_tool(name: str, info: dict, version: str, url: str):
    """Baixa, extrai/instala e registra a versão."""
    dest = TOOLS_DIR / info["dest"]

    if not _download_file(url, dest, name):
        return

    if info["type"] == "zip":
        extract_dir = TOOLS_DIR / info["extract_to"]
        # Remove versão antiga antes de extrair
        if extract_dir.exists():
            _shutil.rmtree(extract_dir, ignore_errors=True)
        if _extract_zip(dest, extract_dir, name):
            print(f"  \033[92m✔ {name:<22}\033[0m v{version}  →  tools/{info['extract_to']}/")
            _set_installed_version(name, version)

    elif info["type"] == "jar":
        wrapper = info.get("wrapper")
        if wrapper:
            _make_bat(TOOLS_DIR / wrapper, info["dest"])
        print(f"  \033[92m✔ {name:<22}\033[0m v{version}  →  tools/{info['dest']}")
        _set_installed_version(name, version)


# ─── Verificação de presença ──────────────────────────────────────────────────

def _tool_present(name: str) -> bool:
    info = _TOOLS.get(name, {})
    if info.get("type") == "jar":
        return (TOOLS_DIR / info["dest"]).exists()
    elif info.get("type") == "zip":
        d = TOOLS_DIR / info.get("extract_to", name)
        return d.exists() and any(d.iterdir())
    return False



# ─── Java (JDK) ───────────────────────────────────────────────────────────────

_JDK_API   = "https://api.adoptium.net/v3/assets/latest/21/hotspot"
_JDK_PARAMS = "?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
_JDK_DIR   = TOOLS_DIR / "jdk"


def _java_exe() -> _Path | None:
    """Retorna o executável java.exe — PATH do sistema ou JDK local."""
    found = _shutil.which("java")
    if found:
        return _Path(found)
    # JDK instalado localmente na pasta tools/jdk/
    for candidate in _JDK_DIR.rglob("java.exe"):
        return candidate
    return None


def _java_version(java: _Path) -> str | None:
    """Retorna a versão do java (ex: '21.0.3')."""
    try:
        r = subprocess.run([str(java), "-version"],
                           capture_output=True, text=True, timeout=8)
        # java -version imprime em stderr: openjdk version "21.0.3" ...
        out = r.stderr or r.stdout
        m = _re.search(r'"([\d._]+)"', out)
        return m.group(1) if m else None
    except Exception:
        return None


def _gh_latest_jdk_version() -> tuple[str, str] | tuple[None, None]:
    """Consulta Adoptium API e retorna (versão, url_msi)."""
    try:
        url = _JDK_API + _JDK_PARAMS
        req = _urllib.Request(url, headers={"User-Agent": "NoxDroid/1.0"})
        with _urllib.urlopen(req, timeout=12) as resp:
            data = _json.loads(resp.read())
        if not data:
            return None, None
        release = data[0]
        version = release["version"]["semver"]
        # Prefere MSI para instalação silenciosa, fallback para zip
        binary  = release["binary"]
        pkg     = binary.get("installer") or binary.get("package")
        if not pkg:
            return None, None
        return version, pkg["link"]
    except Exception:
        return None, None


def _set_java_path(java_bin_dir: _Path):
    """
    Adiciona java_bin_dir ao PATH da sessão atual e persiste no PATH do usuário.
    Seta JAVA_HOME. Operações de persistência são fire-and-forget (não bloqueiam).
    """
    d = str(java_bin_dir)
    java_home = str(java_bin_dir.parent)

    # 1. Sessão atual — imediato, sem subprocess
    os.environ["PATH"]      = d + os.pathsep + os.environ.get("PATH", "")
    os.environ["JAVA_HOME"] = java_home

    # 2. Persiste no PATH do usuário (não requer admin) — fire-and-forget
    ps_user = (
        f'$cur = [Environment]::GetEnvironmentVariable("PATH","User");'
        f'if ($cur -notlike "*{d}*") {{'
        f'  [Environment]::SetEnvironmentVariable("PATH", $cur + ";{d}", "User")'
        f'}};'
        f'[Environment]::SetEnvironmentVariable("JAVA_HOME", "{java_home}", "User")'
    )
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_user],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
    except Exception:
        pass


def _install_java_msi(msi_path: _Path) -> bool:
    """Instala o JDK via MSI silenciosamente."""
    print(f"  \033[96m→ Instalando JDK (instalação silenciosa)...\033[0m", end="", flush=True)
    try:
        r = subprocess.run(
            ["msiexec", "/i", str(msi_path),
             "/quiet", "/norestart",
             f"INSTALLDIR={_JDK_DIR}",
             "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome"],
            timeout=180
        )
        print(f"\r  \033[92m✔ JDK instalado via MSI\033[0m                    ")
        return r.returncode == 0
    except Exception as e:
        print(f"\r  \033[91m✖ MSI falhou: {e}\033[0m")
        return False


def _install_java_zip(zip_path: _Path) -> _Path | None:
    """Extrai JDK de um zip portátil para tools/jdk/."""
    print(f"  \033[96m→ Extraindo JDK portátil...\033[0m", end="", flush=True)
    _JDK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with _zipfile.ZipFile(zip_path, "r") as z:
            members = z.namelist()
            prefix  = members[0] if members and members[0].endswith("/") else ""
            for member in members:
                target = member[len(prefix):] if prefix else member
                if not target:
                    continue
                out = _JDK_DIR / target
                if member.endswith("/"):
                    out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(member) as src, open(out, "wb") as dst:
                        dst.write(src.read())
        zip_path.unlink(missing_ok=True)
        java = next(_JDK_DIR.rglob("java.exe"), None)
        print(f"\r  \033[92m✔ JDK extraído em: {_JDK_DIR}\033[0m                    ")
        return java.parent if java else None
    except Exception as e:
        print(f"\r  \033[91m✖ Extração falhou: {e}\033[0m")
        return None


def ensure_java() -> bool:
    """
    Garante que o Java está disponível.
    1. Verifica se já existe (PATH ou tools/jdk/)
    2. Se não, consulta Adoptium API para obter latest JDK 21
    3. Baixa MSI → instala silenciosamente; fallback para zip portátil
    4. Seta JAVA_HOME e PATH
    Retorna True se Java disponível ao final.
    """
    java = _java_exe()
    if java:
        ver = _java_version(java) or "?"
        print(f"  \033[92m✔ {'java':<22}\033[0m v{ver:<14} ok")
        return True

    print(f"  \033[93m⚠ Java não encontrado — baixando JDK 21 (Adoptium)...\033[0m")
    latest_ver, dl_url = _gh_latest_jdk_version()

    if not dl_url:
        print(f"  \033[91m✖ Não foi possível obter o JDK automaticamente.\033[0m")
        print(f"  \033[93m  Instale manualmente: https://adoptium.net\033[0m")
        return False

    is_msi = dl_url.endswith(".msi")
    ext    = ".msi" if is_msi else ".zip"
    dest   = TOOLS_DIR / f"jdk_installer{ext}"

    if not _download_file(dl_url, dest, f"JDK {latest_ver}"):
        return False

    bin_dir: _Path | None = None

    if is_msi:
        ok = _install_java_msi(dest)
        dest.unlink(missing_ok=True)
        if ok:
            # MSI instala no INSTALLDIR — procura java.exe lá
            java = next(_JDK_DIR.rglob("java.exe"), None)
            if not java:
                # Fallback: procura no Program Files
                for pf in ("PROGRAMFILES", "PROGRAMFILES(X86)"):
                    base = _Path(os.environ.get(pf, "C:/Program Files"))
                    java = next(base.rglob("java.exe"), None)
                    if java:
                        break
            bin_dir = java.parent if java else None
    else:
        bin_dir = _install_java_zip(dest)

    if bin_dir and bin_dir.exists():
        _set_java_path(bin_dir)
        ver = _java_version(bin_dir / "java.exe") or latest_ver
        print(f"  \033[92m✔ {'java':<22}\033[0m v{ver:<14} PATH configurado")
        return True

    print(f"  \033[91m✖ Instalação do Java falhou. Instale manualmente: https://adoptium.net\033[0m")
    return False


def _check_java() -> bool:
    return _java_exe() is not None


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def install_external_tools(force: bool = False):
    """
    Verifica versão instalada vs. latest no GitHub para cada ferramenta.
    Instala se ausente, atualiza se houver nova versão.
    """
    TOOLS_DIR.mkdir(exist_ok=True)

    if not ensure_java():
        print("  \033[91m  Ferramentas que requerem Java podem não funcionar.\033[0m\n")

    updated = installed = 0

    for name, info in _TOOLS.items():
        repo    = info["github_repo"]
        pattern = info["asset_pattern"]

        # Consulta GitHub
        latest_ver, assets = _gh_latest_release(repo)
        if latest_ver is None:
            # Sem acesso à internet — verifica só presença
            if _tool_present(name):
                cur = _installed_version(name) or "?"
                print(f"  \033[92m✔ {name:<22}\033[0m v{cur:<14} ok  \033[90m(offline)\033[0m")
            else:
                print(f"  \033[91m✖ {name:<22}\033[0m não instalado  \033[90m(sem internet)\033[0m")
            continue

        cur_ver = _installed_version(name)
        present = _tool_present(name)

        if present and cur_ver == latest_ver and not force:
            print(f"  \033[92m✔ {name:<22}\033[0m v{cur_ver:<14} ok")
            continue

        # Precisa instalar ou atualizar
        url = _pick_asset(assets, pattern)
        if not url:
            print(f"  \033[91m✖ {name:<22}\033[0m asset não encontrado na release v{latest_ver}")
            continue

        if not present:
            print(f"  \033[93m↓ {name:<22}\033[0m instalando v{latest_ver}...")
            _install_tool(name, info, latest_ver, url)
            installed += 1
        else:
            print(f"  \033[93m↑ {name:<22}\033[0m v{cur_ver} → v{latest_ver} atualizando...")
            _install_tool(name, info, latest_ver, url)
            updated += 1

    # Adiciona tools/ ao PATH da sessão
    import os
    tools_str = str(TOOLS_DIR)
    if tools_str not in os.environ.get("PATH", ""):
        os.environ["PATH"] = tools_str + os.pathsep + os.environ.get("PATH", "")

    if installed:
        print(f"\n  \033[92m✔ {installed} ferramenta(s) instalada(s)\033[0m")
    if updated:
        print(f"  \033[92m✔ {updated} ferramenta(s) atualizada(s)\033[0m")
    if not installed and not updated:
        print("  \033[92m✔ Ferramentas externas atualizadas.\033[0m")
