"""
magisk_modules.py — Instalação unificada de módulos Magisk + certificado CA

Instala em sequência:
  1. MaFrida          — módulo Frida para Magisk (auto-start no boot)
  2. Zygisk-Assistant — esconde root de apps
  3. AlwaysTrustUserCerts — adiciona certs de usuário ao CA store do sistema
  4. Certificado CA   — baixa do Burp Suite e guia instalação manual
"""
import os
import time
import subprocess
import requests
from pathlib import Path
from core.env_check import _adb_exe

_R  = "\033[0m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[90m"
_W  = "\033[97m"
_B  = "\033[1m"
_M  = "\033[95m"

# ─── Catálogo de módulos Magisk ───────────────────────────────────────────────
_MODULES = {
    "zygiskassistant": {
        "label":  "Zygisk-Assistant",
        "repo":   "snake-4/Zygisk-Assistant",
        "desc":   "Esconde root para KernelSU, Magisk e APatch",
        "filter": lambda name: name.endswith(".zip"),
    },
}


def _cls():
    os.system("cls" if os.name == "nt" else "clear")


def _adb_shell(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe(), "shell", cmd], capture_output=True, text=True)


def _adb_su(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe(), "shell", "su", "-c", cmd],
                          capture_output=True, text=True)


# ─── GitHub release helper ────────────────────────────────────────────────────

def _get_latest_zip(repo: str, name_filter=None) -> tuple[str | None, str | None]:
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo}/releases/latest",
            timeout=10
        )
        r.raise_for_status()
        for asset in r.json().get("assets", []):
            name = asset["name"]
            if name_filter and not name_filter(name):
                continue
            if name.endswith(".zip"):
                return asset["browser_download_url"], name
    except Exception as e:
        print(f"  {_RE}✖ Falha ao buscar release ({repo}): {e}{_R}")
    return None, None


# ─── Instalação de módulo individual ─────────────────────────────────────────

def _install_module(key: str) -> bool:
    mod = _MODULES[key]
    adb = _adb_exe()

    print(f"\n  {_C}► {mod['label']}{_R}  {_D}{mod['desc']}{_R}")

    url, filename = _get_latest_zip(mod["repo"], mod.get("filter"))
    if not url:
        print(f"  {_RE}  ✖ Não foi possível obter a release.{_R}")
        return False

    print(f"  {_D}  → Baixando {filename}...{_R}", end="", flush=True)
    try:
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        zip_path = Path(filename)
        zip_path.write_bytes(r.content)
        print(f" {_G}✔{_R}")
    except Exception as e:
        print(f" {_RE}✖ {e}{_R}")
        return False

    print(f"  {_D}  → Enviando para o dispositivo...{_R}", end="", flush=True)
    r = subprocess.run([adb, "push", str(zip_path), f"/data/local/tmp/{filename}"],
                       capture_output=True)
    zip_path.unlink(missing_ok=True)
    if r.returncode != 0:
        print(f" {_RE}✖{_R}")
        return False
    print(f" {_G}✔{_R}")

    print(f"  {_D}  → Instalando módulo via Magisk...{_R}", end="", flush=True)
    r2 = _adb_shell(f"su -c 'magisk --install-module /data/local/tmp/{filename}'")
    if r2.returncode == 0 or "Success" in r2.stdout:
        print(f" {_G}✔{_R}")
        return True

    print(f" {_Y}⚠ {r2.stdout.strip() or r2.stderr.strip()}{_R}")
    return False


# ─── MaFrida ─────────────────────────────────────────────────────────────────

def _install_mafrida() -> bool:
    from modules.frida_magisk import install_magisk_frida_module
    print(f"\n  {_C}► MaFrida{_R}  {_D}módulo Frida para Magisk (auto-start no boot){_R}")
    try:
        install_magisk_frida_module()
        return True
    except Exception as e:
        print(f"  {_RE}  ✖ Erro ao instalar MaFrida: {e}{_R}")
        return False


# ─── Certificado CA + AlwaysTrustUserCerts ───────────────────────────────────

def _install_cert_step():
    """
    1. Instala o módulo AlwaysTrustUserCerts via Magisk
    2. Baixa o cert do Burp Suite, faz push para /sdcard/
    3. Guia o usuário para instalar manualmente nas configurações do Android
    """
    from modules.cert_setup import _cert_intro, _get_burp_pem, _push_and_guide

    print(f"\n  {_C}► AlwaysTrustUserCerts + Certificado CA (Burp Suite){_R}")
    print(f"  {_D}  Instala o módulo Magisk e guia a instalação do certificado{_R}\n")

    # ── Instala AlwaysTrustUserCerts ──────────────────────────────────────────
    adb = _adb_exe()
    print(f"  {_C}[•] Buscando AlwaysTrustUserCerts...{_R}", end="", flush=True)
    try:
        r = requests.get(
            "https://api.github.com/repos/NVISOsecurity/MagiskTrustUserCerts/releases/latest",
            timeout=10
        )
        r.raise_for_status()
        data = r.json()
        module_version = data["tag_name"]
        module_url, filename = None, None
        for asset in data.get("assets", []):
            if asset["name"].endswith(".zip"):
                filename = asset["name"]
                module_url = asset["browser_download_url"]
                break
    except Exception as e:
        print(f" {_Y}⚠ fallback v1.3{_R}")
        module_version = "v1.3"
        filename = f"AlwaysTrustUserCerts_{module_version}.zip"
        module_url = (
            f"https://github.com/NVISOsecurity/MagiskTrustUserCerts/releases/download"
            f"/{module_version}/{filename}"
        )

    if module_url and filename:
        print(f" {_G}✔{_R}")
        print(f"  {_D}  → Baixando {filename}...{_R}", end="", flush=True)
        try:
            dl = requests.get(module_url, timeout=60)
            dl.raise_for_status()
            zip_path = Path(filename)
            zip_path.write_bytes(dl.content)
            print(f" {_G}✔{_R}")

            print(f"  {_D}  → Enviando para o dispositivo...{_R}", end="", flush=True)
            r2 = subprocess.run([adb, "push", str(zip_path), f"/data/local/tmp/{filename}"],
                                capture_output=True)
            zip_path.unlink(missing_ok=True)
            if r2.returncode != 0:
                print(f" {_RE}✖{_R}")
            else:
                print(f" {_G}✔{_R}")
                print(f"  {_D}  → Instalando módulo via Magisk...{_R}", end="", flush=True)
                r3 = subprocess.run(
                    [adb, "shell", "su", "-c",
                     f"magisk --install-module /data/local/tmp/{filename}"],
                    capture_output=True, text=True
                )
                if r3.returncode == 0 or "Success" in r3.stdout:
                    print(f" {_G}✔{_R}")
                else:
                    print(f" {_Y}⚠ {r3.stdout.strip() or r3.stderr.strip()}{_R}")
        except Exception as e:
            print(f" {_RE}✖ {e}{_R}")
    else:
        print(f" {_RE}✖ asset não encontrado{_R}")

    # ── Certificado CA ────────────────────────────────────────────────────────
    print()
    _cert_intro()
    pem = _get_burp_pem()
    if not pem:
        print(f"  {_Y}  ⚠ Certificado não instalado — você pode fazer isso depois em{_R}")
        print(f"  {_Y}    Setup → Certificado CA{_R}")
        return False

    return _push_and_guide(pem, "portswigger")


# ─── Setup completo ───────────────────────────────────────────────────────────

def install_magisk_modules():
    from utils.common import clear_screen
    from core.banner import display_banner

    clear_screen()
    display_banner()

    print(f"\n{_C}{_B}→ Setup Completo — Módulos Magisk + Certificado CA{_R}\n")
    print(f"  {_Y}Pré-requisitos:{_R}")
    print(f"  {_D}  • Kitsune Magisk instalado e ativo no emulador{_R}")
    print(f"  {_D}  • Zygisk ativado nas configurações do Magisk{_R}")
    print(f"  {_D}  • Emulador conectado via ADB{_R}\n")

    print(f"  {_C}O que será instalado:{_R}")
    print(f"  {_D}  1. MaFrida              — Frida server via Magisk{_R}")
    print(f"  {_D}  2. Zygisk-Assistant     — oculta root de apps{_R}")
    print(f"  {_D}  3. AlwaysTrustUserCerts — certs de usuário no CA store{_R}")
    print(f"  {_D}  4. Certificado CA       — Burp Suite (instalação guiada){_R}\n")
    input(f"  {_D}→ Pressione Enter para iniciar...{_R}")
    print()

    results: dict[str, bool] = {}

    # ── 1. MaFrida ────────────────────────────────────────────────────────────
    results["MaFrida"] = _install_mafrida()

    # ── 2 & 3. Módulos Magisk ─────────────────────────────────────────────────
    for key in _MODULES:
        results[_MODULES[key]["label"]] = _install_module(key)

    # ── 4. Certificado CA ─────────────────────────────────────────────────────
    print(f"\n  {_C}{'─'*54}{_R}")
    print(f"  {_C}{_B}  Etapa final: AlwaysTrustUserCerts + Certificado CA{_R}")
    print(f"  {_C}{'─'*54}{_R}")
    results["AlwaysTrustUserCerts + Certificado CA"] = _install_cert_step()

    # ── Resumo ────────────────────────────────────────────────────────────────
    print(f"\n  {_C}{'─'*54}{_R}")
    print(f"  {_C}{_B}  Resumo{_R}")
    print(f"  {_C}{'─'*54}{_R}")
    for label, ok in results.items():
        icon  = f"{_G}✔{_R}" if ok else f"{_RE}✖{_R}"
        state = f"{_G}instalado{_R}" if ok else f"{_RE}falhou{_R}"
        print(f"  {icon}  {_W}{label}{_R}  {_D}—{_R} {state}")

    ok_count  = sum(1 for v in results.values() if v)
    err_count = len(results) - ok_count

    print(f"\n  {_G}✔ {ok_count} concluídos{_R}" + (f"  {_RE}✖ {err_count} com falha{_R}" if err_count else ""))

    if ok_count > 0:
        print(f"\n  {_Y}→ Reinicie o emulador manualmente para ativar os módulos Magisk.{_R}")
        print(f"  {_D}  (Não reinicie agora se ainda não instalou o certificado){_R}")

    input(f"\n  {_D}→ Enter para continuar...{_R}")
    clear_screen()
