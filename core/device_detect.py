# -*- coding: utf-8 -*-
"""
device_detect.py -- Deteccao e selecao de dispositivo ADB.

Identifica automaticamente:
  - Nox Player (emulador, via nox_adb.exe ou porta 62025/62001/62026)
  - Emulador generico (AVD, BlueStacks, etc — porta 5554-5586 ou serial emulator-*)
  - Dispositivo fisico (serial USB, ex: R3CN90XXXXX)

Exporta:
  DEVICE        -- dict com info do dispositivo ativo
  get_adb()     -- retorna o executavel ADB correto para o dispositivo ativo
  select_device()  -- detecta e pede selecao se houver multiplos
"""
import subprocess
import shutil
import os
from pathlib import Path

_R  = "\033[0m"
_B  = "\033[1m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_RE = "\033[91m"
_D  = "\033[90m"
_W  = "\033[97m"

# Dispositivo ativo — preenchido por select_device()
DEVICE: dict = {
    "serial":  None,   # ex: "127.0.0.1:62025" ou "R3CN90XXXXX"
    "type":    None,   # "nox" | "emulator" | "physical"
    "label":   None,   # nome amigavel para exibir
    "adb_exe": None,   # caminho do executavel adb
}

_NOX_PORTS   = [62025, 62001, 62026]
_EMU_PORTS   = list(range(5554, 5588, 2))  # AVD usa 5554, 5556, ...

_NOX_SEARCH_PATHS = [
    Path(os.environ.get("PROGRAMFILES",      "C:/Program Files"))       / "Nox" / "bin",
    Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Nox" / "bin",
    Path("C:/Program Files/Nox/bin"),
    Path("C:/Program Files (x86)/Nox/bin"),
    Path("D:/Program Files/Nox/bin"),
    Path("D:/Nox/bin"),
]


# ── ADB executavel ────────────────────────────────────────────────────────────

def _find_nox_adb() -> str | None:
    # 1. Via processo Nox.exe em execucao
    try:
        import psutil
        for proc in psutil.process_iter(["name", "exe"]):
            if proc.info["name"] and "Nox.exe" in proc.info["name"]:
                exe = proc.info.get("exe")
                if exe:
                    c = Path(exe).parent / "nox_adb.exe"
                    if c.exists():
                        return str(c)
    except Exception:
        pass
    # 2. Caminhos conhecidos
    for base in _NOX_SEARCH_PATHS:
        c = base / "nox_adb.exe"
        if c.exists():
            return str(c)
    return None


def _find_generic_adb() -> str:
    found = shutil.which("adb")
    if found:
        return found
    # Tenta platform-tools local
    local = Path.home() / "AppData" / "Local" / "NoxDroid" / "platform-tools" / "adb.exe"
    if local.exists():
        return str(local)
    return "adb"


def get_adb() -> str:
    """Retorna o executavel ADB para o dispositivo ativo."""
    if DEVICE["adb_exe"]:
        return DEVICE["adb_exe"]
    # Fallback: nox_adb se disponivel, senao adb generico
    return _find_nox_adb() or _find_generic_adb()


# ── Listagem de dispositivos ──────────────────────────────────────────────────

def _run_adb_devices(adb: str) -> list[str]:
    """Retorna linhas de 'adb devices' excluindo cabecalho."""
    try:
        r = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=8)
        return [
            l for l in r.stdout.splitlines()
            if l.strip() and not l.startswith("List of")
        ]
    except Exception:
        return []


def _classify(serial: str) -> str:
    """Classifica o serial como 'nox', 'emulator' ou 'physical'."""
    if any(f":{p}" in serial for p in _NOX_PORTS):
        return "nox"
    if serial.startswith("emulator-") or any(f":{p}" in serial for p in _EMU_PORTS):
        return "emulator"
    if serial.startswith("127.0.0.1:"):
        # Porta desconhecida — tenta identificar pelo ro.product.manufacturer
        return "emulator"
    return "physical"


def _device_label(serial: str, kind: str, adb: str) -> str:
    """Busca modelo/fabricante via getprop para exibir nome amigavel."""
    try:
        def _prop(p):
            r = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", p],
                capture_output=True, text=True, timeout=5
            )
            return r.stdout.strip()

        if kind == "nox":
            return f"Nox Player  ({serial})"

        manufacturer = _prop("ro.product.manufacturer")
        model        = _prop("ro.product.model")
        name         = f"{manufacturer} {model}".strip()

        if kind == "emulator":
            avd = _prop("ro.kernel.qemu.avd_name") or _prop("ro.boot.qemu.avd_name")
            if avd:
                return f"Emulador: {avd}  ({serial})"
            return f"Emulador: {name or serial}"

        # physical
        return f"{name or 'Dispositivo'}  ({serial})"
    except Exception:
        return serial


def list_devices() -> list[dict]:
    """
    Retorna lista de dispositivos conectados e online.
    Tenta nox_adb primeiro, depois adb generico.
    """
    devices = []
    seen    = set()

    for adb in [_find_nox_adb(), _find_generic_adb()]:
        if not adb:
            continue
        for line in _run_adb_devices(adb):
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, status = parts[0], parts[1]
            if status != "device" or serial in seen:
                continue
            seen.add(serial)
            kind  = _classify(serial)
            label = _device_label(serial, kind, adb)
            # Usa nox_adb para Nox, adb generico para o resto
            exe   = _find_nox_adb() if kind == "nox" else _find_generic_adb()
            devices.append({
                "serial":  serial,
                "type":    kind,
                "label":   label,
                "adb_exe": exe,
            })

    return devices


# ── Selecao de dispositivo ────────────────────────────────────────────────────

_TYPE_COLOR = {
    "nox":      _C,
    "emulator": _Y,
    "physical": _G,
}

_TYPE_LABEL = {
    "nox":      "Nox Player",
    "emulator": "Emulador",
    "physical": "Dispositivo Fisico",
}


def select_device() -> bool:
    """
    Detecta dispositivos conectados e preenche DEVICE.
    - 0 dispositivos: aguarda com spinner
    - 1 dispositivo:  seleciona automaticamente
    - 2+:             exibe menu de selecao

    Retorna True se um dispositivo foi selecionado.
    """
    import time, sys

    spinner = ["|", "/", "-", "\\"]
    attempt = 0

    while True:
        devices = list_devices()

        if devices:
            if len(devices) == 1:
                _set_device(devices[0])
                tc = _TYPE_COLOR.get(devices[0]["type"], _W)
                print(f"  {_G}[OK]{_R} {tc}{devices[0]['label']}{_R}")
                return True

            # Multiplos dispositivos — pede selecao
            print(f"\n  {_Y}Multiplos dispositivos detectados:{_R}\n")
            for i, d in enumerate(devices, 1):
                tc = _TYPE_COLOR.get(d["type"], _W)
                tl = _TYPE_LABEL.get(d["type"], d["type"])
                print(f"  {_C}{i}.{_R} {tc}{_B}{tl}{_R}  {_W}{d['label']}{_R}")

            print(f"\n  {_D}0. Sair{_R}")
            choice = input(f"\n{_C}->{_R} Selecione o dispositivo: ").strip()

            if choice == "0":
                sys.exit(0)
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    _set_device(devices[idx])
                    tc = _TYPE_COLOR.get(devices[idx]["type"], _W)
                    print(f"\n  {_G}[OK]{_R} {tc}{devices[idx]['label']}{_R}")
                    return True
            except ValueError:
                pass
            continue

        # Nenhum dispositivo — aguarda
        spin = spinner[attempt % len(spinner)]
        sys.stdout.write(
            f"\r  {_C}{spin} Aguardando dispositivo...{_R}  "
            f"{_D}Ctrl+C para opcoes{_R}   "
        )
        sys.stdout.flush()
        attempt += 1

        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print(f"\n\n  {_Y}Nenhum dispositivo conectado.{_R}")
            print(f"  {_C}1.{_R} Continuar aguardando")
            print(f"  {_C}2.{_R} Pular (funcionalidades limitadas)")
            print(f"  {_C}3.{_R} Sair")
            c = input(f"\n{_C}->{_R} ").strip()
            if c == "1":
                attempt = 0
                continue
            elif c == "2":
                return False
            else:
                sys.exit(0)


def _set_device(d: dict):
    """Preenche o DEVICE global com o dispositivo selecionado."""
    DEVICE["serial"]  = d["serial"]
    DEVICE["type"]    = d["type"]
    DEVICE["label"]   = d["label"]
    DEVICE["adb_exe"] = d["adb_exe"]
