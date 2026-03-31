"""
cert_setup.py — Instalação de certificado CA (Burp Suite / mitmproxy / custom)

Fluxo principal (setup_cert_nox):
  1. Baixa o cert do Burp (ou lê arquivo local)
  2. Faz push de portswigger.crt para /sdcard/
  3. Guia o usuário para instalar manualmente em
     Configurações → Segurança → Instalar certificado → CA
  4. Aguarda confirmação e encerra
"""
import os
import time
import subprocess
import tempfile
import requests
from OpenSSL import crypto
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


def _adb(args: list) -> subprocess.CompletedProcess:
    return subprocess.run([_adb_exe()] + args, capture_output=True, text=True)


def _cls():
    os.system("cls" if os.name == "nt" else "clear")


# ─── Animação de intro ────────────────────────────────────────────────────────

def _cert_intro():
    frames = [
        f"\033[1;31m◕⩊◕  Preparando certificado...\033[0m",
        f"\033[1;36m⸜(｡˃ ᵕ ˂ )⸝♡  Baixando certificado...\033[0m",
        f"\033[1;32m₍^. .^₎⟆  Certificado pronto!\033[0m",
    ]
    for frame in frames:
        _cls()
        print(f"\n  {frame}\n")
        time.sleep(0.9)


# ─── Fontes de certificado ────────────────────────────────────────────────────

def _get_burp_pem() -> bytes | None:
    _cls()
    print(f"\n  {_C}{_B}╔══════════════════════════════════╗{_R}")
    print(f"  {_C}{_B}║  Instalar Certificado Burp Suite  ║{_R}")
    print(f"  {_C}{_B}╚══════════════════════════════════╝{_R}\n")

    print(f"  {_Y}→ PASSOS NECESSÁRIOS ANTES DE CONTINUAR:{_R}")
    print(f"  {_Y}1. Abra o Burp Suite e configure para escutar em 127.0.0.1:8080{_R}")
    print(f"  {_Y}2. No emulador: Configurações → Wi-Fi → Modificar rede → Opções avançadas{_R}")
    print(f"  {_Y}3. Proxy: Manual  |  Host: 127.0.0.1  |  Porta: 8080{_R}")
    print(f"  {_Y}4. Certifique-se que o emulador está rodando com root (Magisk){_R}")
    print(f"  {_M}→ Dica: O proxy permite que o emulador busque o certificado do Burp.{_R}\n")

    print(f"  {_Y}Aguardando 25s para você configurar o proxy...{_R}")
    for i in range(25, 0, -1):
        print(f"\r  {_C}  {i}s restantes...{_R}", end="", flush=True)
        time.sleep(1)
    print()

    # Verifica conexão ADB
    print(f"\n  {_C}[•] Verificando conexão com o emulador...{_R}")
    r = _adb(["devices"])
    lines = [l for l in r.stdout.splitlines() if l.strip() and "List of" not in l]
    if not any("device" in l and "offline" not in l for l in lines):
        print(f"  {_RE}[✖] Nenhum emulador detectado.{_R}")
        print(f"  {_Y}→ Execute 'adb devices' para confirmar a conexão.{_R}")
        return None
    print(f"  {_G}[✓] Emulador detectado{_R}\n")

    print(f"  {_C}[•] Baixando certificado do Burp Suite...{_R}")
    try:
        resp = requests.get("http://127.0.0.1:8080/cert", timeout=10)
        resp.raise_for_status()
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, resp.content)
        pem  = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        print(f"  {_G}[✓] Certificado baixado{_R}")
        return pem
    except Exception as e:
        print(f"  {_RE}[✖] Falha ao baixar certificado: {e}{_R}")
        print(f"  {_Y}→ Verifique se o Burp Suite está rodando em 127.0.0.1:8080{_R}")
        return None


def _get_mitmproxy_pem() -> bytes | None:
    default = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.pem")
    path = input(f"\n  {_C}→{_R} Caminho do certificado [{_D}{default}{_R}]: ").strip() or default
    if not os.path.exists(path):
        print(f"  {_RE}✖ Arquivo não encontrado: {path}{_R}")
        return None
    with open(path, "rb") as f:
        return f.read()


def _get_custom_pem() -> bytes | None:
    path = input(f"\n  {_C}→{_R} Caminho do certificado (.pem/.crt/.cer): ").strip().strip('"')
    if not path or not os.path.exists(path):
        print(f"  {_RE}✖ Arquivo não encontrado.{_R}")
        return None
    with open(path, "rb") as f:
        raw = f.read()
    if b"BEGIN CERTIFICATE" in raw:
        return raw
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, raw)
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    except Exception as e:
        print(f"  {_RE}✖ Não foi possível converter o certificado: {e}{_R}")
        return None


# ─── Push + instrução de instalação manual ────────────────────────────────────

def _push_and_guide(pem_bytes: bytes, label: str):
    """
    Salva o PEM como portswigger.crt, faz push para /sdcard/ e
    guia o usuário para instalar manualmente nas configurações do Android.
    """
    adb = _adb_exe()

    # Salva localmente
    crt_name = "portswigger.crt"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    tmp.write(pem_bytes)
    tmp.close()

    print(f"\n  {_C}[•] Enviando certificado para /sdcard/{crt_name}...{_R}", end="", flush=True)
    r = subprocess.run([adb, "push", tmp.name, f"/sdcard/{crt_name}"],
                       capture_output=True, text=True)
    try:
        os.unlink(tmp.name)
    except OSError:
        pass

    if r.returncode != 0:
        print(f" {_RE}✖{_R}")
        print(f"  {_RE}Erro: {r.stderr.strip()}{_R}")
        return False
    print(f" {_G}✔{_R}")
    print(f"  {_G}[✓] Certificado enviado para /sdcard/{crt_name}{_R}\n")

    # Instruções manuais
    print(f"  {_Y}→ AGORA INSTALE O CERTIFICADO MANUALMENTE NO EMULADOR:{_R}")
    print(f"  {_Y}1. Abra Configurações → Segurança → Criptografia e credenciais{_R}")
    print(f"  {_Y}2. Toque em 'Instalar um certificado' → 'Certificado CA'{_R}")
    print(f"  {_Y}3. Selecione o arquivo: /sdcard/{crt_name}{_R}")
    print(f"  {_Y}4. Confirme o nome '{label}' e aceite{_R}")
    print(f"  {_M}→ Dica: Isso permite que o Burp Suite intercepte tráfego HTTPS.{_R}\n")

    print(f"  {_Y}Aguardando 60s para você instalar o certificado...{_R}")
    for i in range(60, 0, -1):
        print(f"\r  {_C}  {i}s restantes...{_R}", end="", flush=True)
        time.sleep(1)
    print()
    return True


# ─── Menu standalone de certificado ──────────────────────────────────────────

def setup_cert_nox():
    from utils.common import clear_screen
    from core.banner import display_banner

    while True:
        clear_screen()
        display_banner()
        print(f"\n{_C}Certificado CA — Nox Player:{_R}\n")
        print(f"  {_C}1.{_R} Burp Suite    {_D}(download automático via proxy :8080){_R}")
        print(f"  {_C}2.{_R} mitmproxy     {_D}(arquivo local ~/.mitmproxy/){_R}")
        print(f"  {_C}3.{_R} Personalizado {_D}(qualquer .pem / .crt / .cer){_R}")
        print(f"  {_D}0. Voltar{_R}")

        choice = input(f"\n{_C}→{_R} ").strip()

        if choice == "0":
            break
        elif choice == "1":
            _cert_intro()
            pem   = _get_burp_pem()
            label = "portswigger"
        elif choice == "2":
            pem   = _get_mitmproxy_pem()
            label = "mitmproxy"
        elif choice == "3":
            pem   = _get_custom_pem()
            label = "custom"
        else:
            print(f"  {_RE}✖ Opção inválida.{_R}")
            time.sleep(0.6)
            continue

        if not pem:
            input(f"\n  {_D}→ Enter para continuar...{_R}")
            continue

        _push_and_guide(pem, label)
        input(f"\n  {_D}→ Enter para continuar...{_R}")
