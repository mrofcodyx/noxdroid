import sys
import os

_R   = "\033[0m"
_B   = "\033[1m"
_D   = "\033[2m"
_C   = "\033[96m"
_G   = "\033[92m"
_Y   = "\033[93m"
_RE  = "\033[91m"
_W   = "\033[97m"
_BL  = "\033[94m"
_M   = "\033[95m"
_DIM = "\033[90m"


def display_banner():
    os.system("")  # habilita ANSI no Windows

    print(f"""
  {_G}{_B} [:: NoxDroid ::]{_R}
  {_G}  (\_/){_R}
  {_C} ( •ᴗ•){_R}  {_W}{_B}Android Toolkit{_R}  {_DIM}v1.0{_R}
  {_C} />🍃  {_R}  {_DIM}by {_R}{_G}{_B}Mr_ofcodyx{_R}
""")


def display_banner_small():
    os.system("")
    print(f"  {_G}{_B}[:: NoxDroid ::]{_R}  {_DIM}by {_R}{_G}Mr_ofcodyx{_R}\n")


def show_terms():
    """Exibe Termo de Uso. Retorna True se aceito, encerra se recusado."""
    os.system("cls" if sys.platform == "win32" else "clear")
    os.system("")

    w = 64

    print(f"\n  {_RE}{_B}{'─' * w}{_R}")
    print(f"  {_RE}{_B}  TERMO DE USO E RESPONSABILIDADE{_R}")
    print(f"  {_RE}{_B}{'─' * w}{_R}\n")

    print(f"  {_W}Esta ferramenta foi desenvolvida EXCLUSIVAMENTE para fins de{_R}")
    print(f"  {_W}segurança ofensiva, pesquisa e testes de penetração autorizados.{_R}")
    print()
    print(f"  {_Y}Ao continuar, você declara que:{_R}")
    print()
    print(f"  {_DIM}  [1]  Possui autorização EXPLÍCITA e por escrito do proprietário{_R}")
    print(f"  {_DIM}       do sistema ou aplicativo alvo.{_R}")
    print()
    print(f"  {_DIM}  [2]  É o ÚNICO responsável por qualquer ação realizada com{_R}")
    print(f"  {_DIM}       esta ferramenta.{_R}")
    print()
    print(f"  {_DIM}  [3]  Está ciente de que o uso não autorizado pode constituir{_R}")
    print(f"  {_DIM}       crime (Lei nº 12.737/2012 e equivalentes internacionais).{_R}")
    print()
    print(f"  {_DIM}  [4]  Os autores NÃO se responsabilizam por danos ou{_R}")
    print(f"  {_DIM}       consequências legais decorrentes do uso indevido.{_R}")
    print()
    print(f"  {_Y}  USE COM RESPONSABILIDADE. HACK ÉTICO. RESPEITE A LEI.{_R}")
    print()
    print(f"  {_DIM}{'─' * w}{_R}")
    print(f"  {_C}{_B}  CRÉDITOS{_R}")
    print(f"  {_DIM}{'─' * w}{_R}")
    print()

    credits = [
        ("Criador & Desenvolvedor Principal", f"{_G}{_B}Mr_ofcodyx{_R}"),
        ("Frida Scripts (root/ssl bypass)",   f"{_C}lautarovculic{_R}"),
        ("Frida Crypto Hooks",                f"{_C}Magpol  (MiscFrida){_R}"),
        ("Root Bypass (base/edit)",           f"{_DIM}Daniele Linguaglossa, Simone Quatrini{_R}"),
        ("AndroidBeautifest",                 f"{_C}lautarovculic{_R}"),
        ("Androguard / APKiD / APKLeaks",     f"{_DIM}androguard-project, rednaga, dwisiswant0{_R}"),
        ("MobSFScan",                         f"{_DIM}MobSF Project{_R}"),
    ]

    for role, name in credits:
        print(f"  {_DIM}  {role:<38}{_R}  {name}")

    print()
    print(f"  {_DIM}{'─' * w}{_R}")
    print()
    print(f"  {_G}  [S]{_R}  Sim, concordo e aceito os termos")
    print(f"  {_RE}  [N]{_R}  Não, sair")
    print()

    try:
        resp = input(f"  {_C}→{_R} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        resp = "n"

    if resp != "s":
        print(f"\n  {_RE}Saindo...{_R}\n")
        sys.exit(0)

    return True


_TERMS_FILE = ".terms_accepted"


def terms_already_accepted() -> bool:
    return os.path.exists(_TERMS_FILE)


def mark_terms_accepted():
    try:
        with open(_TERMS_FILE, "w") as f:
            f.write("accepted")
    except Exception:
        pass
