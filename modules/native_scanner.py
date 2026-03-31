"""
Native Scanner — análise de bibliotecas .so (ELF) extraídas de APKs Android.
Detecta: RCE symbols, secrets/keys, URLs hardcoded, JNI methods, Base64, risk score.
Implementação Python pura — sem dependências externas (readelf/nm/strings).
"""
import re
import struct
import base64
import zipfile
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

RESULTS_DIR = Path("results")

# ─── Padrões ──────────────────────────────────────────────────────────────────

RCE_SYMBOLS = [
    "system", "execve", "execl", "execlp", "execvp", "popen", "fork",
    "dlopen", "dlsym", "chmod", "chown", "setuid", "setgid",
    "strcpy", "strcat", "sprintf", "gets",          # memory unsafe
    "loadLibrary", "Runtime", "ProcessBuilder",
]

SENSITIVE_PATTERNS = {
    "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase URL":     r"https://[a-z0-9-]+\.firebaseio\.com",
    "AWS Key":          r"AKIA[0-9A-Z]{16}",
    "OpenAI Key":       r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token":     r"ghp_[0-9a-zA-Z]{36}",
    "JWT":              r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Password/Token":   r"(?:pass(?:word)?|pwd|token|auth|secret)[\"'=:\s]+[^\"\s]{4,}",
    "Private Key":      r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
}

URL_RE    = re.compile(r"https?://[^\x00\s\"'<>]{8,}")
JNI_RE    = re.compile(r"Java_[A-Za-z0-9_]{4,}")
B64_RE    = re.compile(r"[A-Za-z0-9+/=]{24,}")


# ─── ELF parser (Python puro) ─────────────────────────────────────────────────

def _elf_strings(data: bytes, min_len: int = 5) -> list[str]:
    """Extrai strings printáveis de um binário ELF."""
    result = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7e:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def _elf_symbols(data: bytes) -> list[str]:
    """
    Extrai nomes de símbolos da tabela dinâmica ELF (.dynsym).
    Suporta ELF32 e ELF64, little e big endian.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []

    ei_class = data[4]   # 1=32bit, 2=64bit
    ei_data  = data[5]   # 1=LE, 2=BE
    endian   = "<" if ei_data == 1 else ">"
    is64     = ei_class == 2

    try:
        if is64:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                f"{endian}QHHH", data, 40)
            sh_fmt, sh_size = f"{endian}QQQQIIQQ", 64
        else:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                f"{endian}IHHH", data, 32)
            sh_fmt, sh_size = f"{endian}IIIIIIII", 40

        # Lê section headers
        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + sh_size > len(data):
                break
            if is64:
                sh_name, sh_type, _, sh_addr, sh_offset, sh_size_v, sh_link, _, _, _ = \
                    struct.unpack_from(f"{endian}IIQQQQIIQQ", data, off)
            else:
                sh_name, sh_type, _, sh_addr, sh_offset, sh_size_v, sh_link, _, _, _ = \
                    struct.unpack_from(f"{endian}IIIIIIIIII", data, off)
            sections.append({
                "name_idx": sh_name, "type": sh_type,
                "offset": sh_offset, "size": sh_size_v, "link": sh_link
            })

        # Encontra .dynsym (type=11) e .dynstr (type=3)
        dynsym = next((s for s in sections if s["type"] == 11), None)
        if not dynsym:
            return []
        dynstr_sec = sections[dynsym["link"]] if dynsym["link"] < len(sections) else None
        if not dynstr_sec:
            return []

        str_data = data[dynstr_sec["offset"]: dynstr_sec["offset"] + dynstr_sec["size"]]
        sym_data = data[dynsym["offset"]: dynsym["offset"] + dynsym["size"]]

        sym_entry = 24 if is64 else 16
        names = []
        for i in range(len(sym_data) // sym_entry):
            st_name = struct.unpack_from(f"{endian}I", sym_data, i * sym_entry)[0]
            end = str_data.find(b"\x00", st_name)
            name = str_data[st_name:end].decode("utf-8", errors="replace").strip()
            if name:
                names.append(name)
        return names

    except Exception:
        return []


# ─── Análise de um .so ────────────────────────────────────────────────────────

def _analyze_so(so_path: Path, out_lines: list[str]) -> int:
    """Analisa um arquivo .so e retorna o risk score."""

    def _p(msg: str, color: str = ""):
        colors = {"red": _RED, "yellow": _YELLOW, "green": _GREEN, "cyan": _CYAN, "dim": _DIM}
        c = colors.get(color, "")
        print(f"{c}{msg}{_RESET}")
        out_lines.append(re.sub(r"\033\[[0-9;]*m", "", msg))

    risk = 0
    data = so_path.read_bytes()

    _p(f"\n{'─'*60}", "cyan")
    _p(f"  {so_path.name}", "cyan")
    _p(f"{'─'*60}", "cyan")

    # ── Símbolos ELF ──────────────────────────────────────────────────────────
    symbols = _elf_symbols(data)
    rce_hits = [s for s in symbols if any(k in s for k in RCE_SYMBOLS)]
    if rce_hits:
        _p(f"\n  [RCE Symbols] {len(rce_hits)} encontrado(s):", "red")
        for s in rce_hits[:20]:
            _p(f"    ▸ {s}", "red")
            risk += 5
    else:
        _p(f"\n  [RCE Symbols] nenhum suspeito", "dim")

    # ── JNI Methods ───────────────────────────────────────────────────────────
    jni_hits = [s for s in symbols if JNI_RE.search(s)]
    if jni_hits:
        _p(f"\n  [JNI Methods] {len(jni_hits)} encontrado(s):", "cyan")
        for s in jni_hits[:20]:
            _p(f"    ▸ {s}", "cyan")

    # ── Strings ───────────────────────────────────────────────────────────────
    strings = _elf_strings(data)

    # Secrets
    secret_hits: list[tuple[str, str]] = []
    for s in strings:
        for label, pat in SENSITIVE_PATTERNS.items():
            if re.search(pat, s, re.IGNORECASE):
                secret_hits.append((label, s[:120]))
                break
    if secret_hits:
        _p(f"\n  [Secrets] {len(secret_hits)} encontrado(s):", "red")
        for label, val in secret_hits[:15]:
            _p(f"    ▸ [{label}] {val}", "red")
            risk += 4 if "Key" in label or "Token" in label else 3
    else:
        _p(f"\n  [Secrets] nenhum encontrado", "dim")

    # URLs
    url_hits = list({m.group() for s in strings for m in [URL_RE.search(s)] if m})
    if url_hits:
        _p(f"\n  [URLs] {len(url_hits)} encontrada(s):", "yellow")
        for u in sorted(url_hits)[:20]:
            _p(f"    ▸ {u}", "yellow")
            risk += 2

    # Base64
    b64_hits = []
    for s in strings:
        if B64_RE.fullmatch(s):
            try:
                dec = base64.b64decode(s + "==").decode("utf-8", errors="replace")
                if sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.7:
                    b64_hits.append((s[:40], dec[:80]))
            except Exception:
                pass
    if b64_hits:
        _p(f"\n  [Base64] {len(b64_hits)} string(s) decodificada(s):", "yellow")
        for enc, dec in b64_hits[:10]:
            _p(f"    ▸ {enc}  →  {dec}", "yellow")

    # ── Risk Score ────────────────────────────────────────────────────────────
    _p(f"\n  Risk Score: {risk}", "red" if risk >= 10 else "yellow" if risk >= 5 else "green")
    if risk >= 10:
        _p("  Nível: HIGH ⚠", "red")
    elif risk >= 5:
        _p("  Nível: MEDIUM ⚠", "yellow")
    else:
        _p("  Nível: LOW ✅", "green")

    return risk


# ─── Entry point ──────────────────────────────────────────────────────────────

def _pkg_from_apk(apk: "Path") -> str:
    """
    Extrai o package name do AndroidManifest.xml binário dentro do APK.
    Fallback: nome do arquivo sem extensão.
    """
    try:
        with zipfile.ZipFile(apk, "r") as z:
            if "AndroidManifest.xml" not in z.namelist():
                return apk.stem
            data = z.read("AndroidManifest.xml")

        # O manifest é XML binário (AXML). Procura a string "package" e pega o valor seguinte.
        # Estratégia simples: extrai todas as strings UTF-16LE do bloco de strings AXML.
        # O bloco de strings começa no offset 8 do chunk de string pool (type=0x0001).
        strings = _axml_strings(data)
        # O package name é sempre a primeira string do manifest que contém pontos
        # e não é um namespace Android.
        for s in strings:
            if (
                "." in s
                and not s.startswith("android")
                and not s.startswith("http")
                and not s.startswith("com.android")
                and 5 < len(s) < 100
                and all(c.isalnum() or c in "._" for c in s)
            ):
                return s
    except Exception:
        pass
    return apk.stem


def _axml_strings(data: bytes) -> list[str]:
    """Extrai strings do bloco StringPool de um AXML binário Android."""
    try:
        # Chunk header: type(2) size(2) chunkSize(4)
        # StringPool chunk type = 0x0001
        i = 0
        while i < len(data) - 8:
            chunk_type = struct.unpack_from("<H", data, i)[0]
            chunk_size = struct.unpack_from("<I", data, i + 4)[0]
            if chunk_type == 0x0001:  # StringPool
                string_count  = struct.unpack_from("<I", data, i + 8)[0]
                style_count   = struct.unpack_from("<I", data, i + 12)[0]
                flags         = struct.unpack_from("<I", data, i + 16)[0]
                strings_start = struct.unpack_from("<I", data, i + 20)[0]
                is_utf8       = bool(flags & (1 << 8))

                offsets_base = i + 28
                strings_base = i + 8 + strings_start

                result = []
                for idx in range(min(string_count, 200)):
                    off = struct.unpack_from("<I", data, offsets_base + idx * 4)[0]
                    pos = strings_base + off
                    try:
                        if is_utf8:
                            # UTF-8: len byte(s) + chars
                            slen = data[pos + 1]
                            s = data[pos + 2: pos + 2 + slen].decode("utf-8", errors="replace")
                        else:
                            # UTF-16LE: 2-byte len + chars
                            slen = struct.unpack_from("<H", data, pos)[0]
                            s = data[pos + 2: pos + 2 + slen * 2].decode("utf-16-le", errors="replace")
                        result.append(s)
                    except Exception:
                        continue
                return result
            i += max(chunk_size, 8)
    except Exception:
        pass
    return []


def _extract_so_from_zip(apk: Path, extract_dir: Path) -> list[Path]:
    """
    Extrai todos os .so de um arquivo APK/zip.
    Procura em qualquer caminho dentro do zip (não só lib/).
    Retorna lista de paths extraídos.
    """
    so_files = []
    with zipfile.ZipFile(apk, "r") as z:
        entries = z.namelist()
        for name in entries:
            low = name.lower()
            if not low.endswith(".so"):
                continue
            parts = name.replace("\\", "/").split("/")
            # Monta nome seguro preservando ABI se disponível
            # lib/arm64-v8a/libfoo.so → arm64-v8a_libfoo.so
            # assets/libfoo.so        → assets_libfoo.so
            if len(parts) >= 3 and parts[0] == "lib":
                safe_name = f"{parts[1]}_{parts[-1]}"
            elif len(parts) >= 2:
                safe_name = f"{parts[-2]}_{parts[-1]}"
            else:
                safe_name = parts[-1]
            dest = extract_dir / safe_name
            dest.write_bytes(z.read(name))
            so_files.append(dest)
    return so_files


def _find_split_apks(apk: Path) -> list[Path]:
    """
    Procura APKs irmãos (split APKs) na mesma pasta.
    Ex: base.apk → split_config.arm64_v8a.apk, split_config.x86.apk, etc.
    Também procura na pasta apk/ do package em results/.
    """
    candidates = []
    parent = apk.parent

    # Irmãos na mesma pasta
    for f in parent.glob("*.apk"):
        if f != apk:
            candidates.append(f)

    # Pasta results/<pkg>/apk/
    # Tenta inferir pkg do nome do arquivo ou do path
    for part in apk.parts:
        apk_folder = Path("results") / part / "apk"
        if apk_folder.exists():
            for f in apk_folder.glob("*.apk"):
                if f not in candidates:
                    candidates.append(f)
            break

    return candidates


def run_native_scanner(apk_path: str):
    """
    Extrai e analisa todos os .so de um APK (incluindo split APKs).
    Salva relatório em results/<pkg>/analysis/<ts>/native_scan.txt
    """
    apk = Path(apk_path)
    if not apk.exists():
        print(f"{_RED}✖ APK não encontrado: {apk}{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    pkg = _pkg_from_apk(apk)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import static_dir
    out_dir = static_dir(pkg)

    print(f"\n{_CYAN}{'═'*60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Native Scanner — {apk.name}{_RESET}")
    print(f"{_DIM}  Package: {pkg}{_RESET}")
    print(f"{_CYAN}{'═'*60}{_RESET}")

    # Extrai .so do APK principal + splits na mesma pasta
    so_files: list[Path] = []
    extract_dir = out_dir / "libs"
    extract_dir.mkdir(exist_ok=True)

    # Coleta todos os APKs a escanear: o principal + irmãos na mesma pasta (splits)
    apks_to_scan = [apk]
    for sibling in sorted(apk.parent.glob("*.apk")):
        if sibling != apk:
            apks_to_scan.append(sibling)

    try:
        for scan_apk in apks_to_scan:
            try:
                found = _extract_so_from_zip(scan_apk, extract_dir)
                if found:
                    print(f"\n{_DIM}  → {len(found)} .so em {scan_apk.name}{_RESET}")
                    so_files.extend(found)
            except zipfile.BadZipFile:
                continue
            except Exception:
                continue

        if not so_files:
            # Diagnóstico: mostra o que tem dentro do APK principal
            with zipfile.ZipFile(apk, "r") as z:
                all_entries = z.namelist()
            libs_entries = [e for e in all_entries if "lib" in e.lower() or e.endswith(".so")]
            print(f"\n{_YELLOW}  ⚠ Nenhuma .so encontrada em {len(apks_to_scan)} APK(s){_RESET}")
            if libs_entries:
                print(f"{_DIM}  Entradas com 'lib' no APK principal:{_RESET}")
                for e in libs_entries[:10]:
                    print(f"  {_DIM}    {e}{_RESET}")
            else:
                print(f"{_DIM}  Conteúdo do APK principal (primeiros 20 arquivos):{_RESET}")
                for e in all_entries[:20]:
                    print(f"  {_DIM}    {e}{_RESET}")

    except zipfile.BadZipFile:
        print(f"{_RED}✖ Arquivo não é um APK válido (zip corrompido).{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return
    except Exception as e:
        print(f"{_RED}✖ Erro ao extrair APK: {e}{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    if not so_files:
        print(f"\n{_YELLOW}⚠ Nenhuma biblioteca .so encontrada.{_RESET}")
        print(f"{_DIM}  Possíveis causas:{_RESET}")
        print(f"{_DIM}    • App pure-Java (sem código nativo){_RESET}")
        print(f"{_DIM}    • App bundle — as .so ficam em split APKs separados{_RESET}")
        print(f"{_DIM}    • .so embutidas em assets/ com extensão diferente{_RESET}")
        print(f"\n{_DIM}  Dica: baixe todos os APKs do app com:{_RESET}")
        print(f"{_CYAN}    adb shell pm path {pkg}{_RESET}")
        print(f"{_CYAN}    adb pull <cada path listado>{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    print(f"\n{_DIM}→ {len(so_files)} biblioteca(s) encontrada(s){_RESET}\n")

    out_lines: list[str] = [
        f"Native Scanner — {apk.name}",
        f"Package  : {pkg}",
        f"Timestamp: {ts}",
        "",
    ]
    total_risk = 0

    for so in sorted(so_files):
        total_risk += _analyze_so(so, out_lines)

    # Resumo final
    out_lines += [
        "",
        "═" * 60,
        f"Risk Score Total: {total_risk}",
        f"Nível: {'HIGH' if total_risk >= 10 else 'MEDIUM' if total_risk >= 5 else 'LOW'}",
    ]

    report = out_dir / "native_scan.txt"
    report.write_text("\n".join(out_lines), encoding="utf-8")

    print(f"\n{_CYAN}{'═'*60}{_RESET}")
    print(f"{_DIM}  Risk Score Total: {_RESET}"
          f"{''+_RED if total_risk >= 10 else _YELLOW if total_risk >= 5 else _GREEN}"
          f"{total_risk}{_RESET}")
    print(f"{_GREEN}✔ Relatório salvo em: {report}{_RESET}")
    input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
