"""
AndroidBeautifest — Analisador de AndroidManifest.xml
Detecta componentes exportados, deep links, configurações inseguras
e gera comandos ADB prontos para uso.
Source: https://github.com/lautarovculic/androidBeautifest
"""
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

_R  = "\033[0m"
_C  = "\033[96m"
_W  = "\033[97m"
_D  = "\033[90m"
_B  = "\033[1m"
_Y  = "\033[93m"
_RE = "\033[91m"
_G  = "\033[92m"
_BL = "\033[94m"

RESULTS_DIR = Path("results")


class AndroidBeautifest:
    def __init__(self, apk_path: str) -> None:
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path).replace(".apk", "")
        self.ns = "{http://schemas.android.com/apk/res/android}"
        self.report_lines: List[str] = []

    # ── Output ────────────────────────────────────────────────────────────────

    def _p(self, text: str, color: str = _W) -> None:
        print(f"{color}{text}{_R}")
        self.report_lines.append(text)

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> None:
        try:
            from androguard.misc import AnalyzeAPK
            import logging
            logging.getLogger("androguard").setLevel(logging.ERROR)
            try:
                from loguru import logger as _ll; _ll.remove()
            except Exception:
                pass
        except ImportError:
            self._p("[-] androguard não instalado. Execute: pip install androguard", _RE)
            return

        self._p(f"\n{'=' * 70}", _D)
        self._p(f"  AndroidBeautifest — {self.apk_name}.apk", _B + _C)
        self._p(f"{'=' * 70}\n", _D)

        try:
            apk, _, _ = AnalyzeAPK(self.apk_path)
        except Exception as e:
            self._p(f"[-] Erro ao analisar APK: {e}", _RE)
            return

        manifest_xml = apk.get_android_manifest_xml()
        root = manifest_xml.getroot() if hasattr(manifest_xml, "getroot") else manifest_xml

        package_name  = apk.get_package()
        version_code  = str(apk.get_androidversion_code() or "N/A")
        version_name  = str(apk.get_androidversion_name() or "N/A")

        self._p(f"  Package : {package_name}", _W)
        self._p(f"  Version : {version_name} (code {version_code})", _D)
        self._p(f"  {'─' * 66}\n", _D)

        self._analyze_insecure_configs(root)
        self._analyze_queries(root)
        self._analyze_components(root, package_name)
        self._save_report(package_name)

    # ── Helpers XML ───────────────────────────────────────────────────────────

    def _attr(self, elem: ET.Element, name: str) -> Optional[str]:
        return elem.attrib.get(f"{self.ns}{name}")

    def _find_first(self, root: ET.Element, suffix: str) -> Optional[ET.Element]:
        for el in root.iter():
            if el.tag.endswith(suffix):
                return el
        return None

    # ── Configurações inseguras ───────────────────────────────────────────────

    def _analyze_insecure_configs(self, root: ET.Element) -> None:
        app = self._find_first(root, "application")
        if app is None:
            return

        issues = []

        if self._attr(app, "debuggable") == "true":
            issues.append(("CRITICAL", "debuggable=true",
                "App debugável — permite JDWP, inspeção de memória e tampering.",
                "Remova android:debuggable ou defina como false em produção."))

        if self._attr(app, "allowBackup") == "true":
            issues.append(("HIGH", "allowBackup=true",
                "Backup habilitado — dados podem ser extraídos via adb backup.",
                "Desabilite backups ou defina uma política restritiva."))

        if self._attr(app, "usesCleartextTraffic") == "true":
            issues.append(("HIGH", "usesCleartextTraffic=true",
                "Tráfego HTTP em texto claro permitido — suscetível a MITM.",
                "Restrinja cleartext e force TLS no network security config."))

        if self._attr(app, "testOnly") == "true":
            issues.append(("MEDIUM", "testOnly=true",
                "App marcado como testOnly — não deve aparecer em produção.",
                "Remova android:testOnly em builds de produção."))

        nsc = self._attr(app, "networkSecurityConfig")
        if nsc:
            issues.append(("INFO", f"networkSecurityConfig={nsc}",
                "Configuração de segurança de rede customizada em uso.",
                "Revise o arquivo XML de network security config manualmente."))

        if not issues:
            return

        self._p("[*] Configurações inseguras:", _C)
        self._p("=" * 70, _D)
        for level, name, desc, hint in issues:
            color = _RE if level == "CRITICAL" else (_Y if level == "HIGH" else _W)
            self._p(f"  [{level}] {name}", color)
            self._p(f"    Descrição : {desc}", _W)
            self._p(f"    Dica      : {hint}", _D)
            self._p("")
        self._p("=" * 70 + "\n", _D)

    # ── Queries / visibilidade de pacotes ─────────────────────────────────────

    def _analyze_queries(self, root: ET.Element) -> None:
        queries = self._find_first(root, "queries")
        if queries is None:
            return

        found = []
        for child in queries:
            if child.tag.endswith("package"):
                p = self._attr(child, "name")
                if p:
                    found.append(("package", p))
            elif child.tag.endswith("intent"):
                actions = [self._attr(a, "name") for a in child if a.tag.endswith("action")]
                actions = [a for a in actions if a]
                if actions:
                    found.append(("intent", ", ".join(actions)))

        if found:
            self._p("[*] Visibilidade de pacotes (<queries>):", _C)
            for q_type, q_val in found:
                prefix = "  PACKAGE:" if q_type == "package" else "  INTENT:"
                self._p(f"{prefix} {q_val}", _D)
            self._p("")

    # ── Componentes ───────────────────────────────────────────────────────────

    _GENERIC_PREFIXES = (
        "com.google.firebase", "com.google.android.gms", "androidx.",
        "android.support.", "com.facebook.", "com.android.vending",
        "com.google.android.play", "com.crashlytics.", "io.fabric.sdk",
        "com.android.installreferrer",
    )

    def _is_generic(self, name: str) -> bool:
        return any(name.startswith(p) for p in self._GENERIC_PREFIXES)

    def _analyze_components(self, root: ET.Element, package_name: str) -> None:
        TYPES = ["activity", "activity-alias", "service", "receiver", "provider"]
        app = self._find_first(root, "application")
        if app is None:
            return

        components = []
        unprotected_count = 0

        for elem in app:
            c_type = next((t for t in TYPES if elem.tag.endswith(t)), None)
            if not c_type:
                continue

            name = self._attr(elem, "name")
            if not name:
                continue

            if name.startswith("."):
                full_name = package_name + name
            elif "." not in name:
                full_name = package_name + "." + name
            else:
                full_name = name

            if self._is_generic(full_name):
                continue

            exported_attr = self._attr(elem, "exported")
            has_filters   = any(c.tag.endswith("intent-filter") for c in elem)
            is_exported   = (exported_attr == "true") if exported_attr is not None else has_filters

            perm  = self._attr(elem, "permission")
            rperm = self._attr(elem, "readPermission")
            wperm = self._attr(elem, "writePermission")
            protected = bool(perm or rperm or wperm)

            unprotected = is_exported and not protected
            if unprotected:
                unprotected_count += 1

            components.append({
                "type": c_type, "name": full_name,
                "exported": is_exported, "unprotected": unprotected,
                "permission": perm, "read_permission": rperm, "write_permission": wperm,
                "authority": self._attr(elem, "authorities"),
                "grant_uri": self._attr(elem, "grantUriPermissions"),
                "actions": self._get_actions(elem),
                "deep_links": self._get_deep_links(elem),
            })

        components.sort(key=lambda x: (not x["unprotected"], not x["exported"], x["type"]))

        exported_count = sum(1 for c in components if c["exported"])
        self._p(f"[*] Componentes: {len(components)} total  |  {exported_count} exportados  |  {unprotected_count} sem permissão", _C)
        self._p("=" * 70 + "\n", _D)

        for comp in components:
            self._display_component(comp, package_name)

    def _get_actions(self, elem: ET.Element) -> List[str]:
        actions = []
        for child in elem:
            if not child.tag.endswith("intent-filter"):
                continue
            for action in child:
                if action.tag.endswith("action"):
                    a = self._attr(action, "name")
                    if a:
                        actions.append(a)
        return actions

    def _get_deep_links(self, elem: ET.Element) -> List[str]:
        links = []
        for intent_filter in elem:
            if not intent_filter.tag.endswith("intent-filter"):
                continue
            auto_verify = self._attr(intent_filter, "autoVerify") == "true"
            schemes, hosts, ports, paths, prefixes, patterns = set(), set(), set(), [], [], []
            for data in intent_filter:
                if not data.tag.endswith("data"):
                    continue
                s = self._attr(data, "scheme")
                h = self._attr(data, "host")
                po = self._attr(data, "port")
                p  = self._attr(data, "path")
                pp = self._attr(data, "pathPrefix")
                ppa = self._attr(data, "pathPattern")
                if s:   schemes.add(s)
                if h:   hosts.add(h)
                if po:  ports.add(po)
                if p:   paths.append(p)
                if pp:  prefixes.append(pp)
                if ppa: patterns.append(ppa)

            link_type = "APP_LINK" if auto_verify else "DEEP_LINK"
            for scheme in schemes:
                bases = [f"{scheme}://{h}" for h in hosts] if hosts else [f"{scheme}://"]
                for base in bases:
                    for port in (ports or [None]):
                        b = f"{base}:{port}" if port else base
                        if paths:
                            links += [f"{link_type} {b}{p}" for p in paths]
                        elif prefixes:
                            links += [f"{link_type} {b}{pp}*" for pp in prefixes]
                        elif patterns:
                            links += [f"{link_type} {b}{ppa}" for ppa in patterns]
                        else:
                            links.append(f"{link_type} {b}")
        return links

    def _display_component(self, comp: Dict[str, Any], package_name: str) -> None:
        if comp["unprotected"]:
            color, status = _RE, "[EXPORTADO SEM PERMISSÃO]"
        elif comp["exported"]:
            color, status = _Y, "[EXPORTADO]"
        else:
            color, status = _D, "[NÃO EXPORTADO]"

        self._p("─" * 70, _D)
        self._p(f"  {status}", color)
        self._p(f"  Tipo : {comp['type']}   Nome : {comp['name']}", color)

        if comp["exported"]:
            for label, val in [("Permissão", comp["permission"]),
                                ("Leitura",   comp["read_permission"]),
                                ("Escrita",   comp["write_permission"])]:
                if val:
                    self._p(f"  {label}: {val}", _W)
            if not any([comp["permission"], comp["read_permission"], comp["write_permission"]]):
                self._p("  ⚠ Exportado sem permissão — qualquer app pode interagir.", color)

        if comp["actions"]:
            self._p("  Intent actions:", _D)
            for a in comp["actions"]:
                self._p(f"    • {a}", _D)

        if comp["deep_links"]:
            self._p("  Deep links:", _D)
            for dl in comp["deep_links"]:
                self._p(f"    • {dl}", _BL)

        if comp["type"] == "provider" and comp["authority"]:
            self._p(f"  Authority: {comp['authority']}", _W)
            if comp["grant_uri"] == "true":
                self._p("  ⚠ grantUriPermissions=true — URIs podem ser compartilhadas.", _Y)

        self._p("\n  Comandos ADB:", _D)
        self._generate_commands(comp, package_name)
        self._p("")

    def _generate_commands(self, comp: Dict[str, Any], package_name: str) -> None:
        t = comp["type"]
        n = comp["name"]

        def cmd(line: str) -> None:
            self._p(f"    > {line}", _G)

        if t in ("activity", "activity-alias"):
            cmd(f"adb shell am start -n {package_name}/{n}")
            for dl in comp["deep_links"]:
                uri = dl.split(" ", 1)[-1]
                cmd(f'adb shell am start -W -a android.intent.action.VIEW -d "{uri}" {package_name}')
            if comp["unprotected"]:
                cmd(f'adb shell am start -n {package_name}/{n} --es "param" "../../../etc/passwd"')
                cmd(f'adb shell am start -n {package_name}/{n} --es "url" "javascript:alert(1)"')

        elif t == "service":
            cmd(f"adb shell am startservice -n {package_name}/{n}")
            if comp["unprotected"]:
                cmd(f'adb shell am startservice -n {package_name}/{n} --es "cmd" "id"')

        elif t == "receiver":
            cmd(f"adb shell am broadcast -n {package_name}/{n}")
            for action in comp["actions"][:2]:
                cmd(f"adb shell am broadcast -a {action} -n {package_name}/{n}")
            if comp["unprotected"]:
                cmd(f'adb shell am broadcast -n {package_name}/{n} --es "data" "payload"')

        elif t == "provider" and comp["authority"]:
            auth = comp["authority"]
            cmd(f"adb shell content query --uri content://{auth}/")
            if comp["unprotected"]:
                cmd(f"adb shell content query --uri content://{auth}/../../")
                cmd(f"adb shell content insert --uri content://{auth}/ --bind column:s:value")
                cmd(f"adb shell content update --uri content://{auth}/ --bind column:s:newvalue")
                cmd(f"adb shell content delete --uri content://{auth}/")
                cmd(f'adb shell content query --uri "content://{auth}/\' OR \'1\'=\'1\""')

    # ── Salvar relatório ──────────────────────────────────────────────────────

    def _save_report(self, package_name: str) -> None:
        from core.report_paths import static_dir
        out_dir  = static_dir(package_name)
        out_file = out_dir / "beautifest.txt"
        out_file.write_text("\n".join(self.report_lines), encoding="utf-8")
        print(f"\n{_G}✔ Relatório salvo em: {out_file}{_R}")


def run_beautifest(apk_path: str) -> None:
    """Entry point chamado pelo main.py."""
    tool = AndroidBeautifest(apk_path)
    tool.run()
    input(f"\n{_D}→ Enter para continuar...{_R}")
