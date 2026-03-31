"""
MobSFScan Analyzer — análise estática de código fonte Android/iOS via mobsfscan.
Usa a Python API diretamente (MobSFScan class) para obter todos os recursos:
  - Semgrep rules (crypto, webview, injection, network, deserialization, xxe, android)
  - Pattern matcher (Kotlin, Objective-C, Swift)
  - AndroidManifest + Network Security Config XML checks
  - Missing Controls (best practices ausentes: TLS pinning, root detection, FLAG_SECURE...)
  - Exportação: JSON + HTML + SARIF + SonarQube
  - Config .mobsf: ignore-rules, ignore-paths, severity-filter
"""
import os
import sys
import json
import shutil
import subprocess
import webbrowser
import html as _html_mod
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

_SEV_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
_SEV_CLASS = {"ERROR": "sev-error", "WARNING": "sev-warn", "INFO": "sev-info"}

# Categorias inferidas do rule_id prefix
_CATEGORIES = {
    "crypto":          "🔐 Crypto",
    "webview":         "🌐 WebView",
    "injection":       "💉 Injection",
    "network":         "📡 Network",
    "deserialization": "📦 Deserialization",
    "xxe":             "🗂 XXE",
    "android":         "🤖 Android",
    "ios":             "🍎 iOS",
    "kotlin":          "🟣 Kotlin",
    "swift":           "🔵 Swift",
    "objectivec":      "⚪ Objective-C",
}


def _category(rule_id: str) -> str:
    low = rule_id.lower()
    for key, label in _CATEGORIES.items():
        if low.startswith(key) or f"_{key}_" in low or low.endswith(f"_{key}"):
            return label
    return "📋 Other"


# ─── Garante código fonte disponível ─────────────────────────────────────────

def _ensure_source(apk_path: str, pkg: str) -> Path | None:
    base = RESULTS_DIR / pkg / "decompiled"

    java_dir = base / "java"
    if java_dir.exists() and any(java_dir.rglob("*.java")):
        print(f"  {_GREEN}✔ Usando Java descompilado: {java_dir}{_RESET}")
        return java_dir

    smali_dir = base / "smali"
    if smali_dir.exists() and any(smali_dir.rglob("*.smali")):
        print(f"  {_YELLOW}→ Usando smali descompilado: {smali_dir}{_RESET}")
        return smali_dir

    print(f"  {_YELLOW}→ Descompilando APK com apktool...{_RESET}", flush=True)
    try:
        from modules.apk_analyzer import decompile_apktool
        result = decompile_apktool(apk_path)
        if result and Path(result).exists():
            return Path(result)
    except Exception as e:
        print(f"  {_RED}✖ Falha ao descompilar: {e}{_RESET}")
    return None


# ─── XMLs relevantes (evita spam de res/values-*/strings.xml) ────────────────

# Apenas estes nomes de arquivo XML interessam ao mobsfscan manifest checker
_RELEVANT_XML_NAMES = {
    "androidmanifest.xml",
    "network_security_config.xml",
    "network-security-config.xml",
}

# Pastas que nunca contêm XMLs úteis para análise de segurança
_SKIP_XML_DIRS = {
    "values", "values-af", "values-am", "values-ar", "values-as",
    "values-az", "values-b+sr+latn", "values-be", "values-bg",
    "values-bn", "values-bs", "values-ca", "values-cs", "values-da",
    "values-de", "values-el", "values-en", "values-es", "values-et",
    "values-eu", "values-fa", "values-fi", "values-fr", "values-gl",
    "values-gu", "values-hi", "values-hr", "values-hu", "values-hy",
    "values-in", "values-is", "values-it", "values-iw", "values-ja",
    "values-ka", "values-kk", "values-km", "values-kn", "values-ko",
    "values-ky", "values-lo", "values-lt", "values-lv", "values-mk",
    "values-ml", "values-mn", "values-mr", "values-ms", "values-my",
    "values-nb", "values-ne", "values-nl", "values-or", "values-pa",
    "values-pl", "values-pt", "values-ro", "values-ru", "values-si",
    "values-sk", "values-sl", "values-sq", "values-sr", "values-sv",
    "values-sw", "values-ta", "values-te", "values-th", "values-tl",
    "values-tr", "values-uk", "values-ur", "values-uz", "values-vi",
    "values-zh", "values-zu",
    "drawable", "drawable-hdpi", "drawable-mdpi", "drawable-xhdpi",
    "drawable-xxhdpi", "drawable-xxxhdpi", "drawable-nodpi",
    "layout", "layout-land", "layout-sw600dp", "layout-xlarge",
    "menu", "anim", "animator", "color", "font", "mipmap",
    "mipmap-hdpi", "mipmap-mdpi", "mipmap-xhdpi", "mipmap-xxhdpi",
    "mipmap-xxxhdpi", "mipmap-anydpi-v26", "raw", "xml",
}


def _filter_xmls(src_path: Path) -> list:
    """
    Retorna apenas XMLs relevantes para análise de segurança:
    - AndroidManifest.xml (em qualquer lugar)
    - network_security_config.xml (em qualquer lugar)
    Ignora res/values-*, res/drawable-*, res/layout, etc.
    """
    relevant = []
    for f in src_path.rglob("*.xml"):
        # Ignora pastas de recursos de UI/localização
        parts_lower = {p.lower() for p in f.parts}
        if any(skip in parts_lower for skip in _SKIP_XML_DIRS):
            continue
        # Aceita apenas nomes conhecidos ou qualquer XML fora de res/
        name_lower = f.name.lower()
        in_res = "res" in {p.lower() for p in f.parts}
        if not in_res or name_lower in _RELEVANT_XML_NAMES:
            relevant.append(f)
    return relevant


# ─── Executa scan via Python API ──────────────────────────────────────────────

def _run_scan(src_path: Path, scan_type: str = "auto",
              mp: str = "default", config_file: str | None = None) -> dict | None:
    """
    Usa MobSFScan Python API diretamente, com filtragem de XMLs irrelevantes.
    Sobrescreve get_xmls() para evitar spam de res/values-*/strings.xml.
    """
    try:
        from mobsfscan.mobsfscan import MobSFScan
    except ImportError:
        print(f"  {_RED}✖ mobsfscan não instalado. Execute: pip install mobsfscan{_RESET}")
        return None

    print(f"  {_YELLOW}→ Executando MobSFScan (tipo={scan_type}, mp={mp})...{_RESET}", flush=True)
    try:
        scanner = MobSFScan(
            paths=[str(src_path)],
            json=True,
            scan_type=scan_type,
            config=config_file or False,
            mp=mp,
        )
        # Substitui a lista de XMLs pela versão filtrada
        scanner.xmls = _filter_xmls(src_path)
        return scanner.scan()
    except Exception as e:
        print(f"  {_RED}✖ Erro no scan: {e}{_RESET}")
        return None


# ─── Exporta SARIF ────────────────────────────────────────────────────────────

def _save_sarif(data: dict, out: Path, src_path: str):
    try:
        import importlib.metadata
        version = importlib.metadata.version("mobsfscan")
        from mobsfscan.formatters.sarif import sarif_output
        sarif_output(str(out), data, version, [src_path])
        print(f"  {_GREEN}✔ SARIF salvo: {out}{_RESET}")
    except Exception as e:
        print(f"  {_DIM}⚠ SARIF não gerado: {e}{_RESET}")


# ─── Exporta SonarQube ────────────────────────────────────────────────────────

def _save_sonarqube(data: dict, out: Path):
    try:
        import importlib.metadata
        version = importlib.metadata.version("mobsfscan")
        from mobsfscan.formatters.sonarqube import sonarqube_output
        sonarqube_output(str(out), data, version)
        print(f"  {_GREEN}✔ SonarQube JSON salvo: {out}{_RESET}")
    except Exception as e:
        print(f"  {_DIM}⚠ SonarQube não gerado: {e}{_RESET}")


# ─── Gera HTML ────────────────────────────────────────────────────────────────

def _h(s) -> str:
    return _html_mod.escape(str(s))


def _save_html(data: dict, out: Path, src_path: str, ts: str, pkg: str):
    results = data.get("results", {})
    errors  = data.get("errors", [])

    # Separa findings com arquivos (detecções) dos sem arquivos (missing controls)
    detections    = {k: v for k, v in results.items() if v.get("files")}
    missing_ctrl  = {k: v for k, v in results.items() if not v.get("files")}

    sorted_det = sorted(detections.items(),
                        key=lambda x: _SEV_ORDER.get(
                            x[1].get("metadata", {}).get("severity", "INFO").upper(), 99))
    sorted_miss = sorted(missing_ctrl.items(),
                         key=lambda x: x[1].get("metadata", {}).get("severity", "INFO"))

    n_error = sum(1 for _, f in sorted_det if f.get("metadata", {}).get("severity", "").upper() == "ERROR")
    n_warn  = sum(1 for _, f in sorted_det if f.get("metadata", {}).get("severity", "").upper() == "WARNING")
    n_info  = sum(1 for _, f in sorted_det if f.get("metadata", {}).get("severity", "").upper() == "INFO")
    n_miss  = len(missing_ctrl)

    # Categorias únicas para filtro
    cats = sorted(set(_category(k) for k, _ in sorted_det))
    cat_btns = "".join(
        f'<button class="filter-btn" onclick="filterCat(\'{_h(c)}\')">{_h(c)}</button>'
        for c in cats
    )

    # OWASP únicos
    owasp_set = sorted(set(
        f.get("metadata", {}).get("owasp-mobile", "")
        for _, f in sorted_det
        if f.get("metadata", {}).get("owasp-mobile", "")
    ))
    owasp_btns = "".join(
        f'<button class="filter-btn" onclick="filterOwasp(\'{_h(o)}\')">{_h(o)}</button>'
        for o in owasp_set
    )

    def _finding_row(rule_id, finding, show_cat=True):
        meta     = finding.get("metadata", {})
        sev      = meta.get("severity", "INFO").upper()
        sev_cls  = _SEV_CLASS.get(sev, "sev-info")
        desc     = meta.get("description", "")
        cwe      = meta.get("cwe", "")
        owasp    = meta.get("owasp-mobile", "")
        masvs    = meta.get("masvs", "")
        ref      = meta.get("reference", "")
        cvss     = meta.get("cvss", "")
        cat      = _category(rule_id)
        files    = finding.get("files", [])

        files_html = ""
        for f in files[:20]:
            fpath   = _h(f.get("file_path", ""))
            lines   = f.get("match_lines", ("?", "?"))
            pos     = f.get("match_position", (1, 1))
            match_s = _h(f.get("match_string", "")[:300])
            files_html += (
                f'<div class="file-entry">'
                f'<span class="file-path">{fpath}</span>'
                f'<span class="file-line">L{lines[0]}:{pos[0]}–L{lines[1]}:{pos[1]}</span>'
                f'<div class="match-str">{match_s}</div>'
                f'</div>'
            )
        if len(files) > 20:
            files_html += f'<div class="file-entry dim">+{len(files)-20} arquivos...</div>'

        ref_html  = f'<a href="{_h(ref)}" target="_blank" class="ref-link">↗ ref</a>' if ref else ""
        cvss_html = f'<span class="cvss-badge">CVSS {_h(cvss)}</span>' if cvss else ""
        cat_html  = f'<span class="cat-tag">{_h(cat)}</span>' if show_cat else ""

        cwe_tag   = f'<span class="meta-tag">{_h(cwe)}</span>' if cwe else ""
        owasp_tag = f'<span class="meta-tag owasp">{_h(owasp)}</span>' if owasp else ""
        masvs_tag = f'<span class="meta-tag masvs">{_h(masvs)}</span>' if masvs else ""
        no_files  = '<span class="dim">sem arquivos</span>'
        return (
            f'<tr class="finding-row" data-sev="{sev}" '
            f'data-owasp="{_h(owasp)}" data-cat="{_h(cat)}">'
            f'<td><span class="badge {sev_cls}">{sev}</span></td>'
            f'<td>'
            f'<div class="rule-id">{_h(rule_id)}</div>'
            f'<div class="rule-desc">{_h(desc)}</div>'
            f'<div class="rule-meta">'
            f'{cat_html}{cwe_tag}{owasp_tag}{masvs_tag}{cvss_html}{ref_html}'
            f'</div></td>'
            f'<td class="files-col">{files_html if files_html else no_files}</td>'
            f'</tr>'
        )

    rows_html = "".join(_finding_row(k, v) for k, v in sorted_det)

    # Missing controls table
    miss_rows = ""
    for rule_id, finding in sorted_miss:
        meta  = finding.get("metadata", {})
        sev   = meta.get("severity", "WARNING").upper()
        sev_cls = _SEV_CLASS.get(sev, "sev-warn")
        desc  = meta.get("description", "")
        cwe   = meta.get("cwe", "")
        owasp = meta.get("owasp-mobile", "")
        masvs = meta.get("masvs", "")
        ref   = meta.get("reference", "")
        ref_html = f'<a href="{_h(ref)}" target="_blank" class="ref-link">↗ ref</a>' if ref else ""
        cwe_tag2   = f'<span class="meta-tag">{_h(cwe)}</span>' if cwe else ""
        owasp_tag2 = f'<span class="meta-tag owasp">{_h(owasp)}</span>' if owasp else ""
        masvs_tag2 = f'<span class="meta-tag masvs">{_h(masvs)}</span>' if masvs else ""
        miss_rows += (
            f'<tr>'
            f'<td><span class="badge {sev_cls}">{sev}</span></td>'
            f'<td>'
            f'<div class="rule-id">{_h(rule_id)}</div>'
            f'<div class="rule-desc">{_h(desc)}</div>'
            f'<div class="rule-meta">{cwe_tag2}{owasp_tag2}{masvs_tag2}{ref_html}</div>'
            f'</td>'
            f'<td class="dim" style="font-size:12px">Controle ausente no código</td>'
            f'</tr>'
        )

    errors_html = "".join(
        f'<div class="error-entry">{_h(str(e))}</div>' for e in errors
    )

    miss_section = ""
    if miss_rows:
        miss_section = f"""
<div style="padding:0 32px 8px">
  <div class="section-title">⚠ Controles de Segurança Ausentes ({n_miss})</div>
  <div class="dim" style="font-size:12px;margin-bottom:8px">
    Boas práticas não encontradas no código — TLS pinning, root detection, FLAG_SECURE, etc.
  </div>
  <table class="miss-table">
    <thead><tr>
      <th style="width:90px">Severidade</th>
      <th>Controle / Descrição</th>
      <th style="width:200px">Nota</th>
    </tr></thead>
    <tbody>{miss_rows}</tbody>
  </table>
</div>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NoxDroid — MobSFScan — {_h(pkg)}</title>
<style>
  :root{{--bg:#0d0f14;--surface:#13161e;--card:#1a1e2a;--border:#252a38;
        --cyan:#00e5ff;--cyan2:#00b8d4;--yellow:#ffd740;--red:#ff5252;
        --orange:#ff9800;--green:#69ff47;--dim:#5a6070;--text:#cdd6f4;--text2:#8892a4}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}}
  header{{background:var(--surface);border-bottom:1px solid var(--border);padding:18px 32px}}
  .logo{{font-size:22px;font-weight:700;color:var(--cyan);letter-spacing:2px}}
  .logo span{{color:var(--text2);font-weight:400;font-size:13px;margin-left:8px}}
  .subtitle{{color:var(--text2);font-size:12px;margin-top:2px}}
  .stats{{display:flex;gap:14px;padding:20px 32px;flex-wrap:wrap}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 22px;min-width:120px}}
  .stat-card .val{{font-size:28px;font-weight:700}}
  .stat-card .lbl{{font-size:11px;color:var(--text2);margin-top:2px;text-transform:uppercase;letter-spacing:1px}}
  .stat-card.error .val{{color:var(--red)}}
  .stat-card.warn  .val{{color:var(--orange)}}
  .stat-card.info  .val{{color:var(--cyan)}}
  .stat-card.miss  .val{{color:var(--yellow)}}
  .filters{{padding:0 32px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
  .filter-btn{{background:var(--card);border:1px solid var(--border);color:var(--text2);
               padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px;transition:all .15s}}
  .filter-btn:hover,.filter-btn.active{{background:var(--cyan);color:#000;border-color:var(--cyan)}}
  .filter-label{{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-right:4px}}
  .search-box{{background:var(--card);border:1px solid var(--border);color:var(--text);
               padding:6px 12px;border-radius:6px;font-size:13px;width:260px;outline:none}}
  .search-box:focus{{border-color:var(--cyan)}}
  table{{width:100%;border-collapse:collapse}}
  .miss-table{{width:calc(100% - 0px);border-collapse:collapse;margin-bottom:24px}}
  thead th{{background:var(--surface);color:var(--text2);font-size:11px;text-transform:uppercase;
            letter-spacing:1px;padding:10px 16px;border-bottom:1px solid var(--border);text-align:left}}
  tbody tr{{border-bottom:1px solid var(--border);transition:background .1s}}
  tbody tr:hover{{background:var(--card)}}
  tbody td{{padding:10px 16px;vertical-align:top}}
  .badge{{display:inline-block;border-radius:5px;padding:3px 10px;font-size:11px;font-weight:700;letter-spacing:.5px;white-space:nowrap}}
  .sev-error{{background:#ff525222;color:var(--red);border:1px solid #ff525244}}
  .sev-warn {{background:#ff980022;color:var(--orange);border:1px solid #ff980044}}
  .sev-info {{background:#00e5ff22;color:var(--cyan);border:1px solid #00e5ff44}}
  .rule-id{{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;color:var(--cyan2);font-weight:600;margin-bottom:4px}}
  .rule-desc{{font-size:13px;color:var(--text);margin-bottom:6px;line-height:1.5}}
  .rule-meta{{display:flex;gap:6px;flex-wrap:wrap;align-items:center}}
  .meta-tag{{background:var(--surface);border:1px solid var(--border);color:var(--text2);
             padding:2px 8px;border-radius:4px;font-size:11px}}
  .meta-tag.owasp{{color:var(--yellow);border-color:#ffd74044}}
  .meta-tag.masvs{{color:var(--green);border-color:#69ff4744}}
  .cat-tag{{background:#00e5ff11;border:1px solid #00e5ff33;color:var(--cyan2);
            padding:2px 8px;border-radius:4px;font-size:11px}}
  .cvss-badge{{background:#ff980022;color:var(--orange);border:1px solid #ff980044;
               padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
  .ref-link{{color:var(--cyan2);font-size:11px;text-decoration:none}}
  .ref-link:hover{{text-decoration:underline}}
  .files-col{{max-width:420px}}
  .file-entry{{margin-bottom:6px;padding:6px 8px;background:var(--surface);border-radius:4px;border-left:2px solid var(--border)}}
  .file-path{{font-family:'Cascadia Code','Consolas',monospace;font-size:11px;color:var(--cyan2);display:block;word-break:break-all}}
  .file-line{{font-size:10px;color:var(--text2);margin-left:4px}}
  .match-str{{font-family:'Cascadia Code','Consolas',monospace;font-size:11px;color:var(--text2);
              margin-top:3px;word-break:break-all;white-space:pre-wrap}}
  .dim{{color:var(--dim);font-size:12px}}
  .error-entry{{background:#ff525211;border:1px solid #ff525233;border-radius:6px;
                padding:8px 12px;margin:4px 32px;font-size:12px;color:var(--red)}}
  .table-wrap{{padding:0 32px 32px;overflow-x:auto}}
  .section-title{{font-size:15px;font-weight:700;color:var(--yellow);margin-bottom:8px;padding-top:8px}}
  footer{{text-align:center;padding:20px;color:var(--dim);font-size:11px;border-top:1px solid var(--border)}}
  .hidden{{display:none!important}}
</style>
</head>
<body>
<header>
  <div class="logo">NoxDroid <span>MobSFScan</span></div>
  <div class="subtitle">Fonte: {_h(src_path)} &nbsp;·&nbsp; {_h(ts)}</div>
</header>

<div class="stats">
  <div class="stat-card error"><div class="val">{n_error}</div><div class="lbl">Error</div></div>
  <div class="stat-card warn"> <div class="val">{n_warn}</div> <div class="lbl">Warning</div></div>
  <div class="stat-card info"> <div class="val">{n_info}</div> <div class="lbl">Info</div></div>
  <div class="stat-card miss"> <div class="val">{n_miss}</div> <div class="lbl">Missing Controls</div></div>
  <div class="stat-card">     <div class="val">{len(results)}</div><div class="lbl">Total</div></div>
</div>

<div class="filters">
  <span class="filter-label">Severidade:</span>
  <button class="filter-btn active" onclick="filterSev('ALL')">Todos</button>
  <button class="filter-btn" onclick="filterSev('ERROR')">Error</button>
  <button class="filter-btn" onclick="filterSev('WARNING')">Warning</button>
  <button class="filter-btn" onclick="filterSev('INFO')">Info</button>
  &nbsp;
  <span class="filter-label">Categoria:</span>
  <button class="filter-btn active" onclick="filterCat('ALL')">Todas</button>
  {cat_btns}
  &nbsp;
  <span class="filter-label">OWASP:</span>
  <button class="filter-btn active" onclick="filterOwasp('ALL')">Todos</button>
  {owasp_btns}
  &nbsp;
  <input class="search-box" type="text" placeholder="Buscar rule ID, descrição, CWE..." oninput="filterSearch(this.value)">
</div>

{f'<div style="padding:0 32px 8px">{errors_html}</div>' if errors_html else ''}

<div class="table-wrap">
<table id="findings-table">
  <thead>
    <tr>
      <th style="width:90px">Severidade</th>
      <th>Regra / Descrição</th>
      <th style="width:420px">Arquivos (linha:col)</th>
    </tr>
  </thead>
  <tbody>
    {rows_html if rows_html else '<tr><td colspan="3" style="padding:20px;color:var(--dim);text-align:center">Nenhum finding.</td></tr>'}
  </tbody>
</table>
</div>

{miss_section}

<footer>NoxDroid · MobSFScan · {_h(ts)}</footer>

<script>
var _curSev='ALL', _curOwasp='ALL', _curCat='ALL', _curSearch='';
function _apply(){{
  document.querySelectorAll('#findings-table tbody tr.finding-row').forEach(function(r){{
    var show=true;
    if(_curSev!=='ALL'&&r.dataset.sev!==_curSev) show=false;
    if(_curOwasp!=='ALL'&&r.dataset.owasp!==_curOwasp) show=false;
    if(_curCat!=='ALL'&&r.dataset.cat!==_curCat) show=false;
    if(_curSearch&&r.textContent.toLowerCase().indexOf(_curSearch.toLowerCase())===-1) show=false;
    r.classList.toggle('hidden',!show);
  }});
}}
function _setBtn(fn,val){{
  document.querySelectorAll('.filter-btn').forEach(function(b){{
    var oc=b.getAttribute('onclick')||'';
    if(oc.includes(fn+'('))
      b.classList.toggle('active',oc.includes("'"+val+"'"));
  }});
}}
function filterSev(v){{_curSev=v;_setBtn('filterSev',v);_apply();}}
function filterOwasp(v){{_curOwasp=v;_setBtn('filterOwasp',v);_apply();}}
function filterCat(v){{_curCat=v;_setBtn('filterCat',v);_apply();}}
function filterSearch(v){{_curSearch=v;_apply();}}
</script>
</body>
</html>"""
    out.write_text(html, encoding="utf-8")


# ─── Config .mobsf ────────────────────────────────────────────────────────────

def _edit_config(config_path: Path):
    """Permite ao usuário configurar ignore-rules, ignore-paths, severity-filter."""
    _clear()
    print(f"{_CYAN}{'═'*60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  MobSFScan — Configurar .mobsf{_RESET}")
    print(f"{_CYAN}{'═'*60}{_RESET}\n")

    current = {}
    if config_path.exists():
        try:
            import yaml
            current = yaml.safe_load(config_path.read_text()) or {}
        except Exception:
            pass

    print(f"  {_DIM}Arquivo: {config_path}{_RESET}")
    print(f"  {_DIM}Configurações atuais:{_RESET}")
    print(f"  {_DIM}  ignore-rules  : {current.get('ignore-rules', [])}{_RESET}")
    print(f"  {_DIM}  ignore-paths  : {current.get('ignore-paths', [])}{_RESET}")
    print(f"  {_DIM}  severity-filter: {current.get('severity-filter', ['INFO','WARNING','ERROR'])}{_RESET}")
    print()
    print(f"  {_CYAN}1.{_RESET} Adicionar rule ID a ignore-rules")
    print(f"  {_CYAN}2.{_RESET} Adicionar path a ignore-paths")
    print(f"  {_CYAN}3.{_RESET} Definir severity-filter")
    print(f"  {_CYAN}4.{_RESET} Limpar configuração")
    print(f"  {_DIM}0. Voltar{_RESET}")

    c = input(f"\n{_CYAN}→{_RESET} ").strip()

    if c == "1":
        rule = input("  Rule ID (ex: android_manifest_debugging_enabled): ").strip()
        if rule:
            rules = current.get("ignore-rules", [])
            if rule not in rules:
                rules.append(rule)
            current["ignore-rules"] = rules

    elif c == "2":
        path = input("  Path (ex: test, fixtures): ").strip()
        if path:
            paths = current.get("ignore-paths", [])
            if path not in paths:
                paths.append(path)
            current["ignore-paths"] = paths

    elif c == "3":
        print("  Severidades disponíveis: INFO, WARNING, ERROR")
        sev = input("  Filtro (ex: WARNING,ERROR): ").strip().upper()
        if sev:
            current["severity-filter"] = [s.strip() for s in sev.split(",")]

    elif c == "4":
        current = {}

    if c in ("1", "2", "3", "4"):
        try:
            import yaml
            config_path.write_text(yaml.dump(current, default_flow_style=False), encoding="utf-8")
            print(f"  {_GREEN}✔ Configuração salva em {config_path}{_RESET}")
        except Exception as e:
            print(f"  {_RED}✖ Erro ao salvar: {e}{_RESET}")
        input(f"\n  → Enter para continuar...")


# ─── Menu de opções ───────────────────────────────────────────────────────────

def _clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def _pick_options(pkg: str) -> dict | None:
    config_path = RESULTS_DIR / pkg / "mobsf_config.yaml"

    while True:
        _clear()
        print(f"{_CYAN}{'═'*60}{_RESET}")
        print(f"{_CYAN}{_BOLD}  MobSFScan — Configurar Scan{_RESET}")
        print(f"{_CYAN}{'═'*60}{_RESET}\n")

        print(f"  {_CYAN}Tipo de análise:{_RESET}")
        print(f"  {_GREEN}1.{_RESET} auto     {_DIM}(detecta Android/iOS — recomendado){_RESET}")
        print(f"  {_GREEN}2.{_RESET} android  {_DIM}(força regras Android){_RESET}")
        print(f"  {_GREEN}3.{_RESET} ios      {_DIM}(força regras iOS){_RESET}")

        print(f"\n  {_CYAN}Multiprocessing:{_RESET}")
        print(f"  {_GREEN}a.{_RESET} default  {_DIM}(multiprocessing padrão){_RESET}")
        print(f"  {_GREEN}b.{_RESET} billiard {_DIM}(billiard — melhor em alguns ambientes){_RESET}")
        print(f"  {_GREEN}c.{_RESET} thread   {_DIM}(threading — mais leve){_RESET}")

        print(f"\n  {_CYAN}Config .mobsf:{_RESET}")
        cfg_status = f"{_GREEN}✔ existe{_RESET}" if config_path.exists() else f"{_DIM}não existe{_RESET}"
        print(f"  {_GREEN}e.{_RESET} Editar configuração  {_DIM}({cfg_status}{_DIM}){_RESET}")

        print(f"\n  {_DIM}0. Cancelar{_RESET}")

        c = input(f"\n{_CYAN}→{_RESET} ").strip().lower()

        if c == "0" or not c:
            return None
        if c == "e":
            _edit_config(config_path)
            continue

        scan_type = {"1": "auto", "2": "android", "3": "ios"}.get(c, "auto")
        mp_choice = input(f"\n{_CYAN}→{_RESET} Multiprocessing [a/b/c, Enter=default]: ").strip().lower()
        mp = {"b": "billiard", "c": "thread"}.get(mp_choice, "default")

        return {
            "scan_type":   scan_type,
            "mp":          mp,
            "config_file": str(config_path) if config_path.exists() else None,
        }


# ─── Runner principal ─────────────────────────────────────────────────────────

def run_mobsfscan(apk_path: str):
    _clear()
    print(f"{_CYAN}{'═'*60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  MobSFScan — Análise de Código Fonte{_RESET}")
    print(f"{_CYAN}{'═'*60}{_RESET}\n")

    apk = Path(apk_path)
    if not apk.exists():
        print(f"  {_RED}✖ Arquivo não encontrado: {apk_path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    # Extrai package name
    pkg = apk.stem
    for i, part in enumerate(apk.parts):
        if part == "results" and i + 1 < len(apk.parts):
            pkg = apk.parts[i + 1]
            break

    print(f"  {_DIM}APK : {apk_path}{_RESET}")
    print(f"  {_DIM}Pkg : {pkg}{_RESET}\n")

    opts = _pick_options(pkg)
    if not opts:
        return

    _clear()
    print(f"{_CYAN}{'═'*60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  MobSFScan — Executando{_RESET}")
    print(f"{_CYAN}{'═'*60}{_RESET}\n")

    src_path = _ensure_source(apk_path, pkg)
    if not src_path:
        print(f"  {_RED}✖ Não foi possível obter código fonte.{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    data = _run_scan(src_path, opts["scan_type"], opts["mp"], opts["config_file"])
    if data is None:
        input(f"\n  → Enter para continuar...")
        return

    results     = data.get("results", {})
    errors      = data.get("errors", [])
    detections  = {k: v for k, v in results.items() if v.get("files")}
    missing     = {k: v for k, v in results.items() if not v.get("files")}

    n_error = sum(1 for f in detections.values() if f.get("metadata", {}).get("severity", "").upper() == "ERROR")
    n_warn  = sum(1 for f in detections.values() if f.get("metadata", {}).get("severity", "").upper() == "WARNING")
    n_info  = sum(1 for f in detections.values() if f.get("metadata", {}).get("severity", "").upper() == "INFO")

    print(f"\n  {_RED}✖ ERROR          : {n_error}{_RESET}")
    print(f"  {_YELLOW}⚠ WARNING        : {n_warn}{_RESET}")
    print(f"  {_CYAN}ℹ INFO           : {n_info}{_RESET}")
    print(f"  {_YELLOW}⚑ Missing Controls: {len(missing)}{_RESET}")
    if errors:
        print(f"  {_DIM}Erros de scan    : {len(errors)}{_RESET}")

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import static_dir
    out_dir = static_dir(pkg)

    # JSON
    json_out = out_dir / "mobsfscan.json"
    json_out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  {_GREEN}✔ JSON    : {json_out}{_RESET}")

    # HTML
    html_out = out_dir / "mobsfscan.html"
    _save_html(data, html_out, str(src_path), ts, pkg)
    print(f"  {_GREEN}✔ HTML    : {html_out}{_RESET}")

    # SARIF
    sarif_out = out_dir / "mobsfscan.sarif"
    _save_sarif(data, sarif_out, str(src_path))

    # SonarQube
    sonar_out = out_dir / "mobsfscan_sonarqube.json"
    _save_sonarqube(data, sonar_out)

    if input(f"\n  Abrir HTML no navegador? [S/n]: ").strip().lower() != "n":
        webbrowser.open(html_out.resolve().as_uri())

    input(f"\n  → Enter para continuar...")
