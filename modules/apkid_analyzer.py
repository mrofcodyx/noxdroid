"""
APKiD Analyzer — identifica compiladores, packers, obfuscators e anti-análise em APKs.
"""
import json
import shutil
import subprocess
import sys
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

# Categorias de risco
_HIGH_RISK = {
    "anti_vm", "anti_disassembly", "anti_debug", "obfuscator",
    "packer", "protector", "dropper",
}
_MED_RISK = {
    "manipulator", "abnormal", "compiler",
}


def _severity(category: str) -> str:
    c = category.lower()
    for h in _HIGH_RISK:
        if h in c:
            return "HIGH"
    for m in _MED_RISK:
        if m in c:
            return "MEDIUM"
    return "LOW"


def _apkid_bin() -> str:
    """Localiza o executável apkid no PATH ou nos Scripts do Python."""
    found = shutil.which("apkid")
    if found:
        return found
    try:
        r = subprocess.run([sys.executable, "-m", "site", "--user-base"],
                           capture_output=True, text=True)
        base = r.stdout.strip()
        for sub in ["Scripts", f"Python{sys.version_info.major}{sys.version_info.minor}\\Scripts"]:
            c = Path(base) / sub / "apkid.exe"
            if c.exists():
                return str(c)
    except Exception:
        pass
    return "apkid"


def _run_apkid(apk_path: str) -> dict | None:
    """Executa apkid --json e retorna o dict de resultados."""
    try:
        r = subprocess.run(
            [_apkid_bin(), "--json", "--timeout", "60", apk_path],
            capture_output=True, text=True, timeout=120
        )
        out = r.stdout.strip()
        if not out:
            out = r.stderr.strip()
        # Extrai JSON do output (pode ter linhas de log antes)
        start = out.find("{")
        if start == -1:
            return None
        return json.loads(out[start:])
    except Exception as e:
        print(f"  {_RED}✖ Erro ao executar APKiD: {e}{_RESET}")
        return None


def _save_html(results: dict, out: Path, apk_path: str, ts: str):
    """Gera relatório HTML do APKiD."""
    import json as _json

    files = results.get("files", [])
    all_matches: list[dict] = []
    for f in files:
        fname = f.get("filename", "")
        for category, detections in f.get("matches", {}).items():
            for det in (detections if isinstance(detections, list) else [detections]):
                all_matches.append({
                    "file": fname,
                    "category": category,
                    "detection": str(det),
                    "sev": _severity(category),
                })

    n_high = sum(1 for m in all_matches if m["sev"] == "HIGH")
    n_med  = sum(1 for m in all_matches if m["sev"] == "MEDIUM")
    n_low  = sum(1 for m in all_matches if m["sev"] == "LOW")
    total  = len(all_matches)

    rows_html = ""
    for m in all_matches:
        sev_cls = {"HIGH": "sev-high", "MEDIUM": "sev-med", "LOW": "sev-low"}[m["sev"]]
        rows_html += f"""
        <tr data-sev="{m['sev']}" data-cat="{_html_mod.escape(m['category'])}">
          <td><span class="badge {sev_cls}">{m['sev']}</span></td>
          <td class="cat-name">{_html_mod.escape(m['category'])}</td>
          <td class="det-val"><code>{_html_mod.escape(m['detection'])}</code></td>
          <td class="file-path" title="{_html_mod.escape(m['file'])}">{_html_mod.escape(m['file'])}</td>
        </tr>"""

    cat_options = "\n".join(
        f'<option value="{_html_mod.escape(c)}">{_html_mod.escape(c)}</option>'
        for c in sorted({m["category"] for m in all_matches})
    )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NoxDroid — APKiD</title>
<style>
  :root {{
    --bg:#0d0f14;--surface:#13161e;--card:#1a1e2a;--border:#252a38;
    --cyan:#00e5ff;--cyan2:#00b8d4;--yellow:#ffd740;--red:#ff5252;
    --orange:#ff9800;--green:#69ff47;--dim:#5a6070;--text:#cdd6f4;--text2:#8892a4;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}}
  header{{background:var(--surface);border-bottom:1px solid var(--border);padding:18px 32px}}
  .logo{{font-size:22px;font-weight:700;color:var(--cyan);letter-spacing:2px}}
  .logo span{{color:var(--text2);font-weight:400;font-size:13px;margin-left:8px}}
  .subtitle{{color:var(--text2);font-size:12px;margin-top:2px}}
  .stats{{display:flex;gap:14px;padding:20px 32px;flex-wrap:wrap}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 22px;min-width:130px;cursor:pointer;transition:border-color .15s,transform .1s;user-select:none}}
  .stat-card:hover{{border-color:var(--cyan);transform:translateY(-2px)}}
  .stat-card.active{{border-color:var(--cyan);box-shadow:0 0 0 2px #00b8d444}}
  .stat-card .val{{font-size:28px;font-weight:700}}
  .stat-card .lbl{{font-size:11px;color:var(--text2);margin-top:2px;text-transform:uppercase;letter-spacing:1px}}
  .stat-card.total .val{{color:var(--cyan)}}
  .stat-card.high .val{{color:var(--red)}}
  .stat-card.med .val{{color:var(--orange)}}
  .stat-card.low .val{{color:var(--yellow)}}
  .toolbar{{padding:0 32px 16px;display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
  .toolbar input,.toolbar select{{background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:7px;padding:8px 14px;font-size:13px;outline:none}}
  .toolbar input{{width:280px}}
  .toolbar input:focus,.toolbar select:focus{{border-color:var(--cyan)}}
  .btn-action{{border:none;border-radius:7px;padding:8px 18px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s}}
  .btn-primary{{background:var(--cyan);color:#000}}
  .btn-secondary{{background:var(--card);color:var(--text2);border:1px solid var(--border)}}
  .btn-action:hover{{opacity:.85}}
  .count-badge{{color:var(--text2);font-size:12px;margin-left:4px}}
  .table-wrap{{padding:0 32px 40px;overflow-x:auto}}
  table{{width:100%;border-collapse:collapse}}
  thead th{{background:var(--surface);color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:10px 14px;border-bottom:1px solid var(--border);text-align:left;position:sticky;top:0;z-index:1}}
  tbody tr{{border-bottom:1px solid var(--border);transition:background .1s}}
  tbody tr:hover{{background:var(--card)}}
  tbody td{{padding:10px 14px;vertical-align:top}}
  .badge{{display:inline-block;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:.5px}}
  .sev-high{{background:#ff525222;color:var(--red);border:1px solid #ff525244}}
  .sev-med{{background:#ff980022;color:var(--orange);border:1px solid #ff980044}}
  .sev-low{{background:#ffd74022;color:var(--yellow);border:1px solid #ffd74044}}
  .cat-name{{color:var(--cyan2);font-weight:500;white-space:nowrap}}
  .det-val code{{background:#0a0c12;border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-family:'Cascadia Code','Consolas',monospace;font-size:12px;color:var(--green);word-break:break-all;display:block;max-width:520px}}
  .file-path{{color:var(--text2);font-size:12px;font-family:monospace;word-break:break-all;max-width:320px}}
  .empty{{text-align:center;padding:60px;color:var(--dim);font-size:15px}}
  footer{{text-align:center;padding:20px;color:var(--dim);font-size:11px;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<header>
  <div class="logo">NoxDroid <span>APKiD</span></div>
  <div class="subtitle">APK: {_html_mod.escape(apk_path)} &nbsp;·&nbsp; {_html_mod.escape(ts)}</div>
</header>
<div class="stats">
  <div class="stat-card total" onclick="clearFilters()" title="Limpar filtros"><div class="val">{total}</div><div class="lbl">Total</div></div>
  <div class="stat-card high" onclick="filterBySev('HIGH')" title="Filtrar HIGH"><div class="val">{n_high}</div><div class="lbl">High</div></div>
  <div class="stat-card med" onclick="filterBySev('MEDIUM')" title="Filtrar MEDIUM"><div class="val">{n_med}</div><div class="lbl">Medium</div></div>
  <div class="stat-card low" onclick="filterBySev('LOW')" title="Filtrar LOW"><div class="val">{n_low}</div><div class="lbl">Low</div></div>
</div>
<div class="toolbar">
  <input type="text" id="search" placeholder="🔍  Filtrar..." oninput="applyFilters()">
  <select id="sev-filter" onchange="applyFilters()">
    <option value="">Severidade</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
  </select>
  <select id="cat-filter" onchange="applyFilters()">
    <option value="">Categoria</option>
    {cat_options}
  </select>
  <button class="btn-action btn-secondary" onclick="clearFilters()">✕ Limpar</button>
  <span class="count-badge" id="count-badge">{total} resultados</span>
</div>
<div class="table-wrap">
  <table>
    <thead><tr>
      <th style="width:80px">Sev.</th>
      <th style="width:200px">Categoria</th>
      <th>Detecção</th>
      <th>Arquivo</th>
    </tr></thead>
    <tbody id="tbody">
      {rows_html if rows_html else '<tr><td colspan="4" class="empty">Nenhuma detecção encontrada.</td></tr>'}
    </tbody>
  </table>
</div>
<footer>NoxDroid · APKiD · {_html_mod.escape(ts)}</footer>
<script>
function applyFilters(){{
  const q=document.getElementById('search').value.toLowerCase();
  const sev=document.getElementById('sev-filter').value;
  const cat=document.getElementById('cat-filter').value;
  const rows=document.querySelectorAll('#tbody tr[data-sev]');
  let v=0;
  rows.forEach(r=>{{
    const ok=(!q||r.textContent.toLowerCase().includes(q))&&(!sev||r.dataset.sev===sev)&&(!cat||r.dataset.cat===cat);
    r.style.display=ok?'':'none';if(ok)v++;
  }});
  document.getElementById('count-badge').textContent=v+' resultado'+(v!==1?'s':'');
}}
function filterBySev(sev){{
  document.getElementById('sev-filter').value=sev;
  document.getElementById('search').value='';
  document.getElementById('cat-filter').value='';
  document.querySelectorAll('.stat-card').forEach(c=>c.classList.remove('active'));
  const map={{'HIGH':1,'MEDIUM':2,'LOW':3}};
  document.querySelectorAll('.stat-card')[map[sev]].classList.add('active');
  applyFilters();
}}
function clearFilters(){{
  document.getElementById('search').value='';
  document.getElementById('sev-filter').value='';
  document.getElementById('cat-filter').value='';
  document.querySelectorAll('.stat-card').forEach(c=>c.classList.remove('active'));
  applyFilters();
}}
</script>
</body>
</html>"""
    out.write_text(html, encoding="utf-8")


def run_apkid(apk_path: str):
    """Menu/runner do APKiD."""
    print(f"\n{_CYAN}{'─'*60}{_RESET}")
    print(f"{_CYAN}{_BOLD}  APKiD — Identificação de Compiladores/Packers{_RESET}")
    print(f"{_DIM}{'─'*60}{_RESET}\n")

    apk = Path(apk_path)
    if not apk.exists():
        print(f"  {_RED}✖ Arquivo não encontrado: {apk_path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    print(f"  {_DIM}APK: {apk_path}{_RESET}")
    print(f"  {_YELLOW}→ Executando APKiD...{_RESET}\n")

    data = _run_apkid(apk_path)
    if not data:
        print(f"  {_RED}✖ APKiD não retornou resultados.{_RESET}")
        print(f"  {_DIM}Verifique se apkid está instalado: python -m pip install apkid{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    # Print resumo no terminal
    files = data.get("files", [])
    total_det = 0
    for f in files:
        fname = f.get("filename", "")
        matches = f.get("matches", {})
        if not matches:
            continue
        print(f"  {_CYAN}► {fname}{_RESET}")
        for category, detections in matches.items():
            sev = _severity(category)
            sev_color = {
                "HIGH": _RED, "MEDIUM": _YELLOW, "LOW": _DIM
            }[sev]
            dets = detections if isinstance(detections, list) else [detections]
            for det in dets:
                print(f"    {sev_color}[{sev}]{_RESET} {_WHITE}{category}{_RESET}: {_GREEN}{det}{_RESET}")
                total_det += 1
        print()

    if total_det == 0:
        print(f"  {_DIM}Nenhuma detecção encontrada.{_RESET}")

    # Salva HTML
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pkg = apk.stem
    # Tenta extrair pkg real do path results/<pkg>/...
    parts = apk.parts
    for i, part in enumerate(parts):
        if part == "results" and i + 1 < len(parts):
            pkg = parts[i + 1]
            break

    from core.report_paths import static_dir
    out_dir = static_dir(pkg)
    out_html = out_dir / "apkid.html"

    _save_html(data, out_html, apk_path, ts)
    print(f"  {_GREEN}✔ Relatório salvo em: {out_html}{_RESET}")

    open_now = input(f"\n  Abrir no navegador? [S/n]: ").strip().lower()
    if open_now != "n":
        webbrowser.open(out_html.resolve().as_uri())

    input(f"\n  → Enter para continuar...")
