"""
Secrets Finder - varre arquivos de um APK descompilado em busca de
API keys, tokens, credenciais e outros segredos hardcoded.
"""
import os
import re
import sys
import html as _html_mod
import subprocess
import webbrowser
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
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
_MAG    = "\033[95m"

RESULTS_DIR = Path("results")
CHUNK_SIZE  = 1024 * 1024  # 1 MB

# ─── Padrões ──────────────────────────────────────────────────────────────────
# Cada entrada: {"regex": compiled, "light_search": bool}
# light_search=True → incluído no modo rápido (menos falsos positivos)

SECRETS_REGEX: dict[str, dict | list] = {
    "API Key Generic": {
        "regex": re.compile(rb'(apikey|api_key|secret|token)[\'"\s:=]+[a-zA-Z0-9\-._]{8,}', re.IGNORECASE),
        "light_search": False,
    },
    "API Key in Variable": {
        "regex": re.compile(rb'(api[_-]?key)[\'"\s:=]+[a-zA-Z0-9\-_.]{8,100}'),
        "light_search": True,
    },
    "Amazon AWS Access Key ID": {
        "regex": re.compile(rb'([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}'),
        "light_search": True,
    },
    "Amazon AWS S3 Bucket": {
        "regex": re.compile(rb'[a-z0-9.-]+\.s3\.amazonaws\.com'),
        "light_search": True,
    },
    "Amazon AWS RDS Hostname": {
        "regex": re.compile(rb'[a-z0-9-]+\.rds\.amazonaws\.com'),
        "light_search": True,
    },
    "Authorization Bearer Token": {
        "regex": re.compile(rb'[Bb]earer\s+[a-zA-Z0-9\-._~+/]+=*'),
        "light_search": True,
    },
    "Authorization Basic": {
        "regex": re.compile(rb'basic\s[a-zA-Z0-9_\-:\.=]+'),
        "light_search": True,
    },
    "Azure Client Secret": {
        "regex": re.compile(rb'azure(.{0,20})?client.secret(.{0,20})?[\'"][a-zA-Z0-9._%+-]{32,}[\'"]', re.IGNORECASE),
        "light_search": True,
    },
    "Basic Auth Credentials": {
        "regex": re.compile(rb'(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+'),
        "light_search": True,
    },
    "Discord Bot Token": {
        "regex": re.compile(rb'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}'),
        "light_search": True,
    },
    "Discord Webhook URL": {
        "regex": re.compile(rb'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'),
        "light_search": True,
    },
    "Facebook AccessToken": {
        "regex": re.compile(rb'EAACEdEose0cBA[0-9A-Za-z]+'),
        "light_search": True,
    },
    "Firebase URL": {
        "regex": re.compile(rb'https://[a-z0-9-]+\.firebaseio\.com'),
        "light_search": True,
    },
    "Firebase API Key": {
        "regex": re.compile(rb'firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*[\'"][^\'"]+[\'"]'),
        "light_search": True,
    },
    "Generic API Key": {
        "regex": re.compile(rb'[aA][pP][iI][_]?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]'),
        "light_search": True,
    },
    "Generic Secret": {
        "regex": re.compile(rb'[sS][eE][cC][rR][eE][tT].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]'),
        "light_search": True,
    },
    "GitHub Token": {
        "regex": re.compile(rb'[gG][iI][tT][hH][uU][bB].*[\'|"][0-9a-zA-Z]{35,40}[\'|"]'),
        "light_search": True,
    },
    "GitHub Personal Access Token": {
        "regex": re.compile(rb'ghp_[a-zA-Z0-9]{36}'),
        "light_search": True,
    },
    "GitHub OAuth Token": {
        "regex": re.compile(rb'gho_[a-zA-Z0-9]{36}'),
        "light_search": True,
    },
    "GitLab Personal Access Token": {
        "regex": re.compile(rb'glpat-[0-9a-zA-Z-_]{20}'),
        "light_search": True,
    },
    "Google API Key": {
        "regex": re.compile(rb'AIza[0-9A-Za-z\-_]{35}'),
        "light_search": True,
    },
    "Google Cloud OAuth": {
        "regex": re.compile(rb'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "light_search": True,
    },
    "Google OAuth Access Token": {
        "regex": re.compile(rb'ya29\.[0-9A-Za-z\-_]+'),
        "light_search": True,
    },
    "Google Service Account": {
        "regex": re.compile(rb'"type":\s*"service_account"'),
        "light_search": True,
    },
    "Heroku API Key": {
        "regex": re.compile(rb'[hH]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
        "light_search": True,
    },
    "JDBC URL": {
        "regex": re.compile(rb'jdbc:\w+://[^\s\'"]+'),
        "light_search": True,
    },
    "JSON Web Token (JWT)": {
        "regex": re.compile(rb'eyJ[a-zA-Z0-9_=]+\.[a-zA-Z0-9_=]+\.[a-zA-Z0-9_\-+/=]+'),
        "light_search": True,
    },
    "Localhost Reference": {
        "regex": re.compile(rb'localhost:[0-9]{2,5}'),
        "light_search": True,
    },
    "MailChimp API Key": {
        "regex": re.compile(rb'[0-9a-f]{32}-us[0-9]{1,2}'),
        "light_search": True,
    },
    "Mailgun API Key": {
        "regex": re.compile(rb'key-[0-9a-zA-Z]{32}'),
        "light_search": True,
    },
    "MongoDB URI": {
        "regex": re.compile(rb'mongodb(\+srv)?://[^\s\'"]+'),
        "light_search": True,
    },
    "MySQL URI": {
        "regex": re.compile(rb'mysql://[^\s\'"]+'),
        "light_search": True,
    },
    "OAuth Client Secret": {
        "regex": re.compile(rb'client_secret[\'"\s:=]+[a-zA-Z0-9\-_.~]{10,100}'),
        "light_search": True,
    },
    "OpenAI API Key": {
        "regex": re.compile(rb'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
        "light_search": True,
    },
    "OpenAI Project Key": {
        "regex": re.compile(rb'sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
        "light_search": True,
    },
    "Password Assignment": {
        "regex": re.compile(rb'(password|pwd|pass)[\'"\s:=]+[^\s\'"]{4,100}', re.IGNORECASE),
        "light_search": False,
    },
    "Password in URL": {
        "regex": re.compile(rb'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\s]'),
        "light_search": True,
    },
    "PEM Certificate": {
        "regex": re.compile(rb'-----BEGIN CERTIFICATE-----'),
        "light_search": True,
    },
    "PGP Private Key": {
        "regex": re.compile(rb'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        "light_search": True,
    },
    "PostgreSQL URI": {
        "regex": re.compile(rb'postgres(?:ql)?://[^\s\'"]+'),
        "light_search": True,
    },
    "Redis URI": {
        "regex": re.compile(rb'redis://[^\s\'"]+'),
        "light_search": True,
    },
    "RSA Private Key": {
        "regex": re.compile(rb'-----BEGIN RSA PRIVATE KEY-----'),
        "light_search": True,
    },
    "SendGrid API Key": {
        "regex": re.compile(rb'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),
        "light_search": True,
    },
    "Sentry DSN": {
        "regex": re.compile(rb'https://[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io/\d+'),
        "light_search": True,
    },
    "Slack API Token": {
        "regex": re.compile(rb'xox[pboare]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}'),
        "light_search": True,
    },
    "Slack Webhook": {
        "regex": re.compile(rb'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'),
        "light_search": True,
    },
    "SSH DSA Private Key": {
        "regex": re.compile(rb'-----BEGIN DSA PRIVATE KEY-----'),
        "light_search": True,
    },
    "SSH EC Private Key": {
        "regex": re.compile(rb'-----BEGIN EC PRIVATE KEY-----'),
        "light_search": True,
    },
    "Stripe Secret Key": {
        "regex": re.compile(rb'sk_live_[0-9a-zA-Z]{24}'),
        "light_search": True,
    },
    "Stripe Test Key": {
        "regex": re.compile(rb'sk_test_[0-9a-zA-Z]{24}'),
        "light_search": True,
    },
    "Stripe Webhook Secret": {
        "regex": re.compile(rb'whsec_[0-9a-zA-Z]{48}'),
        "light_search": True,
    },
    "Telegram Bot Token": {
        "regex": re.compile(rb'\d{9}:[a-zA-Z0-9_-]{35}'),
        "light_search": True,
    },
    "Twilio API Key": {
        "regex": re.compile(rb'SK[0-9a-fA-F]{32}'),
        "light_search": True,
    },
    "Twitter OAuth": {
        "regex": re.compile(rb'[tT]witter.*[\'|"][0-9a-zA-Z]{35,44}[\'|"]'),
        "light_search": True,
    },
    "Dev/Stage URL": {
        "regex": re.compile(rb'(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)'),
        "light_search": True,
    },
    "Internal Subdomain": {
        "regex": re.compile(rb'https?://[a-z0-9.-]+\.internal\.[a-z]{2,}'),
        "light_search": True,
    },
    "Preprod URL": {
        "regex": re.compile(rb'https://preprod\.[a-z0-9-]+\.[a-z]{2,}'),
        "light_search": True,
    },
    "DigitalOcean Token": {
        "regex": re.compile(rb'dop_v1_[a-z0-9]{64}'),
        "light_search": True,
    },
    "HubSpot API Key": {
        "regex": re.compile(rb'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'),
        "light_search": True,
    },
    "WakaTime API Key": {
        "regex": re.compile(rb'waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        "light_search": True,
    },
    "Hashicorp Vault URL": {
        "regex": re.compile(rb'https://vault\.[a-z0-9\-_\.]+\.com'),
        "light_search": True,
    },
    "Secret in Variable": {
        "regex": re.compile(rb'(secret|token)[\'"\s:=]+[a-zA-Z0-9\-_.]{8,100}', re.IGNORECASE),
        "light_search": False,
    },
}


# ─── Core scan ────────────────────────────────────────────────────────────────

def _match_patterns(name: str, entry: dict | list, chunk: bytes,
                    filepath: str, light: bool) -> list[dict]:
    patterns = entry if isinstance(entry, list) else [entry]
    found = []
    for p in patterns:
        if light and not p["light_search"]:
            continue
        try:
            for m in p["regex"].finditer(chunk):
                try:
                    text = m.group().decode("utf-8")
                except UnicodeDecodeError:
                    text = m.group().hex()
                found.append({"pattern": name, "match": text, "file": filepath})
        except Exception:
            pass
    return found


def _scan_file(args: tuple) -> list[dict]:
    filepath, light = args
    results = []
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                for name, entry in SECRETS_REGEX.items():
                    results.extend(_match_patterns(name, entry, chunk, filepath, light))
    except (OSError, IOError):
        pass
    return results


def _gather_files(target: str) -> list[str]:
    p = Path(target)
    if p.is_dir():
        return [str(f) for f in p.rglob("*") if f.is_file()]
    return [str(p)] if p.is_file() else []


# ─── Output ───────────────────────────────────────────────────────────────────

def _severity(pattern: str) -> str:
    """Classifica severidade pelo nome do padrão."""
    high = {"RSA Private Key", "PGP Private Key", "SSH DSA Private Key", "SSH EC Private Key",
            "PEM Certificate", "Google API Key", "OpenAI API Key", "OpenAI Project Key",
            "Stripe Secret Key", "Stripe Test Key", "Stripe Webhook Secret",
            "Amazon AWS Access Key ID", "GitHub Personal Access Token",
            "GitHub OAuth Token", "GitLab Personal Access Token",
            "SendGrid API Key", "Twilio API Key", "Firebase API Key",
            "Google Service Account", "Password in URL", "Basic Auth Credentials",
            "MongoDB URI", "MySQL URI", "PostgreSQL URI", "JDBC URL"}
    medium = {"Generic API Key", "Generic Secret", "OAuth Client Secret",
              "Authorization Bearer Token", "JSON Web Token (JWT)",
              "Slack API Token", "Slack Webhook", "Discord Bot Token",
              "Telegram Bot Token", "Firebase URL", "Sentry DSN",
              "Google OAuth Access Token", "GitHub Token", "Heroku API Key",
              "MailChimp API Key", "Mailgun API Key", "HubSpot API Key",
              "Azure Client Secret", "Google Cloud OAuth"}
    if pattern in high:
        return "HIGH"
    if pattern in medium:
        return "MEDIUM"
    return "LOW"


def _save_html(matches: list[dict], out: Path, target: str, mode: str, ts: str):
    import json as _json
    by_pattern: dict[str, list[dict]] = defaultdict(list)
    for m in matches:
        by_pattern[m["pattern"]].append(m)

    total  = len(matches)
    n_pats = len(by_pattern)
    n_high = sum(1 for m in matches if _severity(m["pattern"]) == "HIGH")
    n_med  = sum(1 for m in matches if _severity(m["pattern"]) == "MEDIUM")
    n_low  = sum(1 for m in matches if _severity(m["pattern"]) == "LOW")

    # ── Coleta conteúdo dos arquivos únicos (até 100 KB cada) ─────────────────
    MAX_FILE_BYTES = 100 * 1024  # 100 KB por arquivo
    unique_files: list[str] = list({m["file"] for m in matches})
    file_contents: dict[str, str] = {}
    for fp in unique_files:
        try:
            raw = Path(fp).read_bytes()[:MAX_FILE_BYTES]
            text = raw.decode("utf-8", errors="replace")
            if len(raw) == MAX_FILE_BYTES:
                text += "\n\n[... arquivo truncado em 100 KB ...]"
        except Exception:
            text = "(não foi possível ler o arquivo)"
        file_contents[fp] = text
    # Serializa como JSON seguro — json.dumps escapa tudo corretamente
    file_contents_js = _json.dumps(file_contents, ensure_ascii=False)

    # ── Gera linhas da tabela ──────────────────────────────────────────────────
    rows_html = ""
    for pattern, hits in sorted(by_pattern.items()):
        sev = _severity(pattern)
        sev_cls = {"HIGH": "sev-high", "MEDIUM": "sev-med", "LOW": "sev-low"}[sev]
        seen: set[str] = set()
        for h in hits:
            match_key = h["match"][:200]
            if match_key in seen:
                continue
            seen.add(match_key)
            rel_file = h["file"].replace(target, "…")
            fp_escaped = _html_mod.escape(h["file"])
            rows_html += f"""
        <tr data-sev="{sev}" data-pat="{_html_mod.escape(pattern)}" data-file="{fp_escaped}">
          <td><span class="badge {sev_cls}">{sev}</span></td>
          <td class="pat-name">{_html_mod.escape(pattern)}</td>
          <td class="match-val"><code>{_html_mod.escape(h['match'][:300])}</code></td>
          <td class="file-cell">
            <span class="file-path" title="{fp_escaped}">{_html_mod.escape(rel_file)}</span>
            <button class="btn-view" onclick="openViewer(this)" data-fp="{fp_escaped}" data-match="{_html_mod.escape(h['match'][:200])}">Ver arquivo</button>
          </td>
        </tr>"""

    # ── Opções do filtro de padrão ─────────────────────────────────────────────
    pat_options = "\n".join(
        f'<option value="{_html_mod.escape(p)}">{_html_mod.escape(p)}</option>'
        for p in sorted(by_pattern)
    )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NoxDroid — Secrets Finder</title>
<style>
  :root {{
    --bg:      #0d0f14;
    --surface: #13161e;
    --card:    #1a1e2a;
    --border:  #252a38;
    --cyan:    #00e5ff;
    --cyan2:   #00b8d4;
    --yellow:  #ffd740;
    --red:     #ff5252;
    --orange:  #ff9800;
    --green:   #69ff47;
    --dim:     #5a6070;
    --text:    #cdd6f4;
    --text2:   #8892a4;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }}

  /* ── Header ── */
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 18px 32px; display: flex; align-items: center; gap: 20px; }}
  .logo {{ font-size: 22px; font-weight: 700; color: var(--cyan); letter-spacing: 2px; }}
  .logo span {{ color: var(--text2); font-weight: 400; font-size: 13px; margin-left: 8px; }}
  .subtitle {{ color: var(--text2); font-size: 12px; margin-top: 2px; }}

  /* ── Stats ── */
  .stats {{ display: flex; gap: 14px; padding: 20px 32px; flex-wrap: wrap; }}
  .stat-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px 22px; min-width: 130px; cursor: pointer; transition: border-color .15s, transform .1s;
    user-select: none;
  }}
  .stat-card:hover {{ border-color: var(--cyan); transform: translateY(-2px); }}
  .stat-card.active {{ border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan2)44; }}
  .stat-card .val {{ font-size: 28px; font-weight: 700; }}
  .stat-card .lbl {{ font-size: 11px; color: var(--text2); margin-top: 2px; text-transform: uppercase; letter-spacing: 1px; }}
  .stat-card.total .val {{ color: var(--cyan); }}
  .stat-card.high  .val {{ color: var(--red); }}
  .stat-card.med   .val {{ color: var(--orange); }}
  .stat-card.low   .val {{ color: var(--yellow); }}
  .stat-card.pats  .val {{ color: var(--green); }}

  /* ── Toolbar ── */
  .toolbar {{ padding: 0 32px 16px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
  .toolbar input, .toolbar select {{
    background: var(--card); border: 1px solid var(--border); color: var(--text);
    border-radius: 7px; padding: 8px 14px; font-size: 13px; outline: none;
  }}
  .toolbar input {{ width: 280px; }}
  .toolbar input:focus, .toolbar select:focus {{ border-color: var(--cyan); }}
  .toolbar select {{ cursor: pointer; }}
  .btn-action {{
    border: none; border-radius: 7px; padding: 8px 18px;
    font-size: 13px; font-weight: 600; cursor: pointer; transition: opacity .15s;
  }}
  .btn-primary {{ background: var(--cyan); color: #000; }}
  .btn-secondary {{ background: var(--card); color: var(--text2); border: 1px solid var(--border); }}
  .btn-action:hover {{ opacity: .85; }}
  .count-badge {{ color: var(--text2); font-size: 12px; margin-left: 4px; }}

  /* ── Table ── */
  .table-wrap {{ padding: 0 32px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    background: var(--surface); color: var(--text2); font-size: 11px;
    text-transform: uppercase; letter-spacing: 1px; padding: 10px 14px;
    border-bottom: 1px solid var(--border); text-align: left; position: sticky; top: 0; z-index: 1;
  }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background .1s; }}
  tbody tr:hover {{ background: var(--card); }}
  tbody td {{ padding: 10px 14px; vertical-align: top; }}

  .badge {{ display: inline-block; border-radius: 5px; padding: 2px 8px; font-size: 11px; font-weight: 700; letter-spacing: .5px; }}
  .sev-high {{ background: #ff525222; color: var(--red); border: 1px solid #ff525244; }}
  .sev-med  {{ background: #ff980022; color: var(--orange); border: 1px solid #ff980044; }}
  .sev-low  {{ background: #ffd74022; color: var(--yellow); border: 1px solid #ffd74044; }}

  .pat-name {{ color: var(--cyan2); font-weight: 500; white-space: nowrap; }}
  .match-val code {{
    background: #0a0c12; border: 1px solid var(--border); border-radius: 5px;
    padding: 3px 8px; font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 12px; color: var(--green); word-break: break-all; display: block; max-width: 520px;
  }}
  .file-cell {{ display: flex; flex-direction: column; gap: 6px; max-width: 340px; }}
  .file-path {{ color: var(--text2); font-size: 12px; font-family: monospace; word-break: break-all; }}
  .btn-view {{
    align-self: flex-start; background: transparent; border: 1px solid var(--border);
    color: var(--cyan2); border-radius: 5px; padding: 3px 10px; font-size: 11px;
    cursor: pointer; transition: background .15s, border-color .15s;
  }}
  .btn-view:hover {{ background: var(--card); border-color: var(--cyan); color: var(--cyan); }}

  /* ── Empty ── */
  .empty {{ text-align: center; padding: 60px; color: var(--dim); font-size: 15px; }}

  /* ── Footer ── */
  footer {{ text-align: center; padding: 20px; color: var(--dim); font-size: 11px; border-top: 1px solid var(--border); }}

  /* ── Modal ── */
  .modal-overlay {{
    display: none; position: fixed; inset: 0; background: #000000cc;
    z-index: 1000; align-items: center; justify-content: center;
  }}
  .modal-overlay.open {{ display: flex; }}
  .modal {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    width: 90vw; max-width: 1100px; height: 85vh; display: flex; flex-direction: column;
    overflow: hidden; box-shadow: 0 24px 80px #00000088;
  }}
  .modal-header {{
    padding: 14px 20px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px; flex-shrink: 0;
  }}
  .modal-title {{
    flex: 1; font-family: monospace; font-size: 12px; color: var(--text2);
    word-break: break-all; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }}
  .modal-toolbar {{
    padding: 10px 20px; border-bottom: 1px solid var(--border);
    display: flex; gap: 10px; align-items: center; flex-shrink: 0; flex-wrap: wrap;
  }}
  .modal-toolbar input {{
    background: var(--card); border: 1px solid var(--border); color: var(--text);
    border-radius: 6px; padding: 6px 12px; font-size: 12px; outline: none; width: 260px;
  }}
  .modal-toolbar input:focus {{ border-color: var(--cyan); }}
  .nav-btn {{
    background: var(--card); border: 1px solid var(--border); color: var(--text2);
    border-radius: 6px; padding: 5px 12px; font-size: 12px; cursor: pointer;
    transition: border-color .15s;
  }}
  .nav-btn:hover {{ border-color: var(--cyan); color: var(--cyan); }}
  .match-counter {{ color: var(--text2); font-size: 12px; white-space: nowrap; }}
  .modal-body {{
    flex: 1; overflow-y: auto; padding: 0;
    font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px;
  }}
  .file-line {{
    display: flex; min-height: 20px; padding: 1px 0;
  }}
  .file-line:hover {{ background: #ffffff08; }}
  .line-num {{
    min-width: 52px; padding: 0 12px; color: var(--dim); text-align: right;
    user-select: none; flex-shrink: 0; border-right: 1px solid var(--border);
  }}
  .line-content {{ padding: 0 16px; white-space: pre-wrap; word-break: break-all; flex: 1; color: var(--text); }}
  .line-highlight {{ background: #ffd74018; }}
  .line-match-highlight {{ background: #00e5ff18; }}
  mark.search-mark {{ background: #ffd74066; color: inherit; border-radius: 2px; }}
  mark.match-mark {{ background: #ff525244; color: inherit; border-radius: 2px; }}
  .btn-close {{
    background: transparent; border: 1px solid var(--border); color: var(--text2);
    border-radius: 6px; padding: 5px 12px; font-size: 13px; cursor: pointer;
    transition: border-color .15s;
  }}
  .btn-close:hover {{ border-color: var(--red); color: var(--red); }}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">NoxDroid <span>Secrets Finder</span></div>
    <div class="subtitle">
      Alvo: {_html_mod.escape(target)} &nbsp;·&nbsp;
      Modo: {_html_mod.escape(mode)} &nbsp;·&nbsp;
      {_html_mod.escape(ts)}
    </div>
  </div>
</header>

<div class="stats">
  <div class="stat-card total" onclick="clearFilters()" title="Limpar filtros">
    <div class="val">{total}</div><div class="lbl">Total</div>
  </div>
  <div class="stat-card high" onclick="filterBySev('HIGH')" title="Filtrar HIGH">
    <div class="val">{n_high}</div><div class="lbl">High</div>
  </div>
  <div class="stat-card med" onclick="filterBySev('MEDIUM')" title="Filtrar MEDIUM">
    <div class="val">{n_med}</div><div class="lbl">Medium</div>
  </div>
  <div class="stat-card low" onclick="filterBySev('LOW')" title="Filtrar LOW">
    <div class="val">{n_low}</div><div class="lbl">Low</div>
  </div>
  <div class="stat-card pats" onclick="clearFilters()" title="Limpar filtros">
    <div class="val">{n_pats}</div><div class="lbl">Padrões</div>
  </div>
</div>

<div class="toolbar">
  <input type="text" id="search" placeholder="🔍  Filtrar por padrão, match ou arquivo..." oninput="applyFilters()">
  <select id="sev-filter" onchange="applyFilters()">
    <option value="">Severidade</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
  </select>
  <select id="pat-filter" onchange="applyFilters()">
    <option value="">Padrão</option>
    {pat_options}
  </select>
  <button class="btn-action btn-secondary" onclick="clearFilters()">✕ Limpar filtros</button>
  <button class="btn-action btn-primary" onclick="copyVisible()">Copiar visíveis</button>
  <span class="count-badge" id="count-badge">{total} resultados</span>
</div>

<div class="table-wrap">
  <table id="results-table">
    <thead>
      <tr>
        <th style="width:80px">Sev.</th>
        <th style="width:220px">Padrão</th>
        <th>Match</th>
        <th>Arquivo</th>
      </tr>
    </thead>
    <tbody id="tbody">
      {rows_html if rows_html else '<tr><td colspan="4" class="empty">Nenhum segredo encontrado.</td></tr>'}
    </tbody>
  </table>
</div>

<footer>NoxDroid · Secrets Finder · {_html_mod.escape(ts)}</footer>

<!-- ── Modal viewer ── -->
<script id="file-data" type="application/json">{file_contents_js}</script>
<div class="modal-overlay" id="modal-overlay" onclick="overlayClick(event)">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title" id="modal-title"></span>
      <button class="btn-action btn-secondary btn-close" onclick="closeModal()">✕ Fechar</button>
      <button class="btn-action btn-primary" onclick="copyFileContent()" id="btn-copy-file">Copiar arquivo</button>
    </div>
    <div class="modal-toolbar">
      <input type="text" id="file-search" placeholder="🔍  Buscar no arquivo..." oninput="searchInFile()">
      <button class="nav-btn" onclick="navMatch(-1)">▲ Anterior</button>
      <button class="nav-btn" onclick="navMatch(1)">▼ Próximo</button>
      <span class="match-counter" id="match-counter"></span>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<script>
const FILE_CONTENTS = JSON.parse(document.getElementById('file-data').textContent);

let _currentFile = '';
let _currentMatch = '';
let _searchMatches = [];
let _searchIdx = 0;

function applyFilters() {{
  const q   = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sev-filter').value;
  const pat = document.getElementById('pat-filter').value;
  const rows = document.querySelectorAll('#tbody tr[data-sev]');
  let visible = 0;
  rows.forEach(r => {{
    const text = r.textContent.toLowerCase();
    const ok = (!q || text.includes(q))
            && (!sev || r.dataset.sev === sev)
            && (!pat || r.dataset.pat === pat);
    r.style.display = ok ? '' : 'none';
    if (ok) visible++;
  }});
  document.getElementById('count-badge').textContent = visible + ' resultado' + (visible !== 1 ? 's' : '');
}}

function filterBySev(sev) {{
  document.getElementById('sev-filter').value = sev;
  document.getElementById('search').value = '';
  document.getElementById('pat-filter').value = '';
  document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
  const map = {{'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}};
  document.querySelectorAll('.stat-card')[map[sev]].classList.add('active');
  applyFilters();
}}

function clearFilters() {{
  document.getElementById('search').value = '';
  document.getElementById('sev-filter').value = '';
  document.getElementById('pat-filter').value = '';
  document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('active'));
  applyFilters();
}}

function copyVisible() {{
  const rows = document.querySelectorAll('#tbody tr[data-sev]');
  const lines = [];
  rows.forEach(r => {{
    if (r.style.display !== 'none') {{
      const cells = r.querySelectorAll('td');
      lines.push([cells[0].textContent.trim(), cells[1].textContent.trim(),
                  cells[2].textContent.trim(), cells[3].textContent.trim()].join('\\t'));
    }}
  }});
  navigator.clipboard.writeText(lines.join('\\n')).then(() => {{
    const btn = document.querySelector('.btn-primary');
    const orig = btn.textContent;
    btn.textContent = '✔ Copiado!';
    setTimeout(() => btn.textContent = orig, 1500);
  }});
}}

function openViewer(btn) {{
  const fp    = btn.dataset.fp;
  const match = btn.dataset.match || '';
  _currentFile  = fp;
  _currentMatch = match;
  _searchMatches = [];
  _searchIdx = 0;

  document.getElementById('modal-title').textContent = fp;
  document.getElementById('file-search').value = '';
  document.getElementById('match-counter').textContent = '';

  const content = FILE_CONTENTS[fp] || '(conteúdo não disponível)';
  renderFile(content, match, '');
  document.getElementById('modal-overlay').classList.add('open');
}}

function renderFile(content, matchStr, searchStr) {{
  const body = document.getElementById('modal-body');
  const lines = content.split('\\n');
  _searchMatches = [];

  let html = '';
  lines.forEach((line, i) => {{
    const lineNum = i + 1;
    const hasMatch  = matchStr && line.includes(matchStr);
    const hasSearch = searchStr && line.toLowerCase().includes(searchStr.toLowerCase());
    let cls = 'file-line';
    if (hasMatch)  cls += ' line-match-highlight';
    if (hasSearch) cls += ' line-highlight';

    let escaped = escHtml(line);
    if (matchStr) {{
      escaped = escaped.split(escHtml(matchStr)).join('<mark class="match-mark">' + escHtml(matchStr) + '</mark>');
    }}
    if (searchStr) {{
      const re = new RegExp(escRegex(searchStr), 'gi');
      escaped = escaped.replace(re, m => '<mark class="search-mark">' + m + '</mark>');
      if (hasSearch) _searchMatches.push(lineNum);
    }}

    html += `<div class="file-line ${{hasMatch ? 'line-match-highlight' : ''}} ${{hasSearch ? 'line-highlight' : ''}}" id="L${{lineNum}}">` +
            `<span class="line-num">${{lineNum}}</span>` +
            `<span class="line-content">${{escaped}}</span></div>`;
  }});

  body.innerHTML = html || '<div style="padding:20px;color:var(--dim)">Arquivo vazio.</div>';

  // Scroll para primeira ocorrência do match
  if (matchStr) {{
    const firstMatch = lines.findIndex(l => l.includes(matchStr));
    if (firstMatch >= 0) {{
      setTimeout(() => {{
        const el = document.getElementById('L' + (firstMatch + 1));
        if (el) el.scrollIntoView({{ block: 'center' }});
      }}, 50);
    }}
  }}
}}

function searchInFile() {{
  const q = document.getElementById('file-search').value;
  const content = FILE_CONTENTS[_currentFile] || '';
  renderFile(content, _currentMatch, q);
  _searchIdx = 0;
  updateMatchCounter();
  if (_searchMatches.length > 0) scrollToMatch(0);
}}

function navMatch(dir) {{
  if (_searchMatches.length === 0) return;
  _searchIdx = (_searchIdx + dir + _searchMatches.length) % _searchMatches.length;
  scrollToMatch(_searchIdx);
  updateMatchCounter();
}}

function scrollToMatch(idx) {{
  const lineNum = _searchMatches[idx];
  const el = document.getElementById('L' + lineNum);
  if (el) el.scrollIntoView({{ block: 'center' }});
}}

function updateMatchCounter() {{
  const el = document.getElementById('match-counter');
  if (_searchMatches.length === 0) {{
    el.textContent = document.getElementById('file-search').value ? '0 resultados' : '';
  }} else {{
    el.textContent = (_searchIdx + 1) + ' / ' + _searchMatches.length;
  }}
}}

function closeModal() {{
  document.getElementById('modal-overlay').classList.remove('open');
}}

function overlayClick(e) {{
  if (e.target === document.getElementById('modal-overlay')) closeModal();
}}

function copyFileContent() {{
  const content = FILE_CONTENTS[_currentFile] || '';
  navigator.clipboard.writeText(content).then(() => {{
    const btn = document.getElementById('btn-copy-file');
    btn.textContent = '✔ Copiado!';
    setTimeout(() => btn.textContent = 'Copiar arquivo', 1500);
  }});
}}

function escHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
function escRegex(s) {{
  return s.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&');
}}

document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') closeModal();
  if (document.getElementById('modal-overlay').classList.contains('open')) {{
    if (e.key === 'F3' || (e.ctrlKey && e.key === 'g')) {{ e.preventDefault(); navMatch(1); }}
    if (e.shiftKey && e.key === 'F3') {{ e.preventDefault(); navMatch(-1); }}
  }}
}});
</script>
</body>
</html>"""

    out.write_text(html, encoding="utf-8")




def _print_results(matches: list[dict], root: str):
    if not matches:
        print(f"\n  {_DIM}Nenhum segredo encontrado.{_RESET}")
        return

    by_pattern: dict[str, list[dict]] = defaultdict(list)
    for m in matches:
        by_pattern[m["pattern"]].append(m)

    total = len(matches)
    print(f"\n  {_YELLOW}→ {total} ocorrência(s) em {len(by_pattern)} padrão(ões){_RESET}\n")

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for pattern, hits in sorted(by_pattern.items(), key=lambda x: sev_order[_severity(x[0])]):
        sev = _severity(pattern)
        sev_color = {
            "HIGH":   _RED,
            "MEDIUM": _YELLOW,
            "LOW":    _DIM,
        }[sev]
        print(f"  {sev_color}[{sev}]{_RESET} {_CYAN}{pattern}{_RESET}  {_DIM}({len(hits)} hits){_RESET}")
        seen: set[str] = set()
        for h in hits[:5]:
            rel = h["file"].replace(root, "…")
            key = h["match"][:60]
            if key in seen:
                continue
            seen.add(key)
            print(f"    {_DIM}{rel}{_RESET}")
            print(f"      {_WHITE}{h['match'][:120]}{_RESET}")
        if len(hits) > 5:
            print(f"    {_DIM}... +{len(hits)-5} mais (ver HTML){_RESET}")
        print()


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def secrets_finder_menu(target_path: str | None = None):
    """
    Menu interativo do Secrets Finder.
    target_path: pasta já descompilada ou None para pedir ao usuário.
    """
    print(f"\n{_CYAN}{'─' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  Secrets Finder{_RESET}")
    print(f"{_DIM}{'─' * 70}{_RESET}\n")

    # Resolve o caminho alvo
    if target_path:
        path = target_path
    else:
        print(f"  {_WHITE}Caminho da pasta/arquivo a varrer:{_RESET}")
        path = input("  → ").strip().strip('"')

    if not os.path.exists(path):
        print(f"  {_RED}✖ Caminho não encontrado: {path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    print(f"\n  {_WHITE}Modo de busca:{_RESET}")
    print(f"  {_CYAN}1.{_RESET} Rápido  {_DIM}(light — menos falsos positivos, mais rápido){_RESET}")
    print(f"  {_CYAN}2.{_RESET} Completo  {_DIM}(todos os padrões — pode gerar mais ruído){_RESET}")
    print(f"\n  {_DIM}0. Cancelar{_RESET}")
    mode = input(f"\n  → Escolha: ").strip()

    if mode == "0" or not mode:
        return

    light = (mode != "2")
    files = _gather_files(path)
    if not files:
        print(f"  {_RED}✖ Nenhum arquivo encontrado em: {path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    workers = min(os.cpu_count() or 2, len(files), 8)
    label   = "rápido" if light else "completo"
    print(f"\n  {_CYAN}→ Varrendo {len(files)} arquivo(s) [{label}] com {workers} workers...{_RESET}\n")

    all_matches: list[dict] = []
    args = [(f, light) for f in files]

    try:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for i, result in enumerate(ex.map(_scan_file, args), 1):
                all_matches.extend(result)
                sys.stdout.write(f"\r  {_DIM}{i}/{len(files)} arquivos processados...{_RESET}  ")
                sys.stdout.flush()
    except Exception as e:
        print(f"\n  {_RED}✖ Erro durante scan: {e}{_RESET}")

    print(f"\r  {_GREEN}✔ Scan concluído — {len(files)} arquivos{_RESET}                    ")

    _print_results(all_matches, path)

    # Salva HTML — tenta extrair pkg do caminho (results/<pkg>/...)
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "light" if light else "full"

    # Detecta pkg a partir do caminho (ex: results/com.pkg/decompiled/...)
    p_parts = Path(path).parts
    pkg_name = None
    for i, part in enumerate(p_parts):
        if part == "results" and i + 1 < len(p_parts):
            pkg_name = p_parts[i + 1]
            break

    if pkg_name:
        from core.report_paths import static_dir
        out_dir = static_dir(pkg_name)
    else:
        from core.report_paths import RESULTS_ROOT, _ts
        out_dir = RESULTS_ROOT / "secrets_finder" / _ts()
        out_dir.mkdir(parents=True, exist_ok=True)
    out_html = out_dir / f"secrets_{suffix}.html"

    if all_matches:
        _save_html(all_matches, out_html, path, label, ts)
        print(f"  {_GREEN}✔ Relatório HTML salvo em: {out_html}{_RESET}")
        open_now = input(f"\n  Abrir no navegador? [S/n]: ").strip().lower()
        if open_now != "n":
            webbrowser.open(out_html.resolve().as_uri())
    else:
        print(f"  {_DIM}Nenhum resultado para salvar.{_RESET}")

    input(f"\n  → Enter para continuar...")
