"""
Network Connections Monitor — lê /proc/net/tcp|tcp6|udp|udp6 do processo do app.
Executado em janela externa.
Uso: python _net_monitor.py <adb_path> <package>

Mostra conexões ativas, IPs remotos, portas, estado TCP, sem precisar de proxy ou root.
Atualiza a cada 2 segundos.
"""
import sys
import subprocess
import time
import struct
import socket
from datetime import datetime

# ─── Cores ────────────────────────────────────────────────────────────────────
R       = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[90m"
WHITE   = "\033[97m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"

# ─── Estados TCP ──────────────────────────────────────────────────────────────
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",   "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2",  "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

STATE_COLOR = {
    "ESTABLISHED": GREEN,
    "LISTEN":      CYAN,
    "TIME_WAIT":   YELLOW,
    "CLOSE_WAIT":  YELLOW,
    "SYN_SENT":    MAGENTA,
    "SYN_RECV":    MAGENTA,
    "FIN_WAIT1":   DIM,
    "FIN_WAIT2":   DIM,
    "CLOSE":       DIM,
    "LAST_ACK":    DIM,
    "CLOSING":     DIM,
}

# Portas conhecidas
WELL_KNOWN = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 110: "POP3",
    143: "IMAP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 1194: "OpenVPN", 1723: "PPTP",
}


def _hex_to_ip4(hex_str: str) -> str:
    """Converte endereço hex little-endian do /proc/net/tcp para IP:porta."""
    addr, port = hex_str.split(":")
    # little-endian byte swap
    ip = socket.inet_ntoa(struct.pack("<I", int(addr, 16)))
    port_num = int(port, 16)
    return ip, port_num


def _hex_to_ip6(hex_str: str) -> str:
    """Converte endereço hex IPv6 do /proc/net/tcp6."""
    addr, port = hex_str.split(":")
    # 4 grupos de 4 bytes little-endian
    raw = bytes.fromhex(addr)
    groups = []
    for i in range(0, 16, 4):
        chunk = raw[i:i+4][::-1]
        groups.append(chunk.hex())
    ip6 = ":".join(groups[i] + groups[i+1] for i in range(0, 8, 2))
    try:
        ip6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex("".join(groups)))
    except Exception:
        pass
    port_num = int(port, 16)
    return ip6, port_num


def _adb_shell(adb: str, cmd: str, timeout: int = 8) -> str:
    try:
        r = subprocess.run([adb, "shell", cmd],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _get_uid(adb: str, pkg: str) -> str | None:
    """Obtém o UID do app via dumpsys package."""
    out = _adb_shell(adb, f"dumpsys package {pkg} | grep userId=")
    for line in out.splitlines():
        line = line.strip()
        if "userId=" in line:
            try:
                uid = line.split("userId=")[1].split()[0].strip()
                return uid
            except Exception:
                pass
    return None


def _get_pid(adb: str, pkg: str) -> str | None:
    try:
        r = subprocess.run([adb, "shell", "pidof", pkg],
                           capture_output=True, text=True, timeout=5)
        pid = r.stdout.strip().split()[0]
        return pid if pid.isdigit() else None
    except Exception:
        return None


def _parse_proc_net(adb: str, proto: str, uid: str) -> list[dict]:
    """
    Lê /proc/net/<proto> e filtra entradas pelo UID do app.
    proto: tcp | tcp6 | udp | udp6
    """
    content = _adb_shell(adb, f"cat /proc/net/{proto} 2>/dev/null")
    if not content:
        return []

    conns = []
    is_v6 = "6" in proto
    is_udp = "udp" in proto

    for line in content.splitlines()[1:]:  # pula header
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            local_hex  = parts[1]
            remote_hex = parts[2]
            state_hex  = parts[3].upper()
            line_uid   = parts[7]

            if line_uid != uid:
                continue

            if is_v6:
                local_ip,  local_port  = _hex_to_ip6(local_hex)
                remote_ip, remote_port = _hex_to_ip6(remote_hex)
            else:
                local_ip,  local_port  = _hex_to_ip4(local_hex)
                remote_ip, remote_port = _hex_to_ip4(remote_hex)

            state = TCP_STATES.get(state_hex, state_hex) if not is_udp else "UDP"

            # Ignora loopback e 0.0.0.0 remoto (apenas LISTEN)
            if remote_ip in ("0.0.0.0", "::") and state == "LISTEN":
                continue

            service = WELL_KNOWN.get(remote_port, WELL_KNOWN.get(local_port, ""))

            conns.append({
                "proto":       proto.upper(),
                "local":       f"{local_ip}:{local_port}",
                "remote":      f"{remote_ip}:{remote_port}",
                "remote_ip":   remote_ip,
                "remote_port": remote_port,
                "state":       state,
                "service":     service,
            })
        except Exception:
            continue

    return conns


def _resolve_hostname(ip: str) -> str:
    """Tenta resolver hostname reverso (com timeout curto)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _render(pkg: str, uid: str, conns: list[dict], stats: dict):
    """Renderiza a tela de conexões."""
    print("\033[2J\033[H", end="")  # clear
    now = datetime.now().strftime("%H:%M:%S")

    print(f"{CYAN}{'═' * 80}{R}")
    print(f"{CYAN}{BOLD}  NoxDroid — Network Connections Monitor{R}")
    print(f"{DIM}  Package : {WHITE}{pkg}{R}  {DIM}UID: {WHITE}{uid}{R}  {DIM}Atualizado: {WHITE}{now}{R}")
    print(f"{CYAN}{'═' * 80}{R}\n")

    if not conns:
        print(f"  {DIM}Nenhuma conexão ativa encontrada para UID {uid}.{R}")
        print(f"  {DIM}(O app pode não estar em execução ou sem atividade de rede){R}")
    else:
        # Cabeçalho
        print(f"  {DIM}{'Proto':<6} {'Estado':<13} {'Remoto':<42} {'Serviço':<10} {'Local'}{R}")
        print(f"  {DIM}{'─'*6} {'─'*13} {'─'*42} {'─'*10} {'─'*22}{R}\n")

        # Agrupa por estado
        established = [c for c in conns if c["state"] == "ESTABLISHED"]
        others      = [c for c in conns if c["state"] != "ESTABLISHED"]

        for c in established + others:
            sc    = STATE_COLOR.get(c["state"], WHITE)
            proto = f"{DIM}{c['proto']:<6}{R}"
            state = f"{sc}{c['state']:<13}{R}"

            remote = c["remote"]
            # Tenta hostname se for IP externo
            if not c["remote_ip"].startswith(("10.", "192.168.", "172.", "127.", "0.")):
                host = _resolve_hostname(c["remote_ip"])
                if host and host != c["remote_ip"]:
                    remote = f"{host}:{c['remote_port']}"

            remote_str = f"{WHITE}{remote:<42}{R}"
            svc_str    = f"{CYAN}{c['service']:<10}{R}" if c["service"] else f"{DIM}{'':10}{R}"
            local_str  = f"{DIM}{c['local']}{R}"

            print(f"  {proto} {state} {remote_str} {svc_str} {local_str}")

        print(f"\n  {DIM}{'─' * 78}{R}")
        print(f"  {GREEN}Estabelecidas: {len(established)}{R}  "
              f"{DIM}Outras: {len(others)}{R}  "
              f"{DIM}Total sessão: {stats['total']}{R}")

    print(f"\n  {DIM}Ctrl+C para parar  |  Atualiza a cada 2s{R}")


def run(adb: str, pkg: str):
    print(f"\033[2J\033[H{CYAN}{BOLD}  Network Connections Monitor{R}\n")
    print(f"  {DIM}→ Obtendo UID de {pkg}...{R}", end="", flush=True)

    uid = _get_uid(adb, pkg)
    if not uid:
        print(f"\r  {RED}✖ Não foi possível obter UID de {pkg}.{R}")
        print(f"  {DIM}  Verifique se o app está instalado.{R}")
        input("\n→ Enter para fechar...")
        return

    print(f"\r  {GREEN}✔ UID: {uid}{R}                    ")

    # Prepara arquivo de log
    from pathlib import Path
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    from core.report_paths import network_dir
    out_dir = network_dir(pkg)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{ts}_connections.txt"
    print(f"  {DIM}Log: {out_file}{R}\n")
    time.sleep(0.5)

    stats    = {"total": 0}
    seen     = set()
    all_seen = []   # histórico completo para salvar

    try:
        while True:
            conns = []
            for proto in ("tcp", "tcp6", "udp", "udp6"):
                conns.extend(_parse_proc_net(adb, proto, uid))

            # Deduplica por (remote, state)
            unique = {}
            for c in conns:
                key = (c["remote"], c["state"], c["proto"])
                unique[key] = c
            conns = list(unique.values())

            # Registra novas conexões no histórico
            for c in conns:
                k = (c["remote"], c["proto"])
                if k not in seen:
                    seen.add(k)
                    stats["total"] += 1
                    all_seen.append({
                        "ts":    datetime.now().strftime("%H:%M:%S"),
                        **c
                    })

            _render(pkg, uid, conns, stats)
            time.sleep(2)

    except KeyboardInterrupt:
        pass

    print(f"\n\n{DIM}  Monitor encerrado. Total de conexões únicas: {stats['total']}{R}\n")

    # Salva histórico
    if all_seen:
        lines = [
            f"Network Connections Monitor — {pkg}",
            f"Timestamp : {ts}",
            f"UID       : {uid}",
            f"Total     : {stats['total']} conexões únicas",
            "─" * 70,
            f"  {'Hora':<10} {'Proto':<6} {'Estado':<13} {'Remoto':<42} {'Serviço':<10} Local",
            "─" * 70,
        ]
        for c in all_seen:
            lines.append(
                f"  {c['ts']:<10} {c['proto']:<6} {c['state']:<13} "
                f"{c['remote']:<42} {c.get('service',''):<10} {c['local']}"
            )
        out_file.write_text("\n".join(lines), encoding="utf-8")
        print(f"  {GREEN}✔ Log salvo em: {out_file}{R}\n")
    else:
        print(f"  {DIM}Nenhuma conexão registrada — arquivo não salvo.{R}\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python _net_monitor.py <adb> <package>")
        sys.exit(1)

    import os
    os.system("")  # habilita ANSI no Windows

    run(sys.argv[1], sys.argv[2])
    input("\n→ Enter para fechar...")
