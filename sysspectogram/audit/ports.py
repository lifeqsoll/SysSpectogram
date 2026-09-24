from __future__ import annotations

from pathlib import Path

import psutil


def _parse_proc_net(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return []
    for line in lines:
        cols = line.split()
        if len(cols) < 10:
            continue
        local = cols[1]
        state = cols[3]
        inode = cols[9]
        ip_hex, port_hex = local.split(":")
        port = int(port_hex, 16)
        # little-endian IPv4 in /proc/net/tcp
        if len(ip_hex) == 8:
            b = bytes.fromhex(ip_hex)
            ip = ".".join(str(x) for x in b[::-1])
        else:
            ip = ip_hex
        state_map = {"01": "ESTABLISHED", "0A": "LISTEN", "06": "TIME_WAIT"}
        rows.append(
            {
                "ip": ip,
                "port": port,
                "state": state_map.get(state, state),
                "inode": inode,
            }
        )
    return rows


def list_listening_and_established(limit: int = 200) -> dict:
    entries = _parse_proc_net("/proc/net/tcp") + _parse_proc_net("/proc/net/tcp6")
    listen = [e for e in entries if e["state"] == "LISTEN"][:limit]
    established = [e for e in entries if e["state"] == "ESTABLISHED"][:limit]

    # Enrich with process names when possible (may need elevated privileges)
    inode_to_proc: dict[str, dict] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = None
                key = f"{c.laddr.ip}:{c.laddr.port}:{c.status}"
                inode_to_proc[key] = {"pid": c.pid, "name": name}
    except (psutil.AccessDenied, PermissionError):
        pass

    def enrich(items: list[dict]) -> list[dict]:
        out = []
        for e in items:
            key = f"{e['ip']}:{e['port']}:{e['state']}"
            extra = inode_to_proc.get(key, {})
            out.append({**e, **extra})
        return out

    return {
        "listen": enrich(listen),
        "established": enrich(established),
        "listen_count": len(listen),
        "established_count": len(established),
    }
