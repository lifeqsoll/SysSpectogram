from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from sysspectogram.perimeter.auth import is_public_ip


@dataclass
class ConnRow:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: str


_STATE = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "0A": "LISTEN",
    "06": "TIME_WAIT",
}


def _parse_ipv4(ip_hex: str) -> str:
    b = bytes.fromhex(ip_hex)
    return ".".join(str(x) for x in b[::-1])


def _parse_ipv6(ip_hex: str) -> str:
    # /proc/net/tcp6: 32 hex chars, little-endian 32-bit words
    raw = bytes.fromhex(ip_hex)
    if len(raw) != 16:
        return ip_hex
    words = []
    for i in range(0, 16, 4):
        words.append(struct.unpack("<I", raw[i : i + 4])[0])
    packed = b"".join(struct.pack(">I", w) for w in words)
    try:
        return str(ipaddress.IPv6Address(packed))
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, packed)
        except OSError:
            return ip_hex


def _parse_addr(hex_addr: str, ipv6: bool = False) -> tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    if ipv6:
        return _parse_ipv6(ip_hex), port
    return _parse_ipv4(ip_hex), port


def _parse_proc(path: str, ipv6: bool = False) -> list[ConnRow]:
    p = Path(path)
    if not p.exists():
        return []
    rows: list[ConnRow] = []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return []
    for line in lines:
        cols = line.split()
        if len(cols) < 10:
            continue
        lip, lport = _parse_addr(cols[1], ipv6=ipv6)
        rip, rport = _parse_addr(cols[2], ipv6=ipv6)
        state = _STATE.get(cols[3], cols[3])
        rows.append(ConnRow(lip, lport, rip, rport, state, cols[9]))
    return rows


def snapshot_connections() -> list[ConnRow]:
    return _parse_proc("/proc/net/tcp") + _parse_proc("/proc/net/tcp6", ipv6=True)


def listening_ports(rows: list[ConnRow] | None = None) -> set[int]:
    rows = rows if rows is not None else snapshot_connections()
    return {r.local_port for r in rows if r.state == "LISTEN"}


def inbound_external(rows: list[ConnRow] | None = None) -> list[ConnRow]:
    rows = rows if rows is not None else snapshot_connections()
    listens = listening_ports(rows)
    out: list[ConnRow] = []
    for r in rows:
        if r.state not in {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}:
            continue
        if r.local_port not in listens:
            continue
        if is_public_ip(r.remote_ip):
            out.append(r)
    return out


def egress_external(rows: list[ConnRow] | None = None) -> list[ConnRow]:
    rows = rows if rows is not None else snapshot_connections()
    listens = listening_ports(rows)
    out: list[ConnRow] = []
    for r in rows:
        if r.state not in {"ESTABLISHED", "SYN_SENT"}:
            continue
        if r.local_port in listens:
            continue
        if is_public_ip(r.remote_ip):
            out.append(r)
    return out
