"""SSRF-safe HTTP(S) POST: resolve once, refuse private, connect to pinned IP."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse


def _blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def resolve_public_host(host: str, *, allow_private: bool = False) -> str:
    """Return one resolved IP for host; raise if blocked/unresolvable."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(".local") or h.endswith(".localhost"):
        if allow_private and h in {"localhost"}:
            return "127.0.0.1"
        raise RuntimeError(f"host blocked: {host!r}")
    try:
        if _blocked_ip(h):
            if allow_private:
                return h
            raise RuntimeError(f"literal private IP blocked: {h}")
        return h
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"cannot resolve {h}: {exc}") from exc
    if not infos:
        raise RuntimeError(f"cannot resolve {h}")
    for info in infos:
        addr = str(info[4][0])
        try:
            if _blocked_ip(addr):
                if allow_private:
                    return addr
                continue
            return addr
        except ValueError:
            continue
    raise RuntimeError(f"all resolved addresses for {h} are private/blocked")


def http_request_pinned(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    method: str = "POST",
    timeout: float = 8.0,
    allow_private: bool = False,
) -> tuple[int, bytes]:
    """HTTP(S) request via pinned IP; TLS verifies cert for original hostname (SNI)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"unsupported scheme: {parsed.scheme}")
    host = parsed.hostname or ""
    if not host:
        raise RuntimeError("url missing host")
    ip = resolve_public_host(host, allow_private=allow_private)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    hdrs.setdefault("Host", host if parsed.port is None else f"{host}:{parsed.port}")

    conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, port), timeout=timeout)
        conn.sock = ctx.wrap_socket(raw, server_hostname=host)

    try:
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read(65536)
        return int(resp.status), body
    finally:
        conn.close()


def post_json_pinned(
    url: str,
    data: bytes,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = 8.0,
    allow_private: bool = False,
) -> tuple[int, bytes]:
    return http_request_pinned(
        url,
        data=data,
        headers=headers,
        method="POST",
        timeout=timeout,
        allow_private=allow_private,
    )
