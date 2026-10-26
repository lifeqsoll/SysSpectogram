"""M3: Host / CSRF / Content-Type on snapshot + unlock; IPv6 Host literals."""

from __future__ import annotations

from http.client import HTTPConnection

from sysspectogram.web.bus import LiveBus
from sysspectogram.web.server import _host_header_name, start_web_server


def test_host_header_ipv6_bracketed():
    assert _host_header_name("[::1]:8765") == "::1"
    assert _host_header_name("[::1]") == "::1"
    assert _host_header_name("127.0.0.1:8765") == "127.0.0.1"
    assert _host_header_name("localhost") == "localhost"
    assert _host_header_name("evil.example") == "evil.example"


def test_snapshot_rejects_foreign_host():
    bus = LiveBus()
    httpd = start_web_server(bus, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.putrequest("GET", "/api/snapshot", skip_host=True)
        conn.putheader("Host", "evil.example")
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 403, body
        conn.close()

        conn2 = HTTPConnection("127.0.0.1", port, timeout=2)
        conn2.putrequest("GET", "/api/snapshot", skip_host=True)
        conn2.putheader("Host", "127.0.0.1")
        conn2.endheaders()
        resp2 = conn2.getresponse()
        assert resp2.status == 200, resp2.read()
        conn2.close()

        # Bracketed IPv6 Host must not 403 (::1 is always allowlisted).
        conn3 = HTTPConnection("127.0.0.1", port, timeout=2)
        conn3.putrequest("GET", "/api/snapshot", skip_host=True)
        conn3.putheader("Host", f"[::1]:{port}")
        conn3.endheaders()
        resp3 = conn3.getresponse()
        assert resp3.status == 200, resp3.read()
        conn3.close()
    finally:
        httpd.shutdown()


def test_unlock_requires_json_content_type():
    bus = LiveBus()
    httpd = start_web_server(bus, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    try:
        body = b'{"code":"ABCDEFGHJK"}'
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.putrequest("POST", "/api/unlock", skip_host=True)
        conn.putheader("Host", "127.0.0.1")
        conn.putheader("Content-Type", "text/plain")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-SS-CSRF", "1")
        conn.endheaders()
        conn.send(body)
        resp = conn.getresponse()
        assert resp.status == 415, resp.read()
        conn.close()
    finally:
        httpd.shutdown()
