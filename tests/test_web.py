from __future__ import annotations

import hashlib
import hmac
import json
import time

from sysspectogram.web.actions import WebControllers
from sysspectogram.web.auth import validate_webapp_init_data
from sysspectogram.web.bus import LiveAlert, LiveBus
from sysspectogram.response.actions import NftBackend


def test_web_action_dry_ban():
    bus = LiveBus()
    nft = NftBackend()
    ctl = WebControllers(bus=bus, nft=nft, watcher=None, dry_run=True)
    out = ctl.run("ban", {"ip": "203.0.113.9", "ttl": 60})
    assert out["ok"] is True
    assert "dry-run" in str(out["result"]).lower() or "ban" in str(out["result"]).lower()
    assert bus.alerts[0].kind == "action"


def test_live_bus_snapshot():
    bus = LiveBus(window=5)
    bus.set_host("h1", 0.7, True)
    bus.push_sample(cpu=10, mem=20, net=30, score=0.2)
    bus.push_alert(LiveAlert(ts=time.time(), severity="high", title="t", body="b"))
    snap = bus.snapshot()
    assert snap["host_id"] == "h1"
    assert snap["cpu"][-1] == 10
    assert snap["alerts"][0]["title"] == "t"


def test_validate_webapp_init_data_roundtrip():
    bot_token = "123456:ABC-DEF"
    user = json.dumps({"id": 42, "first_name": "T"}, separators=(",", ":"))
    auth_date = str(int(time.time()))
    pairs = {"auth_date": auth_date, "user": user}
    data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    init_data = f"auth_date={auth_date}&user={user}&hash={digest}"
    # parse_qsl will decode; user needs URL encoding for special chars — use quote
    from urllib.parse import quote

    init_data = f"auth_date={auth_date}&user={quote(user)}&hash={digest}"
    parsed = validate_webapp_init_data(init_data, bot_token)
    assert parsed is not None
    assert parsed["user"]["id"] == 42
    assert validate_webapp_init_data(init_data, "wrong") is None
