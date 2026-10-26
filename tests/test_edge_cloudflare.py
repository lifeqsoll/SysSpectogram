from unittest.mock import patch

from sysspectogram.edge.cloudflare import clear_under_attack, edge_status, set_under_attack
from sysspectogram.edge.playbook import playbook_m


def test_playbook_m_langs():
    assert "Playbook M" in playbook_m("en")
    assert "Playbook M" in playbook_m("ru")


def test_status_need_config(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ZONE_ID", raising=False)
    out = edge_status()
    assert out["ok"] is False
    assert out.get("need_config") is True
    assert "playbook" in out


def test_under_attack_mock(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "zone123456")

    def fake_req(method, path, *, token, body=None, timeout=20.0):
        assert method == "PATCH"
        assert "security_level" in path
        assert body == {"value": "under_attack"}
        return {"success": True, "result": {"value": "under_attack"}}

    with patch("sysspectogram.edge.cloudflare._cf_request", side_effect=fake_req):
        out = set_under_attack()
    assert out == {"ok": True, "security_level": "under_attack"}


def test_clear_mock(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "zone123456")

    with patch(
        "sysspectogram.edge.cloudflare._cf_request",
        return_value={"success": True, "result": {"value": "high"}},
    ):
        out = clear_under_attack(level="high")
    assert out["ok"] is True
    assert out["security_level"] == "high"


def test_cf_403(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "tok")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "zone123456")
    with patch(
        "sysspectogram.edge.cloudflare._cf_request",
        return_value={"success": False, "errors": [{"message": "auth"}]},
    ):
        out = set_under_attack()
    assert out["ok"] is False
    assert "auth" in out["error"]
