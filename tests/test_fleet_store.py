from __future__ import annotations

from pathlib import Path

from sysspectogram.fleet.store import FleetHost, FleetStore


def test_fleet_upsert_primary(tmp_path: Path):
    store = FleetStore(tmp_path / "fleet.json")
    store.upsert_host(
        FleetHost(id="a", label="Alpha", ssh="a@h", device_token="tok", role="worker")
    )
    store.upsert_host(FleetHost(id="b", label="Beta", ssh="b@h", role="primary"))
    st = store.load()
    assert st.primary_host_id == "b"
    assert store.load().hosts[0].id in {"a", "b"}
    pub = [h.public_dict() for h in st.hosts]
    assert all("device_token" not in p for p in pub)
    assert any(p.get("token_set") is True for p in pub)
    assert any(p.get("token_set") is False for p in pub)
    store.set_primary("a")
    assert store.load().primary_host_id == "a"
