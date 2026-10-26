from sysspectogram.fleet.results import FleetHostResult, FleetOpReport, wrap_host_dict
from sysspectogram.fleet.store import FleetHost


def test_wrap_and_report_shape():
    row = wrap_host_dict({"host_id": "a", "ok": True, "latency_ms": 12.3, "extra": 1})
    assert isinstance(row, FleetHostResult)
    d = row.to_dict()
    assert d["host_id"] == "a"
    assert d["ok"] is True
    assert d["latency_ms"] == 12.3
    assert d["detail"]["extra"] == 1

    rep = FleetOpReport(ok=True, scope="all", results=[row], extra={"n": 1}).to_dict()
    assert rep["scope"] == "all"
    assert rep["n"] == 1
    assert len(rep["results"]) == 1


def test_public_dict_masks_token():
    h = FleetHost(id="1", label="1", device_token="supersecret")
    d = h.public_dict()
    assert "device_token" not in d
    assert d["token_set"] is True
    h2 = FleetHost(id="2", label="2")
    assert h2.public_dict()["token_set"] is False
