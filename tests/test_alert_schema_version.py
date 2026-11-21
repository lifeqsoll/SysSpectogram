from sysspectogram.perimeter.rules import ALERT_SCHEMA_VERSION, Alert


def test_alert_to_dict_has_schema_version():
    a = Alert(rule_id="bruteforce_ssh", severity="critical", message="x", ip="203.0.113.9")
    d = a.to_dict()
    assert d["schema_version"] == ALERT_SCHEMA_VERSION
    assert d["rule_id"] == "bruteforce_ssh"
    assert d["ip"] == "203.0.113.9"
