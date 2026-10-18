from __future__ import annotations

from pathlib import Path

import yaml

from sysspectogram.config import ROOT, load_config
from sysspectogram.settings.scenarios import check_scenarios, load_scenarios
from sysspectogram.settings.schema import (
    check_i18n,
    explain_diff,
    get_value,
    load_schema,
    validate_changes,
    validate_value,
)

SCHEMA = ROOT / "configs" / "schema.yaml"
SCENARIOS = ROOT / "configs" / "scenarios"


def test_schema_has_both_languages_everywhere():
    assert check_i18n(load_schema(SCHEMA)) == []


def test_defaults_match_default_yaml():
    schema = load_schema(SCHEMA)
    cfg = yaml.safe_load((ROOT / "configs" / "default.yaml").read_text(encoding="utf-8"))
    for entry in schema["settings"]:
        assert validate_value(entry, entry["default"]) == []
        cur = get_value(cfg, entry["key"])
        # Overlay / UI store CIDR lists as a comma-separated string; YAML keeps a list.
        if entry["key"] == "response.never_ban_cidrs" and cur == []:
            cur = ""
        assert cur == entry["default"], entry["key"]


def test_scenarios_are_valid():
    schema = load_schema(SCHEMA)
    scenarios = load_scenarios(SCENARIOS)
    ids = {s.id for s in scenarios}
    assert ids == {
        "ssh-server-vps",
        "web-server",
        "workstation",
        "lab-demo",
        "hardened-observe",
        "nginx-web",
        "docker-host",
        "vps-large",
        "dedicated-large",
        "database-server",
    }
    assert check_scenarios(scenarios, schema) == []


def test_unknown_key_is_refused():
    schema = load_schema(SCHEMA)
    assert validate_changes(schema, {"ssh.PermitRootLogin": "yes"})


def test_explain_diff_uses_requested_language():
    schema = load_schema(SCHEMA)
    cfg = {"kirk": {"vmi": False}}
    diff = explain_diff(schema, cfg, {"kirk.vmi": True}, "ru")
    assert len(diff) == 1 and diff[0].restart is True
    assert diff[0].title == "Проверка с гипервизора"


def test_overlay_applies_only_allowed_keys_from_trusted_file(tmp_path, monkeypatch):
    import sysspectogram.config as config_mod

    # Isolate from the developer's state/user-settings.json
    monkeypatch.setattr(config_mod, "_apply_user_settings", lambda data: data)

    overlay = tmp_path / "settings.json"
    overlay.write_text('{"response.mode": "shield", "kirk.auto_isolate": true}', encoding="utf-8")
    monkeypatch.setenv("SYSSPECTOGRAM_SETTINGS_OVERLAY", str(overlay))
    monkeypatch.setattr(config_mod, "_overlay_trusted", lambda _p: True)
    cfg = load_config(Path(ROOT / "configs" / "default.yaml"))
    assert cfg["response"]["mode"] == "shield"
    assert cfg["kirk"].get("auto_isolate") is not True

    overlay.write_text("not json", encoding="utf-8")
    cfg = load_config(Path(ROOT / "configs" / "default.yaml"))
    assert cfg["response"]["mode"] == "observe"


def test_untrusted_overlay_is_ignored(tmp_path, monkeypatch):
    import sysspectogram.config as config_mod

    monkeypatch.setattr(config_mod, "_apply_user_settings", lambda data: data)
    # The file belongs to the test user, not root, so it must not be applied.
    overlay = tmp_path / "settings.json"
    overlay.write_text('{"response.mode": "shield"}', encoding="utf-8")
    monkeypatch.setenv("SYSSPECTOGRAM_SETTINGS_OVERLAY", str(overlay))
    cfg = load_config(Path(ROOT / "configs" / "default.yaml"))
    assert cfg["response"]["mode"] == "observe"


def test_overlay_allowlist_matches_schema_and_helper():
    import re

    from sysspectogram.config import OVERLAY_ALLOWED

    schema_keys = {e["key"] for e in load_schema(SCHEMA)["settings"]}
    helper_src = (ROOT / "helper" / "src" / "ops.rs").read_text(encoding="utf-8")
    helper_keys = set(re.findall(r'\("([a-z_.]+)", Kind::', helper_src))
    assert OVERLAY_ALLOWED == schema_keys == helper_keys


def test_never_ban_accepts_multiple_ips_and_bare_hosts():
    from sysspectogram.config import _parse_cidr_list

    assert _parse_cidr_list("203.0.113.10, 198.51.100.20/32") == [
        "203.0.113.10/32",
        "198.51.100.20/32",
    ]
    assert _parse_cidr_list("203.0.113.10\n198.51.100.20") == [
        "203.0.113.10/32",
        "198.51.100.20/32",
    ]
    assert _parse_cidr_list(["203.0.113.10", "198.51.100.0/24"]) == [
        "203.0.113.10/32",
        "198.51.100.0/24",
    ]
    # dedupe
    assert _parse_cidr_list("1.2.3.4, 1.2.3.4/32") == ["1.2.3.4/32"]


def test_never_ban_change_validates_list_or_string():
    schema = load_schema(SCHEMA)
    assert validate_changes(schema, {"response.never_ban_cidrs": "1.2.3.4, 5.6.7.8/32"}) == []
    assert validate_changes(
        schema, {"response.never_ban_cidrs": ["1.2.3.4/32", "5.6.7.8/32"]}
    ) == []
