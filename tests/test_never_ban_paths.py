"""B/M2: never_ban validation on home settings / schema (not only seed)."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.admin_ip import validate_never_ban_cidr, validate_never_ban_value
from sysspectogram.settings.schema import load_schema, validate_changes

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "configs" / "schema.yaml"


def test_reject_unspecified_and_loopback():
    assert validate_never_ban_cidr("0.0.0.0/32")[1] == "special_address"
    assert validate_never_ban_cidr("127.0.0.1")[1] == "special_address"
    assert validate_never_ban_cidr("0.0.0.0/0")[1] == "too_wide"


def test_schema_rejects_wide_never_ban():
    schema = load_schema(SCHEMA)
    errs = validate_changes(schema, {"response.never_ban_cidrs": "0.0.0.0/0"})
    assert errs
    errs2 = validate_changes(schema, {"response.never_ban_cidrs": "203.0.113.10/32"})
    assert errs2 == []


def test_home_settings_cli_rejects(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    from argparse import Namespace

    from sysspectogram.cli import _cmd_home_settings

    rc = _cmd_home_settings(
        Namespace(changes=json.dumps({"response.never_ban_cidrs": "0.0.0.0/0"}))
    )
    assert rc == 2
    assert not (tmp_path / "state" / "user-settings.json").exists()


def test_validate_never_ban_value_list():
    ok, err = validate_never_ban_value(["203.0.113.10", "198.51.100.0/24"])
    assert err is None
    assert "203.0.113.10/32" in (ok or "")


def test_load_scrubs_wide_never_ban(tmp_path: Path, monkeypatch):
    """Stale 0.0.0.0/0 in user-settings must not disable bans at runtime."""
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "user-settings.json").write_text(
        json.dumps(
            {
                "response.never_ban_cidrs": "0.0.0.0/0, 203.0.113.10, 127.0.0.0/24",
            }
        ),
        encoding="utf-8",
    )
    from sysspectogram.config import default_config_path, load_config

    cfg = load_config(default_config_path())
    never = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    assert "0.0.0.0/0" not in never
    assert "127.0.0.0/24" not in never
    assert any(x.startswith("203.0.113.10") for x in never)


def test_reject_zero_slash8_hosts():
    assert validate_never_ban_cidr("0.0.0.1/32")[1] == "special_address"
    # Leading-zero IPv4 is rejected by ip_network (invalid) or as special.
    assert validate_never_ban_cidr("000.0.0.0/32")[1] in {"special_address", "invalid_ip"}
    assert validate_never_ban_cidr("127.0.0.0/24")[1] == "special_address"


def test_allow_ssh_cidrs_yaml_string_not_chars(tmp_path: Path, monkeypatch):
    """String form in YAML must not be iterated as characters."""
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    cfg_path = tmp_path / "default.yaml"
    cfg_path.write_text(
        "kirk:\n  allow_ssh_cidrs: \"203.0.113.10/32, 198.51.100.0/24\"\n"
        "response:\n  mode: observe\n",
        encoding="utf-8",
    )
    from sysspectogram.config import load_config

    cfg = load_config(cfg_path)
    allows = list((cfg.get("kirk") or {}).get("allow_ssh_cidrs") or [])
    assert allows == ["203.0.113.10/32", "198.51.100.0/24"]
