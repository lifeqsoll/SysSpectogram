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
