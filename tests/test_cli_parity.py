from __future__ import annotations

import runpy

from sysspectogram.config import ROOT


def test_every_cli_command_is_documented():
    module = runpy.run_path(str(ROOT / "scripts" / "check_cli_parity.py"), run_name="check_cli_parity")
    assert module["main"]() == 0
