"""SPDX SBOM generation tests."""

from __future__ import annotations

import json
from pathlib import Path

from sysspectogram.sbom import generate_sbom, write_sbom


def test_sbom_is_deterministic_and_contains_hashes(tmp_path: Path):
    asset = tmp_path / "agent"
    asset.write_bytes(b"binary")
    packages = [{"name": "Example", "version": "1.2.3", "ecosystem": "pypi"}]

    first = generate_sbom(
        tmp_path,
        python_distributions=packages,
        cargo_packages=[],
        include_files=[asset],
    )
    second = generate_sbom(
        tmp_path,
        python_distributions=packages,
        cargo_packages=[],
        include_files=[asset],
    )

    assert first == second
    assert first["spdxVersion"] == "SPDX-2.3"
    assert any(row["name"] == "Example" for row in first["packages"])
    assert first["files"][0]["checksums"][0]["algorithm"] == "SHA256"


def test_sbom_write_is_valid_json(tmp_path: Path):
    output = tmp_path / "sbom.spdx.json"
    write_sbom(
        tmp_path,
        output,
        python_distributions=[],
        cargo_packages=[],
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["documentNamespace"].startswith("https://sysspectogram.dev/sbom/")
    assert payload["creationInfo"]["created"] == "1970-01-01T00:00:00Z"
