"""Supply-chain manifest and signature policy tests."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sysspectogram.supply_chain import (
    ManifestError,
    SignatureError,
    build_manifest,
    open_verified_artifact,
    verify_artifacts,
    verify_manifest,
    write_manifest,
)


@pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign CLI unavailable")
def test_minisign_file_signature_roundtrip(tmp_path: Path):
    payload = tmp_path / "payload"
    payload.write_bytes(b"signed")
    secret = tmp_path / "secret.key"
    public = tmp_path / "public.key"
    subprocess.run(
        ["minisign", "-G", "-p", str(public), "-s", str(secret), "-W"],
        check=True,
        capture_output=True,
        text=True,
    )
    from sysspectogram.supply_chain import sign_file, verify_file

    signature = sign_file(payload, secret)
    assert verify_file(payload, public, signature_path=signature)
    payload.write_bytes(b"tampered")
    with pytest.raises(SignatureError, match="minisign failed"):
        verify_file(payload, public, signature_path=signature)


def test_manifest_is_deterministic_and_excludes_itself(tmp_path: Path):
    (tmp_path / "b.bin").write_bytes(b"two")
    (tmp_path / "a.txt").write_text("one\n", encoding="utf-8")

    first = build_manifest(tmp_path)
    second = build_manifest(tmp_path)

    assert first == second
    assert [row["path"] for row in first["files"]] == ["a.txt", "b.bin"]
    write_manifest(tmp_path)
    assert "artifacts.manifest.json" not in {
        row["path"] for row in build_manifest(tmp_path)["files"]
    }


def test_manifest_detects_tampering_and_unexpected_files(tmp_path: Path):
    (tmp_path / "model.onnx").write_bytes(b"model")
    manifest_path = write_manifest(tmp_path)
    assert verify_manifest(tmp_path, manifest_path)["ok"] is True

    (tmp_path / "model.onnx").write_bytes(b"altered")
    with pytest.raises(ManifestError, match="(size|checksum) mismatch"):
        verify_manifest(tmp_path, manifest_path)

    (tmp_path / "model.onnx").write_bytes(b"model")
    (tmp_path / "extra.bin").write_bytes(b"unexpected")
    with pytest.raises(ManifestError, match="unexpected artifact"):
        verify_manifest(tmp_path, manifest_path)


def test_manifest_rejects_path_traversal(tmp_path: Path):
    manifest_path = tmp_path / "artifacts.manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "sysspectogram.artifacts.v1",
                "files": [{"path": "../outside", "size": 1, "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ManifestError, match="unsafe manifest path"):
        verify_manifest(tmp_path, manifest_path)


def test_unsigned_artifacts_are_compatible_when_not_enforced(tmp_path: Path):
    (tmp_path / "meta.json").write_text("{}", encoding="utf-8")
    result = verify_artifacts(tmp_path, enforce=False)
    assert result["enforced"] is False
    assert result["verified"] is False


def test_enforced_artifacts_require_manifest_and_public_key(tmp_path: Path):
    (tmp_path / "meta.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ManifestError, match="manifest required"):
        verify_artifacts(tmp_path, enforce=True)


def test_open_verified_artifact_holds_and_rechecks_file_bytes(tmp_path: Path):
    artifact = tmp_path / "weights.bin"
    artifact.write_bytes(b"trusted")
    write_manifest(tmp_path)
    with open_verified_artifact(tmp_path, "weights.bin") as handle:
        assert handle.read() == b"trusted"
