"""release-assets.yml fleet signing and post-release verification."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_YML = ROOT / ".github" / "workflows" / "release-assets.yml"

PUBLISH_JOBS = (
    "musl-agent",
    "helper",
    "control-center",
    "fleet-sign",
    "profile-packs",
)


def _load_workflow() -> dict:
    return yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))


def _step_uses(step: dict) -> str:
    return str(step.get("uses") or "")


def test_fleet_center_matrix_does_not_upload_to_release():
    jobs = _load_workflow()["jobs"]
    fleet = jobs["fleet-center"]
    uses = [_step_uses(s) for s in fleet.get("steps", [])]
    assert not any("softprops/action-gh-release" in u for u in uses), (
        "fleet-center matrix must not upload to GitHub release"
    )
    assert any("actions/upload-artifact" in u for u in uses), (
        "fleet-center matrix should upload workflow artifacts"
    )


def test_fleet_center_matrix_does_not_write_fleet_checksums_in_job():
    text = RELEASE_YML.read_text(encoding="utf-8")
    fleet_block = text.split("fleet-center:", 1)[1].split("\n  fleet-sign:", 1)[0]
    assert "SHA256SUMS.fleet-center" not in fleet_block, (
        "fleet-center matrix must not create SHA256SUMS.fleet-center"
    )


def test_fleet_sign_job_exists_and_publishes_fleet_assets():
    jobs = _load_workflow()["jobs"]
    assert "fleet-sign" in jobs
    sign = jobs["fleet-sign"]
    needs = sign.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    assert needs == ["fleet-center"]
    assert sign.get("runs-on")
    uses = [_step_uses(s) for s in sign.get("steps", [])]
    assert any("softprops/action-gh-release" in u for u in uses)
    assert any("actions/download-artifact" in u for u in uses)
    body = yaml.dump(sign)
    assert "SHA256SUMS.fleet-center" in body


def test_verify_release_job_needs_all_publish_jobs():
    jobs = _load_workflow()["jobs"]
    assert "verify-release" in jobs
    verify = jobs["verify-release"]
    needs = verify.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    assert needs is not None
    for job in PUBLISH_JOBS:
        assert job in needs, f"verify-release must need {job}"
    verify_block = RELEASE_YML.read_text(encoding="utf-8").split("verify-release:", 1)[1]
    assert "scripts/verify-release.sh" in verify_block
    assert "VERIFY_RELEASE_TAG" in verify_block
    assert "sha256sum -c" in verify_block
