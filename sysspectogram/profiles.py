"""Shareable host-behavior profile packs (tar.gz on GitHub Releases)."""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "sysspectogram.profile.v1"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_profile(
    *,
    name: str,
    role: str,
    host_artifacts: Path,
    out_tar: Path,
    agent_iforest: Path | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Create profile-*.tar.gz with host/ CNN+IF and optional agent IF."""
    host_artifacts = host_artifacts.resolve()
    if not host_artifacts.is_dir():
        raise FileNotFoundError(f"host artifacts missing: {host_artifacts}")
    out_tar = out_tar.resolve()
    out_tar.parent.mkdir(parents=True, exist_ok=True)

    meta_path = host_artifacts / "meta.json"
    host_meta: dict[str, Any] = {}
    if meta_path.exists():
        host_meta = json.loads(meta_path.read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="ss-profile-") as tmp:
        root = Path(tmp) / name
        host_dst = root / "host"
        shutil.copytree(host_artifacts, host_dst)
        agent_rel = None
        if agent_iforest and agent_iforest.exists():
            agent_dst = root / "agent"
            agent_dst.mkdir(parents=True, exist_ok=True)
            dest = agent_dst / "agent_iforest.joblib"
            shutil.copy2(agent_iforest, dest)
            agent_rel = "agent/agent_iforest.joblib"

        manifest = {
            "schema": SCHEMA,
            "name": name,
            "role": role,
            "description": description
            or f"Baseline pack for role={role}. Fine-tune on your VPS before production trust.",
            "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host_dir": "host",
            "agent_iforest": agent_rel,
            "host_meta": {
                "threshold": host_meta.get("threshold"),
                "cnn_weight": host_meta.get("cnn_weight"),
                "iforest_weight": host_meta.get("iforest_weight"),
                "columns": host_meta.get("columns"),
            },
            "disclaimer": "Third-party packs affect FP/FN. Prefer packs you built or fine-tuned.",
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (root / "README.md").write_text(
            f"# Profile `{name}`\n\nRole: `{role}`\n\n"
            f"Install:\n\n```bash\npython -m sysspectogram profiles install {out_tar.name} "
            f"--dest artifacts/profiles/{name}\n```\n\n"
            "Then: `guard --model artifacts/profiles/<name>/host`\n",
            encoding="utf-8",
        )

        with tarfile.open(out_tar, "w:gz") as tar:
            tar.add(root, arcname=name)

    digest = _sha256_file(out_tar)
    sidecar = out_tar.with_suffix(out_tar.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {out_tar.name}\n", encoding="utf-8")
    return {"path": str(out_tar), "sha256": digest, "manifest": manifest}


def install_profile(
    tar_path: Path,
    dest: Path,
    *,
    expected_sha256: str | None = None,
    insecure_no_verify: bool = False,
) -> dict[str, Any]:
    tar_path = tar_path.resolve()
    if not tar_path.is_file():
        raise FileNotFoundError(tar_path)
    digest = _sha256_file(tar_path)
    if not expected_sha256 and not insecure_no_verify:
        raise ValueError("sha256 required (pass expected_sha256 or insecure_no_verify=True)")
    if expected_sha256 and digest.lower() != expected_sha256.lower().strip():
        raise ValueError(f"sha256 mismatch: got {digest}, expected {expected_sha256}")

    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar.getmembers():
            p = Path(m.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError(f"unsafe path in archive: {m.name}")
            if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                raise ValueError(f"refusing special member: {m.name}")
        # Python 3.12+ data filter blocks symlink slips; fallback: members already scrubbed
        try:
            tar.extractall(dest, filter="data")  # type: ignore[call-arg]
        except TypeError:
            tar.extractall(dest)

    manifests = list(dest.rglob("manifest.json"))
    if not manifests:
        raise ValueError("no manifest.json in pack")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError(f"unsupported schema: {manifest.get('schema')}")
    root = manifests[0].parent
    return {
        "root": str(root),
        "host": str(root / "host"),
        "agent_iforest": str(root / manifest["agent_iforest"]) if manifest.get("agent_iforest") else None,
        "manifest": manifest,
        "sha256": digest,
    }


def pull_profile(
    url: str,
    dest_tar: Path,
    *,
    expected_sha256: str | None = None,
    insecure_no_verify: bool = False,
) -> Path:
    if not expected_sha256 and not insecure_no_verify:
        raise ValueError("sha256 required for pull (or insecure_no_verify=True)")
    dest_tar = dest_tar.resolve()
    dest_tar.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest_tar)  # noqa: S310 — user-supplied release URL
    if expected_sha256:
        got = _sha256_file(dest_tar)
        if got.lower() != expected_sha256.lower().strip():
            dest_tar.unlink(missing_ok=True)
            raise ValueError(f"sha256 mismatch after download: {got}")
    return dest_tar


def list_builtin_roles() -> list[dict[str, str]]:
    """Catalog entries (assets published on GitHub Releases)."""
    return [
        {
            "role": "ubuntu-nginx",
            "name": "profile-ubuntu-nginx-v1",
            "note": "Web VPS: nginx + ssh baseline",
        },
        {
            "role": "docker-host",
            "name": "profile-docker-host-v1",
            "note": "Docker/container host metrics shape",
        },
        {
            "role": "3x-ui",
            "name": "profile-3x-ui-v1",
            "note": "Panel / proxy panel host (3x-ui class)",
        },
        {
            "role": "generic-linux",
            "name": "profile-generic-linux-v1",
            "note": "Generic quiet Linux VPS",
        },
    ]


def finetune_note(host_dir: Path) -> str:
    return (
        f"Fine-tune on this VPS:\n"
        f"  1) collect normal traffic → CSV\n"
        f"  2) build-dataset + train --out {host_dir}\n"
        f"  3) optional: train-agent-if on local agent JSONL\n"
        f"  4) profiles pack --name my-vps --role custom --host {host_dir}\n"
    )
