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
    minisign_secret_key: Path | None = None,
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
        from sysspectogram.supply_chain import write_manifest

        write_manifest(host_dst)
        agent_rel = None
        if agent_iforest and agent_iforest.exists():
            agent_dst = root / "agent"
            agent_dst.mkdir(parents=True, exist_ok=True)
            dest = agent_dst / "agent_iforest.joblib"
            shutil.copy2(agent_iforest, dest)
            if minisign_secret_key is not None:
                from sysspectogram.supply_chain import sign_file

                sign_file(dest, Path(minisign_secret_key))
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
    result = {"path": str(out_tar), "sha256": digest, "manifest": manifest}
    try:
        from sysspectogram.pack_sign import ensure_pack_key, sign_file

        key = ensure_pack_key(Path("state/pack_signing.key"))
        sig = sign_file(out_tar, key)
        result["sig"] = str(sig)
    except Exception:
        pass
    if minisign_secret_key is not None:
        from sysspectogram.supply_chain import sign_file

        sig = sign_file(out_tar, Path(minisign_secret_key))
        result["minisig"] = str(sig)
    return result


def install_profile(
    tar_path: Path,
    dest: Path,
    *,
    expected_sha256: str | None = None,
    insecure_no_verify: bool = False,
    require_sig: bool = False,
    pack_key: str | None = None,
    public_key: str | Path | None = None,
    require_minisign: bool = False,
) -> dict[str, Any]:
    tar_path = tar_path.resolve()
    if not tar_path.is_file():
        raise FileNotFoundError(tar_path)
    digest = _sha256_file(tar_path)
    if not expected_sha256 and not insecure_no_verify:
        raise ValueError("sha256 required (pass expected_sha256 or insecure_no_verify=True)")
    if expected_sha256 and digest.lower() != expected_sha256.lower().strip():
        raise ValueError(f"sha256 mismatch: got {digest}, expected {expected_sha256}")
    if require_sig or pack_key or tar_path.with_suffix(tar_path.suffix + ".sig").exists():
        from sysspectogram.pack_sign import load_pack_key, verify_file

        key = pack_key or load_pack_key(Path("state/pack_signing.key"))
        if not key:
            raise ValueError("pack .sig present or require_sig but no SYSSPECTOGRAM_PACK_KEY / state/pack_signing.key")
        if not verify_file(tar_path, key):
            raise ValueError("pack signature verification failed")
    minisig = Path(f"{tar_path}.minisig")
    if require_minisign or public_key or minisig.exists():
        if not minisig.exists():
            raise ValueError(f"minisign signature required but missing: {minisig}")
        if not public_key:
            raise ValueError("minisign public key required for profile verification")
        from sysspectogram.supply_chain import verify_file as verify_minisign_file

        verify_minisign_file(tar_path, public_key, signature_path=minisig)

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
    agent_path = None
    agent_rel = manifest.get("agent_iforest")
    if agent_rel:
        relative = Path(str(agent_rel))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe agent_iforest path in manifest: {agent_rel}")
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError(f"agent_iforest escapes profile root: {agent_rel}") from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"agent_iforest missing from profile: {agent_rel}")
        agent_path = str(candidate)
    return {
        "root": str(root),
        "host": str(root / "host"),
        "agent_iforest": agent_path,
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
    """Catalog entries (assets published on GitHub Releases / local dist/)."""
    return [
        {
            "role": "generic-linux",
            "name": "profile-generic-linux-v1",
            "note": "Generic quiet Linux VPS (Release asset)",
        },
        {
            "role": "nginx",
            "name": "profile-nginx-v1",
            "note": "Web VPS: nginx/http baseline from role-lab",
        },
        {
            "role": "ssh",
            "name": "profile-ssh-v1",
            "note": "Quiet ssh-only VPS",
        },
        {
            "role": "docker",
            "name": "profile-docker-v1",
            "note": "Docker/container host metrics shape",
        },
        {
            "role": "panel",
            "name": "profile-panel-v1",
            "note": "Panel / 3x-ui class host",
        },
        {
            "role": "wireguard",
            "name": "profile-wireguard-v1",
            "note": "VPN endpoint (wireguard)",
        },
        {
            "role": "python",
            "name": "profile-python-v1",
            "note": "App VPS with sustained CPU/mem",
        },
    ]


def finetune_note(host_dir: Path) -> str:
    return (
        f"Fine-tune (builder PC, not 1GB VPS):\n"
        f"  1) On VPS: collect + data bundle (see docs/TRAIN_BRIDGE.md)\n"
        f"  2) On PC: unpack, build-dataset, train --out {host_dir}\n"
        f"  3) export-onnx --model {host_dir}\n"
        f"  4) artifacts push --model {host_dir} --ssh user@vps --remote .../artifacts/live\n"
        f"  5) optional: train-agent-if on local agent JSONL\n"
    )
