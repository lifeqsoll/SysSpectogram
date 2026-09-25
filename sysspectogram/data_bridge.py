"""VPS ↔ builder train bridge: bundle CSV data, push artifacts over SSH/rsync."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "sysspectogram.data.v1"
_FORBIDDEN = (".env", ".pem", ".key", "id_rsa", "id_ed25519", "credentials")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _refuse_secret(path: Path) -> None:
    name = path.name.lower()
    for bad in _FORBIDDEN:
        if bad in name:
            raise ValueError(f"refusing to bundle secret-like file: {path}")


def create_data_bundle(
    csv_paths: list[Path],
    out_tar: Path,
    *,
    note: str = "",
    host_id: str | None = None,
) -> dict[str, Any]:
    csv_paths = [Path(p).resolve() for p in csv_paths]
    for p in csv_paths:
        if not p.is_file():
            raise FileNotFoundError(p)
        _refuse_secret(p)
    out_tar = Path(out_tar).resolve()
    out_tar.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ss-data-") as tmp:
        root = Path(tmp) / "bundle"
        csv_dir = root / "csv"
        csv_dir.mkdir(parents=True)
        entries = []
        for src in csv_paths:
            dest = csv_dir / src.name
            shutil.copy2(src, dest)
            entries.append({"name": src.name, "sha256": _sha256(dest), "bytes": dest.stat().st_size})
        manifest = {
            "schema": SCHEMA,
            "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host_id": host_id or "",
            "note": note,
            "csv": entries,
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (root / "README.txt").write_text(
            "SysSpectogram data bundle.\n"
            "On builder: unpack → build-dataset → train → export-onnx → artifacts push.\n",
            encoding="utf-8",
        )
        with tarfile.open(out_tar, "w:gz") as tar:
            tar.add(root, arcname="bundle")
    sha = _sha256(out_tar)
    (Path(str(out_tar) + ".sha256")).write_text(f"{sha}  {out_tar.name}\n", encoding="utf-8")
    return {"path": str(out_tar), "sha256": sha, "csv": len(csv_paths)}


def unpack_data_bundle(tar_path: Path, dest: Path) -> dict[str, Any]:
    tar_path = Path(tar_path).resolve()
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tar:
        # refuse path traversal
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                raise ValueError(f"unsafe tar member: {m.name}")
            if any(bad in m.name.lower() for bad in _FORBIDDEN):
                raise ValueError(f"secret-like member refused: {m.name}")
        tar.extractall(dest)
    manifest_path = dest / "bundle" / "manifest.json"
    if not manifest_path.exists():
        # flat extract
        candidates = list(dest.rglob("manifest.json"))
        if not candidates:
            raise FileNotFoundError("manifest.json missing in bundle")
        manifest_path = candidates[0]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        raise ValueError(f"unsupported schema {manifest.get('schema')}")
    csv_root = manifest_path.parent / "csv"
    return {"manifest": manifest, "csv_dir": str(csv_root), "dest": str(dest)}


def pull_cmd(bundle_remote: str, ssh: str) -> str:
    """Copy-paste rsync one-liner for the operator PC."""
    return f"rsync -avz {ssh}:{bundle_remote} ./ss-bundles/"


_SAFE_REMOTE_PATH = re.compile(r"^[A-Za-z0-9/._+-]+$")
_SAFE_UNIT = re.compile(r"^[A-Za-z0-9_@.-]+\.service$")


def _validate_remote_path(remote_dir: str) -> str:
    remote = remote_dir.rstrip("/")
    if not remote or not _SAFE_REMOTE_PATH.match(remote):
        raise ValueError(
            f"unsafe remote_dir {remote_dir!r} — use only [A-Za-z0-9/._+-], no shell metacharacters"
        )
    return remote


def _validate_unit(name: str) -> str:
    if not _SAFE_UNIT.match(name):
        raise ValueError(f"unsafe systemd unit {name!r} — expected name.service")
    return name


def push_artifacts(
    model_dir: Path,
    *,
    ssh: str,
    remote_dir: str,
    restart_unit: str | None = None,
) -> dict[str, Any]:
    """rsync artifacts to VPS with sha256 verify, then optional systemctl restart.

    Paths/units are validated; remote commands use ``ssh --`` argv form (no shell string).
    """
    model_dir = Path(model_dir).resolve()
    if not model_dir.is_dir():
        raise FileNotFoundError(model_dir)
    remote = _validate_remote_path(remote_dir)
    staging = f"{remote}.next"

    files: dict[str, str] = {}
    for p in sorted(model_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name == "artifacts.sha256.json":
            continue
        rel = str(p.relative_to(model_dir)).replace("\\", "/")
        if ".." in rel.split("/"):
            raise ValueError(f"refusing path {rel}")
        files[rel] = _sha256(p)
    manifest = {"schema": "sysspectogram.artifacts.v1", "files": files}
    man_path = model_dir / "artifacts.sha256.json"
    man_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    subprocess.run(["ssh", ssh, "--", "mkdir", "-p", "--", staging], check=True)
    subprocess.run(
        ["rsync", "-avz", "--delete", f"{model_dir}/", f"{ssh}:{staging}/"],
        check=True,
    )

    verify_script = (
        "import json, hashlib, pathlib, sys\n"
        f"root = pathlib.Path({staging!r})\n"
        "man = json.loads((root / 'artifacts.sha256.json').read_text())\n"
        "assert man.get('schema') == 'sysspectogram.artifacts.v1'\n"
        "bad = []\n"
        "for rel, exp in man['files'].items():\n"
        "    p = root / rel\n"
        "    if '..' in pathlib.PurePosixPath(rel).parts or not p.is_file():\n"
        "        bad.append(rel); continue\n"
        "    if hashlib.sha256(p.read_bytes()).hexdigest() != exp:\n"
        "        bad.append(rel)\n"
        "sys.exit(1 if bad else 0)\n"
    )
    subprocess.run(["ssh", ssh, "--", "python3", "-c", verify_script], check=True)

    swap_script = (
        "import pathlib, shutil\n"
        f"remote = pathlib.Path({remote!r})\n"
        f"staging = pathlib.Path({staging!r})\n"
        f"bak = pathlib.Path({remote + '.bak'!r})\n"
        "if bak.exists():\n"
        "    shutil.rmtree(bak)\n"
        "if remote.exists():\n"
        "    remote.rename(bak)\n"
        "staging.rename(remote)\n"
    )
    subprocess.run(["ssh", ssh, "--", "python3", "-c", swap_script], check=True)

    if restart_unit:
        unit = _validate_unit(restart_unit)
        subprocess.run(
            ["ssh", ssh, "--", "sudo", "systemctl", "restart", "--", unit],
            check=False,
        )
    return {
        "remote": remote,
        "ssh": ssh,
        "restart": restart_unit,
        "files": len(files),
        "manifest": str(man_path),
    }
