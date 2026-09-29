"""Artifact manifests and optional minisign verification for v0.8.

The manifest is deliberately deterministic so it can be reviewed, checksummed,
and signed without embedding timestamps or machine-specific absolute paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, BinaryIO

MANIFEST_SCHEMA = "sysspectogram.artifacts.v1"
DEFAULT_MANIFEST_NAME = "artifacts.manifest.json"
DEFAULT_SIGNATURE_NAME = "artifacts.manifest.json.minisig"


class ManifestError(ValueError):
    """Raised when an artifact manifest or its files cannot be trusted."""


class SignatureError(RuntimeError):
    """Raised when minisign cannot sign or verify an artifact."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ManifestError(f"path outside artifact root: {path}") from exc
    if relative.is_absolute() or ".." in relative.parts:
        raise ManifestError(f"unsafe manifest path: {relative}")
    return relative.as_posix()


def _iter_files(root: Path, excluded: set[str]) -> list[tuple[str, Path]]:
    root = root.resolve()
    if not root.is_dir():
        raise ManifestError(f"artifact root is not a directory: {root}")
    rows: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = _safe_relative(path, root)
        if relative in excluded:
            continue
        rows.append((relative, path))
    return rows


def build_manifest(
    root: Path,
    *,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    signature_name: str = DEFAULT_SIGNATURE_NAME,
) -> dict[str, Any]:
    """Build a stable manifest for every regular file below ``root``."""

    root = Path(root)
    files = [
        {
            "path": relative,
            "size": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for relative, path in _iter_files(root, {manifest_name, signature_name})
    ]
    return {
        "schema": MANIFEST_SCHEMA,
        "manifest": manifest_name,
        "signature": signature_name,
        "files": files,
    }


def write_manifest(
    root: Path,
    *,
    output: Path | None = None,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    signature_name: str = DEFAULT_SIGNATURE_NAME,
) -> Path:
    """Write a canonical JSON manifest atomically and return its path."""

    root = Path(root).resolve()
    output = Path(output) if output else root / manifest_name
    output = output.resolve()
    payload = build_manifest(
        root,
        manifest_name=manifest_name,
        signature_name=signature_name,
    )
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return output


def _manifest_rows(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if payload.get("schema") != MANIFEST_SCHEMA:
        raise ManifestError(f"unsupported artifact manifest schema: {payload.get('schema')}")
    rows = payload.get("files")
    if not isinstance(rows, list):
        raise ManifestError("artifact manifest files must be a list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ManifestError("malformed artifact manifest entry")
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ManifestError(f"unsafe manifest path: {row['path']}")
        if relative.as_posix() in result:
            raise ManifestError(f"duplicate manifest path: {row['path']}")
        digest = str(row.get("sha256") or "")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            raise ManifestError(f"invalid manifest checksum: {row['path']}")
        try:
            size = int(row.get("size"))
        except (TypeError, ValueError) as exc:
            raise ManifestError(f"invalid manifest size: {row['path']}") from exc
        if size < 0:
            raise ManifestError(f"invalid manifest size: {row['path']}")
        row = dict(row)
        row["size"] = size
        result[relative.as_posix()] = row
    return result


def verify_manifest(
    root: Path,
    manifest_path: Path | None = None,
    *,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    signature_name: str = DEFAULT_SIGNATURE_NAME,
) -> dict[str, Any]:
    """Verify both listed files and the complete file set under ``root``."""

    root = Path(root).resolve()
    manifest_path = (manifest_path or root / manifest_name).resolve()
    if not manifest_path.is_file():
        raise ManifestError(f"manifest required: {manifest_path}")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read artifact manifest: {manifest_path}") from exc
    if not isinstance(payload, dict):
        raise ManifestError("artifact manifest must be an object")
    if payload.get("manifest") not in (None, manifest_name):
        raise ManifestError("artifact manifest filename does not match policy")
    if payload.get("signature") not in (None, signature_name):
        raise ManifestError("artifact signature filename does not match policy")
    expected = _manifest_rows(payload)
    actual_rows = {
        relative: path for relative, path in _iter_files(root, {manifest_name, signature_name})
    }
    for relative, row in expected.items():
        path = root / relative
        if relative not in actual_rows or not path.is_file() or path.is_symlink():
            raise ManifestError(f"missing artifact: {relative}")
        if int(row.get("size", -1)) != path.stat().st_size:
            raise ManifestError(f"size mismatch for {relative}")
        if _sha256(path) != str(row["sha256"]).lower():
            raise ManifestError(f"checksum mismatch for {relative}")
    unexpected = sorted(set(actual_rows) - set(expected))
    if unexpected:
        raise ManifestError(f"unexpected artifact: {unexpected[0]}")
    return {"ok": True, "files": len(expected), "manifest": str(manifest_path)}


def open_verified_artifact(
    root: Path,
    relative_path: str,
    *,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    signature_name: str = DEFAULT_SIGNATURE_NAME,
) -> BinaryIO:
    """Open an artifact by held descriptor and recheck its manifest digest.

    The caller owns and must close the returned file object. Reading and
    deserializing from this handle prevents a path replacement after the
    manifest check from changing the bytes actually consumed.
    """

    root = Path(root).resolve()
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ManifestError(f"unsafe artifact path: {relative_path}")
    manifest_path = root / manifest_name
    if not manifest_path.is_file():
        raise ManifestError(f"manifest required: {manifest_path}")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read artifact manifest: {manifest_path}") from exc
    if not isinstance(payload, dict):
        raise ManifestError("artifact manifest must be an object")
    expected = _manifest_rows(payload).get(relative.as_posix())
    if expected is None:
        raise ManifestError(f"artifact missing from manifest: {relative_path}")
    target = root / relative
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise ManifestError(f"cannot open verified artifact: {relative_path}") from exc
    handle = os.fdopen(fd, "rb")
    data = handle.read()
    if len(data) != int(expected.get("size", -1)):
        handle.close()
        raise ManifestError(f"size mismatch for {relative_path}")
    if hashlib.sha256(data).hexdigest() != str(expected["sha256"]).lower():
        handle.close()
        raise ManifestError(f"checksum mismatch for {relative_path}")
    handle.seek(0)
    return handle


def _minisign() -> str:
    executable = shutil.which("minisign")
    if not executable:
        raise SignatureError(
            "minisign is required for signed artifacts; install minisign or use "
            "supply_chain.enforce=false for legacy local artifacts"
        )
    return executable


def _run_minisign(args: list[str]) -> None:
    try:
        result = subprocess.run(
            [_minisign(), *args],
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
    except OSError as exc:
        raise SignatureError(f"could not execute minisign: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown minisign error").strip()
        raise SignatureError(f"minisign failed: {detail}")


def sign_file(
    path: Path,
    secret_key: Path,
    *,
    signature_path: Path | None = None,
) -> Path:
    path = Path(path).resolve()
    secret_key = Path(secret_key).resolve()
    if not path.is_file():
        raise SignatureError(f"file to sign does not exist: {path}")
    if not secret_key.is_file():
        raise SignatureError(f"minisign secret key does not exist: {secret_key}")
    signature_path = (
        Path(signature_path).resolve()
        if signature_path
        else Path(f"{path}.minisig").resolve()
    )
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    _run_minisign(["-S", "-s", str(secret_key), "-m", str(path), "-x", str(signature_path), "-q"])
    return signature_path


def verify_file(
    path: Path,
    public_key: str | Path,
    *,
    signature_path: Path | None = None,
) -> bool:
    path = Path(path).resolve()
    if not path.is_file():
        raise SignatureError(f"file to verify does not exist: {path}")
    signature_path = (
        Path(signature_path).resolve()
        if signature_path
        else Path(f"{path}.minisig").resolve()
    )
    if not signature_path.is_file():
        raise SignatureError(f"signature does not exist: {signature_path}")
    key = Path(public_key)
    if key.is_file():
        if not key.read_text(encoding="utf-8").strip():
            raise SignatureError("minisign public key is empty")
        key_args = ["-p", str(key)]
    else:
        public_value = str(public_key).strip()
        if not public_value:
            raise SignatureError("minisign public key is empty")
        key_args = ["-P", public_value]
    _run_minisign(["-Vm", str(path), *key_args, "-x", str(signature_path), "-q"])
    return True


def verify_artifacts(
    root: Path,
    *,
    enforce: bool = False,
    public_key: str | Path | None = None,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    signature_name: str = DEFAULT_SIGNATURE_NAME,
) -> dict[str, Any]:
    """Apply the configured policy before any model deserialization."""

    root = Path(root).resolve()
    manifest_path = root / manifest_name
    if not manifest_path.exists():
        if enforce:
            raise ManifestError(f"manifest required when supply-chain enforcement is enabled: {manifest_path}")
        return {"enforced": False, "verified": False, "signed": False}
    result = verify_manifest(
        root,
        manifest_path,
        manifest_name=manifest_name,
        signature_name=signature_name,
    )
    signature_path = root / signature_name
    if enforce or signature_path.exists():
        if not public_key:
            raise SignatureError("public key required to verify enforced artifact manifest")
        verify_file(manifest_path, public_key, signature_path=signature_path)
        result["signature"] = str(signature_path)
        result["signed"] = True
    else:
        result["signed"] = False
    result.update({"enforced": enforce, "verified": True})
    return result
