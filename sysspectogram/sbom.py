"""Deterministic SPDX 2.3 SBOM generation for Python and Rust releases."""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Iterable

SPDX_VERSION = "SPDX-2.3"
SBOM_NAMESPACE = "https://sysspectogram.dev/sbom"


def _spdx_id(prefix: str, name: str, version: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", f"{name}-{version}").strip("-")
    return f"SPDXRef-{prefix}-{safe or 'unknown'}"


def _purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "cargo":
        return f"pkg:cargo/{name}@{version}"
    return f"pkg:pypi/{name.lower().replace('_', '-')}/{version}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_info(project_root: Path) -> tuple[str, str]:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.is_file():
        return "sysspectogram", "0.0.0"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data.get("project") or {}
        return str(project.get("name") or "sysspectogram"), str(
            project.get("version") or "0.0.0"
        )
    except (OSError, tomllib.TOMLDecodeError):
        return "sysspectogram", "0.0.0"


def _installed_python_distributions() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for distribution in metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip()
        version = str(distribution.version or "").strip()
        if name and version:
            rows.append({"name": name, "version": version, "ecosystem": "pypi"})
    return rows


def _cargo_packages(project_root: Path) -> list[dict[str, str]]:
    cargo_root = project_root if (project_root / "Cargo.toml").is_file() else project_root / "agent"
    if not (cargo_root / "Cargo.toml").is_file():
        raise RuntimeError(f"cannot find Cargo.toml below {project_root}")
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--no-deps"],
            cwd=cargo_root,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
    except OSError as exc:
        raise RuntimeError(f"cannot execute cargo metadata: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "cargo metadata failed").strip()
        raise RuntimeError(detail)
    try:
        payload = json.loads(result.stdout)
        packages = payload["packages"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("cargo metadata returned malformed JSON") from exc
    return [
        {
            "name": str(row["name"]),
            "version": str(row["version"]),
            "ecosystem": "cargo",
        }
        for row in packages
        if isinstance(row, dict) and row.get("name") and row.get("version")
    ]


def _normalise_packages(
    project_root: Path,
    python_distributions: Iterable[dict[str, str]] | None,
    cargo_packages: Iterable[dict[str, str]] | None,
) -> list[dict[str, str]]:
    python_rows = (
        list(python_distributions)
        if python_distributions is not None
        else _installed_python_distributions()
    )
    cargo_rows = (
        list(cargo_packages)
        if cargo_packages is not None
        else _cargo_packages(project_root)
    )
    rows = python_rows + cargo_rows
    normalised: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in rows:
        ecosystem = str(row.get("ecosystem") or "pypi").lower()
        name = str(row.get("name") or "").strip()
        version = str(row.get("version") or "").strip()
        if not name or not version or ecosystem not in {"pypi", "cargo"}:
            raise ValueError("SBOM packages require name, version, and pypi/cargo ecosystem")
        normalised[(ecosystem, name.lower(), version)] = {
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
        }
    return [
        normalised[key]
        for key in sorted(normalised, key=lambda item: (item[0], item[1], item[2]))
    ]


def generate_sbom(
    project_root: Path,
    *,
    python_distributions: Iterable[dict[str, str]] | None = None,
    cargo_packages: Iterable[dict[str, str]] | None = None,
    include_files: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """Build a deterministic SPDX document for the project and dependencies."""

    project_root = Path(project_root).resolve()
    project_name, project_version = _project_info(project_root)
    packages = _normalise_packages(project_root, python_distributions, cargo_packages)
    root_id = _spdx_id("Project", project_name, project_version)
    package_rows: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    package_rows.append(
        {
            "SPDXID": root_id,
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": _purl("pypi", project_name, project_version),
                }
            ],
        }
    )
    for row in packages:
        package_id = _spdx_id(row["ecosystem"], row["name"], row["version"])
        package_rows.append(
            {
                "SPDXID": package_id,
                "name": row["name"],
                "versionInfo": row["version"],
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": _purl(
                            row["ecosystem"], row["name"], row["version"]
                        ),
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )

    files: list[dict[str, Any]] = []
    for path in sorted((Path(p).resolve() for p in (include_files or [])), key=str):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"SBOM input is not a regular file: {path}")
        try:
            relative = path.relative_to(project_root).as_posix()
        except ValueError as exc:
            raise ValueError(f"SBOM input outside project root: {path}") from exc
        files.append(
            {
                "SPDXID": _spdx_id("File", relative, _sha256(path)[:12]),
                "fileName": relative,
                "checksums": [{"algorithm": "SHA256", "checksumValue": _sha256(path)}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = f"{epoch}"  # stable input marker; converted below for SPDX
    import datetime

    created = datetime.datetime.fromtimestamp(
        int(created), datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-{project_version}",
        "documentNamespace": f"{SBOM_NAMESPACE}/{project_name}-{project_version}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: sysspectogram-sbom"],
        },
        "packages": package_rows,
        "files": files,
        "relationships": relationships,
    }


def write_sbom(project_root: Path, output: Path, **kwargs: Any) -> Path:
    payload = generate_sbom(project_root, **kwargs)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
