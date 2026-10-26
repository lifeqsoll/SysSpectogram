#!/usr/bin/env python3
"""Fail if package / Tauri / Cargo / __version__ / locks disagree (optional: GITHUB_REF tag)."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

OUR_LOCK_PACKAGES = {
    "control-center/src-tauri/Cargo.lock": "sysspectogram-control-center",
    "fleet-center/src-tauri/Cargo.lock": "sysspectogram-fleet-center",
    "agent/Cargo.lock": "sysspectogram-agent",
    "helper/Cargo.lock": "sysspectogram-helper",
}


def _cargo_lock_pkg_version(text: str, name: str) -> str | None:
    m = re.search(rf'name = "{re.escape(name)}"\nversion = "([^"]+)"', text)
    return m.group(1) if m else None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    expected = str(pyproject["project"]["version"])
    tag = f"v{expected}"

    init = (root / "sysspectogram" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init)
    if not m or m.group(1) != expected:
        print(f"__init__.__version__ mismatch: want {expected}, got {m.group(1) if m else None}", file=sys.stderr)
        return 1

    cargo = (root / "control-center" / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    cm = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)
    if not cm or cm.group(1) != expected:
        print(f"Cargo.toml version mismatch: want {expected}, got {cm.group(1) if cm else None}", file=sys.stderr)
        return 1

    tauri = json.loads((root / "control-center" / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    if str(tauri.get("version")) != expected:
        print(f"tauri.conf.json version mismatch: want {expected}, got {tauri.get('version')}", file=sys.stderr)
        return 1

    pkg = json.loads((root / "control-center" / "package.json").read_text(encoding="utf-8"))
    if str(pkg.get("version")) != expected:
        print(f"package.json version mismatch: want {expected}, got {pkg.get('version')}", file=sys.stderr)
        return 1

    pkgbuild = (root / "packaging" / "aur" / "PKGBUILD").read_text(encoding="utf-8")
    if f"pkgver={expected}" not in pkgbuild:
        print(f"PKGBUILD pkgver missing {expected}", file=sys.stderr)
        return 1

    changelog = (root / "packaging" / "debian" / "changelog").read_text(encoding="utf-8")
    if f"sysspectogram ({expected}-1)" not in changelog:
        print(f"debian/changelog missing ({expected}-1)", file=sys.stderr)
        return 1

    for rel in ("agent/Cargo.toml", "helper/Cargo.toml", "fleet-center/src-tauri/Cargo.toml"):
        cargo_txt = (root / rel).read_text(encoding="utf-8")
        cm2 = re.search(r'^version\s*=\s*"([^"]+)"', cargo_txt, re.M)
        if not cm2 or cm2.group(1) != expected:
            print(f"{rel} version mismatch: want {expected}, got {cm2.group(1) if cm2 else None}", file=sys.stderr)
            return 1

    fc_pkg = json.loads((root / "fleet-center" / "package.json").read_text(encoding="utf-8"))
    if str(fc_pkg.get("version")) != expected:
        print(f"fleet-center/package.json version mismatch: want {expected}, got {fc_pkg.get('version')}", file=sys.stderr)
        return 1

    fc_tauri = json.loads((root / "fleet-center" / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    if str(fc_tauri.get("version")) != expected:
        print(f"fleet-center tauri.conf.json version mismatch: want {expected}, got {fc_tauri.get('version')}", file=sys.stderr)
        return 1

    for rel, name in OUR_LOCK_PACKAGES.items():
        lock = root / rel
        if not lock.is_file():
            print(f"missing {rel}", file=sys.stderr)
            return 1
        got = _cargo_lock_pkg_version(lock.read_text(encoding="utf-8"), name)
        if got != expected:
            print(f"{rel}::{name} version mismatch: want {expected}, got {got}", file=sys.stderr)
            return 1

    for rel in ("control-center/package-lock.json", "fleet-center/package-lock.json"):
        data = json.loads((root / rel).read_text(encoding="utf-8"))
        got = str(data.get("version") or "")
        root_pkg = (data.get("packages") or {}).get("") or {}
        got_root = str(root_pkg.get("version") or "")
        if got != expected or got_root != expected:
            print(
                f"{rel} version mismatch: want {expected}, got version={got} packages['']={got_root}",
                file=sys.stderr,
            )
            return 1

    for script, patterns in (
        ("scripts/friend-day0.sh", (f'TAG="${{TAG:-{tag}}}"', f'TAG="${{1:-{tag}}}"')),
        ("scripts/install-helper-from-release.sh", (f'TAG="${{1:-{tag}}}"',)),
    ):
        text = (root / script).read_text(encoding="utf-8")
        if not any(p in text for p in patterns):
            print(f"{script} default TAG missing one of {patterns}", file=sys.stderr)
            return 1

    i18n = (root / "control-center" / "src" / "lib" / "i18n.ts").read_text(encoding="utf-8")
    m_i18n = re.search(r"export const APP_VERSION_TAG = '(v\d+\.\d+\.\d+)'", i18n)
    if not m_i18n or m_i18n.group(1) != tag:
        print(
            f"i18n.ts APP_VERSION_TAG mismatch: want {tag}, got {m_i18n.group(1) if m_i18n else None}",
            file=sys.stderr,
        )
        return 1
    # No other hard-coded vX.Y.Z outside the constant / template uses of APP_VERSION_TAG
    hard = set(re.findall(r"v\d+\.\d+\.\d+", i18n))
    if hard - {tag}:
        print(f"i18n.ts unexpected tags {sorted(hard - {tag})} (want only {tag})", file=sys.stderr)
        return 1

    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        ref_tag = ref.rsplit("/", 1)[-1]
        want = f"v{expected}"
        if ref_tag != want:
            print(f"tag {ref_tag} does not match project version {want}", file=sys.stderr)
            return 1

    print(f"versions OK {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
