#!/usr/bin/env python3
"""Bump project version in our packages only — never rewrite third-party crate versions in Cargo.lock.

Usage:
  python scripts/bump_versions.py 1.3.3
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OUR_CARGO_LOCK_PACKAGES = (
    "sysspectogram-control-center",
    "sysspectogram-fleet-center",
    "sysspectogram-agent",
    "sysspectogram-helper",
)


def _sub_file(path: Path, pattern: str, repl: str, *, count: int = 0) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=count, flags=re.M)
    if n == 0:
        raise SystemExit(f"no match in {path}: {pattern}")
    path.write_text(new, encoding="utf-8")
    print(f"ok {path.relative_to(ROOT)} ({n})")


def _set_json_version(path: Path, version: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"ok {path.relative_to(ROOT)}")


def _set_cargo_lock_our_packages(lock: Path, version: str) -> None:
    text = lock.read_text(encoding="utf-8")
    changed = 0
    for name in OUR_CARGO_LOCK_PACKAGES:
        pat = rf'(name = "{re.escape(name)}"\n)version = "[^"]+"'
        text2, n = re.subn(pat, rf'\1version = "{version}"', text, count=1)
        if n:
            text = text2
            changed += n
            print(f"ok {lock.relative_to(ROOT)}::{name}")
    if changed:
        lock.write_text(text, encoding="utf-8")


def _set_package_lock(path: Path, version: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = version
    pkgs = data.get("packages") or {}
    root = pkgs.get("")
    if isinstance(root, dict):
        root["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"ok {path.relative_to(ROOT)}")


def bump(old: str, new: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", new):
        raise SystemExit(f"bad version: {new}")

    _sub_file(ROOT / "pyproject.toml", rf'(?m)^version = "{re.escape(old)}"', f'version = "{new}"', count=1)
    _sub_file(
        ROOT / "sysspectogram" / "__init__.py",
        rf'__version__\s*=\s*"{re.escape(old)}"',
        f'__version__ = "{new}"',
        count=1,
    )
    for rel in (
        "control-center/src-tauri/Cargo.toml",
        "agent/Cargo.toml",
        "helper/Cargo.toml",
        "fleet-center/src-tauri/Cargo.toml",
    ):
        _sub_file(ROOT / rel, rf'(?m)^version = "{re.escape(old)}"', f'version = "{new}"', count=1)

    _set_json_version(ROOT / "control-center" / "package.json", new)
    _set_json_version(ROOT / "fleet-center" / "package.json", new)
    _set_json_version(ROOT / "control-center" / "src-tauri" / "tauri.conf.json", new)
    _set_json_version(ROOT / "fleet-center" / "src-tauri" / "tauri.conf.json", new)

    _sub_file(ROOT / "packaging" / "aur" / "PKGBUILD", rf"pkgver={re.escape(old)}", f"pkgver={new}", count=1)

    chg = ROOT / "packaging" / "debian" / "changelog"
    text = chg.read_text(encoding="utf-8")
    if f"sysspectogram ({new}-1)" not in text:
        entry = (
            f"sysspectogram ({new}-1) unstable; urgency=medium\n"
            f"\n"
            f"  * Release {new}.\n"
            f"\n"
            f" -- SysSpectogram <noreply@sysspectogram.local>  Mon, 26 Oct 2026 23:30:00 +0300\n"
            f"\n"
        )
        chg.write_text(entry + text, encoding="utf-8")
        print(f"ok packaging/debian/changelog")

    for lock in (
        ROOT / "control-center" / "src-tauri" / "Cargo.lock",
        ROOT / "fleet-center" / "src-tauri" / "Cargo.lock",
        ROOT / "agent" / "Cargo.lock",
        ROOT / "helper" / "Cargo.lock",
    ):
        if lock.is_file():
            _set_cargo_lock_our_packages(lock, new)

    for plock in (
        ROOT / "control-center" / "package-lock.json",
        ROOT / "fleet-center" / "package-lock.json",
    ):
        if plock.is_file():
            _set_package_lock(plock, new)

    tag = f"v{new}"
    i18n = ROOT / "control-center" / "src" / "lib" / "i18n.ts"
    if i18n.is_file():
        _sub_file(
            i18n,
            r"export const APP_VERSION_TAG = 'v[^']+'",
            f"export const APP_VERSION_TAG = '{tag}'",
            count=1,
        )

    for script in ("scripts/friend-day0.sh", "scripts/install-helper-from-release.sh"):
        p = ROOT / script
        t = p.read_text(encoding="utf-8")
        t2 = re.sub(r'TAG="\$\{1:-v[0-9.]+\}"', f'TAG="${{1:-{tag}}}"', t, count=1)
        if t2 == t:
            raise SystemExit(f"TAG default not updated in {script}")
        # comment examples that hardcode a tag
        t2 = re.sub(r"v\d+\.\d+\.\d+", tag, t2)
        p.write_text(t2, encoding="utf-8")
        print(f"ok {script}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("new_version")
    ap.add_argument("--from", dest="old", default=None, help="previous version (default: pyproject)")
    args = ap.parse_args()
    if args.old:
        old = args.old
    else:
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        old = str(tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
    if old == args.new_version:
        print("already at", old, file=sys.stderr)
        return 1
    bump(old, args.new_version)
    print("bumped", old, "->", args.new_version)
    print("next: python scripts/check_versions.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
