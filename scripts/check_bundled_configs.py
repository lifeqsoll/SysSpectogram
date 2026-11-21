#!/usr/bin/env python3
"""Fail if sysspectogram/resources/configs drifts from repo configs/."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_FILES = (
    "default.yaml",
    "schema.yaml",
    "denylist.txt",
    "demo_interactive.yaml",
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    tree = root / "configs"
    bundled = root / "sysspectogram" / "resources" / "configs"
    if not tree.is_dir() or not bundled.is_dir():
        print(f"missing configs dirs: tree={tree.is_dir()} bundled={bundled.is_dir()}", file=sys.stderr)
        return 1
    for rel in ROOT_FILES:
        a = tree / rel
        b = bundled / rel
        if not a.is_file() or not b.is_file():
            print(f"missing {rel}: tree={a.is_file()} bundled={b.is_file()}", file=sys.stderr)
            return 1
        if a.read_bytes() != b.read_bytes():
            print(
                f"mismatch {rel}: update sysspectogram/resources/configs from configs/",
                file=sys.stderr,
            )
            return 1
    tree_sc = sorted(p.name for p in (tree / "scenarios").glob("*.yaml"))
    bund_sc = sorted(p.name for p in (bundled / "scenarios").glob("*.yaml"))
    if tree_sc != bund_sc:
        print(f"scenario list mismatch: {tree_sc!r} vs {bund_sc!r}", file=sys.stderr)
        return 1
    for name in tree_sc:
        if (tree / "scenarios" / name).read_bytes() != (bundled / "scenarios" / name).read_bytes():
            print(f"mismatch scenarios/{name}", file=sys.stderr)
            return 1
    print("bundled configs match configs/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
