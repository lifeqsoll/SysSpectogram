#!/usr/bin/env python3
"""Generate the reproducible SPDX SBOM used by CI and release jobs."""

from __future__ import annotations

import argparse
from pathlib import Path

from sysspectogram.sbom import write_sbom


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--out", required=True, help="SPDX JSON output path")
    parser.add_argument(
        "--file",
        action="append",
        default=[],
        help="release file to hash in the SBOM; repeatable",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.out).resolve()
    write_sbom(
        root,
        output,
        include_files=[root / path for path in args.file],
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
