#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python - <<'PY'
from pathlib import Path
import re
import tomllib

root = Path(".")
pyproject = tomllib.loads((root / "pyproject.toml").read_text())
version = pyproject["project"]["version"]
pkgbuild = (root / "packaging/aur/PKGBUILD").read_text()
changelog = (root / "packaging/debian/changelog").read_text()
assert f"pkgver={version}" in pkgbuild
assert re.search(rf"sysspectogram \({re.escape(version)}-1\)", changelog)
for path in (
    "packaging/distro/sysspectogram-agent.service",
    "packaging/distro/sysspectogram-guard.service",
    "packaging/distro/sysspectogram-monitor.service",
):
    text = (root / path).read_text()
    assert "ExecStart=" in text
    assert "UMask=0077" in text
    assert "ReadWritePaths=" in text or "StateDirectory=" in text
    if path.endswith(("guard.service", "monitor.service")):
        assert "User=sysspectogram" in text
        assert "Group=sysspectogram" in text
print(f"package metadata OK version={version}")
for path in (
    "packaging/debian/control",
    "packaging/debian/rules",
    "packaging/debian/changelog",
):
    assert (root / path).is_file(), path
print("Debian metadata OK")
PY

if command -v makepkg >/dev/null 2>&1; then
  (cd packaging/aur && makepkg --printsrcinfo >/dev/null)
  echo "AUR SRCINFO OK"
fi
if command -v dpkg-buildpackage >/dev/null 2>&1; then
  dpkg-parsechangelog -l packaging/debian/changelog >/dev/null
  echo "Debian changelog OK"
fi
