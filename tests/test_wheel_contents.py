"""Wheel/sdist must ship sysspectogram/web/static for the embedded web UI."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "sysspectogram" / "web" / "static"
PYPROJECT = ROOT / "pyproject.toml"
MANIFEST = ROOT / "MANIFEST.in"

REQUIRED_STATIC = (
    "index.html",
    "app.js",
    "styles.css",
    "chart.umd.min.js",
)


def _package_data_globs() -> list[str]:
    text = PYPROJECT.read_text(encoding="utf-8")
    block = re.search(
        r"\[tool\.setuptools\.package-data\]\s*\nsysspectogram\s*=\s*\[(.*?)\]",
        text,
        re.S,
    )
    assert block, "package-data block for sysspectogram"
    return re.findall(r'"([^"]+)"', block.group(1))


def _glob_covers_static(glob_pattern: str, rel_name: str) -> bool:
    """Match setuptools-style globs under sysspectogram/."""
    if glob_pattern.endswith("/*"):
        prefix = glob_pattern[:-1]
        return rel_name.startswith(prefix)
    return glob_pattern == rel_name


@pytest.mark.parametrize("name", REQUIRED_STATIC)
def test_web_static_files_exist_in_source_tree(name: str):
    path = STATIC_DIR / name
    assert path.is_file(), f"missing source static file: {path}"


def test_pyproject_package_data_covers_web_static():
    globs = _package_data_globs()
    covered = any(g.startswith("web/static") for g in globs)
    assert covered, f"web/static not in package-data: {globs}"
    for name in REQUIRED_STATIC:
        rel = f"web/static/{name}"
        assert any(_glob_covers_static(g, rel) for g in globs), (
            f"package-data globs {globs!r} do not cover {rel}"
        )


def test_manifest_in_includes_web_static():
    assert MANIFEST.is_file(), "MANIFEST.in required for sdist static files"
    text = MANIFEST.read_text(encoding="utf-8")
    assert "sysspectogram/web/static" in text


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory) -> Path | None:
    if shutil.which("python3") is None:
        return None
    out = tmp_path_factory.mktemp("wheel-build")
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"wheel build unavailable: {proc.stderr[-500:]}")
    wheels = sorted(out.glob("sysspectogram-*.whl"))
    if not wheels:
        pytest.skip("no wheel produced")
    return wheels[-1]


def test_wheel_contains_web_static(built_wheel: Path | None):
    if built_wheel is None:
        pytest.skip("no wheel")
    with zipfile.ZipFile(built_wheel) as zf:
        names = set(zf.namelist())
    missing = [
        f"sysspectogram/web/static/{name}"
        for name in REQUIRED_STATIC
        if f"sysspectogram/web/static/{name}" not in names
    ]
    assert not missing, f"wheel missing static files: {missing}"
