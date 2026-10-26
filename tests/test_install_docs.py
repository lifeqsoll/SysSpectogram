"""Keep INSTALL.md / INSTALL_RU.md / INSTALL_WITH_AI.md from rotting.

Extracts `python -m sysspectogram …` invocations and release asset basenames from
the install docs and checks them against the live CLI argparse tree and
`.github/workflows/release-assets.yml`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "docs" / "INSTALL.md"
INSTALL_RU = ROOT / "docs" / "INSTALL_RU.md"
INSTALL_AI = ROOT / "docs" / "INSTALL_WITH_AI.md"
RELEASE_YML = ROOT / ".github" / "workflows" / "release-assets.yml"

# Subcommands that appear in install docs (must exist as top-level or nested).
_DOC_CLI_RE = re.compile(
    r"python(?:3)?\s+-m\s+sysspectogram\s+([a-z][\w-]*(?:\s+[a-z][\w-]*){0,3})",
    re.I,
)

# Release asset basenames mentioned in docs (ignore globs / placeholders).
_ASSET_NAMES = (
    "friend-day0.sh",
    "friend-day0.sh.minisig",
    "install-helper-from-release.sh",
    "install-helper-from-release.sh.minisig",
    "sysspectogram-helper-x86_64-linux",
    "sysspectogram-helper-packaging.tgz",
    "sysspectogram-agent-x86_64-linux-musl",
    "SysSpectogram.minisign.pub",
    "SHA256SUMS.desktop",
    "SHA256SUMS.fleet-center",
)

_HEADING_BLOCK_RE = re.compile(
    r"Headings the agent may cite.*?:\n\n((?:- `[^`]+`\n)+)",
    re.S,
)


def _cli_known_paths() -> set[str]:
    from sysspectogram import cli as cli_mod

    parser = cli_mod.build_parser() if hasattr(cli_mod, "build_parser") else None
    if parser is None:
        # Fall back: invoke private builder by parsing help via Namespace walk.
        # cli.py uses a local `build` inside main — introspect add_parser names via source.
        text = (ROOT / "sysspectogram" / "cli.py").read_text(encoding="utf-8")
        tops = set(re.findall(r'add_parser\(\s*"([^"]+)"', text))
        return tops

    paths: set[str] = set()

    def walk(p: argparse.ArgumentParser, prefix: tuple[str, ...] = ()) -> None:
        for action in p._actions:  # noqa: SLF001
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
                for name, sub in action.choices.items():
                    path = prefix + (name,)
                    paths.add(" ".join(path))
                    walk(sub, path)

    walk(parser)
    return paths


def _cli_top_level_from_source() -> set[str]:
    text = (ROOT / "sysspectogram" / "cli.py").read_text(encoding="utf-8")
    # Only top-level: sub.add_parser("name"
    return set(re.findall(r'\n\s+\w+_?p?\s*=\s*sub\.add_parser\(\s*"([^"]+)"', text)) | set(
        re.findall(r'sub\.add_parser\(\s*"([^"]+)"', text)
    )


@pytest.fixture(scope="module")
def release_yml_text() -> str:
    return RELEASE_YML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def install_text() -> str:
    return INSTALL.read_text(encoding="utf-8")


def test_install_docs_exist():
    assert INSTALL.is_file()
    assert INSTALL_RU.is_file()
    assert INSTALL_AI.is_file()


def test_readme_points_at_install():
    en = (ROOT / "README.md").read_text(encoding="utf-8")
    ru = (ROOT / "README_RU.md").read_text(encoding="utf-8")
    assert "docs/INSTALL.md" in en
    assert "docs/INSTALL_WITH_AI.md" in en
    assert "docs/INSTALL_RU.md" in ru
    assert "docs/INSTALL_WITH_AI.md" in ru


def test_install_uses_latest_tag_placeholder(install_text: str):
    assert "<LATEST_TAG>" in install_text
    # Avoid hard-coding a specific release in the quick-start body.
    assert "releases/latest" in install_text


def test_ai_doc_headings_exist_in_install(install_text: str):
    ai = INSTALL_AI.read_text(encoding="utf-8")
    m = _HEADING_BLOCK_RE.search(ai)
    assert m, "INSTALL_WITH_AI.md missing headings checklist block"
    headings = re.findall(r"- `([^`]+)`", m.group(1))
    assert headings, "no headings listed"
    missing = [h for h in headings if h not in install_text]
    assert not missing, f"headings missing from INSTALL.md: {missing}"


def test_doc_cli_invocations_are_real(install_text: str):
    tops = _cli_top_level_from_source()
    assert "configure" in tops and "home" in tops and "protect" in tops and "guard" in tops

    blobs = [
        install_text,
        INSTALL_RU.read_text(encoding="utf-8"),
        INSTALL_AI.read_text(encoding="utf-8"),
    ]
    unknown: list[str] = []
    for blob in blobs:
        for m in _DOC_CLI_RE.finditer(blob):
            parts = m.group(1).split()
            if not parts:
                continue
            # First token must be a top-level subcommand.
            if parts[0] not in tops:
                unknown.append(m.group(0))
            # Nested home/protect/fleet/edge second token: best-effort from source.
            if len(parts) >= 2 and parts[0] in {"home", "protect", "fleet", "edge", "kirk"}:
                src = (ROOT / "sysspectogram" / "cli.py").read_text(encoding="utf-8")
                if f'"{parts[1]}"' not in src and f"'{parts[1]}'" not in src:
                    # allow flags mistaken as words — skip if looks like flag
                    if not parts[1].startswith("-"):
                        unknown.append(m.group(0))
    assert not unknown, f"unknown CLI in install docs: {unknown}"


def test_doc_release_assets_listed_in_workflow(release_yml_text: str, install_text: str):
    combined = install_text + "\n" + INSTALL_RU.read_text(encoding="utf-8")
    missing = []
    for name in _ASSET_NAMES:
        if name not in combined:
            continue  # doc may not mention every asset
        if name not in release_yml_text and name.replace(".minisig", "") not in release_yml_text:
            # .minisig often produced as "$asset.minisig" in a loop
            if ".minisig" in name and "minisig" in release_yml_text:
                continue
            missing.append(name)
    # Assets that docs do mention must appear in workflow somehow.
    mentioned = [n for n in _ASSET_NAMES if n in combined]
    assert mentioned, "install docs mention no known release assets"
    assert not missing, f"assets in docs but not in release-assets.yml: {missing}"


def test_friend_day0_and_helper_assets_in_workflow(release_yml_text: str):
    for name in (
        "friend-day0.sh",
        "install-helper-from-release.sh",
        "sysspectogram-helper-packaging.tgz",
        "sysspectogram-agent-x86_64-linux-musl",
    ):
        assert name in release_yml_text
