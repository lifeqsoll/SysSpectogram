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
README = ROOT / "README.md"
README_RU = ROOT / "README_RU.md"
FRIEND = ROOT / "docs" / "FRIEND.md"
RELEASE_YML = ROOT / ".github" / "workflows" / "release-assets.yml"
PYPROJECT = ROOT / "pyproject.toml"

# Subcommands that appear in install docs (must exist as top-level or nested).
_DOC_CLI_RE = re.compile(
    r"python(?:3)?\s+-m\s+sysspectogram\s+([a-z][\w-]*(?:\s+[a-z][\w-]*){0,3})",
    re.I,
)

_DOC_FLAG_IN_CLI_RE = re.compile(
    r"python(?:3)?\s+-m\s+sysspectogram[^\n`]*?(--[a-z][\w-]*)",
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

_MD_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+)$", re.M)

_MD_LINK_ANCHOR_RE = re.compile(r"\]\((#[\w-]+)\)")

_VERSION_TAG_RE = re.compile(r"\bv\d+\.\d+\.\d+\b")

_CURL_PIPE_FRIEND_RE = re.compile(
    r"curl[^\n|]*\|\s*(?:sudo\s+)?bash[^\n]*friend-day0|friend-day0[^\n]*\|\s*bash",
    re.I,
)


def _project_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "pyproject version"
    return m.group(1)


def _cli_known_paths() -> set[str]:
    from sysspectogram.cli import build_parser

    parser = build_parser()
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


def _cli_option_strings() -> set[str]:
    from sysspectogram.cli import build_parser

    parser = build_parser()
    opts: set[str] = set()

    def walk(p: argparse.ArgumentParser) -> None:
        for action in p._actions:  # noqa: SLF001
            if action.option_strings:
                opts.update(action.option_strings)
            if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
                for sub in action.choices.values():
                    walk(sub)

    walk(parser)
    return opts


def _cli_top_level_from_source() -> set[str]:
    text = (ROOT / "sysspectogram" / "cli.py").read_text(encoding="utf-8")
    return set(re.findall(r'\n\s+\w+_?p?\s*=\s*sub\.add_parser\(\s*"([^"]+)"', text)) | set(
        re.findall(r'sub\.add_parser\(\s*"([^"]+)"', text)
    )


def _install_blobs() -> list[str]:
    return [
        INSTALL.read_text(encoding="utf-8"),
        INSTALL_RU.read_text(encoding="utf-8"),
        INSTALL_AI.read_text(encoding="utf-8"),
    ]


def _heading_structure(md: str) -> list[tuple[int, str]]:
    """Level + structural key (numbers / A–E / anonymous ## order)."""
    out: list[tuple[int, str]] = []
    anon = 0
    for m in _MD_HEADING_RE.finditer(md):
        level = len(m.group(1))
        title = m.group(2).strip()
        num = re.match(r"^(\d+(?:\.\d+)*)", title)
        if num:
            out.append((level, num.group(1)))
            continue
        letter = re.match(r"^([A-E])\.", title)
        if letter:
            out.append((level, letter.group(1)))
            continue
        if level == 2:
            anon += 1
            out.append((level, f"h2-{anon}"))
        else:
            out.append((level, f"h{level}-child"))
    return out


def _github_heading_anchors(md: str) -> set[str]:
    anchors: set[str] = set()

    def slug(text: str) -> str:
        s = text.strip().lower()
        s = re.sub(r"[^\w\s-]", "", s, flags=re.U)
        s = re.sub(r"\s+", "-", s)
        return s.strip("-")

    for m in _MD_HEADING_RE.finditer(md):
        anchors.add("#" + slug(m.group(2)))
    return anchors


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
    en = README.read_text(encoding="utf-8")
    ru = README_RU.read_text(encoding="utf-8")
    assert "docs/INSTALL.md" in en
    assert "docs/INSTALL_WITH_AI.md" in en
    assert "docs/INSTALL_RU.md" in ru
    assert "docs/INSTALL_WITH_AI.md" in ru


def test_install_uses_latest_tag_placeholder(install_text: str):
    assert "<LATEST_TAG>" in install_text
    assert "releases/latest" in install_text


def test_install_with_ai_tagged_raw_urls_not_main():
    ai = INSTALL_AI.read_text(encoding="utf-8")
    assert "<LATEST_TAG>" in ai
    assert "raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/" in ai
    assert "SysSpectogram/main/docs/INSTALL" not in ai


def test_ai_doc_headings_exist_in_install(install_text: str):
    ai = INSTALL_AI.read_text(encoding="utf-8")
    m = _HEADING_BLOCK_RE.search(ai)
    assert m, "INSTALL_WITH_AI.md missing headings checklist block"
    headings = re.findall(r"- `([^`]+)`", m.group(1))
    assert headings, "no headings listed"
    missing = [h for h in headings if h not in install_text]
    assert not missing, f"headings missing from INSTALL.md: {missing}"


def test_doc_cli_invocations_use_build_parser(install_text: str):
    known = _cli_known_paths()
    tops = _cli_top_level_from_source()
    assert "configure" in tops and "home" in tops

    unknown: list[str] = []
    for blob in _install_blobs():
        for m in _DOC_CLI_RE.finditer(blob):
            parts = m.group(1).split()
            if not parts:
                continue
            path = " ".join(parts[: min(3, len(parts))])
            # Trim trailing flags mistaken as words
            while path and path.split()[-1].startswith("-"):
                path = " ".join(path.split()[:-1])
            if not path:
                continue
            if path not in known:
                # allow top-level only if doc shows partial path
                if parts[0] not in tops:
                    unknown.append(m.group(0))
                elif len(parts) >= 2:
                    # second token might be subcommand — must exist in known paths prefix
                    pref = " ".join(parts[:2])
                    if not any(k == pref or k.startswith(pref + " ") for k in known):
                        if not parts[1].startswith("-"):
                            unknown.append(m.group(0))
    assert not unknown, f"unknown CLI in install docs: {unknown}"


def test_doc_cli_flags_exist_in_argparse():
    opts = _cli_option_strings()
    missing: list[str] = []
    for blob in _install_blobs():
        for m in _DOC_FLAG_IN_CLI_RE.finditer(blob):
            flag = m.group(1)
            if flag not in opts:
                missing.append(flag)
    assert not missing, f"flags in install docs not in CLI --help tree: {sorted(set(missing))}"


def test_install_en_ru_heading_parity():
    en = _heading_structure(INSTALL.read_text(encoding="utf-8"))
    ru = _heading_structure(INSTALL_RU.read_text(encoding="utf-8"))
    assert len(en) == len(ru), f"heading count EN={len(en)} RU={len(ru)}"
    for (le, ke), (lr, kr) in zip(en, ru, strict=True):
        assert le == lr, f"level mismatch {ke} vs {kr}"
        assert ke == kr, f"section key mismatch: EN {ke!r} vs RU {kr!r}"


def test_install_internal_anchor_links(install_text: str):
    ru = INSTALL_RU.read_text(encoding="utf-8")
    en_anchors = _github_heading_anchors(install_text)
    ru_anchors = _github_heading_anchors(ru)
    for blob, anchors in ((install_text, en_anchors), (ru, ru_anchors)):
        for m in _MD_LINK_ANCHOR_RE.finditer(blob):
            href = m.group(1)
            assert href in anchors, f"broken anchor {href}"


def test_no_curl_pipe_friend_day0_in_readme_or_friend():
    for path in (README, README_RU, FRIEND):
        text = path.read_text(encoding="utf-8")
        assert not _CURL_PIPE_FRIEND_RE.search(text), f"curl|bash friend-day0 forbidden in {path.name}"


def test_readme_friend_use_latest_tag_not_stale_install_snippets():
    current = _project_version()
    for path in (README, README_RU, FRIEND):
        text = path.read_text(encoding="utf-8")
        assert "<LATEST_TAG>" in text or "releases/latest" in text
        # Headless install snippets must not hardcode old tags (release note links OK elsewhere)
        for m in _VERSION_TAG_RE.finditer(text):
            tag = m.group(0)
            # allow current version and release doc links only when not in friend-day0 download block
            start = max(0, m.start() - 80)
            ctx = text[start : m.end() + 80]
            if "friend-day0" in ctx or "releases/download" in ctx:
                assert tag == f"v{current}", f"stale tag {tag} in install snippet ({path.name})"


def test_doc_release_assets_listed_in_workflow(release_yml_text: str, install_text: str):
    combined = install_text + "\n" + INSTALL_RU.read_text(encoding="utf-8")
    missing = []
    for name in _ASSET_NAMES:
        if name not in combined:
            continue
        if name not in release_yml_text and name.replace(".minisig", "") not in release_yml_text:
            if ".minisig" in name and "minisign" in release_yml_text:
                continue
            missing.append(name)
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


_DESKTOP_TAG_IN_FILENAME_RE = re.compile(
    r"Control_Center_\$\{TAG\}_|Control_Center_\$\{tag\}_",
    re.I,
)


def test_install_desktop_urls_use_ver_not_tag_in_filename():
    bad: list[str] = []
    for path in (INSTALL, INSTALL_RU):
        text = path.read_text(encoding="utf-8")
        if _DESKTOP_TAG_IN_FILENAME_RE.search(text):
            bad.append(path.name)
        if "VER=\"${TAG#v}\"" not in text and "VER=${TAG#v}" not in text:
            bad.append(f"{path.name} (missing VER=${{TAG#v}})")
        if "Control_Center_${VER}_" not in text:
            bad.append(f"{path.name} (missing Control_Center_${{VER}}_)")
    assert not bad, f"desktop asset naming: {bad}"


def test_install_with_ai_desktop_version_without_v_prefix():
    ai = INSTALL_AI.read_text(encoding="utf-8")
    assert "without" in ai.lower() and "leading `v`" in ai
    assert "Control_Center_1." in ai or "1.4.0_amd64" in ai or "1.3.3_amd64" in ai
    assert "Control_Center_v1." not in ai
    assert "releases/download/${TAG}/" in INSTALL.read_text(encoding="utf-8")
