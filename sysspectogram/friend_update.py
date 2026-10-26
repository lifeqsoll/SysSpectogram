"""Download signed wheel + musl agent from GitHub Releases into user home (ADR 0005)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from sysspectogram.config import state_root

DEFAULT_REPO = os.environ.get("SYSSPECTOGRAM_GITHUB_REPO", "lifeqsoll/SysSpectogram")
UA = "SysSpectogram-FriendUpdate/1.1"


def _home() -> Path:
    return state_root()


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 — release URLs only
        return resp.read()


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(_get(url))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_minisign(pub: Path, data: Path, sig: Path) -> None:
    r = subprocess.run(
        ["minisign", "-Vm", str(data), "-p", str(pub), "-x", str(sig)],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "minisign failed").strip()
        raise RuntimeError(err)


def _version_tuple(ver: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in str(ver).strip().lstrip("v").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts or (0,))


def _embedded_minisign_pub() -> Path | None:
    """Resolve embedded minisign pubkey (wheel package data, then checkout keys/)."""
    # 1) Same-tree / wheel package data next to this module (day0 pip installs).
    local = Path(__file__).resolve().parent / "resources" / "keys" / "SysSpectogram.minisign.pub"
    if local.is_file():
        return local
    # 2) Editable monorepo checkout: control-center keys (same file as Tauri embed).
    checkout = (
        Path(__file__).resolve().parents[1]
        / "control-center"
        / "src-tauri"
        / "keys"
        / "SysSpectogram.minisign.pub"
    )
    if checkout.is_file():
        return checkout
    # 3) importlib.resources (zipimport / alternate layouts).
    try:
        from importlib import resources

        cand = resources.files("sysspectogram").joinpath(
            "resources", "keys", "SysSpectogram.minisign.pub"
        )
        with resources.as_file(cand) as path:
            if not path.is_file():
                return None
            # Materialize outside the context (zip temp may vanish after `with`).
            data = path.read_bytes()
        cache = state_root() / "state" / "bootstrap-cache" / "SysSpectogram.minisign.pub"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
        return cache
    except (ImportError, FileNotFoundError, TypeError, OSError, ModuleNotFoundError):
        pass
    return None


def update_stack(tag: str) -> dict[str, Any]:
    tag = tag.strip()
    if not tag.startswith("v"):
        tag = f"v{tag}"
    home = _home()
    cache = home / "state" / "bootstrap-cache"
    cache.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []

    release = json.loads(
        _get(f"https://api.github.com/repos/{DEFAULT_REPO}/releases/tags/{tag}").decode()
    )
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets") or []}
    steps.append({"step": "release", "ok": True, "tag": tag})

    wheel_name = next((n for n in assets if n.endswith(".whl")), None)
    if not wheel_name:
        return {"ok": False, "error": "no .whl on release", "assets": list(assets)}
    if "SHA256SUMS" not in assets:
        return {"ok": False, "error": "release missing SHA256SUMS (required)", "steps": steps}
    wheel_path = cache / wheel_name
    _download(assets[wheel_name], wheel_path)
    steps.append({"step": "download_wheel", "ok": True, "file": wheel_name})

    sums = _get(assets["SHA256SUMS"]).decode()
    wheel_ok = False
    for line in sums.splitlines():
        if wheel_name in line:
            exp = line.split()[0].lower()
            got = _sha256(wheel_path)
            if got != exp:
                return {"ok": False, "error": f"sha256 wheel mismatch {got} != {exp}"}
            steps.append({"step": "sha256_wheel", "ok": True})
            wheel_ok = True
            break
    if not wheel_ok:
        return {"ok": False, "error": f"SHA256SUMS has no entry for {wheel_name}", "steps": steps}

    agent_key = "sysspectogram-agent-x86_64-linux-musl"
    if agent_key not in assets:
        return {"ok": False, "error": "no musl agent on release", "steps": steps}
    if f"{agent_key}.sha256" not in assets:
        return {"ok": False, "error": "release missing agent .sha256 (required)", "steps": steps}
    agent_path = cache / agent_key
    _download(assets[agent_key], agent_path)
    steps.append({"step": "download_agent", "ok": True})
    line = _get(assets[f"{agent_key}.sha256"]).decode().strip()
    exp = line.split()[0].lower()
    if _sha256(agent_path) != exp:
        return {"ok": False, "error": "sha256 agent mismatch", "steps": steps}
    steps.append({"step": "sha256_agent", "ok": True})

    # Embedded pubkey only (ADR 0005) — never download pubkey from the release.
    pub = _embedded_minisign_pub()
    if pub is None or not pub.is_file():
        return {
            "ok": False,
            "error": "embedded SysSpectogram.minisign.pub missing from install tree",
            "steps": steps,
        }
    agent_sig_name = f"{agent_key}.minisig"
    wheel_sig_name = f"{wheel_name}.minisig"
    if agent_sig_name not in assets or wheel_sig_name not in assets:
        return {
            "ok": False,
            "error": "release missing required .minisig (agent and wheel); refuse unsigned update",
            "steps": steps,
        }
    # Refuse version downgrade when current install reports a version.
    try:
        from sysspectogram import __version__ as cur_ver
    except ImportError as exc:
        return {
            "ok": False,
            "error": f"cannot read installed version for downgrade check: {exc}",
            "steps": steps,
        }
    want = tag.lstrip("v")
    try:
        if _version_tuple(want) < _version_tuple(str(cur_ver)):
            return {
                "ok": False,
                "error": f"refuse downgrade {cur_ver} → {want}",
                "steps": steps,
            }
    except (TypeError, ValueError) as exc:
        return {
            "ok": False,
            "error": f"cannot compare versions for downgrade check: {exc}",
            "steps": steps,
        }
    sig_agent = cache / "agent.minisig"
    _download(assets[agent_sig_name], sig_agent)
    try:
        _verify_minisign(pub, agent_path, sig_agent)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"minisign agent: {exc}", "steps": steps}
    steps.append({"step": "minisign_agent", "ok": True})
    sig_wheel = cache / "wheel.minisig"
    _download(assets[wheel_sig_name], sig_wheel)
    try:
        _verify_minisign(pub, wheel_path, sig_wheel)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"minisign wheel: {exc}", "steps": steps}
    steps.append({"step": "minisign_wheel", "ok": True})
    venv = home / ".venv"
    py = venv / "bin" / "python"
    if not py.is_file():
        r = subprocess.run(
            ["python3", "-m", "venv", str(venv)],
            check=False,
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "venv failed").strip()
            return {"ok": False, "error": f"venv failed: {err}", "steps": steps}
        steps.append({"step": "venv", "ok": True})
    # Always `python -m pip` — venv/bin/pip shebang breaks after the tree is moved.
    # capture_output: pip must not pollute stdout (CC parses CLI stdout as JSON).
    r = subprocess.run(
        [str(py), "-m", "pip", "install", "--upgrade", "pip", "wheel", str(wheel_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "pip install failed").strip()
        return {"ok": False, "error": f"pip install failed: {err[:500]}", "steps": steps}
    steps.append({"step": "pip_install", "ok": True})

    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / "sysspectogram-agent"
    shutil.copy2(agent_path, dest)
    dest.chmod(0o755)
    steps.append({"step": "agent_bin", "ok": True, "path": str(dest)})

    cfg = home / "configs"
    cfg.mkdir(parents=True, exist_ok=True)
    if not (cfg / "default.yaml").is_file():
        steps.append(
            {
                "step": "config_default.yaml",
                "ok": False,
                "detail": "unsigned raw GitHub config fetch disabled; unpack configs from release tarball",
            }
        )

    return {"ok": True, "tag": tag, "home": str(home), "steps": steps}
