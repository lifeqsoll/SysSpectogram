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
    wheel_path = cache / wheel_name
    _download(assets[wheel_name], wheel_path)
    steps.append({"step": "download_wheel", "ok": True, "file": wheel_name})

    if "SHA256SUMS" in assets:
        sums = _get(assets["SHA256SUMS"]).decode()
        for line in sums.splitlines():
            if wheel_name in line:
                exp = line.split()[0].lower()
                got = _sha256(wheel_path)
                if got != exp:
                    return {"ok": False, "error": f"sha256 wheel mismatch {got} != {exp}"}
                steps.append({"step": "sha256_wheel", "ok": True})
                break

    agent_key = "sysspectogram-agent-x86_64-linux-musl"
    if agent_key not in assets:
        return {"ok": False, "error": "no musl agent on release", "steps": steps}
    agent_path = cache / agent_key
    _download(assets[agent_key], agent_path)
    steps.append({"step": "download_agent", "ok": True})
    if f"{agent_key}.sha256" in assets:
        line = _get(assets[f"{agent_key}.sha256"]).decode().strip()
        exp = line.split()[0].lower()
        if _sha256(agent_path) != exp:
            return {"ok": False, "error": "sha256 agent mismatch", "steps": steps}
        steps.append({"step": "sha256_agent", "ok": True})

    venv = home / ".venv"
    py = venv / "bin" / "python"
    if not py.is_file():
        r = subprocess.run(["python3", "-m", "venv", str(venv)], check=False)
        if r.returncode != 0:
            return {"ok": False, "error": "venv failed", "steps": steps}
        steps.append({"step": "venv", "ok": True})
    pip = venv / "bin" / "pip"
    r = subprocess.run(
        [str(pip), "install", "--upgrade", "pip", "wheel", str(wheel_path)],
        check=False,
    )
    if r.returncode != 0:
        return {"ok": False, "error": "pip install failed", "steps": steps}
    steps.append({"step": "pip_install", "ok": True})

    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / "sysspectogram-agent"
    shutil.copy2(agent_path, dest)
    dest.chmod(0o755)
    steps.append({"step": "agent_bin", "ok": True, "path": str(dest)})

    cfg = home / "configs"
    cfg.mkdir(parents=True, exist_ok=True)
    for name in ("default.yaml", "schema.yaml"):
        if not (cfg / name).is_file():
            url = f"https://raw.githubusercontent.com/{DEFAULT_REPO}/{tag}/configs/{name}"
            try:
                _download(url, cfg / name)
                steps.append({"step": f"config_{name}", "ok": True})
            except Exception as exc:  # noqa: BLE001
                steps.append({"step": f"config_{name}", "ok": False, "detail": str(exc)})

    return {"ok": True, "tag": tag, "home": str(home), "steps": steps}
