"""Stage a model in shadow, promote it to live after supply-chain verify, or roll back."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

_PHASES = ("off", "shadow", "live")


def read_ml_phase(path: str | Path) -> str:
    dest = Path(path)
    if not dest.is_file():
        return "off"
    try:
        payload = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "off"
    if not isinstance(payload, dict):
        return "off"
    phase = str(payload.get("phase") or "off").strip().lower()
    return phase if phase in _PHASES else "off"


def write_ml_phase(path: str | Path, phase: str) -> None:
    key = str(phase or "").strip().lower()
    if key not in _PHASES:
        raise ValueError(f"ml phase must be one of {', '.join(_PHASES)}")
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"phase": key}) + "\n", encoding="utf-8")


def stage(src: str | Path, shadow_dir: str | Path) -> Path:
    """Replace `shadow_dir` with a copy of the candidate artifact directory."""
    source = Path(src)
    if not source.is_dir():
        raise FileNotFoundError(source)
    dest = Path(shadow_dir)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, dest)
    return dest


def _previous_dir(live_dir: Path, previous_dir: str | Path | None) -> Path:
    if previous_dir is not None:
        return Path(previous_dir)
    return live_dir.parent / "ml-previous"


def promote(
    shadow_dir: str | Path,
    live_dir: str | Path,
    previous_dir: str | Path | None = None,
    *,
    supply_chain: dict[str, Any] | None = None,
) -> Path:
    """Verify the shadow tree, then rotate live → previous and shadow → live."""
    from sysspectogram.supply_chain import verify_artifacts

    shadow = Path(shadow_dir)
    live = Path(live_dir)
    if not shadow.is_dir():
        raise FileNotFoundError(shadow)
    policy = dict(supply_chain or {})
    verify_artifacts(
        shadow,
        enforce=bool(policy.get("enforce", False)),
        public_key=policy.get("public_key"),
        manifest_name=str(policy.get("manifest_name") or "artifacts.manifest.json"),
        signature_name=str(policy.get("signature_name") or "artifacts.manifest.json.minisig"),
    )
    previous = _previous_dir(live, previous_dir)
    if previous.exists():
        shutil.rmtree(previous)
    previous.parent.mkdir(parents=True, exist_ok=True)
    if live.exists():
        shutil.move(str(live), str(previous))
    live.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(shadow), str(live))
    return live


def rollback(
    live_dir: str | Path,
    previous_dir: str | Path | None = None,
) -> Path:
    """Swap live with previous. The displaced live tree becomes previous."""
    live = Path(live_dir)
    previous = _previous_dir(live, previous_dir)
    if not previous.is_dir():
        raise FileNotFoundError(previous)
    holding = live.parent / f".ml-rollback-{live.name}"
    if holding.exists():
        shutil.rmtree(holding)
    if live.exists():
        shutil.move(str(live), str(holding))
    shutil.move(str(previous), str(live))
    if holding.exists():
        shutil.move(str(holding), str(previous))
    return live
