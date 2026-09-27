"""Host capability probe — recommend lite/full and related defaults."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HostFacts:
    ram_gib: float
    vcpus: int
    container: bool
    has_onnx: bool
    has_torch: bool
    desktopish: bool
    systemd: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class RecItem:
    key: str
    recommended: Any
    reason: str
    severity: str = "info"  # info | warn | critical


@dataclass
class Recommendations:
    facts: HostFacts
    items: list[RecItem]
    profile: str
    overlay: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "facts": asdict(self.facts),
            "profile": self.profile,
            "items": [asdict(i) for i in self.items],
            "overlay": self.overlay,
            "ts": time.time(),
        }


def _in_container() -> bool:
    if Path("/.dockerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
        if "docker" in cgroup or "containerd" in cgroup or "kubepods" in cgroup:
            return True
    except OSError:
        pass
    return bool(os.environ.get("container") or os.environ.get("KUBERNETES_SERVICE_HOST"))


def _desktopish() -> bool:
    """Heuristic: lots of GUI / compositor processes → recommend quieter agent defaults."""
    markers = (
        "Hyprland",
        "sway",
        "gnome-shell",
        "plasmashell",
        "xfce4-session",
        "Xorg",
        "wayland",
        "firefox",
        "chromium",
        "Cursor",
    )
    hits = 0
    try:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                comm = (p / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if any(m.lower() in comm.lower() for m in markers):
                hits += 1
                if hits >= 2:
                    return True
    except OSError:
        return False
    return hits >= 2


def _has_mod(name: str) -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def collect_facts() -> HostFacts:
    import psutil

    mem = psutil.virtual_memory()
    ram_gib = float(mem.total) / (1024**3)
    vcpus = int(psutil.cpu_count(logical=True) or 1)
    container = _in_container()
    has_onnx = _has_mod("onnxruntime")
    has_torch = _has_mod("torch")
    desktopish = _desktopish()
    systemd = Path("/run/systemd/system").exists() or Path("/etc/systemd/system").exists()
    reasons: list[str] = []
    if container:
        reasons.append("container/cgroup detected")
    if desktopish:
        reasons.append("desktop/GUI processes present")
    if ram_gib < 2.0:
        reasons.append(f"low RAM ({ram_gib:.1f} GiB)")
    if vcpus <= 2:
        reasons.append(f"few vCPUs ({vcpus})")
    return HostFacts(
        ram_gib=round(ram_gib, 2),
        vcpus=vcpus,
        container=container,
        has_onnx=has_onnx,
        has_torch=has_torch,
        desktopish=desktopish,
        systemd=systemd,
        reasons=reasons,
    )


def recommend(facts: HostFacts | None = None) -> Recommendations:
    facts = facts or collect_facts()
    items: list[RecItem] = []

    # Profile
    if facts.container or facts.ram_gib < 3.0 or facts.vcpus <= 2:
        profile = "lite"
        items.append(
            RecItem(
                "load_profile",
                "lite",
                f"RAM={facts.ram_gib}GiB vCPU={facts.vcpus} container={facts.container}",
                "info",
            )
        )
    else:
        profile = "full"
        items.append(
            RecItem(
                "load_profile",
                "full",
                f"enough headroom ({facts.ram_gib}GiB / {facts.vcpus} vCPU)",
                "info",
            )
        )

    # Runtime prefer
    if facts.ram_gib < 2.0 or not facts.has_torch:
        prefer = "notorch"
        reason = "no torch or RAM<2GiB — ONNX/notorch preferred"
        sev = "warn" if facts.ram_gib < 1.5 else "info"
    else:
        prefer = "torch" if facts.has_torch else "notorch"
        reason = "torch available and RAM ok"
        sev = "info"
    if prefer == "notorch" and not facts.has_onnx:
        reason += "; install onnxruntime for ML scoring"
        sev = "warn"
    items.append(RecItem("runtime.prefer", prefer, reason, sev))

    # Agent
    agent_on = True
    agent_reason = "agent recommended for integrity + root_watch"
    if facts.desktopish and not facts.systemd:
        agent_on = True  # still on, but userspace + quieter
        agent_reason = "desktop detected — keep agent but userspace mode, lower poll"
    items.append(RecItem("agent.enabled", agent_on, agent_reason, "info"))
    items.append(RecItem("agent.auto_start", agent_on, "auto_start with agent.enabled", "info"))
    items.append(
        RecItem(
            "agent.mode",
            "userspace",
            "userspace avoids eBPF openat flood on desktop; use ebpf on quiet VPS only",
            "warn" if facts.desktopish else "info",
        )
    )

    # Response
    items.append(
        RecItem(
            "response.mode",
            "observe",
            "safe default — switch to shield only after TG unlock tested",
            "info",
        )
    )

    # Flow
    flow_on = profile == "full" and not facts.container
    items.append(
        RecItem(
            "flow.enabled",
            flow_on,
            "full non-container hosts get netview/flow; lite keeps off",
            "info",
        )
    )

    # Feedback IF
    items.append(
        RecItem(
            "feedback.if_refit",
            False,
            "IF refit off by default on VPS; ProcessLabelRules handle FP first",
            "info",
        )
    )

    # Widen rules
    items.append(
        RecItem(
            "feedback.widen_rules",
            "comm_prefix",
            "As normal/anomaly also adds similar-comm rule by default",
            "info",
        )
    )

    overlay: dict[str, Any] = {
        "load_profile": profile,
        "runtime": {"prefer": prefer},
        "agent": {
            "enabled": agent_on,
            "auto_start": agent_on,
            "mode": "userspace",
            "root_watch": True,
        },
        "response": {"mode": "observe"},
        "flow": {"enabled": flow_on, "backend": "netview" if flow_on else "proc"},
        "feedback": {
            "if_refit": False,
            "widen_rules": "comm_prefix",
        },
        "telegram": {"require_console_unlock": True},
    }
    if profile == "lite":
        overlay["agent"]["poll_ms"] = 1000
        overlay["agent"]["metrics_ms"] = 2000
    return Recommendations(facts=facts, items=items, profile=profile, overlay=overlay)


def save_probe(path: Path, rec: Recommendations | None = None) -> Path:
    rec = rec or recommend()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec.as_dict(), indent=2) + "\n", encoding="utf-8")
    return path


def load_probe(path: Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
