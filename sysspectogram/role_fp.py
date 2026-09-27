"""Role-specific FP baseline process labels (Track A).

Applied once via configure or `sysspectogram labels seed --role ssh`.
"""

from __future__ import annotations

from typing import Any

# Each entry: (label, match, pattern, note)
RoleLabel = tuple[str, str, str, str]

ROLE_FP_LABELS: dict[str, list[RoleLabel]] = {
    "ssh": [
        ("baseline", "exact", "sshd", "ssh role: sshd normal"),
        ("baseline", "exact", "systemd", "ssh role: systemd"),
        ("baseline", "exact", "systemd-logind", "ssh role"),
        ("baseline", "comm_prefix", "systemd-", "ssh role: systemd helpers"),
        ("baseline", "exact", "cron", "ssh role"),
        ("baseline", "exact", "crond", "ssh role"),
        ("anomaly", "path_contains", "/dev/shm/", "ssh role: droppers in shm"),
        ("anomaly", "cmdline_contains", "xmrig", "ssh role: miner"),
        ("anomaly", "cmdline_contains", "kdevtmpfsi", "ssh role: known malware"),
    ],
    "nginx": [
        ("baseline", "exact", "nginx", "nginx role"),
        ("baseline", "exact", "sshd", "nginx role"),
        ("baseline", "comm_prefix", "php-fpm", "nginx role"),
        ("baseline", "exact", "systemd", "nginx role"),
        ("anomaly", "path_glob", "/tmp/*", "nginx: unusual tmp exec (review)"),
        ("anomaly", "cmdline_contains", "xmrig", "nginx role: miner"),
    ],
    "docker": [
        ("baseline", "exact", "dockerd", "docker role"),
        ("baseline", "exact", "containerd", "docker role"),
        ("baseline", "comm_prefix", "docker-", "docker role"),
        ("baseline", "exact", "sshd", "docker role"),
        ("anomaly", "cmdline_contains", "xmrig", "docker role: miner"),
    ],
    "panel": [
        ("baseline", "exact", "sshd", "panel role"),
        ("baseline", "comm_prefix", "nginx", "panel role"),
        ("baseline", "path_contains", "/usr/local/cpanel", "panel role"),
        ("baseline", "path_contains", "plesk", "panel role"),
        ("anomaly", "cmdline_contains", "xmrig", "panel role: miner"),
    ],
    "python": [
        ("baseline", "exact", "sshd", "python role"),
        ("baseline", "path_contains", "/.venv/", "python role: venv"),
        ("baseline", "path_contains", "/venv/", "python role: venv"),
        ("anomaly", "cmdline_contains", "xmrig", "python role: miner"),
    ],
    "wireguard": [
        ("baseline", "exact", "sshd", "wireguard role"),
        ("baseline", "exact", "wg-quick", "wireguard role"),
        ("baseline", "comm_prefix", "wg", "wireguard role"),
        ("anomaly", "cmdline_contains", "xmrig", "wireguard role: miner"),
    ],
}


def seed_role_labels(store: Any, role: str, *, source: str = "role-fp") -> int:
    """Add role FP labels into ProcessLabelStore. Returns number added."""
    from sysspectogram.process_labels import ProcessLabelRule
    import time
    import uuid

    role = (role or "").strip().lower()
    rows = ROLE_FP_LABELS.get(role) or []
    n = 0
    for label, match, pattern, note in rows:
        store.add_rule(
            ProcessLabelRule(
                id=uuid.uuid4().hex[:12],
                label=label,  # type: ignore[arg-type]
                match=match,  # type: ignore[arg-type]
                pattern=pattern,
                source=source,
                note=note,
                ts=time.time(),
            )
        )
        n += 1
    return n


def list_seed_roles() -> list[str]:
    return sorted(ROLE_FP_LABELS.keys())
