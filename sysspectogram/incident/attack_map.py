"""Map SysSpectogram rule ids to MITRE ATT&CK technique ids.

Best-effort mapping. Techniques are hints for triage, not verdicts.
Review against the current ATT&CK release before quoting them externally.
"""

from __future__ import annotations

MATRIX_NOTE = "best-effort mapping; not verified against a specific ATT&CK release"

RULE_TO_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "agent_exec_burst": ("T1059",),
    "agent_ebpf_execve": ("T1059",),
    "agent_open_sensitive": ("T1003.008",),
    "agent_path_watch": ("T1565.001",),
    "agent_ebpf_openat": ("T1083",),
    "agent_connect_burst": ("T1046",),
    "agent_module_load": ("T1547.006",),
    "agent_kirk_module_load": ("T1547.006",),
    "agent_kirk_module_delete": ("T1547.006",),
    "agent_kirk_module_hide": ("T1014",),
    "agent_kirk_pid_hide": ("T1014",),
    "agent_kirk_symbol_drift": ("T1014",),
    "agent_kirk_ima_mismatch": ("T1014",),
    "agent_unexpected_root": ("T1548",),
    "agent_kirk_agent_down": ("T1562.001",),
    "agent_exe_mismatch": ("T1562.001",),
}

# Keyword fallbacks for perimeter and other rule names.
KEYWORD_TO_TECHNIQUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("brute", ("T1110",)),
    ("scan", ("T1046",)),
    ("honeypot", ("T1046",)),
    ("canary", ("T1046",)),
    ("beacon", ("T1071",)),
    ("egress", ("T1071",)),
    ("dns", ("T1071.004",)),
    ("fim", ("T1565.001",)),
    ("kick", ("T1078",)),
)


def techniques_for(rule_id: str) -> list[str]:
    """Return technique ids for a rule. Empty list means not mapped (e.g. host ML only)."""
    rid = (rule_id or "").strip().lower()
    if not rid or rid in ("host_anomaly", "unknown"):
        return []
    if rid in RULE_TO_TECHNIQUES:
        return list(RULE_TO_TECHNIQUES[rid])
    for keyword, techs in KEYWORD_TO_TECHNIQUES:
        if keyword in rid:
            return list(techs)
    return []
