from __future__ import annotations


def explain_perimeter(alert) -> str:
    rid = getattr(alert, "rule_id", "")
    ip = getattr(alert, "ip", None) or "?"
    port = getattr(alert, "port", None)
    extras = getattr(alert, "extras", {}) or {}
    if rid == "bruteforce_ssh":
        return (
            f"Template: SSH authentication failures spike from {ip} "
            f"({extras.get('fails', '?')} fails). Likely credential stuffing / brute force."
        )
    if rid == "port_scan_suspected":
        return (
            f"Template: many unique external IPs hitting port {port}. "
            f"Likely reconnaissance / port scan."
        )
    if rid == "new_login_source":
        return (
            f"Template: successful login from previously unseen IP {ip} "
            f"(user={extras.get('user', '?')}). Verify this is you or an expected admin."
        )
    if rid == "egress_denylist_hit":
        return (
            f"Template: this host opened an outbound connection to denylisted {ip}:{port}. "
            f"Possible malware beacon / C2."
        )
    if rid == "suspicious_egress":
        return (
            f"Template: new external egress to {ip}:{port} "
            f"(process={extras.get('process')}). Unusual for this baseline."
        )
    if rid == "suspicious_dns":
        return (
            f"Template: DNS lookup for denylisted/suspicious domain "
            f"{extras.get('domain', '?')}. Possible malware callback."
        )
    if rid == "honeypot_hit":
        return f"Template: something connected to honeypot port {port} from {ip}."
    if rid == "lockdown_inbound":
        return (
            f"Template: host is in LOCKDOWN; inbound from {ip} to :{port} is treated as hostile. "
            f"Ban/allowlist as appropriate."
        )
    return f"Template: perimeter alert {rid} involving {ip}."


def explain_host_anomaly(
    *,
    cpu: float | None = None,
    mem: float | None = None,
    swap: float | None = None,
    gpu: float | None = None,
    disk_write: float | None = None,
    top_procs: list[dict] | None = None,
    top_features: list[dict] | None = None,
) -> str:
    signals: list[tuple[str, float]] = []
    if cpu is not None:
        signals.append(("cpu", cpu))
    if mem is not None:
        signals.append(("mem", mem))
    if swap is not None:
        signals.append(("swap", swap))
    if gpu is not None:
        signals.append(("gpu", gpu))
    if disk_write is not None:
        signals.append(("disk", min(disk_write / 1e7, 100.0)))
    signals.sort(key=lambda x: x[1], reverse=True)
    primary = signals[0][0] if signals else "mixed"
    proc_txt = ""
    if top_procs:
        proc_txt = "; top: " + ", ".join(
            f"{p.get('name')}(pid={p.get('pid')},cpu={p.get('cpu_percent')}%)"
            for p in top_procs[:3]
        )
    feat_txt = ""
    if top_features:
        feat_txt = "; features: " + ", ".join(
            f"{f.get('feature')}={f.get('mean'):.2f}" for f in top_features[:5]
        )
    if primary == "cpu":
        return f"Template: high CPU load pattern (cpu≈{cpu:.0f}%){proc_txt}{feat_txt}. Miner / runaway compute possible."
    if primary == "mem" or primary == "swap":
        return f"Template: memory pressure (mem≈{mem}, swap≈{swap}){proc_txt}{feat_txt}."
    if primary == "gpu":
        return f"Template: elevated GPU utilization (≈{gpu}%). Check compute / possible GPU miner."
    if primary == "disk":
        return f"Template: abnormal disk write rate{proc_txt}{feat_txt}."
    return f"Template: mixed host anomaly signals{proc_txt}{feat_txt}."
