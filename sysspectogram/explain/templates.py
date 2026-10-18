from __future__ import annotations

from sysspectogram.alert_text import describe


def explain_perimeter(alert, *, lang: str = "en") -> str:
    rid = getattr(alert, "rule_id", "") or ""
    ip = getattr(alert, "ip", None) or "?"
    port = getattr(alert, "port", None)
    extras = getattr(alert, "extras", {}) or {}
    info = describe(str(rid), lang="en" if lang == "en" else "ru")
    detail_bits: list[str] = []
    if rid == "bruteforce_ssh":
        detail_bits.append(f"from {ip} ({extras.get('fails', '?')} fails)")
    elif rid == "port_scan_suspected":
        detail_bits.append(f"port {port}")
    elif rid == "new_login_source":
        detail_bits.append(f"ip={ip} user={extras.get('user', '?')}")
    elif rid in ("egress_denylist_hit", "suspicious_egress", "lockdown_inbound"):
        detail_bits.append(f"{ip}:{port}" if port else str(ip))
        if extras.get("process"):
            detail_bits.append(f"process={extras.get('process')}")
    elif rid == "suspicious_dns":
        detail_bits.append(str(extras.get("domain", "?")))
    elif rid in ("honeypot_hit", "canary_hit"):
        detail_bits.append(f"port {port} from {ip}")
    else:
        detail_bits.append(str(ip))
    detail = "; ".join(detail_bits)
    return f"{info.title}. {info.what} ({detail}). {info.action}"


def explain_host_anomaly(
    *,
    cpu: float | None = None,
    mem: float | None = None,
    swap: float | None = None,
    gpu: float | None = None,
    disk_write: float | None = None,
    top_procs: list[dict] | None = None,
    top_features: list[dict] | None = None,
    lang: str = "en",
) -> str:
    info = describe("host_anomaly", lang="en" if lang == "en" else "ru")
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
    metric_bit = {
        "cpu": f"cpu≈{cpu:.0f}%" if cpu is not None else "cpu",
        "mem": f"mem≈{mem} swap≈{swap}",
        "swap": f"mem≈{mem} swap≈{swap}",
        "gpu": f"gpu≈{gpu}%",
        "disk": "disk write",
        "mixed": "mixed",
    }.get(primary, "mixed")
    return f"{info.title}. {info.what} ({metric_bit}{proc_txt}{feat_txt}). {info.action}"
