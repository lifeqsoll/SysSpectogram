from __future__ import annotations

import psutil


def list_top_processes(limit: int = 3) -> list[dict]:
    procs: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
        try:
            with proc.oneshot():
                cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_percent()
                info = proc.info
                procs.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "username": info.get("username"),
                        "cpu_percent": round(float(cpu), 2),
                        "memory_percent": round(float(mem), 2),
                        "cmdline": " ".join(info.get("cmdline") or [])[:200],
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    # Second pass after warming cpu_percent
    for proc in psutil.process_iter(["pid"]):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Refresh with real interval sample
    import time

    time.sleep(0.15)
    refreshed: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
        try:
            with proc.oneshot():
                info = proc.info
                refreshed.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "username": info.get("username"),
                        "cpu_percent": round(float(proc.cpu_percent(interval=None)), 2),
                        "memory_percent": round(float(proc.memory_percent()), 2),
                        "cmdline": " ".join(info.get("cmdline") or [])[:200],
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    refreshed.sort(key=lambda r: (r["cpu_percent"], r["memory_percent"]), reverse=True)
    return refreshed[:limit]


def suspicious_heuristics(limit: int = 50) -> list[dict]:
    findings: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            cmdline = " ".join(info.get("cmdline") or []).lower()
            exe = (info.get("exe") or "").lower()
            reasons = []
            if any(x in name for x in ("xmrig", "minerd", "cpuminer")):
                reasons.append("known miner process name")
            if exe and ("/tmp/" in exe or exe.startswith("/dev/shm")):
                if "/tmp/.mount_" in exe:
                    reasons.append("appimage_mount")
                else:
                    reasons.append("executable from world-writable path")
            if "curl" in cmdline and ("| sh" in cmdline or "| bash" in cmdline):
                reasons.append("pipe-to-shell pattern in cmdline")
            if reasons:
                findings.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "exe": info.get("exe"),
                        "username": info.get("username"),
                        "reasons": reasons,
                        "cmdline": " ".join(info.get("cmdline") or [])[:300],
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        if len(findings) >= limit:
            break
    return findings
