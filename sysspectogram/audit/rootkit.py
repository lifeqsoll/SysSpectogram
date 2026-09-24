from __future__ import annotations

from pathlib import Path


def rootkit_heuristics() -> list[dict]:
    """Best-effort Linux rootkit/tamper hints. Not authoritative."""
    findings: list[dict] = []
    # hidden process: /proc entry without matching cmdline readable? skip heavy scan
    for path in (Path("/usr/bin/ls"), Path("/bin/ls"), Path("/usr/bin/ps")):
        if path.exists():
            try:
                st = path.stat()
                # world-writable binary is suspicious
                if st.st_mode & 0o002:
                    findings.append({"check": "world_writable", "path": str(path)})
            except OSError:
                pass
    # unexpected LKM listing soft-fail
    modules = Path("/proc/modules")
    if modules.exists():
        try:
            text = modules.read_text(encoding="utf-8", errors="replace")
            for name in ("Diamorphine", "hide", "rootkit"):
                if name.lower() in text.lower():
                    findings.append({"check": "module_name", "hint": name})
        except OSError:
            pass
    # deleted binary still running: scan a few /proc/*/exe
    proc = Path("/proc")
    try:
        for pdir in list(proc.iterdir())[:200]:
            if not pdir.name.isdigit():
                continue
            exe = pdir / "exe"
            try:
                target = exe.readlink()
            except OSError:
                continue
            if "(deleted)" in str(target):
                findings.append({"check": "deleted_exe", "pid": pdir.name, "path": str(target)})
                if len(findings) > 20:
                    break
    except OSError:
        pass
    return findings
