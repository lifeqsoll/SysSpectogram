from __future__ import annotations

import argparse
import ipaddress
import subprocess

from sysspectogram.config import load_config


def _parse_allowed(entries: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in entries:
        try:
            out.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            continue
    return out


def target_allowed(target: str, allowed_entries: list[str]) -> bool:
    """True iff ``target`` is an IP/CIDR wholly contained in an allowlisted network.

    Hostnames, option-like strings, and wider-than-allowlist CIDRs are refused.
    Minimum allowlisted prefix: /24 (v4) or /120 (v6) — refuse listing a broader net.
    """
    t = (target or "").strip()
    if not t or t.startswith("-") or any(c in t for c in (" ", "\t", "\n", "\r", "\0")):
        return False
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return False
    # Single host or subnet must fit inside an allowlisted network.
    for allow in _parse_allowed(allowed_entries):
        if allow.version == 4 and allow.prefixlen < 24:
            continue
        if allow.version == 6 and allow.prefixlen < 120:
            continue
        if net.version == allow.version and net.subnet_of(allow):
            return True
    # Exact loopback convenience when listed or classic locals
    if t in {"127.0.0.1", "::1"} and t in set(allowed_entries):
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lab nmap only against allowlisted targets")
    p.add_argument("target")
    p.add_argument("--config", default=None)
    p.add_argument("--lab", action="store_true", required=True)
    args = p.parse_args(argv)
    cfg = load_config(args.config)
    allowed = list(cfg.get("lab", {}).get("nmap_targets") or [])
    if not target_allowed(args.target, allowed):
        print(f"refusing: {args.target} not in lab.nmap_targets")
        return 2
    cmd = ["nmap", "-F", "--max-retries", "1", "-T3", "--", args.target]
    print("lab nmap:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
