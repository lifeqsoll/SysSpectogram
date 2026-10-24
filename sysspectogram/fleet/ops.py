"""Fleet orchestration: status, unlock-locked, attack L2/L3, release."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from sysspectogram.fleet.ssh import remote_cat_unlock_code, remote_control
from sysspectogram.fleet.store import FleetHost, FleetStore
from sysspectogram.unlock_help import locked_playbook


def _select(store: FleetStore, scope: str) -> list[FleetHost]:
    st = store.load()
    scope = (scope or "all").strip()
    low = scope.lower()
    if low in ("", "all", "*"):
        return list(st.hosts)
    if low.startswith("group:"):
        gid = scope.split(":", 1)[1]
        for g in st.groups:
            if g.id == gid or g.label.lower() == gid.lower():
                ids = set(g.host_ids)
                return [h for h in st.hosts if h.id in ids]
        # fallback: tag/role
        return [h for h in st.hosts if gid in h.tags or h.role == gid]
    return [h for h in st.hosts if h.id == scope or h.label.lower() == low]


def apply_profile(
    store: FleetStore,
    profile_id: str,
    scope: str,
    *,
    identity: str | None = None,
    max_workers: int = 6,
) -> dict[str, Any]:
    """Push profile.settings via `home settings` on each host (allowlisted keys only)."""
    import json
    import shlex

    from sysspectogram.fleet.ssh import remote_python, ssh_run

    st = store.load()
    prof = next((p for p in st.profiles if p.id == profile_id), None)
    if prof is None:
        return {"ok": False, "error": f"unknown profile {profile_id}"}
    # refuse silent isolate via profile
    settings = dict(prof.settings)
    if str(settings.get("response.mode") or "").lower() == "isolate":
        return {"ok": False, "error": "profile must not set response.mode=isolate; use Attack"}
    hosts = _select(store, scope)
    payload = json.dumps(settings, separators=(",", ":"))

    def one(h: FleetHost) -> dict[str, Any]:
        home = (h.home_path or "").rstrip("/") or "."
        py = remote_python(h)
        remote = (
            f"cd {shlex.quote(home)} && {py} -m sysspectogram home settings "
            f"--changes {shlex.quote(payload)}"
        )
        r = ssh_run(h, remote, identity=identity)
        data = r.json() or {}
        ok = bool(data.get("ok")) if data else bool(r.ok)
        return {
            "host_id": h.id,
            "ok": ok,
            "result": data or {"stdout": r.stdout, "stderr": r.stderr},
        }

    results: list[dict[str, Any]] = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return {
        "ok": all(r.get("ok") for r in results),
        "profile_id": profile_id,
        "results": results,
    }


def warmup_remote(
    store: FleetStore,
    scope: str = "all",
    *,
    identity: str | None = None,
) -> dict[str, Any]:
    import shlex

    from sysspectogram.fleet.ssh import remote_python, ssh_run

    hosts = _select(store, scope)
    results: list[dict[str, Any]] = []
    for h in hosts:
        home = (h.home_path or "").rstrip("/") or "."
        py = remote_python(h)
        remote = f"cd {shlex.quote(home)} && {py} -m sysspectogram home warmup"
        r = ssh_run(h, remote, identity=identity)
        data = r.json() or {"ok": False, "error": r.stderr or r.stdout}
        data["host_id"] = h.id
        results.append(data)
    return {"ok": True, "results": results}


def status_many(
    store: FleetStore,
    scope: str = "all",
    *,
    max_workers: int = 8,
    identity: str | None = None,
) -> dict[str, Any]:
    hosts = _select(store, scope)
    results: list[dict[str, Any]] = []

    def one(h: FleetHost) -> dict[str, Any]:
        return remote_control(h, {"op": "status"}, identity=identity)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"ok": False, "host_id": h.id, "error": str(exc)})
    online = sum(1 for r in results if r.get("ok"))
    return {"ok": True, "n": len(hosts), "online": online, "results": results}


def unlock_locked(
    store: FleetStore,
    scope: str = "all",
    *,
    max_workers: int = 6,
    identity: str | None = None,
) -> dict[str, Any]:
    """Read unlock.code over SSH and submit unlock on each LOCKED host."""
    hosts = _select(store, scope)
    out: list[dict[str, Any]] = []

    def one(h: FleetHost) -> dict[str, Any]:
        st = remote_control(h, {"op": "status"}, identity=identity)
        if not st.get("ok"):
            return {"host_id": h.id, "ok": False, "error": st.get("error"), "step": "status"}
        status = st.get("status") or {}
        if status.get("control_unlocked", True):
            return {"host_id": h.id, "ok": True, "skipped": True, "reason": "already unlocked"}
        code = remote_cat_unlock_code(h, identity=identity)
        if not code:
            return {
                "host_id": h.id,
                "ok": False,
                "error": "no unlock.code on host",
                "help": locked_playbook(host_id=h.id),
            }
        ur = remote_control(h, {"op": "unlock", "code": code}, identity=identity)
        ur["host_id"] = h.id
        if not ur.get("ok"):
            ur["help"] = locked_playbook(host_id=h.id)
        return ur

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            out.append(fut.result())
    ok_n = sum(1 for r in out if r.get("ok"))
    return {"ok": ok_n == len(out), "unlocked_or_skipped": ok_n, "n": len(out), "results": out}


def attack(
    store: FleetStore,
    scope: str,
    *,
    level: str = "L2",
    deps: bool = False,
    ports: Iterable[int] | None = None,
    max_workers: int = 6,
    identity: str | None = None,
) -> dict[str, Any]:
    """L2 = app-port quarantine; L3 = lockdown. Skips LOCKED with help text."""
    level = level.upper().replace(" ", "")
    if level not in ("L2", "L3"):
        level = "L2"
    hosts = _select(store, scope)
    st = store.load()
    if deps and len(hosts) == 1:
        dep_ids = store.dependents(hosts[0].id)
        by_id = {h.id: h for h in st.hosts}
        # never auto-include bastion/dns
        for did in dep_ids:
            h = by_id.get(did)
            if h and h.role not in ("bastion", "dns") and h.id not in {x.id for x in hosts}:
                hosts.append(h)

    port_list = list(ports) if ports else [80, 443]

    def one(h: FleetHost) -> dict[str, Any]:
        st0 = remote_control(h, {"op": "status"}, identity=identity)
        status = (st0.get("status") or {}) if st0.get("ok") else {}
        if st0.get("ok") and status.get("control_unlocked") is False:
            return {
                "host_id": h.id,
                "ok": False,
                "error": "LOCKED",
                "help": locked_playbook(host_id=h.id),
            }
        if level == "L2":
            return remote_control(
                h,
                {"op": "action", "name": "quarantine", "payload": {"ports": port_list}},
                identity=identity,
            )
        return remote_control(
            h,
            {"op": "action", "name": "lockdown", "payload": {}},
            identity=identity,
        )

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return {"ok": all(r.get("ok") for r in results), "level": level, "results": results}


def ban_ip(
    store: FleetStore,
    scope: str,
    ip: str,
    *,
    ttl_sec: float = 3600.0,
    max_workers: int = 6,
    identity: str | None = None,
) -> dict[str, Any]:
    """Fan-out IP ban to scope (control action `ban`)."""
    hosts = _select(store, scope)

    def one(h: FleetHost) -> dict[str, Any]:
        st0 = remote_control(h, {"op": "status"}, identity=identity)
        status = (st0.get("status") or {}) if st0.get("ok") else {}
        if st0.get("ok") and status.get("control_unlocked") is False:
            return {
                "host_id": h.id,
                "ok": False,
                "error": "LOCKED",
                "help": locked_playbook(host_id=h.id),
            }
        return remote_control(
            h,
            {"op": "action", "name": "ban", "payload": {"ip": ip, "ttl_sec": ttl_sec}},
            identity=identity,
        )

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return {"ok": all(r.get("ok") for r in results), "ip": ip, "results": results}


def mark_false_positive(
    store: FleetStore,
    scope: str,
    *,
    label: str = "host_fp",
    identity: str | None = None,
) -> dict[str, Any]:
    """Record a host-anomaly false positive on each host (operator_feedback.json)."""
    import shlex

    from sysspectogram.fleet.ssh import remote_python, ssh_run

    hosts = _select(store, scope)
    results: list[dict[str, Any]] = []
    for h in hosts:
        home = (h.home_path or "").rstrip("/") or "."
        py = remote_python(h)
        remote = (
            f"cd {shlex.quote(home)} && {py} -m sysspectogram home false-positive "
            f"--label {shlex.quote(label)} --source fleet"
        )
        r = ssh_run(h, remote, identity=identity)
        data = r.json() or {"ok": False, "error": r.stderr or r.stdout}
        data["host_id"] = h.id
        results.append(data)
    return {"ok": all(r.get("ok") for r in results), "results": results}


def incidents_feed(
    store: FleetStore,
    scope: str = "all",
    *,
    limit: int = 40,
    identity: str | None = None,
) -> dict[str, Any]:
    """Pull recent incidents/alerts JSONL tails from each host and merge."""
    import shlex

    from sysspectogram.fleet.ssh import remote_python, ssh_run

    hosts = _select(store, scope)
    items: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for h in hosts:
        home = (h.home_path or "").rstrip("/") or "."
        py = remote_python(h)
        remote = (
            f"cd {shlex.quote(home)} && {py} -m sysspectogram home feed-tail "
            f"--limit {int(limit)} --host-id {shlex.quote(h.id)}"
        )
        r = ssh_run(h, remote, identity=identity, timeout=45.0)
        data = r.json()
        if not data or not data.get("ok"):
            errors.append({"host_id": h.id, "error": (r.stderr or r.stdout or "ssh failed")[:300]})
            continue
        for row in data.get("rows") or []:
            if isinstance(row, dict):
                row.setdefault("host_id", h.id)
                items.append(row)

    def _ts(row: dict[str, Any]) -> float:
        for k in ("ts", "last_ts", "first_ts", "at"):
            try:
                return float(row.get(k) or 0)
            except (TypeError, ValueError):
                continue
        return 0.0

    items.sort(key=_ts, reverse=True)
    return {
        "ok": True,
        "n": len(items),
        "items": items[: max(1, limit)],
        "errors": errors,
    }


def release(
    store: FleetStore,
    scope: str = "all",
    *,
    max_workers: int = 6,
    identity: str | None = None,
) -> dict[str, Any]:
    hosts = _select(store, scope)

    def one(h: FleetHost) -> dict[str, Any]:
        # release quarantine then try kirk_release / clear lockdown comments best-effort
        a = remote_control(h, {"op": "action", "name": "release_quarantine", "payload": {}}, identity=identity)
        b = remote_control(h, {"op": "action", "name": "kirk_release", "payload": {}}, identity=identity)
        c = remote_control(h, {"op": "action", "name": "release_lockdown", "payload": {}}, identity=identity)
        return {
            "host_id": h.id,
            "ok": bool(a.get("ok") or b.get("ok") or c.get("ok")),
            "quarantine": a,
            "kirk": b,
            "lockdown": c,
        }

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return {"ok": True, "results": results}
