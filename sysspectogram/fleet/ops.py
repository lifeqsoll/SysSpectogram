"""Fleet orchestration: status, unlock-locked, attack L2/L3, release."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from sysspectogram.fleet.results import FleetOpReport, wrap_host_dict
from sysspectogram.fleet.ssh import remote_cat_unlock_code, remote_control, require_host_pin
from sysspectogram.fleet.store import FleetHost, FleetStore
from sysspectogram.unlock_help import locked_playbook


def _report(scope: str, rows: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    results = [wrap_host_dict(r) for r in rows]
    ok = bool(results) and all(r.ok for r in results)
    if not results:
        ok = True
    return FleetOpReport(ok=ok, scope=scope, results=results, extra=dict(extra)).to_dict()


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
        pin_err = require_host_pin(h, mutating=True)
        if pin_err:
            return {"host_id": h.id, "ok": False, "error": pin_err}
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
            "error": None if ok else (data.get("error") or r.stderr or "apply failed"),
            "result": data or {"stdout": r.stdout, "stderr": r.stderr},
        }

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return _report(scope, results, profile_id=profile_id)


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
        pin_err = require_host_pin(h, mutating=True)
        if pin_err:
            results.append({"ok": False, "host_id": h.id, "error": pin_err})
            continue
        home = (h.home_path or "").rstrip("/") or "."
        py = remote_python(h)
        remote = f"cd {shlex.quote(home)} && {py} -m sysspectogram home warmup"
        r = ssh_run(h, remote, identity=identity)
        data = r.json() or {"ok": False, "error": r.stderr or r.stdout}
        data["host_id"] = h.id
        if "ok" not in data:
            data["ok"] = False
        results.append(data)
    ok = bool(results) and all(bool(r.get("ok")) for r in results)
    if not results:
        ok = True
    return {"ok": ok, "results": results}


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
        return remote_control(h, {"op": "status"}, identity=identity, mutating=False)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"ok": False, "host_id": h.id, "error": str(exc)})
    online = sum(1 for r in results if r.get("ok"))
    return _report(scope, results, n=len(hosts), online=online)


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
        st = remote_control(h, {"op": "status"}, identity=identity, mutating=False)
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
                "error": "no unlock.code on host (or host not pinned)",
                "help": locked_playbook(host_id=h.id),
            }
        ur = remote_control(
            h, {"op": "unlock", "code": code}, identity=identity, mutating=True
        )
        ur["host_id"] = h.id
        if not ur.get("ok"):
            ur["help"] = locked_playbook(host_id=h.id)
        return ur

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            out.append(fut.result())
    ok_n = sum(1 for r in out if r.get("ok"))
    return _report(
        scope,
        out,
        unlocked_or_skipped=ok_n,
        n=len(out),
    )


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
        st0 = remote_control(h, {"op": "status"}, identity=identity, mutating=False)
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
                mutating=True,
            )
        return remote_control(
            h,
            {"op": "action", "name": "lockdown", "payload": {}},
            identity=identity,
            mutating=True,
        )

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return _report(scope, results, level=level)


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
    from sysspectogram.net_ip import parse_ban_ip

    try:
        ip = parse_ban_ip(ip)
    except ValueError as exc:
        return {"ok": False, "error": str(exc), "scope": scope, "results": []}
    hosts = _select(store, scope)

    def one(h: FleetHost) -> dict[str, Any]:
        st0 = remote_control(h, {"op": "status"}, identity=identity, mutating=False)
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
            mutating=True,
        )

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(hosts) or 1))) as pool:
        futs = {pool.submit(one, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return _report(scope, results, ip=ip)


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
        pin_err = require_host_pin(h, mutating=True)
        if pin_err:
            results.append({"ok": False, "host_id": h.id, "error": pin_err})
            continue
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


def _one_host(store: FleetStore, scope: str) -> FleetHost | dict[str, Any]:
    hosts = _select(store, scope)
    if len(hosts) != 1:
        return {
            "ok": False,
            "error": "timeseries needs a single host scope (host id)",
            "n": len(hosts),
        }
    return hosts[0]


def _remote_ts_sqlite(
    h: FleetHost,
    *,
    op: str,
    metrics: str = "",
    range_name: str = "1h",
    identity: str | None = None,
) -> dict[str, Any]:
    """Read remote timeseries.sqlite via inline Python (works on older VPS packages)."""
    import base64
    import json
    import shlex
    import textwrap

    from sysspectogram.fleet.ssh import remote_python, ssh_run

    home = (h.home_path or "").rstrip("/") or "."
    payload = {
        "home": home,
        "op": op,
        "metrics": [x.strip() for x in metrics.split(",") if x.strip()],
        "range": range_name,
    }
    script = textwrap.dedent(
        r"""
        import json, sqlite3, time, sys
        from pathlib import Path
        cfg = json.loads(sys.argv[1])
        db = Path(cfg["home"]) / "state" / "timeseries.sqlite"
        if not db.is_file():
            print(json.dumps({"ok": True, "metrics": [], "latest": [], "series": {}}))
            raise SystemExit(0)
        ranges = {"1h":3600,"6h":21600,"12h":43200,"24h":86400,"7d":604800,"30d":2592000}
        # Prefer rollups over raw for hub SSH (1h raw is huge).
        tables = {"1h":"r10s","6h":"r10s","12h":"r10s","24h":"r1m","7d":"r1m","30d":"r5m"}
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        op = cfg["op"]
        if op == "metrics":
            rows = conn.execute("SELECT DISTINCT metric FROM raw ORDER BY metric").fetchall()
            print(json.dumps({"ok": True, "metrics": [r[0] for r in rows]}))
        elif op == "latest":
            names = cfg["metrics"] or [r[0] for r in conn.execute(
                "SELECT DISTINCT metric FROM raw ORDER BY metric").fetchall()]
            out = []
            for name in names:
                row = conn.execute(
                    "SELECT ts, value FROM raw WHERE metric=? ORDER BY ts DESC LIMIT 1",
                    (name,),
                ).fetchone()
                if row:
                    out.append({"metric": name, "ts": float(row[0]), "value": float(row[1])})
            print(json.dumps({"ok": True, "latest": out}))
        elif op == "query":
            rng = cfg.get("range") or "1h"
            secs = ranges.get(rng)
            table = tables.get(rng)
            if secs is None or table is None:
                print(json.dumps({"ok": False, "error": f"bad range {rng}"}))
                raise SystemExit(0)
            start = int(time.time() - secs)
            series = {}
            for name in cfg["metrics"]:
                rows = []
                use = table
                if use != "raw":
                    try:
                        rows = conn.execute(
                            f"SELECT ts, avg, min, max, n FROM {use} "
                            "WHERE metric=? AND ts>=? ORDER BY ts",
                            (name, start),
                        ).fetchall()
                    except Exception:
                        rows = []
                if not rows:
                    rows = conn.execute(
                        "SELECT ts, value, value, value, 1 FROM raw "
                        "WHERE metric=? AND ts>=? ORDER BY ts",
                        (name, start),
                    ).fetchall()
                pts = [
                    {"ts": float(r[0]), "avg": r[1], "min": r[2], "max": r[3], "n": int(r[4])}
                    for r in rows
                ]
                max_pts = 240
                if len(pts) > max_pts:
                    step = max(1, len(pts) // max_pts)
                    pts = pts[::step][:max_pts]
                series[name] = pts
            print(json.dumps({"ok": True, "series": series}))
        else:
            print(json.dumps({"ok": False, "error": f"bad op {op}"}))
        conn.close()
        """
    ).strip()
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    cfg_json = json.dumps(payload, separators=(",", ":"))
    py = remote_python(h)
    remote = (
        f"cd {shlex.quote(home)} && {py} -c "
        + shlex.quote(
            "import base64,sys\n"
            f"code=base64.b64decode({b64!r}).decode()\n"
            f"sys.argv=[sys.argv[0], {cfg_json!r}]\n"
            "exec(code)\n"
        )
    )
    r = ssh_run(h, remote, identity=identity, timeout=90.0)
    data = r.json()
    if isinstance(data, dict) and data.get("ok"):
        data["host_id"] = h.id
        return data
    return {
        "ok": False,
        "host_id": h.id,
        "error": (r.stderr or r.stdout or "ssh failed")[:500],
    }


def timeseries_metrics(
    store: FleetStore,
    scope: str,
    *,
    identity: str | None = None,
) -> dict[str, Any]:
    """List timeseries metric names on one host (scope must be a single host id)."""
    h = _one_host(store, scope)
    if isinstance(h, dict):
        return h
    return _remote_ts_sqlite(h, op="metrics", identity=identity)


def timeseries_latest(
    store: FleetStore,
    scope: str,
    *,
    metrics: str = "",
    identity: str | None = None,
) -> dict[str, Any]:
    """Latest raw samples from one host."""
    h = _one_host(store, scope)
    if isinstance(h, dict):
        return h
    return _remote_ts_sqlite(h, op="latest", metrics=metrics, identity=identity)


def timeseries_query_many(
    store: FleetStore,
    scope: str,
    *,
    metrics: str,
    range_name: str = "1h",
    identity: str | None = None,
) -> dict[str, Any]:
    """Batch timeseries query on one host (JSON object metric -> points)."""
    h = _one_host(store, scope)
    if isinstance(h, dict):
        return h
    if not str(metrics or "").strip():
        return {"ok": False, "host_id": h.id, "error": "--metrics required"}
    return _remote_ts_sqlite(
        h,
        op="query",
        metrics=metrics,
        range_name=range_name,
        identity=identity,
    )


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
        a = remote_control(
            h,
            {"op": "action", "name": "release_quarantine", "payload": {}},
            identity=identity,
            mutating=True,
        )
        b = remote_control(
            h,
            {"op": "action", "name": "kirk_release", "payload": {}},
            identity=identity,
            mutating=True,
        )
        c = remote_control(
            h,
            {"op": "action", "name": "release_lockdown", "payload": {}},
            identity=identity,
            mutating=True,
        )
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
    return _report(scope, results)
