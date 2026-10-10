"""Group normalized alerts into incidents.

Two events join the same incident when they share an entity value (pid, comm,
path or ip) and their timestamps differ by at most `window_sec`. Chaining is
transitive: A-B and B-C join A, B and C even if A and C are far apart in time.

Events without any entity are chained by time only, per host.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Iterable, Mapping

from sysspectogram.incident.attack_map import MATRIX_NOTE, techniques_for
from sysspectogram.incident.normalize import SEVERITY_ORDER, normalize

SCHEMA = "incident.v1"
DEFAULT_WINDOW_SEC = 300.0
MAX_TIMELINE = 200


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _chain_by_time(
    uf: _UnionFind, indices: list[int], events: list[dict[str, Any]], window: float
) -> None:
    """Union consecutive indices (already sorted by ts) that fall inside the window."""
    for prev, cur in zip(indices, indices[1:]):
        if events[cur]["ts"] - events[prev]["ts"] <= window:
            uf.union(prev, cur)


def _build_incident(
    host: str, members: list[dict[str, Any]], shared_keys: set[str]
) -> dict[str, Any]:
    members = sorted(members, key=lambda e: e["ts"])
    first_ts = members[0]["ts"]
    last_ts = members[-1]["ts"]
    rules = sorted({m["rule_id"] for m in members})
    severity = max(
        (m["severity"] for m in members), key=lambda s: SEVERITY_ORDER.get(s, 2)
    )
    risks = [m["risk"] for m in members if m["risk"] is not None]
    entities: dict[str, set[str]] = defaultdict(set)
    for m in members:
        for key, values in m["entities"].items():
            entities[key].update(values)
    attack: set[str] = set()
    for rule in rules:
        attack.update(techniques_for(rule))
    digest_src = f"{host}|{first_ts:.3f}|{'|'.join(rules)}|{len(members)}"
    incident_id = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:16]
    if shared_keys:
        reason = (
            f"{len(members)} events grouped by shared {', '.join(sorted(shared_keys))}"
            f" within the time window"
        )
    else:
        reason = f"{len(members)} events grouped by time on this host"
    if len(members) == 1:
        reason = "single event"
    timeline = [
        {
            "ts": m["ts"],
            "rule_id": m["rule_id"],
            "kind": m["kind"],
            "severity": m["severity"],
            "message": m["message"],
        }
        for m in members[:MAX_TIMELINE]
    ]
    return {
        "schema": SCHEMA,
        "id": incident_id,
        "host_id": host,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_sec": round(last_ts - first_ts, 3),
        "event_count": len(members),
        "severity": severity,
        "risk_max": max(risks) if risks else None,
        "rules": rules,
        "entities": {k: sorted(v)[:20] for k, v in sorted(entities.items())},
        "attack": sorted(attack),
        "attack_note": MATRIX_NOTE,
        "reason": reason,
        "timeline": timeline,
    }


def correlate(
    events: Iterable[Mapping[str, Any]],
    *,
    window_sec: float = DEFAULT_WINDOW_SEC,
    min_events: int = 1,
) -> list[dict[str, Any]]:
    """Return incidents sorted by first timestamp."""
    normalized: list[dict[str, Any]] = []
    for idx, raw in enumerate(events):
        rec = normalize(raw, source_index=idx)
        if rec is not None:
            normalized.append(rec)
    normalized.sort(key=lambda e: (e["host_id"], e["ts"]))

    incidents: list[dict[str, Any]] = []
    by_host: dict[str, list[int]] = defaultdict(list)
    for i, rec in enumerate(normalized):
        by_host[rec["host_id"]].append(i)

    for host, host_idx in by_host.items():
        uf = _UnionFind(len(normalized))
        entity_index: dict[tuple[str, str], list[int]] = defaultdict(list)
        no_entity: list[int] = []
        for i in host_idx:
            ents = normalized[i]["entities"]
            if not ents:
                no_entity.append(i)
                continue
            for key, values in ents.items():
                for val in values:
                    entity_index[(key, val)].append(i)

        shared_pairs: dict[int, set[str]] = defaultdict(set)
        for (key, _val), idxs in entity_index.items():
            idxs.sort(key=lambda j: normalized[j]["ts"])
            for prev, cur in zip(idxs, idxs[1:]):
                if normalized[cur]["ts"] - normalized[prev]["ts"] <= window_sec:
                    uf.union(prev, cur)
                    shared_pairs[cur].add(key)
                    shared_pairs[prev].add(key)
        _chain_by_time(uf, no_entity, normalized, window_sec)

        components: dict[int, list[int]] = defaultdict(list)
        for i in host_idx:
            components[uf.find(i)].append(i)

        for root_members in components.values():
            if len(root_members) < min_events:
                continue
            members = [normalized[i] for i in root_members]
            shared: set[str] = set()
            for i in root_members:
                shared |= shared_pairs.get(i, set())
            incidents.append(_build_incident(host, members, shared))

    incidents.sort(key=lambda inc: inc["first_ts"])
    return incidents
