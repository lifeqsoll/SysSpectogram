"""fleet.json on the admin machine — hosts, primary, groups, profiles, edges."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def default_fleet_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sysspectogram" / "fleet.json"


@dataclass
class FleetHost:
    id: str
    label: str
    ssh: str = ""
    home_path: str = ""
    device_id: str = ""
    device_token: str = ""
    role: str = "worker"
    tags: list[str] = field(default_factory=list)
    profile_id: str | None = None

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d.get("device_token"):
            d["device_token"] = "***"
        return d


@dataclass
class FleetGroup:
    id: str
    label: str
    host_ids: list[str] = field(default_factory=list)
    profile_id: str | None = None
    primary_host_id: str | None = None


@dataclass
class FleetProfile:
    id: str
    label: str
    settings: dict[str, Any] = field(default_factory=dict)
    ml_artifact: str | None = None  # local path to model dir on admin PC


@dataclass
class FleetEdge:
    frm: str  # from
    to: str
    kind: str = "depends_on"  # depends_on|serves|replica|bastion|custom
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"from": self.frm, "to": self.to, "kind": self.kind, "note": self.note}


@dataclass
class FleetState:
    schema: str = "fleet.v1"
    primary_host_id: str | None = None
    hosts: list[FleetHost] = field(default_factory=list)
    groups: list[FleetGroup] = field(default_factory=list)
    profiles: list[FleetProfile] = field(default_factory=list)
    edges: list[FleetEdge] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "primary_host_id": self.primary_host_id,
            "hosts": [asdict(h) for h in self.hosts],
            "groups": [asdict(g) for g in self.groups],
            "profiles": [asdict(p) for p in self.profiles],
            "edges": [e.as_dict() for e in self.edges],
        }


class FleetStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_fleet_path()

    def load(self) -> FleetState:
        if not self.path.is_file():
            return FleetState()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return FleetState()
        hosts: list[FleetHost] = []
        for row in raw.get("hosts") or []:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            hosts.append(
                FleetHost(
                    id=str(row["id"]),
                    label=str(row.get("label") or row["id"]),
                    ssh=str(row.get("ssh") or ""),
                    home_path=str(row.get("home_path") or ""),
                    device_id=str(row.get("device_id") or ""),
                    device_token=str(row.get("device_token") or ""),
                    role=str(row.get("role") or "worker"),
                    tags=[str(t) for t in (row.get("tags") or [])],
                    profile_id=row.get("profile_id"),
                )
            )
        groups: list[FleetGroup] = []
        for row in raw.get("groups") or []:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            groups.append(
                FleetGroup(
                    id=str(row["id"]),
                    label=str(row.get("label") or row["id"]),
                    host_ids=[str(x) for x in (row.get("host_ids") or [])],
                    profile_id=row.get("profile_id"),
                    primary_host_id=row.get("primary_host_id"),
                )
            )
        profiles: list[FleetProfile] = []
        for row in raw.get("profiles") or []:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            settings = row.get("settings") if isinstance(row.get("settings"), dict) else {}
            profiles.append(
                FleetProfile(
                    id=str(row["id"]),
                    label=str(row.get("label") or row["id"]),
                    settings=dict(settings),
                    ml_artifact=row.get("ml_artifact"),
                )
            )
        edges: list[FleetEdge] = []
        for row in raw.get("edges") or []:
            if not isinstance(row, dict):
                continue
            frm = str(row.get("from") or row.get("frm") or "")
            to = str(row.get("to") or "")
            if not frm or not to:
                continue
            edges.append(
                FleetEdge(
                    frm=frm,
                    to=to,
                    kind=str(row.get("kind") or "depends_on"),
                    note=str(row.get("note") or ""),
                )
            )
        return FleetState(
            schema=str(raw.get("schema") or "fleet.v1"),
            primary_host_id=raw.get("primary_host_id"),
            hosts=hosts,
            groups=groups,
            profiles=profiles,
            edges=edges,
        )

    def save(self, state: FleetState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(state.as_dict(), indent=2, ensure_ascii=False) + "\n"
        self.path.write_text(text, encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def upsert_host(self, host: FleetHost) -> FleetState:
        st = self.load()
        prev = next((h for h in st.hosts if h.id == host.id), None)
        if prev is not None:
            # Re-add without --device-token / --device-id must not wipe secrets.
            if not (host.device_token or "").strip():
                host.device_token = prev.device_token
            if not (host.device_id or "").strip():
                host.device_id = prev.device_id
            if not (host.ssh or "").strip():
                host.ssh = prev.ssh
            if not (host.home_path or "").strip():
                host.home_path = prev.home_path
            if not host.tags and prev.tags:
                host.tags = list(prev.tags)
            if host.profile_id is None and prev.profile_id:
                host.profile_id = prev.profile_id
        st.hosts = [h for h in st.hosts if h.id != host.id] + [host]
        if host.role == "primary":
            st.primary_host_id = host.id
            for h in st.hosts:
                if h.id != host.id and h.role == "primary":
                    h.role = "worker"
        elif st.primary_host_id is None:
            st.primary_host_id = host.id
        self.save(st)
        return st

    def set_primary(self, host_id: str) -> FleetState:
        st = self.load()
        if host_id not in {h.id for h in st.hosts}:
            raise KeyError(host_id)
        st.primary_host_id = host_id
        for h in st.hosts:
            h.role = "primary" if h.id == host_id else (h.role if h.role != "primary" else "worker")
        self.save(st)
        return st

    def remove_host(self, host_id: str) -> FleetState:
        st = self.load()
        st.hosts = [h for h in st.hosts if h.id != host_id]
        st.edges = [e for e in st.edges if e.frm != host_id and e.to != host_id]
        for g in st.groups:
            g.host_ids = [x for x in g.host_ids if x != host_id]
        if st.primary_host_id == host_id:
            st.primary_host_id = st.hosts[0].id if st.hosts else None
            if st.hosts:
                st.hosts[0].role = "primary"
        self.save(st)
        return st

    def upsert_profile(self, profile: FleetProfile) -> FleetState:
        st = self.load()
        st.profiles = [p for p in st.profiles if p.id != profile.id] + [profile]
        self.save(st)
        return st

    def upsert_group(self, group: FleetGroup) -> FleetState:
        st = self.load()
        st.groups = [g for g in st.groups if g.id != group.id] + [group]
        self.save(st)
        return st

    def add_edge(self, edge: FleetEdge) -> FleetState:
        st = self.load()
        st.edges = [e for e in st.edges if not (e.frm == edge.frm and e.to == edge.to and e.kind == edge.kind)]
        st.edges.append(edge)
        self.save(st)
        return st

    def remove_edge(self, frm: str, to: str, kind: str | None = None) -> FleetState:
        st = self.load()
        st.edges = [
            e
            for e in st.edges
            if not (e.frm == frm and e.to == to and (kind is None or e.kind == kind))
        ]
        self.save(st)
        return st

    def dependents(self, host_id: str) -> list[str]:
        """Hosts that depend_on / are served by host_id (one hop)."""
        st = self.load()
        out: list[str] = []
        for e in st.edges:
            if e.kind in ("depends_on", "serves") and e.frm == host_id:
                out.append(e.to)
            if e.kind == "depends_on" and e.to == host_id:
                out.append(e.frm)
        # unique preserve order
        seen: set[str] = set()
        ordered: list[str] = []
        for x in out:
            if x not in seen and x != host_id:
                seen.add(x)
                ordered.append(x)
        return ordered
