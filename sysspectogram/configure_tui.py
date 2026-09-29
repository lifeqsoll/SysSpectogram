"""Unified terminal configure — Day-0 setup with host_probe recommendations."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from sysspectogram.host_probe import Recommendations, recommend, save_probe
from sysspectogram.load_profile import _deep_merge


console = Console()


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _update_env(env_path: Path, updates: dict[str, str]) -> None:
    kv: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                kv[k.strip()] = v.strip()
    for k, v in updates.items():
        if v:
            kv[k] = v
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(f"{k}={v}" for k, v in kv.items()) + "\n", encoding="utf-8")


def _show_recs(rec: Recommendations) -> None:
    table = Table(title="Recommended for this host")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_column("Reason")
    for it in rec.items:
        table.add_row(it.key, str(it.recommended), it.reason)
    console.print(table)
    facts = rec.facts
    console.print(
        Panel(
            f"RAM={facts.ram_gib} GiB · vCPU={facts.vcpus} · container={facts.container} · "
            f"desktop={facts.desktopish} · onnx={facts.has_onnx} · torch={facts.has_torch}\n"
            f"reasons: {', '.join(facts.reasons) or 'none'}",
            title="Host probe",
        )
    )


def _confirm_override(key: str, recommended: Any, chosen: Any, reason: str) -> bool:
    if chosen == recommended:
        return True
    console.print(
        Panel(
            f"[bold]{key}[/]\n"
            f"Recommended: [green]{recommended}[/] — {reason}\n"
            f"You chose: [yellow]{chosen}[/]\n\n"
            "Current settings are best for this machine based on probe data. "
            "Changing them may raise CPU/RAM use or alert noise.",
            title="Override warning",
            border_style="yellow",
        )
    )
    return Confirm.ask("Continue with your value?", default=False)


def apply_overlay(
    config_path: Path,
    overlay: dict[str, Any],
    *,
    role: str | None = None,
) -> dict[str, Any]:
    base = _load_yaml(config_path)
    merged = _deep_merge(base, overlay)
    if role:
        merged["role"] = role
    _dump_yaml(config_path, merged)
    return merged


def run_configure(
    *,
    prefix: Path,
    config_path: Path | None = None,
    env_path: Path | None = None,
    accept_recommended: bool = False,
    non_interactive: bool = False,
    role: str | None = None,
    seed_fp: bool = True,
) -> dict[str, Any]:
    """Interactive or accept-recommended configure. Returns applied overlay summary."""
    prefix = Path(prefix)
    config_path = Path(config_path or (prefix / "configs" / "default.yaml"))
    env_path = Path(env_path or (prefix / ".env"))
    probe_path = prefix / "state" / "host_probe.json"

    rec = recommend()
    save_probe(probe_path, rec)
    _show_recs(rec)

    if accept_recommended or non_interactive:
        overlay = copy.deepcopy(rec.overlay)
        if role:
            overlay["role"] = role
        apply_overlay(config_path, overlay, role=role)
        if seed_fp and role:
            _seed_labels(prefix, role)
        console.print(f"[green]Applied recommended config → {config_path}[/]")
        console.print(f"Probe saved → {probe_path}")
        console.print("Next: set TELEGRAM_* in .env (or re-run configure interactive), then:")
        console.print("  python -m sysspectogram guard --model artifacts/real_v3 --telegram")
        return {"config": str(config_path), "overlay": overlay, "mode": "accept-recommended"}

    # Interactive
    console.print("\n[bold]Configure[/] — Enter to keep recommended. Overrides ask for confirm.\n")

    # Role
    from sysspectogram.rolelab.recipes import list_roles

    roles = list_roles() + ["generic-linux"]
    role_rec = role or "generic-linux"
    role_in = Prompt.ask(f"Role {roles}", default=role_rec)
    if role_in != role_rec and not _confirm_override("role", role_rec, role_in, "from CLI/default"):
        role_in = role_rec

    # Profile
    prof_rec = rec.profile
    prof = Prompt.ask("load_profile", choices=["lite", "full"], default=prof_rec)
    item = next(i for i in rec.items if i.key == "load_profile")
    if not _confirm_override("load_profile", item.recommended, prof, item.reason):
        prof = str(item.recommended)

    # Agent
    agent_rec = bool(rec.overlay["agent"]["enabled"])
    agent_on = Confirm.ask("Enable Rust agent?", default=agent_rec)
    if agent_on != agent_rec:
        it = next(i for i in rec.items if i.key == "agent.enabled")
        if not _confirm_override("agent.enabled", agent_rec, agent_on, it.reason):
            agent_on = agent_rec
    mode_rec = "userspace"
    mode = Prompt.ask("agent.mode", choices=["userspace", "ebpf"], default=mode_rec)
    if mode != mode_rec:
        it = next(i for i in rec.items if i.key == "agent.mode")
        if not _confirm_override("agent.mode", mode_rec, mode, it.reason):
            mode = mode_rec

    prefer_rec = str(rec.overlay["runtime"]["prefer"])
    prefer = Prompt.ask("runtime.prefer", choices=["notorch", "torch", "auto"], default=prefer_rec)
    if prefer != prefer_rec:
        it = next(i for i in rec.items if i.key == "runtime.prefer")
        if not _confirm_override("runtime.prefer", prefer_rec, prefer, it.reason):
            prefer = prefer_rec

    resp_rec = "observe"
    resp = Prompt.ask("response.mode", choices=["observe", "shield", "aggressive"], default=resp_rec)
    if resp != resp_rec:
        it = next(i for i in rec.items if i.key == "response.mode")
        if not _confirm_override("response.mode", resp_rec, resp, it.reason):
            resp = resp_rec

    flow_rec = bool(rec.overlay.get("flow", {}).get("enabled"))
    flow_on = Confirm.ask("Enable flow/netview?", default=flow_rec)
    if flow_on != flow_rec:
        it = next(i for i in rec.items if i.key == "flow.enabled")
        if not _confirm_override("flow.enabled", flow_rec, flow_on, it.reason):
            flow_on = flow_rec

    if_refit = Confirm.ask("Enable IsolationForest refit on feedback? (CNN stays frozen)", default=False)
    widen = Prompt.ask(
        "Widen As normal/anomaly rules",
        choices=["exact", "comm_prefix", "path_glob", "both"],
        default="comm_prefix",
    )

    model = Prompt.ask("Model artifacts dir", default="artifacts/real_v3")
    supply_base = _load_yaml(config_path).get("supply_chain") or {}
    supply_enforce = Confirm.ask(
        "Enforce signed model manifests? (requires a minisign public key)",
        default=bool(supply_base.get("enforce", False)),
    )
    public_key = Prompt.ask(
        "Minisign public key path (empty = keep existing)",
        default=str(supply_base.get("public_key") or ""),
    )
    if supply_enforce and not public_key:
        console.print("[yellow]No public key supplied; keeping supply_chain.enforce=false[/]")
        supply_enforce = False

    console.print("Telegram (empty = keep existing .env):")
    token = Prompt.ask("TELEGRAM_BOT_TOKEN", default="", password=True)
    chat = Prompt.ask("TELEGRAM_CHAT_ID", default="")

    overlay: dict[str, Any] = {
        "load_profile": prof,
        "role": role_in,
        "runtime": {"prefer": prefer},
        "agent": {
            "enabled": agent_on,
            "auto_start": agent_on,
            "mode": mode,
            "root_watch": True,
        },
        "response": {"mode": resp},
        "flow": {
            "enabled": flow_on,
            "backend": "netview" if flow_on else "proc",
            "window_sec": 30 if flow_on else 60,
        },
        "feedback": {
            "if_refit": if_refit,
            "widen_rules": widen if widen != "exact" else False,
            "model_dir": model,
        },
        "telegram": {"require_console_unlock": True},
        "model": {"path": model},
        "supply_chain": {
            "enforce": supply_enforce,
            "public_key": public_key or supply_base.get("public_key"),
            "manifest_name": "artifacts.manifest.json",
            "signature_name": "artifacts.manifest.json.minisig",
        },
    }
    apply_overlay(config_path, overlay, role=role_in)
    env_updates = {"SYSSPECTOGRAM_ROLE": role_in}
    if token:
        env_updates["TELEGRAM_BOT_TOKEN"] = token
    if chat:
        env_updates["TELEGRAM_CHAT_ID"] = chat
    _update_env(env_path, env_updates)

    if seed_fp and role_in and role_in != "generic-linux":
        n = _seed_labels(prefix, role_in)
        console.print(f"[cyan]Seeded {n} role FP labels for {role_in}[/]")

    if Confirm.ask("Edit process labels now?", default=False):
        _labels_submenu(prefix)

    console.print(Panel.fit(
        f"[green]Wrote[/] {config_path}\n"
        f"[green]Wrote[/] {env_path}\n"
        f"Probe: {probe_path}\n\n"
        f"Start: python -m sysspectogram guard --model {model} --telegram\n"
        "Read UNLOCK CODE on console → TG /unlock CODE\n"
        "See docs/COLD_INSTALL.md",
        title="Done",
    ))
    return {"config": str(config_path), "overlay": overlay, "mode": "interactive"}


def _seed_labels(prefix: Path, role: str) -> int:
    from sysspectogram.process_labels import ProcessLabelStore
    from sysspectogram.role_fp import seed_role_labels

    store = ProcessLabelStore(prefix / "state" / "process_labels.json")
    return seed_role_labels(store, role)


def _labels_submenu(prefix: Path) -> None:
    from sysspectogram.process_labels import ProcessLabelRule, ProcessLabelStore
    import time
    import uuid

    store = ProcessLabelStore(prefix / "state" / "process_labels.json")
    while True:
        rules = store.list_rules()
        console.print(f"\n[bold]Labels[/] ({len(rules)} rules)")
        for r in rules[:30]:
            console.print(f"  {r.id[:8]} {r.label:8} {r.match:16} {r.pattern}")
        if len(rules) > 30:
            console.print(f"  … +{len(rules) - 30} more")
        act = Prompt.ask("Action", choices=["add", "del", "done"], default="done")
        if act == "done":
            break
        if act == "add":
            label = Prompt.ask("label", choices=["baseline", "anomaly", "ignore"])
            match = Prompt.ask(
                "match",
                choices=["exact", "comm_prefix", "path_glob", "path_contains", "cmdline_contains"],
                default="exact",
            )
            pattern = Prompt.ask("pattern")
            store.add_rule(
                ProcessLabelRule(
                    id=uuid.uuid4().hex[:12],
                    label=label,  # type: ignore[arg-type]
                    match=match,  # type: ignore[arg-type]
                    pattern=pattern,
                    source="configure",
                    note="configure",
                    ts=time.time(),
                )
            )
        elif act == "del":
            rid = Prompt.ask("rule id or pattern")
            if store.delete(rid):
                console.print("[green]deleted[/]")
            else:
                console.print("[yellow]not found[/]")
