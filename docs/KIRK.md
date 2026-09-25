# Kirk — Kernel Integrity / Rootkit signals

Status: **in-guest** integrity signals for v0.5. Honest trust labels — not a silver-bullet rootkit killer.

## Trust labels

| Label | Meaning |
| --- | --- |
| `best-effort` | In-guest views (`/proc`, eBPF, cross-view). A sophisticated LKM can lie. |
| `measured` | **IMA present** and (**Secure Boot on** or **TPM present**). Kernel/hardware hashes load path; TPM can record measurements. Still not remote attestation by itself. |
| `out-of-band` | Host VMI — **deferred to v1.0** ([VMI.md](VMI.md)). |

Probe on guard start (`kirk.trust: auto`):

```bash
python -c "from sysspectogram.kirk_trust import probe_kirk_trust; print(probe_kirk_trust())"
```

Without Secure Boot / IMA, SysSpectogram stays at **best-effort** and says so in `/status` and alerts.

## Signals

| Rule | Source | Meaning |
| --- | --- | --- |
| `agent_kirk_module_load` / `_delete` | eBPF finit/init/delete_module + `/proc/modules` | Module lifecycle |
| `agent_kirk_module_hide` | cross-view `/sys/module` vs `/proc/modules` | Hide mismatch (confirm streak) |
| `agent_kirk_pid_hide` | sudden PID list collapse | Soft hide signal |
| `agent_kirk_symbol_drift` | sealed kallsyms baseline | Hook / table move |
| `agent_kirk_ima_event` | IMA ascii log growth (module lines) | New measured module-ish entry |
| `agent_kirk_agent_down` | guard heartbeat | Agent silenced |

## Baseline seal

Presence-only (not absolute addresses — KASLR / `kptr_restrict` safe):

```bash
# Seal and poll as the **same** user (prefer root for both if agent is root)
sudo ./agent/target/release/sysspectogram-agent --kirk-seal \
  --kirk-baseline state/kirk-baseline.json
```

## Response

`NftBackend.kirk_isolate` / `kirk_release` — nft table `inet ss_kirk`.
**TTL is enforced** in-process (`expire_kirk_isolate` via ban cleanup loop). TG: `/kirk_release` (unlock-gated).

```yaml
kirk:
  enabled: true
  trust: auto
  auto_isolate: false   # CRITICAL allowlisted rules only; set allow_ssh_cidrs first
  allow_ssh_cidrs: ["YOUR.IP/32"]
  isolate_ttl_sec: 3600
  ima_watch: true
  vmi: false            # ignored until v1.0
```

Never auto-`rmmod`. Prefer isolate → reboot to known-good.

## Run eBPF agent (root)

```bash
sudo -E ./agent/target/release/sysspectogram-agent \
  --mode ebpf --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock"
```

See [EBPF_SETUP.md](EBPF_SETUP.md), [ROADMAP_V3.md](ROADMAP_V3.md), [VMI.md](VMI.md).
