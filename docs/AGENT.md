# SysSpectogram agent (v3 integrity + metrics sensor)

Rust side-car: process/integrity signals + lightweight `/proc` metrics for the live web bus. Complements host-metric CNN (still Python for full feature vectors).

Optional **eBPF** mode: `execve` / `openat` via clang BPF object + Aya loader. See [EBPF_SETUP.md](EBPF_SETUP.md).

## What it closes vs v0.2

| Layer | v0.2 | Agent |
| --- | --- | --- |
| Host ML | CPU/mem/net/disk/GPU windows (Python) | — (full columns still Python) |
| Live web charts | Python collector | **Rust metrics** (`kind=metrics`) |
| Quiet file touch | often missed | `/proc` fd sample + **inotify** + optional eBPF `openat` |
| New processes | audit snapshot | new PID ≈ exec + optional eBPF `execve` |
| Kernel modules | soft name heuristics | `/proc/modules` delta |
| FIM | — | optional sha256 watches (`--fim`, `full` load profile) |

**Not** a full rootkit killer. Userspace `/proc` can still be lied to by advanced LKM; eBPF helps but is not a silver bullet.

## eBPF (v0.4)

Build needs: `clang`, `llvm`, kernel BTF (`/sys/kernel/btf/vmlinux`).  
Attach needs: **real root** (on Arch, `/sys/kernel/tracing` is `0700` — `setcap` alone → `tracefs not found`).

```bash
# Arch
sudo pacman -S clang llvm
cd agent && cargo build --release
sudo -E ./target/release/sysspectogram-agent \
  --mode ebpf \
  --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock"
```

Without root/clang, `--mode ebpf` falls back to userspace (`/proc` + inotify). Details: [EBPF_SETUP.md](EBPF_SETUP.md).

## Build

```bash
cd agent
cargo build --release
# binary: agent/target/release/sysspectogram-agent
# skip BPF: SYSSPECTOGRAM_SKIP_EBPF=1 cargo build --release --no-default-features
```

## Run

```bash
# configs/default.yaml → agent.enabled: true, agent.metrics: true
.venv/bin/python -m sysspectogram guard --model artifacts/real_v3 --telegram --web --dry-run
# auto_start spawns the agent; or:
./agent/target/release/sysspectogram-agent --socket /tmp/sysspectogram-agent.sock --metrics-ms 1000
```

Telegram AGENT alerts include **Kill** / **Ignore** inline buttons (after console `/unlock`).

## Alert JSON (`schema: sysspectogram.agent.v1`)

Rules include: `agent_open_sensitive`, `agent_exec_burst`, `agent_connect_burst`, `agent_module_load`, `agent_fim_*`, `agent_ebpf_execve`, `agent_ebpf_openat`.

## Metrics JSON (`schema: sysspectogram.metrics.v1`)

```json
{"schema":"sysspectogram.metrics.v1","kind":"metrics","cpu_percent":12.0,"mem_percent":40.0}
```

## Config

```yaml
agent:
  enabled: true
  auto_start: true
  mode: userspace   # or ebpf (needs root to attach)
  metrics: true
  socket: null      # null → $XDG_RUNTIME_DIR/sysspectogram-agent.sock (0600)
  cooldown_sec: 60
```

## systemd

Unit: [scripts/systemd/sysspectogram-agent.service](../scripts/systemd/sysspectogram-agent.service). Install helper: [scripts/install.sh](../scripts/install.sh).

## Roadmap

[ROADMAP_V3.md](ROADMAP_V3.md)
