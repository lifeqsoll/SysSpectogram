# SysSpectogram v1.5.0

Host perimeter + agent integrity release: faster Control Center charts, per-source port-scan scoring, live **guard-core** RuleEngine/risk over a Unix socket, default **ONNX** host path (metrics-only without artifacts), and musl agent builds with **eBPF on by default**.

Docs: [INSTALL](INSTALL.md) · [INSTALL (RU)](INSTALL_RU.md) · [EBPF_SETUP](EBPF_SETUP.md) · [NFT_COEXISTENCE](NFT_COEXISTENCE.md) · [ML](ML.md) · [CHANGELOG](../CHANGELOG.md)

---

## Assets (after CI)

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.5.0_amd64.AppImage` / `.deb` (+ `.minisig`) | Desktop — note **no** `v` in the filename (`VER="${TAG#v}"`) |
| Fleet Hub AppImage / `.deb` / `.dmg` / `.exe` (+ `.minisig`, `SHA256SUMS.fleet-center`) | Fleet |
| `sysspectogram-1.5.0-*.whl` + musl agent (+ sha256 / minisig) | Stack |
| `sysspectogram-helper-x86_64-linux` (+ sha256 / minisig) | Soft/full bans on friend path |
| `friend-day0.sh` / `install-helper-from-release.sh` (+ minisig) | Headless |
| `SHA256SUMS` / `SHA256SUMS.desktop` / `SHA256SUMS.fleet-center` + `.minisig` | Verify |

GUI, wheel, agent, and helper must match **this tag**. Trusted comment shape: `sysspectogram v1.5.0 <file>`.

---

## Highlights

### Control Center & charts

- Downsample + incremental timeseries tails (`max_points` / `after_ts`).
- Multi-metric **grid**, shared Charts/Dashboards poller, cursor sync, overlays (risk+threshold, score+ml_raw, mem/swap, net/disk).
- Stacked severity alert rates; marker jump to Alerts.
- Fleet host timeseries over SSH.

### Perimeter & Telegram

- Port scans counted **per source IP** (`scan_unique_ports`); `public_ports` + optional `inbound_flood_suspected`.
- Telegram Shield warns when public ports are exposed.
- **/notify** filters: groups (internet noise, scans, SSH, egress/DNS, host ML, eBPF, critical), min severity, per-rule overrides; `/notify ids` lists ids.

### guard-core

- Live **RuleEngine**, **decide_risk**, and helper **ban** over `serve` Unix JSONL (defaults on).
- CLI: `metrics`, `auth-fail-ip`, `tcp-addr`, `render`, `serve`.
- Python falls back if the binary/socket is missing.

### Agent / eBPF

- Release musl agent enables **eBPF by default**; runtime prints `mode=ebpf` or `mode=proc (ebpf unavailable: …)`.
- systemd unit: CAP_BPF / PERFMON / SYS_RESOURCE / SYS_PTRACE; `MemoryDenyWriteExecute=no`.
- Optional agent `onnx` feature (`tract-onnx`) for shadow scores — not in the default musl binary.

### ML

- Default `runtime.prefer: onnx` — without `cnn.onnx` / artifacts the host stays on a **safe metrics-only** path.
- `ml.mode: one_class`; adaptive thresholds on; promote/shadow/rollback; model-occlusion explain.
- Feature-event JSONL + weak labels (including Telegram actions).

### Stability & rootkit honesty

- Non-UTF8 `/proc/*/comm` no longer crashes perimeter mapping.
- Timeseries disk-full no longer kills the sample loop.
- `(deleted)` exe after package upgrade → **info**, not high (`audit.deleted_exe_downgrade_on_upgrade`).
- Telegram long-poll exponential backoff on API failures.

### nft

- Migrating legacy `ban6` (timeout-only) to `interval,timeout` **preserves** active IPv6 members (empty `nft -j` falls back to text parse).

---

## Breaking / behaviour changes vs 1.4.x

1. Default **`runtime.prefer: onnx`** (was `notorch`). Missing artifacts → metrics-only, not a hard fail.
2. Prefer **`perimeter.scan_unique_ports`**; `scan_unique_ips` remains a deprecated alias with a warning.
3. Many IPs on :80/:443 alone no longer fire `port_scan_suspected` — use flood/baseline rules.
4. `deleted_exe` severity can drop to info after a package upgrade unless the paranoid flag is off.

Config: `configs/default.yaml` (`public_ports`, `scan_unique_ports`, `audit.deleted_exe_downgrade_on_upgrade`, `runtime.prefer`).

---

## Known limitations

- Agent ONNX (`tract-onnx`) is feature-gated and off by default; scores are extras only and do not replace rule severity.

---

## Install / upgrade

Friend / headless: use assets from **this** release with minisign — see [INSTALL](INSTALL.md) / [INSTALL_RU](INSTALL_RU.md) / [FRIEND](FRIEND.md).

```bash
TAG=v1.5.0
# verify + install from release assets (not raw git)
```

Full detail: [CHANGELOG.md](../CHANGELOG.md).
