# SysSpectogram 1.5.0 — release notes (DRAFT for review)

**Status:** preparation only — **do not tag / publish** until Mell finishes review.  
**Version:** `1.5.0` (pyproject / Cargo / Control Center / helper / agent aligned; `scripts/check_versions.py` green).  
**Base:** `main` @ work after `fix/audit-686a05f` merge (`d848280` + local prep).

## Highlights

1. **Control Center performance & charts** — downsample + incremental tails, shared poller/cache, multi-metric grid with cursor sync, fleet host timeseries over SSH.
2. **Perimeter** — port scans counted **per source IP** (not “many IPs on :443”); `public_ports` + optional `inbound_flood_suspected`; Telegram Shield warns on public ports.
3. **Rootkit** — `(deleted)` exe after package upgrade → **info**, not high (`audit.deleted_exe_downgrade_on_upgrade`).
4. **Stability** — non-UTF8 `/proc` comm; timeseries disk-full does not kill sampling; TG poll backoff.
5. **guard-core** — live **RuleEngine** + **decide_risk** + helper ban over `serve` socket (defaults on); metrics/auth/tcp/render; Python fallback if binary/socket missing.
6. **eBPF** — release musl build ships with eBPF feature; runtime prints `mode=ebpf` or `mode=proc (ebpf unavailable: …)`.
7. **ML** — ONNX prefer + `one_class` default; feature events + weak-label audit; adaptive thresholds on; model-occlusion explain; promote/shadow; optional agent `tract-onnx`.
8. **Charts** — combined overlays, stacked severity alerts, shared poller with Dashboards, marker jump to Alerts.

## Migration

| Old | New |
|---|---|
| `perimeter.scan_unique_ips` | Prefer `scan_unique_ports` (alias still works, warns) |
| Many IPs on :80/:443 → `port_scan_suspected` | No longer; use flood rule / baseline |
| `runtime.prefer: notorch` default | `onnx` (still fine without artifacts) |
| `deleted_exe` always high | Downgraded after package upgrade unless paranoid flag off |

Config snippets: see `configs/default.yaml` (`public_ports`, `scan_unique_ports`, `audit.deleted_exe_downgrade_on_upgrade`).

## Docs

- [EBPF_SETUP.md](EBPF_SETUP.md) — requirements, fallback, systemd caps  
- [NFT_COEXISTENCE.md](NFT_COEXISTENCE.md) — ufw/firewalld/Docker/fail2ban  
- [ML.md](ML.md) — onnx default, feature stream, adaptive thresholds, promote/shadow, optional agent ONNX  
- [FLEET.md](FLEET.md) / [CONTROL_CENTER.md](CONTROL_CENTER.md) — charts / fleet host picker  

## Known limitations

- Agent ONNX is an optional `onnx` feature (`tract-onnx`), not linked into the default musl build; scores are extras only.

## Verify before tag (Mell)

```bash
python scripts/check_versions.py
pytest -q
(cd guard-core && cargo test -q)
(cd agent && cargo test -q)
(cd control-center && npm run check)
```

Then (after review only):

```bash
git tag -s v1.5.0 -m "SysSpectogram 1.5.0"
git push origin v1.5.0
gh release create v1.5.0 --title "SysSpectogram 1.5.0" --notes-file docs/RELEASE_v1.5.0.md
```

## Artifact expectations

- `sysspectogram-agent-*-linux-musl` with eBPF linked (strings / probes present).
- Python sdist/wheel from `python -m build`.
- Control Center AppImage rebuilt from `1.5.0` package metadata.
