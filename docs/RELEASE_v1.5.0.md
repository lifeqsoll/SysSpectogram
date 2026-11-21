# SysSpectogram 1.5.0 — release notes (DRAFT for review)

**Status:** preparation only — **do not tag / publish** until Mell finishes review.  
**Version:** `1.5.0` (pyproject / Cargo / Control Center / helper / agent aligned; `scripts/check_versions.py` green).  
**Base:** `main` @ work after `fix/audit-686a05f` merge (`d848280` + local prep).

## Highlights

1. **Control Center performance & charts** — downsample + incremental tails, shared poller/cache, multi-metric grid with cursor sync, fleet host timeseries over SSH.
2. **Perimeter** — port scans counted **per source IP** (not “many IPs on :443”); `public_ports` + optional `inbound_flood_suspected`; Telegram Shield warns on public ports.
3. **Rootkit** — `(deleted)` exe after package upgrade → **info**, not high (`audit.deleted_exe_downgrade_on_upgrade`).
4. **Stability** — non-UTF8 `/proc` comm; timeseries disk-full does not kill sampling; TG poll backoff.
5. **guard-core** — new Rust crate with `schema_version` alerts + procfs metrics (foundation for 1.6 migration).
6. **eBPF** — release musl build ships with eBPF feature; runtime prints `mode=ebpf` or `mode=proc (ebpf unavailable: …)`.
7. **ML prep** — default prefer ONNX; feature-event JSONL + weak labels; mini reference dataset; viz debounce.

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
- [ML.md](ML.md) — onnx default, feature stream, 1.6 known items  
- [FLEET.md](FLEET.md) / [CONTROL_CENTER.md](CONTROL_CENTER.md) — charts / fleet host picker  

## Known limitations → 1.6

- Complete `guard-core` **shadow swap** of live Python loops (crate already has metrics/flow/auth/plotters + CI).
- Agent ONNX via `tract`, signed promote/shadow loop.
- Per-rule adaptive thresholds beyond the mini reference CI gate.

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
