# SysSpectogram v0.5.0 — VPS Adopt + Kirk trust

Biggest release since v0.4: turn a hybrid ML host IDS into **practical VPS defense** you can run on a cheap box **without PyTorch**, with honest kernel-integrity labels and safer response actions.

## Why it matters

| Before (v0.4) | Now (v0.5) |
| --- | --- |
| Torch often blocked 1GB VPS | **`runtime: notorch` / `onnx`** — day-0 without CNN, or light ONNX |
| Retrain pain on the server | **Train bridge**: collect on VPS → train on PC → `artifacts push` back |
| “Rootkit” ≈ heuristics | **Kirk**: module eBPF, cross-view hide, kallsyms **presence** baseline |
| Unclear trust | **`kirk.trust`**: `best-effort` \| `measured` (IMA + Secure Boot/TPM) — no hype |
| IP bans only | **`kirk_isolate` / `kirk_release`** with TTL; TG `/kirk_release` (unlock-gated) |
| Flat auto-ban | **`response.mode`**: observe → shield → aggressive |

**Honest ceiling:** many Arch/cloud hosts have no IMA in-kernel and Secure Boot off → trust stays `best-effort`. That is correct. Live **VMI** (hypervisor) is deferred to **v1.0**.

## What's new

### VPS Adopt

- `runtime: notorch | onnx | torch_ml` (`SYSSPECTOGRAM_RUNTIME`)
- ONNX export/infer; train bridge (`data bundle` / `artifacts push` with checksum verify)
- Setup/bootstrap helpers

### Kirk (in-guest integrity)

- eBPF execve/openat/**module**; cross-view hide; `--kirk-seal` presence baseline
- `python -m sysspectogram kirk trust` (+ reason codes)
- Docs: [KIRK.md](docs/KIRK.md) · [VMI.md](docs/VMI.md) (VMI → v1.0)

### Response & safety

- nft `ss_kirk` isolate + TTL; refuse empty `allow_ssh_cidrs`
- `auto_isolate` allowlisted CRITICAL only (default **off**)
- Hardened push paths; no false `measured` on unreadable IMA

## Quick start

```bash
pip install -e ".[dev]"
cd agent && cargo build --release && cd ..
python -m sysspectogram kirk trust
python -m sysspectogram guard --telegram --dry-run

# ONNX
SYSSPECTOGRAM_RUNTIME=onnx python -m sysspectogram guard \
  --model artifacts/real_v3 --telegram --dry-run

# eBPF agent (root)
sudo -E ./agent/target/release/sysspectogram-agent \
  --mode ebpf --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock"
```

## Profile pack

sha256: `a8402315fec15ed9dd602f78dcbb8b59c680768d7f904e46175dd22d3abb20b4`

```bash
python -m sysspectogram profiles pull \
  --url https://github.com/lifeqsoll/SysSpectogram/releases/download/v0.5.0/profile-generic-linux-v1.tar.gz \
  --out /tmp/p.tar.gz \
  --sha256 a8402315fec15ed9dd602f78dcbb8b59c680768d7f904e46175dd22d3abb20b4

python -m sysspectogram profiles install /tmp/p.tar.gz \
  --dest artifacts/profiles/generic-linux \
  --sha256 a8402315fec15ed9dd602f78dcbb8b59c680768d7f904e46175dd22d3abb20b4
```

## Docs

- [ROADMAP_QUALITY.md](docs/ROADMAP_QUALITY.md)
- [TRAIN_BRIDGE.md](docs/TRAIN_BRIDGE.md)
- [KIRK.md](docs/KIRK.md)
- [VMI.md](docs/VMI.md)
- [CONFIG.md](docs/CONFIG.md)

## Notes

- Default runtime is **notorch** (host CNN off until onnx/torch_ml + `--model`).
- Do not enable `kirk.auto_isolate` without `allow_ssh_cidrs`.
- Seal kallsyms as the **same user** that runs the agent.
