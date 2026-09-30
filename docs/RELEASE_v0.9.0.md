# SysSpectogram v0.9.0 — hardening + product finish

v0.9 hardens the single-VPS path without pretending to be kernel EDR, finishes
the operator story (Day-0, golden path, eval, threat model), and cleans up
overloaded README navigation.

## Included

### Safe artifacts (no pickle on the critical path)
- Train/export write `scaler.json` and `iforest.ssf.npz` (+ meta).
- Runtime refuses `.joblib`; migrate-only legacy read via
  `artifacts migrate --delete-legacy`.
- Agent IF train/load uses `.ssf.npz`.
- `supply_chain.enforce: true` refuses unsigned / unsafe loads.

### Remote alert sinks
```yaml
alerts:
  allow_private_sinks: false
  strict_secrets: true
  sinks:
    - type: file
      path: reports/alerts.jsonl
    # - type: syslog
    #   host: siem.example
    #   port: 6514
    #   transport: tls
    # - type: https
    #   url: https://collector.example/ingest
    #   token_env: SS_ALERT_TOKEN
```
Fail-open per sink. HTTPS SSRF guards + `token_env` for secrets. Not a full SIEM.

### FIM
- Baseline persists to `state/fim-baseline.json` (+ `.sha256` seal) via serde_json.
- Enabled by default on the `lite` load profile (longer interval).

### Hybrid watchdog
- Phoenix userspace twin + Dead-man remote emit; systemd `WatchdogSec`.
- Optional DKMS module `packaging/kmod/sysspectogram_wd` (PID registry;
  `watchdog.kernel_protect: false` by default).

### Narrow auto-isolate
```yaml
kirk:
  auto_isolate: false
  auto_isolate_host_risk: false
  host_risk_threshold: 0.99
```
Host-risk path still requires `allow_ssh_cidrs`.

### Docs & eval
- README EN/RU: grouped links, Limitations, ONNX VPS recipe.
- [DAY0_VPS.md](DAY0_VPS.md), [GOLDEN_PATH.md](GOLDEN_PATH.md),
  [EVAL.md](EVAL.md), [THREAT_MODEL.md](THREAT_MODEL.md),
  [SUPPLY_CHAIN_STORY.md](SUPPLY_CHAIN_STORY.md), [AGENT.md](AGENT.md).
- `scripts/eval_offline.py`, `scripts/demo_golden_path.sh`.

## Migrate existing models

```bash
python -m sysspectogram artifacts migrate --model artifacts/live --delete-legacy
python -m sysspectogram supply-chain manifest --root artifacts/live
# re-sign if you enforce
```

## Verify

```bash
pytest -q
cd agent && cargo check
python scripts/eval_offline.py --dataset dataset/ --methods zscore --out reports/eval
```

## Honest ceiling

Same-host root can stop units and wipe local disks. Remote sinks + signatures
make that louder and harder to hide — not impossible. VMI remains v1.0.
