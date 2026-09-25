# Shareable baseline profile packs

Packs are **`tar.gz`** published as GitHub Release assets (not Hugging Face).

## Why

Cold-start on a typical VPS role (Ubuntu+nginx, Docker host, 3x-ui, generic Linux) without waiting for local `collect` weeks. Then **fine-tune** on your own host.

## Load profiles (CPU budget)

| Profile | Target | Behavior |
| --- | --- | --- |
| `lite` (default) | 1–2 vCPU VPS | slower polls, fewer alerts/min, FIM off, flow off |
| `full` | 4+ vCPU VDS | faster polls, FIM on, flow lite on, higher agent weight |

```yaml
load_profile: lite   # or full
# env: SYSSPECTOGRAM_LOAD_PROFILE=full
```

`scripts/install.sh` accepts `LOAD_PROFILE=full`.

## Pack format (`sysspectogram.profile.v1`)

```
profile-ubuntu-nginx-v1/
  manifest.json
  README.md
  host/          # CNN+IF artifacts (meta.json, models…)
  agent/         # optional agent_iforest.joblib
```

Sidecar: `profile-….tar.gz.sha256`.

## CLI

```bash
python -m sysspectogram profiles list
python -m sysspectogram profiles pack \
  --name profile-ubuntu-nginx-v1 --role ubuntu-nginx \
  --host artifacts/real_v3 --out dist/profile-ubuntu-nginx-v1.tar.gz \
  --agent-if artifacts/agent_iforest.joblib

python -m sysspectogram profiles pull \
  --url https://github.com/<org>/SysSpectogram/releases/download/v0.4.0/profile-ubuntu-nginx-v1.tar.gz \
  --out /tmp/p.tar.gz --sha256 <hex>   # sha256 required (or --insecure)

python -m sysspectogram profiles install /tmp/p.tar.gz \
  --dest artifacts/profiles/ubuntu-nginx --sha256 <hex>

python -m sysspectogram guard --model artifacts/profiles/ubuntu-nginx/host --telegram --dry-run
python -m sysspectogram profiles finetune-help --host artifacts/profiles/ubuntu-nginx/host
```

## Trust

- Packs are **weights only** (no scripts executed from the archive).
- Path traversal in tar is rejected.
- Prefer verifying `.sha256`.
- Third-party packs change FP/FN — fine-tune locally before trusting production bans.
