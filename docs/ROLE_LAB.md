# VPS Role Lab - train baseline packs without VMs

Collect metric spectrograms for common VPS roles on your builder PC, then train
profile packs. No KVM/libvirt required.

## Roles

| Role | Shape |
| --- | --- |
| `ssh` | Quiet idle + rare bursts |
| `nginx` | HTTP-like CPU/net (local http.server; nginx configtest if installed) |
| `python` | Sustained mid CPU + memory waves |
| `docker` | Bursty load + process churn |
| `wireguard` | Mostly idle + rare UDP-like net bursts |
| `panel` | 3x-ui style: light HTTP + periodic admin bursts |

## Collect

```bash
python -m sysspectogram role-lab list
python -m sysspectogram role-lab run --role nginx --out artifacts/rolelab/nginx \
  --duration 600 --synthetic-only
```

Listeners bind 127.0.0.1 only. WAN is not opened.

Interrupted collect is OK: `role-lab train` recovers a short anomaly clip if needed.

## Train on PC

```bash
pip install -e '.[ml]'
python -m sysspectogram role-lab train \
  --role-dir artifacts/rolelab/nginx \
  --out artifacts/profiles/nginx/host \
  --pack dist/profile-nginx-v1.tar.gz \
  --epochs 12
```

Outputs:

- `artifacts/profiles/<role>/host/`
- `dist/profile-<role>-v1.tar.gz` + `.sha256`

Install on VPS with `profiles install` (see [PROFILES.md](PROFILES.md)).

## Design notes

- Anomaly clip (at least 75s) is collected after the normal window.
- Quality filters are off for role-lab so synthetic runs still train.
- Fine-tune on the real VPS before production trust.
