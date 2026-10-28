# FAQ

Short answers for operators. Install detail: [INSTALL.md](INSTALL.md).

## Can I lock myself out (self-ban)?

Yes, if you enable **soft/full/isolate** auto-ban without listing your admin SSH source in `response.never_ban_cidrs`. Always seed never-ban **before** enabling bans. The guard also skips bans for **active SSH session** IPs when it can detect them. See [FRIEND.md](FRIEND.md) and `home health`.

## Why did protect stop after I closed SSH?

User systemd units stop on logout unless **linger** is enabled:

```bash
loginctl enable-linger "$USER"
```

Then `python -m sysspectogram protect enable` again.

## What is soft mode “confirm” / rollback?

Switching to **soft** (or stronger) modes can schedule a **pending rollback** timer. Confirm in Control Center / Telegram / web when prompted, or the mode reverts to **observe**. See `response.mode_rollback` in config schema.

## Which IP is my `ssh_source` for never-ban?

On the VPS, `${SSH_CONNECTION%% *}` (or `${SSH_CLIENT%% *}`) is usually **your laptop’s public IP**, not the server’s egress IP. From Windows use `curl.exe -4 ifconfig.me` on the client. Do not rely on bare `seed-never-ban` without `--ip` on cloud images (egress ≠ admin path).

## Do I need the helper for soft auto-ban?

**Yes** on typical friend installs: the guard runs non-root, so nft set bans go through **sysspectogram-helper** (group `sysspectogram`). Without helper or root, `home health` reports `ban_backend` not OK — stay on **observe** until helper is installed. Polkit helper is still used for other privileged settings.

## How are release binaries signed?

Release assets ship **SHA256SUMS** and, when published, **minisign** signatures. Friend install scripts refuse to run without verification. Details: [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [SECURITY.md](../SECURITY.md).

## Is host ML production-ready?

Treat it as **experimental**. Default guard paths do not require PyTorch on the VPS (`notorch` / ONNX). Run offline gates in [EVAL.md](EVAL.md) before trusting F1 / FPR claims on your data.

## Where is the comparison to fail2ban / Wazuh?

[COMPARISON.md](COMPARISON.md).
