# Fleet hub (admin PC)

Run the **fleet control plane** on a laptop or small always-on box. Workers stay on the VPS; the hub only needs OpenSSH Client, Python, and a user venv.

Full ops reference: [FLEET.md](FLEET.md). Edge / CDN: [EDGE.md](EDGE.md).

---

## What the hub is (and is not)

| Hub has | Hub does **not** need |
|---------|------------------------|
| OpenSSH Client (`ssh` / `ssh.exe`) | `sysspectogram-helper` / polkit |
| Python **3.10+** + pip | Local guard / nft overlays |
| Wheel installed into a **user** venv | `/opt/sysspectogram` system tree |
| `fleet.json` + optional fleet Telegram bot | Running protect on the admin PC |

Soft host mitigation on a VPS is **not** anti-DDoS. Volumetric floods need CDN/WAF — see [EDGE.md](EDGE.md). Soft ≠ scrubber.

---

## Day-0 on the admin PC

1. Install **OpenSSH Client** (Windows Optional Feature, or `openssh-client` / built-in on macOS/Linux).
2. Create a user venv and install the wheel (or editable checkout):

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip
pip install /path/to/sysspectogram-*.whl
# or: pip install -e /path/to/SysSpectogram
```

3. Point runtime state at the hub tree (or leave unset to use the checkout / XDG defaults):

```bash
export SYSSPECTOGRAM_HOME=/path/to/hub-or-checkout
```

`fleet.json` lives under a portable config dir (override with `SYSSPECTOGRAM_FLEET_PATH`):

| OS | Default path |
|----|----------------|
| Linux | `$XDG_CONFIG_HOME/sysspectogram/fleet.json` or `~/.config/sysspectogram/fleet.json` |
| macOS | `~/Library/Application Support/sysspectogram/fleet.json` |
| Windows | `%APPDATA%\sysspectogram\fleet.json` |

4. Pair each VPS and register hosts — see [FLEET.md](FLEET.md) Day-0. Then pin SSH keys before mutating ops.

---

## Safety on the hub

- **Pin host keys** before Attack / unlock-locked / ban / profile-apply:

```bash
python -m sysspectogram fleet pin-host --id web1 --host-key-line 'ssh-ed25519 AAAA…'
```

Mutating fleet SSH requires `host_key_line` unless `FLEET_SSH_TOFU=1`.

- **Destructive CLI** (`attack`, `release`, `unlock-locked`, `ban`, …) needs `--yes` when stdin is not a TTY.
- Soft shield on workers = L1 IP ban; L2/L3 are intentional site/lockdown — not a substitute for Edge Under Attack.

---

## Quick smoke

See [scripts/fleet-hub-smoke.md](../scripts/fleet-hub-smoke.md).

```bash
python -m sysspectogram fleet path
python -m sysspectogram fleet status --scope all
python -m sysspectogram edge status
```

Optional fleet Telegram on the hub: `FLEET_TELEGRAM_BOT_TOKEN`, `FLEET_TELEGRAM_CHAT_ID`, and allowlist `FLEET_TELEGRAM_ALLOW_USERS` (comma-separated **user** IDs only — group/channel IDs are ignored; groups require this list).
