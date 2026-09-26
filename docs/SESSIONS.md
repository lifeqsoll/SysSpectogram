# Unexpected SSH sessions

Watch interactive logins (`who`) and alert when a session appears **after** a learn window and is not allowlisted.

## Config

```yaml
sessions:
  enabled: true
  learn_sec: 120
  poll_sec: 15
  allow_users: []    # empty = any user after learn is unexpected
  allow_cidrs: []    # optional source IP allowlist
```

## Telegram

After learn: **Kick tty** / **Ban IP** (unlock-gated). Kick ends the login session on that TTY; Ban adds a temporary nft drop when response mode allows.

## Notes

- Learn on a quiet box so your own SSH is in the baseline.
- Complements agent root watch ([ROOT_WATCH.md](ROOT_WATCH.md)) — different signal (login vs uid=0 process).

See [TELEGRAM.md](TELEGRAM.md), [DAY0_VPS.md](DAY0_VPS.md).
