# nftables coexistence (ufw / firewalld / Docker / fail2ban)

SysSpectogram uses its **own** nft table and does **not** flush the global ruleset in production.

## What we own

| Object | Notes |
|---|---|
| Table `inet sysspectogram` | Isolated from others |
| Chain `input` | `type filter hook input priority -10; policy accept` |
| Table `inet ss_kirk` | Only in kirk/isolate lockdown |

There is **no** `flush ruleset` on the live path. Hook is **input only** — Docker/container **forward** traffic is untouched.

## With other tools

- **ufw / firewalld**: separate tables/backends; SysSpectogram does not rewrite their chains.
- **Docker**: forward chain not modified; published ports keep working.
- **fail2ban / crowdsec**: may ban the same IP → duplicate ban, not a conflict. Prefer one autoban owner or align never-ban lists.
- **Cloud / provider firewall**: still the first line for volumetric DDoS; host nft is host mitigation only.

## Isolate / kirk

`kirk_isolate` flushes **only** `inet ss_kirk` and sets a strict policy with `never_ban` exceptions. Intentional full host lockdown — not a global nft wipe.

## Sets (`ban4` / `ban6`)

Named sets live in `inet sysspectogram` with kernel timeouts. Soft/full bans go through these sets (or the helper when the guard is non-root).

**IPv6 migrate (1.5.0):** upgrading a legacy `ban6` set from `flags timeout` to `flags interval,timeout` keeps existing members. Empty `nft -j` output falls back to parsing the text `nft list` so active IPv6 bans are not dropped.

## Startup note

When Docker is detected (`/.dockerenv` or `docker0`), status may note that the forward chain is not touched. No automatic firewall changes for that.
