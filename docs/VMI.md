# VMI out-of-band — deferred to **v1.0**

> **Decision (2026-09-25):** live `sysspectogram-vmi` binary is **not** in v0.5.  
> Ship in **v1.0** only if self-host KVM demand is real. Cloud shared VPS cannot use it.

## Why later

VMI needs **hypervisor host access** (libvirt/KVM + often libvmi). Typical rented VPS has no HV API. Building/maintaining a host agent is a large separate product surface.

## What it would do (v1.0)

- Run on the **host**, not inside the guest.
- Read guest RAM task/module lists; compare with in-guest agent heartbeat.
- On mismatch → pause VM / host nft / alert (true out-of-band trust = `kirk.trust: out-of-band`).

## Config (reserved)

```yaml
kirk:
  vmi: false   # ignored until v1.0
```

Until then: use in-guest Kirk + optional **IMA/TPM measured** label — see [KIRK.md](KIRK.md).
