# OSINT 2.0

Recon is a **score**, not a wall of text.

## Pipeline

1. Perimeter alert with IP -> optional `run_full_recon` (cooldown).
2. **`recon_score` 0..1** from cached DNSBL/Tor + ASN heuristics (+ canary = 1.0).
3. Append **`reports/recon/recon_dossier.jsonl`** (append-only).
4. Auto-ban TTL scales with score (`0.5x` .. `3x` base TTL).

## Cache

- In-memory TTL + optional SQLite (`state/recon_cache.sqlite` when configured).
- Tor exit list refresh is background (`tor_exit_refresh`); lookups use cache only.
- Spamhaus ZEN reverse lookup results cached 24h.

## CLI / TG

- `/recon <ip>` still prints human summary including `score=`.
- Verdict notes: `dnsbl_zen`, `tor_exit`, `cloud_asn`, `canary_hit`.

## Config

```yaml
recon:
  auto: false
  cooldown_sec: 900
  nmap: false
```

See [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md).
