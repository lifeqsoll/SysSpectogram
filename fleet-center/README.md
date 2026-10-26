# SysSpectogram Fleet Hub

Thin desktop app for **fleet-only** ops (multi-VPS from an admin PC). Reuses Control Center Tauri/Svelte patterns but strips protect/helper/onboarding noise.

Modes from `fleet.json` host count:

| N | UI |
|---|----|
| 0 | Pair / add wizard |
| 1 | Host shell (status, unlock, L2/L3, release, ban, incidents, warmup) |
| ≥2 | Overview table + mass ops + drill-down to host shell |

Edge / CDN panel is always visible. Destructive actions (L2, L3, BAN, UNLOCK, RELEASE, EDGE) require typing the confirm word. Raw `device_token` is never shown after add (password field once; lists use `token_set`).

## Run (dev)

From the **repo root**, ensure the Python package is importable (`.venv` recommended):

```bash
cd fleet-center
npm install
npm run tauri dev
```

Requires: Node 20+, Rust toolchain, system deps for Tauri 2 (same as Control Center).

Optional env:

- `SYSSPECTOGRAM_HOME` — project root (auto-detected from checkout in `tauri dev`)
- `SYSSPECTOGRAM_PYTHON` — interpreter (defaults to `$HOME/.venv/bin/python` under the root)

Dev UI port: **1421** (Control Center uses 1420).

## CLI bridge

Rust invokes `python -m sysspectogram` with argv arrays only — see [docs/FLEET_CLI.md](../docs/FLEET_CLI.md).
