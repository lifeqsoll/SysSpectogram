# SysSpectogram v1.2.1

Patch release: install/CI blockers after v1.2.0.

## Fixes

- **Wheel config:** `configs/default.yaml` (+ schema/scenarios) shipped under `sysspectogram/resources/configs/` so `pip install` / Install stack work without a source tree
- **control.sock:** guard `_resolve(state/…)` uses `state_root()` / `SYSSPECTOGRAM_HOME` (same place as CLI)
- **Release CI:** minisign apt failure falls back to jedisct1 binary; `musl-agent` uploads with `tag_name` on `workflow_dispatch` (restores `SHA256SUMS`)
- **Tests:** lazy ML import checked in a subprocess (no `sys.modules.pop("torch")`); CLI parity docs for `eval` / `metrics`

## Upgrade

Same friend path as v1.2.0 — Install stack / `friend-day0` for tag **v1.2.1**.
