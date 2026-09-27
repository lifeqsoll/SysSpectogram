# SysSpectogram v0.7.1 — module_hide FP + Ignore mute

## Fixes

- **`agent_kirk_module_hide` false positive:** `/sys/module` lists kernel builtins (acpi, 8250, …) that never appear in `/proc/modules`. Cross-view now only compares **loadable** modules (those with `/sys/module/*/initstate`), so builtin noise no longer floods Telegram.
- **Ignore button for kirk/host alerts:** clicking Ignore on an alert without a process identity used to ack `"ignored"` without storing anything. It now **mutes by `rule_id`** (persisted in `state/process_labels.json`), and the guard skips muted rules.

## Upgrade

```bash
git pull
pip install -e '.[onnx]'   # or your usual install
cd agent && cargo build --release
# restart agent + guard
```

If spam already started, either Ignore once more (now persists) or:

```bash
python -c "
from sysspectogram.process_labels import ProcessLabelStore
from pathlib import Path
s = ProcessLabelStore(Path('state/process_labels.json'))
s.mute_rule('agent_kirk_module_hide', note='builtin-fp')
print('muted')
"
```
