#!/usr/bin/env python3
"""CI check: settings schema validates, every key has en and ru text, defaults are valid.

Exit code 0 when clean, 1 when problems are found.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from sysspectogram.settings.scenarios import check_scenarios, load_scenarios  # noqa: E402
from sysspectogram.settings.schema import check_i18n, load_schema, validate_value  # noqa: E402


def main() -> int:
    schema = load_schema(ROOT / "configs" / "schema.yaml")
    problems = check_i18n(schema)
    defaults = yaml.safe_load((ROOT / "configs" / "default.yaml").read_text(encoding="utf-8"))
    for entry in schema.get("settings") or []:
        default = entry.get("default")
        problems.extend(validate_value(entry, default))
        cur = defaults
        for part in entry["key"].split("."):
            if not isinstance(cur, dict) or part not in cur:
                problems.append(f"{entry['key']}: not present in configs/default.yaml")
                break
            cur = cur[part]
        else:
            if cur != default:
                problems.append(f"{entry['key']}: default.yaml={cur!r} schema default={default!r}")
    problems.extend(check_scenarios(load_scenarios(ROOT / 'configs' / 'scenarios'), schema))
    for p in problems:
        print(f"FAIL {p}")
    print(f"settings={len(schema.get('settings') or [])} problems={len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
