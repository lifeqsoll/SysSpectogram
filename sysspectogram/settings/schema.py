"""Load configs/schema.yaml, validate values, build diffs with explanations, check i18n."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

LANGS = ("en", "ru")
DEFAULT_LANG = "en"


@dataclass(frozen=True)
class SettingDiff:
    key: str
    title: str
    old: Any
    new: Any
    description: str
    restart: bool


def load_schema(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "config.schema.v1":
        raise ValueError("not a config.schema.v1 document")
    return data


def settings_by_key(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["key"]: s for s in schema.get("settings") or []}


def get_value(cfg: dict[str, Any], dotted: str) -> Any:
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def set_value(cfg: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = cfg
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def validate_value(entry: dict[str, Any], value: Any) -> list[str]:
    errors: list[str] = []
    kind = entry.get("type")
    key = entry["key"]
    if kind == "bool":
        if not isinstance(value, bool):
            errors.append(f"{key}: expected true or false")
    elif kind in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{key}: expected a number")
        else:
            if kind == "int" and not isinstance(value, int):
                errors.append(f"{key}: expected an integer")
            lo, hi = entry.get("min"), entry.get("max")
            if lo is not None and value < lo:
                errors.append(f"{key}: below minimum {lo}")
            if hi is not None and value > hi:
                errors.append(f"{key}: above maximum {hi}")
    elif kind == "enum":
        if value not in (entry.get("choices") or []):
            errors.append(f"{key}: must be one of {entry.get('choices')}")
    elif kind == "string":
        # never_ban_cidrs: UI sends a comma-separated string; YAML/export may be a list.
        if key == "response.never_ban_cidrs":
            from sysspectogram.admin_ip import validate_never_ban_value

            if isinstance(value, list):
                if not all(isinstance(x, str) for x in value):
                    errors.append(f"{key}: list entries must be strings")
                    return errors
                if sum(len(x) for x in value) > 2048:
                    errors.append(f"{key}: string too long (max 2048)")
                    return errors
            elif not isinstance(value, str):
                errors.append(f"{key}: expected a string")
                return errors
            elif len(value) > 2048:
                errors.append(f"{key}: string too long (max 2048)")
                return errors
            _, err = validate_never_ban_value(value)
            if err:
                errors.append(f"{key}: {err} (reject /0, loopback, unspecified, wide prefixes)")
        elif not isinstance(value, str):
            errors.append(f"{key}: expected a string")
        elif len(value) > 2048:
            errors.append(f"{key}: string too long (max 2048)")
    return errors


def validate_changes(schema: dict[str, Any], changes: dict[str, Any]) -> list[str]:
    known = settings_by_key(schema)
    errors: list[str] = []
    for key, value in changes.items():
        entry = known.get(key)
        if entry is None:
            errors.append(f"{key}: not in the settings schema")
            continue
        errors.extend(validate_value(entry, value))
    return errors


def explain_diff(
    schema: dict[str, Any],
    current: dict[str, Any],
    changes: dict[str, Any],
    lang: str = DEFAULT_LANG,
) -> list[SettingDiff]:
    """Plain explanation of each change in the requested language (falls back to en)."""
    if lang not in LANGS:
        lang = DEFAULT_LANG
    known = settings_by_key(schema)
    out: list[SettingDiff] = []
    for key, new in changes.items():
        entry = known[key]
        old = get_value(current, key)
        if old == new:
            continue
        out.append(
            SettingDiff(
                key=key,
                title=entry["title"].get(lang) or entry["title"][DEFAULT_LANG],
                old=old,
                new=new,
                description=entry["description"].get(lang) or entry["description"][DEFAULT_LANG],
                restart=bool(entry.get("restart", False)),
            )
        )
    return out


def check_i18n(schema: dict[str, Any]) -> list[str]:
    """Every group and setting needs non-empty title and description in every language."""
    problems: list[str] = []
    for gid, group in (schema.get("groups") or {}).items():
        for lang in LANGS:
            if not str((group.get("title") or {}).get(lang) or "").strip():
                problems.append(f"group {gid}: missing title.{lang}")
    for entry in schema.get("settings") or []:
        key = entry.get("key", "?")
        for field in ("title", "description"):
            block = entry.get(field) or {}
            for lang in LANGS:
                if not str(block.get(lang) or "").strip():
                    problems.append(f"{key}: missing {field}.{lang}")
        if entry.get("group") not in (schema.get("groups") or {}):
            problems.append(f"{key}: unknown group {entry.get('group')!r}")
    return problems
