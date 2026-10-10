"""Load protection scenario presets from configs/scenarios/*.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sysspectogram.settings.schema import LANGS, DEFAULT_LANG, validate_changes


@dataclass(frozen=True)
class Scenario:
    id: str
    title: dict[str, str]
    description: dict[str, str]
    overrides: dict[str, Any]
    path: Path

    def text(self, field: str, lang: str) -> str:
        block = getattr(self, field)
        if lang not in LANGS:
            lang = DEFAULT_LANG
        return str(block.get(lang) or block.get(DEFAULT_LANG) or "")


def load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "scenario.v1":
        raise ValueError(f"{path}: not a scenario.v1 document")
    return Scenario(
        id=str(data["id"]),
        title=dict(data.get("title") or {}),
        description=dict(data.get("description") or {}),
        overrides=dict(data.get("overrides") or {}),
        path=Path(path),
    )


def load_scenarios(directory: Path) -> list[Scenario]:
    return [load_scenario(p) for p in sorted(Path(directory).glob("*.yaml"))]


def check_scenarios(scenarios: list[Scenario], schema: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for sc in scenarios:
        for lang in LANGS:
            if not str(sc.title.get(lang) or "").strip():
                problems.append(f"{sc.id}: missing title.{lang}")
            if not str(sc.description.get(lang) or "").strip():
                problems.append(f"{sc.id}: missing description.{lang}")
        for err in validate_changes(schema, sc.overrides):
            problems.append(f"{sc.id}: {err}")
    return problems
