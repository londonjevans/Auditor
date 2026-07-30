"""Stable versioned JSON serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def stable_json(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    if isinstance(value, BaseModel):
        validated = type(value).model_validate(value.model_dump(mode="python"))
        payload: Any = validated.model_dump(mode="json")
    else:
        payload = value
    return (
        json.dumps(
            payload,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def write_json(path: Path, value: BaseModel | dict[str, Any] | list[Any]) -> None:
    serialized = stable_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
