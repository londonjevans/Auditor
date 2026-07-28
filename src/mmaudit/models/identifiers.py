"""Canonical OpenRouter identifiers shared by every production model path."""

from __future__ import annotations

import re
from typing import Final

EXACT_MODEL_ID_PATTERN: Final = r"^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._:-]{0,255}$"
_MUTABLE_OR_ROUTED_PARTS = frozenset(
    {
        "auto",
        "free",
        "latest",
        "online",
        "random",
        "router",
    }
)


def is_exact_openrouter_model_id(value: object) -> bool:
    """Return whether a value is one exact non-routed lowercase author/model slug.

    Exact syntax is not proof that the provider deployment or alias is immutable.
    """

    if not isinstance(value, str) or re.fullmatch(EXACT_MODEL_ID_PATTERN, value) is None:
        return False
    _author, model = value.split("/", 1)
    variant_parts = {part for part in re.split(r"[:._-]+", model.casefold()) if part}
    return not bool(variant_parts & _MUTABLE_OR_ROUTED_PARTS)


def require_exact_openrouter_model_id(value: object, *, label: str = "model ID") -> str:
    """Return a validated exact identifier or fail without provider-controlled text."""

    if not is_exact_openrouter_model_id(value):
        raise ValueError(f"{label} must be an exact non-routed author/model identifier")
    assert isinstance(value, str)
    return value
