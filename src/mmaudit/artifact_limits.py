"""Shared byte ceilings for bounded on-disk artifacts."""

from __future__ import annotations

from typing import Final

MAX_JSON_ARTIFACT_BYTES: Final[int] = 100_000_000
"""Maximum encoded size of a JSON run artifact accepted by the manifest."""
