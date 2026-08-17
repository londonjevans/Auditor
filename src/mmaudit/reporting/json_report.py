"""Stable versioned JSON serialization."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES

JsonReportValue = BaseModel | dict[str, Any] | list[Any]


class JsonArtifactTooLargeError(ValueError):
    """Raised before publication when canonical JSON exceeds its byte ceiling."""

    def __init__(self, *, actual_bytes: int, max_bytes: int) -> None:
        self.actual_bytes = actual_bytes
        self.max_bytes = max_bytes
        super().__init__(
            f"stable JSON artifact is {actual_bytes} bytes; maximum is {max_bytes} bytes"
        )


def stable_json(value: JsonReportValue) -> str:
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


def stable_json_bytes(value: JsonReportValue) -> bytes:
    """Return the exact UTF-8 bytes used for a stable JSON artifact."""

    return stable_json(value).encode("utf-8")


def write_json(path: Path, value: JsonReportValue) -> None:
    serialized = stable_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def write_json_bounded(
    path: Path,
    value: JsonReportValue,
    *,
    max_bytes: int = MAX_JSON_ARTIFACT_BYTES,
) -> int:
    """Atomically publish stable JSON only when its exact UTF-8 bytes fit the ceiling.

    Serialization and bound validation happen before the destination or its parent is
    touched. A temporary file in the destination directory is fully written and synced
    before one atomic replacement, so a failed write leaves any prior destination intact.
    The exact published byte count is returned.
    """

    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("JSON artifact byte ceiling must be a positive integer")

    serialized = stable_json_bytes(value)
    actual_bytes = len(serialized)
    if actual_bytes > max_bytes:
        raise JsonArtifactTooLargeError(actual_bytes=actual_bytes, max_bytes=max_bytes)

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        remaining = memoryview(serialized)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("bounded JSON artifact write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)

        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != actual_bytes
        ):
            raise OSError("bounded JSON temporary artifact is not exact and unique")

        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)

    return actual_bytes
