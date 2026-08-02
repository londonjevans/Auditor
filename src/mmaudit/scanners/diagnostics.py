"""Typed, path-safe scanner preflight diagnostics."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

MAX_PUBLIC_TOOL_VERSION_CHARACTERS = 256
MAX_PRIVATE_VERSION_PROBE_CHARACTERS = 64 * 1024


class ExecutableVersionProbeStatus(StrEnum):
    """Terminal result of one isolated, scrubbed-environment version probe."""

    SUCCESS = "success"
    EXECUTION_REFUSED = "execution_refused"
    INTERPRETER_OR_LOADER_FAILURE = "interpreter_or_loader_failure"
    ISOLATION_FAILURE = "isolation_failure"
    INVALID_VERSION = "invalid_version"
    TIMED_OUT = "timed_out"


class ScannerExecutableState(StrEnum):
    """The three operator-facing availability states required by preflight."""

    ABSENT = "absent"
    PRESENT_ISOLATION_UNEXECUTABLE = "present_isolation_unexecutable"
    PRESENT_EXECUTABLE = "present_executable"


@dataclass(frozen=True, slots=True)
class ExecutableVersionProbe:
    """Path-free public facts from one version probe.

    Raw stdout and stderr are deliberately absent. They remain only in the private
    run directory used for the probe.
    """

    status: ExecutableVersionProbeStatus
    version: str | None
    diagnostic: str | None
    return_code: int | None


@dataclass(frozen=True, slots=True)
class ScannerExecutablePreflight:
    """Local operator preflight result; never a client-report schema."""

    state: ScannerExecutableState
    resolved_path: Path | None
    version: str | None
    failure_kind: ExecutableVersionProbeStatus | None
    diagnostic: str | None


def validated_public_tool_version(value: str) -> str | None:
    """Return one canonical public version line, or ``None`` when unsafe.

    Public versions are intentionally much stricter than private tool output:
    bounded, NFC-normalized, one line, free of control characters and free of
    absolute POSIX, Windows, UNC, or ``file:///`` host paths.
    """

    if (
        not value
        or value != value.strip()
        or len(value) > MAX_PUBLIC_TOOL_VERSION_CHARACTERS
        or "\n" in value
        or "\r" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
        or "/" in value
        or "\\" in value
        or "=" in value
    ):
        return None
    return value


def select_public_tool_version_line(
    raw_output: str,
    *,
    forbidden_values: Iterable[str] = (),
) -> str | None:
    """Select one safe version-bearing line from bounded private output.

    Several trusted tools emit a banner before the actual version (notably
    ``solc``), while others emit build metadata after it. Prefer the first safe
    line containing a digit, then fall back to the first safe line.
    """

    if len(raw_output) > MAX_PRIVATE_VERSION_PROBE_CHARACTERS:
        return None
    meaningful_forbidden_values = tuple(
        sorted({value.casefold() for value in forbidden_values if len(value.strip()) >= 8})
    )
    safe_lines = tuple(
        validated
        for line in raw_output.splitlines()
        if (validated := validated_public_tool_version(line.strip())) is not None
        and not any(value in validated.casefold() for value in meaningful_forbidden_values)
    )
    return next(
        (line for line in safe_lines if any(character.isdigit() for character in line)),
        safe_lines[0] if safe_lines else None,
    )
