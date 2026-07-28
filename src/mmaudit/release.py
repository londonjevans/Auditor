"""Stable gate and verdict identities for authoritative release evidence."""

from __future__ import annotations

from enum import StrEnum


class ReleaseGateId(StrEnum):
    """The exact fixed twelve-gate release portfolio."""

    ARTIFACTS = "artifacts"
    BENCHMARK_CERTIFICATE = "benchmark_certificate"
    DOCTOR = "doctor"
    MANIFESTS = "manifests"
    MAXIMUM_ASSURANCE_RUN = "maximum_assurance_run"
    MODEL_BENCHMARK = "model_benchmark"
    MYPY = "mypy"
    PYTEST = "pytest"
    REPLAY = "replay"
    RUFF_CHECK = "ruff_check"
    RUFF_FORMAT = "ruff_format"
    SCHEMAS = "schemas"


class ReleaseGateStatus(StrEnum):
    """One derived gate outcome."""

    PASSED = "passed"
    BLOCKED_TECHNICAL = "blocked_technical"
    FAILED = "failed"


class ReleaseStatus(StrEnum):
    """Aggregate release outcome; only authoritative validation may certify it."""

    COMPLETE = "complete"
    BLOCKED_TECHNICAL = "blocked_technical"
    FAILED = "failed"
