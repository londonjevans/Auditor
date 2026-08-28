"""Explicit configuration custody for authenticated-runner schema retry continuity."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

from mmaudit.config import AuditConfig, load_config

AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT: Final = 3
AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT: Final = 1
AUTHENTICATED_RUNNER_LOGICAL_REQUEST_COUNT: Final = 96
FROZEN_QUALIFICATION_CONFIG_SHA256: Final = (
    "e81516464de46b3b10d4533b1c0f792ae895e09c43cafc2d01f60cc2ad5bc438"
)
FROZEN_QUALIFICATION_CONFIG_RAW_SHA256: Final = (
    "696b70a811835dc6d711048670dfb4055858b07cf3a07b518cd6a3af9f3a2dca"
)
RETRY_CONTINUITY_CONFIG_SHA256: Final = (
    "c848ab89d2ecce2c182c635eb2f4825ece82ef39f30907fa3ce0cb63937c8b20"
)
RETRY_CONTINUITY_CONFIG_RAW_SHA256: Final = (
    "309fab2335472654a2402803bda6af5d1dec6c80fea580ed266463611a021a03"
)

_SCHEMA_RETRY_FIELD: Final = "max_schema_validation_retries"


class RetryContinuityConfigurationError(ValueError):
    """Raised when authenticated-runner retry continuity is not selected exactly."""


def _without_schema_retry(config: AuditConfig) -> dict[str, object]:
    payload = config.model_dump(mode="json", by_alias=True)
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        raise RetryContinuityConfigurationError("retry continuity configuration is malformed")
    normalized_execution = dict(execution)
    normalized_execution.pop(_SCHEMA_RETRY_FIELD, None)
    return {**payload, "execution": normalized_execution}


def require_default_authenticated_runner_retry_policy(config: AuditConfig) -> None:
    """Reject implicit schema retries on the authenticated-runner command."""

    if type(config) is not AuditConfig:
        raise RetryContinuityConfigurationError(
            "authenticated-runner configuration has the wrong exact type"
        )
    if config.execution.max_schema_validation_retries != 0:
        raise RetryContinuityConfigurationError(
            "schema retries require explicit --retry-continuity-config selection"
        )


def _read_pinned_profile(path: Path, *, label: str) -> bytes:
    if not isinstance(path, Path):
        raise RetryContinuityConfigurationError(f"{label} path has the wrong exact type")
    try:
        raw = path.read_bytes()
    except OSError:
        raise RetryContinuityConfigurationError(
            f"{label} profile is absent or unreadable"
        ) from None
    if not raw:
        raise RetryContinuityConfigurationError(f"{label} profile is empty")
    return raw


def load_authenticated_runner_default_config(
    path: Path,
    *,
    environ: dict[str, str] | None = None,
) -> AuditConfig:
    """Load the exact byte- and semantic-pinned retry-off runner profile."""

    raw_before = _read_pinned_profile(path, label="default qualification configuration")
    default = load_config(path, environ=environ)
    raw_after = _read_pinned_profile(path, label="default qualification configuration")
    if type(default) is not AuditConfig:
        raise RetryContinuityConfigurationError(
            "default qualification loader returned the wrong exact configuration type"
        )
    if (
        raw_before != raw_after
        or hashlib.sha256(raw_after).hexdigest() != FROZEN_QUALIFICATION_CONFIG_RAW_SHA256
        or default.stable_hash() != FROZEN_QUALIFICATION_CONFIG_SHA256
        or default.execution.max_schema_validation_retries != 0
    ):
        raise RetryContinuityConfigurationError(
            "default qualification configuration is not the frozen retry-off profile"
        )
    return default


def load_authenticated_runner_retry_continuity_config(
    *,
    default_path: Path,
    continuity_path: Path,
    environ: dict[str, str] | None = None,
) -> AuditConfig:
    """Load the exact default and continuity profiles and return the latter."""

    if not isinstance(default_path, Path) or not isinstance(continuity_path, Path):
        raise RetryContinuityConfigurationError("retry continuity paths have the wrong exact type")
    default = load_authenticated_runner_default_config(default_path, environ=environ)
    continuity_raw_before = _read_pinned_profile(
        continuity_path,
        label="authenticated-runner retry continuity configuration",
    )
    continuity = load_config(continuity_path, environ=environ)
    continuity_raw_after = _read_pinned_profile(
        continuity_path,
        label="authenticated-runner retry continuity configuration",
    )
    if type(continuity) is not AuditConfig:
        raise RetryContinuityConfigurationError(
            "retry continuity loader returned the wrong exact configuration type"
        )
    if (
        continuity.stable_hash() != RETRY_CONTINUITY_CONFIG_SHA256
        or continuity_raw_before != continuity_raw_after
        or hashlib.sha256(continuity_raw_after).hexdigest() != RETRY_CONTINUITY_CONFIG_RAW_SHA256
    ):
        raise RetryContinuityConfigurationError(
            "authenticated-runner retry continuity configuration is not package-pinned"
        )
    execution = continuity.execution
    if (
        execution.max_schema_validation_retries
        != AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT
        or execution.max_model_retries != AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT
        or execution.maximum_model_attempts
        != 1
        + AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT
        + AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT
    ):
        raise RetryContinuityConfigurationError(
            "authenticated-runner retry continuity quotas are not exact"
        )
    if (
        execution.max_requests_per_agent
        < AUTHENTICATED_RUNNER_LOGICAL_REQUEST_COUNT * execution.maximum_model_attempts
    ):
        raise RetryContinuityConfigurationError(
            "authenticated-runner retry continuity request capacity is insufficient"
        )
    if _without_schema_retry(continuity) != _without_schema_retry(default):
        raise RetryContinuityConfigurationError(
            "retry continuity profile differs from the frozen default beyond its schema quota"
        )
    return continuity


__all__ = [
    "AUTHENTICATED_RUNNER_LOGICAL_REQUEST_COUNT",
    "AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT",
    "AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT",
    "FROZEN_QUALIFICATION_CONFIG_RAW_SHA256",
    "FROZEN_QUALIFICATION_CONFIG_SHA256",
    "RETRY_CONTINUITY_CONFIG_RAW_SHA256",
    "RETRY_CONTINUITY_CONFIG_SHA256",
    "RetryContinuityConfigurationError",
    "load_authenticated_runner_default_config",
    "load_authenticated_runner_retry_continuity_config",
    "require_default_authenticated_runner_retry_policy",
]
