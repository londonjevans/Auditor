from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import mmaudit.models.retry_continuity as retry_continuity_module
from mmaudit.config import ExecutionConfig, load_config
from mmaudit.models.retry_continuity import (
    AUTHENTICATED_RUNNER_LOGICAL_REQUEST_COUNT,
    AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT,
    AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT,
    FROZEN_QUALIFICATION_CONFIG_RAW_SHA256,
    FROZEN_QUALIFICATION_CONFIG_SHA256,
    RETRY_CONTINUITY_CONFIG_RAW_SHA256,
    RETRY_CONTINUITY_CONFIG_SHA256,
    RetryContinuityConfigurationError,
    load_authenticated_runner_default_config,
    load_authenticated_runner_retry_continuity_config,
    require_default_authenticated_runner_retry_policy,
)

ROOT = Path(__file__).parents[2]
DEFAULT_PROFILE = ROOT / "config" / "openrouter-qualification.toml"
CONTINUITY_PROFILE = ROOT / "config" / "openrouter-authenticated-runner-retry-continuity.toml"


def test_exact_retry_continuity_profile_preserves_the_frozen_default() -> None:
    default_raw = DEFAULT_PROFILE.read_bytes()
    continuity_raw = CONTINUITY_PROFILE.read_bytes()
    default = load_config(DEFAULT_PROFILE, environ={})
    continuity = load_authenticated_runner_retry_continuity_config(
        default_path=DEFAULT_PROFILE,
        continuity_path=CONTINUITY_PROFILE,
        environ={},
    )

    assert hashlib.sha256(default_raw).hexdigest() == FROZEN_QUALIFICATION_CONFIG_RAW_SHA256
    assert hashlib.sha256(continuity_raw).hexdigest() == RETRY_CONTINUITY_CONFIG_RAW_SHA256
    assert default.stable_hash() == FROZEN_QUALIFICATION_CONFIG_SHA256
    assert default.execution.max_schema_validation_retries == 0
    assert "max_schema_validation_retries" not in default.execution.model_dump(mode="json")
    assert continuity.stable_hash() == RETRY_CONTINUITY_CONFIG_SHA256
    assert continuity.execution.max_model_retries == AUTHENTICATED_RUNNER_TRANSIENT_RETRY_COUNT
    assert (
        continuity.execution.max_schema_validation_retries
        == AUTHENTICATED_RUNNER_SCHEMA_RETRY_CONTINUITY_COUNT
    )
    assert continuity.execution.maximum_model_attempts == 5
    assert continuity.execution.model_dump(mode="json")["max_schema_validation_retries"] == 3
    assert continuity.stable_hash() != default.stable_hash()
    assert (
        AUTHENTICATED_RUNNER_LOGICAL_REQUEST_COUNT * continuity.execution.maximum_model_attempts
        <= continuity.execution.max_requests_per_agent
    )


def test_schema_retries_require_explicit_continuity_selection() -> None:
    default = load_config(DEFAULT_PROFILE, environ={})
    require_default_authenticated_runner_retry_policy(default)

    enabled_execution = ExecutionConfig.model_validate(
        {
            **default.execution.model_dump(mode="json"),
            "max_schema_validation_retries": 3,
        }
    )
    enabled = default.model_copy(update={"execution": enabled_execution})
    with pytest.raises(
        RetryContinuityConfigurationError,
        match="explicit --retry-continuity-config",
    ):
        require_default_authenticated_runner_retry_policy(enabled)


def test_default_runner_profile_is_byte_and_semantic_pinned(tmp_path: Path) -> None:
    assert (
        load_authenticated_runner_default_config(DEFAULT_PROFILE, environ={}).stable_hash()
        == FROZEN_QUALIFICATION_CONFIG_SHA256
    )
    drifted = tmp_path / "comment-drift.toml"
    drifted.write_bytes(DEFAULT_PROFILE.read_bytes() + b"\n# synthetic byte drift\n")
    assert load_config(drifted, environ={}).stable_hash() == FROZEN_QUALIFICATION_CONFIG_SHA256

    with pytest.raises(
        RetryContinuityConfigurationError,
        match="not the frozen retry-off profile",
    ):
        load_authenticated_runner_default_config(drifted, environ={})


@pytest.mark.parametrize(
    ("profile", "old", "new", "expected"),
    (
        (
            "default",
            "concurrency = 3",
            "concurrency = 4",
            "default qualification configuration is not the frozen retry-off profile",
        ),
        (
            "continuity",
            "max_schema_validation_retries = 3",
            "max_schema_validation_retries = 2",
            "retry continuity configuration is not package-pinned",
        ),
        (
            "continuity",
            "request_timeout_seconds = 180",
            "request_timeout_seconds = 181",
            "retry continuity configuration is not package-pinned",
        ),
    ),
)
def test_retry_continuity_rejects_profile_drift(
    tmp_path: Path,
    profile: str,
    old: str,
    new: str,
    expected: str,
) -> None:
    default_path = tmp_path / "default.toml"
    continuity_path = tmp_path / "continuity.toml"
    default_raw = DEFAULT_PROFILE.read_text(encoding="utf-8")
    continuity_raw = CONTINUITY_PROFILE.read_text(encoding="utf-8")
    if profile == "default":
        default_raw = default_raw.replace(old, new, 1)
    else:
        continuity_raw = continuity_raw.replace(old, new, 1)
    default_path.write_text(default_raw, encoding="utf-8")
    continuity_path.write_text(continuity_raw, encoding="utf-8")

    with pytest.raises(RetryContinuityConfigurationError, match=expected):
        load_authenticated_runner_retry_continuity_config(
            default_path=default_path,
            continuity_path=continuity_path,
            environ={},
        )


def test_retry_continuity_rejects_insufficient_campaign_attempt_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    continuity_path = tmp_path / "continuity.toml"
    raw = CONTINUITY_PROFILE.read_text(encoding="utf-8").replace(
        "max_requests_per_agent = 576",
        "max_requests_per_agent = 479",
        1,
    )
    continuity_path.write_text(raw, encoding="utf-8")
    changed = load_config(continuity_path, environ={})
    monkeypatch.setattr(
        retry_continuity_module,
        "RETRY_CONTINUITY_CONFIG_SHA256",
        changed.stable_hash(),
    )
    monkeypatch.setattr(
        retry_continuity_module,
        "RETRY_CONTINUITY_CONFIG_RAW_SHA256",
        hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )

    with pytest.raises(
        RetryContinuityConfigurationError,
        match="request capacity is insufficient",
    ):
        load_authenticated_runner_retry_continuity_config(
            default_path=DEFAULT_PROFILE,
            continuity_path=continuity_path,
            environ={},
        )


def test_retry_continuity_rejects_any_second_configuration_difference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    continuity_path = tmp_path / "continuity.toml"
    raw = CONTINUITY_PROFILE.read_text(encoding="utf-8").replace(
        "concurrency = 3",
        "concurrency = 4",
        1,
    )
    continuity_path.write_text(raw, encoding="utf-8")
    changed = load_config(continuity_path, environ={})
    monkeypatch.setattr(
        retry_continuity_module,
        "RETRY_CONTINUITY_CONFIG_SHA256",
        changed.stable_hash(),
    )
    monkeypatch.setattr(
        retry_continuity_module,
        "RETRY_CONTINUITY_CONFIG_RAW_SHA256",
        hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )

    with pytest.raises(
        RetryContinuityConfigurationError,
        match="differs from the frozen default beyond its schema quota",
    ):
        load_authenticated_runner_retry_continuity_config(
            default_path=DEFAULT_PROFILE,
            continuity_path=continuity_path,
            environ={},
        )


def test_retry_continuity_rejects_allowlisted_environment_drift() -> None:
    with pytest.raises(
        RetryContinuityConfigurationError,
        match="default qualification configuration is not the frozen retry-off profile",
    ):
        load_authenticated_runner_retry_continuity_config(
            default_path=DEFAULT_PROFILE,
            continuity_path=CONTINUITY_PROFILE,
            environ={"MMAUDIT_PROFILE": "deep"},
        )
