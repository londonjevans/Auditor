"""Focused model regressions for durable main-task truncation capture."""

from __future__ import annotations

from pathlib import Path

import pytest

import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.models.scheduler import SchedulerProviderAttemptEvidence, SchedulerTaskActivation
from mmaudit.models.truncation import seal_candidate_review_truncated_envelope_evidence
from tests.unit.test_scheduler_journal import (
    _framed_candidate_review_fixture,
    resume_scheduler_journal,
)
from tests.unit.test_scheduler_truncation_failure import (
    _truncation_error,
    _typed_truncation_custody,
)


def _typed_attempt(path: Path) -> tuple[dict[str, object], SchedulerProviderAttemptEvidence]:
    fixture = _framed_candidate_review_fixture(path)
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    journal = fixture["journal"]
    task = fixture["task"]
    activation = next(item for item in journal.activations if item.task_id == task.task_id)
    assert isinstance(activation, SchedulerTaskActivation)
    attempt = SchedulerProviderAttemptEvidence.build_truncated(
        task=task,
        activation=activation,
        usage_record=failed_usage,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
        truncated_envelope_evidence=envelope,
        truncation_projection=projection,
    )
    return fixture, attempt


def test_typed_provider_attempt_retains_exact_raw_free_truncation_custody(
    tmp_path: Path,
) -> None:
    fixture, attempt = _typed_attempt(tmp_path / "typed")

    assert attempt.schema_version == "1.1"
    assert attempt.truncated_envelope_evidence is not None
    assert attempt.truncation_projection is not None
    assert (
        attempt.provider_response_sha256 == attempt.truncation_projection.original_response_sha256
    )
    assert attempt.validated_response_sha256 is None
    assert (
        SchedulerProviderAttemptEvidence.model_validate_json(
            attempt.model_dump_json(),
        )
        == attempt
    )
    fixture["runtime"].close()


def test_typed_provider_attempt_rejects_a_swapped_envelope(tmp_path: Path) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / "swap")
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    journal = fixture["journal"]
    task = fixture["task"]
    activation = next(item for item in journal.activations if item.task_id == task.task_id)
    swapped = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=envelope.logical_request_id,
        generation_id=envelope.generation_id,
        generation_header_id=envelope.generation_header_id,
        requested_model=envelope.requested_model,
        returned_model=envelope.returned_model,
        selected_model=envelope.selected_model,
        response_provider_identity=envelope.response_provider_identity,
        selected_provider_endpoint=envelope.selected_provider_endpoint,
        selected_provider_identity=envelope.selected_provider_identity,
        selected_provider_name=envelope.selected_provider_name,
        router_metadata_sha256="8" * 64,
        finish_reason=envelope.finish_reason,
        native_finish_reason=envelope.native_finish_reason,
        wire_schema_sha256=envelope.wire_schema_sha256,
        response_sha256=envelope.response_sha256,
    )

    with pytest.raises(ValueError, match="differs from its truncation custody"):
        SchedulerProviderAttemptEvidence.build_truncated(
            task=task,
            activation=activation,
            usage_record=failed_usage,
            audit_model_selection=journal.manifest.bindings.audit_model_selection,
            audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
            truncated_envelope_evidence=swapped,
            truncation_projection=projection,
        )
    fixture["runtime"].close()


def test_runtime_failure_persists_typed_capture_before_truncated_terminal(
    tmp_path: Path,
) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / "runtime")
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    runtime = fixture["runtime"]
    task = fixture["task"]

    result = runtime.record_failure(
        task,
        _truncation_error(envelope, projection, failed_usage, custody="complete"),
        usage_records=(failed_usage,),
    )

    attempt = next(
        item for item in runtime.journal.provider_attempts if item.task_id == task.task_id
    )
    assert attempt.schema_version == "1.1"
    assert attempt.truncated_envelope_evidence == envelope
    assert attempt.truncation_projection == projection
    assert result.terminal_evidence_sha256 == projection.evidence_sha256
    runtime.close()


def test_legacy_provider_attempt_replays_without_new_fields(tmp_path: Path) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / "legacy")
    _envelope, _projection, failed_usage = _typed_truncation_custody(fixture)
    journal = fixture["journal"]
    task = fixture["task"]
    activation = next(item for item in journal.activations if item.task_id == task.task_id)

    attempt = SchedulerProviderAttemptEvidence.build(
        task=task,
        activation=activation,
        usage_record=failed_usage,
        audit_model_selection=journal.manifest.bindings.audit_model_selection,
        audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
    )
    serialized = attempt.model_dump(mode="json")

    assert attempt.schema_version == "1.0"
    assert "truncated_envelope_evidence" not in serialized
    assert "truncation_projection" not in serialized
    assert SchedulerProviderAttemptEvidence.model_validate(serialized) == attempt
    fixture["runtime"].close()


def test_resume_selects_truncated_after_durable_typed_attempt_before_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "typed-crash"
    fixture = _framed_candidate_review_fixture(path)
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    journal = fixture["journal"]
    task = fixture["task"]
    attempt = journal.persist_truncated_provider_attempt(
        task.task_id,
        failed_usage,
        truncated_envelope_evidence=envelope,
        truncation_projection=projection,
    )
    assert attempt.schema_version == "1.1"
    fixture["runtime"].close()
    monkeypatch.setattr(
        scheduler_module,
        "_validate_live_scheduler_model_refresh",
        lambda **_values: (True, True),
    )

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=fixture["bindings"],
        expected_shard_inventory=fixture["inventory"],
    )

    result = next(item for item in resumed.task_results if item.task_id == task.task_id)
    retained = next(item for item in resumed.provider_attempts if item.task_id == task.task_id)
    assert result.terminal_status.value == "TRUNCATED"
    assert result.terminal_evidence_sha256 == projection.evidence_sha256
    assert retained.truncated_envelope_evidence == envelope
    assert retained.truncation_projection == projection
    resumed.close()


def test_resume_keeps_legacy_post_dispatch_attempt_uncertain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "legacy-crash"
    fixture = _framed_candidate_review_fixture(path)
    _envelope, _projection, failed_usage = _typed_truncation_custody(fixture)
    journal = fixture["journal"]
    task = fixture["task"]
    legacy = journal.persist_provider_attempt(task.task_id, failed_usage)
    assert legacy.schema_version == "1.0"
    fixture["runtime"].close()
    monkeypatch.setattr(
        scheduler_module,
        "_validate_live_scheduler_model_refresh",
        lambda **_values: (True, True),
    )

    resumed = resume_scheduler_journal(
        path,
        expected_bindings=fixture["bindings"],
        expected_shard_inventory=fixture["inventory"],
    )

    result = next(item for item in resumed.task_results if item.task_id == task.task_id)
    assert result.terminal_status.value == "UNCERTAIN"
    resumed.close()
