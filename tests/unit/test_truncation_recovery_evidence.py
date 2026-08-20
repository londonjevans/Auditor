"""Comparison-boundary tests for truncation-recovery surface evidence."""

from __future__ import annotations

import copy
import hashlib
import os
import pickle
from dataclasses import dataclass

import pytest

import mmaudit.orchestration.truncation_recovery_evidence as recovery_evidence
from mmaudit.models.schemas import (
    ContextPackage,
    ExecutionEvidenceKind,
    ModelSurfaceReviewRequest,
    UsageRecord,
)
from mmaudit.models.truncation_closure import (
    TruncationRecoveredSurfaceReviewArtifact,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryRequestLimitBinding,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.usage import atomic_request_limit_reservations_from_usage
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.truncation_recovery_evidence import (
    TruncationRecoveryChildInput,
    TruncationRecoveryEvidenceError,
    VerifiedTruncationRecoveryClosure,
    build_truncation_recovery_child_context,
    model_surface_analysis_context_sha256,
    require_verified_truncation_recovery_closure,
    require_verified_truncation_recovery_closure_projection,
    seal_truncation_recovery_surface_evidence,
    verify_truncation_recovery_closure,
)
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)
from tests.unit.test_truncation_closure import build_closure_fixture


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class _TypedClosureFixture:
    family: SchedulerTruncationRecoveryFamilyRoot
    closure: SchedulerTruncationRecoveryFamilyClosure
    results: tuple[SchedulerTruncationRecoveryChildResult, ...]
    dispatches: tuple[SchedulerTruncationRecoveryChildDispatch, ...]
    parent_usage: UsageRecord
    child_usages: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]
    requests: tuple[ModelSurfaceReviewRequest, ...]


def _typed_closure_fixture() -> _TypedClosureFixture:
    comparison, parent_context, child_contexts = build_closure_fixture()
    parent_usage = reattest_synthetic_real_usage(
        UsageRecord.model_validate(
            {
                **comparison.parent.usage_record.model_dump(mode="python"),
                "execution_evidence": ExecutionEvidenceKind.REAL,
            }
        )
    )
    child_usages = tuple(
        bind_synthetic_usage_identity(
            UsageRecord.model_validate(
                {
                    **child.usage_record.model_dump(mode="python"),
                    "execution_evidence": ExecutionEvidenceKind.REAL,
                }
            )
        )
        for child in comparison.children
    )
    parent_reservations = atomic_request_limit_reservations_from_usage(parent_usage)
    assert len(parent_reservations) == 1
    manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.build(comparison.requests)
    binding = SchedulerTruncationRecoveryRequestLimitBinding.build(
        campaign_id=comparison.campaign_id,
        manifest_sha256=_digest("typed-closure-journal-manifest"),
        request_limit_id=parent_usage.request_id,
        policy=comparison.recovery_plan.policy,
        parent_request_limit_reservation=parent_reservations[0],
    )
    family = SchedulerTruncationRecoveryFamilyRoot.build(
        request_limit_binding=binding,
        family_index=0,
        parent_kind=SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK,
        parent_family_id=None,
        parent_terminal_result_sha256=_digest("typed-closure-parent-terminal"),
        requested_surface_manifest=manifest,
        truncation_projection=comparison.parent.projection,
        recovery_plan=comparison.recovery_plan,
        request_count_before_family=0,
        request_limit_count_before_family=1,
        entry_index=0,
        previous_entry_sha256=None,
    )
    results: list[SchedulerTruncationRecoveryChildResult] = []
    dispatches: list[SchedulerTruncationRecoveryChildDispatch] = []
    previous_entry_sha256 = family.entry_sha256
    entry_index = 1
    for child_plan, child, usage in zip(
        family.recovery_plan.children,
        comparison.children,
        child_usages,
        strict=True,
    ):
        assert usage.request_body_sha256 is not None
        assert usage.user_prompt_sha256 is not None
        assert usage.schema_sha256 is not None
        activation = SchedulerTruncationRecoveryChildActivation.build(
            family=family,
            child=child_plan,
            actual_input_sha256=usage.request_body_sha256,
            system_prompt_sha256=_digest(f"typed-closure-system:{child_plan.child_task_id}"),
            user_prompt_sha256=usage.user_prompt_sha256,
            provider_prompt_sha256=usage.prompt_sha256,
            response_schema_sha256=usage.schema_sha256,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )
        dispatch = SchedulerTruncationRecoveryChildDispatch.build(
            activation=activation,
            entry_index=entry_index + 1,
            previous_entry_sha256=activation.entry_sha256,
        )
        result = SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child_plan,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage,
            normalization_evidence=child.normalization,
            normalized_batch=child.normalized_batch,
            requested_surface_requests=child.requests,
            output_artifact=child.surface_artifact,
            entry_index=entry_index + 2,
            previous_entry_sha256=dispatch.entry_sha256,
        )
        dispatches.append(dispatch)
        results.append(result)
        previous_entry_sha256 = result.entry_sha256
        entry_index += 3
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=(result.entry_sha256 for result in results),
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=family.recovery_plan.parent.unfinished_surface_ids,
        entry_index=entry_index,
        previous_entry_sha256=previous_entry_sha256,
    )
    return _TypedClosureFixture(
        family=family,
        closure=closure,
        results=tuple(results),
        dispatches=tuple(dispatches),
        parent_usage=parent_usage,
        child_usages=child_usages,
        parent_context=parent_context,
        child_contexts=child_contexts,
        requests=comparison.requests,
    )


def _verify_typed_fixture(
    fixture: _TypedClosureFixture,
) -> tuple[VerifiedTruncationRecoveryClosure, TruncationRecoveredSurfaceReviewArtifact]:
    return verify_truncation_recovery_closure(
        family=fixture.family,
        closure=fixture.closure,
        child_results=fixture.results,
        parent_usage_record=fixture.parent_usage,
        child_usage_records=fixture.child_usages,
        parent_context=fixture.parent_context,
        child_contexts=fixture.child_contexts,
        requests=fixture.requests,
    )


def _seal_fixture() -> TruncationRecoveredSurfaceReviewArtifact:
    closure, parent_context, child_contexts = build_closure_fixture()
    return seal_truncation_recovery_surface_evidence(
        recovery_plan=closure.recovery_plan,
        requests=closure.requests,
        parent=closure.parent,
        parent_context=parent_context,
        children=tuple(
            TruncationRecoveryChildInput(completion=completion, context=context)
            for completion, context in zip(
                closure.children,
                child_contexts,
                strict=True,
            )
        ),
    )


def test_live_predicates_produce_only_noncreditable_surface_comparison() -> None:
    artifact = _seal_fixture()

    assert artifact.structural_outcome == "EXACT_SURFACE_PARTITION_VALIDATED"
    assert artifact.surface_set_structurally_closed
    assert not artifact.scheduler_custody_verified
    assert not artifact.scheduler_surface_closure_eligible
    assert not artifact.surface_review_credit_eligible
    assert not artifact.review_credit_authorized
    assert not artifact.completion_authorized
    assert not artifact.candidate_credit_eligible
    assert "usage_record" not in type(artifact).model_fields


def test_capability_is_unconstructible_noncopyable_and_registry_bound() -> None:
    fixture = _typed_closure_fixture()
    capability, artifact = _verify_typed_fixture(fixture)
    with pytest.raises(TypeError):
        VerifiedTruncationRecoveryClosure()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"cannot be copied|cannot be serialized"):
            operation(capability)

    forged = object.__new__(VerifiedTruncationRecoveryClosure)
    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(forged, artifact)

    class ForgedSubclass(VerifiedTruncationRecoveryClosure):
        pass

    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(
            object.__new__(ForgedSubclass),
            artifact,
        )
    with pytest.raises(TruncationRecoveryEvidenceError, match="absent or forged"):
        require_verified_truncation_recovery_closure(object(), artifact)  # type: ignore[arg-type]


def test_direct_typed_success_family_issues_only_fresh_non_authorizing_artifacts() -> None:
    fixture = _typed_closure_fixture()
    capability, initial = _verify_typed_fixture(fixture)

    first = require_verified_truncation_recovery_closure(capability, initial)
    second = require_verified_truncation_recovery_closure(capability)
    projection = require_verified_truncation_recovery_closure_projection(capability)
    second_projection = require_verified_truncation_recovery_closure_projection(capability)

    assert first == second == initial
    assert first is not initial
    assert second is not first
    assert first.parent.projection.findings == fixture.family.truncation_projection.findings
    assert first.records == initial.records
    assert not first.scheduler_custody_verified
    assert not first.scheduler_surface_closure_eligible
    assert not first.surface_review_credit_eligible
    assert not first.candidate_credit_eligible
    assert not first.review_credit_authorized
    assert not first.completion_authorized
    assert not first.release_authorized
    expected_fingerprints = (_digest("truncation-closure-scanner-fingerprint"),)
    expected_request_ids = tuple(
        sorted(
            (
                fixture.parent_usage.request_id,
                *(usage.request_id for usage in fixture.child_usages),
            )
        )
    )
    assert projection.artifact == initial
    assert tuple(item[0] for item in projection.scanner_fingerprints_by_request) == (
        expected_request_ids
    )
    assert all(
        fingerprints == expected_fingerprints
        for _request_id, fingerprints in projection.scanner_fingerprints_by_request
    )
    assert second_projection == projection
    assert second_projection is not projection
    assert second_projection.artifact is not projection.artifact
    durable_payload = projection.artifact.model_dump(mode="json")
    assert "scanner_fingerprints_by_request" not in durable_payload
    assert "parent_context" not in durable_payload
    assert "child_contexts" not in durable_payload


@pytest.mark.parametrize("clone_kind", ["parent", "child"])
def test_serialized_real_usage_clone_cannot_issue_live_closure(clone_kind: str) -> None:
    fixture = _typed_closure_fixture()
    parent_usage = fixture.parent_usage
    child_usages = fixture.child_usages
    if clone_kind == "parent":
        parent_usage = UsageRecord.model_validate_json(parent_usage.model_dump_json())
    else:
        child_usages = (
            UsageRecord.model_validate_json(child_usages[0].model_dump_json()),
            child_usages[1],
        )

    with pytest.raises(TruncationRecoveryEvidenceError, match="live re-attested"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=fixture.results,
            parent_usage_record=parent_usage,
            child_usage_records=child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


def test_module_predicate_reassignment_cannot_admit_detached_real_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _typed_closure_fixture()
    detached_parent = UsageRecord.model_validate_json(fixture.parent_usage.model_dump_json())
    monkeypatch.setattr(
        recovery_evidence,
        "is_accountable_usage_record",
        lambda _usage, **_requirements: True,
    )
    monkeypatch.setattr(
        recovery_evidence,
        "is_recovery_creditable_usage_record",
        lambda _usage, **_requirements: True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="live re-attested"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=fixture.results,
            parent_usage_record=detached_parent,
            child_usage_records=fixture.child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


@pytest.mark.parametrize("swap_kind", ["results", "usage", "contexts"])
def test_direct_child_swap_cannot_issue_live_closure(swap_kind: str) -> None:
    fixture = _typed_closure_fixture()
    results = fixture.results
    child_usages = fixture.child_usages
    child_contexts = fixture.child_contexts
    if swap_kind == "results":
        results = tuple(reversed(results))
    elif swap_kind == "usage":
        child_usages = tuple(reversed(child_usages))
    else:
        child_contexts = tuple(reversed(child_contexts))

    with pytest.raises(TruncationRecoveryEvidenceError):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=fixture.closure,
            child_results=results,
            parent_usage_record=fixture.parent_usage,
            child_usage_records=child_usages,
            parent_context=fixture.parent_context,
            child_contexts=child_contexts,
            requests=fixture.requests,
        )


def test_v11_closed_family_rejects_mixed_legacy_hash_only_child() -> None:
    fixture = _typed_closure_fixture()
    child = fixture.family.recovery_plan.children[0]
    legacy = SchedulerTruncationRecoveryChildResult.build_runtime(
        child=child,
        dispatch=fixture.dispatches[0],
        terminal_status=SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED,
        terminal_evidence_sha256=_digest("legacy-completion"),
        provider_attempt_evidence_sha256=_digest("legacy-provider-attempt"),
        accounted_provider_attempts=child.reserved_provider_attempts,
        accounted_completion_tokens=child.reserved_completion_tokens,
        accounted_cost_usd_exact=child.reserved_usd_exact,
        runtime_completion_evidence_sha256=_digest("legacy-runtime-completion"),
        runtime_usage_record_sha256=_digest("legacy-usage"),
        runtime_output_artifact_sha256=_digest("legacy-output"),
        entry_index=fixture.results[0].entry_index,
        previous_entry_sha256=fixture.results[0].previous_entry_sha256,
    )
    results = (legacy, fixture.results[1])
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=fixture.family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=(result.entry_sha256 for result in results),
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=(fixture.family.recovery_plan.parent.unfinished_surface_ids),
        entry_index=fixture.closure.entry_index,
        previous_entry_sha256=fixture.closure.previous_entry_sha256,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="mixed or non-success"):
        verify_truncation_recovery_closure(
            family=fixture.family,
            closure=closure,
            child_results=results,
            parent_usage_record=fixture.parent_usage,
            child_usage_records=fixture.child_usages,
            parent_context=fixture.parent_context,
            child_contexts=fixture.child_contexts,
            requests=fixture.requests,
        )


def test_returned_artifact_and_live_usage_mutation_cannot_change_closure_state() -> None:
    fixture = _typed_closure_fixture()
    capability, artifact = _verify_typed_fixture(fixture)
    expected_sha256 = artifact.artifact_sha256
    projection = require_verified_truncation_recovery_closure_projection(capability)
    expected_scanner_projection = projection.scanner_fingerprints_by_request
    object.__setattr__(projection, "scanner_fingerprints_by_request", ())
    object.__setattr__(artifact, "artifact_sha256", "0" * 64)

    with pytest.raises(TruncationRecoveryEvidenceError, match="differs"):
        require_verified_truncation_recovery_closure(capability, artifact)
    assert require_verified_truncation_recovery_closure(capability).artifact_sha256 == (
        expected_sha256
    )
    assert (
        require_verified_truncation_recovery_closure_projection(
            capability
        ).scanner_fingerprints_by_request
        == expected_scanner_projection
    )

    object.__setattr__(fixture.child_usages[0], "status", "mutated")
    with pytest.raises(TruncationRecoveryEvidenceError):
        require_verified_truncation_recovery_closure(capability)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_verified_closure_cannot_cross_a_process_fork() -> None:
    capability, _artifact = _verify_typed_fixture(_typed_closure_fixture())
    child = os.fork()
    if child == 0:  # pragma: no cover - asserted through the child exit status
        status = 1
        try:
            require_verified_truncation_recovery_closure(capability)
        except TruncationRecoveryEvidenceError as exc:
            if "process fork" in str(exc):
                status = 0
        os._exit(status)
    _, wait_status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(wait_status) == 0


def test_swapped_child_context_cannot_seal() -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    assert len(closure.children) == len(child_contexts) == 2

    with pytest.raises(TruncationRecoveryEvidenceError):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=(
                TruncationRecoveryChildInput(
                    completion=closure.children[0],
                    context=child_contexts[1],
                ),
                TruncationRecoveryChildInput(
                    completion=closure.children[1],
                    context=child_contexts[0],
                ),
            ),
        )


def test_child_control_budget_drift_cannot_seal() -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    drifted = child_contexts[0].model_copy(
        update={"byte_budget": child_contexts[0].byte_budget + 1},
        deep=True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="drifted"):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=(
                TruncationRecoveryChildInput(
                    completion=closure.children[0],
                    context=drifted,
                ),
                TruncationRecoveryChildInput(
                    completion=closure.children[1],
                    context=child_contexts[1],
                ),
            ),
        )


def test_child_context_is_exact_strict_shard_of_parent_analysis() -> None:
    closure, parent_context, expected_child_contexts = build_closure_fixture()

    derived = tuple(
        build_truncation_recovery_child_context(parent_context=parent_context, child=child)
        for child in closure.recovery_plan.children
    )

    assert derived == expected_child_contexts
    assert all(
        tuple(request.surface_id for request in context.requested_model_surfaces)
        == child.surface_ids
        for child, context in zip(closure.recovery_plan.children, derived, strict=True)
    )
    assert {
        model_surface_analysis_context_sha256(context) for context in (parent_context, *derived)
    } == {model_surface_analysis_context_sha256(parent_context)}


def test_child_context_rejects_surface_outside_exact_parent_inventory() -> None:
    closure, parent_context, _child_contexts = build_closure_fixture()
    child = closure.recovery_plan.children[0]
    narrowed_parent = parent_context.model_copy(
        update={
            "requested_model_surfaces": tuple(
                request
                for request in closure.requests
                if request.surface_id not in child.surface_ids
            )
        },
        deep=True,
    )
    narrowed_parent = narrowed_parent.model_copy(
        update={"bytes_used": len(render_context(narrowed_parent).encode("utf-8"))},
        deep=True,
    )

    with pytest.raises(TruncationRecoveryEvidenceError, match="unknown parent surface"):
        build_truncation_recovery_child_context(
            parent_context=narrowed_parent,
            child=child,
        )


def test_child_context_revalidates_the_child_plan_before_derivation() -> None:
    closure, parent_context, _child_contexts = build_closure_fixture()
    child = closure.recovery_plan.children[0].model_copy(deep=True)
    object.__setattr__(child, "surface_ids", closure.recovery_plan.children[1].surface_ids)

    with pytest.raises(TruncationRecoveryEvidenceError, match="exact boundary"):
        build_truncation_recovery_child_context(
            parent_context=parent_context,
            child=child,
        )


@pytest.mark.parametrize("custody_check", ["parent", "child"])
def test_live_usage_predicate_failure_never_produces_comparison_evidence(
    monkeypatch: pytest.MonkeyPatch,
    custody_check: str,
) -> None:
    closure, parent_context, child_contexts = build_closure_fixture()
    children = tuple(
        TruncationRecoveryChildInput(completion=completion, context=context)
        for completion, context in zip(closure.children, child_contexts, strict=True)
    )
    if custody_check == "parent":
        monkeypatch.setattr(recovery_evidence, "is_accountable_usage_record", lambda _usage: False)
    else:
        monkeypatch.setattr(
            recovery_evidence,
            "is_recovery_creditable_usage_record",
            lambda _usage, **_coordinates: False,
        )

    with pytest.raises(TruncationRecoveryEvidenceError):
        seal_truncation_recovery_surface_evidence(
            recovery_plan=closure.recovery_plan,
            requests=closure.requests,
            parent=closure.parent,
            parent_context=parent_context,
            children=children,
        )
