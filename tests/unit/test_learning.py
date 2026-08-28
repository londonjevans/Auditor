"""Synthetic local regressions for tenant-scoped terminal learning capture."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.learning import (
    MAX_LEARNING_CONFIRMED_FINDINGS,
    MAX_LEARNING_LONG_TEXT_CHARS,
    MAX_LEARNING_MODELS_PER_ROLE,
    MAX_LEARNING_REQUESTS_PER_ROLE,
    TERMINAL_AUDIT_LEARNING_SCHEMA_VERSION,
    ExternallyEstablishedMiss,
    ExternalMissEstablishmentKind,
    LearningAcceptedFindingStatus,
    LearningActorKind,
    LearningAttributionOutcome,
    LearningAttributionTargetKind,
    LearningFindingSeverity,
    LearningSourceKind,
    LearningSurfaceKind,
    LearningSurfaceOutcome,
    TerminalAuditLearningRecord,
    TerminalConfirmedFinding,
    TerminalRejectedCandidate,
    TerminalReviewedSurface,
    TerminalReviewerAttribution,
    TerminalRoleResourceUsage,
    append_externally_established_miss,
    build_terminal_audit_learning_record,
    learning_actor_id,
    learning_canonical_sha256,
)
from mmaudit.models.schemas import FindingStatus
from mmaudit.orchestration.learning import persist_terminal_learning_successor

_TENANT = "tenant-synthetic-a"
_OTHER_TENANT = "Tenant-synthetic-a"
_COMPLETED_AT = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
_ESTABLISHED_AT = _COMPLETED_AT + timedelta(hours=1)
_CAPTURED_AT = _COMPLETED_AT + timedelta(days=1)


def _sha(character: str) -> str:
    return character * 64


def _confirmed(*, tenant_id: str = _TENANT) -> TerminalConfirmedFinding:
    return TerminalConfirmedFinding(
        tenant_id=tenant_id,
        source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
        finding_id="finding-001",
        finding_sha256=_sha("1"),
        title_excerpt="Synthetic unchecked transition",
        category="STATE_INTEGRITY",
        status=LearningAcceptedFindingStatus.CONFIRMED,
        severity=LearningFindingSeverity.HIGH,
        summary_excerpt=(
            "The synthetic terminal review confirmed an invalid local state transition."
        ),
    )


def _rejected(*, tenant_id: str = _TENANT) -> TerminalRejectedCandidate:
    return TerminalRejectedCandidate(
        tenant_id=tenant_id,
        source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
        candidate_id="candidate-001",
        candidate_sha256=_sha("2"),
        title_excerpt="Synthetic access-control candidate",
        category="ACCESS_CONTROL",
        reason_code="UNREACHABLE_PATH",
        reason_excerpt=("The candidate was falsified because its synthetic path is unreachable."),
    )


def _external_miss(*, tenant_id: str = _TENANT) -> ExternallyEstablishedMiss:
    return ExternallyEstablishedMiss(
        tenant_id=tenant_id,
        source_kind=LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT,
        external_miss_id="external-miss-001",
        finding_sha256=_sha("3"),
        title_excerpt="Synthetic later-established accounting miss",
        category="ACCOUNTING",
        severity=LearningFindingSeverity.MEDIUM,
        summary_excerpt=(
            "Independent post-audit review established a synthetic accounting defect."
        ),
        established_at=_ESTABLISHED_AT,
        establishment_kind=ExternalMissEstablishmentKind.INDEPENDENT_POST_AUDIT_REVIEW,
        establishment_reference_sha256=_sha("4"),
        expected_surface_ids=("surface-001",),
    )


def _attribution(
    attribution_id: str,
    *,
    outcome: LearningAttributionOutcome,
    target_kind: LearningAttributionTargetKind,
    target_id: str,
    target_sha256: str,
    actor_kind: LearningActorKind = LearningActorKind.MODEL,
    tenant_id: str = _TENANT,
    surface_ids: tuple[str, ...] | None = None,
) -> TerminalReviewerAttribution:
    external = target_kind is LearningAttributionTargetKind.EXTERNAL_MISS
    audit_role = "economic_game_theory" if actor_kind is LearningActorKind.SPECIALIST else "lead"
    model_id = (
        "vendor/specialist-model"
        if actor_kind is LearningActorKind.SPECIALIST
        else "vendor/lead-model"
    )
    return TerminalReviewerAttribution(
        tenant_id=tenant_id,
        source_kind=(
            LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT
            if external
            else LearningSourceKind.TERMINAL_PRODUCTION_AUDIT
        ),
        attribution_id=attribution_id,
        actor_kind=actor_kind,
        actor_id=learning_actor_id(audit_role=audit_role, model_id=model_id),
        model_id=model_id,
        audit_role=audit_role,
        specialist_role=(
            "economic_game_theory" if actor_kind is LearningActorKind.SPECIALIST else None
        ),
        outcome=outcome,
        target_kind=target_kind,
        target_id=target_id,
        target_sha256=target_sha256,
        surface_ids=(
            surface_ids
            if surface_ids is not None
            else (("surface-001",) if outcome is LearningAttributionOutcome.MISSED else ())
        ),
    )


def _attributions() -> tuple[TerminalReviewerAttribution, ...]:
    return (
        _attribution(
            "attribution-001",
            outcome=LearningAttributionOutcome.PROPOSED,
            target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
            target_id="finding-001",
            target_sha256=_sha("1"),
        ),
        _attribution(
            "attribution-002",
            outcome=LearningAttributionOutcome.VERIFIED,
            target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
            target_id="finding-001",
            target_sha256=_sha("1"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-003",
            outcome=LearningAttributionOutcome.PROPOSED,
            target_kind=LearningAttributionTargetKind.REJECTED_CANDIDATE,
            target_id="candidate-001",
            target_sha256=_sha("2"),
        ),
        _attribution(
            "attribution-004",
            outcome=LearningAttributionOutcome.FALSIFIED,
            target_kind=LearningAttributionTargetKind.REJECTED_CANDIDATE,
            target_id="candidate-001",
            target_sha256=_sha("2"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-005",
            outcome=LearningAttributionOutcome.VERIFIED,
            target_kind=LearningAttributionTargetKind.REJECTED_CANDIDATE,
            target_id="candidate-001",
            target_sha256=_sha("2"),
        ),
        _attribution(
            "attribution-006",
            outcome=LearningAttributionOutcome.FALSIFIED,
            target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
            target_id="finding-001",
            target_sha256=_sha("1"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-007",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
            target_id="finding-001",
            target_sha256=_sha("1"),
        ),
        _attribution(
            "attribution-008",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-009",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
        ),
    )


def _surfaces(*, tenant_id: str = _TENANT) -> tuple[TerminalReviewedSurface, ...]:
    credited_actor_ids = tuple(
        sorted(
            (
                learning_actor_id(audit_role="lead", model_id="vendor/lead-model"),
                learning_actor_id(
                    audit_role="economic_game_theory",
                    model_id="vendor/specialist-model",
                ),
            )
        )
    )
    return (
        TerminalReviewedSurface(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            surface_id="surface-001",
            surface_sha256=_sha("5"),
            surface_kind=LearningSurfaceKind.FUNCTION,
            descriptor_excerpt="SyntheticState.update(uint256)",
            outcome=LearningSurfaceOutcome.MIXED,
            credited_reviewer_actor_ids=credited_actor_ids,
            confirmed_finding_ids=("finding-001",),
            rejected_candidate_ids=("candidate-001",),
        ),
        TerminalReviewedSurface(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            surface_id="surface-002",
            surface_sha256=_sha("6"),
            surface_kind=LearningSurfaceKind.INVARIANT,
            descriptor_excerpt="Synthetic balance conservation invariant",
            outcome=LearningSurfaceOutcome.REVIEWED_NO_ISSUE,
            credited_reviewer_actor_ids=credited_actor_ids,
            confirmed_finding_ids=(),
            rejected_candidate_ids=(),
        ),
    )


def _usage(*, tenant_id: str = _TENANT) -> tuple[TerminalRoleResourceUsage, ...]:
    return (
        TerminalRoleResourceUsage(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            role_id="lead",
            model_ids=("vendor/lead-model",),
            request_count=2,
            cost_usd_exact="0.012300",
            runtime_seconds_exact="12.345678901",
        ),
        TerminalRoleResourceUsage(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            role_id="specialist",
            model_ids=("vendor/specialist-model",),
            request_count=3,
            cost_usd_exact="0.020001",
            runtime_seconds_exact="20.000000001",
        ),
    )


def _record(**overrides: Any) -> TerminalAuditLearningRecord:
    values: dict[str, Any] = {
        "tenant_id": _TENANT,
        "audit_id": "scheduler-audit-synthetic-001",
        "terminal_report_authority_sha256": _sha("a"),
        "report_payload_sha256": _sha("b"),
        "parent_record_sha256": _sha("c"),
        "completed_at": _COMPLETED_AT,
        "captured_at": _CAPTURED_AT,
        "confirmed_findings": (_confirmed(),),
        "rejected_candidates": (_rejected(),),
        "reviewer_attributions": _attributions(),
        "reviewed_surfaces": _surfaces(),
        "role_usage": _usage(),
        "external_misses": (_external_miss(),),
    }
    values.update(overrides)
    if "parent_record_sha256" not in overrides:
        values["parent_record_sha256"] = _sha("c") if values["external_misses"] else None
    return build_terminal_audit_learning_record(**values)


def _payload(record: TerminalAuditLearningRecord | None = None) -> dict[str, Any]:
    value = json.loads((record or _record()).model_dump_json())
    assert isinstance(value, dict)
    return value


def _reseal(payload: dict[str, Any]) -> TerminalAuditLearningRecord:
    payload.pop("record_sha256", None)
    payload["record_sha256"] = learning_canonical_sha256(payload)
    return TerminalAuditLearningRecord.model_validate_json(
        json.dumps(payload, sort_keys=True),
        strict=True,
    )


def test_terminal_learning_record_retains_exact_bounded_nonauthorizing_outcomes() -> None:
    record = _record(
        confirmed_findings=(_confirmed(),),
        rejected_candidates=(_rejected(),),
        reviewer_attributions=tuple(reversed(_attributions())),
        reviewed_surfaces=tuple(reversed(_surfaces())),
        role_usage=tuple(reversed(_usage())),
    )

    assert record.schema_version == TERMINAL_AUDIT_LEARNING_SCHEMA_VERSION
    assert record.tenant_id == _TENANT
    assert tuple(item.outcome for item in record.reviewer_attributions) == (
        LearningAttributionOutcome.PROPOSED,
        LearningAttributionOutcome.VERIFIED,
        LearningAttributionOutcome.PROPOSED,
        LearningAttributionOutcome.FALSIFIED,
        LearningAttributionOutcome.VERIFIED,
        LearningAttributionOutcome.FALSIFIED,
        LearningAttributionOutcome.MISSED,
        LearningAttributionOutcome.MISSED,
        LearningAttributionOutcome.MISSED,
    )
    assert record.confirmed_findings[0].status is LearningAcceptedFindingStatus.CONFIRMED
    assert record.terminal_report_authority_sha256 == _sha("a")
    assert record.report_payload_sha256 == _sha("b")
    assert record.external_misses[0].established_at == _ESTABLISHED_AT
    assert record.role_usage[0].cost_usd_exact == "0.012300"
    assert record.role_usage[0].runtime_seconds_exact == "12.345678901"
    assert record.permitted_use == "LEAD_ONLY_NON_PRIMING"
    assert record.authority == "NONAUTHORIZING"
    assert record.evidence_credit_authorized is False
    assert record.confidence_credit_authorized is False
    assert record.coverage_credit_authorized is False
    assert record.consensus_credit_authorized is False
    assert record.prompt_priming_authorized is False
    assert record.cross_tenant_aggregation_authorized is False
    assert record.provider_dispatch_authorized is False
    assert record.qualification_authorized is False
    assert record.release_authorized is False
    assert record.record_sha256 == learning_canonical_sha256(
        record.model_dump(mode="json", exclude={"record_sha256"})
    )
    assert (
        TerminalAuditLearningRecord.model_validate_json(record.model_dump_json(), strict=True)
        == record
    )


def test_learning_confirmed_finding_inventory_accepts_only_confirmed_status() -> None:
    assert {item.value for item in LearningAcceptedFindingStatus} == {FindingStatus.CONFIRMED.value}
    payload = _confirmed().model_dump(mode="python")
    payload["status"] = FindingStatus.UNSUPPORTED.value
    with pytest.raises(ValidationError):
        TerminalConfirmedFinding.model_validate(payload, strict=True)


def test_terminal_learning_record_rejects_unresealed_and_coherently_resealed_tamper() -> None:
    payload = _payload()
    payload["rejected_candidates"][0]["reason_excerpt"] = "Tampered rejection rationale."
    with pytest.raises(ValidationError, match="self-hash"):
        TerminalAuditLearningRecord.model_validate_json(json.dumps(payload), strict=True)

    payload = _payload()
    payload["reviewer_attributions"][0]["target_sha256"] = _sha("9")
    with pytest.raises(ValidationError, match="hash-mismatched"):
        _reseal(payload)

    payload = _payload()
    payload["prompt_priming_authorized"] = True
    with pytest.raises(ValidationError):
        _reseal(payload)


@pytest.mark.parametrize("source_kind", ["BENCHMARK", "PRIVATE_HOLDOUT", "TIME_SPLIT"])
def test_learning_source_inventory_rejects_contaminating_source_kinds(
    source_kind: str,
) -> None:
    payload = _payload()
    payload["source_kind"] = source_kind
    with pytest.raises(ValidationError):
        _reseal(payload)

    payload = _payload()
    payload["confirmed_findings"][0]["source_kind"] = source_kind
    with pytest.raises(ValidationError):
        _reseal(payload)

    payload = _payload()
    payload["external_misses"][0]["source_kind"] = source_kind
    with pytest.raises(ValidationError):
        _reseal(payload)


def test_learning_record_requires_exact_same_tenant_for_every_nested_fact() -> None:
    with pytest.raises(ValidationError, match="across tenant"):
        _record(confirmed_findings=(_confirmed(tenant_id=_OTHER_TENANT),))

    with pytest.raises(ValidationError, match="across tenant"):
        _record(reviewed_surfaces=_surfaces(tenant_id=_OTHER_TENANT))

    with pytest.raises(ValidationError, match="across tenant"):
        _record(role_usage=_usage(tenant_id=_OTHER_TENANT))

    payload = _payload()
    payload["tenant_id"] = " tenant-synthetic-a"
    with pytest.raises(ValidationError):
        _reseal(payload)


def test_learning_record_bounds_counts_text_usage_and_exact_decimals() -> None:
    with pytest.raises(ValidationError):
        TerminalRejectedCandidate(
            tenant_id=_TENANT,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            candidate_id="candidate-long",
            candidate_sha256=_sha("7"),
            title_excerpt="Bounded synthetic candidate",
            category="ACCESS_CONTROL",
            reason_code="FALSE_POSITIVE",
            reason_excerpt="x" * (MAX_LEARNING_LONG_TEXT_CHARS + 1),
        )

    with pytest.raises(ValidationError):
        TerminalRoleResourceUsage(
            tenant_id=_TENANT,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            role_id="lead",
            model_ids=tuple(
                f"vendor/model-{index:03d}" for index in range(MAX_LEARNING_MODELS_PER_ROLE + 1)
            ),
            request_count=1,
            cost_usd_exact="0",
            runtime_seconds_exact="0",
        )

    payload = _usage()[0].model_dump(mode="python")
    payload["request_count"] = MAX_LEARNING_REQUESTS_PER_ROLE + 1
    with pytest.raises(ValidationError):
        TerminalRoleResourceUsage.model_validate(payload, strict=True)

    for field_name, value in (
        ("cost_usd_exact", 0.1),
        ("cost_usd_exact", "1e-3"),
        ("runtime_seconds_exact", 1.5),
        ("runtime_seconds_exact", "-1"),
    ):
        payload = _usage()[0].model_dump(mode="python")
        payload[field_name] = value
        with pytest.raises(ValidationError):
            TerminalRoleResourceUsage.model_validate(payload, strict=True)

    with pytest.raises(ValueError, match="exceeds its item limit"):
        _record(confirmed_findings=(_confirmed(),) * (MAX_LEARNING_CONFIRMED_FINDINGS + 1))


def test_learning_record_rejects_noncanonical_sets_dangling_joins_and_duplicate_roles() -> None:
    payload = _payload()
    payload["reviewer_attributions"].reverse()
    with pytest.raises(ValidationError, match="sorted and unique"):
        _reseal(payload)

    duplicate_event = _attribution(
        "attribution-010",
        outcome=LearningAttributionOutcome.PROPOSED,
        target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
        target_id="finding-001",
        target_sha256=_sha("1"),
    )
    with pytest.raises(ValidationError, match="semantically unique"):
        _record(reviewer_attributions=(*_attributions(), duplicate_event))

    payload = _payload()
    payload["reviewed_surfaces"][0]["confirmed_finding_ids"] = ["finding-absent"]
    with pytest.raises(ValidationError, match="absent confirmed"):
        _reseal(payload)

    payload = _payload()
    payload["role_usage"].append(payload["role_usage"][0])
    with pytest.raises(ValidationError, match="sorted and unique"):
        _reseal(payload)


def test_external_later_established_miss_is_first_class_and_requires_missed_attribution() -> None:
    with pytest.raises(ValidationError, match="lacks exact missed-attribution"):
        _record(
            reviewer_attributions=tuple(
                item
                for item in _attributions()
                if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
            )
        )

    payload = _payload()
    payload["external_misses"][0]["established_at"] = _COMPLETED_AT.isoformat().replace(
        "+00:00", "Z"
    )
    with pytest.raises(ValidationError, match="after audit completion"):
        _reseal(payload)

    attribution = _attribution(
        "attribution-invalid-source",
        outcome=LearningAttributionOutcome.MISSED,
        target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
        target_id="external-miss-001",
        target_sha256=_sha("3"),
    )
    payload = attribution.model_dump(mode="python")
    payload["source_kind"] = LearningSourceKind.TERMINAL_PRODUCTION_AUDIT
    with pytest.raises(ValidationError, match="source"):
        TerminalReviewerAttribution.model_validate(payload, strict=True)


def test_external_miss_append_preserves_terminal_facts_and_reseals_snapshot() -> None:
    terminal_attributions = tuple(
        item
        for item in _attributions()
        if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
    )
    original = _record(
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        external_misses=(),
    )
    appended_attributions = (
        _attribution(
            "attribution-008",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-009",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
        ),
    )

    updated = append_externally_established_miss(
        record=original,
        miss=_external_miss(),
        missed_attributions=appended_attributions,
        captured_at=_CAPTURED_AT,
    )

    assert original.external_misses == ()
    assert original.captured_at == _COMPLETED_AT
    assert updated.record_sha256 != original.record_sha256
    assert updated.tenant_id == original.tenant_id
    assert updated.audit_id == original.audit_id
    assert updated.terminal_report_authority_sha256 == original.terminal_report_authority_sha256
    assert updated.report_payload_sha256 == original.report_payload_sha256
    assert updated.completed_at == original.completed_at
    assert updated.confirmed_findings == original.confirmed_findings
    assert updated.rejected_candidates == original.rejected_candidates
    assert updated.reviewed_surfaces == original.reviewed_surfaces
    assert updated.role_usage == original.role_usage
    assert updated.external_misses == (_external_miss(),)
    assert updated.reviewer_attributions[: len(original.reviewer_attributions)] == (
        original.reviewer_attributions
    )
    assert updated.reviewer_attributions[len(original.reviewer_attributions) :] == (
        appended_attributions
    )


def test_external_miss_append_rejects_cross_tenant_stale_and_mismatched_inputs() -> None:
    terminal_attributions = tuple(
        item
        for item in _attributions()
        if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
    )
    original = _record(
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        external_misses=(),
    )
    joined = (
        _attribution(
            "attribution-008",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-009",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
        ),
    )

    with pytest.raises(ValueError, match="cross tenant"):
        append_externally_established_miss(
            record=original,
            miss=_external_miss(tenant_id=_OTHER_TENANT),
            missed_attributions=joined,
            captured_at=_CAPTURED_AT,
        )

    same_window = append_externally_established_miss(
        record=_record(
            captured_at=_ESTABLISHED_AT,
            reviewer_attributions=terminal_attributions,
            external_misses=(),
        ),
        miss=_external_miss(),
        missed_attributions=joined,
        captured_at=_CAPTURED_AT,
    )
    assert same_window.external_misses == (_external_miss(),)

    mismatched = _attribution(
        "attribution-mismatched",
        outcome=LearningAttributionOutcome.MISSED,
        target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
        target_id="finding-001",
        target_sha256=_sha("1"),
    )
    with pytest.raises(ValueError, match="exact missed-attribution"):
        append_externally_established_miss(
            record=original,
            miss=_external_miss(),
            missed_attributions=(mismatched,),
            captured_at=_CAPTURED_AT,
        )


def test_external_miss_retains_unreviewed_surface_without_fabricated_reviewer() -> None:
    terminal_attributions = tuple(
        item
        for item in _attributions()
        if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
    )
    surfaces = tuple(
        surface.model_copy(
            update={
                "outcome": LearningSurfaceOutcome.INCONCLUSIVE,
                "credited_reviewer_actor_ids": (),
            }
        )
        if surface.surface_id == "surface-002"
        else surface
        for surface in _surfaces()
    )
    original = _record(
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        reviewed_surfaces=surfaces,
        external_misses=(),
    )
    miss = _external_miss().model_copy(update={"expected_surface_ids": ("surface-002",)})

    updated = append_externally_established_miss(
        record=original,
        miss=miss,
        missed_attributions=(),
        captured_at=_CAPTURED_AT,
    )

    assert updated.external_misses == (miss,)
    assert not any(
        item.target_kind is LearningAttributionTargetKind.EXTERNAL_MISS
        for item in updated.reviewer_attributions
    )


def test_external_miss_successor_is_parent_linked_append_only_and_durable(tmp_path) -> None:
    terminal_attributions = tuple(
        item
        for item in _attributions()
        if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
    )
    original = _record(
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        external_misses=(),
    )
    first_attributions = (
        _attribution(
            "attribution-008",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-009",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-001",
            target_sha256=_sha("3"),
        ),
    )
    first = append_externally_established_miss(
        record=original,
        miss=_external_miss(),
        missed_attributions=first_attributions,
        captured_at=_CAPTURED_AT,
    )
    assert first.parent_record_sha256 == original.record_sha256

    corpus_root = tmp_path / "learning-corpus"
    corpus_root.mkdir(mode=0o700)
    path = persist_terminal_learning_successor(
        corpus_root=corpus_root,
        parent_record=original,
        successor_record=first,
    )
    assert path == (corpus_root / _TENANT / "records" / f"{first.record_sha256}.json")
    assert path.stat().st_mode & 0o777 == 0o600
    assert (
        persist_terminal_learning_successor(
            corpus_root=corpus_root,
            parent_record=original,
            successor_record=first,
        )
        == path
    )

    injected = _attribution(
        "attribution-injected",
        outcome=LearningAttributionOutcome.PROPOSED,
        target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
        target_id="finding-001",
        target_sha256=_sha("1"),
    ).model_copy(
        update={
            "actor_id": learning_actor_id(
                audit_role="lead",
                model_id="vendor/injected-model",
            ),
            "model_id": "vendor/injected-model",
        }
    )
    injected_successor = build_terminal_audit_learning_record(
        tenant_id=first.tenant_id,
        audit_id=first.audit_id,
        terminal_report_authority_sha256=first.terminal_report_authority_sha256,
        report_payload_sha256=first.report_payload_sha256,
        parent_record_sha256=original.record_sha256,
        completed_at=first.completed_at,
        captured_at=first.captured_at,
        confirmed_findings=first.confirmed_findings,
        rejected_candidates=first.rejected_candidates,
        reviewer_attributions=(*first.reviewer_attributions, injected),
        reviewed_surfaces=first.reviewed_surfaces,
        role_usage=first.role_usage,
        external_misses=first.external_misses,
    )
    with pytest.raises(ValueError, match="unrelated new attribution"):
        persist_terminal_learning_successor(
            corpus_root=corpus_root,
            parent_record=original,
            successor_record=injected_successor,
        )

    second_miss = _external_miss().model_copy(
        update={
            "external_miss_id": "external-miss-002",
            "finding_sha256": _sha("8"),
            "establishment_reference_sha256": _sha("9"),
        }
    )
    second_attributions = (
        _attribution(
            "attribution-010",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-002",
            target_sha256=_sha("8"),
            actor_kind=LearningActorKind.SPECIALIST,
        ),
        _attribution(
            "attribution-011",
            outcome=LearningAttributionOutcome.MISSED,
            target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
            target_id="external-miss-002",
            target_sha256=_sha("8"),
        ),
    )
    second = append_externally_established_miss(
        record=first,
        miss=second_miss,
        missed_attributions=second_attributions,
        captured_at=_CAPTURED_AT,
    )
    assert second.parent_record_sha256 == first.record_sha256
    assert len(second.external_misses) == 2

    unrelated = _record(
        audit_id="unrelated-audit",
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        external_misses=(),
    )
    with pytest.raises(ValueError, match="exact parent hash"):
        persist_terminal_learning_successor(
            corpus_root=corpus_root,
            parent_record=unrelated,
            successor_record=first,
        )


def test_external_miss_rejects_dangling_surface_and_spoofed_reviewer_identity() -> None:
    terminal_attributions = tuple(
        item
        for item in _attributions()
        if item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
    )
    original = _record(
        captured_at=_COMPLETED_AT,
        reviewer_attributions=terminal_attributions,
        external_misses=(),
    )
    dangling_miss = _external_miss().model_copy(
        update={"expected_surface_ids": ("surface-absent",)}
    )
    dangling_attribution = _attribution(
        "attribution-dangling",
        outcome=LearningAttributionOutcome.MISSED,
        target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
        target_id="external-miss-001",
        target_sha256=_sha("3"),
        surface_ids=("surface-absent",),
    )
    with pytest.raises(ValidationError, match="absent reviewed surface"):
        append_externally_established_miss(
            record=original,
            miss=dangling_miss,
            missed_attributions=(dangling_attribution,),
            captured_at=_CAPTURED_AT,
        )

    spoofed_payload = _attribution(
        "attribution-spoofed",
        outcome=LearningAttributionOutcome.MISSED,
        target_kind=LearningAttributionTargetKind.EXTERNAL_MISS,
        target_id="external-miss-001",
        target_sha256=_sha("3"),
    ).model_dump(mode="python")
    spoofed_payload["model_id"] = "vendor/spoofed-model"
    with pytest.raises(ValidationError, match="actor ID"):
        TerminalReviewerAttribution.model_validate(spoofed_payload, strict=True)


def test_learning_security_constants_are_required_and_extra_fields_are_forbidden() -> None:
    payload = _payload()
    payload.pop("consensus_credit_authorized")
    payload.pop("record_sha256")
    payload["record_sha256"] = learning_canonical_sha256(payload)
    with pytest.raises(ValidationError):
        TerminalAuditLearningRecord.model_validate_json(json.dumps(payload), strict=True)

    payload = _payload()
    payload["finding_evidence"] = "synthetic authority canary"
    with pytest.raises(ValidationError):
        _reseal(payload)
