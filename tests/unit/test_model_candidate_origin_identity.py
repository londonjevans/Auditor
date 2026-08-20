from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

import pytest

import mmaudit.models.candidate_review_stamping as candidate_stamping
from mmaudit.agents.base import (
    _model_review_origin_candidate_id,
    _require_unique_raw_candidate_ids,
)
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.agents.specialists import SpecialistFindingAgent
from mmaudit.config import AuditConfig
from mmaudit.models.candidate_review_stamping import (
    CandidateReviewStampingError,
    stamp_candidate_review_findings,
)
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ContextPackage,
    ContextRequestEvidence,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import (
    is_creditable_usage_record,
    is_structurally_accountable_usage_record,
    request_token_plan_from_usage,
)
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from mmaudit.orchestration.consensus import group_candidates
from mmaudit.orchestration.context import render_context
from tests.fake_openrouter import _candidate
from tests.unit.test_model_review_evidence import (
    _context,
    _record,
    _request,
    _usage,
)

_SPECIALIST_ROLE = "specialist:accounting_invariant"


class _CandidateReviewSpyClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete_candidate_review_with_evidence(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("invalid recovery coordinates must fail before transport")


def _raw_candidate(
    candidate_id: str,
    *,
    title: str = "Observed accounting may diverge from local assets",
) -> CandidateFinding:
    return CandidateFinding.model_validate(
        _candidate(
            candidate_id=candidate_id,
            role=_SPECIALIST_ROLE,
            title=title,
            path="src/SyntheticVault.sol",
            start_line=3,
            end_line=3,
            cwe="CWE-682",
            symbol="deposit",
        )
    )


def _bound_usage(batch: CandidateReviewBatch, *, role: str) -> UsageRecord:
    context = _context((_request(),))
    rendered_sha256 = hashlib.sha256(render_context(context).encode("utf-8")).hexdigest()
    return _usage(batch, role=role).model_copy(update={"user_prompt_sha256": rendered_sha256})


def _structural_truncated_usage(
    *,
    role: str,
    request_id: str,
    requested_model: str = "author/exact-model",
) -> UsageRecord:
    return UsageRecord(
        request_id=request_id,
        role=role,
        requested_model=requested_model,
        returned_model=requested_model,
        actual_model=requested_model,
        model_family="detached-input-does-not-control-stamping",
        timestamp=datetime(2026, 8, 18, tzinfo=UTC),
        prompt_sha256="f" * 64,
        validation_status=ModelRequestValidationStatus.TRUNCATED,
        status="rejected_truncated_response",
        attempts=1,
    )


def _accountable_truncated_usage(
    batch: CandidateReviewBatch,
    *,
    context: ContextPackage,
    role: str,
) -> UsageRecord:
    usage = _bound_usage(batch, role=role)
    plan = request_token_plan_from_usage(usage)
    assert plan is not None
    request_limit = AtomicRequestLimitReservationEvidence.build(
        request_id=usage.request_id,
        exact_model_id=usage.requested_model,
        role=usage.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope=usage.request_id,
        request_limit_count_before=0,
        request_limit_maximum=10,
    )
    rendered = render_context(context)
    context_evidence = ContextRequestEvidence.build(
        request_id=usage.request_id,
        request_role=usage.role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered.encode("utf-8")),
        source_bytes=sum(len(item.content.encode("utf-8")) for item in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
    )
    payload = usage.model_dump(mode="json")
    payload.update(
        {
            "validation_status": ModelRequestValidationStatus.TRUNCATED.value,
            "status": "rejected_truncated_response",
            "validated_response_sha256": None,
            "finish_reason": "length",
            "provider_error_classification": "truncated_response",
        }
    )
    payload["routing"] = {
        **payload["routing"],
        "validation_status": "rejected",
        "finish_reason": "length",
        "context_request_evidence": context_evidence.model_dump(mode="json"),
        "context_request_evidence_sha256": context_evidence.evidence_sha256,
        "atomic_request_limit_reservations": [request_limit.model_dump(mode="json")],
        "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
        "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
        "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
    }
    return UsageRecord.model_validate_json(json.dumps(payload))


def test_origin_candidate_identity_binds_request_raw_identity_and_content() -> None:
    candidate = _raw_candidate("raw-a")
    first = _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-a",
        candidate=candidate,
    )

    assert first == "cand-85a00263db8286ab9739f657"
    assert first == _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-a",
        candidate=candidate.model_copy(deep=True),
    )
    assert first != _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-b",
        candidate=candidate,
    )
    assert first != _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-a",
        candidate=_raw_candidate("raw-b"),
    )
    assert first != _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-a",
        candidate=_raw_candidate("raw-a", title="A distinct raw accounting observation"),
    )


def test_raw_candidate_identity_reuse_is_rejected_before_host_stamping() -> None:
    with pytest.raises(OpenRouterSchemaError, match="duplicate raw candidate IDs"):
        _require_unique_raw_candidate_ids(
            [
                _raw_candidate("raw-duplicate"),
                _raw_candidate(
                    "raw-duplicate",
                    title="Conflicting content under the same raw identity",
                ),
            ]
        )


def test_pure_stamping_rejects_duplicate_raw_candidate_ids() -> None:
    usage = _structural_truncated_usage(
        role=_SPECIALIST_ROLE,
        request_id="scheduler-request-duplicate",
    )
    with pytest.raises(CandidateReviewStampingError, match="duplicate raw candidate IDs"):
        stamp_candidate_review_findings(
            request_role=_SPECIALIST_ROLE,
            usage_record=usage,
            trusted_scanner_fingerprints=(),
            raw_findings=(
                _raw_candidate("raw-duplicate"),
                _raw_candidate(
                    "raw-duplicate",
                    title="Conflicting content under the same raw identity",
                ),
            ),
        )


def test_pure_stamping_enforces_bounded_input_inventories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usage = _structural_truncated_usage(
        role=_SPECIALIST_ROLE,
        request_id="scheduler-request-bounds",
    )
    monkeypatch.setattr(candidate_stamping, "MAX_CANDIDATE_REVIEW_FINDINGS", 1)
    with pytest.raises(CandidateReviewStampingError, match="candidate inventory exceeds"):
        stamp_candidate_review_findings(
            request_role=_SPECIALIST_ROLE,
            usage_record=usage,
            trusted_scanner_fingerprints=(),
            raw_findings=(_raw_candidate("raw-a"), _raw_candidate("raw-b")),
        )

    monkeypatch.setattr(candidate_stamping, "MAX_TRUSTED_SCANNER_FINGERPRINTS", 1)
    with pytest.raises(CandidateReviewStampingError, match="fingerprint inventory exceeds"):
        stamp_candidate_review_findings(
            request_role=_SPECIALIST_ROLE,
            usage_record=usage,
            trusted_scanner_fingerprints=("scanner-a", "scanner-b"),
            raw_findings=(_raw_candidate("raw-a"),),
        )


def test_pure_stamping_rejects_role_drift_from_usage_identity() -> None:
    with pytest.raises(CandidateReviewStampingError, match="role differs from usage identity"):
        stamp_candidate_review_findings(
            request_role="source_audit",
            usage_record=_structural_truncated_usage(
                role="business_logic",
                request_id="scheduler-request-role-mismatch",
            ),
            trusted_scanner_fingerprints=(),
            raw_findings=(_raw_candidate("raw-role-mismatch"),),
        )


def test_pure_stamping_binds_request_role_and_model_projection() -> None:
    raw_candidate = _raw_candidate("raw-drift")
    baseline_usage = _structural_truncated_usage(
        role="source_audit",
        request_id="scheduler-request-baseline",
    )
    baseline = stamp_candidate_review_findings(
        request_role="source_audit",
        usage_record=baseline_usage,
        trusted_scanner_fingerprints=(),
        raw_findings=(raw_candidate,),
    )[0]
    request_drift = stamp_candidate_review_findings(
        request_role="source_audit",
        usage_record=_structural_truncated_usage(
            role="source_audit",
            request_id="scheduler-request-drift",
        ),
        trusted_scanner_fingerprints=(),
        raw_findings=(raw_candidate,),
    )[0]
    role_drift = stamp_candidate_review_findings(
        request_role="business_logic",
        usage_record=_structural_truncated_usage(
            role="business_logic",
            request_id=baseline_usage.request_id,
        ),
        trusted_scanner_fingerprints=(),
        raw_findings=(raw_candidate,),
    )[0]
    model_drift = stamp_candidate_review_findings(
        request_role="source_audit",
        usage_record=_structural_truncated_usage(
            role="source_audit",
            request_id=baseline_usage.request_id,
            requested_model="different/alternate-lineage",
        ),
        trusted_scanner_fingerprints=(),
        raw_findings=(raw_candidate,),
    )[0]

    assert request_drift.candidate_id != baseline.candidate_id
    assert role_drift.candidate_id != baseline.candidate_id
    assert model_drift.candidate_id == baseline.candidate_id
    assert model_drift.model_family != baseline.model_family
    assert model_drift.model_votes != baseline.model_votes


def test_structurally_accountable_truncated_usage_stamps_without_granting_credit() -> None:
    request = _request()
    context = _context((request,)).model_copy(update={"role": "source_audit"})
    raw_candidate = _raw_candidate("raw-truncated")
    batch = CandidateReviewBatch(
        findings=[raw_candidate],
        surface_reviews=(_record(request, role="source_audit"),),
    )
    truncated_usage = _accountable_truncated_usage(
        batch,
        context=context,
        role="source_audit",
    )

    assert is_structurally_accountable_usage_record(truncated_usage)
    assert not is_creditable_usage_record(truncated_usage)
    stamped = stamp_candidate_review_findings(
        request_role="source_audit",
        usage_record=truncated_usage,
        trusted_scanner_fingerprints=(),
        raw_findings=batch.findings,
    )

    assert stamped[0].candidate_id == _model_review_origin_candidate_id(
        request_role="source_audit",
        request_id=truncated_usage.request_id,
        candidate=raw_candidate,
    )
    assert stamped[0].execution_provenance is None
    assert stamped[0].model_votes[0].verdict == "proposed"
    candidate_payload = stamped[0].model_dump(mode="json")
    assert "review_credit_authorized" not in candidate_payload
    assert "completion_authorized" not in candidate_payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("single_route_single_attempt", "request_limit_scope", "request_limit_count_before"),
    [
        (False, f"scheduler-request-{'1' * 64}", 1),
        (True, "", -1),
    ],
)
async def test_generic_and_specialist_recovery_coordinates_fail_before_transport(
    config_factory: Callable[..., AuditConfig],
    single_route_single_attempt: bool,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> None:
    config = config_factory()
    context = _context((_request(),))
    clients = (_CandidateReviewSpyClient(), _CandidateReviewSpyClient())
    agents = (
        SourceAuditAgent(config, cast(OpenRouterClient, clients[0])),
        SpecialistFindingAgent(
            config,
            cast(OpenRouterClient, clients[1]),
            "accounting_invariant",
        ),
    )

    for agent, client in zip(agents, clients, strict=True):
        with pytest.raises(OpenRouterSchemaError, match="one-route/one-attempt coordinates"):
            await agent.run(
                context.model_copy(update={"role": agent.role}),
                single_route_single_attempt=single_route_single_attempt,
                recovery_request_limit_scope=request_limit_scope,
                recovery_request_limit_count_before=request_limit_count_before,
            )
        assert client.calls == 0


def test_generic_and_specialist_binders_use_request_bound_origin_identity(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    inert_client = cast(OpenRouterClient, object())
    request = _request()
    specialist_context = _context((request,))
    source_context = specialist_context.model_copy(update={"role": "source_audit"})
    raw_candidate = _raw_candidate("raw-bound")

    source_batch = CandidateReviewBatch(
        findings=[raw_candidate],
        surface_reviews=(_record(request, role="source_audit"),),
    )
    source_usage = _bound_usage(source_batch, role="source_audit")
    source_result = SourceAuditAgent(config, inert_client).bind_completed_review(
        source_context,
        raw_response=source_batch,
        completion_usage=source_usage,
    )

    specialist_batch = CandidateReviewBatch(
        findings=[raw_candidate],
        surface_reviews=(_record(request, role=_SPECIALIST_ROLE),),
    )
    specialist_usage = _bound_usage(specialist_batch, role=_SPECIALIST_ROLE)
    specialist_result = SpecialistFindingAgent(
        config,
        inert_client,
        "accounting_invariant",
    ).bind_completed_review(
        specialist_context,
        raw_response=specialist_batch,
        completion_usage=specialist_usage,
    )

    assert source_result.findings == stamp_candidate_review_findings(
        request_role="source_audit",
        usage_record=source_usage,
        trusted_scanner_fingerprints=(),
        raw_findings=source_batch.findings,
    )
    assert specialist_result.findings == stamp_candidate_review_findings(
        request_role=_SPECIALIST_ROLE,
        usage_record=specialist_usage,
        trusted_scanner_fingerprints=(),
        raw_findings=specialist_batch.findings,
    )

    assert source_result.findings[0].candidate_id == _model_review_origin_candidate_id(
        request_role="source_audit",
        request_id=source_usage.request_id,
        candidate=raw_candidate,
    )
    assert specialist_result.findings[0].candidate_id == _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id=specialist_usage.request_id,
        candidate=raw_candidate,
    )
    assert source_result.findings[0].candidate_id != specialist_result.findings[0].candidate_id


def test_semantic_grouping_is_deterministic_across_identical_scheduler_reruns() -> None:
    raw_candidates = (_raw_candidate("raw-left"), _raw_candidate("raw-right"))
    request_ids = ("scheduler-request-left", "scheduler-request-right")

    def stamped_run() -> list[CandidateFinding]:
        return [
            candidate.model_copy(
                update={
                    "candidate_id": _model_review_origin_candidate_id(
                        request_role=_SPECIALIST_ROLE,
                        request_id=request_id,
                        candidate=candidate,
                    )
                }
            )
            for request_id, candidate in zip(request_ids, raw_candidates, strict=True)
        ]

    first = group_candidates(stamped_run())
    second = group_candidates(stamped_run())

    assert first == second
    assert len(first) == 1
    assert len(first[0].candidates) == 2
