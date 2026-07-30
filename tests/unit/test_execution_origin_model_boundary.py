"""Model authority boundaries for deterministic execution-origin candidates."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any, cast

import pytest

from mmaudit.agents.base import FindingReviewResult
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError, StructuredCompletion
from mmaudit.models.schemas import (
    CandidateOriginKind,
    CandidateReviewBatch,
    ContextPackage,
    ContextRequestEvidence,
    EvidenceStrength,
    FindingOriginKind,
    FindingStatus,
    Location,
    Severity,
    UsageRecord,
    VerificationVerdict,
)
from mmaudit.orchestration.consensus import (
    group_candidates,
    merge_group,
    preliminary_status,
    stable_finding_id,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.pipeline import _validated_finding_result
from tests.unit.test_execution_origin_consensus import (
    _decision,
    _execution_candidate,
    _judge,
    _model_candidate,
    _provenance,
    _validation,
)
from tests.unit.test_model_review_evidence import _context, _usage


class _SyntheticCompletionClient:
    """Return one local structured batch without provider or network access."""

    def __init__(self, batch: CandidateReviewBatch) -> None:
        self.batch = batch

    async def complete_with_evidence(
        self,
        *,
        role: str,
        user_prompt: str,
        **_kwargs: Any,
    ) -> StructuredCompletion[CandidateReviewBatch]:
        usage = _usage(self.batch, role=role).model_copy(
            update={
                "user_prompt_sha256": hashlib.sha256(user_prompt.encode()).hexdigest(),
            }
        )
        return StructuredCompletion(value=self.batch, usage_record=usage)


def _bound_usage(
    batch: CandidateReviewBatch,
    context: ContextPackage,
) -> UsageRecord:
    rendered = render_context(context).encode()
    rendered_sha256 = hashlib.sha256(rendered).hexdigest()
    usage = _usage(batch, role=context.role)
    evidence = ContextRequestEvidence.build(
        request_id=usage.request_id,
        request_role=context.role,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered),
        source_bytes=sum(len(excerpt.content.encode()) for excerpt in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=rendered_sha256,
    )
    return usage.model_copy(
        update={
            "user_prompt_sha256": rendered_sha256,
            "routing": {
                **usage.routing,
                "context_request_evidence": evidence.model_dump(mode="json"),
                "context_request_evidence_sha256": evidence.evidence_sha256,
            },
        }
    )


@pytest.mark.asyncio
async def test_model_response_cannot_create_or_reattribute_execution_origin(
    config_factory: Callable[..., AuditConfig],
) -> None:
    claimed_execution = _execution_candidate(_provenance())
    response = CandidateReviewBatch(findings=[claimed_execution], surface_reviews=())
    client = cast(OpenRouterClient, _SyntheticCompletionClient(response))
    agent = SourceAuditAgent(config_factory(), client)

    result = await agent.run(_context((), role="source_audit"))

    assert len(result.findings) == 1
    normalized = result.findings[0]
    assert normalized.origin_kind is CandidateOriginKind.MODEL_REVIEW
    assert normalized.execution_provenance is None
    assert normalized.role == "source_audit"
    assert normalized.candidate_id != claimed_execution.candidate_id
    assert all(item.type == "model" for item in normalized.evidence)


def test_pipeline_rejects_execution_origin_claim_that_bypasses_agent_normalization() -> None:
    claimed_execution = _execution_candidate(_provenance())
    batch = CandidateReviewBatch(findings=[claimed_execution], surface_reviews=())
    context = _context((), role="source_audit")
    usage = _bound_usage(batch, context)
    result = FindingReviewResult(
        findings=(claimed_execution,),
        surface_review_artifact=None,
        surface_review_context=context,
        completion_usage=usage,
    )

    with pytest.raises(
        OpenRouterSchemaError,
        match="model review attempted to claim host-owned deterministic execution origin",
    ):
        _validated_finding_result(
            result,
            expected_role="source_audit",
            usage_records=[usage],
        )


def test_model_verifier_and_judge_cannot_delete_execution_origin() -> None:
    execution = _execution_candidate(_provenance())
    group = group_candidates([execution])[0]

    finding = merge_group(
        group,
        decisions={
            execution.candidate_id: _decision(
                execution.candidate_id,
                VerificationVerdict.REJECTED,
            )
        },
        validations={execution.candidate_id: _validation(valid=True, marker="a")},
        scanner_findings=[],
        judge=_judge(
            group.group_id,
            status=FindingStatus.REJECTED,
            severity=Severity.LOW,
            confidence=0.01,
        ),
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    assert finding.execution_provenance == (execution.execution_provenance,)
    assert finding.contributing_candidate_ids == [execution.candidate_id]


def test_model_agreement_cannot_confirm_without_deterministic_evidence() -> None:
    location = Location(
        path="src/SyntheticVault.sol",
        start_line=30,
        end_line=32,
        symbol="settle",
    )
    candidates = [
        _model_candidate(
            candidate_id="model-lineage-a",
            locations=[location],
            family="lineage-a",
        ),
        _model_candidate(
            candidate_id="model-lineage-b",
            locations=[location],
            family="lineage-b",
        ),
    ]
    group = group_candidates(candidates)[0]
    decisions = {
        candidate.candidate_id: _decision(
            candidate.candidate_id,
            VerificationVerdict.VERIFIED,
        )
        for candidate in candidates
    }
    validations = {
        candidate.candidate_id: _validation(valid=True, marker=marker)
        for candidate, marker in zip(candidates, ("a", "b"), strict=True)
    }

    assert preliminary_status(group, decisions, validations, []) is FindingStatus.STRONGLY_SUPPORTED
    finding = merge_group(
        group,
        decisions=decisions,
        validations=validations,
        scanner_findings=[],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert finding.status is FindingStatus.STRONGLY_SUPPORTED
    assert finding.origin_kind is FindingOriginKind.MODEL_REVIEW
    assert finding.execution_provenance == ()
    assert finding.evidence_strength is EvidenceStrength.VALIDATED_ATTACK_PATH


def test_model_enrichment_cannot_change_execution_identity_or_location() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance, confidence=0.4)
    relocated = Location(
        path=provenance.source_locations[0].path,
        start_line=200,
        end_line=202,
        symbol="unrelatedTransition",
        content_hash="b" * 64,
    )
    enrichment = _model_candidate(
        candidate_id="model-impact-remediation-enrichment",
        locations=[provenance.source_locations[0], relocated],
        confidence=0.99,
    ).model_copy(
        update={
            "title": "Model-authored replacement title",
            "impact": "Model-authored impact analysis.",
            "recommendation": "Model-authored remediation analysis.",
        }
    )
    expected_group = group_candidates([execution])[0]
    group = group_candidates([enrichment, execution])[0]

    finding = merge_group(
        group,
        decisions={
            execution.candidate_id: _decision(
                execution.candidate_id,
                VerificationVerdict.REJECTED,
            ),
            enrichment.candidate_id: _decision(
                enrichment.candidate_id,
                VerificationVerdict.VERIFIED,
            ),
        },
        validations={
            execution.candidate_id: _validation(valid=True, marker="a"),
            enrichment.candidate_id: _validation(valid=True, marker="b"),
        },
        scanner_findings=[],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert group.group_id == expected_group.group_id
    assert finding.id == stable_finding_id(execution)
    assert finding.group_id == expected_group.group_id
    assert finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    assert finding.execution_provenance == (provenance,)
    assert finding.locations == list(provenance.source_locations)
    assert relocated not in finding.locations
    assert enrichment.candidate_id in finding.contributing_candidate_ids
    assert any(item.type == "model" for item in finding.evidence)
