from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import cast

import pytest

from mmaudit.agents.base import (
    _model_review_origin_candidate_id,
    _require_unique_raw_candidate_ids,
)
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.agents.specialists import SpecialistFindingAgent
from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterSchemaError
from mmaudit.models.schemas import CandidateFinding, CandidateReviewBatch
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


def _bound_usage(batch: CandidateReviewBatch, *, role: str):
    context = _context((_request(),))
    rendered_sha256 = hashlib.sha256(render_context(context).encode("utf-8")).hexdigest()
    return _usage(batch, role=role).model_copy(update={"user_prompt_sha256": rendered_sha256})


def test_origin_candidate_identity_binds_request_raw_identity_and_content() -> None:
    candidate = _raw_candidate("raw-a")
    first = _model_review_origin_candidate_id(
        request_role=_SPECIALIST_ROLE,
        request_id="scheduler-request-a",
        candidate=candidate,
    )

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
