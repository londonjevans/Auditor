from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace

import pytest

from mmaudit.agents.judge import JudgeAgent, PreparedJudgmentInput
from mmaudit.agents.verifier import (
    CandidateCrossExaminerAgent,
    PreparedCandidateCrossExaminationInput,
    PreparedVerificationInput,
    VerifierAgent,
)
from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import CandidateFinding, ContextPackage, RepositoryMap


class _SpyClient:
    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("transport must not run for a drifted prepared workflow")


def _context(role: str) -> ContextPackage:
    return ContextPackage(
        role=role,
        byte_budget=1,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        scanner_findings=[],
        excerpts=[],
        repository_map=RepositoryMap(
            root_name="synthetic-verifier-agent",
            languages={},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
    )


def _assert_exact_workflow(
    workflow_prompt: str,
    workflow_byte_upper_bound_tokens: int,
    workflow_sha256: str,
    *,
    closing_tag: str,
) -> None:
    encoded = workflow_prompt.encode("utf-8")
    assert workflow_prompt.endswith(f"{closing_tag}\n")
    assert workflow_byte_upper_bound_tokens == len(encoded)
    assert workflow_sha256 == hashlib.sha256(encoded).hexdigest()


def test_verifier_and_judge_workflows_are_deterministic_and_exactly_bound(
    config_factory: Callable[..., AuditConfig],
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    candidate = candidate_factory(
        candidate_id="internal-origin-id",
        role="specialist:origin-role",
        family="origin/root-lineage",
    )
    cross_examiner = CandidateCrossExaminerAgent(
        config_factory(),
        _SpyClient(),  # type: ignore[arg-type]
        reviewer_index=1,
        model_id="alpha/atlas-secure",
        root_lineage="sha256:" + ("a" * 64),
    )

    cross_exam = cross_examiner.prepare_input([candidate])
    verification = VerifierAgent.prepare_input([candidate])
    judgment = JudgeAgent.prepare_input(
        groups=[{"group_id": "group-1", "candidate_ids": [candidate.candidate_id]}],
        threat_model=None,
    )

    assert cross_exam == cross_examiner.prepare_input([candidate])
    assert verification == VerifierAgent.prepare_input([candidate])
    assert judgment == JudgeAgent.prepare_input(
        groups=[{"group_id": "group-1", "candidate_ids": [candidate.candidate_id]}],
        threat_model=None,
    )
    assert cross_exam.candidate_ids == (("candidate-0001", "internal-origin-id"),)
    assert "internal-origin-id" not in cross_exam.workflow_prompt
    assert "specialist:origin-role" not in cross_exam.workflow_prompt
    assert "origin/root-lineage" not in cross_exam.workflow_prompt

    for prepared, closing_tag in (
        (cross_exam, "</ANONYMIZED_CANDIDATES_JSON>"),
        (verification, "</SUBMITTED_CANDIDATES_JSON>"),
        (judgment, "</VERIFIED_GROUPS_JSON>"),
    ):
        _assert_exact_workflow(
            prepared.workflow_prompt,
            prepared.workflow_byte_upper_bound_tokens,
            prepared.workflow_sha256,
            closing_tag=closing_tag,
        )


@pytest.mark.parametrize("field", ["bound", "hash"])
def test_verifier_and_judge_workflows_reject_tampered_preparation(field: str) -> None:
    prepared_inputs = (
        PreparedCandidateCrossExaminationInput.build(
            [{"candidate_ref": "candidate-0001"}],
            candidate_ids={"candidate-0001": "candidate-real"},
        ),
        PreparedVerificationInput.build({"candidates": []}),
        PreparedJudgmentInput.build({"candidate_groups": [], "threat_model": None}),
    )

    for prepared in prepared_inputs:
        with pytest.raises(ValueError, match=r"prepared .* workflow"):
            replace(
                prepared,
                workflow_byte_upper_bound_tokens=(
                    prepared.workflow_byte_upper_bound_tokens + (1 if field == "bound" else 0)
                ),
                workflow_sha256=("0" * 64 if field == "hash" else prepared.workflow_sha256),
            )


@pytest.mark.asyncio
async def test_cross_examiner_rejects_evidence_drift_before_transport(
    config_factory: Callable[..., AuditConfig],
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    client = _SpyClient()
    agent = CandidateCrossExaminerAgent(
        config_factory(),
        client,  # type: ignore[arg-type]
        reviewer_index=1,
        model_id="alpha/atlas-secure",
        root_lineage="sha256:" + ("a" * 64),
    )
    prepared = agent.prepare_input([candidate_factory(candidate_id="candidate-before")])
    current = agent.prepare_input([candidate_factory(candidate_id="candidate-after")])

    assert prepared.workflow_prompt == current.workflow_prompt
    assert prepared.candidate_ids != current.candidate_ids

    with pytest.raises(OpenRouterSchemaError, match="differs from submitted candidate evidence"):
        await agent.run(
            [candidate_factory(candidate_id="candidate-after")],
            _context("falsifier"),
            prepared_input=prepared,
        )

    assert client.calls == 0


@pytest.mark.asyncio
async def test_verifier_rejects_evidence_drift_before_transport(
    config_factory: Callable[..., AuditConfig],
    candidate_factory: Callable[..., CandidateFinding],
) -> None:
    client = _SpyClient()
    agent = VerifierAgent(config_factory(), client)  # type: ignore[arg-type]
    prepared = agent.prepare_input([candidate_factory(candidate_id="candidate-before")])

    with pytest.raises(OpenRouterSchemaError, match="differs from submitted verification evidence"):
        await agent.run(
            [candidate_factory(candidate_id="candidate-after")],
            _context("verifier"),
            prepared_input=prepared,
        )

    assert client.calls == 0


@pytest.mark.asyncio
async def test_judge_rejects_evidence_drift_before_transport(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client = _SpyClient()
    agent = JudgeAgent(config_factory(), client)  # type: ignore[arg-type]
    prepared = agent.prepare_input(
        groups=[{"group_id": "group-before"}],
        threat_model=None,
    )

    with pytest.raises(OpenRouterSchemaError, match="differs from submitted judgment evidence"):
        await agent.run(
            groups=[{"group_id": "group-after"}],
            context=_context("judge"),
            threat_model=None,
            prepared_input=prepared,
        )

    assert client.calls == 0
