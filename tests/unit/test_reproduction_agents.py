from __future__ import annotations

import hashlib

import pytest

from mmaudit.agents.reproduction import (
    ExploitTestPlannerAgent,
    FalsifierAgent,
    PreparedExploitTestInput,
    PreparedFalsificationInput,
)
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import ContextPackage, RepositoryMap


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
            root_name="synthetic-reproduction-agent",
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


def test_reproduction_workflows_are_deterministic_and_exactly_bound(
    config_factory,
    candidate_factory,
) -> None:
    candidate = candidate_factory(candidate_id="candidate-prepared")
    planner = ExploitTestPlannerAgent(
        config_factory(),
        _SpyClient(),  # type: ignore[arg-type]
        investigator_role="source_audit",
    )

    exploit_input = planner.prepare_input([candidate])
    repeated_exploit_input = planner.prepare_input([candidate])
    falsification_input = FalsifierAgent.prepare_input(
        candidates=[candidate],
        tests=[],
        results=[],
    )
    repeated_falsification_input = FalsifierAgent.prepare_input(
        candidates=[candidate],
        tests=[],
        results=[],
    )

    assert exploit_input == repeated_exploit_input
    assert falsification_input == repeated_falsification_input
    for prepared, closing_tag in (
        (exploit_input, "</REPRODUCTION_INPUT_JSON>\n"),
        (falsification_input, "</FALSIFICATION_INPUT_JSON>\n"),
    ):
        encoded = prepared.workflow_prompt.encode("utf-8")
        assert prepared.workflow_prompt.endswith(closing_tag)
        assert prepared.workflow_byte_upper_bound_tokens == len(encoded)
        assert prepared.workflow_sha256 == hashlib.sha256(encoded).hexdigest()
        assert '"candidate_id":"candidate-prepared"' in prepared.workflow_prompt


@pytest.mark.parametrize(
    ("prepared_type", "field"),
    [
        (PreparedExploitTestInput, "bound"),
        (PreparedExploitTestInput, "hash"),
        (PreparedFalsificationInput, "bound"),
        (PreparedFalsificationInput, "hash"),
    ],
)
def test_reproduction_workflows_reject_tampered_preparation(
    prepared_type,
    field: str,
) -> None:
    prepared = prepared_type.build({"synthetic": "reproduction evidence"})

    with pytest.raises(ValueError, match=r"prepared .* workflow"):
        prepared_type(
            workflow_prompt=prepared.workflow_prompt,
            workflow_byte_upper_bound_tokens=(
                prepared.workflow_byte_upper_bound_tokens + (1 if field == "bound" else 0)
            ),
            workflow_sha256=("0" * 64 if field == "hash" else prepared.workflow_sha256),
        )


@pytest.mark.asyncio
async def test_exploit_planner_rejects_valid_evidence_drift_before_transport(
    config_factory,
    candidate_factory,
) -> None:
    client = _SpyClient()
    agent = ExploitTestPlannerAgent(
        config_factory(),
        client,  # type: ignore[arg-type]
        investigator_role="source_audit",
    )
    prepared = agent.prepare_input([candidate_factory(candidate_id="candidate-before")])

    with pytest.raises(OpenRouterSchemaError, match="differs from submitted planning evidence"):
        await agent.run(
            [candidate_factory(candidate_id="candidate-after")],
            _context("source_audit"),
            prepared_input=prepared,
        )

    assert client.calls == 0


@pytest.mark.asyncio
async def test_falsifier_rejects_valid_evidence_drift_before_transport(
    config_factory,
    candidate_factory,
) -> None:
    client = _SpyClient()
    agent = FalsifierAgent(config_factory(), client)  # type: ignore[arg-type]
    prepared = agent.prepare_input(
        candidates=[candidate_factory(candidate_id="candidate-before")],
        tests=[],
        results=[],
    )

    with pytest.raises(OpenRouterSchemaError, match="differs from submitted evidence"):
        await agent.run(
            candidates=[candidate_factory(candidate_id="candidate-after")],
            tests=[],
            results=[],
            context=_context("falsifier"),
            prepared_input=prepared,
        )

    assert client.calls == 0
