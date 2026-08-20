from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.agents.base as base_agent_module
import mmaudit.agents.specialists as specialist_agent_module
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.agents.specialists import SpecialistFindingAgent
from mmaudit.config import AuditConfig
from mmaudit.models.coverage_planning import ModelSurfaceGapTask
from mmaudit.models.openrouter import (
    OpenRouterCandidateReviewBoundaryError,
    OpenRouterClient,
    trusted_complete_candidate_review_with_evidence,
    trusted_preview_candidate_review_task_resources,
)
from mmaudit.models.scheduler import SchedulerCampaignManifest, SchedulerTaskPlan
from mmaudit.models.schemas import ContextPackage
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.context import render_context
from tests.scheduler_support import _synthetic_manifest
from tests.unit.test_coverage_resource_preview import (
    _MODEL,
    _PROVIDER,
    _ROLE,
    _context,
    _coverage_task,
    _preview_client,
    _scheduler_task,
)
from tests.unit.test_openrouter import (
    _completion_response,
    _empty_candidate_review_wire,
    _empty_context_package,
)


def _resource_coordinates(
    client: OpenRouterClient,
) -> tuple[
    ModelSurfaceGapTask,
    SchedulerTaskPlan,
    SchedulerCampaignManifest,
    ContextPackage,
    str,
    str,
    datetime,
]:
    manifest = _synthetic_manifest("trusted-candidate-review-dispatch")
    scope_id = manifest.shard_inventory.shards[0].shard_id
    coverage_task, request = _coverage_task(scope_id=scope_id)
    context = _context(request)
    system_prompt = "Review only the supplied synthetic surface."
    schema_name = "mmaudit_source_audit_findings"
    scheduler_task = _scheduler_task(
        client,
        coverage_task=coverage_task,
        context=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        campaign_manifest=manifest,
    )
    return (
        coverage_task,
        scheduler_task,
        manifest,
        context,
        system_prompt,
        schema_name,
        datetime.now(UTC).replace(microsecond=0),
    )


def _side_effect_state(
    *,
    calls: list[httpx.Request],
    client: OpenRouterClient,
    usage: UsageLedger,
    budget: BudgetManager,
) -> tuple[object, ...]:
    return (
        tuple(calls),
        usage.records,
        frozenset(client._claimed_request_ids),
        client.context_preflight.records,
        budget.spent_usd_exact,
        budget.reserved_usd,
        budget.spent_input_tokens,
        budget.reserved_input_tokens,
        budget.spent_output_tokens,
        budget.reserved_output_tokens,
    )


@pytest.mark.asyncio
async def test_trusted_candidate_review_entrypoints_preserve_nominal_preview_and_dispatch(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[httpx.Request] = []
    _batch, wire = _empty_candidate_review_wire()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return _completion_response(wire, provider=_PROVIDER)

    client, http_client, usage, _budget = _preview_client(
        config_factory,
        handler,
        ledger_path=tmp_path / "trusted-nominal-cost-ledger.json",
    )
    (
        coverage_task,
        scheduler_task,
        manifest,
        context,
        system_prompt,
        schema_name,
        checked_at,
    ) = _resource_coordinates(client)
    try:
        expected = client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        preview = trusted_preview_candidate_review_task_resources(
            client,
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        assert preview == expected
        assert calls == []

        completion = await trusted_complete_candidate_review_with_evidence(
            client,
            role=_ROLE,
            models=[_MODEL],
            system_prompt=system_prompt,
            user_prompt=render_context(context),
            context_package=context,
            schema_name=schema_name,
            logical_request_id=scheduler_task.logical_request_id,
            expected_resource_preview=preview,
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            resource_preview_checked_at=checked_at,
        )
        assert completion.value.findings == []
        assert len(calls) == 1
        assert len(usage.records) == 1
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_trusted_entrypoints_reject_instance_shadows_without_side_effects(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[httpx.Request] = []
    shadow_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise AssertionError("a rejected dispatch shadow must never reach transport")

    client, http_client, usage, budget = _preview_client(
        config_factory,
        handler,
        ledger_path=tmp_path / "trusted-shadow-cost-ledger.json",
    )
    (
        coverage_task,
        scheduler_task,
        manifest,
        context,
        system_prompt,
        schema_name,
        checked_at,
    ) = _resource_coordinates(client)
    before = _side_effect_state(calls=calls, client=client, usage=usage, budget=budget)
    instance_state = object.__getattribute__(client, "__dict__")

    def preview_shadow(**_kwargs: object) -> object:
        nonlocal shadow_calls
        shadow_calls += 1
        raise AssertionError("the instance preview shadow must never be invoked")

    async def completion_shadow(**_kwargs: object) -> object:
        nonlocal shadow_calls
        shadow_calls += 1
        raise AssertionError("the instance completion shadow must never be invoked")

    try:
        instance_state["preview_candidate_review_task_resources"] = preview_shadow
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="resource_preview dispatch boundary changed",
        ):
            trusted_preview_candidate_review_task_resources(
                client,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=checked_at,
            )
        del instance_state["preview_candidate_review_task_resources"]
        instance_state["complete_candidate_review_with_evidence"] = completion_shadow
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="completion dispatch boundary changed",
        ):
            await trusted_complete_candidate_review_with_evidence(
                client,
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=render_context(context),
                context_package=context,
                schema_name=schema_name,
                logical_request_id=scheduler_task.logical_request_id,
            )
        assert shadow_calls == 0
        assert _side_effect_state(calls=calls, client=client, usage=usage, budget=budget) == before
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_trusted_entrypoints_reject_class_helper_mutation_without_side_effects(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[httpx.Request] = []
    mutated_helper_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise AssertionError("a rejected class mutation must never reach transport")

    client, http_client, usage, budget = _preview_client(
        config_factory,
        handler,
        ledger_path=tmp_path / "trusted-class-mutation-cost-ledger.json",
    )
    (
        coverage_task,
        scheduler_task,
        manifest,
        context,
        system_prompt,
        schema_name,
        checked_at,
    ) = _resource_coordinates(client)
    before = _side_effect_state(calls=calls, client=client, usage=usage, budget=budget)

    def mutated_reasoning_helper(self: OpenRouterClient, role: str) -> None:
        del self, role
        nonlocal mutated_helper_calls
        mutated_helper_calls += 1

    monkeypatch.setattr(OpenRouterClient, "_reasoning_for_role", mutated_reasoning_helper)
    try:
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="resource_preview dispatch boundary changed",
        ):
            trusted_preview_candidate_review_task_resources(
                client,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=checked_at,
            )
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="completion dispatch boundary changed",
        ):
            await trusted_complete_candidate_review_with_evidence(
                client,
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=render_context(context),
                context_package=context,
                schema_name=schema_name,
                logical_request_id=scheduler_task.logical_request_id,
            )
        assert mutated_helper_calls == 0
        assert _side_effect_state(calls=calls, client=client, usage=usage, budget=budget) == before
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("agent_module", "agent_kind"),
    ((base_agent_module, "source"), (specialist_agent_module, "specialist")),
)
async def test_finding_agents_reject_import_binding_substitution_before_client_dispatch(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    agent_module: Any,
    agent_kind: str,
) -> None:
    substituted_calls = 0

    async def substituted_dispatch(*_args: object, **_kwargs: object) -> object:
        nonlocal substituted_calls
        substituted_calls += 1
        raise AssertionError("a substituted agent import binding must never be invoked")

    monkeypatch.setattr(
        agent_module,
        "trusted_complete_candidate_review_with_evidence",
        substituted_dispatch,
    )
    config = config_factory(
        models={
            "specialists": {
                "accounting_invariant": {
                    "primary": _MODEL,
                    "fallbacks": [],
                }
            }
        }
    )
    client = object.__new__(OpenRouterClient)
    agent = (
        SourceAuditAgent(config, client)
        if agent_kind == "source"
        else SpecialistFindingAgent(config, client, "accounting_invariant")
    )
    context = _empty_context_package(role=agent.role)

    with pytest.raises(
        OpenRouterCandidateReviewBoundaryError,
        match="dispatch binding changed",
    ):
        await agent.run(context)
    assert substituted_calls == 0
