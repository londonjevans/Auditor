"""Scheduler-owned logical identity at the model request boundary."""

from __future__ import annotations

import hashlib
import inspect
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.agents.base import FindingAgent, ThreatModelAgent
from mmaudit.agents.business_logic import BusinessLogicAgent
from mmaudit.agents.configuration import ConfigurationAgent
from mmaudit.agents.invariant_review import InvariantReviewAgent
from mmaudit.agents.judge import JudgeAgent
from mmaudit.agents.reproduction import ExploitTestPlannerAgent, FalsifierAgent
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.agents.specialists import ReportQualityAgent, SpecialistFindingAgent
from mmaudit.agents.verifier import CandidateCrossExaminerAgent, VerifierAgent
from mmaudit.config import AuditConfig
from mmaudit.models import openrouter as openrouter_module
from mmaudit.models.openrouter import (
    DeliveredSourceDescriptor,
    ModelRequestPrivacyBinding,
    OpenRouterClient,
    OpenRouterPrivacyError,
    OpenRouterProviderPolicy,
    OpenRouterRequestLimitError,
    OpenRouterSchemaError,
    structured_output_system_prompt_sha256,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerPassKind,
    SchedulerPrivacyEvidenceCustody,
    SchedulerScope,
    SchedulerTaskEventKind,
)
from mmaudit.models.schemas import ContextExcerpt, RepositoryFile, ThreatModel
from mmaudit.models.usage import atomic_request_limit_reservations_from_usage
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    _issue_trusted_request_limit_scope,
    _TrustedRequestLimitScope,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from tests.unit.test_openrouter import (
    Answer,
    _client,
    _completion_response,
    _empty_context_package,
)
from tests.unit.test_scheduler_journal import (
    _analysis_inventory,
    _bindings,
    _inventory,
    _privacy_custody,
)


class _LifecycleRecorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def request_ready(self, **values: Any) -> _TrustedRequestLimitScope | None:
        self.events.append(("ready", values))
        return None

    def request_dispatched(self, *, logical_request_id: str) -> None:
        self.events.append(("dispatched", {"logical_request_id": logical_request_id}))


class _TrustedSchedulerLifecycleRecorder(_LifecycleRecorder):
    """Synthetic trusted scheduler boundary for request-count capability tests."""

    def request_ready(self, **values: Any) -> _TrustedRequestLimitScope:
        super().request_ready(**values)
        logical_request_id = values["logical_request_id"]
        assert isinstance(logical_request_id, str)
        return _issue_trusted_request_limit_scope(logical_request_id)


@pytest.mark.asyncio
async def test_scheduler_identity_reaches_provider_usage_and_context_evidence(
    config_factory: Callable[..., AuditConfig],
) -> None:
    request_bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_bodies.append(json.loads(request.content))
        return _completion_response('{"answer":"bounded"}')

    client, http_client, usage = _client(config_factory(), handler)
    logical_request_id = "campaign-001.source-audit.node-0007"
    context = _empty_context_package()
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt=render_context(context),
            context_package=context,
            response_model=Answer,
            schema_name="answer",
            logical_request_id=logical_request_id,
        )
    finally:
        await http_client.aclose()

    record = completion.usage_record
    assert record is usage.records[0]
    assert record.request_id == logical_request_id
    assert record.routing["request_token_plan"]["request_id"] == logical_request_id
    assert record.routing["context_request_evidence"]["request_id"] == logical_request_id
    assert record.routing["atomic_token_reservations"][0]["request_id"] == logical_request_id
    assert "atomic_request_limit_reservations" not in record.routing
    assert request_bodies[0]["metadata"]["mmaudit_request_id"] == logical_request_id


@pytest.mark.asyncio
async def test_scheduler_request_preview_matches_exact_primary_route_usage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"previewed"}'),
    )
    context = _empty_context_package()
    user_prompt = render_context(context)
    preview = client.preview_structured_request_hashes(
        role="source_audit",
        model="alpha/atlas-secure",
        system_prompt="system",
        user_prompt=user_prompt,
        response_model=Answer,
        schema_name="answer",
    )
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt=user_prompt,
            context_package=context,
            response_model=Answer,
            schema_name="answer",
            logical_request_id="campaign-001.preview-node",
        )
    finally:
        await http_client.aclose()

    usage = completion.usage_record
    assert preview.prompt_sha256 == usage.prompt_sha256
    assert preview.system_prompt_sha256 == structured_output_system_prompt_sha256(
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        system_prompt="system",
        user_prompt=user_prompt,
        response_model=Answer,
        schema_name="answer",
    )
    assert preview.user_prompt_sha256 == usage.user_prompt_sha256
    assert preview.schema_sha256 == usage.schema_sha256


@pytest.mark.asyncio
async def test_scheduler_request_preview_reuses_its_single_schema_generation(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"unused"}'),
    )
    original_plan = openrouter_module._structured_output_request_plan
    planned_schema_sha256: list[str] = []

    def capture_plan(*args: Any, **kwargs: Any) -> Any:
        plan = original_plan(*args, **kwargs)
        planned_schema_sha256.append(plan.schema_sha256)

        def reject_second_generation(_response_model: type[Any]) -> dict[str, Any]:
            raise AssertionError("request preview regenerated its schema after sealing the plan")

        monkeypatch.setattr(openrouter_module, "strict_json_schema", reject_second_generation)
        return plan

    monkeypatch.setattr(openrouter_module, "_structured_output_request_plan", capture_plan)
    try:
        preview = client.preview_structured_request_hashes(
            role="source_audit",
            model="alpha/atlas-secure",
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert planned_schema_sha256 == [preview.schema_sha256]


@pytest.mark.asyncio
async def test_scheduler_lifecycle_is_durable_before_transport(
    config_factory: Callable[..., AuditConfig],
) -> None:
    lifecycle = _LifecycleRecorder()
    logical_request_id = "campaign-001.lifecycle-node"

    def handler(_request: httpx.Request) -> httpx.Response:
        assert [event for event, _values in lifecycle.events] == ["ready", "dispatched"]
        return _completion_response('{"answer":"observed"}')

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("synthetic-provider",)),
    )
    client.bind_request_lifecycle_observer(lifecycle)
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
            logical_request_id=logical_request_id,
        )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    ready = lifecycle.events[0][1]
    usage = completion.usage_record
    assert ready["logical_request_id"] == logical_request_id
    assert ready["role"] == usage.role
    assert ready["requested_model"] == usage.requested_model
    assert ready["prompt_sha256"] == usage.prompt_sha256
    assert ready["user_prompt_sha256"] == usage.user_prompt_sha256
    assert ready["schema_sha256"] == usage.schema_sha256
    policy = client.effective_privacy_policy
    assert policy is not None
    assert ready["privacy_binding"] == ModelRequestPrivacyBinding(
        source_sha256=policy.source_sha256,
        effective_policy_sha256=policy.evidence_sha256,
        source_provenance_sha256=policy.source_provenance_sha256,
    )


@pytest.mark.asyncio
async def test_scheduler_privacy_mismatch_stops_before_budget_or_transport(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    handler_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal handler_calls
        handler_calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory()
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("synthetic-provider",)),
    )
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    client.budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        atomic_ledger=ledger,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
    )
    scheduler = PipelineScheduler.create(
        tmp_path / "journal",
        bindings=_bindings(),
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=_inventory(),
        privacy_evidence_custody=_privacy_custody(),
    )
    system_prompt = "system"
    user_prompt = "synthetic local input"
    preview = client.preview_structured_request_hashes(
        role="threat_model",
        model="alpha/atlas-secure",
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=ThreatModel,
        schema_name="threat_model",
    )
    task = scheduler.model_task(
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_key="privacy-mismatch",
        role="threat_model",
        requested_model="alpha/atlas-secure",
        root_lineage="sha256:" + "1" * 64,
        system_prompt_sha256=preview.system_prompt_sha256,
        response_schema_sha256=preview.schema_sha256,
    )
    scheduler.seal_pass(SchedulerPassKind.ORIENTATION, (task,))
    before = ledger.snapshot()
    client.bind_request_lifecycle_observer(scheduler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="privacy authority differs"):
            await client.complete_with_evidence(
                role="threat_model",
                models=["alpha/atlas-secure"],
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=ThreatModel,
                schema_name="threat_model",
                logical_request_id=task.logical_request_id,
            )
    finally:
        client.unbind_request_lifecycle_observer(scheduler)
        scheduler.close()
        await http_client.aclose()

    assert handler_calls == 0
    assert usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_scheduler_privacy_binding_is_rechecked_after_reservation(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    handler_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal handler_calls
        handler_calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory()
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("synthetic-provider",)),
    )
    inventory = _inventory()
    evaluated_at = datetime.now(UTC).replace(microsecond=0)

    def policy_for(source_sha256: str):  # type: ignore[no-untyped-def]
        return resolve_effective_privacy_policy(
            profile=PrivacyProfile.STRICT_ZDR,
            require_zdr=True,
            consent_observation=None,
            source_sha256=source_sha256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=("alpha/atlas-secure",),
            configured_provider_endpoints=("synthetic-provider",),
            requested_budget_usd=Decimal(str(config.execution.budget_usd)),
            now=evaluated_at,
        )

    initial_policy = policy_for(inventory.source_tree_sha256)
    client.effective_privacy_policy = initial_policy
    custody = SchedulerPrivacyEvidenceCustody.build(
        source_sha256=inventory.source_tree_sha256,
        source_provenance_size=128,
        source_provenance_artifact_sha256="a" * 64,
        source_provenance_evidence_sha256=initial_policy.source_provenance_sha256,
        effective_policy_size=256,
        effective_policy_artifact_sha256="b" * 64,
        effective_policy_evidence_sha256=initial_policy.evidence_sha256,
        policy_source_provenance_sha256=initial_policy.source_provenance_sha256,
    )
    original_bindings = _bindings()
    bindings = SchedulerBindings.build(
        source_sha256=original_bindings.source_sha256,
        analysis_input_sha256=original_bindings.analysis_input_sha256,
        effective_config_sha256=original_bindings.effective_config_sha256,
        shard_inventory_sha256=original_bindings.shard_inventory_sha256,
        model_selection_sha256=original_bindings.model_selection_sha256,
        qualification_sha256=original_bindings.qualification_sha256,
        prompt_set_sha256=original_bindings.prompt_set_sha256,
        schema_set_sha256=original_bindings.schema_set_sha256,
        tool_policy_sha256=original_bindings.tool_policy_sha256,
        privacy_evidence_custody_sha256=custody.custody_sha256,
    )
    control = tmp_path / "recheck-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        atomic_ledger=ledger,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
    )
    client.budget = budget
    scheduler = PipelineScheduler.create(
        tmp_path / "recheck-journal",
        bindings=bindings,
        analysis_input_inventory=_analysis_inventory(),
        shard_inventory=inventory,
        privacy_evidence_custody=custody,
    )
    system_prompt = "system"
    user_prompt = "synthetic local input"
    preview = client.preview_structured_request_hashes(
        role="threat_model",
        model="alpha/atlas-secure",
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=ThreatModel,
        schema_name="threat_model",
    )
    task = scheduler.model_task(
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_key="privacy-recheck",
        role="threat_model",
        requested_model="alpha/atlas-secure",
        root_lineage="sha256:" + "1" * 64,
        system_prompt_sha256=preview.system_prompt_sha256,
        response_schema_sha256=preview.schema_sha256,
    )
    scheduler.seal_pass(SchedulerPassKind.ORIENTATION, (task,))
    original_reserve = budget.reserve

    async def reserve_then_replace_policy(*args: Any, **kwargs: Any) -> Any:
        reservation = await original_reserve(*args, **kwargs)
        client.effective_privacy_policy = policy_for("f" * 64)
        return reservation

    monkeypatch.setattr(budget, "reserve", reserve_then_replace_policy)
    client.bind_request_lifecycle_observer(scheduler)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="changed before provider transport"):
            await client.complete_with_evidence(
                role="threat_model",
                models=["alpha/atlas-secure"],
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=ThreatModel,
                schema_name="threat_model",
                logical_request_id=task.logical_request_id,
            )
    finally:
        client.unbind_request_lifecycle_observer(scheduler)
        scheduler.close()
        await http_client.aclose()

    ledger_snapshot = ledger.snapshot()
    assert handler_calls == 0
    assert usage.records == []
    assert ledger_snapshot.active_reserved_usd == 0
    assert ledger_snapshot.spent_usd == 0
    assert len(ledger_snapshot.entries) == 1
    assert ledger_snapshot.entries[0].status.value == "released"
    assert tuple(event.kind for event in scheduler.journal.events) == (
        SchedulerTaskEventKind.PLANNED,
        SchedulerTaskEventKind.ACTIVATED,
    )


@pytest.mark.asyncio
async def test_scheduler_lifecycle_credits_only_exact_whole_file_delivery(
    config_factory: Callable[..., AuditConfig],
) -> None:
    lifecycle = _LifecycleRecorder()
    full_source = "contract Whole {\n    function ok() external {}\n}\n"
    source_sha256 = hashlib.sha256(full_source.encode("utf-8")).hexdigest()
    base = _empty_context_package()
    repository_map = base.repository_map.model_copy(
        update={
            "files": [
                RepositoryFile(
                    path="src/Whole.sol",
                    size=len(full_source.encode("utf-8")),
                    lines=len(full_source.splitlines(keepends=True)),
                    sha256=source_sha256,
                    language="Solidity",
                    categories=["smart_contract"],
                ),
                RepositoryFile(
                    path="src/Partial.sol",
                    size=24,
                    lines=3,
                    sha256="a" * 64,
                    language="Solidity",
                    categories=["smart_contract"],
                ),
                RepositoryFile(
                    path="docs/Empty.md",
                    size=0,
                    lines=0,
                    sha256=hashlib.sha256(b"").hexdigest(),
                    language="Markdown",
                    categories=["documentation"],
                ),
            ]
        }
    )
    package = base.model_copy(
        update={
            "effective_source_byte_ceiling": 1_000,
            "repository_map": repository_map,
            "excerpts": (
                ContextExcerpt(
                    path="src/Whole.sol",
                    start_line=1,
                    end_line=3,
                    content_hash=source_sha256,
                    content=full_source,
                    categories=("smart_contract",),
                ),
                ContextExcerpt(
                    path="src/Partial.sol",
                    start_line=2,
                    end_line=2,
                    content_hash=hashlib.sha256(b"partial\n").hexdigest(),
                    content="partial\n",
                    categories=("smart_contract",),
                    omitted_before=True,
                    omitted_after=True,
                ),
                ContextExcerpt(
                    path="docs/Empty.md",
                    start_line=1,
                    end_line=1,
                    content_hash=hashlib.sha256(b"").hexdigest(),
                    content="",
                ),
            ),
        }
    )
    package = package.model_copy(
        update={"bytes_used": len(render_context(package).encode("utf-8"))}
    )
    client, http_client, _usage = _client(
        config_factory(), lambda _request: _completion_response('{"answer":"reviewed"}')
    )
    client.bind_request_lifecycle_observer(lifecycle)
    try:
        await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt=render_context(package),
            context_package=package,
            response_model=Answer,
            schema_name="answer",
            logical_request_id="campaign-001.delivery-proof",
        )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    ready = lifecycle.events[0][1]
    assert ready["delivered_sources"] == (
        DeliveredSourceDescriptor(
            path="docs/Empty.md",
            sha256=hashlib.sha256(b"").hexdigest(),
            size=0,
        ),
        DeliveredSourceDescriptor(
            path="src/Whole.sol",
            sha256=source_sha256,
            size=len(full_source.encode("utf-8")),
        ),
    )


@pytest.mark.asyncio
async def test_scheduler_tasks_share_semantic_role_without_sharing_request_ceiling(
    config_factory: Callable[..., AuditConfig],
) -> None:
    lifecycle = _TrustedSchedulerLifecycleRecorder()
    client, http_client, usage = _client(
        config_factory(execution={"max_requests_per_agent": 1}),
        lambda _request: _completion_response('{"answer":"reviewed"}'),
    )
    client.bind_request_lifecycle_observer(lifecycle)
    task_ids = ("campaign-001.map-task-a", "campaign-001.map-task-b")
    try:
        for task_id in task_ids:
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                logical_request_id=task_id,
            )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    assert [record.role for record in usage.records] == ["source_audit", "source_audit"]
    assert [record.request_id for record in usage.records] == list(task_ids)
    for record, task_id in zip(usage.records, task_ids, strict=True):
        reservation = record.routing["atomic_request_limit_reservation"]
        assert reservation["request_limit_scope"] == task_id
        assert reservation["request_limit_count_before"] == 0
        assert reservation["request_limit_count_after"] == 1
        assert reservation["request_limit_maximum"] == 1
        assert len(atomic_request_limit_reservations_from_usage(record)) == 1


@pytest.mark.asyncio
async def test_generic_lifecycle_observer_cannot_bypass_role_request_ceiling(
    config_factory: Callable[..., AuditConfig],
) -> None:
    lifecycle = _LifecycleRecorder()
    client, http_client, usage = _client(
        config_factory(execution={"max_requests_per_agent": 1}),
        lambda _request: _completion_response('{"answer":"reviewed"}'),
    )
    client.bind_request_lifecycle_observer(lifecycle)
    try:
        await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
            logical_request_id="campaign-001.generic-observer-a",
        )
        with pytest.raises(BudgetExhaustedError, match="request limit"):
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                logical_request_id="campaign-001.generic-observer-b",
            )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    assert len(usage.records) == 1
    assert "atomic_request_limit_reservation" not in usage.records[0].routing
    assert [kind for kind, _values in lifecycle.events] == [
        "ready",
        "dispatched",
        "ready",
    ]


@pytest.mark.asyncio
async def test_scheduler_retry_ceiling_is_scoped_to_stable_task_and_evidenced(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0"},
                json={
                    "error": {"code": 429, "message": "synthetic retry"},
                    "usage": {
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "cost": 0,
                    },
                },
            )
        return _completion_response('{"answer":"bounded"}')

    lifecycle = _TrustedSchedulerLifecycleRecorder()
    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1, "max_requests_per_agent": 2}),
        handler,
    )
    client.bind_request_lifecycle_observer(lifecycle)

    async def no_wait(_attempt: int, _retry_after: str | None) -> None:
        return None

    monkeypatch.setattr(client, "_backoff", no_wait)
    task_id = "campaign-001.retry-task"
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
            logical_request_id=task_id,
        )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    assert calls == 2
    assert completion.usage_record is usage.records[0]
    inventory = completion.usage_record.routing["atomic_request_limit_reservations"]
    assert [item["request_limit_scope"] for item in inventory] == [task_id, task_id]
    assert [item["request_limit_count_before"] for item in inventory] == [0, 1]
    assert [item["request_limit_count_after"] for item in inventory] == [1, 2]
    assert [item["request_limit_maximum"] for item in inventory] == [2, 2]
    assert len(atomic_request_limit_reservations_from_usage(completion.usage_record)) == 2
    tampered_routing = json.loads(json.dumps(completion.usage_record.routing))
    tampered_routing["atomic_request_limit_reservations"][1]["request_limit_count_before"] = 0
    tampered = completion.usage_record.model_copy(update={"routing": tampered_routing})
    with pytest.raises(ValueError, match="request-limit reservation"):
        atomic_request_limit_reservations_from_usage(tampered)


@pytest.mark.asyncio
async def test_scheduler_retry_cannot_exceed_stable_task_request_ceiling(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            429,
            headers={"Retry-After": "0"},
            json={
                "error": {"code": 429, "message": "synthetic retry"},
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "cost": 0,
                },
            },
        )

    lifecycle = _TrustedSchedulerLifecycleRecorder()
    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1, "max_requests_per_agent": 1}),
        handler,
    )
    client.bind_request_lifecycle_observer(lifecycle)

    async def no_wait(_attempt: int, _retry_after: str | None) -> None:
        return None

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        with pytest.raises(BudgetExhaustedError, match="scheduled task"):
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                logical_request_id="campaign-001.capped-retry-task",
            )
    finally:
        client.unbind_request_lifecycle_observer(lifecycle)
        await http_client.aclose()

    assert calls == 1
    assert len(usage.records) == 1
    assert usage.records[0].attempts == 1
    assert (
        usage.records[0].routing["atomic_request_limit_reservation"]["request_limit_scope"]
        == "campaign-001.capped-retry-task"
    )


@pytest.mark.asyncio
async def test_default_identity_remains_a_fresh_uuid(
    config_factory: Callable[..., AuditConfig],
) -> None:
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"uuid"}'),
    )
    try:
        first = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="first",
            response_model=Answer,
            schema_name="answer",
        )
        second = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="second",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 2
    assert uuid.UUID(first.usage_record.request_id).version == 4
    assert uuid.UUID(second.usage_record.request_id).version == 4
    assert first.usage_record.request_id != second.usage_record.request_id


@pytest.mark.asyncio
async def test_invalid_or_reused_scheduler_identity_is_rejected_before_transport(
    config_factory: Callable[..., AuditConfig],
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"once"}')

    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
    )
    arguments = {
        "role": "source_audit",
        "models": ["alpha/atlas-secure"],
        "system_prompt": "system",
        "user_prompt": "synthetic local input",
        "response_model": Answer,
        "schema_name": "answer",
    }
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="restricted non-secret"):
            await client.complete_with_evidence(
                **arguments,
                logical_request_id="invalid/request/id",
            )
        with pytest.raises(OpenRouterRequestLimitError, match="attempt identities"):
            await client.complete_with_evidence(
                **arguments,
                logical_request_id="a" * 120,
            )
        await client.complete_with_evidence(
            **arguments,
            logical_request_id="campaign-001.unique-node",
        )
        with pytest.raises(OpenRouterRequestLimitError, match="already claimed"):
            await client.complete_with_evidence(
                **arguments,
                logical_request_id="campaign-001.unique-node",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert len(usage.records) == 1


@pytest.mark.asyncio
async def test_explicit_fallback_and_retry_identities_have_deterministic_suffixes(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bodies: list[dict[str, Any]] = []
    fallback_attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal fallback_attempts
        body = json.loads(request.content)
        bodies.append(body)
        if body["model"] == "alpha/atlas-secure":
            return httpx.Response(404)
        fallback_attempts += 1
        if fallback_attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return _completion_response(
            '{"answer":"fallback"}',
            model="bravo/borealis-secure",
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1, "max_requests_per_agent": 4}),
        handler,
    )

    async def no_wait(_attempt: int, _retry_after: str | None) -> None:
        return None

    monkeypatch.setattr(client, "_backoff", no_wait)
    logical_request_id = "campaign-001.fallback-node"
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
            logical_request_id=logical_request_id,
        )
    finally:
        await http_client.aclose()

    fallback_id = f"{logical_request_id}:route:2"
    assert [record.request_id for record in usage.records] == [
        logical_request_id,
        fallback_id,
    ]
    assert completion.usage_record.request_id == fallback_id
    assert [body["metadata"]["mmaudit_request_id"] for body in bodies] == [
        logical_request_id,
        fallback_id,
        fallback_id,
    ]
    assert [
        item["request_id"] for item in completion.usage_record.routing["atomic_token_reservations"]
    ] == [fallback_id, f"{fallback_id}:attempt:2"]


@pytest.mark.parametrize(
    ("agent_type", "method_name"),
    [
        (ThreatModelAgent, "run"),
        (FindingAgent, "run"),
        (SourceAuditAgent, "run"),
        (BusinessLogicAgent, "run"),
        (ConfigurationAgent, "run"),
        (CandidateCrossExaminerAgent, "run"),
        (VerifierAgent, "run"),
        (JudgeAgent, "run"),
        (InvariantReviewAgent, "run"),
        (InvariantReviewAgent, "run_with_evidence"),
        (ExploitTestPlannerAgent, "run"),
        (ExploitTestPlannerAgent, "run_with_evidence"),
        (FalsifierAgent, "run"),
        (FalsifierAgent, "run_with_evidence"),
        (SpecialistFindingAgent, "run"),
        (ReportQualityAgent, "run"),
        (ReportQualityAgent, "run_with_evidence"),
    ],
)
def test_every_agent_model_entrypoint_accepts_scheduler_identity(
    agent_type: type[object],
    method_name: str,
) -> None:
    parameter = inspect.signature(getattr(agent_type, method_name)).parameters["logical_request_id"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None


@pytest.mark.parametrize(
    "method_name",
    ["complete", "complete_with_evidence", "complete_with_bound_identity"],
)
def test_openrouter_public_completion_entrypoints_accept_scheduler_identity(
    method_name: str,
) -> None:
    parameter = inspect.signature(getattr(OpenRouterClient, method_name)).parameters[
        "logical_request_id"
    ]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None
