from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal, localcontext
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.models.openrouter as openrouter_module
from mmaudit.models.coverage_planning import (
    ModelSurfaceAssignmentPurpose,
    ModelSurfaceCoverageRequirement,
    ModelSurfaceGapAssignment,
    ModelSurfaceGapTask,
    ModelSurfaceReviewerBinding,
    build_model_surface_coverage_policy,
    classify_model_surface_risk,
)
from mmaudit.models.openrouter import (
    OpenRouterCandidateReviewBoundaryError,
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterRequestLimitError,
)
from mmaudit.models.scheduler import (
    SchedulerCampaignManifest,
    SchedulerPassKind,
    SchedulerScope,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    ContextPackage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
)
from mmaudit.models.truncation import (
    CandidateReviewFramedDocument,
    candidate_review_frame_wire_schema_sha256,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.scheduler_runtime import scheduler_response_normalizer_sha256
from tests.scheduler_support import _synthetic_manifest
from tests.unit.test_openrouter import (
    _client,
    _completion_response,
    _empty_candidate_review_wire,
    _empty_context_package,
    _endpoint_snapshot,
)

_MODEL = "alpha/atlas-secure"
_PROVIDER = "approved-provider"
_ROLE = "source_audit"
_ROOT_LINEAGE = "sha256:" + hashlib.sha256(b"coverage-preview-root").hexdigest()


class _RejectingLifecycleObserver:
    def __init__(self) -> None:
        self.ready_calls = 0
        self.dispatched_calls = 0

    def request_ready(self, **_kwargs: object) -> None:
        self.ready_calls += 1
        raise AssertionError("resource preview must not activate the scheduler observer")

    def request_dispatched(self, **_kwargs: object) -> None:
        self.dispatched_calls += 1
        raise AssertionError("resource preview must not dispatch through the scheduler observer")


def _surface_request(subject_suffix: str = "invariant") -> ModelSurfaceReviewRequest:
    subject_id = f"synthetic:coverage-preview-{subject_suffix}"
    kind = ModelReviewSurfaceKind.INVARIANT
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(kind, subject_id),
        kind=kind,
        subject_id=subject_id,
        contract="SyntheticVault",
        function_or_state_surface="assets == liabilities",
        critical=True,
        allowed_locations=(),
        allowed_symbols=("syntheticInvariant",),
        invariant_considered="Synthetic accounting remains balanced.",
    )


def _coverage_task(
    *,
    scope_id: str,
    subject_suffix: str = "invariant",
) -> tuple[ModelSurfaceGapTask, ModelSurfaceReviewRequest]:
    request = _surface_request(subject_suffix)
    policy = build_model_surface_coverage_policy(1)
    requirement = ModelSurfaceCoverageRequirement.build(
        request=request,
        scope_id=scope_id,
        tier_requirement=policy.requirement_for(classify_model_surface_risk(request)),
        credited_root_lineages=(),
    )
    reviewer = ModelSurfaceReviewerBinding.build(
        review_role=_ROLE,
        requested_model=_MODEL,
        root_lineage=_ROOT_LINEAGE,
    )
    assignment = ModelSurfaceGapAssignment.build(
        requirement=requirement,
        reviewer=reviewer,
        purpose=ModelSurfaceAssignmentPurpose.LINEAGE_GAP,
    )
    return ModelSurfaceGapTask.build(assignments=(assignment,), requests=(request,)), request


def _context(request: ModelSurfaceReviewRequest) -> ContextPackage:
    base = _empty_context_package(role=_ROLE)
    with_surface = base.model_copy(update={"requested_model_surfaces": (request,)})
    return with_surface.model_copy(
        update={"bytes_used": len(render_context(with_surface).encode("utf-8"))}
    )


def _campaign_manifest() -> SchedulerCampaignManifest:
    return _synthetic_manifest("coverage-resource-preview")


def _request_projection_from_dispatch(
    body: dict[str, object],
    token_plan: dict[str, Any],
) -> tuple[str, str, str]:
    plan_payload = json.loads(json.dumps(token_plan))
    plan_payload.pop("plan_sha256")
    global_budget = plan_payload.pop("global_budget")
    assert isinstance(global_budget, dict)
    plan_payload["global_budget"] = {
        key: global_budget[key]
        for key in (
            "schema_version",
            "global_input_token_budget",
            "global_output_token_budget",
            "request_input_tokens",
            "request_output_tokens",
        )
    }
    token_projection = hashlib.sha256(
        json.dumps(
            {
                "domain": "mmaudit.openrouter.candidate-review-token-plan-projection.v1",
                "request_token_plan": plan_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    projected_body = json.loads(json.dumps(body))
    assert isinstance(projected_body, dict)
    metadata = projected_body["metadata"]
    assert isinstance(metadata, dict)
    metadata["mmaudit_token_plan_sha256"] = token_projection
    material = json.dumps(
        projected_body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return token_projection, material, hashlib.sha256(material.encode("utf-8")).hexdigest()


def _scheduler_task(
    client: OpenRouterClient,
    *,
    coverage_task: ModelSurfaceGapTask,
    context: ContextPackage,
    system_prompt: str,
    schema_name: str,
    task_key: str | None = None,
    scope: SchedulerScope | None = None,
    role: str | None = None,
    requested_model: str | None = None,
    root_lineage: str | None = None,
    response_schema_sha256: str | None = None,
    system_prompt_sha256: str | None = None,
    prompt_sha256: str | None = None,
    candidate_ids: tuple[str, ...] = (),
    campaign_manifest: SchedulerCampaignManifest | None = None,
) -> SchedulerTaskPlan:
    manifest = campaign_manifest or _campaign_manifest()
    selected_scope = scope or SchedulerScope.single_shard(coverage_task.scope_id)
    selected_key = task_key or coverage_task.task_id
    selected_role = role or coverage_task.review_role
    selected_model = requested_model or coverage_task.requested_model
    selected_root = root_lineage or coverage_task.root_lineage
    hashes = client.preview_structured_request_hashes(
        role=selected_role,
        model=selected_model,
        system_prompt=system_prompt,
        user_prompt=render_context(context),
        response_model=CandidateReviewFramedDocument,
        schema_name=schema_name,
    )
    input_recipe_sha256 = scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.model-input-recipe.v1",
            "pass_kind": SchedulerPassKind.BLIND_SHARD_REVIEW,
            "scope_sha256": selected_scope.scope_sha256,
            "task_key": selected_key,
            "role": selected_role,
        }
    )
    prompt_recipe_sha256 = scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.model-prompt-recipe.v1",
            "prompt_set_sha256": manifest.bindings.prompt_set_sha256,
            "task_key": selected_key,
            "role": selected_role,
        }
    )
    selected_response_schema_sha256 = (
        response_schema_sha256 or candidate_review_frame_wire_schema_sha256()
    )
    normalizer_sha256 = (
        scheduler_response_normalizer_sha256(selected_response_schema_sha256)
        if selected_response_schema_sha256 == candidate_review_frame_wire_schema_sha256()
        else "e" * 64
    )
    return SchedulerTaskPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        scope=selected_scope,
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        task_key=selected_key,
        role=selected_role,
        requested_model=selected_model,
        root_lineage=selected_root,
        input_sha256=input_recipe_sha256,
        prompt_sha256=prompt_sha256 or prompt_recipe_sha256,
        system_prompt_sha256=system_prompt_sha256 or hashes.system_prompt_sha256,
        normalizer_sha256=normalizer_sha256,
        response_schema_sha256=selected_response_schema_sha256,
        candidate_ids=candidate_ids,
    )


def _preview_client(
    config_factory: Callable[..., Any],
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    ledger_path: Path,
    request_limit: int = 2,
    pricing: dict[str, str] | None = None,
) -> tuple[OpenRouterClient, httpx.AsyncClient, UsageLedger, BudgetManager]:
    config = config_factory(
        execution={
            "max_model_retries": 1,
            "max_requests_per_agent": request_limit,
        }
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=request_limit,
        atomic_ledger=AtomicCostLedger.initialize(
            ledger_path,
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=OpenRouterProviderPolicy(only=(_PROVIDER,)),
        budget=budget,
    )
    client.register_endpoint_snapshot(evidence=_endpoint_snapshot(pricing=pricing))
    return client, http_client, usage, budget


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_preview_is_exact_nonauthorizing_and_matches_dispatch_plan(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    _batch, wire = _empty_candidate_review_wire()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return _completion_response(wire, provider=_PROVIDER)

    client, http_client, usage, budget = _preview_client(
        config_factory,
        handler,
        ledger_path=tmp_path / "preview-cost-ledger.json",
    )
    manifest = _synthetic_manifest("coverage-resource-preview")
    scope_id = next(
        shard.shard_id
        for shard in manifest.shard_inventory.shards
        if shard.shard_id == "shard-000000000000000000000001"
    )
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
    )
    observer = _RejectingLifecycleObserver()
    client.bind_request_lifecycle_observer(observer)
    budget_before = (
        budget.spent_usd_exact,
        budget.reserved_usd,
        budget.spent_input_tokens,
        budget.reserved_input_tokens,
        budget.spent_output_tokens,
        budget.reserved_output_tokens,
    )
    checked_at = datetime.now(UTC).replace(microsecond=0)
    try:
        preview = client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        repeated = client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )

        assert repeated == preview
        assert preview.coverage_task_id == coverage_task.task_id
        assert preview.coverage_task_sha256 == coverage_task.task_sha256
        assert preview.scheduler_task_id == scheduler_task.task_id
        assert preview.scheduler_task_plan_sha256 == scheduler_task.task_plan_sha256
        assert preview.campaign_manifest_sha256 == manifest.manifest_sha256
        assert (
            preview.rendered_context_sha256
            == hashlib.sha256(render_context(context).encode("utf-8")).hexdigest()
        )
        endpoint_policy = client._endpoint_pricing[_MODEL]
        assert preview.endpoint_policy_snapshot_sha256 == endpoint_policy.snapshot_sha256
        assert preview.endpoint_policy_pricing_sha256 == endpoint_policy.policy_pricing_sha256
        assert preview.maximum_attempts == 2
        assert preview.maximum_request_count == 2
        assert preview.maximum_input_tokens == preview.maximum_prompt_tokens_per_attempt * 2
        assert preview.maximum_output_tokens == preview.maximum_completion_tokens_per_attempt * 2
        assert Decimal(preview.maximum_cost_usd_exact) == (
            Decimal(preview.maximum_cost_usd_per_attempt_exact) * 2
        )
        assert preview.authorizes_dispatch is False
        assert preview.grants_review_credit is False
        assert preview.grants_completion_credit is False
        assert calls == []
        assert usage.records == []
        assert client._claimed_request_ids == set()
        assert client.context_preflight.records == ()
        assert observer.ready_calls == 0
        assert observer.dispatched_calls == 0
        assert (
            budget.spent_usd_exact,
            budget.reserved_usd,
            budget.spent_input_tokens,
            budget.reserved_input_tokens,
            budget.spent_output_tokens,
            budget.reserved_output_tokens,
        ) == budget_before

        client.unbind_request_lifecycle_observer(observer)
        completion = await client.complete_candidate_review_with_evidence(
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
        token_plan = completion.usage_record.routing["request_token_plan"]
        context_evidence = completion.usage_record.routing["context_request_evidence"]
        assert preview.context_request_evidence_sha256 == context_evidence["evidence_sha256"]
        assert preview.rendered_context_sha256 == context_evidence["rendered_sha256"]
        assert (
            preview.maximum_prompt_tokens_per_attempt
            == token_plan["prompt_byte_upper_bound_tokens"]
        )
        assert (
            preview.maximum_completion_tokens_per_attempt
            == token_plan["requested_completion_tokens"]
        )
        request_material = json.dumps(
            calls[0],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        token_projection, projected_material, projected_material_sha256 = (
            _request_projection_from_dispatch(calls[0], token_plan)
        )
        assert preview.request_token_plan_projection_sha256 == token_projection
        assert preview.request_material_projection_utf8_bytes == len(
            projected_material.encode("utf-8")
        )
        assert preview.request_material_projection_sha256 == projected_material_sha256
        assert len(projected_material.encode("utf-8")) == len(request_material.encode("utf-8"))
        assert (
            completion.usage_record.request_body_sha256
            == hashlib.sha256(request_material.encode("utf-8")).hexdigest()
        )
        prompt_units = max(
            len(request_material.encode("utf-8")),
            token_plan["prompt_byte_upper_bound_tokens"],
        )
        with localcontext() as decimal_context:
            decimal_context.prec = 160
            exact_maximum = (
                Decimal("0.000001") * prompt_units
                + Decimal("0.00001") * token_plan["requested_completion_tokens"]
            ).quantize(Decimal("0.000000000001"), rounding=ROUND_CEILING)
        assert Decimal(preview.maximum_cost_usd_per_attempt_exact) == exact_maximum
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_saved_previews_survive_unrelated_spend_and_sequential_bound_dispatch(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[dict[str, object]] = []
    _batch, wire = _empty_candidate_review_wire()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return _completion_response(wire, provider=_PROVIDER)

    client, http_client, usage, _budget = _preview_client(
        config_factory,
        handler,
        ledger_path=tmp_path / "preview-sequential-cost-ledger.json",
        request_limit=8,
    )
    manifest = _campaign_manifest()
    scopes = manifest.shard_ids
    first_task, first_request = _coverage_task(
        scope_id=scopes[0],
        subject_suffix="first-invariant",
    )
    second_task, second_request = _coverage_task(
        scope_id=scopes[1],
        subject_suffix="second-invariant",
    )
    first_context = _context(first_request)
    second_context = _context(second_request)
    system_prompt = "Review only the supplied synthetic surface."
    schema_name = "mmaudit_source_audit_findings"
    first_scheduler_task = _scheduler_task(
        client,
        coverage_task=first_task,
        context=first_context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        campaign_manifest=manifest,
    )
    second_scheduler_task = _scheduler_task(
        client,
        coverage_task=second_task,
        context=second_context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        campaign_manifest=manifest,
    )
    checked_at = datetime.now(UTC).replace(microsecond=0)
    saved_previews = tuple(
        client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        for coverage_task, scheduler_task, context in (
            (first_task, first_scheduler_task, first_context),
            (second_task, second_scheduler_task, second_context),
        )
    )
    unrelated_request_id = (
        "scheduler-request-" + hashlib.sha256(b"unrelated-prior-spend").hexdigest()
    )
    try:
        await client.complete_candidate_review_with_evidence(
            role=_ROLE,
            models=[_MODEL],
            system_prompt=system_prompt,
            user_prompt=render_context(first_context),
            context_package=first_context,
            schema_name=schema_name,
            logical_request_id=unrelated_request_id,
        )
        recomputed_after_unrelated_spend = client.preview_candidate_review_task_resources(
            coverage_task=first_task,
            scheduler_task=first_scheduler_task,
            campaign_manifest=manifest,
            context_package=first_context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at + timedelta(seconds=1),
        )
        assert (
            recomputed_after_unrelated_spend.model_dump_json()
            == saved_previews[0].model_dump_json()
        )
        bound_completions = []
        for index, (coverage_task, scheduler_task, context, preview) in enumerate(
            (
                (first_task, first_scheduler_task, first_context, saved_previews[0]),
                (second_task, second_scheduler_task, second_context, saved_previews[1]),
            ),
            start=2,
        ):
            recomputed_before_dispatch = client.preview_candidate_review_task_resources(
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=checked_at + timedelta(seconds=index),
            )
            assert recomputed_before_dispatch.model_dump_json() == preview.model_dump_json()
            bound_completions.append(
                await client.complete_candidate_review_with_evidence(
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
            )
            recomputed_after_dispatch = client.preview_candidate_review_task_resources(
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=checked_at + timedelta(seconds=index + 1),
            )
            assert recomputed_after_dispatch.model_dump_json() == preview.model_dump_json()
        assert len(calls) == 3
        assert len(usage.records) == 3
        for index, (preview, completion) in enumerate(
            zip(saved_previews, bound_completions, strict=True),
            start=1,
        ):
            token_plan = completion.usage_record.routing["request_token_plan"]
            token_projection, material, material_sha256 = _request_projection_from_dispatch(
                calls[index],
                token_plan,
            )
            assert token_plan["global_budget"]["input_tokens_reserved_before"] > 0
            assert token_plan["global_budget"]["output_tokens_reserved_before"] > 0
            assert preview.request_token_plan_projection_sha256 == token_projection
            assert preview.request_material_projection_sha256 == material_sha256
            assert preview.request_material_projection_utf8_bytes == len(material.encode("utf-8"))
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_projection_helper_substitution_cannot_mask_changed_request_body(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[httpx.Request] = []

    def reject_transport(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        pytest.fail("mutated projection helper reached transport")

    client, http_client, usage, _budget = _preview_client(
        config_factory,
        reject_transport,
        ledger_path=tmp_path / "preview-helper-mutation-ledger.json",
    )
    manifest = _campaign_manifest()
    coverage_task, request = _coverage_task(scope_id=manifest.shard_ids[0])
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
    checked_at = datetime.now(UTC).replace(microsecond=0)
    preview = client.preview_candidate_review_task_resources(
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=manifest,
        context_package=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        checked_at=checked_at,
    )
    monkeypatch.setattr(
        openrouter_module,
        "_candidate_review_request_token_plan_projection_sha256",
        lambda _plan: preview.request_token_plan_projection_sha256,
    )
    monkeypatch.setattr(
        openrouter_module,
        "_candidate_review_request_material_projection",
        lambda _body, *, request_token_plan: (
            preview.request_token_plan_projection_sha256,
            "x" * preview.request_material_projection_utf8_bytes,
            preview.request_material_projection_sha256,
        ),
    )
    monkeypatch.setattr(
        openrouter_module,
        "_endpoint_request_cost_bound_projection_sha256",
        lambda _bound, *, request_material_projection_sha256: (
            preview.endpoint_cost_bound_projection_sha256
        ),
    )
    changed_schema_name = schema_name[:-1] + "x"
    assert len(changed_schema_name) == len(schema_name)
    try:
        with pytest.raises(OpenRouterCandidateReviewBoundaryError, match="boundary changed"):
            await client.complete_candidate_review_with_evidence(
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=render_context(context),
                context_package=context,
                schema_name=changed_schema_name,
                logical_request_id=scheduler_task.logical_request_id,
                expected_resource_preview=preview,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                resource_preview_checked_at=checked_at,
            )
        assert calls == []
        assert usage.records == []
        assert client._claimed_request_ids == set()
        assert client.context_preflight.records == ()
    finally:
        await http_client.aclose()


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "mutation",
    (
        "canonical_sha256",
        "canonical_json_dumps",
        "copy_deepcopy_dispatch",
        "hashlib_sha256",
        "json_dumps",
        "json_encoder_encode",
        "json_encoder_iterencode",
    ),
)
@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_projection_transitive_mutation_blocks_before_transport(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    calls: list[httpx.Request] = []

    def reject_transport(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        pytest.fail("mutated projection dependency reached transport")

    client, http_client, usage, _budget = _preview_client(
        config_factory,
        reject_transport,
        ledger_path=tmp_path / f"preview-{mutation}-mutation-ledger.json",
    )
    manifest = _campaign_manifest()
    coverage_task, request = _coverage_task(scope_id=manifest.shard_ids[0])
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
    checked_at = datetime.now(UTC).replace(microsecond=0)
    preview = client.preview_candidate_review_task_resources(
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=manifest,
        context_package=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        checked_at=checked_at,
    )
    rendered_user_context = render_context(context)
    if mutation == "canonical_sha256":
        monkeypatch.setattr(openrouter_module, "_canonical_sha256", lambda _value: "0" * 64)
    elif mutation == "canonical_json_dumps":
        monkeypatch.setattr(
            openrouter_module,
            "_CANDIDATE_REVIEW_CANONICAL_JSON_DUMPS",
            lambda _value: "{}",
        )
    elif mutation == "copy_deepcopy_dispatch":
        dispatch = openrouter_module.copy._deepcopy_dispatch
        monkeypatch.setitem(dispatch, dict, lambda value, memo: value)
    elif mutation == "hashlib_sha256":
        monkeypatch.setattr(openrouter_module.hashlib, "sha256", lambda _value: object())
    elif mutation == "json_dumps":
        monkeypatch.setattr(openrouter_module.json, "dumps", lambda *_args, **_kwargs: "{}")
    elif mutation == "json_encoder_encode":
        monkeypatch.setattr(
            openrouter_module.json.JSONEncoder,
            "encode",
            lambda _self, _value: "{}",
        )
    elif mutation == "json_encoder_iterencode":
        monkeypatch.setattr(
            openrouter_module.json.JSONEncoder,
            "iterencode",
            lambda _self, _value, _one_shot=False: iter(("{}",)),
        )
    else:  # pragma: no cover - the closed parameter list makes this unreachable.
        raise AssertionError(mutation)
    try:
        with pytest.raises(OpenRouterCandidateReviewBoundaryError, match="boundary changed"):
            await client.complete_candidate_review_with_evidence(
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=rendered_user_context,
                context_package=context,
                schema_name=schema_name,
                logical_request_id=scheduler_task.logical_request_id,
                expected_resource_preview=preview,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                resource_preview_checked_at=checked_at,
            )
        assert calls == []
        assert usage.records == []
        assert client._claimed_request_ids == set()
        assert client.context_preflight.records == ()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_preview_rejects_request_limit_below_retry_attempts(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    client, http_client, _usage, _budget = _preview_client(
        config_factory,
        lambda _request: pytest.fail("resource preview attempted transport"),
        ledger_path=tmp_path / "preview-limit-cost-ledger.json",
        request_limit=1,
    )
    manifest = _synthetic_manifest("coverage-resource-preview")
    scope_id = "shard-000000000000000000000001"
    assert scope_id in manifest.shard_ids
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
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="retry attempts"):
            client.preview_candidate_review_task_resources(
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=datetime.now(UTC),
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_preview_rejects_valid_but_different_scheduler_task_key(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    client, http_client, _usage, _budget = _preview_client(
        config_factory,
        lambda _request: pytest.fail("resource preview attempted transport"),
        ledger_path=tmp_path / "preview-key-cost-ledger.json",
    )
    scope_id = "shard-000000000000000000000001"
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
        task_key="different-compact-task",
    )
    try:
        with pytest.raises(OpenRouterCandidateReviewBoundaryError, match="scheduler task"):
            client.preview_candidate_review_task_resources(
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=_campaign_manifest(),
                context_package=context,
                system_prompt=system_prompt,
                schema_name=schema_name,
                checked_at=datetime.now(UTC),
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_preview_rejects_every_scheduler_identity_or_protocol_mismatch(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    client, http_client, _usage, _budget = _preview_client(
        config_factory,
        lambda _request: pytest.fail("resource preview attempted transport"),
        ledger_path=tmp_path / "preview-join-cost-ledger.json",
    )
    coverage_task, request = _coverage_task(scope_id="shard-000000000000000000000001")
    context = _context(request)
    system_prompt = "Review only the supplied synthetic surface."
    schema_name = "mmaudit_source_audit_findings"
    mismatched_tasks = (
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            role="business_logic",
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            requested_model="beta/borealis-secure",
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            root_lineage="sha256:" + "f" * 64,
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            scope=SchedulerScope.single_shard("shard-000000000000000000000002"),
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            response_schema_sha256="f" * 64,
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            system_prompt_sha256="f" * 64,
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            prompt_sha256="0" * 64,
        ),
        _scheduler_task(
            client,
            coverage_task=coverage_task,
            context=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            candidate_ids=(request.surface_id,),
        ),
    )
    try:
        for scheduler_task in mismatched_tasks:
            with pytest.raises(OpenRouterCandidateReviewBoundaryError):
                client.preview_candidate_review_task_resources(
                    coverage_task=coverage_task,
                    scheduler_task=scheduler_task,
                    campaign_manifest=_campaign_manifest(),
                    context_package=context,
                    system_prompt=system_prompt,
                    schema_name=schema_name,
                    checked_at=datetime.now(UTC),
                )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_same_surface_context_drift_changes_preview_and_old_preview_blocks_transport(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[httpx.Request] = []

    def reject_transport(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        pytest.fail("stale preview reached transport")

    client, http_client, usage, budget = _preview_client(
        config_factory,
        reject_transport,
        ledger_path=tmp_path / "preview-context-drift-cost-ledger.json",
    )
    manifest = _campaign_manifest()
    coverage_task, request = _coverage_task(scope_id="shard-000000000000000000000001")
    context = _context(request)
    changed_map = context.repository_map.model_copy(
        update={"root_name": "synthetic-request-contexx"}
    )
    changed_context = context.model_copy(update={"repository_map": changed_map})
    changed_context = changed_context.model_copy(
        update={"bytes_used": len(render_context(changed_context).encode("utf-8"))}
    )
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
    checked_at = datetime.now(UTC).replace(microsecond=0)
    original_preview = client.preview_candidate_review_task_resources(
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=manifest,
        context_package=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        checked_at=checked_at,
    )
    changed_preview = client.preview_candidate_review_task_resources(
        coverage_task=coverage_task,
        scheduler_task=scheduler_task,
        campaign_manifest=manifest,
        context_package=changed_context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        checked_at=checked_at,
    )
    observer = _RejectingLifecycleObserver()
    client.bind_request_lifecycle_observer(observer)
    budget_before = (
        budget.spent_usd_exact,
        budget.reserved_usd,
        budget.spent_input_tokens,
        budget.reserved_input_tokens,
        budget.spent_output_tokens,
        budget.reserved_output_tokens,
    )
    try:
        assert changed_preview.preview_sha256 != original_preview.preview_sha256
        assert changed_preview.rendered_context_sha256 != original_preview.rendered_context_sha256
        assert (
            changed_preview.context_request_evidence_sha256
            != original_preview.context_request_evidence_sha256
        )
        assert (
            changed_preview.request_material_projection_sha256
            != original_preview.request_material_projection_sha256
        )
        assert (
            changed_preview.endpoint_cost_bound_projection_sha256
            != original_preview.endpoint_cost_bound_projection_sha256
        )
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="changed after aggregate preflight",
        ):
            await client.complete_candidate_review_with_evidence(
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=render_context(changed_context),
                context_package=changed_context,
                schema_name=schema_name,
                logical_request_id=scheduler_task.logical_request_id,
                expected_resource_preview=original_preview,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                resource_preview_checked_at=checked_at,
            )
        assert calls == []
        assert usage.records == []
        assert client._claimed_request_ids == set()
        assert client.context_preflight.records == ()
        assert observer.ready_calls == 0
        assert observer.dispatched_calls == 0
        assert (
            budget.spent_usd_exact,
            budget.reserved_usd,
            budget.spent_input_tokens,
            budget.reserved_input_tokens,
            budget.spent_output_tokens,
            budget.reserved_output_tokens,
        ) == budget_before
    finally:
        await http_client.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_pricing_drift_changes_preview_and_old_preview_blocks_transport(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    calls: list[httpx.Request] = []

    def reject_transport(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        pytest.fail("stale preview or pricing reached transport")

    original_client, original_http, _original_usage, _original_budget = _preview_client(
        config_factory,
        reject_transport,
        ledger_path=tmp_path / "preview-original-pricing-ledger.json",
    )
    changed_client, changed_http, changed_usage, changed_budget = _preview_client(
        config_factory,
        reject_transport,
        ledger_path=tmp_path / "preview-changed-pricing-ledger.json",
        pricing={
            "prompt": "0.000002",
            "completion": "0.00001",
            "request": "0",
        },
    )
    manifest = _campaign_manifest()
    coverage_task, request = _coverage_task(scope_id="shard-000000000000000000000001")
    context = _context(request)
    system_prompt = "Review only the supplied synthetic surface."
    schema_name = "mmaudit_source_audit_findings"
    scheduler_task = _scheduler_task(
        original_client,
        coverage_task=coverage_task,
        context=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
        campaign_manifest=manifest,
    )
    checked_at = datetime.now(UTC).replace(microsecond=0)
    try:
        original_preview = original_client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        changed_preview = changed_client.preview_candidate_review_task_resources(
            coverage_task=coverage_task,
            scheduler_task=scheduler_task,
            campaign_manifest=manifest,
            context_package=context,
            system_prompt=system_prompt,
            schema_name=schema_name,
            checked_at=checked_at,
        )
        budget_before = (
            changed_budget.spent_usd_exact,
            changed_budget.reserved_usd,
            changed_budget.spent_input_tokens,
            changed_budget.reserved_input_tokens,
            changed_budget.spent_output_tokens,
            changed_budget.reserved_output_tokens,
        )
        assert (
            changed_preview.endpoint_policy_pricing_sha256
            != original_preview.endpoint_policy_pricing_sha256
        )
        assert (
            changed_preview.endpoint_pricing_snapshot_sha256
            != original_preview.endpoint_pricing_snapshot_sha256
        )
        assert changed_preview.preview_sha256 != original_preview.preview_sha256
        with pytest.raises(
            OpenRouterCandidateReviewBoundaryError,
            match="changed after aggregate preflight",
        ):
            await changed_client.complete_candidate_review_with_evidence(
                role=_ROLE,
                models=[_MODEL],
                system_prompt=system_prompt,
                user_prompt=render_context(context),
                context_package=context,
                schema_name=schema_name,
                logical_request_id=scheduler_task.logical_request_id,
                expected_resource_preview=original_preview,
                coverage_task=coverage_task,
                scheduler_task=scheduler_task,
                campaign_manifest=manifest,
                resource_preview_checked_at=checked_at,
            )
        assert calls == []
        assert changed_usage.records == []
        assert changed_client._claimed_request_ids == set()
        assert changed_client.context_preflight.records == ()
        assert (
            changed_budget.spent_usd_exact,
            changed_budget.reserved_usd,
            changed_budget.spent_input_tokens,
            changed_budget.reserved_input_tokens,
            changed_budget.spent_output_tokens,
            changed_budget.reserved_output_tokens,
        ) == budget_before
    finally:
        await original_http.aclose()
        await changed_http.aclose()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_preview_rejects_context_role_or_surface_manifest_mismatch(
    config_factory: Callable[..., Any],
    tmp_path: Path,
) -> None:
    client, http_client, _usage, _budget = _preview_client(
        config_factory,
        lambda _request: pytest.fail("resource preview attempted transport"),
        ledger_path=tmp_path / "preview-context-cost-ledger.json",
    )
    coverage_task, request = _coverage_task(scope_id="shard-000000000000000000000001")
    context = _context(request)
    system_prompt = "Review only the supplied synthetic surface."
    schema_name = "mmaudit_source_audit_findings"
    scheduler_task = _scheduler_task(
        client,
        coverage_task=coverage_task,
        context=context,
        system_prompt=system_prompt,
        schema_name=schema_name,
    )
    wrong_role = context.model_copy(update={"role": "business_logic"})
    wrong_role = wrong_role.model_copy(
        update={"bytes_used": len(render_context(wrong_role).encode("utf-8"))}
    )
    missing_surface = context.model_copy(update={"requested_model_surfaces": ()})
    missing_surface = missing_surface.model_copy(
        update={"bytes_used": len(render_context(missing_surface).encode("utf-8"))}
    )
    try:
        for mismatched_context in (wrong_role, missing_surface):
            with pytest.raises(OpenRouterCandidateReviewBoundaryError, match="context"):
                client.preview_candidate_review_task_resources(
                    coverage_task=coverage_task,
                    scheduler_task=scheduler_task,
                    campaign_manifest=_campaign_manifest(),
                    context_package=mismatched_context,
                    system_prompt=system_prompt,
                    schema_name=schema_name,
                    checked_at=datetime.now(UTC),
                )
    finally:
        await http_client.aclose()
