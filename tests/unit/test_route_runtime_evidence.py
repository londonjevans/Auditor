from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel, ValidationError

import mmaudit.benchmark.models as benchmark_models_module
import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.route_runtime_evidence as route_runtime_evidence_module
from mmaudit.config import AuditConfig, ModelRetryPolicy
from mmaudit.models.authenticated_runner_smoke import (
    AuthenticatedRunnerSmokeEvidenceBundle,
    build_authenticated_runner_smoke_cost_plan,
    seal_authenticated_runner_smoke_evidence_bundle,
    seal_authenticated_runner_smoke_run_evidence,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.output_modes import StructuredOutputMode, supported_output_modes
from mmaudit.models.qualification import (
    CandidateModel,
    QualificationPolicy,
    seal_qualification_policy,
)
from mmaudit.models.route_admission import (
    AuthenticatedRunnerRouteArtifacts,
    require_authenticated_runner_three_route_admission,
)
from mmaudit.models.route_constraints import (
    ExactRouteRole,
    NormalizedRouteFacts,
    RouteConstraintError,
    RouteConstraintPurpose,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateReason,
    RoutePredicateReport,
    bind_registry_route_facts,
    bind_runtime_route_facts,
    evaluate_route_predicates,
    require_route_predicates,
    transition_full_campaign_runtime_predicates,
)
from mmaudit.models.route_runtime_evidence import (
    RouteRuntimeEvidenceArtifact,
    RouteRuntimeEvidenceError,
    VerifiedThreeRouteRuntimeEvidence,
    _runtime_freshness_reason_for_test,
    build_route_runtime_evidence_artifact,
    revalidate_route_runtime_evidence_bytes,
    route_runtime_evidence_bytes,
    runtime_predicate_transition_reasons,
    verify_route_runtime_evidence,
)
from mmaudit.models.schemas import StructuredOutputEvidence, UsageRecord
from mmaudit.models.token_planning import (
    RequestTokenPlan,
    request_token_plan_projection_sha256,
)
from mmaudit.models.usage import structurally_noncrediting_unknown_token_smoke_usage_error
from mmaudit.orchestration.manifest import canonical_sha256
from tests.identity_fixtures import bind_synthetic_usage_identity
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.unit import test_authenticated_runner_smoke_runtime as smoke_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures
from tests.unit.test_authenticated_runner_durable_bundle import _cost_preview_for_usage

type _RouteSubject = tuple[
    ExactRouteRole,
    CandidateModel,
    OpenRouterModelDiscoveryRunManifest,
    OpenRouterModelDiscoveryEvidence,
    NormalizedRouteFacts,
    RoutePredicateReport,
]
type _ThreeRouteArtifacts = tuple[
    AuthenticatedRunnerRouteArtifacts,
    AuthenticatedRunnerRouteArtifacts,
    AuthenticatedRunnerRouteArtifacts,
]


def _route_hash(label: str) -> str:
    value: str = canonical_sha256({"route-runtime-test": label})
    return value


def _route_bound_model(model: CandidateModel, role: ExactRouteRole) -> CandidateModel:
    payload = model.model_dump(mode="python")
    payload.update(
        {
            "selection_plan_sha256": _route_hash("selection-plan"),
            "route_predicate_profile_sha256": _route_hash(f"profile:{role.value}"),
            "exact_route_constraint_sha256": _route_hash(f"constraint:{role.value}"),
            "route_predicate_report_sha256": _route_hash(f"registry-report:{role.value}"),
        }
    )
    return CandidateModel.model_validate(payload, strict=True)


def _route_bound_smoke_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> AuthenticatedRunnerSmokeEvidenceBundle:
    source = smoke_fixtures._sealed_current_smoke_bundle(monkeypatch)
    runs = []
    for run in source.runs:
        judge_role = (
            ExactRouteRole.PRIMARY_JUDGE
            if run.run_kind.value == "PRIMARY"
            else ExactRouteRole.REPLAY_JUDGE
        )
        runs.append(
            seal_authenticated_runner_smoke_run_evidence(
                smoke_run_index=run.smoke_run_index,
                run_kind=run.run_kind,
                candidate=_route_bound_model(run.candidate, ExactRouteRole.CANDIDATE),
                judge=_route_bound_model(run.judge, judge_role),
                candidate_cost_plan=run.candidate_cost_plan,
                candidate_report=run.candidate_report,
                candidate_generation_refetch=run.candidate_generation_refetch,
                prepared_adjudication=run.prepared_adjudication,
                judge_cost_plan=run.judge_cost_plan,
                adjudication_report=run.adjudication_report,
                judge_generation_refetch=run.judge_generation_refetch,
            )
        )
    payload = source.model_dump(mode="python", exclude={"bundle_sha256", "runs"})
    return seal_authenticated_runner_smoke_evidence_bundle(
        **payload,
        runs=tuple(runs),
    )


def _native_route_usage(
    usage: UsageRecord,
    *,
    model: CandidateModel,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
    system_prompt: str,
    user_prompt: str,
    response_model: type[BaseModel],
    schema_name: str,
) -> UsageRecord:
    plan = openrouter_module._structured_output_request_plan(
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        schema_name=schema_name,
    )
    prompt_sha256 = openrouter_module.structured_output_prompt_sha256(
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=response_model,
        schema_name=schema_name,
    )
    assert usage.request_body_sha256 is not None
    assert usage.schema_sha256 is not None
    assert usage.response_sha256 is not None
    assert usage.validated_response_sha256 is not None
    assert model.output_capability_sha256 is not None
    payload = usage.model_dump(mode="python")
    payload.update(
        {
            "requested_model": model.exact_model_id,
            "returned_model": model.canonical_model_slug,
            "actual_model": model.canonical_model_slug,
            "provider": model.approved_provider_name,
            "configured_provider_endpoints": [model.approved_provider_endpoint],
            "actual_provider_endpoint": model.approved_provider_endpoint,
            "prompt_sha256": prompt_sha256,
            "reasoning_evidence": None,
            "reasoning_tokens": 0,
            "token_detail_accounting_evidence": None,
        }
    )
    routing = dict(payload["routing"])
    for field in smoke_fixtures._TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    provider_policy_sha256 = routing.get("provider_policy_sha256")
    assert isinstance(provider_policy_sha256, str)
    structured = synthetic_structured_output_routing(
        configured_provider_endpoints=(model.approved_provider_endpoint,),
        selected_provider_endpoint=model.approved_provider_endpoint,
        endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
        output_capability_sha256=model.output_capability_sha256,
        prompt_sha256=prompt_sha256,
        request_body_sha256=usage.request_body_sha256,
        provider_policy_sha256=provider_policy_sha256,
        schema_sha256=usage.schema_sha256,
        original_response_sha256=usage.response_sha256,
        validated_response_sha256=usage.validated_response_sha256,
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        request_shape_sha256=plan.request_shape_sha256,
        strict_protocol_sha256=plan.strict_protocol_sha256,
    )
    output_parameters = cast(list[str], structured["endpoint_structured_output_parameters"])
    routing.update(
        {
            "selected_model": model.canonical_model_slug,
            "canonical_model": model.canonical_model_slug,
            "selected_provider_endpoint": model.approved_provider_endpoint,
            "selected_provider_name": model.approved_provider_name,
            "discovery_manifest_sha256": manifest.manifest_sha256,
            "discovery_provenance_sha256": evidence.provenance.provenance_sha256,
            "discovery_evidence_sha256": evidence.discovery_evidence_sha256,
            "catalog_snapshot_sha256": evidence.provenance.catalog_snapshot_sha256,
            "catalog_identity_binding_sha256": evidence.catalog_identity_binding_sha256,
            "model_metadata_snapshot_sha256": evidence.model_metadata_snapshot_sha256,
            "endpoint_snapshot_sha256": evidence.endpoint_snapshot_sha256,
            "endpoint_pricing_sha256": evidence.pricing_snapshot_sha256,
            "output_capability_sha256": evidence.output_capability_sha256,
            "structured_output": structured,
            "structured_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA.value,
            "structured_output_request_shape_sha256": plan.request_shape_sha256,
            "structured_output_require_parameters": plan.require_parameters,
            "structured_output_required_provider_parameters": list(
                plan.required_provider_parameters
            ),
            "structured_output_reasoning_request_sha256": plan.reasoning_request_sha256,
            "structured_output_response_format": cast(dict[str, Any], plan.response_format)["type"],
            "structured_output_protocol_sha256": plan.strict_protocol_sha256,
            "structured_output_supported_modes": [
                mode.value for mode in supported_output_modes(output_parameters)
            ],
            "structured_output_capability_sha256": evidence.output_capability_sha256,
            "structured_output_request_body_sha256": usage.request_body_sha256,
            "structured_output_original_response_sha256": usage.response_sha256,
            "structured_output_validated_response_sha256": usage.validated_response_sha256,
            "repair_used": False,
            "repair_request": False,
        }
    )
    payload["routing"] = routing
    rebound = UsageRecord.model_validate(payload)
    reasoning_plan = (
        None if usage.reasoning_evidence is None else usage.reasoning_evidence.request_plan
    )
    return bind_synthetic_usage_identity(
        rebound,
        reasoning_plan=reasoning_plan,
        observed_reasoning_tokens=0 if reasoning_plan is not None else None,
    )


def _usage_bound_to_route(
    usage: UsageRecord,
    *,
    model: CandidateModel,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
) -> UsageRecord:
    assert model.output_capability_sha256 is not None
    structured = StructuredOutputEvidence.model_validate(usage.routing["structured_output"])
    structured_payload = structured.model_dump(mode="python", exclude={"evidence_sha256"})
    structured_payload.update(
        {
            "configured_provider_endpoints": (model.approved_provider_endpoint,),
            "selected_provider_endpoint": model.approved_provider_endpoint,
            "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
            "output_capability_sha256": model.output_capability_sha256,
        }
    )
    structured_hash_payload = structured.model_dump(
        mode="json",
        exclude={"evidence_sha256"},
    )
    structured_hash_payload.update(
        {
            "configured_provider_endpoints": [model.approved_provider_endpoint],
            "selected_provider_endpoint": model.approved_provider_endpoint,
            "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
            "output_capability_sha256": model.output_capability_sha256,
        }
    )
    structured = StructuredOutputEvidence.model_validate(
        {
            **structured_payload,
            "evidence_sha256": canonical_sha256(structured_hash_payload),
        },
        strict=True,
    )
    payload = usage.model_dump(mode="python")
    payload.update(
        {
            "requested_model": model.exact_model_id,
            "returned_model": model.canonical_model_slug,
            "actual_model": model.canonical_model_slug,
            "provider": model.approved_provider_name,
            "configured_provider_endpoints": [model.approved_provider_endpoint],
            "actual_provider_endpoint": model.approved_provider_endpoint,
            "reasoning_evidence": None,
            "reasoning_tokens": 0,
            "token_detail_accounting_evidence": None,
        }
    )
    routing = dict(payload["routing"])
    for field in smoke_fixtures._TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing.update(
        {
            "selected_model": model.canonical_model_slug,
            "canonical_model": model.canonical_model_slug,
            "selected_provider_endpoint": model.approved_provider_endpoint,
            "selected_provider_name": model.approved_provider_name,
            "discovery_manifest_sha256": manifest.manifest_sha256,
            "discovery_provenance_sha256": evidence.provenance.provenance_sha256,
            "discovery_evidence_sha256": evidence.discovery_evidence_sha256,
            "catalog_snapshot_sha256": evidence.provenance.catalog_snapshot_sha256,
            "model_metadata_snapshot_sha256": evidence.model_metadata_snapshot_sha256,
            "endpoint_snapshot_sha256": evidence.endpoint_snapshot_sha256,
            "endpoint_pricing_sha256": evidence.pricing_snapshot_sha256,
            "output_capability_sha256": evidence.output_capability_sha256,
            "structured_output": structured.model_dump(mode="json"),
            "structured_output_capability_sha256": evidence.output_capability_sha256,
        }
    )
    payload["routing"] = routing
    reasoning_plan = (
        None if usage.reasoning_evidence is None else usage.reasoning_evidence.request_plan
    )
    return bind_synthetic_usage_identity(
        UsageRecord.model_validate(payload),
        reasoning_plan=reasoning_plan,
        observed_reasoning_tokens=0 if reasoning_plan is not None else None,
    )


def _launch_bound_native_smoke_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    *,
    candidate_native: bool = True,
    observed_age: timedelta = timedelta(minutes=10),
) -> tuple[
    AuthenticatedRunnerSmokeEvidenceBundle,
    tuple[_RouteSubject, ...],
    _ThreeRouteArtifacts,
]:
    route_directory = tmp_path / "runtime-routes"
    route_directory.mkdir()
    launch = smoke_fixtures._launch(
        config=smoke_fixtures._smoke_config(config_factory),
        tmp_path=route_directory,
    )
    raw_routes = (
        (
            ExactRouteRole.CANDIDATE,
            launch.candidate_registry.candidates[0],
            launch.candidate_discovery_manifest,
            launch.candidate_discovery_evidence[0],
            launch.candidate_registry,
        ),
        (
            ExactRouteRole.PRIMARY_JUDGE,
            launch.run_plans[0].judge,
            launch.run_plans[0].judge_discovery_manifest,
            launch.run_plans[0].judge_discovery_evidence[0],
            launch.run_plans[0].judge_registry,
        ),
        (
            ExactRouteRole.REPLAY_JUDGE,
            launch.run_plans[1].judge,
            launch.run_plans[1].judge_discovery_manifest,
            launch.run_plans[1].judge_discovery_evidence[0],
            launch.run_plans[1].judge_registry,
        ),
    )
    route_by_model = {model.exact_model_id: item for item in raw_routes for model in (item[1],)}
    registry_by_model = {item[1].exact_model_id: item[4] for item in raw_routes}

    def selected_registry(model_ids: tuple[str, ...]) -> Any:
        assert len(model_ids) == 1
        return registry_by_model[model_ids[0]]

    def selected_judge(model_id: str) -> CandidateModel:
        return route_by_model[model_id][1]

    monkeypatch.setattr(smoke_fixtures, "_candidate_registry", selected_registry)
    monkeypatch.setattr(smoke_fixtures, "_judge", selected_judge)

    original_rebound_usage = smoke_fixtures._rebound_smoke_usage
    usage_index = 0
    fresh_base = datetime.now(UTC).replace(microsecond=0) - observed_age

    def fresh_rebound_usage(usage: UsageRecord, **kwargs: Any) -> UsageRecord:
        nonlocal usage_index
        rebound = original_rebound_usage(usage, **kwargs)
        started_at = fresh_base + timedelta(minutes=usage_index * 2)
        ended_at = started_at + timedelta(seconds=1)
        usage_index += 1
        payload = rebound.model_dump(mode="python")
        payload.update(
            {
                "timestamp": started_at,
                "started_at": started_at,
                "ended_at": ended_at,
                "latency_ms": 1_000,
            }
        )
        routing = dict(payload["routing"])
        routing.update(
            {
                "request_started_at": started_at.isoformat(),
                "request_ended_at": ended_at.isoformat(),
                "latency_ms": 1_000,
            }
        )
        payload["routing"] = routing
        fresh = UsageRecord.model_validate(payload)
        _role, model, manifest, evidence, _registry = route_by_model[fresh.requested_model]
        return _usage_bound_to_route(
            fresh,
            model=model,
            manifest=manifest,
            evidence=evidence,
        )

    monkeypatch.setattr(smoke_fixtures, "_rebound_smoke_usage", fresh_rebound_usage)

    original_rebound_generation = smoke_fixtures._rebound_generation

    def fresh_rebound_generation(
        generation: Any,
        *,
        usage: UsageRecord,
    ) -> Any:
        rebound = original_rebound_generation(generation, usage=usage)
        assert usage.actual_model is not None
        assert usage.started_at is not None
        assert usage.ended_at is not None
        provider_name = usage.routing.get("selected_provider_name")
        assert isinstance(provider_name, str)
        payload = rebound.model_dump(mode="json", exclude={"evidence_sha256"})
        payload.update(
            {
                "exact_model_id": usage.actual_model,
                "provider_name": provider_name,
                "created_at": usage.started_at.isoformat().replace("+00:00", "Z"),
                "retrieved_at": (usage.ended_at + timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
        return type(rebound).model_validate(
            {**payload, "evidence_sha256": canonical_sha256(payload)}
        )

    monkeypatch.setattr(smoke_fixtures, "_rebound_generation", fresh_rebound_generation)

    original_candidate_report = smoke_fixtures._current_candidate_smoke_report

    def native_candidate_report(
        suite: Any,
        *,
        run_kind: Any,
        index: int,
        retry_policy: ModelRetryPolicy | None = None,
    ) -> tuple[Any, OpenRouterStructuredRequestCostPreview]:
        report, original_preview = original_candidate_report(
            suite,
            run_kind=run_kind,
            index=index,
            retry_policy=retry_policy,
        )
        if not candidate_native:
            return report, original_preview
        smoke = load_authenticated_runner_smoke_corpus_bundle(smoke_fixtures.SMOKE_CORPUS_PATH)
        usage = report.result.usage_record
        assert usage is not None
        descriptor = (
            benchmark_models_module.authenticated_runner_smoke_model_benchmark_request_descriptor(
                smoke_run_index=1,
                run_kind=run_kind.value,
                selection_sha256=smoke.bundle_sha256,
                case=smoke.case,
                target=report.target,
            )
        )
        _role, model, manifest, evidence, _registry = route_by_model[usage.requested_model]
        usage = _native_route_usage(
            usage,
            model=model,
            manifest=manifest,
            evidence=evidence,
            system_prompt=descriptor.system_prompt,
            user_prompt=descriptor.user_prompt,
            response_model=descriptor.response_model,
            schema_name=descriptor.schema_name,
        )
        usage, preview = smoke_fixtures._current_smoke_usage_and_preview(
            usage,
            index=index,
            user_prompt_sha256=hashlib.sha256(descriptor.user_prompt.encode("utf-8")).hexdigest(),
        )
        generation = report.result.generation_evidence
        assert generation is not None
        generation = fresh_rebound_generation(generation, usage=usage)
        result_payload = report.result.model_dump(mode="json")
        result_payload.update(
            {
                "usage_record": usage.model_dump(mode="json"),
                "generation_evidence": generation.model_dump(mode="json"),
            }
        )
        result = benchmark_models_module.ModelBenchmarkCaseResult.model_validate(result_payload)
        report_payload = report.model_dump(mode="json", exclude={"report_sha256"})
        report_payload["result"] = result.model_dump(mode="json")
        return (
            type(report).model_validate(
                {
                    **report_payload,
                    "report_sha256": canonical_sha256(report_payload),
                }
            ),
            preview,
        )

    monkeypatch.setattr(
        smoke_fixtures,
        "_current_candidate_smoke_report",
        native_candidate_report,
    )

    original_cost_preview = _cost_preview_for_usage

    def route_cost_preview(
        usage: UsageRecord,
        *,
        index: int,
        drift: str | None = None,
    ) -> OpenRouterStructuredRequestCostPreview:
        preview = original_cost_preview(usage, index=index, drift=drift)
        _role, _model, manifest, _evidence, _registry = route_by_model[usage.requested_model]
        payload = preview.model_dump(mode="python", exclude={"preview_sha256"})
        payload["discovery_manifest_sha256"] = manifest.manifest_sha256
        hash_payload = preview.model_dump(mode="json", exclude={"preview_sha256"})
        hash_payload["discovery_manifest_sha256"] = manifest.manifest_sha256
        return OpenRouterStructuredRequestCostPreview.model_validate(
            {**payload, "preview_sha256": canonical_sha256(hash_payload)},
            strict=True,
        )

    monkeypatch.setattr(smoke_fixtures, "_cost_preview_for_usage", route_cost_preview)
    bundle = smoke_fixtures._sealed_current_smoke_bundle(monkeypatch)
    subjects: list[_RouteSubject] = []
    for role, model, manifest, evidence, _registry in raw_routes:
        snapshot = evidence.endpoint_snapshot
        profile = snapshot.route_predicate_profile
        constraint = snapshot.exact_route_constraint
        discovery_facts = snapshot.normalized_route_facts
        assert profile is not None
        assert constraint is not None
        assert discovery_facts is not None
        assert model.selection_plan_sha256 is not None
        registry_facts = bind_registry_route_facts(
            discovery_facts,
            registry_selection_plan_sha256=model.selection_plan_sha256,
            profile=profile,
            constraint=constraint,
        )
        registry_report = evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=registry_facts,
        )
        assert registry_report.report_sha256 == model.route_predicate_report_sha256
        facts = bind_runtime_route_facts(
            registry_facts,
            required_output_tokens=profile.required_output_tokens,
        )
        report = evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=facts,
        )
        subjects.append((role, model, manifest, evidence, facts, report))
    route_artifacts = cast(
        _ThreeRouteArtifacts,
        tuple(
            (registry, manifest, (evidence,))
            for _role, _model, manifest, evidence, registry in raw_routes
        ),
    )
    return bundle, tuple(subjects), route_artifacts


def _policy(*, maximum_age_days: int = 7) -> QualificationPolicy:
    policy_factory = cast(Callable[[], QualificationPolicy], qualification_fixtures._policy)
    source = policy_factory()
    return seal_qualification_policy(
        created_at=source.created_at,
        thresholds=source.thresholds,
        tier_a_minimum_overall_score=source.tier_a_minimum_overall_score,
        maximum_validity_days=source.maximum_validity_days,
        maximum_benchmark_evidence_age_days=maximum_age_days,
    )


def _artifact(
    monkeypatch: pytest.MonkeyPatch,
    *,
    maximum_age_days: int = 7,
) -> tuple[RouteRuntimeEvidenceArtifact, QualificationPolicy]:
    policy = _policy(maximum_age_days=maximum_age_days)
    return (
        build_route_runtime_evidence_artifact(
            smoke_bundle=_route_bound_smoke_bundle(monkeypatch),
            qualification_policy=policy,
        ),
        policy,
    )


def test_runtime_artifact_derives_ordered_independent_proofs_and_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, policy = _artifact(monkeypatch)

    assert tuple(item.role for item in artifact.observations) == (
        ExactRouteRole.CANDIDATE,
        ExactRouteRole.PRIMARY_JUDGE,
        ExactRouteRole.REPLAY_JUDGE,
    )
    assert tuple(len(item.request_ids) for item in artifact.observations) == (2, 1, 1)
    assert all(not item.empirical_schema_conformance_proven for item in artifact.observations)
    assert all(item.token_detail_reporting_convention_proven for item in artifact.observations)
    assert artifact.qualification_policy_sha256 == policy.policy_sha256
    assert artifact.maximum_benchmark_evidence_age_days == 7
    assert artifact.source_bundle_sha256 == artifact.source_bundle.bundle_sha256
    assert all(
        value is False
        for name, value in artifact.model_dump(mode="python").items()
        if name.endswith("_authorized")
        or name
        in {
            "full_corpus_execution_completed",
            "grants_review_credit",
            "grants_completion_credit",
        }
    )

    raw = route_runtime_evidence_bytes(artifact)
    assert revalidate_route_runtime_evidence_bytes(raw) == artifact
    assert route_runtime_evidence_bytes(revalidate_route_runtime_evidence_bytes(raw)) == raw

    run = artifact.source_bundle.runs[0]
    usage = run.candidate_report.result.usage_record
    assert usage is not None
    token_plan = RequestTokenPlan.model_validate_json(
        json.dumps(
            usage.routing["request_token_plan"],
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    legacy_projection_payload = token_plan.model_dump(
        mode="json",
        exclude={"global_budget", "plan_sha256"},
    )
    legacy_projection_payload["global_budget"] = {
        "schema_version": token_plan.global_budget.schema_version,
        "global_input_token_budget": token_plan.global_budget.global_input_token_budget,
        "global_output_token_budget": token_plan.global_budget.global_output_token_budget,
        "request_input_tokens": token_plan.global_budget.request_input_tokens,
        "request_output_tokens": token_plan.global_budget.request_output_tokens,
    }
    legacy_projection = hashlib.sha256(
        json.dumps(
            {
                "domain": "mmaudit.openrouter.candidate-review-token-plan-projection.v1",
                "request_token_plan": legacy_projection_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    preview = run.candidate_cost_plan.request_preview
    assert preview.request_token_plan_projection_sha256 == (
        request_token_plan_projection_sha256(token_plan)
    )
    assert preview.request_token_plan_projection_sha256 == legacy_projection
    assert preview.request_token_plan_projection_sha256 != token_plan.plan_sha256
    valid_item = route_runtime_evidence_module._RuntimeSourceItem(
        run=run,
        model=run.candidate,
        plan=run.candidate_cost_plan,
        usage=usage,
        proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
    )
    assert route_runtime_evidence_module._token_detail_proof_is_valid(valid_item)

    preview_payload = preview.model_dump(mode="json", exclude={"preview_sha256"})
    preview_payload["request_token_plan_projection_sha256"] = token_plan.plan_sha256
    wrong_projection_preview = type(preview).model_validate_json(
        json.dumps(
            {
                **preview_payload,
                "preview_sha256": canonical_sha256(preview_payload),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        strict=True,
    )
    wrong_projection_plan = build_authenticated_runner_smoke_cost_plan(
        smoke_run_index=run.candidate_cost_plan.smoke_run_index,
        run_kind=run.candidate_cost_plan.run_kind,
        stage=run.candidate_cost_plan.stage,
        case_id=run.candidate_cost_plan.case_id,
        selection_sha256=run.candidate_cost_plan.selection_sha256,
        request_preview=wrong_projection_preview,
    )
    wrong_projection_item = route_runtime_evidence_module._RuntimeSourceItem(
        run=run,
        model=run.candidate,
        plan=wrong_projection_plan,
        usage=usage,
        proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
    )
    assert not route_runtime_evidence_module._token_detail_proof_is_valid(wrong_projection_item)


def test_route_runtime_source_rejects_noncanonical_smoke_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _route_bound_smoke_bundle(monkeypatch)
    run = bundle.runs[0]
    usage = run.candidate_report.result.usage_record
    assert usage is not None
    payload = usage.model_dump(mode="python")
    routing = dict(payload["routing"])
    routing["data_collection"] = "allow"
    payload["routing"] = routing
    invalid_origin = UsageRecord.model_validate(payload)
    item = route_runtime_evidence_module._RuntimeSourceItem(
        run=run,
        model=run.candidate,
        plan=run.candidate_cost_plan,
        usage=invalid_origin,
        proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
    )

    assert (
        structurally_noncrediting_unknown_token_smoke_usage_error(invalid_origin)
        == "UsageEnvelopeError"
    )
    with pytest.raises(ValueError, match="not a route-bound REAL success"):
        route_runtime_evidence_module._validate_source_item(item)


def test_verified_native_runtime_evidence_satisfies_both_predicates_for_all_roles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle, subjects, route_artifacts = _launch_bound_native_smoke_bundle(
        monkeypatch,
        tmp_path,
        config_factory,
    )
    policy = _policy(maximum_age_days=30)
    artifact = build_route_runtime_evidence_artifact(
        smoke_bundle=bundle,
        qualification_policy=policy,
    )
    capability = verify_route_runtime_evidence(artifact, policy)

    assert all(item.empirical_schema_conformance_proven for item in artifact.observations)
    assert all(item.token_detail_reporting_convention_proven for item in artifact.observations)
    for role, model, manifest, evidence, facts, report in subjects:
        assert runtime_predicate_transition_reasons(
            capability,
            role=role,
            model=model,
            manifest=manifest,
            evidence=evidence,
            facts=facts,
            report=report,
            qualification_policy=policy,
        ) == (None, None)
        transitioned = transition_full_campaign_runtime_predicates(
            report,
            runtime_evidence=capability,
            qualification_policy=policy,
            role=role,
            model=model,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            facts=facts,
        )
        require_route_predicates(
            transitioned,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        )
        by_id = {item.predicate_id: item for item in transitioned.results}
        assert by_id[RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE].disposition is (
            RoutePredicateDisposition.SATISFIED
        )
        assert by_id[RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION].disposition is (
            RoutePredicateDisposition.SATISFIED
        )

    required_output_tokens = subjects[0][4].runtime_required_output_tokens
    assert required_output_tokens is not None
    assert all(
        subject[4].runtime_required_output_tokens == required_output_tokens for subject in subjects
    )
    admitted = require_authenticated_runner_three_route_admission(
        candidate=route_artifacts[0],
        primary_judge=route_artifacts[1],
        replay_judge=route_artifacts[2],
        purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        runtime_evidence=capability,
        qualification_policy=policy,
        runtime_required_output_tokens=required_output_tokens,
    )
    assert len(admitted) == 3
    for report in admitted:
        require_route_predicates(
            report,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        )


def test_non_native_source_invalidates_schema_proof_not_token_convention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle, subjects, _route_artifacts = _launch_bound_native_smoke_bundle(
        monkeypatch,
        tmp_path,
        config_factory,
        candidate_native=False,
    )
    policy = _policy(maximum_age_days=30)
    artifact = build_route_runtime_evidence_artifact(
        smoke_bundle=bundle,
        qualification_policy=policy,
    )
    capability = verify_route_runtime_evidence(artifact, policy)
    role, model, manifest, evidence, facts, report = subjects[0]

    assert artifact.observations[0].empirical_schema_conformance_proven is False
    assert artifact.observations[0].token_detail_reporting_convention_proven is True
    assert runtime_predicate_transition_reasons(
        capability,
        role=role,
        model=model,
        manifest=manifest,
        evidence=evidence,
        facts=facts,
        report=report,
        qualification_policy=policy,
    ) == (RoutePredicateReason.RUNTIME_EVIDENCE_INVALID, None)


def test_consumer_rejects_stale_evidence_at_exact_policy_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle, subjects, _route_artifacts = _launch_bound_native_smoke_bundle(
        monkeypatch,
        tmp_path,
        config_factory,
        observed_age=timedelta(days=30),
    )
    policy = _policy(maximum_age_days=30)
    artifact = build_route_runtime_evidence_artifact(
        smoke_bundle=bundle,
        qualification_policy=policy,
    )
    capability = verify_route_runtime_evidence(artifact, policy)
    role, model, manifest, evidence, facts, report = subjects[0]

    assert runtime_predicate_transition_reasons(
        capability,
        role=role,
        model=model,
        manifest=manifest,
        evidence=evidence,
        facts=facts,
        report=report,
        qualification_policy=policy,
    ) == (
        RoutePredicateReason.RUNTIME_EVIDENCE_STALE,
        RoutePredicateReason.RUNTIME_EVIDENCE_STALE,
    )


def test_consumer_rejects_every_current_binding_axis_and_policy_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle, subjects, _route_artifacts = _launch_bound_native_smoke_bundle(
        monkeypatch,
        tmp_path,
        config_factory,
    )
    policy = _policy(maximum_age_days=30)
    artifact = build_route_runtime_evidence_artifact(
        smoke_bundle=bundle,
        qualification_policy=policy,
    )
    capability = verify_route_runtime_evidence(artifact, policy)
    role, model, manifest, evidence, facts, report = subjects[0]
    alternate = subjects[1]
    model_payload = model.model_dump(mode="python")

    def drifted_model(**updates: object) -> CandidateModel:
        return CandidateModel.model_validate(
            {**model_payload, **updates},
            strict=True,
        )

    mismatches: tuple[tuple[str, dict[str, object]], ...] = (
        ("role", {"role": ExactRouteRole.PRIMARY_JUDGE}),
        ("model", {"model": alternate[1]}),
        (
            "provider-endpoint",
            {"model": drifted_model(approved_provider_endpoint="other-provider/fp8")},
        ),
        ("selection-plan", {"model": drifted_model(selection_plan_sha256="9" * 64)}),
        (
            "predicate-profile",
            {"model": drifted_model(route_predicate_profile_sha256="a" * 64)},
        ),
        (
            "route-constraint",
            {"model": drifted_model(exact_route_constraint_sha256="b" * 64)},
        ),
        (
            "registry-report",
            {"model": drifted_model(route_predicate_report_sha256="c" * 64)},
        ),
        (
            "endpoint-snapshot",
            {"model": drifted_model(endpoint_snapshot_sha256="d" * 64)},
        ),
        (
            "output-capability",
            {"model": drifted_model(output_capability_sha256="e" * 64)},
        ),
        (
            "discovery-evidence",
            {"model": drifted_model(discovery_evidence_sha256="f" * 64)},
        ),
        ("discovery-provenance-manifest", {"manifest": alternate[2]}),
        ("discovery-provenance-evidence", {"evidence": alternate[3]}),
        ("normalized-facts", {"facts": alternate[4]}),
        ("predicate-report", {"report": alternate[5]}),
    )
    baseline: dict[str, object] = {
        "role": role,
        "model": model,
        "manifest": manifest,
        "evidence": evidence,
        "facts": facts,
        "report": report,
        "qualification_policy": policy,
    }
    for axis, mismatch in mismatches:
        assert runtime_predicate_transition_reasons(
            capability,
            **cast(Any, {**baseline, **mismatch}),
        ) == (
            RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH,
            RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH,
        ), axis

    assert runtime_predicate_transition_reasons(
        capability,
        role=role,
        model=model,
        manifest=manifest,
        evidence=evidence,
        facts=facts,
        report=report,
        qualification_policy=_policy(maximum_age_days=29),
    ) == (
        RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
        RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
    )

    monkeypatch.setattr(
        route_runtime_evidence_module,
        "runtime_predicate_transition_reasons",
        lambda *_args, **_kwargs: (None, None),
    )
    with pytest.raises(
        RouteConstraintError,
        match=r"(?:consumer authority|callable boundary) changed",
    ):
        transition_full_campaign_runtime_predicates(
            report,
            runtime_evidence=capability,
            qualification_policy=policy,
            role=role,
            model=model,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            facts=facts,
        )


def test_runtime_artifact_rejects_tamper_and_coherent_projection_reseal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, _policy_value = _artifact(monkeypatch)
    raw = route_runtime_evidence_bytes(artifact)
    tampered = raw.replace(
        artifact.qualification_policy_sha256.encode(),
        ("f" * 64).encode(),
        1,
    )

    with pytest.raises(RouteRuntimeEvidenceError, match="do not validate"):
        revalidate_route_runtime_evidence_bytes(tampered)

    hash_payload = artifact.model_dump(mode="json", exclude={"artifact_sha256"})
    observation_payloads = cast(list[dict[str, Any]], hash_payload["observations"])
    observation_payloads[0]["empirical_schema_conformance_proven"] = True
    observation_payloads[0]["observation_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in observation_payloads[0].items()
            if key != "observation_sha256"
        }
    )
    mutated_observation = artifact.observations[0].model_validate_json(
        json.dumps(observation_payloads[0], sort_keys=True, separators=(",", ":"))
    )
    payload = artifact.model_dump(mode="python", exclude={"artifact_sha256"})
    payload["observations"] = (mutated_observation, *artifact.observations[1:])
    payload["artifact_sha256"] = canonical_sha256(hash_payload)
    with pytest.raises(ValidationError, match="differ from their durable source"):
        RouteRuntimeEvidenceArtifact.model_validate(payload, strict=True)


def test_runtime_capability_is_opaque_and_policy_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, policy = _artifact(monkeypatch)
    capability = verify_route_runtime_evidence(artifact, policy)

    assert type(capability) is VerifiedThreeRouteRuntimeEvidence
    with pytest.raises(TypeError, match="cannot be constructed directly"):
        VerifiedThreeRouteRuntimeEvidence()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    with pytest.raises(RouteRuntimeEvidenceError, match="differs from the qualification policy"):
        verify_route_runtime_evidence(artifact, _policy(maximum_age_days=8))


def test_runtime_freshness_boundary_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, policy = _artifact(monkeypatch)
    observation = artifact.observations[0]
    boundary = observation.observed_from + timedelta(
        days=policy.maximum_benchmark_evidence_age_days
    )

    assert (
        _runtime_freshness_reason_for_test(
            observation,
            policy,
            now=boundary - timedelta(microseconds=1),
        )
        is None
    )
    assert (
        _runtime_freshness_reason_for_test(
            observation,
            policy,
            now=boundary,
        )
        is RoutePredicateReason.RUNTIME_EVIDENCE_STALE
    )
    with pytest.raises(RouteRuntimeEvidenceError, match="test time"):
        _runtime_freshness_reason_for_test(
            observation,
            policy,
            now=boundary.replace(tzinfo=None),
        )


def test_absent_or_fork_inherited_capability_maps_to_both_invalid_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, policy = _artifact(monkeypatch)
    capability = verify_route_runtime_evidence(artifact, policy)
    forged = object.__new__(VerifiedThreeRouteRuntimeEvidence)
    expected = (
        RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
        RoutePredicateReason.RUNTIME_EVIDENCE_INVALID,
    )

    assert (
        runtime_predicate_transition_reasons(
            forged,
            role=ExactRouteRole.CANDIDATE,
            model=cast(Any, object()),
            manifest=cast(Any, object()),
            evidence=cast(Any, object()),
            facts=cast(Any, object()),
            report=cast(Any, object()),
            qualification_policy=policy,
        )
        == expected
    )

    if not hasattr(os, "fork"):
        pytest.skip("fork inheritance test requires os.fork")
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            os.close(read_fd)
            result = runtime_predicate_transition_reasons(
                capability,
                role=ExactRouteRole.CANDIDATE,
                model=cast(Any, object()),
                manifest=cast(Any, object()),
                evidence=cast(Any, object()),
                facts=cast(Any, object()),
                report=cast(Any, object()),
                qualification_policy=policy,
            )
            os.write(write_fd, b"invalid" if result == expected else b"accepted")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    observed = os.read(read_fd, 32)
    os.close(read_fd)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.waitstatus_to_exitcode(status) == 0
    assert observed == b"invalid"
