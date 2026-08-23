from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import repeat
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import mmaudit.benchmark.cross_lineage_adjudication as adjudication_module
import mmaudit.models.openrouter as openrouter_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
    CrossLineageAdjudicationCaseRequest,
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationError,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationResponse,
    CrossLineageAdjudicationRunKind,
    CrossLineageAdjudicationWireResponse,
    adjudication_generation_verification_requests,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_prompt,
    build_cross_lineage_adjudication_report,
    build_cross_lineage_adjudication_response,
    cross_lineage_adjudication_response_schema_sha256,
    cross_lineage_adjudication_source_sha256,
    cross_lineage_adjudication_system_prompt,
    cross_lineage_adjudication_validated_response_sha256,
    execute_cross_lineage_adjudication_requests,
    prepare_cross_lineage_adjudication,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    load_model_benchmark_corpus,
)
from mmaudit.config import PrivacyConfig
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    validate_openrouter_generation_payload,
)
from mmaudit.models.identity import OpenRouterModelEndpointIdentitySnapshot
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    StructuredCompletion,
    strict_json_schema,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.public_lineage_authority import (
    PublicModelLineageAuthorityError,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import CandidateModel
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import UsageLedger, is_creditable_usage_record
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceObservation,
    prove_release_pinned_cross_lineage_adjudication_source,
    validate_provider_visible_source_request,
)
from tests.identity_fixtures import bind_synthetic_usage_identity
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.unit.test_model_benchmark_portfolio import (
    _as_structural_real,
    _candidate_registry,
    _report,
)

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
CANDIDATE_ID = "deepseek/deepseek-v3.2-exp"
JUDGE_ID = "google/gemma-4-26b-a4b-it"
SAME_ROOT_JUDGE_ID = "deepcogito/cogito-v2.1-671b"
_SYNTHETIC_COMPLETION_GENERATIONS: dict[str, OpenRouterGenerationEvidence] = {}


@dataclass(frozen=True, slots=True)
class _Inputs:
    suite: ModelBenchmarkSuite
    candidate_report: ModelBenchmarkReport
    judge: CandidateModel


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def inputs() -> _Inputs:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    candidate_report = _as_structural_real(_report(suite, CANDIDATE_ID))
    base_judge = _candidate_registry((JUDGE_ID,)).candidates[0]
    judge_payload = base_judge.model_dump(mode="json")
    judge_payload.update(
        {
            "approved_provider_endpoint": "provider-judge",
            "approved_provider_name": "Synthetic Judge",
            "discovery_evidence_sha256": "5" * 64,
        }
    )
    return _Inputs(
        suite=suite,
        candidate_report=candidate_report,
        judge=CandidateModel.model_validate(judge_payload),
    )


def _prepare(
    inputs: _Inputs,
    *,
    run_kind: CrossLineageAdjudicationRunKind = CrossLineageAdjudicationRunKind.PRIMARY,
    report: ModelBenchmarkReport | None = None,
    judge: CandidateModel | None = None,
) -> CrossLineageAdjudicationPreparedRun:
    return prepare_cross_lineage_adjudication(
        public_lineage_capability=resolve_verified_public_model_lineage(),
        suite=inputs.suite,
        candidate_report=report or inputs.candidate_report,
        judge=judge or inputs.judge,
        run_kind=run_kind,
    )


def _judge_usage_and_generation(
    *,
    case_index: int,
    request: CrossLineageAdjudicationCaseRequest,
    response: CrossLineageAdjudicationResponse,
    judge: CandidateModel,
) -> tuple[UsageRecord, OpenRouterGenerationEvidence]:
    started_at = NOW + timedelta(seconds=case_index * 2)
    ended_at = started_at + timedelta(milliseconds=125)
    generation_id = f"judge-generation-{case_index}"
    request_id = f"cross-lineage-{request.request_sha256}"
    endpoint = judge.approved_provider_endpoint
    provider_name = judge.approved_provider_name
    schema_sha256 = cross_lineage_adjudication_response_schema_sha256()
    response_sha256 = cross_lineage_adjudication_validated_response_sha256(response)
    output_mode = judge.structured_output_mode
    output_plan = openrouter_module._structured_output_request_plan(
        mode=output_mode,
        system_prompt=cross_lineage_adjudication_system_prompt(),
        user_prompt=request.provider_visible_user_prompt,
        response_model=CrossLineageAdjudicationWireResponse,
        schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
    )
    prompt_sha256 = openrouter_module.structured_output_prompt_sha256(
        mode=output_mode,
        system_prompt=cross_lineage_adjudication_system_prompt(),
        user_prompt=request.provider_visible_user_prompt,
        response_model=CrossLineageAdjudicationWireResponse,
        schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
    )
    assert output_plan.response_format is not None
    request_body_sha256 = canonical_sha256(
        {
            "model": judge.exact_model_id,
            "provider_endpoint": endpoint,
            "prompt_sha256": prompt_sha256,
            "response_schema_sha256": schema_sha256,
            "case_id": request.case_id,
            "request_index": case_index,
        }
    )
    endpoint_snapshot_sha256 = judge.endpoint_snapshot_sha256
    provider_policy_sha256 = "f" * 64
    routing: dict[str, object] = {
        "generation_id": generation_id,
        "selected_model": judge.canonical_model_slug,
        "canonical_model": judge.canonical_model_slug,
        "selected_provider_endpoint": endpoint,
        "selected_provider_name": provider_name,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "finish_reason": "stop",
        "native_finish_reason": None,
        "schema_sha256": schema_sha256,
        "router_metadata_sha256": "e" * 64,
        "provider_policy_sha256": provider_policy_sha256,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "endpoint_pricing_sha256": judge.pricing_snapshot_sha256,
        "catalog_snapshot_sha256": "3" * 64,
        "model_metadata_snapshot_sha256": judge.model_metadata_snapshot_sha256,
        "discovery_provenance_sha256": "6" * 64,
        "discovery_evidence_sha256": judge.discovery_evidence_sha256,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": judge.canonical_model_slug,
                "id": judge.exact_model_id,
            }
        ),
        "output_capability_sha256": judge.output_capability_sha256,
        "provider_fallbacks_allowed": False,
        "certification_request": True,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "structured_output_mode": output_mode.value,
        "structured_output_capability_sha256": judge.output_capability_sha256,
        "structured_output_request_shape_sha256": output_plan.request_shape_sha256,
        "structured_output_require_parameters": output_plan.require_parameters,
        "structured_output_required_provider_parameters": list(
            output_plan.required_provider_parameters
        ),
        "structured_output_reasoning_request_sha256": output_plan.reasoning_request_sha256,
        "structured_output_response_format": output_plan.response_format["type"],
        "structured_output_protocol_sha256": output_plan.strict_protocol_sha256,
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=(endpoint,),
            selected_provider_endpoint=endpoint,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            output_capability_sha256=judge.output_capability_sha256,
            prompt_sha256=prompt_sha256,
            request_body_sha256=request_body_sha256,
            provider_policy_sha256=provider_policy_sha256,
            schema_sha256=schema_sha256,
            original_response_sha256=response_sha256,
            validated_response_sha256=response_sha256,
            mode=output_mode,
            request_shape_sha256=output_plan.request_shape_sha256,
            strict_protocol_sha256=output_plan.strict_protocol_sha256,
        ),
        "request_started_at": started_at.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": 125,
        "privacy_profile": "SYNTHETIC_BENCHMARK",
        "privacy_authorization": "STRICT_ZDR_ENFORCED",
        "effective_privacy_policy_sha256": "8" * 64,
        "privacy_source_sha256": adjudication_module.cross_lineage_adjudication_source_sha256(
            request
        ),
        "privacy_source_provenance_sha256": "9" * 64,
        "privacy_source_classification": "SYNTHETIC_COMMITTED",
        "privacy_source_proof_kind": "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
        "privacy_endpoint_policy_class": "ZDR",
    }
    record = UsageRecord(
        request_id=request_id,
        role="model_benchmark",
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=judge.exact_model_id,
        returned_model=judge.canonical_model_slug,
        actual_model=judge.canonical_model_slug,
        provider=provider_name,
        model_family=judge.exact_model_id,
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=25,
        total_tokens=125,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing=routing,
        prompt_sha256=prompt_sha256,
        user_prompt_sha256=request.user_prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=response_sha256,
        request_body_sha256=request_body_sha256,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=125,
        finish_reason="stop",
        reasoning_tokens=0,
        cached_tokens=0,
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )
    bound = bind_synthetic_usage_identity(record)
    evidence = validate_openrouter_generation_payload(
        {
            "data": {
                "id": generation_id,
                "model": judge.canonical_model_slug,
                "provider_name": provider_name,
                "finish_reason": "stop",
                "native_finish_reason": None,
                "tokens_prompt": bound.prompt_tokens,
                "tokens_completion": bound.completion_tokens,
                "native_tokens_prompt": bound.prompt_tokens,
                "native_tokens_completion": bound.completion_tokens,
                "native_tokens_reasoning": 0,
                "native_tokens_cached": 0,
                "total_cost": "0.01",
                "usage": "0.01",
                "cancelled": False,
                "created_at": started_at,
                "request_id": request_id,
                "latency": "125",
                "generation_time": None,
            }
        },
        requested_generation_id=generation_id,
        retrieved_at=ended_at + timedelta(seconds=1),
        execution_evidence=ExecutionEvidenceKind.REAL,
    )
    return bound, evidence


class _SyntheticCrossLineageClient:
    def __init__(
        self,
        *,
        prepared: CrossLineageAdjudicationPreparedRun,
        judge: CandidateModel,
        observation: PrivacySourceProvenanceObservation,
        effective_privacy_policy: Any,
        return_unbound_usage: bool = False,
    ) -> None:
        self.prepared = prepared
        self.judge = judge
        self.observation = observation
        self.return_unbound_usage = return_unbound_usage
        self.provider_policy = OpenRouterProviderPolicy(
            certification=True,
            only=(prepared.target.judge_provider_endpoint,),
            allow_fallbacks=False,
        )
        self.privacy = PrivacyConfig(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=True,
            maximum_model_retention="zero",
        )
        self.effective_privacy_policy = effective_privacy_policy
        self.usage = UsageLedger()
        self.requests = {
            item.provider_visible_user_prompt: (index, item)
            for index, item in enumerate(prepared.requests)
        }
        self.generations: dict[str, OpenRouterGenerationEvidence] = {}
        self.generation_fetches: list[str] = []
        sample_request = prepared.requests[0]
        sample_response = build_cross_lineage_adjudication_response(
            request=sample_request,
            dimension_outcomes=sample_request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale="Synthetic snapshot construction only.",
        )
        sample_usage, _ = _judge_usage_and_generation(
            case_index=0,
            request=sample_request,
            response=sample_response,
            judge=judge,
        )
        raw_binding = sample_usage.routing["identity_binding"]
        assert isinstance(raw_binding, dict)
        self.identity_snapshot = OpenRouterModelEndpointIdentitySnapshot.model_validate(
            raw_binding["snapshot"]
        )

    def _selected_structured_output_mode(self, model: str) -> StructuredOutputMode:
        assert model == self.prepared.target.judge_model_id
        return self.prepared.target.judge_structured_output_mode

    def registered_model_identity_snapshot(
        self,
        exact_model_id: str,
    ) -> OpenRouterModelEndpointIdentitySnapshot:
        assert exact_model_id == self.prepared.target.judge_model_id
        return self.identity_snapshot

    def _is_trusted_prequalification_request(
        self,
        role: str,
        **kwargs: Any,
    ) -> bool:
        try:
            validate_provider_visible_source_request(
                self.observation,
                request_role=role,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
                response_model=kwargs["response_model"],
                schema_name=kwargs["schema_name"],
                structured_output_mode=kwargs["structured_output_mode"],
                context_package=kwargs["context_package"],
            )
        except ValueError:
            return False
        return True

    async def complete_with_evidence(self, **kwargs: Any) -> StructuredCompletion[Any]:
        assert kwargs["role"] == "model_benchmark"
        assert kwargs["models"] == [self.prepared.target.judge_model_id]
        assert kwargs["response_model"] is CrossLineageAdjudicationWireResponse
        assert kwargs["schema_name"] == CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME
        index, request = self.requests[kwargs["user_prompt"]]
        wire = CrossLineageAdjudicationWireResponse.model_validate_json(
            json.dumps(
                {
                    "dimension_outcomes": [
                        {
                            "dimension": item.dimension.value,
                            "passed": item.passed,
                        }
                        for item in request.expected_dimension_outcomes
                    ],
                    "disposition": "CONFIRMED",
                    "rationale": "Independent synthetic adjudication matches the sealed outcomes.",
                }
            ),
            strict=True,
        )
        host = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale=wire.rationale,
        )
        usage, generation = _judge_usage_and_generation(
            case_index=index,
            request=request,
            response=host,
            judge=self.judge,
        )
        if self.return_unbound_usage:
            usage = usage.model_copy(update={"identity_strength": ModelIdentityStrength.UNBOUND})
        self.usage.add(usage)
        assert usage.openrouter_generation_id is not None
        self.generations[usage.openrouter_generation_id] = generation
        completion = StructuredCompletion(
            value=wire,
            usage_record=usage,
        )
        _SYNTHETIC_COMPLETION_GENERATIONS[usage.request_id] = generation
        return completion

    async def get_generation_evidence(
        self,
        generation_id: str,
    ) -> OpenRouterGenerationEvidence:
        self.generation_fetches.append(generation_id)
        return self.generations[generation_id]


async def _synthetic_complete_with_evidence(
    client: OpenRouterClient,
    **kwargs: Any,
) -> StructuredCompletion[Any]:
    return await cast(Any, client).complete_with_evidence(**kwargs)


async def _synthetic_get_generation_evidence(
    client: OpenRouterClient,
    generation_id: str,
) -> OpenRouterGenerationEvidence:
    return await cast(Any, client).get_generation_evidence(generation_id)


def _synthetic_structured_completion_generation(
    completion: StructuredCompletion[Any],
) -> OpenRouterGenerationEvidence:
    return _SYNTHETIC_COMPLETION_GENERATIONS.pop(completion.usage_record.request_id)


def _synthetic_selected_structured_output_mode(
    client: OpenRouterClient,
    model: str,
) -> StructuredOutputMode:
    return cast(Any, client)._selected_structured_output_mode(model)


def _synthetic_registered_model_identity_snapshot(
    client: OpenRouterClient,
    model: str,
) -> OpenRouterModelEndpointIdentitySnapshot:
    return cast(Any, client).registered_model_identity_snapshot(model)


def _synthetic_trusted_source_request(
    client: OpenRouterClient,
    role: str,
    **kwargs: Any,
) -> bool:
    return bool(cast(Any, client)._is_trusted_prequalification_request(role, **kwargs))


def _cross_lineage_privacy_context(
    inputs: _Inputs,
    prepared: CrossLineageAdjudicationPreparedRun,
) -> tuple[PrivacySourceProvenanceObservation, Any]:
    observation = prove_release_pinned_cross_lineage_adjudication_source(
        prepared,
        inputs.suite,
        inputs.candidate_report,
        now=NOW,
    )
    policy = resolve_effective_privacy_policy(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        require_zdr=True,
        consent_observation=None,
        source_sha256=cross_lineage_adjudication_source_sha256(prepared),
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=observation,
        configured_model_ids=(prepared.target.judge_model_id,),
        configured_provider_endpoints=(prepared.target.judge_provider_endpoint,),
        requested_budget_usd=Decimal("250"),
        now=NOW,
    )
    return observation, policy


def _complete_report(inputs: _Inputs) -> CrossLineageAdjudicationReport:
    prepared = _prepare(inputs)
    results = []
    for index, request in enumerate(prepared.requests):
        response = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale="The independently scored outcomes match the frozen expected outcomes.",
        )
        usage, generation = _judge_usage_and_generation(
            case_index=index,
            request=request,
            response=response,
            judge=inputs.judge,
        )
        results.append(
            build_cross_lineage_adjudication_case_result(
                request=request,
                response=response,
                usage_record=usage,
                generation_evidence=generation,
            )
        )
    return build_cross_lineage_adjudication_report(prepared=prepared, results=results)


def test_prepare_derives_exact_independent_roots_and_one_case_prompts(inputs: _Inputs) -> None:
    prepared = _prepare(inputs)

    assert prepared.run_kind is CrossLineageAdjudicationRunKind.PRIMARY
    assert prepared.target.candidate_model_id == CANDIDATE_ID
    assert prepared.target.judge_model_id == JUDGE_ID
    assert prepared.target.candidate_root_lineage != prepared.target.judge_root_lineage
    assert prepared.case_ids == tuple(sorted(prepared.case_ids))
    assert len(prepared.requests) == len(inputs.suite.cases)
    assert all(request.provider_call_authorized is False for request in prepared.requests)
    assert prepared.runner_authority_authorized is False
    assert prepared.adjudication_credit_authorized is False

    first = prepared.requests[0]
    prompt = build_cross_lineage_adjudication_prompt(
        request=first,
        suite=inputs.suite,
        candidate_report=inputs.candidate_report,
    )
    assert hashlib.sha256(prompt.encode()).hexdigest() == first.user_prompt_sha256
    prompt_payload = json.loads(prompt)["case_payload"]
    assert prompt_payload["case"]["source_excerpt"] == inputs.suite.cases[0].source_excerpt
    assert prompt_payload["case"]["source_excerpt"] != inputs.suite.cases[1].source_excerpt
    assert '"usage_record"' not in prompt
    assert '"routing"' not in prompt
    assert first.candidate_dimension_result_sha256s


def test_provider_wire_schema_has_only_decisions_and_host_derives_hashes(inputs: _Inputs) -> None:
    prepared = _prepare(inputs)
    request = prepared.requests[0]
    schema = strict_json_schema(CrossLineageAdjudicationWireResponse)
    assert set(schema["properties"]) == {
        "dimension_outcomes",
        "disposition",
        "rationale",
    }
    assert "sha256" not in json.dumps(schema).casefold()

    wire = CrossLineageAdjudicationWireResponse.model_validate_json(
        json.dumps(
            {
                "dimension_outcomes": [
                    {"dimension": item.dimension.value, "passed": item.passed}
                    for item in request.expected_dimension_outcomes
                ],
                "disposition": "CONFIRMED",
                "rationale": "The sealed synthetic evidence supports each dimension decision.",
            }
        ),
        strict=True,
    )
    response = adjudication_module.bind_cross_lineage_adjudication_wire_response(
        request=request,
        wire_response=wire,
    )
    assert response.wire_response_sha256 == (
        cross_lineage_adjudication_validated_response_sha256(wire)
    )
    assert response.wire_response_sha256 != response.adjudication_sha256
    assert all(item.outcome_sha256 for item in response.dimension_outcomes)


def test_exact_cross_lineage_source_provenance_rejects_prompt_contamination(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    observation, policy = _cross_lineage_privacy_context(inputs, prepared)
    evidence = observation.evidence
    first = prepared.requests[0]

    assert evidence.proof_kind == "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
    assert evidence.adjudication_prepared_run_sha256 == prepared.prepared_run_sha256
    assert evidence.adjudication_candidate_report_sha256 == inputs.candidate_report.report_sha256
    assert evidence.provider_visible_case_count == len(prepared.requests)
    assert policy.source_sha256 == cross_lineage_adjudication_source_sha256(prepared)
    validate_provider_visible_source_request(
        observation,
        request_role="model_benchmark",
        system_prompt=cross_lineage_adjudication_system_prompt(),
        user_prompt=first.provider_visible_user_prompt,
        response_model=CrossLineageAdjudicationWireResponse,
        schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        structured_output_mode=prepared.target.judge_structured_output_mode,
        context_package=None,
    )
    with pytest.raises(ValueError, match="absent from the live release-pinned"):
        validate_provider_visible_source_request(
            observation,
            request_role="model_benchmark",
            system_prompt=cross_lineage_adjudication_system_prompt(),
            user_prompt=first.provider_visible_user_prompt + " ",
            response_model=CrossLineageAdjudicationWireResponse,
            schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
            structured_output_mode=prepared.target.judge_structured_output_mode,
            context_package=None,
        )


def test_async_transport_executes_exact_inventory_and_refetches_generation(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    observation, policy = _cross_lineage_privacy_context(inputs, prepared)
    fake = _SyntheticCrossLineageClient(
        prepared=prepared,
        judge=inputs.judge,
        observation=observation,
        effective_privacy_policy=policy,
    )
    results = asyncio.run(
        adjudication_module._execute_cross_lineage_adjudication_requests_impl(
            client=cast(OpenRouterClient, fake),
            prepared=prepared,
            generation_evidence_fetcher=None,
            usage=fake.usage,
            complete_with_evidence=_synthetic_complete_with_evidence,
            get_generation_evidence=_synthetic_get_generation_evidence,
            selected_structured_output_mode=_synthetic_selected_structured_output_mode,
            registered_model_identity_snapshot=(_synthetic_registered_model_identity_snapshot),
            trusted_source_request=_synthetic_trusted_source_request,
            require_transport=adjudication_module._require_exact_cross_lineage_transport,
            runtime_credit_predicate=is_creditable_usage_record,
            structured_completion_generation_resolver=None,
            require_pristine=lambda: None,
        )
    )

    assert tuple(item.case_id for item in results) == prepared.case_ids
    assert len(fake.usage.records) == len(prepared.requests)
    assert all(item.usage_record.role == "model_benchmark" for item in results)
    assert all(
        item.usage_record.requested_model == prepared.target.judge_model_id for item in results
    )
    assert all(
        item.usage_record.actual_provider_endpoint == prepared.target.judge_provider_endpoint
        for item in results
    )
    assert all(
        item.judge_validated_response_sha256 == item.response.wire_response_sha256
        and item.judge_validated_response_sha256 != item.response.adjudication_sha256
        for item in results
    )
    assert all(
        is_creditable_usage_record(
            item.usage_record,
            require_real=True,
            require_certification=True,
        )
        for item in results
    )
    report = build_cross_lineage_adjudication_report(prepared=prepared, results=results)
    assert all(
        is_creditable_usage_record(
            item.usage_record,
            require_real=True,
            require_certification=True,
        )
        for item in report.cases
    )
    assert fake.generation_fetches == [
        result.generation_evidence.generation_id for result in results
    ]


def test_smoke_transport_uses_bounded_usage_and_generation_hooks(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    observation, policy = _cross_lineage_privacy_context(inputs, prepared)
    fake = _SyntheticCrossLineageClient(
        prepared=prepared,
        judge=inputs.judge,
        observation=observation,
        effective_privacy_policy=policy,
    )
    usage_checks: list[str] = []
    generation_checks: list[str] = []

    def forbidden_general_credit(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("noncrediting smoke must not call the general credit predicate")

    def bounded_usage_error(record: UsageRecord) -> str | None:
        usage_checks.append(record.request_id)
        return None

    def reconcile_generation(
        evidence: OpenRouterGenerationEvidence,
        **kwargs: Any,
    ) -> OpenRouterGenerationEvidence:
        assert kwargs["expected_exact_model"] == prepared.target.judge_model_id
        assert kwargs["expected_canonical_model"] == prepared.target.judge_canonical_model_id
        assert kwargs["expected_provider_name"] == prepared.target.judge_provider_name
        generation_checks.append(evidence.generation_id)
        return evidence

    results = asyncio.run(
        adjudication_module._execute_cross_lineage_adjudication_requests_impl(
            client=cast(OpenRouterClient, fake),
            prepared=prepared,
            generation_evidence_fetcher=None,
            usage=fake.usage,
            complete_with_evidence=_synthetic_complete_with_evidence,
            get_generation_evidence=_synthetic_get_generation_evidence,
            selected_structured_output_mode=_synthetic_selected_structured_output_mode,
            registered_model_identity_snapshot=(_synthetic_registered_model_identity_snapshot),
            trusted_source_request=_synthetic_trusted_source_request,
            require_transport=adjudication_module._require_exact_cross_lineage_transport,
            runtime_credit_predicate=forbidden_general_credit,
            noncrediting_smoke_usage_error=bounded_usage_error,
            noncrediting_smoke_generation_reconcile=reconcile_generation,
            structured_completion_generation_resolver=(_synthetic_structured_completion_generation),
            require_pristine=lambda: None,
        )
    )

    assert len(results) == len(prepared.requests)
    assert usage_checks == [
        request_id
        for result in results
        for request_id in (result.usage_record.request_id, result.usage_record.request_id)
    ]
    assert generation_checks == [result.generation_evidence.generation_id for result in results]
    assert fake.generation_fetches == []


def test_async_transport_rejects_unbound_real_judge_usage_before_runner_custody(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    observation, policy = _cross_lineage_privacy_context(inputs, prepared)
    fake = _SyntheticCrossLineageClient(
        prepared=prepared,
        judge=inputs.judge,
        observation=observation,
        effective_privacy_policy=policy,
        return_unbound_usage=True,
    )

    with pytest.raises(CrossLineageAdjudicationError, match="non-creditable REAL judge usage"):
        asyncio.run(
            adjudication_module._execute_cross_lineage_adjudication_requests_impl(
                client=cast(OpenRouterClient, fake),
                prepared=prepared,
                generation_evidence_fetcher=None,
                usage=fake.usage,
                complete_with_evidence=_synthetic_complete_with_evidence,
                get_generation_evidence=_synthetic_get_generation_evidence,
                selected_structured_output_mode=_synthetic_selected_structured_output_mode,
                registered_model_identity_snapshot=(_synthetic_registered_model_identity_snapshot),
                trusted_source_request=_synthetic_trusted_source_request,
                require_transport=adjudication_module._require_exact_cross_lineage_transport,
                runtime_credit_predicate=is_creditable_usage_record,
                structured_completion_generation_resolver=None,
                require_pristine=lambda: None,
            )
        )

    assert len(fake.usage.records) == 1
    assert fake.usage.records[0].identity_strength is ModelIdentityStrength.UNBOUND
    assert not is_creditable_usage_record(
        fake.usage.records[0],
        require_real=True,
        require_certification=True,
    )


def test_async_transport_rejects_registered_discovery_mismatch_before_dispatch(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    observation, policy = _cross_lineage_privacy_context(inputs, prepared)
    fake = _SyntheticCrossLineageClient(
        prepared=prepared,
        judge=inputs.judge,
        observation=observation,
        effective_privacy_policy=policy,
    )
    snapshot_payload = fake.identity_snapshot.model_dump(mode="json")
    snapshot_payload["discovery_evidence_sha256"] = "a" * 64
    snapshot_payload["snapshot_sha256"] = canonical_sha256(
        {key: value for key, value in snapshot_payload.items() if key != "snapshot_sha256"}
    )
    fake.identity_snapshot = OpenRouterModelEndpointIdentitySnapshot.model_validate(
        snapshot_payload
    )

    with pytest.raises(
        CrossLineageAdjudicationError,
        match="registered judge discovery differs",
    ):
        asyncio.run(
            adjudication_module._execute_cross_lineage_adjudication_requests_impl(
                client=cast(OpenRouterClient, fake),
                prepared=prepared,
                generation_evidence_fetcher=None,
                usage=fake.usage,
                complete_with_evidence=_synthetic_complete_with_evidence,
                get_generation_evidence=_synthetic_get_generation_evidence,
                selected_structured_output_mode=_synthetic_selected_structured_output_mode,
                registered_model_identity_snapshot=(_synthetic_registered_model_identity_snapshot),
                trusted_source_request=_synthetic_trusted_source_request,
                require_transport=adjudication_module._require_exact_cross_lineage_transport,
                runtime_credit_predicate=is_creditable_usage_record,
                structured_completion_generation_resolver=None,
                require_pristine=lambda: None,
            )
        )

    assert fake.usage.records == []
    assert fake.generations == {}


def _uninitialized_exact_client() -> OpenRouterClient:
    client = object.__new__(OpenRouterClient)
    object.__setattr__(client, "usage", UsageLedger())
    return client


@pytest.mark.parametrize(
    "method_name",
    (
        "complete_with_evidence",
        "get_generation_evidence",
        "_selected_structured_output_mode",
        "registered_model_identity_snapshot",
        "_is_trusted_prequalification_request",
    ),
)
def test_transport_rejects_instance_callable_retarget_before_provider_state(
    inputs: _Inputs,
    method_name: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    side_effects = {"post": 0, "reserve": 0, "claim": 0}

    def retargeted(*_args: Any, **_kwargs: Any) -> None:
        for name in side_effects:
            side_effects[name] += 1

    object.__setattr__(client, method_name, retargeted)
    with pytest.raises(CrossLineageAdjudicationError, match="binding changed before provider work"):
        asyncio.run(
            execute_cross_lineage_adjudication_requests(
                client=client,
                prepared=prepared,
            )
        )

    assert side_effects == {"post": 0, "reserve": 0, "claim": 0}
    assert client.usage.records == []


@pytest.mark.parametrize(
    "method_name",
    (
        "complete_with_evidence",
        "get_generation_evidence",
        "_selected_structured_output_mode",
        "registered_model_identity_snapshot",
        "_is_trusted_prequalification_request",
    ),
)
def test_transport_rejects_class_callable_retarget_before_provider_state(
    inputs: _Inputs,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    side_effects = {"post": 0, "reserve": 0, "claim": 0}

    def retargeted(*_args: Any, **_kwargs: Any) -> None:
        for name in side_effects:
            side_effects[name] += 1

    monkeypatch.setattr(OpenRouterClient, method_name, retargeted)
    with pytest.raises(CrossLineageAdjudicationError, match="binding changed before provider work"):
        asyncio.run(
            execute_cross_lineage_adjudication_requests(
                client=client,
                prepared=prepared,
            )
        )

    assert side_effects == {"post": 0, "reserve": 0, "claim": 0}
    assert client.usage.records == []


@pytest.mark.parametrize(
    "binding_name",
    (
        "OpenRouterClient",
        "_execute_cross_lineage_adjudication_requests_impl",
        "_require_exact_cross_lineage_transport",
        "_require_usage_matches_live_judge_snapshot",
        "is_creditable_usage_record",
        "require_authenticated_runner_smoke_run_index",
        "cross_lineage_adjudication_validated_response_sha256",
        "execute_cross_lineage_adjudication_requests",
    ),
)
def test_transport_rejects_module_retarget_before_provider_state(
    inputs: _Inputs,
    monkeypatch: pytest.MonkeyPatch,
    binding_name: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    side_effects = {"post": 0, "reserve": 0, "claim": 0}

    def retargeted(*_args: Any, **_kwargs: Any) -> None:
        for name in side_effects:
            side_effects[name] += 1

    monkeypatch.setattr(adjudication_module, binding_name, retargeted)
    with pytest.raises(CrossLineageAdjudicationError, match="binding changed before provider work"):
        asyncio.run(
            execute_cross_lineage_adjudication_requests(
                client=client,
                prepared=prepared,
            )
        )

    assert side_effects == {"post": 0, "reserve": 0, "claim": 0}
    assert client.usage.records == []


@pytest.mark.parametrize(
    "binding_name",
    (
        "require_authenticated_runner_smoke_run_index",
        "noncrediting_unknown_token_smoke_usage_error",
        "reconcile_noncrediting_smoke_generation_evidence",
    ),
)
def test_smoke_transport_rejects_smoke_binding_retarget_before_provider_state(
    inputs: _Inputs,
    monkeypatch: pytest.MonkeyPatch,
    binding_name: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    side_effects = {"validator": 0, "provider": 0}

    def retargeted(_value: object) -> int:
        side_effects["validator"] += 1
        return 1

    monkeypatch.setattr(adjudication_module, binding_name, retargeted)
    with pytest.raises(CrossLineageAdjudicationError, match="binding changed before provider work"):
        asyncio.run(
            adjudication_module._execute_cross_lineage_adjudication_smoke_requests(
                client=client,
                prepared=prepared,
                expected_request_cost_previews=(),
                smoke_run_index=1,
            )
        )

    assert side_effects == {"validator": 0, "provider": 0}
    assert client.usage.records == []


@pytest.mark.parametrize(
    "binding_name",
    (
        "_resolve_structured_completion_generation_evidence",
        "_openrouter_client_callables_are_pristine",
    ),
)
def test_smoke_transport_rejects_in_place_carrier_authority_retarget_before_provider_state(
    inputs: _Inputs,
    binding_name: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    authority_function = getattr(openrouter_module, binding_name)
    original_code = authority_function.__code__

    def changed(*_args: object, **_kwargs: object) -> object:
        return object()

    authority_function.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        with pytest.raises(
            CrossLineageAdjudicationError,
            match="binding changed before provider work",
        ):
            asyncio.run(
                adjudication_module._execute_cross_lineage_adjudication_smoke_requests(
                    client=client,
                    prepared=prepared,
                    expected_request_cost_previews=(),
                    smoke_run_index=1,
                )
            )
    finally:
        authority_function.__code__ = original_code

    assert client.usage.records == []


def test_smoke_transport_rejects_in_place_executor_impl_retarget_before_provider_state(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    trusted_impl = adjudication_module._execute_cross_lineage_adjudication_requests_impl
    original_code = trusted_impl.__code__

    async def changed(*_args: object, **_kwargs: object) -> object:
        return object()

    trusted_impl.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        with pytest.raises(
            CrossLineageAdjudicationError,
            match="transport guard changed before provider work",
        ):
            asyncio.run(
                adjudication_module._execute_cross_lineage_adjudication_smoke_requests(
                    client=client,
                    prepared=prepared,
                    expected_request_cost_previews=(),
                    smoke_run_index=1,
                )
            )
    finally:
        trusted_impl.__code__ = original_code

    assert client.usage.records == []


@pytest.mark.parametrize("mutation", ("code", "module_alias", "attribute"))
def test_public_smoke_transport_pins_private_executor_state_before_provider_state(
    inputs: _Inputs,
    mutation: str,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    trusted_executor = adjudication_module._execute_cross_lineage_adjudication_smoke_requests
    original_code = trusted_executor.__code__
    original_binding = adjudication_module._execute_cross_lineage_adjudication_smoke_requests
    original_attributes = dict(trusted_executor.__dict__)

    async def changed(*_args: object, **_kwargs: object) -> object:
        return "BYPASS"

    if mutation == "code":
        trusted_executor.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    elif mutation == "module_alias":
        adjudication_module._execute_cross_lineage_adjudication_smoke_requests = cast(
            Any,
            changed,
        )
    else:
        trusted_executor.__dict__["synthetic_state_retarget"] = object()
    try:
        with pytest.raises(
            CrossLineageAdjudicationError,
            match="smoke executor boundary changed",
        ):
            asyncio.run(
                adjudication_module.execute_noncrediting_cross_lineage_adjudication_smoke_requests(
                    smoke_run_index=1,
                    client=client,
                    prepared=prepared,
                    expected_request_cost_previews=(cast(Any, None),),
                )
            )
    finally:
        trusted_executor.__code__ = original_code
        adjudication_module._execute_cross_lineage_adjudication_smoke_requests = original_binding
        trusted_executor.__dict__.clear()
        trusted_executor.__dict__.update(original_attributes)

    assert client.usage.records == []


def test_smoke_transport_rejects_in_place_outer_pristine_guard_retarget_before_provider_state(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    executor = adjudication_module._execute_cross_lineage_adjudication_smoke_requests
    executor_closure = dict(
        zip(executor.__code__.co_freevars, executor.__closure__ or (), strict=True)
    )
    require_pristine = cast(Any, executor_closure["require_pristine"].cell_contents)
    original_code = require_pristine.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    require_pristine.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        with pytest.raises(
            CrossLineageAdjudicationError,
            match="transport guard changed before provider work",
        ):
            asyncio.run(
                executor(
                    client=client,
                    prepared=prepared,
                    expected_request_cost_previews=(),
                    smoke_run_index=1,
                )
            )
    finally:
        require_pristine.__code__ = original_code

    assert client.usage.records == []


def test_smoke_transport_rejects_provider_graph_subset_and_default_retarget_before_state(
    inputs: _Inputs,
) -> None:
    prepared = _prepare(inputs)
    client = _uninitialized_exact_client()
    predicate = openrouter_module._openrouter_client_callables_are_pristine
    original_kwdefaults = predicate.__kwdefaults__
    assert original_kwdefaults is not None
    guard = cast(Any, original_kwdefaults["_provider_authority_graph_is_pristine"])
    guard_closure = dict(zip(guard.__code__.co_freevars, guard.__closure__ or (), strict=True))
    states_cell = guard_closure["frozen_states"]
    seal_cell = guard_closure["frozen_states_seal"]
    original_states = states_cell.cell_contents
    assert type(original_states) is tuple
    subset = (original_states[0],)
    states_cell.cell_contents = subset
    seal_cell.cell_contents = subset
    predicate.__kwdefaults__ = {
        **original_kwdefaults,
        "_provider_authority_graph_frozen_states": subset,
    }
    try:
        with pytest.raises(
            CrossLineageAdjudicationError,
            match="binding changed before provider work",
        ):
            asyncio.run(
                adjudication_module._execute_cross_lineage_adjudication_smoke_requests(
                    client=client,
                    prepared=prepared,
                    expected_request_cost_previews=(),
                    smoke_run_index=1,
                )
            )
    finally:
        predicate.__kwdefaults__ = original_kwdefaults
        states_cell.cell_contents = original_states
        seal_cell.cell_contents = original_states
    assert predicate()
    assert client.usage.records == []


def test_primary_replay_and_rationale_are_deterministically_separated(inputs: _Inputs) -> None:
    primary = _prepare(inputs, run_kind=CrossLineageAdjudicationRunKind.PRIMARY)
    replay = _prepare(inputs, run_kind=CrossLineageAdjudicationRunKind.REPLAY)
    assert primary.target.target_sha256 != replay.target.target_sha256
    assert primary.prepared_run_sha256 != replay.prepared_run_sha256
    assert primary.requests[0].request_sha256 != replay.requests[0].request_sha256

    first = primary.requests[0]
    left = build_cross_lineage_adjudication_response(
        request=first,
        dimension_outcomes=first.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="First bounded explanation.",
    )
    right = build_cross_lineage_adjudication_response(
        request=first,
        dimension_outcomes=first.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="A completely different bounded explanation.",
    )
    assert left.adjudication_sha256 == right.adjudication_sha256
    assert left.rationale != right.rationale


def test_prepare_rejects_same_root_mock_and_conflicting_report_root(inputs: _Inputs) -> None:
    same_root_judge = _candidate_registry((SAME_ROOT_JUDGE_ID,)).candidates[0]
    with pytest.raises(PublicModelLineageAuthorityError, match="not independent"):
        _prepare(inputs, judge=same_root_judge)

    mock_report = _report(inputs.suite, CANDIDATE_ID)
    with pytest.raises(CrossLineageAdjudicationError, match="REAL-shaped"):
        _prepare(inputs, report=mock_report)

    payload = inputs.candidate_report.model_dump(mode="json")
    payload["results"][0]["target"]["root_lineage"] = "sha256:" + ("f" * 64)
    payload["report_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    conflicting = ModelBenchmarkReport.model_validate(payload)
    with pytest.raises(CrossLineageAdjudicationError, match="conflicting root"):
        _prepare(inputs, report=conflicting)


def test_prepare_rejects_ordinary_lineage_api_retarget(
    inputs: _Inputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        adjudication_module,
        "require_independent_public_model_lineage",
        lambda *_args: object(),
    )
    with pytest.raises(CrossLineageAdjudicationError, match="binding changed"):
        _prepare(inputs)


def test_request_models_are_strict_frozen_and_self_hashed(inputs: _Inputs) -> None:
    request = _prepare(inputs).requests[0]
    payload = request.model_dump(mode="json")
    payload["unexpected"] = False
    with pytest.raises(ValidationError, match="Extra inputs"):
        CrossLineageAdjudicationCaseRequest.model_validate_json(json.dumps(payload))

    payload.pop("unexpected")
    payload["candidate_request_body_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="request hash"):
        CrossLineageAdjudicationCaseRequest.model_validate_json(json.dumps(payload))

    with pytest.raises(ValidationError, match="frozen"):
        request.case_id = "case-0000000000000000"


def test_complete_report_binds_real_judge_usage_generation_and_refetch(inputs: _Inputs) -> None:
    report = _complete_report(inputs)
    requests = adjudication_generation_verification_requests(
        report=report,
        judge=inputs.judge,
    )

    assert report.execution_evidence is ExecutionEvidenceKind.REAL
    assert report.case_ids == tuple(item.case_id for item in report.cases)
    assert tuple(item.case_id for item in requests) == report.case_ids
    assert all(item.benchmark_report_sha256 == report.report_sha256 for item in requests)
    assert all(item.exact_model_id == JUDGE_ID for item in requests)
    assert report.serialized_authority is False
    assert report.runner_authority_authorized is False
    assert report.generation_verification_authorized is False
    assert report.adjudication_credit_authorized is False


def test_report_rejects_missing_replayed_and_mock_judge_evidence(inputs: _Inputs) -> None:
    report = _complete_report(inputs)
    prepared = _prepare(inputs)
    with pytest.raises(CrossLineageAdjudicationError, match="prepared request set"):
        build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=report.cases[:-1],
        )
    with pytest.raises(CrossLineageAdjudicationError, match="exceeds"):
        build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=repeat(report.cases[0]),
        )

    first = report.cases[0]
    mock_usage = first.usage_record.model_copy(
        update={"execution_evidence": ExecutionEvidenceKind.MOCK}
    )
    with pytest.raises(ValueError, match="REAL-shaped"):
        build_cross_lineage_adjudication_case_result(
            request=first.request,
            response=first.response,
            usage_record=mock_usage,
            generation_evidence=first.generation_evidence,
        )


def test_report_tamper_and_judge_metadata_drift_fail_closed(inputs: _Inputs) -> None:
    report = _complete_report(inputs)
    payload = report.model_dump(mode="json")
    payload["candidate_report_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        CrossLineageAdjudicationReport.model_validate_json(json.dumps(payload))

    judge_payload = inputs.judge.model_dump(mode="json")
    judge_payload["discovery_evidence_sha256"] = "9" * 64
    drifted = CandidateModel.model_validate(judge_payload)
    with pytest.raises(CrossLineageAdjudicationError, match="judge differs"):
        adjudication_generation_verification_requests(report=report, judge=drifted)
