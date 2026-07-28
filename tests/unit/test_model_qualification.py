from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import pickle
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import mmaudit.models.generation_evidence as generation_evidence_module
from mmaudit.benchmark.models import ModelBenchmarkDimension, load_model_benchmark_corpus
from mmaudit.constants import ALL_MODEL_ROLES, ALL_SPECIALIST_ROLES
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    ModelDiscoveryArtifactBinding,
    OpenRouterDiscoveryRunProvenance,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    openrouter_endpoint_query,
    openrouter_model_query,
    seal_model_discovery_run_manifest,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    validate_openrouter_generation_payload,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateFalsifierEvidence,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    CriticalSurfaceReviewEvidence,
    LineageReviewStatus,
    ModelQualificationArtifact,
    OperatorLineageReview,
    ProductionModelSelection,
    QualificationBindings,
    QualificationDimensionResult,
    QualificationDimensionThreshold,
    QualificationDisposition,
    QualificationPolicy,
    QualificationVerification,
    SelectionVerification,
    TrustedBenchmarkVerificationEvidence,
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
    _freshly_reverify_production_benchmarks,
    _stable_generation_binding,
    evaluate_certified_ensemble,
    load_candidate_registry,
    resolve_verified_production_qualification,
    seal_candidate_registry,
    seal_model_qualification_artifact,
    seal_model_qualification_result,
    seal_operator_lineage_review,
    seal_production_selection,
    seal_qualification_policy,
    validate_candidate_registry_discovery,
    verify_model_qualification,
    verify_production_selection,
)
from mmaudit.models.qualification_workflow import (
    candidate_generation_verification_requests,
    run_qualification_workflow,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import candidate_falsifier_role
from mmaudit.orchestration.manifest import canonical_sha256
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)
from tests.qualification_support import synthetic_release_observation

_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_ROOT = Path(__file__).parents[2]
_ROLES = tuple(
    sorted(
        {
            *ALL_MODEL_ROLES,
            *ALL_SPECIALIST_ROLES,
            "whole_protocol_review",
        }
    )
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


_PRODUCTION_CONFIG_SHA256 = _sha("production-effective-config")


def _model_id(index: int) -> str:
    return f"author{index}/security-model-{index}"


def _root(index: int) -> str:
    return "sha256:" + hashlib.sha256(f"root-{index}".encode()).hexdigest()


def _discovery_run(
    *,
    model_id: str,
    index: int,
) -> tuple[OpenRouterModelDiscoveryRunManifest, OpenRouterModelDiscoveryEvidence]:
    endpoint_id = f"provider-{index}/exact"
    provider_name = f"Approved Provider {index}"
    endpoint = {
        "model_id": model_id,
        "slug": endpoint_id,
        "provider_name": provider_name,
        "status": 0,
        "context_length": 100_000,
        "max_prompt_tokens": 90_000,
        "max_completion_tokens": 8_192,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ],
        "pricing": {"completion": "0.000002", "prompt": "0.000001"},
    }
    endpoint_snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model_id,
        configured_provider_endpoints=(endpoint_id,),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": model_id,
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=True,
        zdr_payload={"data": [endpoint]},
        reasoning_requested=True,
    )
    catalog_model = {
        "id": model_id,
        "canonical_slug": f"{model_id}-20260727",
        "context_length": 100_000,
        "top_provider": {
            "context_length": 100_000,
            "max_completion_tokens": 8_192,
            "is_moderated": False,
        },
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ],
    }
    payload = validate_openrouter_model_discovery(
        exact_model_id=model_id,
        models_payload={"data": [catalog_model]},
        single_model_payload={"data": catalog_model},
        endpoint_snapshot=endpoint_snapshot,
    )
    route = DiscoveryCandidateRoute(
        exact_model_id=model_id,
        approved_provider_endpoint=endpoint_id,
    )
    binding = DiscoveryEndpointMetadataBinding(
        exact_model_id=model_id,
        api_query=openrouter_endpoint_query(model_id),
        response_snapshot_sha256=_sha(f"endpoint-response-{index}"),
    )
    model_binding = DiscoveryModelMetadataBinding(
        exact_model_id=model_id,
        canonical_slug=payload.canonical_slug,
        api_query=openrouter_model_query(payload.canonical_slug),
        response_snapshot_sha256=_sha(f"model-response-{index}"),
        model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
    )
    provenance_payload = {
        "schema_version": "1.0",
        "run_id": f"{index + 1:032x}",
        "retrieved_at": _NOW.isoformat().replace("+00:00", "Z"),
        "execution_evidence": "real",
        "authenticated_metadata": True,
        "source_api_identity": "https://openrouter.ai/api/v1",
        "catalog_api_query": "/models?zdr=true&supported_parameters=response_format",
        "zdr_api_query": "/endpoints/zdr",
        "client_fingerprint_sha256": _sha(f"client-{index}"),
        "provider_fingerprint_sha256": _sha(f"provider-fingerprint-{index}"),
        "catalog_snapshot_sha256": _sha(f"catalog-{index}"),
        "zdr_snapshot_sha256": _sha(f"zdr-{index}"),
        "candidate_routes": [route.model_dump(mode="json")],
        "candidate_set_sha256": canonical_sha256([route.model_dump(mode="json")]),
        "model_metadata_bindings": [model_binding.model_dump(mode="json")],
        "endpoint_metadata_bindings": [binding.model_dump(mode="json")],
    }
    provenance = OpenRouterDiscoveryRunProvenance.model_validate(
        {
            **provenance_payload,
            "provenance_sha256": canonical_sha256(provenance_payload),
        }
    )
    evidence_payload = {
        **payload.model_dump(mode="json"),
        "provenance": provenance.model_dump(mode="json"),
    }
    evidence = OpenRouterModelDiscoveryEvidence.model_validate(
        {
            **evidence_payload,
            "discovery_evidence_sha256": canonical_sha256(evidence_payload),
        }
    )
    filename = f"candidate-{hashlib.sha256(model_id.encode()).hexdigest()}.json"
    manifest = seal_model_discovery_run_manifest(
        provenance=provenance,
        artifacts=(
            ModelDiscoveryArtifactBinding(
                exact_model_id=model_id,
                approved_provider_endpoint=endpoint_id,
                filename=filename,
                artifact_sha256=_sha(f"artifact-{index}"),
                discovery_evidence_sha256=evidence.discovery_evidence_sha256,
            ),
        ),
    )
    return manifest, evidence


def _dimension_results(*, failed_dimension: ModelBenchmarkDimension | None = None):
    return tuple(
        QualificationDimensionResult(
            dimension=dimension,
            passed=0 if dimension is failed_dimension else 1,
            evaluated=1,
            score=0 if dimension is failed_dimension else 1,
        )
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )


def _usage_record(
    *,
    candidate: CandidateModel,
    role: str,
    request_id: str,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    qualification_artifact_sha256: str | None = None,
    production_selection_sha256: str | None = None,
) -> UsageRecord:
    ended_at = _NOW + timedelta(seconds=1)
    generation_id = f"generation-{request_id}"
    routing: dict[str, object] = {
        "generation_id": generation_id,
        "selected_model": candidate.canonical_model_slug,
        "canonical_model": candidate.canonical_model_slug,
        "selected_provider_endpoint": candidate.approved_provider_endpoint,
        "selected_provider_name": candidate.approved_provider_name,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "finish_reason": "stop",
        "schema_sha256": _sha("schema"),
        "router_metadata_sha256": _sha(f"router-{request_id}"),
        "provider_policy_sha256": _sha("provider-policy"),
        "provider_fallbacks_allowed": False,
        "certification_request": True,
        "endpoint_snapshot_sha256": candidate.endpoint_snapshot_sha256,
        "endpoint_pricing_sha256": candidate.pricing_snapshot_sha256,
        "model_metadata_snapshot_sha256": candidate.model_metadata_snapshot_sha256,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": candidate.canonical_model_slug,
                "id": candidate.exact_model_id,
            }
        ),
        "catalog_snapshot_sha256": _sha(f"catalog-{candidate.exact_model_id}"),
        "discovery_provenance_sha256": _sha(f"discovery-provenance-{candidate.exact_model_id}"),
        "discovery_evidence_sha256": candidate.discovery_evidence_sha256,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": _NOW.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": 1_000,
    }
    if qualification_artifact_sha256 is not None:
        routing["qualification_artifact_sha256"] = qualification_artifact_sha256
    if production_selection_sha256 is not None:
        routing["production_selection_sha256"] = production_selection_sha256
    return bind_synthetic_usage_identity(
        UsageRecord(
            request_id=request_id,
            role=role,
            execution_evidence=execution_evidence,
            requested_model=candidate.exact_model_id,
            returned_model=candidate.exact_model_id,
            actual_model=candidate.canonical_model_slug,
            provider="Approved Provider",
            model_family=candidate.exact_model_id,
            timestamp=_NOW,
            prompt_tokens=100,
            completion_tokens=25,
            total_tokens=125,
            reported_cost_usd=0.01,
            accounted_cost_usd=0.01,
            routing=routing,
            prompt_sha256=_sha(f"prompt-{request_id}"),
            response_sha256=_sha(f"response-{request_id}"),
            validated_response_sha256=_sha(f"validated-response-{request_id}"),
            request_body_sha256=_sha(f"request-{request_id}"),
            schema_sha256=_sha("schema"),
            openrouter_generation_id=generation_id,
            configured_provider_endpoints=[candidate.approved_provider_endpoint],
            actual_provider_endpoint=candidate.approved_provider_endpoint,
            started_at=_NOW,
            ended_at=ended_at,
            latency_ms=1_000,
            finish_reason="stop",
            retry_count=0,
            validation_status=ModelRequestValidationStatus.VALID,
            status="success",
            attempts=1,
        )
    )


def _generation_attestation(record: UsageRecord) -> OpenRouterGenerationEvidence:
    assert record.openrouter_generation_id is not None
    assert record.actual_model is not None
    assert record.finish_reason is not None
    assert record.reported_cost_usd is not None
    return validate_openrouter_generation_payload(
        {
            "data": {
                "id": record.openrouter_generation_id,
                "model": record.actual_model,
                "provider_name": record.routing["selected_provider_name"],
                "finish_reason": record.finish_reason,
                "native_finish_reason": None,
                "tokens_prompt": record.prompt_tokens,
                "tokens_completion": record.completion_tokens,
                "native_tokens_prompt": record.prompt_tokens,
                "native_tokens_completion": record.completion_tokens,
                "native_tokens_reasoning": record.reasoning_tokens,
                "native_tokens_cached": record.cached_tokens,
                "total_cost": str(record.reported_cost_usd),
                "usage": str(record.reported_cost_usd),
                "cancelled": False,
                "created_at": _NOW.isoformat(),
                "request_id": record.request_id,
                "latency": str(record.latency_ms),
                "generation_time": "500",
            }
        },
        requested_generation_id=record.openrouter_generation_id,
        retrieved_at=_NOW + timedelta(seconds=2),
        execution_evidence=ExecutionEvidenceKind.REAL,
    )


def _test_trusted_benchmark_evidence(
    *,
    candidate: CandidateModel,
    report_sha256: str,
    corpus_sha256: str,
    ground_truth_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
    parsed_responses_sha256: str,
    case_ids: tuple[str, ...],
    usage_records: tuple[UsageRecord, ...],
    dimensions: tuple[QualificationDimensionResult, ...],
) -> TrustedBenchmarkVerificationEvidence:
    attestations = tuple(
        sorted(
            (_generation_attestation(record) for record in usage_records),
            key=lambda item: item.generation_id,
        )
    )
    payload = {
        "schema_version": "1.0",
        "verified_by": "mmaudit-deterministic-benchmark-verifier",
        "exact_model_id": candidate.exact_model_id,
        "canonical_model_id": candidate.canonical_model_slug,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": candidate.canonical_model_slug,
                "id": candidate.exact_model_id,
            }
        ),
        "discovery_evidence_sha256": candidate.discovery_evidence_sha256,
        "benchmark_report_sha256": report_sha256,
        "benchmark_corpus_sha256": corpus_sha256,
        "benchmark_ground_truth_sha256": ground_truth_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
        "parsed_responses_sha256": parsed_responses_sha256,
        "generation_evidence_sha256": canonical_sha256(
            [_stable_generation_binding(item) for item in attestations]
        ),
        "case_ids": list(case_ids),
        "usage_records": [
            record.model_dump(mode="json")
            for record in sorted(usage_records, key=lambda item: item.request_id)
        ],
        "generation_attestations": [item.model_dump(mode="json") for item in attestations],
        "dimensions": [
            item.model_dump(mode="json")
            for item in sorted(dimensions, key=lambda item: item.dimension.value)
        ],
        "execution_evidence": "real",
        "valid": True,
    }
    payload["verification_sha256"] = canonical_sha256(
        {
            **payload,
            "generation_attestations": [_stable_generation_binding(item) for item in attestations],
        }
    )
    return TrustedBenchmarkVerificationEvidence.model_validate(payload)


@dataclass(frozen=True)
class _Bundle:
    registry: CandidateRegistry
    policy: QualificationPolicy
    bindings: QualificationBindings
    benchmark_evidence: tuple[TrustedBenchmarkVerificationEvidence, ...]
    artifact: ModelQualificationArtifact
    verification: QualificationVerification
    selection: ProductionModelSelection | None
    selection_verification: SelectionVerification | None


def _bundle(
    *,
    review_status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    root_count: int = 6,
    failed_dimension: ModelBenchmarkDimension | None = None,
    benchmark_execution: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    validity_days: int = 6,
) -> _Bundle:
    model_ids = tuple(_model_id(index) for index in range(8))
    grouped_ids = {
        root_index: tuple(
            sorted(
                model_id
                for index, model_id in enumerate(model_ids)
                if index % root_count == root_index
            )
        )
        for root_index in range(root_count)
    }
    reviews: dict[int, OperatorLineageReview] = {}
    for root_index, reviewed_ids in grouped_ids.items():
        if review_status is LineageReviewStatus.PENDING:
            reviews[root_index] = seal_operator_lineage_review(
                status=review_status,
                reviewed_model_ids=reviewed_ids,
                rationale="Pending independent operator lineage adjudication.",
            )
        elif review_status is LineageReviewStatus.REJECTED:
            reviews[root_index] = seal_operator_lineage_review(
                status=review_status,
                reviewed_model_ids=reviewed_ids,
                rationale="Operator rejected the proposed lineage mapping.",
                reviewed_by="operator",
                reviewed_at=_NOW,
                evidence_sha256=_sha(f"lineage-evidence-{root_index}"),
            )
        else:
            reviews[root_index] = seal_operator_lineage_review(
                status=review_status,
                reviewed_model_ids=reviewed_ids,
                root_lineage=_root(root_index),
                rationale="Operator approved one independently reviewed root lineage.",
                reviewed_by="operator",
                reviewed_at=_NOW,
                evidence_sha256=_sha(f"lineage-evidence-{root_index}"),
            )
    candidates = tuple(
        CandidateModel(
            exact_model_id=model_id,
            canonical_model_slug=model_id,
            root_lineage=(
                _root(index % root_count) if review_status is LineageReviewStatus.APPROVED else None
            ),
            lineage_review=reviews[index % root_count],
            discovery_evidence_sha256=_sha(f"discovery-{model_id}"),
            approved_provider_endpoint=f"provider-{index}",
            approved_provider_name=f"Approved Provider {index}",
            endpoint_snapshot_sha256=_sha(f"endpoint-{model_id}"),
            model_metadata_snapshot_sha256=_sha(f"metadata-{model_id}"),
            pricing_snapshot_sha256=_sha(f"pricing-{model_id}"),
            context_size=100_000,
            output_limit=8_192,
            structured_output_supported=True,
            reasoning_supported=True,
            zdr_eligible=True,
            data_collection_deny_eligible=True,
            operational_status=CandidateOperationalStatus.AVAILABLE,
            benchmark_status=CandidateBenchmarkStatus.PASSED,
            benchmark_artifact_sha256=_sha(f"report-{model_id}"),
            qualification_expires_at=_NOW + timedelta(days=validity_days),
            approved_roles=_ROLES,
        )
        for index, model_id in enumerate(model_ids)
    )
    registry = seal_candidate_registry(
        created_at=_NOW,
        discovery_run_sha256=_sha("discovery-run"),
        candidates=candidates,
    )
    policy = seal_qualification_policy(
        created_at=_NOW,
        thresholds=tuple(
            QualificationDimensionThreshold(
                dimension=dimension,
                minimum_cases=1,
                minimum_score=1,
            )
            for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
        ),
        tier_a_minimum_overall_score=1,
        maximum_validity_days=30,
    )
    bindings = QualificationBindings(
        source_commit="1" * 40,
        source_tree_sha256=_sha("source-tree"),
        effective_config_sha256=_sha("effective-config"),
        prompt_sha256=_sha("benchmark-prompt"),
        response_schema_sha256=_sha("response-schema"),
        toolchain_sha256=_sha("toolchain"),
        isolation_sha256=_sha("isolation"),
        benchmark_corpus_version="2.0",
        benchmark_corpus_sha256=_sha("corpus"),
        benchmark_ground_truth_version="2.0",
        benchmark_ground_truth_sha256=_sha("ground-truth"),
        benchmark_portfolio_sha256=_sha("benchmark-portfolio"),
        candidate_registry_sha256=registry.registry_sha256,
        qualification_policy_sha256=policy.policy_sha256,
    )
    dimensions = _dimension_results(failed_dimension=failed_dimension)
    real_benchmark_evidence = tuple(
        _test_trusted_benchmark_evidence(
            candidate=candidate,
            report_sha256=_sha(f"report-{candidate.exact_model_id}"),
            corpus_sha256=bindings.benchmark_corpus_sha256,
            ground_truth_sha256=bindings.benchmark_ground_truth_sha256,
            prompt_sha256=bindings.prompt_sha256,
            response_schema_sha256=bindings.response_schema_sha256,
            parsed_responses_sha256=_sha(f"parsed-{candidate.exact_model_id}"),
            case_ids=(f"case-{index}",),
            usage_records=(
                _usage_record(
                    candidate=candidate,
                    role="model_benchmark",
                    request_id=f"benchmark-{index}",
                ),
            ),
            dimensions=dimensions,
        )
        for index, candidate in enumerate(candidates)
    )
    benchmark_evidence = (
        real_benchmark_evidence
        if benchmark_execution is ExecutionEvidenceKind.REAL
        else tuple(
            evidence.model_copy(
                update={
                    "usage_records": tuple(
                        record.model_copy(update={"execution_evidence": benchmark_execution})
                        for record in evidence.usage_records
                    )
                }
            )
            for evidence in real_benchmark_evidence
        )
    )
    results = tuple(
        seal_model_qualification_result(
            exact_model_id=candidate.exact_model_id,
            canonical_model_slug=candidate.canonical_model_slug,
            root_lineage=candidate.root_lineage,
            approved_provider_endpoint=candidate.approved_provider_endpoint,
            approved_provider_name=candidate.approved_provider_name,
            endpoint_snapshot_sha256=candidate.endpoint_snapshot_sha256,
            model_metadata_snapshot_sha256=candidate.model_metadata_snapshot_sha256,
            pricing_snapshot_sha256=candidate.pricing_snapshot_sha256,
            benchmark_report_sha256=evidence.benchmark_report_sha256,
            benchmark_verification_sha256=evidence.verification_sha256,
            disposition=QualificationDisposition.TIER_A,
            dimensions=dimensions,
            overall_score=round(
                sum(result.score for result in dimensions) / len(dimensions),
                6,
            ),
            approved_roles=candidate.approved_roles,
            evaluated_at=_NOW + timedelta(hours=1),
            expires_at=_NOW + timedelta(days=validity_days),
        )
        for candidate, evidence in zip(candidates, benchmark_evidence, strict=True)
    )
    artifact = seal_model_qualification_artifact(
        created_at=_NOW + timedelta(hours=2),
        bindings=bindings,
        results=results,
    )
    verification = verify_model_qualification(
        artifact=artifact,
        registry=registry,
        policy=policy,
        expected_bindings=bindings,
        trusted_benchmark_evidence=benchmark_evidence,
        now=_NOW + timedelta(hours=3),
    )
    selection: ProductionModelSelection | None = None
    selection_verification: SelectionVerification | None = None
    if verification.valid and verification.production_selection_ready:
        selection = seal_production_selection(
            artifact=artifact,
            verification=verification,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            selected_at=_NOW + timedelta(hours=3),
        )
        selection_verification = verify_production_selection(
            selection=selection,
            artifact=artifact,
            qualification_verification=verification,
            expected_production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=4),
        )
    return _Bundle(
        registry=registry,
        policy=policy,
        bindings=bindings,
        benchmark_evidence=benchmark_evidence,
        artifact=artifact,
        verification=verification,
        selection=selection,
        selection_verification=selection_verification,
    )


def _resolve_for_test(
    bundle: _Bundle,
    *,
    fresh_evidence: tuple[TrustedBenchmarkVerificationEvidence, ...] | None = None,
    **overrides: object,
) -> VerifiedProductionQualification:
    """Exercise resolver logic while the fresh-provider boundary is tested separately."""

    arguments: dict[str, object] = {
        "artifact": bundle.artifact,
        "registry": bundle.registry,
        "policy": bundle.policy,
        "expected_bindings": bundle.bindings,
        "benchmark_reports": (),
        "benchmark_corpus": None,
        "trusted_campaign_verification": object(),
        "trusted_generation_verification": None,
        "trusted_release_observation": synthetic_release_observation(
            bundle.bindings,
            observed_at=_NOW + timedelta(hours=3),
        ),
        "production_effective_config_sha256": _PRODUCTION_CONFIG_SHA256,
        "now": _NOW + timedelta(hours=3),
    }
    arguments.update(overrides)
    with (
        patch("mmaudit.models.qualification._require_live_campaign_content_provenance"),
        patch(
            "mmaudit.models.qualification._freshly_reverify_production_benchmarks",
            return_value=(bundle.benchmark_evidence if fresh_evidence is None else fresh_evidence),
        ),
    ):
        return resolve_verified_production_qualification(**arguments)  # type: ignore[arg-type]


def test_pending_lineage_review_loads_and_tier_a_scores_but_is_not_eligible(
    tmp_path: Path,
) -> None:
    bundle = _bundle(review_status=LineageReviewStatus.PENDING)
    path = tmp_path / "candidates.json"
    path.write_text(
        json.dumps(bundle.registry.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )

    loaded = load_candidate_registry(path)

    assert loaded == bundle.registry
    assert bundle.verification.valid
    assert not bundle.verification.production_selection_ready
    assert bundle.verification.eligible_tier_a_model_ids == ()
    assert all(
        result.disposition is QualificationDisposition.TIER_A for result in bundle.artifact.results
    )
    with pytest.raises(ValueError, match="not ready for production selection"):
        seal_production_selection(
            artifact=bundle.artifact,
            verification=bundle.verification,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            selected_at=_NOW + timedelta(hours=3),
        )


def test_rejected_lineage_review_is_not_production_eligible() -> None:
    bundle = _bundle(review_status=LineageReviewStatus.REJECTED)

    assert bundle.verification.valid
    assert bundle.verification.eligible_tier_a_model_ids == ()
    assert bundle.verification.eligible_root_lineages == ()


def test_unapproved_candidate_cannot_assign_a_root_lineage() -> None:
    bundle = _bundle(review_status=LineageReviewStatus.PENDING)
    candidate = bundle.registry.candidates[0]

    with pytest.raises(ValidationError, match="cannot assign"):
        CandidateModel.model_validate(
            {
                **candidate.model_dump(mode="json"),
                "root_lineage": _root(0),
            }
        )


def test_qualification_policy_rejects_an_empty_dimension() -> None:
    bundle = _bundle()
    payload = bundle.policy.model_dump(mode="json", exclude={"policy_sha256"})
    payload["thresholds"] = payload["thresholds"][:-1]
    payload["policy_sha256"] = canonical_sha256(payload)

    with pytest.raises(
        ValidationError,
        match=r"at least 17 items|cover every dimension",
    ):
        QualificationPolicy.model_validate(payload)


def test_complete_real_tier_a_artifact_and_all_eligible_selection_verify() -> None:
    bundle = _bundle()

    assert bundle.verification.valid
    assert bundle.verification.production_selection_ready
    assert len(bundle.verification.eligible_tier_a_model_ids) == 8
    assert len(bundle.verification.eligible_root_lineages) == 6
    assert bundle.selection is not None
    assert bundle.selection_verification is not None
    assert bundle.selection_verification.valid
    assert {model.exact_model_id for model in bundle.selection.models} == set(
        bundle.verification.eligible_tier_a_model_ids
    )


def test_verified_production_capability_is_opaque_current_and_exact() -> None:
    bundle = _bundle()
    verified_at = _NOW + timedelta(hours=3)

    capability = _resolve_for_test(
        bundle,
        production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
        now=verified_at,
    )

    assert capability.require_current(now=verified_at) is capability
    assert capability.bindings == bundle.bindings
    assert capability.expected_bindings_sha256 == canonical_sha256(
        bundle.bindings.model_dump(mode="json")
    )
    assert capability.artifact_sha256 == bundle.artifact.artifact_sha256
    assert capability.qualification_verification_sha256 == (bundle.verification.verification_sha256)
    assert capability.production_effective_config_sha256 == _PRODUCTION_CONFIG_SHA256
    assert bundle.selection is not None
    assert bundle.selection.production_effective_config_sha256 == _PRODUCTION_CONFIG_SHA256
    assert capability.production_selection_sha256 == bundle.selection.selection_sha256
    selection_verification = verify_production_selection(
        selection=bundle.selection,
        artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        expected_production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
        now=verified_at,
    )
    assert capability.selection_verification_sha256 == (selection_verification.verification_sha256)
    assert len(capability.models) == 8
    assert len({model.root_lineage for model in capability.models}) == 6
    expected_results = {result.exact_model_id: result for result in bundle.artifact.results}
    expected_evidence = {
        evidence.exact_model_id: evidence for evidence in bundle.benchmark_evidence
    }
    for model in capability.models:
        result = expected_results[model.exact_model_id]
        evidence = expected_evidence[model.exact_model_id]
        assert model.qualification_disposition is QualificationDisposition.TIER_A
        assert model.qualification_result_sha256 == result.result_sha256
        assert model.benchmark_report_sha256 == result.benchmark_report_sha256
        assert model.benchmark_verification_sha256 == (result.benchmark_verification_sha256)
        assert model.fresh_benchmark_evidence_sha256 == evidence.fresh_evidence_sha256
        assert model.endpoint_snapshot_sha256 == result.endpoint_snapshot_sha256
        assert model.model_metadata_snapshot_sha256 == (result.model_metadata_snapshot_sha256)
        assert model.pricing_snapshot_sha256 == result.pricing_snapshot_sha256
        assert model.approved_roles == result.approved_roles
        assert model.expires_at == result.expires_at
        assert model.quality_measurement_sha256 == result.quality_measurement_sha256
        assert model.quality_measurement == f"sha256:{result.quality_measurement_sha256}"
        assert model.benchmark_case_count > 0
    assert capability.model_for(_model_id(0), now=verified_at).exact_model_id == _model_id(0)
    assert len(capability.production_selection_sha256) == 64
    assert len(capability.selection_verification_sha256) == 64
    assert len(capability.capability_sha256) == 64
    with pytest.raises(FrozenInstanceError):
        capability.models = ()  # type: ignore[misc]
    with pytest.raises(TypeError, match="only be issued"):
        VerifiedProductionQualification()
    with pytest.raises(ValueError, match="lacks verified"):
        capability.model_for("other/unqualified-model-1", now=verified_at)
    with pytest.raises(ValueError, match="expired"):
        capability.require_current(now=capability.expires_at)
    object.__setattr__(capability, "capability_sha256", _sha("tampered-capability"))
    with pytest.raises(ValueError, match="integrity"):
        capability.require_current(now=verified_at)


def test_verified_production_capability_records_fresh_full_benchmark_evidence() -> None:
    bundle = _bundle()
    historical = bundle.benchmark_evidence[0]
    refreshed_attestations = []
    for attestation in historical.generation_attestations:
        payload = attestation.model_dump(mode="json", exclude={"evidence_sha256"})
        payload["retrieved_at"] = (
            (attestation.retrieved_at + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        )
        payload["evidence_sha256"] = canonical_sha256(payload)
        refreshed_attestations.append(OpenRouterGenerationEvidence.model_validate(payload))
    evidence_payload = historical.model_dump(mode="json")
    evidence_payload["generation_attestations"] = [
        item.model_dump(mode="json") for item in refreshed_attestations
    ]
    refreshed = TrustedBenchmarkVerificationEvidence.model_validate(evidence_payload)
    capability = _resolve_for_test(
        bundle,
        fresh_evidence=(refreshed, *bundle.benchmark_evidence[1:]),
        production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
        now=_NOW + timedelta(hours=3),
    )
    model = capability.model_for(historical.exact_model_id, now=_NOW + timedelta(hours=3))

    assert refreshed.stable_measurement_sha256 == historical.stable_measurement_sha256
    assert refreshed.fresh_evidence_sha256 != historical.fresh_evidence_sha256
    assert model.benchmark_verification_sha256 == historical.stable_measurement_sha256
    assert model.fresh_benchmark_evidence_sha256 == refreshed.fresh_evidence_sha256


def test_verified_qualification_capabilities_are_process_local_and_issuer_bound() -> None:
    capability = _resolve_for_test(_bundle())
    model = capability.models[0]

    for value in (capability, model):
        with pytest.raises(TypeError, match=r"cannot be (?:copied|serialized)"):
            copy.copy(value)
        with pytest.raises(TypeError, match=r"cannot be (?:copied|serialized)"):
            copy.deepcopy(value)
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(value)

    forged = object.__new__(VerifiedProductionQualification)
    with pytest.raises(ValueError, match="invalid capability type"):
        forged.require_current(now=_NOW + timedelta(hours=3))
    reconstructed = object.__new__(VerifiedProductionQualification)
    for field_name in capability.__dataclass_fields__:
        object.__setattr__(reconstructed, field_name, getattr(capability, field_name))
    with pytest.raises(ValueError, match="invalid capability type"):
        reconstructed.require_current(now=_NOW + timedelta(hours=3))

    forged_model = object.__new__(VerifiedTierAModelQualification)
    object.__setattr__(capability, "models", (forged_model, *capability.models[1:]))
    with pytest.raises(ValueError, match="invalid model type"):
        capability.require_current(now=_NOW + timedelta(hours=3))


def test_expired_qualification_cannot_be_revived_with_backdated_resolver_time() -> None:
    bundle = _bundle()
    observed_at = _NOW + timedelta(days=8)
    observation = synthetic_release_observation(
        bundle.bindings,
        observed_at=observed_at,
    )

    with pytest.raises(ValueError, match="trusted release observation"):
        _resolve_for_test(
            bundle,
            trusted_release_observation=observation,
            now=_NOW + timedelta(hours=3),
        )
    with pytest.raises(ValueError, match="expired"):
        _resolve_for_test(
            bundle,
            trusted_release_observation=observation,
            now=observed_at,
        )


def test_quality_measurement_is_stable_across_verification_and_time_refresh() -> None:
    original = _bundle().artifact.results[0]
    refreshed = seal_model_qualification_result(
        exact_model_id=original.exact_model_id,
        canonical_model_slug=original.canonical_model_slug,
        root_lineage=original.root_lineage,
        approved_provider_endpoint=original.approved_provider_endpoint,
        approved_provider_name=original.approved_provider_name,
        endpoint_snapshot_sha256=original.endpoint_snapshot_sha256,
        model_metadata_snapshot_sha256=original.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=original.pricing_snapshot_sha256,
        benchmark_report_sha256=original.benchmark_report_sha256,
        benchmark_verification_sha256=_sha("fresh-verification"),
        disposition=original.disposition,
        dimensions=original.dimensions,
        overall_score=original.overall_score,
        approved_roles=original.approved_roles,
        evaluated_at=original.evaluated_at + timedelta(days=1),
        expires_at=original.expires_at + timedelta(days=1) if original.expires_at else None,
    )

    assert refreshed.quality_measurement_sha256 == original.quality_measurement_sha256
    assert refreshed.result_sha256 != original.result_sha256


def test_fresh_production_reverification_replays_and_rescores_frozen_workflow() -> None:
    from tests.unit import test_qualification_workflow as workflow_fixtures

    manifest, discovery_evidence, registry = workflow_fixtures._candidate_inputs()
    report = workflow_fixtures._as_real_report(
        asyncio.run(workflow_fixtures._mock_report()),
        candidate=registry.candidates[0],
    )
    portfolio, campaign_verification = workflow_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
    )
    requests = candidate_generation_verification_requests(
        registry=registry,
        benchmark_reports=(report,),
    )
    attestations = tuple(
        case.generation_evidence
        for case in report.results[0].cases
        if case.generation_evidence is not None
    )
    trusted_generation_verification = (
        generation_evidence_module._issue_trusted_generation_verification(
            requests=requests,
            attestations=attestations,
            verification_started_at=min(item.retrieved_at for item in attestations),
        )
    )
    corpus = load_model_benchmark_corpus(_ROOT / "benchmarks" / "model_corpus" / "manifest.json")
    release_bindings = workflow_fixtures._release_bindings(report)
    workflow = run_qualification_workflow(
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        discovery_evidence=discovery_evidence,
        policy=workflow_fixtures._policy(),
        benchmark_suite=corpus,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        release_bindings=release_bindings,
        trusted_campaign_verification=campaign_verification,
        trusted_generation_verification=trusted_generation_verification,
        trusted_release_observation=synthetic_release_observation(
            release_bindings,
            observed_at=workflow_fixtures.NOW + timedelta(hours=1),
        ),
        evaluated_at=workflow_fixtures.NOW + timedelta(hours=1),
        qualification_expires_at=workflow_fixtures.NOW + timedelta(days=6),
    )

    refreshed_attestations = []
    for attestation in attestations:
        payload = attestation.model_dump(mode="json", exclude={"evidence_sha256"})
        payload["retrieved_at"] = (
            (attestation.retrieved_at + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        )
        payload["evidence_sha256"] = canonical_sha256(payload)
        refreshed_attestations.append(OpenRouterGenerationEvidence.model_validate(payload))
    refreshed_generation_verification = (
        generation_evidence_module._issue_trusted_generation_verification(
            requests=requests,
            attestations=tuple(refreshed_attestations),
            verification_started_at=min(item.retrieved_at for item in refreshed_attestations),
        )
    )
    freshly_verified = _freshly_reverify_production_benchmarks(
        artifact=workflow.qualification_artifact,
        registry=workflow.updated_registry,
        benchmark_reports=workflow.benchmark_reports,
        benchmark_corpus=corpus,
        trusted_generation_verification=refreshed_generation_verification,
    )

    assert freshly_verified[0].verification_sha256 == (
        workflow.trusted_benchmark_evidence[0].verification_sha256
    )
    assert freshly_verified[0].stable_measurement_sha256 == (
        workflow.trusted_benchmark_evidence[0].stable_measurement_sha256
    )
    assert freshly_verified[0].fresh_evidence_sha256 != (
        workflow.trusted_benchmark_evidence[0].fresh_evidence_sha256
    )
    assert freshly_verified[0].generation_attestations != (
        workflow.trusted_benchmark_evidence[0].generation_attestations
    )
    assert all(evidence.case_ids for evidence in freshly_verified)
    assert all(
        evidence.execution_evidence is ExecutionEvidenceKind.REAL for evidence in freshly_verified
    )


def test_fresh_production_reverification_rejects_self_declared_benchmark_versions() -> None:
    from tests.unit import test_qualification_workflow as workflow_fixtures

    manifest, discovery_evidence, registry = workflow_fixtures._candidate_inputs()
    report = workflow_fixtures._as_real_report(
        asyncio.run(workflow_fixtures._mock_report()),
        candidate=registry.candidates[0],
    )
    portfolio, campaign_verification = workflow_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
    )
    requests = candidate_generation_verification_requests(
        registry=registry,
        benchmark_reports=(report,),
    )
    attestations = tuple(
        case.generation_evidence
        for case in report.results[0].cases
        if case.generation_evidence is not None
    )
    trusted_generation_verification = (
        generation_evidence_module._issue_trusted_generation_verification(
            requests=requests,
            attestations=attestations,
            verification_started_at=min(item.retrieved_at for item in attestations),
        )
    )
    corpus = load_model_benchmark_corpus(_ROOT / "benchmarks" / "model_corpus" / "manifest.json")
    release_bindings = workflow_fixtures._release_bindings(report)
    workflow = run_qualification_workflow(
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        discovery_evidence=discovery_evidence,
        policy=workflow_fixtures._policy(),
        benchmark_suite=corpus,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        release_bindings=release_bindings,
        trusted_campaign_verification=campaign_verification,
        trusted_generation_verification=trusted_generation_verification,
        trusted_release_observation=synthetic_release_observation(
            release_bindings,
            observed_at=workflow_fixtures.NOW + timedelta(hours=1),
        ),
        evaluated_at=workflow_fixtures.NOW + timedelta(hours=1),
        qualification_expires_at=workflow_fixtures.NOW + timedelta(days=6),
    )

    for binding_name in (
        "benchmark_corpus_version",
        "benchmark_ground_truth_version",
    ):
        mismatched_bindings = QualificationBindings.model_validate(
            workflow.qualification_artifact.bindings.model_copy(
                update={binding_name: "self-declared-version"}
            ).model_dump(mode="json")
        )
        mismatched_artifact = seal_model_qualification_artifact(
            created_at=workflow.qualification_artifact.created_at,
            bindings=mismatched_bindings,
            results=workflow.qualification_artifact.results,
        )

        with pytest.raises(ValueError, match="corpus differs from qualification bindings"):
            _freshly_reverify_production_benchmarks(
                artifact=mismatched_artifact,
                registry=workflow.updated_registry,
                benchmark_reports=workflow.benchmark_reports,
                benchmark_corpus=corpus,
                trusted_generation_verification=trusted_generation_verification,
            )


def test_serialized_qualification_bundle_alone_cannot_mint_production_capability() -> None:
    bundle = _bundle()
    corpus = load_model_benchmark_corpus(_ROOT / "benchmarks" / "model_corpus" / "manifest.json")

    with pytest.raises(ValueError, match="live response-content campaign provenance"):
        resolve_verified_production_qualification(
            artifact=bundle.artifact,
            registry=bundle.registry,
            policy=bundle.policy,
            expected_bindings=bundle.bindings,
            benchmark_reports=(),
            benchmark_corpus=corpus,
            trusted_campaign_verification=None,
            trusted_generation_verification=None,  # type: ignore[arg-type]
            trusted_release_observation=synthetic_release_observation(
                bundle.bindings,
                observed_at=_NOW + timedelta(hours=3),
            ),
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )


def test_verified_production_capability_rejects_shape_staleness_and_binding_mismatch() -> None:
    bundle = _bundle()

    with pytest.raises(ValueError, match="production effective configuration hash"):
        _resolve_for_test(
            bundle,
            production_effective_config_sha256="not-a-hash",
            now=_NOW + timedelta(hours=3),
        )
    with pytest.raises(ValueError, match="fully validated typed value"):
        _resolve_for_test(
            bundle,
            artifact=_sha("shape-only"),  # type: ignore[arg-type]
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )
    with pytest.raises(ValueError, match="expired"):
        expired_at = _NOW + timedelta(days=21)
        _resolve_for_test(
            bundle,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            trusted_release_observation=synthetic_release_observation(
                bundle.bindings,
                observed_at=expired_at,
            ),
            now=expired_at,
        )
    mismatched = bundle.bindings.model_copy(
        update={"source_tree_sha256": _sha("different-source-tree")}
    )
    with pytest.raises(ValueError, match="differs from qualification bindings"):
        _resolve_for_test(
            bundle,
            expected_bindings=mismatched,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )


def test_verified_production_capability_rejects_failed_or_incomplete_evidence() -> None:
    failed_threshold = _bundle(failed_dimension=ModelBenchmarkDimension.ACCESS_CONTROL)
    with pytest.raises(ValueError, match="thresholds"):
        _resolve_for_test(
            failed_threshold,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )

    bundle = _bundle()
    with pytest.raises(ValueError, match="exact non-empty benchmark evidence"):
        _resolve_for_test(
            bundle,
            fresh_evidence=bundle.benchmark_evidence[:-1],
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )
    empty_cases = bundle.benchmark_evidence[0].model_copy(
        update={"case_ids": (), "usage_records": ()}
    )
    with pytest.raises(ValueError):
        _resolve_for_test(
            bundle,
            fresh_evidence=(empty_cases, *bundle.benchmark_evidence[1:]),
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )
    non_real = _bundle(benchmark_execution=ExecutionEvidenceKind.MOCK)
    with pytest.raises(ValueError):
        _resolve_for_test(
            non_real,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )


def test_verified_production_capability_rejects_inconclusive_artifact_result() -> None:
    bundle = _bundle()
    original = bundle.artifact.results[0]
    incomplete = seal_model_qualification_result(
        exact_model_id=original.exact_model_id,
        canonical_model_slug=original.canonical_model_slug,
        root_lineage=original.root_lineage,
        approved_provider_endpoint=original.approved_provider_endpoint,
        approved_provider_name=original.approved_provider_name,
        endpoint_snapshot_sha256=original.endpoint_snapshot_sha256,
        model_metadata_snapshot_sha256=original.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=original.pricing_snapshot_sha256,
        benchmark_report_sha256=original.benchmark_report_sha256,
        benchmark_verification_sha256=None,
        disposition=QualificationDisposition.INCONCLUSIVE,
        dimensions=(),
        overall_score=0.0,
        approved_roles=original.approved_roles,
        evaluated_at=original.evaluated_at,
        expires_at=None,
        failure_reasons=("synthetic_incomplete_verification",),
    )
    artifact = seal_model_qualification_artifact(
        created_at=bundle.artifact.created_at,
        bindings=bundle.bindings,
        results=(incomplete, *bundle.artifact.results[1:]),
    )

    with pytest.raises(ValueError, match="cannot contain incomplete"):
        _resolve_for_test(
            bundle,
            artifact=artifact,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            now=_NOW + timedelta(hours=3),
        )


@pytest.mark.parametrize("mode", ["missing", "mock"])
def test_unresolved_or_mock_benchmark_evidence_cannot_validate(mode: str) -> None:
    bundle = _bundle(
        benchmark_execution=(
            ExecutionEvidenceKind.MOCK if mode == "mock" else ExecutionEvidenceKind.REAL
        )
    )
    evidence = () if mode == "missing" else bundle.benchmark_evidence

    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=bundle.policy,
        expected_bindings=bundle.bindings,
        trusted_benchmark_evidence=evidence,
        now=_NOW + timedelta(hours=3),
    )

    assert not verification.valid
    assert verification.eligible_tier_a_model_ids == () or mode == "mock"
    assert any(
        "trusted benchmark evidence is missing" in error or "certification-grade" in error
        for error in verification.errors
    )


def test_one_failed_dimension_cannot_be_hidden_by_the_aggregate() -> None:
    bundle = _bundle(
        failed_dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
    )

    assert not bundle.verification.valid
    assert any("Tier A thresholds" in error for error in bundle.verification.errors)


def test_missing_generation_attestation_invalidates_trusted_benchmark_evidence() -> None:
    bundle = _bundle()
    malformed = tuple(
        (evidence.model_copy(update={"generation_attestations": ()}) if index == 0 else evidence)
        for index, evidence in enumerate(bundle.benchmark_evidence)
    )

    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=bundle.policy,
        expected_bindings=bundle.bindings,
        trusted_benchmark_evidence=malformed,
        now=_NOW + timedelta(hours=3),
    )

    assert not verification.valid
    assert not verification.production_selection_ready
    assert _model_id(0) not in verification.eligible_tier_a_model_ids
    assert "trusted benchmark evidence is schema-invalid" in verification.errors


def test_private_ground_truth_hash_is_required_at_qualification_boundary() -> None:
    bundle = _bundle()
    original = bundle.benchmark_evidence[0]
    payload = original.model_dump(mode="json", exclude={"verification_sha256"})
    payload["benchmark_ground_truth_sha256"] = _sha("different-ground-truth")
    payload["verification_sha256"] = canonical_sha256(
        {
            **payload,
            "generation_attestations": [
                _stable_generation_binding(item) for item in original.generation_attestations
            ],
        }
    )
    mismatched = TrustedBenchmarkVerificationEvidence.model_validate(payload)
    evidence = (mismatched, *bundle.benchmark_evidence[1:])

    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=bundle.policy,
        expected_bindings=bundle.bindings,
        trusted_benchmark_evidence=evidence,
        now=_NOW + timedelta(hours=3),
    )

    assert not verification.valid
    assert _model_id(0) not in verification.eligible_tier_a_model_ids
    assert any("independently verified benchmark" in error for error in verification.errors)


def test_candidate_benchmark_metadata_must_match_qualification_result() -> None:
    bundle = _bundle()
    candidates = list(bundle.registry.candidates)
    candidates[0] = candidates[0].model_copy(
        update={"benchmark_artifact_sha256": _sha("different-report")}
    )
    registry = seal_candidate_registry(
        created_at=bundle.registry.created_at,
        discovery_run_sha256=bundle.registry.discovery_run_sha256,
        candidates=tuple(candidates),
    )
    bindings = bundle.bindings.model_copy(
        update={"candidate_registry_sha256": registry.registry_sha256}
    )
    artifact = seal_model_qualification_artifact(
        created_at=bundle.artifact.created_at,
        bindings=bindings,
        results=bundle.artifact.results,
    )

    verification = verify_model_qualification(
        artifact=artifact,
        registry=registry,
        policy=bundle.policy,
        expected_bindings=bindings,
        trusted_benchmark_evidence=bundle.benchmark_evidence,
        now=_NOW + timedelta(hours=3),
    )

    assert not verification.valid
    assert _model_id(0) not in verification.eligible_tier_a_model_ids
    assert any("benchmark report hash differs" in error for error in verification.errors)


@pytest.mark.parametrize(
    "model_id",
    (
        "openrouter/auto",
        "author/model-free",
        "author/model:latest",
        "author/model_online",
        "author/model.random",
        "author/model-router",
    ),
)
def test_mutable_or_router_aliases_cannot_enter_candidate_registry(model_id: str) -> None:
    candidate = _bundle().registry.candidates[0]
    payload = candidate.model_dump(mode="json")
    payload["exact_model_id"] = model_id
    payload["canonical_model_slug"] = model_id

    with pytest.raises(ValidationError, match="exact non-routed"):
        CandidateModel.model_validate(payload)


def test_candidate_registry_rejects_overlapping_lineage_review_groups() -> None:
    bundle = _bundle(review_status=LineageReviewStatus.PENDING)
    candidates = list(bundle.registry.candidates)
    affected_ids = tuple(
        sorted(
            {
                _model_id(0),
                *candidates[1].lineage_review.reviewed_model_ids,
            }
        )
    )
    overlapping = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=affected_ids,
        rationale="Synthetic overlapping review group must be rejected.",
    )
    for index, candidate in enumerate(candidates):
        if candidate.exact_model_id in candidates[1].lineage_review.reviewed_model_ids:
            candidates[index] = candidate.model_copy(update={"lineage_review": overlapping})

    with pytest.raises(ValidationError, match="review groups overlap"):
        seal_candidate_registry(
            created_at=bundle.registry.created_at,
            discovery_run_sha256=bundle.registry.discovery_run_sha256,
            candidates=tuple(candidates),
        )


def test_candidate_registry_rejects_reviewed_model_outside_candidate_set() -> None:
    bundle = _bundle(review_status=LineageReviewStatus.PENDING)
    candidates = list(bundle.registry.candidates)
    original_review = candidates[0].lineage_review
    expanded = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=tuple(sorted((*original_review.reviewed_model_ids, "other/model-99"))),
        rationale="Synthetic out-of-set review member must be rejected.",
    )
    for index, candidate in enumerate(candidates):
        if candidate.exact_model_id in original_review.reviewed_model_ids:
            candidates[index] = candidate.model_copy(update={"lineage_review": expanded})

    with pytest.raises(ValidationError, match="candidate set exactly once"):
        seal_candidate_registry(
            created_at=bundle.registry.created_at,
            discovery_run_sha256=bundle.registry.discovery_run_sha256,
            candidates=tuple(candidates),
        )


def test_candidate_registry_rejects_duplicate_canonical_slug_lineage_inflation() -> None:
    bundle = _bundle()
    candidates = list(bundle.registry.candidates)
    candidates[1] = candidates[1].model_copy(
        update={"canonical_model_slug": candidates[0].canonical_model_slug}
    )

    with pytest.raises(ValidationError, match="canonical model slug"):
        seal_candidate_registry(
            created_at=bundle.registry.created_at,
            discovery_run_sha256=bundle.registry.discovery_run_sha256,
            candidates=tuple(candidates),
        )


def test_one_model_one_root_verification_cannot_be_selected() -> None:
    bundle = _bundle()
    payload = bundle.verification.model_dump(
        mode="json",
        exclude={"verification_sha256"},
    )
    payload["eligible_tier_a_model_ids"] = [bundle.verification.eligible_tier_a_model_ids[0]]
    payload["eligible_root_lineages"] = [bundle.verification.eligible_root_lineages[0]]
    payload["production_selection_ready"] = False
    payload["verification_sha256"] = canonical_sha256(payload)
    undersized = QualificationVerification.model_validate(payload)

    assert undersized.valid
    assert not undersized.production_selection_ready
    with pytest.raises(ValueError, match="not ready"):
        seal_production_selection(
            artifact=bundle.artifact,
            verification=undersized,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            selected_at=_NOW + timedelta(hours=3),
        )


def test_wrong_release_binding_fails_closed() -> None:
    bundle = _bundle()
    mismatched = bundle.bindings.model_copy(update={"source_tree_sha256": _sha("different-source")})

    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=bundle.policy,
        expected_bindings=mismatched,
        trusted_benchmark_evidence=bundle.benchmark_evidence,
        now=_NOW + timedelta(hours=3),
    )

    assert not verification.valid
    assert "qualification bindings differ from expected release inputs" in verification.errors


def test_expired_or_excessively_long_tier_a_evidence_fails_closed() -> None:
    expired = _bundle(validity_days=0)
    stale_window = _bundle(validity_days=8)
    excessive = _bundle(validity_days=31)

    assert not expired.verification.valid
    assert any("expired" in error for error in expired.verification.errors)
    assert not stale_window.verification.valid
    assert any(
        "benchmark evidence window exceeds policy" in error
        for error in stale_window.verification.errors
    )
    assert not excessive.verification.valid
    assert any("validity exceeds policy" in error for error in excessive.verification.errors)


def test_selection_verifier_rejects_omission_and_expiry() -> None:
    bundle = _bundle()
    assert bundle.selection is not None
    payload = bundle.selection.model_dump(mode="json", exclude={"selection_sha256"})
    payload["models"] = payload["models"][:-1]
    payload["selection_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValidationError, match="at least 8 items"):
        ProductionModelSelection.model_validate(payload)
    expired = verify_production_selection(
        selection=bundle.selection,
        artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        expected_production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
        now=_NOW + timedelta(days=21),
    )

    assert not expired.valid
    assert "production selection is expired" in expired.errors

    wrong_production_config = verify_production_selection(
        selection=bundle.selection,
        artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        expected_production_effective_config_sha256=_sha("wrong-production-config"),
        now=_NOW + timedelta(hours=4),
    )
    assert not wrong_production_config.valid
    assert (
        "production selection binds a different effective configuration"
        in wrong_production_config.errors
    )


def _artifact_with_different_release_binding(bundle: _Bundle) -> ModelQualificationArtifact:
    bindings = QualificationBindings.model_validate(
        bundle.bindings.model_copy(
            update={"source_tree_sha256": _sha("different-selection-source-tree")}
        ).model_dump(mode="json")
    )
    return seal_model_qualification_artifact(
        created_at=bundle.artifact.created_at,
        bindings=bindings,
        results=bundle.artifact.results,
    )


def test_production_selection_rejects_cross_artifact_verification_splice() -> None:
    bundle = _bundle()
    different_artifact = _artifact_with_different_release_binding(bundle)

    with pytest.raises(ValueError, match="does not bind the supplied artifact"):
        seal_production_selection(
            artifact=different_artifact,
            verification=bundle.verification,
            production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
            selected_at=_NOW + timedelta(hours=3),
        )


def test_selection_verifier_rejects_cross_artifact_verification_splice() -> None:
    bundle = _bundle()
    assert bundle.selection is not None
    different_artifact = _artifact_with_different_release_binding(bundle)
    payload = bundle.selection.model_dump(mode="json", exclude={"selection_sha256"})
    payload["qualification_artifact_sha256"] = different_artifact.artifact_sha256
    payload["selection_sha256"] = canonical_sha256(payload)
    spliced_selection = ProductionModelSelection.model_validate(payload)

    verification = verify_production_selection(
        selection=spliced_selection,
        artifact=different_artifact,
        qualification_verification=bundle.verification,
        expected_production_effective_config_sha256=_PRODUCTION_CONFIG_SHA256,
        now=_NOW + timedelta(hours=4),
    )

    assert not verification.valid
    assert (
        "qualification verification binds a different qualification artifact" in verification.errors
    )


def test_ensemble_rejects_unrelated_valid_evidence_objects() -> None:
    bundle = _bundle()
    assert bundle.selection is not None
    different_artifact = _artifact_with_different_release_binding(bundle)
    records, _critical, _candidates, _falsifier = _production_evidence(bundle)
    rebound_records = tuple(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    "qualification_artifact_sha256": different_artifact.artifact_sha256,
                }
            }
        )
        for record in records
    )
    different_selection = seal_production_selection(
        artifact=bundle.artifact,
        verification=bundle.verification,
        production_effective_config_sha256=_sha("different-production-config"),
        selected_at=_NOW + timedelta(hours=4),
    )
    different_selection_verification = verify_production_selection(
        selection=different_selection,
        artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        expected_production_effective_config_sha256=_sha("different-production-config"),
        now=_NOW + timedelta(hours=5),
    )
    assert different_selection_verification.valid

    artifact_splice = _evaluate(
        bundle,
        artifact=different_artifact,
        usage_records=rebound_records,
    )
    selection_verification_splice = _evaluate(
        bundle,
        selection_verification=different_selection_verification,
    )

    assert not artifact_splice.passed
    assert (
        "qualification verification binds a different qualification artifact"
        in artifact_splice.errors
    )
    assert "production selection binds a different qualification artifact" in (
        artifact_splice.errors
    )
    assert not selection_verification_splice.passed
    assert (
        "selection verification binds a different production selection"
        in selection_verification_splice.errors
    )


def test_registry_loader_rejects_links_and_duplicate_json_keys(tmp_path: Path) -> None:
    bundle = _bundle()
    source = tmp_path / "registry.json"
    source.write_text(
        json.dumps(bundle.registry.model_dump(mode="json")),
        encoding="utf-8",
    )
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="link"):
        load_candidate_registry(linked)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_candidate_registry(duplicate)


def test_candidate_registry_rejects_mixed_discovery_run_provenance() -> None:
    manifest, evidence = _discovery_run(model_id="alpha/security-model", index=0)
    _, different_run_evidence = _discovery_run(
        model_id="beta/security-model",
        index=1,
    )
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=(evidence.exact_model_id,),
        rationale="Pending independent operator lineage adjudication.",
    )
    candidate = CandidateModel(
        exact_model_id=evidence.exact_model_id,
        canonical_model_slug=evidence.canonical_slug,
        root_lineage=None,
        lineage_review=review,
        discovery_evidence_sha256=evidence.discovery_evidence_sha256,
        approved_provider_endpoint=evidence.approved_provider_endpoint,
        approved_provider_name=evidence.provider_name,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot_sha256,
        model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=evidence.pricing_snapshot_sha256,
        context_size=evidence.context_size,
        output_limit=evidence.output_limit,
        structured_output_supported=evidence.structured_output_supported,
        reasoning_supported=evidence.reasoning_supported,
        zdr_eligible=evidence.zdr_eligible,
        data_collection_deny_eligible=evidence.data_collection_deny_eligible,
        operational_status=CandidateOperationalStatus.AVAILABLE,
        benchmark_status=CandidateBenchmarkStatus.PENDING,
    )
    registry = seal_candidate_registry(
        created_at=manifest.run_provenance.retrieved_at,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=(candidate,),
    )

    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=(evidence,),
    )
    with pytest.raises(ValueError, match="mixes discovery provenance"):
        validate_candidate_registry_discovery(
            registry=registry,
            run_manifest=manifest,
            evidence=(evidence, different_run_evidence),
        )


def _production_evidence(bundle: _Bundle):
    assert bundle.selection is not None
    candidates = {candidate.exact_model_id: candidate for candidate in bundle.registry.candidates}
    records: list[UsageRecord] = []
    specialist_request_ids: list[str] = []
    for index, role in enumerate(ALL_SPECIALIST_ROLES[:24]):
        candidate = candidates[_model_id(index % 8)]
        request_id = f"specialist-{index}"
        specialist_request_ids.append(request_id)
        records.append(
            _usage_record(
                candidate=candidate,
                role=f"specialist:{role}",
                request_id=request_id,
                qualification_artifact_sha256=bundle.artifact.artifact_sha256,
                production_selection_sha256=bundle.selection.selection_sha256,
            )
        )
    whole_request_ids: list[str] = []
    for index in range(4):
        candidate = candidates[_model_id(index)]
        request_id = f"whole-{index}"
        whole_request_ids.append(request_id)
        records.append(
            _usage_record(
                candidate=candidate,
                role=f"whole_protocol_review:{index}",
                request_id=request_id,
                qualification_artifact_sha256=bundle.artifact.artifact_sha256,
                production_selection_sha256=bundle.selection.selection_sha256,
            )
        )
    falsifier_request_ids: list[str] = []
    for index in range(2):
        candidate = candidates[_model_id(index)]
        request_id = f"falsifier-{index}"
        falsifier_request_ids.append(request_id)
        records.append(
            _usage_record(
                candidate=candidate,
                role=candidate_falsifier_role("candidate-high", index + 1),
                request_id=request_id,
                qualification_artifact_sha256=bundle.artifact.artifact_sha256,
                production_selection_sha256=bundle.selection.selection_sha256,
            )
        )
    critical = (
        CriticalSurfaceReviewEvidence(
            surface_id="surface-critical",
            review_artifact_sha256=_sha("surface-review"),
            request_ids=tuple(whole_request_ids[:3]),
        ),
    )
    falsifier = (
        CandidateFalsifierEvidence(
            candidate_id="candidate-high",
            cross_examination_sha256=_sha("cross-examination"),
            request_ids=tuple(falsifier_request_ids),
        ),
    )
    return (
        tuple(_bind_ensemble_usage(bundle, record) for record in records),
        critical,
        ("candidate-high",),
        falsifier,
    )


def _bind_ensemble_usage(bundle: _Bundle, record: UsageRecord) -> UsageRecord:
    assert bundle.selection is not None
    assert bundle.selection_verification is not None
    selected = next(
        model for model in bundle.selection.models if model.exact_model_id == record.requested_model
    )
    result = next(
        result
        for result in bundle.artifact.results
        if result.exact_model_id == record.requested_model
    )
    assert result.expires_at is not None
    rebound = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "qualified_exact_model_id": selected.exact_model_id,
                "qualified_canonical_model_slug": selected.canonical_model_slug,
                "qualified_root_lineage": selected.root_lineage,
                "qualified_provider_endpoint": selected.approved_provider_endpoint,
                "qualified_provider_name": selected.approved_provider_name,
                "qualified_endpoint_snapshot_sha256": result.endpoint_snapshot_sha256,
                "qualified_model_metadata_snapshot_sha256": (result.model_metadata_snapshot_sha256),
                "qualified_pricing_snapshot_sha256": result.pricing_snapshot_sha256,
                "qualified_roles": list(selected.approved_roles),
                "qualification_verified_at": bundle.verification.verified_at.isoformat(),
                "qualification_expires_at": result.expires_at.isoformat(),
                "qualification_artifact_sha256": bundle.artifact.artifact_sha256,
                "qualification_verification_sha256": bundle.verification.verification_sha256,
                "production_effective_config_sha256": (
                    bundle.selection.production_effective_config_sha256
                ),
                "production_selection_sha256": bundle.selection.selection_sha256,
                "selection_verification_sha256": (
                    bundle.selection_verification.verification_sha256
                ),
                "qualification_result_sha256": result.result_sha256,
            }
        }
    )
    return reattest_synthetic_real_usage(rebound)


def _evaluate(bundle: _Bundle, **updates):
    assert bundle.selection is not None
    assert bundle.selection_verification is not None
    records, critical, candidates, falsifier = _production_evidence(bundle)
    arguments = {
        "artifact": bundle.artifact,
        "qualification_verification": bundle.verification,
        "selection": bundle.selection,
        "selection_verification": bundle.selection_verification,
        "usage_records": records,
        "critical_surface_evidence": critical,
        "required_high_critical_candidate_ids": candidates,
        "falsifier_evidence": falsifier,
        "now": _NOW + timedelta(hours=5),
    }
    arguments.update(updates)
    return evaluate_certified_ensemble(**arguments)


def test_certified_ensemble_enforces_all_six_runtime_minima() -> None:
    evaluation = _evaluate(_bundle())

    assert evaluation.passed
    assert len(evaluation.exact_model_ids) == 8
    assert len(evaluation.root_lineages) == 6
    assert len(evaluation.specialist_responsibilities) == 24
    assert len(evaluation.whole_protocol_root_lineages) == 4
    assert len(evaluation.critical_surface_lineages["surface-critical"]) == 3
    assert len(evaluation.falsifier_candidate_lineages["candidate-high"]) == 2


@pytest.mark.parametrize(
    "binding",
    [
        "canonical_model",
        "selected_provider_endpoint",
        "selected_provider_name",
        "endpoint_snapshot_sha256",
        "endpoint_pricing_sha256",
        "model_metadata_snapshot_sha256",
        "qualified_exact_model_id",
        "qualified_canonical_model_slug",
        "qualified_root_lineage",
        "qualified_provider_endpoint",
        "qualified_provider_name",
        "qualified_endpoint_snapshot_sha256",
        "qualified_model_metadata_snapshot_sha256",
        "qualified_pricing_snapshot_sha256",
        "qualified_roles",
        "qualification_verified_at",
        "qualification_expires_at",
        "qualification_artifact_sha256",
        "qualification_verification_sha256",
        "production_effective_config_sha256",
        "production_selection_sha256",
        "selection_verification_sha256",
        "qualification_result_sha256",
    ],
)
def test_each_missing_model_evidence_join_revokes_ensemble_credit(binding: str) -> None:
    bundle = _bundle()
    records, _critical, _candidates, _falsifier = _production_evidence(bundle)
    unbound = tuple(
        record.model_copy(
            update={
                "routing": {key: value for key, value in record.routing.items() if key != binding}
            }
        )
        for record in records
    )

    evaluation = _evaluate(bundle, usage_records=unbound)

    assert not evaluation.passed
    assert evaluation.exact_model_ids == ()


def test_each_ensemble_minimum_fails_independently() -> None:
    bundle = _bundle()
    records, critical, _candidates, _falsifier = _production_evidence(bundle)
    specialist_ids = {
        record.request_id
        for record in records
        if record.role.startswith("specialist:") and not _is_falsifier_test_role(record.role)
    }
    one_specialist_id = sorted(specialist_ids)[0]
    only_twenty_three = tuple(
        record for record in records if record.request_id != one_specialist_id
    )
    only_three_whole = tuple(record for record in records if record.request_id != "whole-3")
    two_lineage_surface = (critical[0].model_copy(update={"request_ids": ("whole-0", "whole-1")}),)

    specialist_result = _evaluate(bundle, usage_records=only_twenty_three)
    whole_result = _evaluate(bundle, usage_records=only_three_whole)
    critical_result = _evaluate(
        bundle,
        critical_surface_evidence=two_lineage_surface,
    )

    assert not specialist_result.passed
    assert _requirement_state(specialist_result, "specialist_responsibilities") == "fail"
    assert not whole_result.passed
    assert _requirement_state(whole_result, "whole_protocol_reviews") == "fail"
    assert not critical_result.passed
    assert _requirement_state(critical_result, "critical_surface_lineages") == "fail"


def test_five_roots_or_one_falsifier_root_cannot_pass() -> None:
    five_roots = _bundle(root_count=5)
    assert five_roots.verification.valid
    assert not five_roots.verification.production_selection_ready
    assert five_roots.selection is None
    bundle = _bundle()
    records, _critical, _candidates, _falsifier = _production_evidence(bundle)
    assert bundle.selection is not None
    candidate_by_id = {
        candidate.exact_model_id: candidate for candidate in bundle.registry.candidates
    }
    same_root_record = _usage_record(
        candidate=candidate_by_id[_model_id(6)],
        role=candidate_falsifier_role("candidate-high", 2),
        request_id="falsifier-same-root",
        qualification_artifact_sha256=bundle.artifact.artifact_sha256,
        production_selection_sha256=bundle.selection.selection_sha256,
    )
    same_root_record = _bind_ensemble_usage(bundle, same_root_record)
    records = (
        *(record for record in records if record.request_id != "falsifier-1"),
        same_root_record,
    )
    same_root_falsifier = (
        CandidateFalsifierEvidence(
            candidate_id="candidate-high",
            cross_examination_sha256=_sha("cross-examination-same-root"),
            request_ids=("falsifier-0", "falsifier-same-root"),
        ),
    )
    falsifier_result = _evaluate(
        bundle,
        usage_records=records,
        falsifier_evidence=same_root_falsifier,
    )

    assert not falsifier_result.passed
    assert _requirement_state(falsifier_result, "candidate_falsifier_lineages") == "fail"


def _is_falsifier_test_role(role: str) -> bool:
    return role.startswith(("candidate_falsifier:", "specialist:falsifier:"))


def _requirement_state(evaluation, name: str) -> str:
    return next(
        requirement.state.value
        for requirement in evaluation.requirements
        if requirement.requirement == name
    )
