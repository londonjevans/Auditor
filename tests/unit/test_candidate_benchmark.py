from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.benchmark.models import (
    ModelBenchmarkCaseResult,
    ModelBenchmarkModelResult,
    ModelBenchmarkReport,
    load_model_benchmark_corpus,
)
from mmaudit.config import AuditConfig, model_lineage_index
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkFailureStage,
    CandidateBenchmarkRunState,
    _require_exact_candidate_usage_binding,
    run_candidate_registry_benchmarks,
    validate_candidate_benchmark_policy_capacity,
)
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    _issue_real_openrouter_discovery_run,
    openrouter_endpoint_query,
    openrouter_model_query,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    QualificationDimensionThreshold,
    load_qualification_policy,
    seal_candidate_registry,
    seal_operator_lineage_review,
    seal_qualification_policy,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import UsageLedger, is_creditable_usage_record
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification
from tests.identity_fixtures import bind_synthetic_usage_identity

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"
_NOW = datetime(2026, 7, 27, 9, 0, tzinfo=UTC)


@dataclass(frozen=True)
class _CandidateSpec:
    model_id: str
    provider_endpoint: str
    provider_name: str
    reasoning_supported: bool = True
    canonical_model_id: str | None = None


@dataclass
class _MockClientFactory:
    failing_models: set[str] = field(default_factory=set)
    authentication_failure_models: set[str] = field(default_factory=set)
    pricing_drift_models: set[str] = field(default_factory=set)
    single_model_failure_modes: dict[str, str] = field(default_factory=dict)
    orphan_usage_models: set[str] = field(default_factory=set)
    clients: list[OpenRouterClient] = field(default_factory=list)
    http_clients: list[httpx.AsyncClient] = field(default_factory=list)
    calls: list[tuple[str, OpenRouterProviderPolicy, OpenRouterReasoning | None]] = field(
        default_factory=list
    )
    request_bodies: list[dict[str, Any]] = field(default_factory=list)
    metadata_requests: list[str] = field(default_factory=list)

    def __call__(
        self,
        *,
        api_key: str,
        config: AuditConfig,
        budget: BudgetManager,
        usage: UsageLedger,
        candidate: CandidateModel,
        provider_policy: OpenRouterProviderPolicy,
        reasoning: OpenRouterReasoning | None,
    ) -> OpenRouterClient:
        self.calls.append((candidate.exact_model_id, provider_policy, reasoning))
        if candidate.exact_model_id in self.orphan_usage_models:
            usage.add(
                UsageRecord(
                    request_id=f"orphan-{candidate.exact_model_id}",
                    role="model_benchmark",
                    requested_model=candidate.exact_model_id,
                    model_family=candidate.exact_model_id,
                    timestamp=_NOW,
                    prompt_sha256="a" * 64,
                    status="failed",
                    attempts=1,
                )
            )
            raise RuntimeError(api_key)
        if candidate.exact_model_id in self.failing_models:
            raise RuntimeError(api_key)
        candidate_spec = _CandidateSpec(
            model_id=candidate.exact_model_id,
            provider_endpoint=candidate.approved_provider_endpoint,
            provider_name=candidate.approved_provider_name,
            reasoning_supported=candidate.reasoning_supported,
            canonical_model_id=candidate.canonical_model_slug,
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                self.metadata_requests.append(request.url.path)
            if request.method == "GET" and request.url.path.endswith("/key"):
                if candidate.exact_model_id in self.authentication_failure_models:
                    return httpx.Response(
                        401,
                        request=request,
                        json={"error": {"message": api_key}},
                    )
                return httpx.Response(
                    200,
                    request=request,
                    json={"data": {"label": "synthetic-test-key"}},
                )
            if request.method == "GET" and request.url.path.endswith("/endpoints/zdr"):
                return httpx.Response(
                    200,
                    request=request,
                    json={"data": [_endpoint(candidate_spec)]},
                )
            if request.method == "GET" and request.url.path.endswith("/models"):
                return httpx.Response(
                    200,
                    request=request,
                    json={"data": [_catalog_model(candidate_spec)]},
                )
            if request.method == "GET" and "/model/" in request.url.path:
                expected_path = f"/api/v1/model/{candidate.exact_model_id}"
                if request.url.path != expected_path:
                    return httpx.Response(
                        404,
                        request=request,
                        json={"error": {"message": "synthetic exact lookup required"}},
                    )
                failure_mode = self.single_model_failure_modes.get(candidate.exact_model_id)
                if failure_mode == "missing":
                    return httpx.Response(
                        404,
                        request=request,
                        json={"error": {"message": "synthetic model lookup missing"}},
                    )
                if failure_mode == "malformed":
                    return httpx.Response(
                        200,
                        request=request,
                        json={"data": []},
                    )
                if failure_mode == "mismatch":
                    mismatched = {
                        **_catalog_model(candidate_spec),
                        "id": "alpha/unrelated-model",
                        "canonical_slug": "alpha/unrelated-model-20260727",
                    }
                    return httpx.Response(
                        200,
                        request=request,
                        json={"data": mismatched},
                    )
                return httpx.Response(
                    200,
                    request=request,
                    json={"data": _catalog_model(candidate_spec)},
                )
            if request.method == "GET" and request.url.path.endswith("/endpoints"):
                endpoint = _endpoint(candidate_spec)
                if candidate.exact_model_id in self.pricing_drift_models:
                    endpoint["pricing"] = {
                        **endpoint["pricing"],
                        "completion": "0.000003",
                    }
                return httpx.Response(
                    200,
                    request=request,
                    json={
                        "data": {
                            "id": candidate.exact_model_id,
                            "endpoints": [
                                {key: value for key, value in endpoint.items() if key != "model_id"}
                            ],
                        }
                    },
                )
            if request.method == "POST":
                body = json.loads(request.content)
                assert isinstance(body, dict)
                self.request_bodies.append(body)
            return httpx.Response(
                503,
                request=request,
                json={"error": {"message": "synthetic endpoint unavailable"}},
            )

        http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="https://fake.test/api/v1/",
        )
        client = OpenRouterClient(
            api_key=api_key,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=usage,
            http_client=http_client,
            provider_policy=provider_policy,
            reasoning=reasoning,
        )
        self.clients.append(client)
        self.http_clients.append(http_client)
        return client

    async def close(self) -> None:
        for client in self.http_clients:
            await client.aclose()


def _endpoint(spec: _CandidateSpec) -> dict[str, Any]:
    parameters = ["max_tokens", "response_format", "temperature"]
    if spec.reasoning_supported:
        parameters.append("reasoning")
    return {
        "model_id": spec.model_id,
        "tag": spec.provider_endpoint,
        "provider_name": spec.provider_name,
        "status": 0,
        "context_length": 100_000,
        "max_prompt_tokens": 90_000,
        "max_completion_tokens": 8_192,
        "supported_parameters": sorted(parameters),
        "pricing": {
            "completion": "0.000002",
            "prompt": "0.000001",
            "request": "0",
        },
    }


def _catalog_model(spec: _CandidateSpec) -> dict[str, Any]:
    parameters = ["max_tokens", "response_format", "temperature"]
    if spec.reasoning_supported:
        parameters.append("reasoning")
    return {
        "id": spec.model_id,
        "canonical_slug": spec.canonical_model_id or spec.model_id,
        "context_length": 100_000,
        "top_provider": {
            "context_length": 100_000,
            "max_completion_tokens": 8_192,
        },
        "supported_parameters": sorted(parameters),
    }


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


def _discovery_and_registry(
    *,
    tmp_path: Path,
    config: AuditConfig,
    specs: tuple[_CandidateSpec, ...],
) -> tuple[Any, tuple[OpenRouterModelDiscoveryEvidence, ...], Any]:
    ordered = tuple(sorted(specs, key=lambda item: item.model_id))
    catalog_payload = {"data": [_catalog_model(spec) for spec in ordered]}
    zdr_payload = {"data": [_endpoint(spec) for spec in ordered]}
    payloads: list[OpenRouterModelDiscoveryPayload] = []
    endpoint_payloads: dict[str, dict[str, Any]] = {}
    for spec in ordered:
        endpoint_payload = {
            "data": {
                "id": spec.model_id,
                "endpoints": [
                    {key: value for key, value in _endpoint(spec).items() if key != "model_id"}
                ],
            }
        }
        endpoint_payloads[spec.model_id] = endpoint_payload
        snapshot = validate_openrouter_endpoint_snapshot(
            exact_model_id=spec.model_id,
            configured_provider_endpoints=(spec.provider_endpoint,),
            provider_policy_mode="only",
            endpoint_payload=endpoint_payload,
            require_zdr=config.privacy.require_zdr,
            zdr_payload=zdr_payload,
            structured_output_required=False,
        )
        payloads.append(
            validate_openrouter_model_discovery(
                exact_model_id=spec.model_id,
                models_payload=catalog_payload,
                single_model_payload={"data": _catalog_model(spec)},
                endpoint_snapshot=snapshot,
            )
        )
    provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=_NOW,
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256=_canonical_hash(catalog_payload),
        zdr_snapshot_sha256=_canonical_hash(zdr_payload),
        candidate_routes=tuple(
            DiscoveryCandidateRoute(
                exact_model_id=spec.model_id,
                approved_provider_endpoint=spec.provider_endpoint,
            )
            for spec in ordered
        ),
        model_metadata_bindings=tuple(
            DiscoveryModelMetadataBinding(
                exact_model_id=payload.exact_model_id,
                canonical_slug=payload.canonical_slug,
                api_query=openrouter_model_query(payload.exact_model_id),
                response_snapshot_sha256=_canonical_hash(
                    {
                        "data": _catalog_model(
                            next(
                                spec for spec in ordered if spec.model_id == payload.exact_model_id
                            )
                        )
                    }
                ),
                model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
            )
            for payload in payloads
        ),
        endpoint_metadata_bindings=tuple(
            DiscoveryEndpointMetadataBinding(
                exact_model_id=spec.model_id,
                api_query=openrouter_endpoint_query(spec.model_id),
                response_snapshot_sha256=_canonical_hash(endpoint_payloads[spec.model_id]),
            )
            for spec in ordered
        ),
        payloads=tuple(payloads),
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    manifest = write_model_discovery_run(tmp_path / "discovery-run", evidence)
    lineage_index = model_lineage_index(config)
    candidates: list[CandidateModel] = []
    for item in evidence:
        lineage = lineage_index.get(item.exact_model_id)
        if lineage is None:
            review = seal_operator_lineage_review(
                status=LineageReviewStatus.PENDING,
                reviewed_model_ids=(item.exact_model_id,),
                rationale="Pending independent operator lineage adjudication.",
            )
            root_lineage = None
        else:
            review = seal_operator_lineage_review(
                status=LineageReviewStatus.APPROVED,
                reviewed_model_ids=(item.exact_model_id,),
                root_lineage=lineage.root_lineage,
                rationale="Synthetic operator-reviewed lineage for local regression coverage.",
                reviewed_by="test-operator",
                reviewed_at=_NOW,
                evidence_sha256=canonical_sha256({"model": item.exact_model_id}),
            )
            root_lineage = lineage.root_lineage
        candidates.append(
            CandidateModel(
                exact_model_id=item.exact_model_id,
                canonical_model_slug=item.canonical_slug,
                root_lineage=root_lineage,
                lineage_review=review,
                discovery_evidence_sha256=item.discovery_evidence_sha256,
                approved_provider_endpoint=item.approved_provider_endpoint,
                approved_provider_name=item.provider_name,
                endpoint_snapshot_sha256=item.endpoint_snapshot_sha256,
                model_metadata_snapshot_sha256=item.model_metadata_snapshot_sha256,
                pricing_snapshot_sha256=item.pricing_snapshot_sha256,
                context_size=item.context_size,
                output_limit=item.output_limit,
                structured_output_supported=item.structured_output_supported,
                reasoning_supported=item.reasoning_supported,
                zdr_eligible=item.zdr_eligible,
                data_collection_deny_eligible=item.data_collection_deny_eligible,
                data_collection_deny_request_policy_enforced=(
                    item.data_collection_deny_request_policy_enforced
                ),
                data_collection_deny_evidence_source=(item.data_collection_deny_evidence_source),
                data_collection_deny_evidence_sha256=(item.data_collection_deny_evidence_sha256),
                data_collection_deny_evidence_expires_at=(
                    item.data_collection_deny_evidence_expires_at
                ),
                operational_status=CandidateOperationalStatus.AVAILABLE,
            )
        )
    registry = seal_candidate_registry(
        created_at=provenance.retrieved_at,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=tuple(candidates),
    )
    return manifest, evidence, registry


def _budget(tmp_path: Path, config: AuditConfig) -> BudgetManager:
    tmp_path.mkdir(parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    return BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(
        execution={"max_requests_per_agent": 512},
        models={"reasoning": {"effort": "high"}},
    )


def test_discovery_and_candidate_snapshot_use_the_same_configured_privacy_mode(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = _CandidateSpec(
        model_id="alpha/atlas-secure",
        provider_endpoint="provider-alpha",
        provider_name="Provider Alpha",
    )
    endpoint = _endpoint(spec)
    endpoint_payload = {
        "data": {
            "id": spec.model_id,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }
    zdr_payload = {"data": [endpoint]}

    discovery_snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=spec.model_id,
        configured_provider_endpoints=(spec.provider_endpoint,),
        provider_policy_mode="only",
        endpoint_payload=endpoint_payload,
        require_zdr=config.privacy.require_zdr,
        zdr_payload=zdr_payload,
        structured_output_required=False,
    )
    candidate_snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=spec.model_id,
        configured_provider_endpoints=(spec.provider_endpoint,),
        provider_policy_mode="only",
        endpoint_payload=endpoint_payload,
        require_zdr=config.privacy.require_zdr,
        zdr_payload=zdr_payload,
        reasoning_requested=False,
        structured_output_required=False,
    )

    assert config.privacy.profile is PrivacyProfile.STRICT_ZDR
    assert discovery_snapshot.require_zdr is True
    assert candidate_snapshot == discovery_snapshot
    assert candidate_snapshot.snapshot_sha256 == discovery_snapshot.snapshot_sha256


def _attested_candidate_usage() -> UsageRecord:
    model_id = "alpha/atlas-secure"
    endpoint = "provider-alpha"
    ended_at = _NOW + timedelta(seconds=1)
    generation_id = "generation-candidate-usage-join"
    schema_sha256 = _canonical_hash("candidate benchmark schema")
    return bind_synthetic_usage_identity(
        UsageRecord(
            request_id="candidate-usage-join",
            role="model_benchmark",
            execution_evidence=ExecutionEvidenceKind.REAL,
            requested_model=model_id,
            returned_model=model_id,
            actual_model=model_id,
            provider="Provider Alpha",
            model_family=model_id,
            timestamp=_NOW,
            prompt_tokens=100,
            completion_tokens=25,
            total_tokens=125,
            reported_cost_usd=0.01,
            accounted_cost_usd=0.01,
            routing={
                "generation_id": generation_id,
                "selected_model": model_id,
                "canonical_model": model_id,
                "selected_provider_endpoint": endpoint,
                "selected_provider_name": "Provider Alpha",
                "router_strategy": "direct",
                "router_attempt": 1,
                "router_attempt_count": 1,
                "router_pipeline": [],
                "finish_reason": "stop",
                "schema_sha256": schema_sha256,
                "router_metadata_sha256": _canonical_hash("router metadata"),
                "provider_policy_sha256": _canonical_hash("provider policy"),
                "provider_fallbacks_allowed": False,
                "certification_request": True,
                "validation_status": "valid",
                "zdr_requested": True,
                "data_collection": "deny",
                "privacy_profile": PrivacyProfile.STRICT_ZDR.value,
                "privacy_authorization": "STRICT_ZDR_ENFORCED",
                "effective_privacy_policy_sha256": _canonical_hash("effective privacy policy"),
                "privacy_source_sha256": _canonical_hash("privacy source"),
                "privacy_source_provenance_sha256": _canonical_hash("privacy source provenance"),
                "privacy_source_classification": (
                    PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
                ),
                "privacy_consent_file_sha256": None,
                "privacy_consent_sha256": None,
                "privacy_consent_expires_at": None,
                "privacy_endpoint_policy_class": EndpointPolicyClass.ZDR.value,
                "repair_used": False,
                "repair_request": False,
                "request_started_at": _NOW.isoformat(),
                "request_ended_at": ended_at.isoformat(),
                "latency_ms": 1_000,
            },
            prompt_sha256=_canonical_hash("prompt"),
            response_sha256=_canonical_hash("response"),
            validated_response_sha256=_canonical_hash("validated response"),
            request_body_sha256=_canonical_hash("request body"),
            schema_sha256=schema_sha256,
            openrouter_generation_id=generation_id,
            configured_provider_endpoints=[endpoint],
            actual_provider_endpoint=endpoint,
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


def _report_with_usage(record: UsageRecord) -> ModelBenchmarkReport:
    case = ModelBenchmarkCaseResult.model_construct(usage_record=record)
    result = ModelBenchmarkModelResult.model_construct(cases=[case])
    return ModelBenchmarkReport.model_construct(results=[result])


@pytest.mark.parametrize(
    "failure_stage",
    [None, CandidateBenchmarkFailureStage.BENCHMARK_EXECUTION],
)
def test_candidate_usage_join_uses_public_projection_without_restoring_runtime_authority(
    failure_stage: CandidateBenchmarkFailureStage | None,
) -> None:
    observed = _attested_candidate_usage()
    serialized = UsageRecord.model_validate(observed.model_dump(mode="json"))

    assert observed is not serialized
    assert observed == serialized
    assert observed.model_dump(mode="json") == serialized.model_dump(mode="json")
    assert is_creditable_usage_record(
        observed,
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        serialized,
        require_real=True,
        require_certification=True,
    )

    _require_exact_candidate_usage_binding(
        report=_report_with_usage(serialized),
        observed_records=(observed,),
        failure_stage=failure_stage,
    )


@pytest.mark.parametrize(
    "failure_stage",
    [None, CandidateBenchmarkFailureStage.BENCHMARK_EXECUTION],
)
def test_candidate_usage_join_rejects_changed_public_evidence(
    failure_stage: CandidateBenchmarkFailureStage | None,
) -> None:
    observed = _attested_candidate_usage()
    changed = UsageRecord.model_validate(
        {
            **observed.model_dump(mode="json"),
            "request_id": "changed-candidate-usage",
        }
    )

    with pytest.raises(
        ValueError,
        match=r"not bound to its exact report|unobserved request usage",
    ):
        _require_exact_candidate_usage_binding(
            report=_report_with_usage(changed),
            observed_records=(observed,),
            failure_stage=failure_stage,
        )


def test_candidate_benchmark_policy_rejects_underfilled_dimension() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    thresholds = tuple(
        QualificationDimensionThreshold(
            dimension=item.dimension,
            minimum_cases=(
                item.minimum_cases + 1
                if item.dimension.value == "access_control"
                else item.minimum_cases
            ),
            minimum_score=item.minimum_score,
        )
        for item in policy.thresholds
    )
    underfilled = seal_qualification_policy(
        created_at=policy.created_at,
        thresholds=thresholds,
        tier_a_minimum_overall_score=policy.tier_a_minimum_overall_score,
        maximum_validity_days=policy.maximum_validity_days,
    )

    with pytest.raises(ValueError, match=r"underfills.*access_control"):
        validate_candidate_benchmark_policy_capacity(
            benchmark_suite=suite,
            qualification_policy=underfilled,
        )


@pytest.mark.asyncio
async def test_candidate_benchmark_uses_exact_mock_certification_route(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    spec = _CandidateSpec(
        model_id="alpha/atlas-secure",
        provider_endpoint="provider-alpha",
        provider_name="Provider Alpha",
        canonical_model_id="alpha/atlas-secure-20260727",
    )
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(spec,),
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    factory = _MockClientFactory()
    canary = "SYNTHETIC_OPENROUTER_CANARY"
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=suite,
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key=canary,
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    report = result.reports[0]
    diagnostic = result.diagnostics[0]
    assert [item.target.model_id for item in report.results] == [spec.model_id]
    assert report.execution_evidence is ExecutionEvidenceKind.MOCK
    assert diagnostic.state is CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES
    assert diagnostic.corpus_cases == len(suite.cases)
    assert diagnostic.requests_observed == len(suite.cases)
    assert factory.calls[0][1] == OpenRouterProviderPolicy(
        certification=True,
        only=(spec.provider_endpoint,),
        allow_fallbacks=False,
    )
    assert factory.calls[0][2] == OpenRouterReasoning(effort="high")
    assert any(path.endswith("/endpoints") for path in factory.metadata_requests)
    assert any(path.endswith("/endpoints/zdr") for path in factory.metadata_requests)
    assert f"/api/v1/model/{spec.model_id}" in factory.metadata_requests
    assert f"/api/v1/model/{spec.model_id}-20260727" not in factory.metadata_requests
    for body in factory.request_bodies:
        assert isinstance(body["provider"], dict)
        assert {
            key: body["provider"][key]
            for key in (
                "allow_fallbacks",
                "data_collection",
                "only",
                "require_parameters",
                "zdr",
            )
        } == {
            "allow_fallbacks": False,
            "data_collection": "deny",
            "only": [spec.provider_endpoint],
            "require_parameters": True,
            "zdr": True,
        }
        assert "max_price" in body["provider"]
    assert all(body["reasoning"]["effort"] == "high" for body in factory.request_bodies)
    effective_policy = factory.clients[0].effective_privacy_policy
    assert effective_policy is not None
    assert effective_policy.privacy_profile is PrivacyProfile.STRICT_ZDR
    assert effective_policy.source_sha256 == suite.corpus_sha256
    assert effective_policy.source_classification is (
        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
    )
    assert effective_policy.permitted_model_ids == (spec.model_id,)
    assert effective_policy.permitted_provider_endpoints == (spec.provider_endpoint,)
    for case in report.results[0].cases:
        assert case.usage_record is not None
        assert (
            case.usage_record.routing["effective_privacy_policy_sha256"]
            == effective_policy.evidence_sha256
        )
        assert case.usage_record.routing["privacy_source_sha256"] == suite.corpus_sha256
    assert all(not client._credential for client in factory.clients)
    assert canary not in result.model_dump_json()


@pytest.mark.asyncio
async def test_candidate_benchmark_requires_shared_atomic_endpoint_bound_ledger(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )

    with pytest.raises(ValueError, match="shared durable atomic"):
        await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=budget,
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
        )


@pytest.mark.asyncio
async def test_candidate_benchmark_rejects_discovery_set_and_endpoint_mismatches(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    with pytest.raises(ValueError, match="exactly cover"):
        await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=(),
            candidate_registry=registry,
            benchmark_suite=suite,
            budget=_budget(tmp_path / "set-mismatch", config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
        )

    changed_candidate = registry.candidates[0].model_copy(
        update={"approved_provider_endpoint": "other-provider"}
    )
    changed_registry = seal_candidate_registry(
        created_at=registry.created_at,
        discovery_run_sha256=registry.discovery_run_sha256,
        candidates=(changed_candidate,),
    )
    with pytest.raises(ValueError, match="metadata differs"):
        await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=changed_registry,
            benchmark_suite=suite,
            budget=_budget(tmp_path / "endpoint-mismatch", config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
        )


@pytest.mark.asyncio
async def test_candidate_benchmark_revalidates_alias_tampering(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    invalid_candidate = registry.candidates[0].model_copy(
        update={"exact_model_id": "openrouter/auto"}
    )
    invalid_registry = registry.model_copy(update={"candidates": (invalid_candidate,)})

    with pytest.raises(ValidationError, match="exact non-routed"):
        await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=invalid_registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
        )


@pytest.mark.asyncio
async def test_unsupported_reasoning_is_suppressed_without_changing_mock_provenance(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
                reasoning_supported=False,
            ),
        ),
    )
    factory = _MockClientFactory()
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    assert factory.calls[0][2] is None
    assert result.diagnostics[0].reasoning_suppressed is True
    assert result.reports[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert all("reasoning" not in body for body in factory.request_bodies)


@pytest.mark.asyncio
async def test_pending_lineage_candidate_can_be_measured_without_becoming_approved(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(
        execution={"max_requests_per_agent": 512},
        privacy={"approved_model_lineages": []},
        models={
            "registry": [],
            "reasoning": {"effort": "high"},
        },
    )
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id="alpha/atlas-secure",
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    assert registry.candidates[0].lineage_review.status is LineageReviewStatus.PENDING
    assert registry.candidates[0].root_lineage is None
    factory = _MockClientFactory()
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    assert result.reports[0].results[0].target.root_lineage is None
    assert result.reports[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert factory.request_bodies
    assert registry.candidates[0].lineage_review.status is LineageReviewStatus.PENDING


@pytest.mark.asyncio
async def test_authentication_failure_is_sanitized_unverified_and_spend_free(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    model_id = "alpha/atlas-secure"
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    factory = _MockClientFactory(authentication_failure_models={model_id})
    budget = _budget(tmp_path, config)
    canary = "SYNTHETIC_AUTH_SECRET_CANARY"
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=budget,
            usage=UsageLedger(),
            operator_api_key=canary,
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    diagnostic = result.diagnostics[0]
    assert diagnostic.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert diagnostic.failure_stage is CandidateBenchmarkFailureStage.AUTHENTICATION
    assert diagnostic.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert diagnostic.requests_observed == 0
    assert not factory.request_bodies
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()
    assert all(not client._credential for client in factory.clients)
    assert canary not in result.model_dump_json()


@pytest.mark.asyncio
async def test_current_endpoint_drift_fails_before_candidate_requests(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    model_id = "alpha/atlas-secure"
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    factory = _MockClientFactory(pricing_drift_models={model_id})
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    diagnostic = result.diagnostics[0]
    assert diagnostic.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert diagnostic.failure_stage is CandidateBenchmarkFailureStage.ENDPOINT_REGISTRATION
    assert diagnostic.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert diagnostic.requests_observed == 0
    assert not factory.request_bodies


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ("missing", "malformed", "mismatch"))
async def test_single_model_lookup_failure_fails_before_candidate_requests(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    failure_mode: str,
) -> None:
    config = _config(config_factory)
    model_id = "alpha/atlas-secure"
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    factory = _MockClientFactory(
        single_model_failure_modes={model_id: failure_mode},
    )
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key="synthetic-key",
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    diagnostic = result.diagnostics[0]
    assert diagnostic.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert diagnostic.failure_stage is CandidateBenchmarkFailureStage.ENDPOINT_REGISTRATION
    assert diagnostic.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert diagnostic.requests_observed == 0
    assert any("/model/" in path for path in factory.metadata_requests)
    assert not factory.request_bodies


@pytest.mark.asyncio
async def test_candidate_benchmark_preserves_terminal_orphaned_usage_as_unverified(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    model_id = "alpha/atlas-secure"
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            _CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    factory = _MockClientFactory(orphan_usage_models={model_id})

    result = await run_candidate_registry_benchmarks(
        config=config,
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        candidate_registry=registry,
        benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
        budget=_budget(tmp_path, config),
        usage=UsageLedger(),
        operator_api_key="synthetic-key",
        explicitly_allow_synthetic_egress=True,
        client_factory=factory,
    )

    assert result.diagnostics[0].state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert result.diagnostics[0].requests_observed == 1
    assert result.diagnostics[0].failed_request_count == 1


@pytest.mark.asyncio
async def test_failed_candidate_is_unverified_and_next_candidate_still_runs_without_secret_leak(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _config(config_factory)
    specs = (
        _CandidateSpec(
            model_id="alpha/atlas-secure",
            provider_endpoint="provider-alpha",
            provider_name="Provider Alpha",
        ),
        _CandidateSpec(
            model_id="bravo/borealis-secure",
            provider_endpoint="provider-bravo",
            provider_name="Provider Bravo",
        ),
    )
    manifest, evidence, registry = _discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=specs,
    )
    factory = _MockClientFactory(failing_models={"alpha/atlas-secure"})
    canary = "SYNTHETIC_SECRET_MUST_NOT_PERSIST"
    try:
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            candidate_registry=registry,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            budget=_budget(tmp_path, config),
            usage=UsageLedger(),
            operator_api_key=canary,
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
        )
    finally:
        await factory.close()

    assert [report.results[0].target.model_id for report in result.reports] == [
        "alpha/atlas-secure",
        "bravo/borealis-secure",
    ]
    failed, continued = result.diagnostics
    assert failed.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    assert failed.failure_stage is CandidateBenchmarkFailureStage.CLIENT_INITIALIZATION
    assert failed.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert failed.requests_observed == 0
    assert failed.failed_cases == len(load_model_benchmark_corpus(CORPUS_PATH).cases)
    assert continued.execution_evidence is ExecutionEvidenceKind.MOCK
    assert any(call[0] == "bravo/borealis-secure" for call in factory.calls)
    assert canary not in result.model_dump_json()
    assert all(not client._credential for client in factory.clients)
