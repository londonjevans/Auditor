from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import traceback
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

import mmaudit.models.openrouter as openrouter_module
from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    _issue_real_openrouter_discovery_run,
    openrouter_endpoint_query,
    openrouter_model_query,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.generation_evidence import validate_openrouter_generation_payload
from mmaudit.models.identity import (
    OpenRouterIdentityDiagnosticCode,
    OpenRouterIdentityStrength,
)
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterCostControlError,
    OpenRouterModelError,
    OpenRouterPrivacyError,
    OpenRouterProviderPolicy,
    OpenRouterProviderPolicyError,
    OpenRouterQualificationError,
    OpenRouterQualificationRoutingEvidence,
    OpenRouterQualifiedReasoningRoutingBinding,
    OpenRouterReasoning,
    OpenRouterRequestLimitError,
    OpenRouterSchemaError,
    OpenRouterStructuredOutputError,
    OpenRouterTransientError,
    OpenRouterTruncatedResponseError,
    OpenRouterUnboundIdentityError,
    StructuredCompletion,
    _require_exact_qualification_routing_authority,
    is_retryable_status,
    safe_headers,
    strict_json_schema,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningRequestPlanEvidence,
)
from mmaudit.models.schemas import (
    ContextExcerpt,
    ContextPackage,
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    RepositoryMap,
    UsageRecord,
)
from mmaudit.models.structured_output import StructuredOutputFailureCode
from mmaudit.models.token_planning import (
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionReason,
    PromptAllocationCategory,
)
from mmaudit.models.usage import (
    UsageLedger,
    _attest_owned_real_usage_record,
    is_creditable_usage_record,
)
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    TokenReservationOverrunError,
)
from mmaudit.orchestration.context import (
    context_category_measurements,
    render_context,
)
from mmaudit.orchestration.context_manifest import (
    ContextPreflightReason,
    ContextPreflightSource,
    ContextRequestEvidence,
    ContextRequestState,
    build_context_manifest,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import (
    REQUIRED_PROHIBITED_CONTENT,
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    EndpointPrivacyDisclosure,
    PrivacyProfile,
    PrivacyRetentionConsent,
    PrivacySourceClassification,
    TrustedPrivacyAuthorization,
    load_privacy_retention_consent,
    resolve_effective_privacy_policy,
    resolve_trusted_privacy_authorization,
)
from tests.qualification_support import synthetic_production_qualification


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


class OptionalAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    note: str | None = None


class NumericAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: float


class LooseAnswer(BaseModel):
    answer: str


def _empty_context_package(*, role: str = "source_audit") -> ContextPackage:
    package = ContextPackage(
        role=role,
        byte_budget=10_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        repository_map=RepositoryMap(
            root_name="synthetic-request-context",
            languages={"Solidity": 1},
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
            omitted_files=[],
        ),
        scanner_findings=[],
        excerpts=[],
    )
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _qualification_routing(
    *,
    model: str = "alpha/atlas-secure",
    canonical_model: str | None = None,
    provider: str = "approved-provider",
    provider_name: str | None = None,
    roles: tuple[str, ...] = ("source_audit",),
    verified_at: datetime | None = None,
    expires_at: datetime | None = None,
    endpoint_snapshot_sha256: str = "6" * 64,
    output_capability_sha256: str = "9" * 64,
    structured_output_mode: StructuredOutputMode = StructuredOutputMode.JSON_OBJECT,
    model_metadata_snapshot_sha256: str = "7" * 64,
    pricing_snapshot_sha256: str = "8" * 64,
    reasoning_policy: ReasoningPolicyArtifact | None = None,
    reasoning_bindings: tuple[OpenRouterQualifiedReasoningRoutingBinding, ...] | None = None,
) -> OpenRouterQualificationRoutingEvidence:
    now = datetime.now(UTC)
    verification_time = verified_at or now
    effective_provider_name = provider_name or provider
    policy = reasoning_policy or ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="disabled",
                reserved_reasoning_tokens=0,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )
    if reasoning_bindings is None:
        projected_bindings: list[OpenRouterQualifiedReasoningRoutingBinding] = []
        for qualified_role in roles:
            configured_roles = (
                ("threat_model",)
                if qualified_role == "whole_protocol_review"
                else (
                    ("falsifier", "verifier")
                    if qualified_role == "falsifier"
                    else (qualified_role,)
                )
            )
            for configured_role in configured_roles:
                role_policy = policy.role_policy(configured_role)
                payload: dict[str, Any] = {
                    "schema_version": "1.0",
                    "binding_status": "exact_evidence_bound",
                    "selection_authority": False,
                    "exact_model_id": model,
                    "approved_provider_endpoint": provider,
                    "approved_provider_name": effective_provider_name,
                    "qualified_role": qualified_role,
                    "configured_policy_role": configured_role,
                    "control_profile": role_policy.control.model_dump(mode="json"),
                    "control_profile_sha256": role_policy.control.profile_sha256,
                    "reasoning_policy_artifact_sha256": policy.artifact_sha256,
                    "reasoning_policy_role_binding_sha256": role_policy.binding_sha256,
                    "endpoint_reasoning_capability_sha256": "a" * 64,
                    "reasoning_benchmark_report_sha256": "b" * 64,
                    "reasoning_benchmark_verification_sha256": "2" * 64,
                    "reasoning_benchmark_fresh_evidence_sha256": "2" * 64,
                    "qualification_report_sha256": "b" * 64,
                    "qualification_result_sha256": "5" * 64,
                    "qualification_verification_sha256": "2" * 64,
                }
                projected_bindings.append(
                    OpenRouterQualifiedReasoningRoutingBinding(
                        exact_model_id=model,
                        approved_provider_endpoint=provider,
                        approved_provider_name=effective_provider_name,
                        qualified_role=qualified_role,
                        configured_policy_role=configured_role,
                        control_profile=role_policy.control,
                        control_profile_sha256=role_policy.control.profile_sha256,
                        reasoning_policy_artifact_sha256=policy.artifact_sha256,
                        reasoning_policy_role_binding_sha256=role_policy.binding_sha256,
                        endpoint_reasoning_capability_sha256="a" * 64,
                        reasoning_benchmark_report_sha256="b" * 64,
                        reasoning_benchmark_verification_sha256="2" * 64,
                        reasoning_benchmark_fresh_evidence_sha256="2" * 64,
                        qualification_report_sha256="b" * 64,
                        qualification_result_sha256="5" * 64,
                        qualification_verification_sha256="2" * 64,
                        binding_sha256=canonical_sha256(payload),
                    )
                )
        reasoning_bindings = tuple(
            sorted(
                projected_bindings,
                key=lambda binding: (
                    binding.qualified_role,
                    binding.configured_policy_role,
                ),
            )
        )
    return OpenRouterQualificationRoutingEvidence(
        exact_model_id=model,
        canonical_model_slug=canonical_model or model,
        root_lineage=f"sha256:{'a' * 64}",
        approved_provider_endpoint=provider,
        approved_provider_name=effective_provider_name,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        output_capability_sha256=output_capability_sha256,
        structured_output_mode=structured_output_mode,
        model_metadata_snapshot_sha256=model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=pricing_snapshot_sha256,
        approved_roles=roles,
        verified_at=verification_time,
        expires_at=expires_at or verification_time + timedelta(days=1),
        qualification_artifact_sha256="1" * 64,
        qualification_verification_sha256="2" * 64,
        production_selection_sha256="3" * 64,
        selection_verification_sha256="4" * 64,
        qualification_result_sha256="5" * 64,
        benchmark_report_sha256="b" * 64,
        reasoning_bindings=reasoning_bindings,
    )


def _completion(
    content: str,
    *,
    cost: float | None = 0.01,
    model: str = "alpha/atlas-secure",
    selected_model: str | None = None,
    provider: str = "synthetic-provider",
    reasoning_tokens: int | None = None,
) -> dict[str, Any]:
    routed_model = selected_model or model
    usage: dict[str, Any] = {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
    }
    if reasoning_tokens is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning_tokens}
    if cost is not None:
        usage["cost"] = cost
    return {
        "id": "generation-test",
        "model": model,
        "provider": provider,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": usage,
        "openrouter_metadata": {
            "requested": model,
            "strategy": "direct",
            "attempt": 1,
            "endpoints": {
                "total": 1,
                "available": [
                    {
                        "provider": provider,
                        "model": routed_model,
                        "selected": True,
                    }
                ],
            },
            "attempts": [
                {
                    "provider": provider,
                    "model": routed_model,
                    "status": 200,
                }
            ],
            "pipeline": [],
        },
    }


def _completion_response(
    content: str,
    *,
    cost: float | None = 0.01,
    model: str = "alpha/atlas-secure",
    selected_model: str | None = None,
    provider: str = "synthetic-provider",
    reasoning_tokens: int | None = None,
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"X-Generation-Id": "generation-test"},
        json=_completion(
            content,
            cost=cost,
            model=model,
            selected_model=selected_model,
            provider=provider,
            reasoning_tokens=reasoning_tokens,
        ),
    )


def _generation_payload(
    *,
    generation_id: str = "generation-test",
    model: str = "alpha/atlas-secure-20260727",
    provider_name: str = "Approved Provider",
) -> dict[str, Any]:
    return {
        "data": {
            "api_type": "completions",
            "cancelled": False,
            "created_at": datetime.now(UTC).isoformat(),
            "finish_reason": "stop",
            "generation_time": 120,
            "id": generation_id,
            "latency": 125,
            "model": model,
            "native_finish_reason": "stop",
            "native_tokens_cached": 0,
            "native_tokens_completion": 5,
            "native_tokens_prompt": 10,
            "native_tokens_reasoning": 0,
            "provider_name": provider_name,
            "request_id": "provider-request-test",
            "tokens_completion": 5,
            "tokens_prompt": 10,
            "total_cost": 0.01,
            "usage": 0.01,
        }
    }


def _endpoint_snapshot(
    *,
    model: str = "alpha/atlas-secure",
    provider: str = "approved-provider",
    provider_name: str = "Approved Provider",
    context_length: int = 200_000,
    max_prompt_tokens: int = 180_000,
    max_completion_tokens: int = 20_000,
    pricing: dict[str, str] | None = None,
    require_zdr: bool = True,
    supported_parameters: list[str] | None = None,
    reasoning_requested: bool = False,
    structured_output_required: bool = True,
) -> OpenRouterEndpointSnapshotEvidence:
    endpoint = {
        "tag": provider,
        "provider_name": provider_name,
        "status": 0,
        "context_length": context_length,
        "max_prompt_tokens": max_prompt_tokens,
        "max_completion_tokens": max_completion_tokens,
        "supported_parameters": supported_parameters
        or ["max_tokens", "response_format", "temperature"],
        "pricing": pricing
        or {
            "prompt": "0.000001",
            "completion": "0.00001",
            "request": "0",
        },
    }
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(provider,),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=require_zdr,
        zdr_payload=({"data": [{**endpoint, "model_id": model}]} if require_zdr else None),
        reasoning_requested=reasoning_requested,
        structured_output_required=structured_output_required,
    )


def _frontier_privacy_authorization(
    tmp_path: Path,
    *,
    model: str = "alpha/atlas-secure",
    provider: str = "approved-provider",
    provider_policy_classes: tuple[tuple[str, EndpointPolicyClass], ...] | None = None,
    evaluation_time: datetime | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> tuple[
    EffectivePrivacyPolicyEvidence,
    TrustedPrivacyAuthorization,
    tuple[str, ...],
]:
    evaluated_at = evaluation_time or datetime.now(UTC).replace(microsecond=0)
    source_sha256 = "9" * 64
    consent_canaries = (
        "consent-disclosure-body-canary",
        "operator-reference-body-canary",
        "consent-path-body-canary",
    )
    endpoint_policy_pairs = provider_policy_classes or (
        (provider, EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED),
    )
    endpoint_policy_pairs = tuple(sorted(endpoint_policy_pairs))
    disclosures = tuple(
        EndpointPrivacyDisclosure(
            provider_endpoint=endpoint,
            policy_class=policy_class,
            disclosed_retention=consent_canaries[0],
            privacy_policy_reference=(
                f"https://privacy.example.test/{hashlib.sha256(endpoint.encode()).hexdigest()}"
            ),
            privacy_policy_sha256="8" * 64,
        )
        for endpoint, policy_class in endpoint_policy_pairs
    )
    consent_payload = {
        "schema_version": "1.0",
        "selected_privacy_profile": (PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT),
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "permitted_source_sha256": source_sha256,
        "permitted_model_ids": (model,),
        "permitted_provider_endpoints": tuple(item[0] for item in endpoint_policy_pairs),
        "permitted_endpoint_policy_classes": tuple(
            sorted({item[1] for item in endpoint_policy_pairs}, key=lambda item: item.value)
        ),
        "endpoint_disclosures": disclosures,
        "issued_at": issued_at or evaluated_at - timedelta(minutes=5),
        "expires_at": expires_at or evaluated_at + timedelta(hours=1),
        "operator_identity_reference": consent_canaries[1],
        "signature_reference": None,
        "maximum_cost_usd": "20",
        "prohibited_content": REQUIRED_PROHIBITED_CONTENT,
        "acknowledges_zdr_not_in_force": True,
    }
    consent = PrivacyRetentionConsent.model_validate(
        {
            **consent_payload,
            "consent_sha256": hashlib.sha256(
                json.dumps(
                    PrivacyRetentionConsent.model_construct(
                        **consent_payload,
                        consent_sha256="0" * 64,
                    ).model_dump(mode="json", exclude={"consent_sha256"}),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode()
            ).hexdigest(),
        }
    )
    target_root = tmp_path / "target"
    target_root.mkdir(exist_ok=True)
    consent_path = tmp_path / "operator-control" / f"{consent_canaries[2]}.json"
    consent_path.parent.mkdir(exist_ok=True)
    consent_path.write_text(
        json.dumps(consent.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    consent_path.chmod(0o600)
    observation = load_privacy_retention_consent(
        consent_path.resolve(),
        target_root=target_root.resolve(),
    )
    authorization = resolve_trusted_privacy_authorization(
        profile=PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
        require_zdr=False,
        consent_observation=observation,
        source_sha256=source_sha256,
        source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        configured_model_ids=(model,),
        configured_provider_endpoints=tuple(item[0] for item in endpoint_policy_pairs),
        requested_budget_usd=Decimal("20"),
        now=evaluated_at,
    )
    return authorization.evidence, authorization, consent_canaries


def _strict_privacy_policy(
    config: Any,
    *,
    models: tuple[str, ...] = ("alpha/atlas-secure",),
    providers: tuple[str, ...] = ("approved-provider",),
    requested_budget_usd: Decimal | None = None,
) -> EffectivePrivacyPolicyEvidence:
    return resolve_effective_privacy_policy(
        profile=PrivacyProfile.STRICT_ZDR,
        require_zdr=True,
        consent_observation=None,
        source_sha256=hashlib.sha256(b"synthetic strict-ZDR test source").hexdigest(),
        source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        configured_model_ids=tuple(sorted(models)),
        configured_provider_endpoints=tuple(sorted(providers)),
        requested_budget_usd=(
            requested_budget_usd
            if requested_budget_usd is not None
            else Decimal(str(config.execution.budget_usd))
        ),
        now=datetime.now(UTC).replace(microsecond=0),
    )


def _model_discovery_run(
    tmp_path: Path,
    *,
    exact_model: str = "alpha/atlas-secure",
    canonical_model: str = "alpha/atlas-secure-20260727",
    provider: str = "approved-provider",
    provider_name: str = "Approved Provider",
    model_supported_parameters: tuple[str, ...] = (
        "max_tokens",
        "response_format",
        "temperature",
    ),
    endpoint_supported_parameters: tuple[str, ...] | None = None,
    endpoint_reasoning_requested: bool = False,
) -> tuple[OpenRouterModelDiscoveryRunManifest, OpenRouterModelDiscoveryEvidence]:
    endpoint_snapshot = _endpoint_snapshot(
        model=exact_model,
        provider=provider,
        provider_name=provider_name,
        supported_parameters=(
            list(endpoint_supported_parameters)
            if endpoint_supported_parameters is not None
            else None
        ),
        reasoning_requested=endpoint_reasoning_requested,
        structured_output_required=False,
    )
    catalog = {
        "data": [
            {
                "id": exact_model,
                "canonical_slug": canonical_model,
                "context_length": 200_000,
                "top_provider": {
                    "context_length": 200_000,
                    "max_completion_tokens": 20_000,
                },
                "supported_parameters": list(model_supported_parameters),
            }
        ]
    }
    payload = validate_openrouter_model_discovery(
        exact_model_id=exact_model,
        models_payload=catalog,
        single_model_payload={"data": dict(catalog["data"][0])},
        endpoint_snapshot=endpoint_snapshot,
    )
    route = DiscoveryCandidateRoute(
        exact_model_id=exact_model,
        approved_provider_endpoint=provider,
    )
    _provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256=hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        zdr_snapshot_sha256="d" * 64,
        candidate_routes=(route,),
        model_metadata_bindings=(
            DiscoveryModelMetadataBinding(
                exact_model_id=exact_model,
                canonical_slug=canonical_model,
                api_query=openrouter_model_query(exact_model),
                response_snapshot_sha256="f" * 64,
                model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
            ),
        ),
        endpoint_metadata_bindings=(
            DiscoveryEndpointMetadataBinding(
                exact_model_id=exact_model,
                api_query=openrouter_endpoint_query(exact_model),
                response_snapshot_sha256="e" * 64,
            ),
        ),
        payloads=(payload,),
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    manifest = write_model_discovery_run(tmp_path / canonical_model.rsplit("/", 1)[-1], evidence)
    return manifest, evidence[0]


@pytest.mark.asyncio
async def test_endpoint_tag_observation_normalizes_to_frozen_provider_name(
    config_factory,
    tmp_path: Path,
) -> None:
    provider_endpoint = "akashml/fp8"
    provider_name = "AkashML"
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
        provider=provider_endpoint,
        provider_name=provider_name,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"canonical provider identity"}',
            selected_model=canonical_model,
            provider=provider_endpoint,
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=(provider_endpoint,),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert completion.value.answer == "canonical provider identity"
    assert record.validation_status.value == "valid"
    assert record.provider == provider_name
    assert record.actual_provider_endpoint == provider_endpoint
    assert record.routing["selected_provider_identity"] == provider_endpoint
    assert record.routing["selected_provider_name"] == provider_name

    retrieved_at = datetime.now(UTC)
    generation = validate_openrouter_generation_payload(
        _generation_payload(
            model=canonical_model,
            provider_name=provider_name,
        ),
        requested_generation_id="generation-test",
        retrieved_at=retrieved_at,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    binding = client.bind_generation_identity(
        usage_record=record,
        generation_evidence=generation,
        evaluated_at=retrieved_at,
    )
    assert binding.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND


@pytest.mark.asyncio
async def test_unbound_generation_mismatch_preserves_bounded_observation(
    config_factory,
    tmp_path: Path,
) -> None:
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"unbound observation content canary"}',
            selected_model=evidence.canonical_slug,
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    retrieved_at = datetime.now(UTC)
    generation = validate_openrouter_generation_payload(
        _generation_payload(
            model=evidence.canonical_slug,
            provider_name="Different Provider",
        ),
        requested_generation_id="generation-test",
        retrieved_at=retrieved_at,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    binding = client.bind_generation_identity(
        usage_record=completion.usage_record,
        generation_evidence=generation,
        evaluated_at=retrieved_at,
    )
    assert binding.strength is OpenRouterIdentityStrength.UNBOUND
    concluded = client._usage_with_unbound_identity(
        usage_record=completion.usage_record,
        identity_binding=binding,
        trusted_issuer=None,
        generation_observation=generation,
    )

    observation = concluded.routing["unbound_generation_observation"]
    assert observation == generation.model_dump(mode="json")
    assert observation["provider_name"] == "Different Provider"
    assert observation["exact_model_id"] == evidence.canonical_slug
    assert binding.diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH,
    )
    assert "unbound observation content canary" not in json.dumps(
        observation,
        sort_keys=True,
    )
    assert not is_creditable_usage_record(concluded, require_certification=True)


def _qualification_routing_for_discovery(
    evidence: OpenRouterModelDiscoveryEvidence,
) -> OpenRouterQualificationRoutingEvidence:
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    assert endpoint is not None
    return _qualification_routing(
        model=evidence.exact_model_id,
        canonical_model=evidence.canonical_slug,
        provider=evidence.approved_provider_endpoint,
        provider_name=endpoint.provider_name,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot_sha256,
        output_capability_sha256=evidence.output_capability_sha256,
        structured_output_mode=evidence.structured_output_mode,
        model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )


def _qualification_routing_for_endpoint_snapshot(
    snapshot: OpenRouterEndpointSnapshotEvidence,
    *,
    provider_name: str | None = None,
) -> OpenRouterQualificationRoutingEvidence:
    endpoint = snapshot.endpoints[0]
    return _qualification_routing(
        model=snapshot.exact_model_id,
        provider=endpoint.provider_endpoint,
        provider_name=provider_name or endpoint.provider_name,
        endpoint_snapshot_sha256=snapshot.snapshot_sha256,
        output_capability_sha256=snapshot.output_capability_sha256,
        structured_output_mode=snapshot.structured_output_mode,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )


def _multi_endpoint_snapshot(
    *,
    shared_provider_name: bool = False,
) -> OpenRouterEndpointSnapshotEvidence:
    endpoints = [
        {
            "tag": "provider-economy",
            "provider_name": "Provider Economy",
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        },
        {
            "tag": "provider-premium",
            "provider_name": ("Provider Economy" if shared_provider_name else "Provider Premium"),
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000004",
                "completion": "0.00004",
                "request": "0.002",
            },
        },
    ]
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("provider-economy", "provider-premium"),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": endpoints,
            }
        },
        require_zdr=True,
        zdr_payload={
            "data": [
                {
                    **endpoint,
                    "model_id": "alpha/atlas-secure",
                }
                for endpoint in endpoints
            ]
        },
    )


def _asymmetric_token_endpoint_snapshot() -> OpenRouterEndpointSnapshotEvidence:
    endpoints = [
        {
            "tag": "provider-wide",
            "provider_name": "Provider Wide",
            "status": 0,
            "context_length": 160_000,
            "max_prompt_tokens": 140_000,
            "max_completion_tokens": 24_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        },
        {
            "tag": "provider-narrow",
            "provider_name": "Provider Narrow",
            "status": 0,
            "context_length": 96_000,
            "max_prompt_tokens": 72_000,
            "max_completion_tokens": 12_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000002",
                "completion": "0.00002",
                "request": "0",
            },
        },
    ]
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("provider-narrow", "provider-wide"),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": endpoints,
            }
        },
        require_zdr=True,
        zdr_payload={
            "data": [
                {
                    **endpoint,
                    "model_id": "alpha/atlas-secure",
                }
                for endpoint in endpoints
            ]
        },
    )


def _client(
    config,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str = "synthetic-key",
    run_dir: Path | None = None,
    provider_policy: OpenRouterProviderPolicy | None = None,
    reasoning: OpenRouterReasoning | None = None,
    reasoning_policy: ReasoningPolicyArtifact | None = None,
    qualification_routing: tuple[OpenRouterQualificationRoutingEvidence, ...] | None = None,
    production_qualification: Any | None = None,
    privacy_models: tuple[str, ...] = ("alpha/atlas-secure",),
) -> tuple[OpenRouterClient, httpx.AsyncClient, UsageLedger]:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(
        transport=transport,
        base_url="https://fake.test/api/v1/",
    )
    usage = UsageLedger()
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
    )
    policy = provider_policy or OpenRouterProviderPolicy()
    if qualification_routing is None and policy.certification:
        qualification_routing = (_qualification_routing(provider=policy.configured_endpoints[0]),)
    effective_privacy_policy = (
        _strict_privacy_policy(
            config,
            models=privacy_models,
            providers=policy.configured_endpoints,
        )
        if (config.privacy.profile is PrivacyProfile.STRICT_ZDR and policy.configured_endpoints)
        else None
    )
    client = OpenRouterClient(
        api_key=api_key,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
        run_dir=run_dir,
        provider_policy=policy,
        reasoning=reasoning,
        reasoning_policy=reasoning_policy,
        token_budgets=config.token_budgets,
        qualification_routing=qualification_routing or (),
        production_qualification=production_qualification,
        effective_privacy_policy=effective_privacy_policy,
    )
    return client, http_client, usage


async def _paid_control_client_with_mock_transport(
    config,
    *,
    budget: BudgetManager,
    handler: Callable[[httpx.Request], httpx.Response],
    provider_policy: OpenRouterProviderPolicy,
    qualification_routing: tuple[OpenRouterQualificationRoutingEvidence, ...] | None = None,
) -> tuple[OpenRouterClient, UsageLedger, httpx.AsyncClient]:
    usage = UsageLedger()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
        provider_policy=provider_policy,
        qualification_routing=(
            qualification_routing
            if qualification_routing is not None
            else (
                (_qualification_routing(provider=provider_policy.configured_endpoints[0]),)
                if provider_policy.certification
                else ()
            )
        ),
        effective_privacy_policy=_strict_privacy_policy(
            config,
            models=tuple(
                sorted(
                    {binding.exact_model_id for binding in (qualification_routing or ())}
                    or {"alpha/atlas-secure"}
                )
            ),
            providers=provider_policy.configured_endpoints,
            requested_budget_usd=Decimal(str(budget.total_usd)),
        ),
    )
    assert client.execution_evidence is ExecutionEvidenceKind.MOCK
    return client, usage, http_client


def _owned_client(config, *, base_url: str) -> OpenRouterClient:
    return OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
        ),
        usage=UsageLedger(),
        base_url=base_url,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        OPENROUTER_DEFAULT_BASE_URL,
        f"{OPENROUTER_DEFAULT_BASE_URL}/",
        f"{OPENROUTER_DEFAULT_BASE_URL}///",
    ],
)
async def test_owned_official_transport_is_real_after_trailing_slash_normalization(
    config_factory,
    base_url: str,
) -> None:
    client = _owned_client(config_factory(), base_url=base_url)
    try:
        assert client.execution_evidence is ExecutionEvidenceKind.REAL
        assert str(client._client.base_url) == f"{OPENROUTER_DEFAULT_BASE_URL}/"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_injected_network_transport_is_unverified_and_cannot_send(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(base_url=f"{OPENROUTER_DEFAULT_BASE_URL}/")
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config_factory().execution,
        privacy=config_factory().privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=2_048,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
        ),
        usage=UsageLedger(),
        http_client=http_client,
    )
    try:
        assert client.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        with pytest.raises(OpenRouterPrivacyError, match="injected provider clients"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        client.clear_credentials()
        await http_client.aclose()


@pytest.mark.asyncio
async def test_injected_network_transport_cannot_redirect_operator_credentials(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(base_url="https://unapproved.invalid/api/v1/")
    try:
        with pytest.raises(OpenRouterPrivacyError, match="canonical OpenRouter"):
            OpenRouterClient(
                api_key="synthetic-key",
                execution=config_factory().execution,
                privacy=config_factory().privacy,
                budget=BudgetManager(
                    total_usd=20,
                    max_output_tokens=2_048,
                    conservative_usd_per_million_tokens=10,
                    max_requests_per_agent=2,
                ),
                usage=UsageLedger(),
                http_client=http_client,
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_owned_transport_replacement_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    replacement = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"data": {}})),
        base_url=f"{OPENROUTER_DEFAULT_BASE_URL}/",
    )
    client._client = replacement
    try:
        with pytest.raises(OpenRouterPrivacyError, match="transport provenance changed"):
            await client.validate_authentication()
    finally:
        await client.close()
        await replacement.aclose()


@pytest.mark.asyncio
async def test_owned_client_send_mutation_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)

    async def fabricated_send(*_args: Any, **_kwargs: Any) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    client._client.send = fabricated_send  # type: ignore[method-assign]
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callable provenance"):
            await client.validate_authentication()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_owned_transport_request_mutation_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    transport = client._client._transport

    async def fabricated_request(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    transport.handle_async_request = fabricated_request  # type: ignore[method-assign]
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callable provenance"):
            await client.validate_authentication()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_mock_transport_exception_is_secretless(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-transport-exception-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        raise RuntimeError(f"untrusted transport detail {canary}")

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="transport failed safely") as captured:
            await client.validate_authentication()
    finally:
        await http_client.aclose()

    assert canary not in str(captured.value)
    assert canary not in repr(captured.value.__context__)


@pytest.mark.asyncio
async def test_real_completion_requires_durable_atomic_cost_ledger(config_factory) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    try:
        with pytest.raises(OpenRouterCostControlError, match="durable atomic cost ledger"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_real_completion_requires_frozen_identity_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / "identity-preflight-ledger.json",
        cap_usd=Decimal("20"),
    )
    endpoint_snapshot = _endpoint_snapshot()
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
        base_url=OPENROUTER_DEFAULT_BASE_URL,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(endpoint_snapshot),),
        effective_privacy_policy=_strict_privacy_policy(config),
    )
    client.register_certification_endpoint_snapshot(evidence=endpoint_snapshot)
    client._authentication_validated = True
    try:
        with pytest.raises(OpenRouterModelError, match="frozen model identity"):
            await client.complete(
                role="model_benchmark",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()

    assert ledger.snapshot().spent_usd == 0
    assert ledger.snapshot().active_reserved_usd == 0


@pytest.mark.asyncio
async def test_certification_requires_validated_endpoint_pricing_before_send(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"bounded"}',
            provider="Approved Provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    endpoint_snapshot = _endpoint_snapshot()
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(endpoint_snapshot),),
        effective_privacy_policy=_strict_privacy_policy(
            config,
            requested_budget_usd=Decimal(str(budget.total_usd)),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="validated endpoint pricing"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
        client.register_certification_endpoint_snapshot(
            evidence=endpoint_snapshot,
        )
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "bounded"
    assert calls == 1
    assert ledger.snapshot().active_reserved_usd == 0
    assert ledger.snapshot().spent_usd == Decimal("0.01")


@pytest.mark.asyncio
async def test_paid_request_without_effective_privacy_evidence_refuses_before_reservation(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / "missing-privacy-policy-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    snapshot = _endpoint_snapshot()
    client, _usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(snapshot),),
    )
    client.effective_privacy_policy = None
    try:
        client.register_certification_endpoint_snapshot(evidence=snapshot)
        with pytest.raises(OpenRouterPrivacyError, match="requires effective privacy evidence"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_defect", "expected_error"),
    [
        ("model", "model outside effective privacy evidence"),
        ("provider", "endpoint outside effective privacy evidence"),
        ("budget", "differs from the active model budget"),
    ],
)
async def test_paid_request_privacy_binding_mismatch_refuses_before_reservation(
    config_factory,
    tmp_path: Path,
    policy_defect: str,
    expected_error: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / f"privacy-{policy_defect}-mismatch-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    snapshot = _endpoint_snapshot()
    client, _usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(snapshot),),
    )
    client.effective_privacy_policy = _strict_privacy_policy(
        config,
        models=(("other/model",) if policy_defect == "model" else ("alpha/atlas-secure",)),
        providers=(("other-provider",) if policy_defect == "provider" else ("approved-provider",)),
        requested_budget_usd=Decimal("19" if policy_defect == "budget" else "20"),
    )
    try:
        client.register_certification_endpoint_snapshot(evidence=snapshot)
        with pytest.raises(OpenRouterPrivacyError, match=expected_error):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_paid_privacy_policy_is_revalidated_after_reservation(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / "privacy-revalidation-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    snapshot = _endpoint_snapshot()
    client, _usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(snapshot),),
    )
    original_reserve = budget.reserve

    async def reserve_then_replace_policy(*args: Any, **kwargs: Any) -> Any:
        reservation = await original_reserve(*args, **kwargs)
        client.effective_privacy_policy = _strict_privacy_policy(
            config,
            requested_budget_usd=Decimal("19"),
        )
        return reservation

    monkeypatch.setattr(budget, "reserve", reserve_then_replace_policy)
    try:
        client.register_certification_endpoint_snapshot(evidence=snapshot)
        with pytest.raises(OpenRouterPrivacyError, match="differs from the active model budget"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    ledger_snapshot = ledger.snapshot()
    assert calls == 0
    assert ledger_snapshot.active_reserved_usd == 0
    assert ledger_snapshot.spent_usd == 0
    assert len(ledger_snapshot.entries) == 1
    assert ledger_snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_certification_endpoint_pricing_registration_is_exact(config_factory) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterProviderPolicyError, match="exact configured"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(provider="other-provider"),
            )
        with pytest.raises(OpenRouterCostControlError, match="unsupported"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(
                    pricing={
                        "prompt": "0.1",
                        "completion": "0.2",
                        "unknown_fee": "1",
                    }
                ),
            )
        with pytest.raises(OpenRouterCostControlError, match="cannot be provider-capped"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(
                    pricing={
                        "prompt": "0.1",
                        "completion": "0.2",
                        "internal_reasoning": "0",
                    }
                ),
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_provider_cost_is_parsed_exactly_before_decimal_ledger_reconciliation(
    config_factory,
    tmp_path: Path,
) -> None:
    exact_cost = Decimal("0.100000000000000004")

    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"exact-cost"}',
            cost=0,
            provider="Approved Provider",
        )
        serialized = json.dumps(payload, sort_keys=True).replace(
            '"cost": 0',
            f'"cost": {exact_cost}',
            1,
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            content=serialized.encode(),
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / "exact-provider-cost-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    endpoint_snapshot = _endpoint_snapshot(
        pricing={
            "prompt": "0.000001",
            "completion": "0.001",
            "request": "0",
        }
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(endpoint_snapshot),),
    )
    try:
        client.register_certification_endpoint_snapshot(evidence=endpoint_snapshot)
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert result.answer == "exact-cost"
    assert ledger.snapshot().spent_usd == exact_cost
    assert usage.records[0].reported_cost_usd == float(exact_cost)


@pytest.mark.asyncio
async def test_endpoint_registration_rejects_ambiguous_provider_display_names(
    config_factory,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    try:
        with pytest.raises(EndpointSnapshotValidationError, match="display name is ambiguous"):
            client.register_endpoint_snapshot(
                evidence=_multi_endpoint_snapshot(shared_provider_name=True)
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_provider_price_ceiling_never_rounds_below_validated_snapshot(
    config_factory,
) -> None:
    prompt_price = Decimal("0.000000100000000000000000000000000001")
    completion_price = Decimal("0.000000200000000000000000000000000001")
    config = config_factory(execution={"max_json_repair_attempts": 0})
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        client.register_certification_endpoint_snapshot(
            evidence=_endpoint_snapshot(
                pricing={
                    "prompt": format(prompt_price, "f"),
                    "completion": format(completion_price, "f"),
                }
            )
        )
        request = client.build_request(
            model="alpha/atlas-secure",
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    max_price = request["provider"]["max_price"]
    assert Decimal(str(max_price["prompt"])) >= prompt_price * 1_000_000
    assert Decimal(str(max_price["completion"])) >= completion_price * 1_000_000


@pytest.mark.asyncio
async def test_real_noncertification_completion_requires_endpoint_bound_budget_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"must not execute"}',
            cost=0.000001,
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "noncertification-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=False,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="endpoint-bound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_paid_non_zdr_completion_requires_live_consent_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0
    credential_canary = "synthetic-paid-non-zdr-credential-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "missing-privacy-authorization-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client = OpenRouterClient(
        api_key=credential_canary,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
    )
    try:
        with pytest.raises(
            OpenRouterPrivacyError,
            match="requires live operator privacy authorization",
        ) as caught:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()
    assert credential_canary not in str(caught.value)
    assert credential_canary not in repr(caught.value.__context__)


@pytest.mark.asyncio
async def test_non_zdr_model_membership_uses_validated_capability_snapshot(
    config_factory,
    tmp_path: Path,
) -> None:
    class PermissiveTuple(tuple[str, ...]):
        def __contains__(self, _value: object) -> bool:
            return True

    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    policy, authorization, _canaries = _frontier_privacy_authorization(tmp_path)
    forged_policy = policy.model_copy()
    object.__setattr__(
        forged_policy,
        "permitted_model_ids",
        PermissiveTuple(policy.permitted_model_ids),
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "permissive-model-membership-ledger.json",
        cap_usd=Decimal("20"),
    )
    client = OpenRouterClient(
        api_key="synthetic-permissive-membership-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        effective_privacy_policy=forged_policy,
        privacy_authorization=authorization,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError, match="model outside consent"):
            await client.complete(
                role="source_audit",
                models=["outside/model"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_certification_non_zdr_client_requires_live_consent_at_construction(
    config_factory,
) -> None:
    calls = 0
    credential_canary = "synthetic-certification-non-zdr-credential-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    try:
        with pytest.raises(
            OpenRouterPrivacyError,
            match="requires live operator privacy authorization",
        ) as caught:
            OpenRouterClient(
                api_key=credential_canary,
                execution=config.execution,
                privacy=config.privacy,
                budget=BudgetManager(
                    total_usd=20,
                    max_output_tokens=config.execution.max_output_tokens_per_request,
                    conservative_usd_per_million_tokens=10,
                    max_requests_per_agent=2,
                ),
                usage=UsageLedger(),
                http_client=http_client,
                provider_policy=OpenRouterProviderPolicy(
                    certification=True,
                    only=("approved-provider",),
                    allow_fallbacks=False,
                ),
                qualification_routing=(_qualification_routing(provider="approved-provider"),),
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert credential_canary not in str(caught.value)
    assert credential_canary not in repr(caught.value.__context__)


@pytest.mark.asyncio
async def test_client_copies_stateful_provider_policy_before_request_construction(
    config_factory,
) -> None:
    class StatefulEndpointTuple(tuple[str, ...]):
        emit_outside = False

        def __iter__(self):
            if self.emit_outside:
                return iter(("outside-provider",))
            return super().__iter__()

    config = config_factory(execution={"max_json_repair_attempts": 0})
    endpoints = StatefulEndpointTuple(("approved-provider",))
    policy = OpenRouterProviderPolicy(only=endpoints)
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=policy,
    )
    endpoints.emit_outside = True
    try:
        body = client.build_request(
            model="alpha/atlas-secure",
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert type(client.provider_policy.only) is tuple
    assert body["provider"]["only"] == ["approved-provider"]
    assert http_client.is_closed is True


@pytest.mark.asyncio
async def test_consent_bound_non_zdr_request_omits_zdr_and_serializes_only_hash_evidence(
    config_factory,
    tmp_path: Path,
) -> None:
    request_bodies: list[dict[str, Any]] = []
    credential_canary = "synthetic-valid-non-zdr-credential-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        request_bodies.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"validated"}',
            cost=0.001,
            provider="approved-provider",
        )

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    policy, authorization, consent_canaries = _frontier_privacy_authorization(tmp_path)
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "valid-non-zdr-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    usage = UsageLedger()
    client = OpenRouterClient(
        api_key=credential_canary,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
        effective_privacy_policy=policy,
        privacy_authorization=authorization,
    )
    try:
        client.register_endpoint_snapshot(
            evidence=_endpoint_snapshot(require_zdr=False),
        )
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert completion.value.answer == "validated"
    assert len(request_bodies) == 1
    provider_payload = request_bodies[0]["provider"]
    assert provider_payload == {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "only": ["approved-provider"],
        "max_price": provider_payload["max_price"],
    }
    assert "zdr" not in provider_payload
    assert completion.usage_record.routing["privacy_authorization"] == ("CONSENT_BOUND_NON_ZDR")
    assert completion.usage_record.routing["privacy_endpoint_policy_class"] == (
        EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED.value
    )
    assert completion.usage_record.routing["effective_privacy_policy_sha256"] == (
        policy.evidence_sha256
    )
    serialized_evidence = json.dumps(
        {
            "request": request_bodies[0],
            "usage": completion.usage_record.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert credential_canary not in serialized_evidence
    assert all(canary not in serialized_evidence for canary in consent_canaries)
    assert usage.records == [completion.usage_record]


@pytest.mark.asyncio
async def test_non_zdr_consent_expiry_after_reservation_prevents_transport_and_releases_budget(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    evaluated_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = evaluated_at + timedelta(minutes=10)

    class ControlledDateTime(datetime):
        current = evaluated_at

        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            value = cls.current
            return value if tz is None else value.astimezone(tz)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    policy, authorization, _canaries = _frontier_privacy_authorization(
        tmp_path,
        evaluation_time=evaluated_at,
        expires_at=expires_at,
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "expiry-after-reservation-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    client = OpenRouterClient(
        api_key="synthetic-expiry-after-reservation-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
        effective_privacy_policy=policy,
        privacy_authorization=authorization,
    )
    original_reserve = budget.reserve

    async def reserve_then_expire(*args: Any, **kwargs: Any) -> Any:
        reservation = await original_reserve(*args, **kwargs)
        ControlledDateTime.current = expires_at
        return reservation

    monkeypatch.setattr(openrouter_module, "datetime", ControlledDateTime)
    monkeypatch.setattr(budget, "reserve", reserve_then_expire)
    try:
        client.register_endpoint_snapshot(evidence=_endpoint_snapshot(require_zdr=False))
        with pytest.raises(OpenRouterPrivacyError, match="not currently valid"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    snapshot = ledger.snapshot()
    assert calls == 0
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_non_zdr_exact_request_endpoint_is_refused_before_reservation(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    policy, authorization, _canaries = _frontier_privacy_authorization(tmp_path)
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "exact-route-revalidation-ledger.json",
        cap_usd=Decimal("20"),
    )
    client = OpenRouterClient(
        api_key="synthetic-exact-route-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
        effective_privacy_policy=policy,
        privacy_authorization=authorization,
    )
    try:
        client.register_endpoint_snapshot(evidence=_endpoint_snapshot(require_zdr=False))
        with pytest.raises(
            OpenRouterPrivacyError,
            match="endpoint outside effective privacy evidence",
        ):
            await client._complete_one(
                role="source_audit",
                model="alpha/atlas-secure",
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                fallback_used=False,
                qualification_binding=_qualification_routing(provider="outside-consent-provider"),
            )
    finally:
        await client.close()
        await http_client.aclose()

    snapshot = ledger.snapshot()
    assert calls == 0
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert snapshot.entries == ()


@pytest.mark.asyncio
async def test_non_zdr_exact_endpoint_requires_disclosure_before_reservation(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0
    providers = ("approved-provider", "zdr-only-provider")

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    policy, authorization, _canaries = _frontier_privacy_authorization(
        tmp_path,
        provider_policy_classes=(
            (
                "approved-provider",
                EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
            ),
            ("zdr-only-provider", EndpointPolicyClass.ZDR),
        ),
    )
    endpoint_payloads = [
        {
            "tag": provider,
            "provider_name": provider.replace("-", " ").title(),
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        }
        for provider in providers
    ]
    endpoint_snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=providers,
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": endpoint_payloads,
            }
        },
        require_zdr=False,
    )
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "exact-disclosure-revalidation-ledger.json",
        cap_usd=Decimal("20"),
    )
    client = OpenRouterClient(
        api_key="synthetic-exact-disclosure-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=providers,
            allow_fallbacks=False,
        ),
        effective_privacy_policy=policy,
        privacy_authorization=authorization,
    )
    try:
        client.register_endpoint_snapshot(evidence=endpoint_snapshot)
        with pytest.raises(OpenRouterPrivacyError, match="without exact non-ZDR disclosure"):
            await client._complete_one(
                role="source_audit",
                model="alpha/atlas-secure",
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                fallback_used=False,
                qualification_binding=_qualification_routing(provider="zdr-only-provider"),
            )
    finally:
        await client.close()
        await http_client.aclose()

    snapshot = ledger.snapshot()
    assert calls == 0
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert snapshot.entries == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_authorization",
    ["route_mismatch", "expired", "tampered"],
)
async def test_invalid_non_zdr_authorization_is_refused_before_transport(
    config_factory,
    tmp_path: Path,
    invalid_authorization: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        privacy={
            "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
            "require_zdr": False,
            "maximum_model_retention": "temporary",
        },
        execution={"max_json_repair_attempts": 0},
    )
    current = datetime.now(UTC).replace(microsecond=0)
    if invalid_authorization == "expired":
        policy, authorization, _canaries = _frontier_privacy_authorization(
            tmp_path,
            evaluation_time=current - timedelta(minutes=90),
            issued_at=current - timedelta(hours=2),
            expires_at=current - timedelta(hours=1),
        )
        provider = "approved-provider"
        expected_error = "not currently valid"
    elif invalid_authorization == "tampered":
        policy, authorization, _canaries = _frontier_privacy_authorization(tmp_path)
        object.__setattr__(
            authorization,
            "_evidence",
            policy.model_copy(update={"evidence_sha256": "7" * 64}),
        )
        provider = "approved-provider"
        expected_error = "binding is inconsistent"
    else:
        policy, authorization, _canaries = _frontier_privacy_authorization(tmp_path)
        provider = "different-provider"
        expected_error = "different exact route"
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / f"invalid-{invalid_authorization}-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client = OpenRouterClient(
        api_key="synthetic-invalid-authorization-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            only=(provider,),
            allow_fallbacks=False,
        ),
        effective_privacy_policy=policy,
        privacy_authorization=authorization,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError, match=expected_error):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_real_completion_requires_registered_endpoint_snapshot_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"must not execute"}',
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "missing-snapshot-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="validated endpoint pricing"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_multi_endpoint_snapshot_reserves_worst_case_advertised_price(
    config_factory,
    tmp_path: Path,
) -> None:
    observed_reservations: list[float] = []
    observed_request_material: list[str] = []
    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "multi-endpoint-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        observed_reservations.append(budget.reserved_usd)
        body = json.loads(request.content)
        observed_request_material.append(
            json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        )
        return _completion_response(
            '{"answer":"bounded"}',
            cost=0.000001,
            provider="provider-economy",
        )

    client, _usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    snapshot = _multi_endpoint_snapshot()
    try:
        client.register_endpoint_snapshot(evidence=snapshot)
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    premium = snapshot.endpoint("provider-premium")
    assert result.answer == "bounded"
    assert len(observed_reservations) == len(observed_request_material) == 1
    provider = json.loads(observed_request_material[0])["provider"]
    assert provider["max_price"] == {
        "completion": float(Decimal(premium.pricing["completion"]) * 1_000_000),
        "prompt": float(Decimal(premium.pricing["prompt"]) * 1_000_000),
        "request": float(Decimal(premium.pricing["request"])),
    }
    expected_worst_case = (
        Decimal(premium.pricing["prompt"]) * len(observed_request_material[0].encode("utf-8"))
        + Decimal(premium.pricing["completion"]) * config.execution.max_output_tokens_per_request
        + Decimal(premium.pricing["request"])
    )
    assert observed_reservations[0] == pytest.approx(float(expected_worst_case))


@pytest.mark.asyncio
async def test_multi_endpoint_routing_evidence_binds_actual_endpoint_and_full_snapshot(
    config_factory,
    tmp_path: Path,
) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "multi-endpoint-evidence-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=lambda _request: _completion_response(
            '{"answer":"premium"}',
            cost=0.000001,
            provider="provider-premium",
        ),
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    snapshot = _multi_endpoint_snapshot()
    try:
        client.register_endpoint_snapshot(evidence=snapshot)
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    record = usage.records[0]
    assert result.answer == "premium"
    assert record.actual_provider_endpoint == "provider-premium"
    assert record.configured_provider_endpoints == [
        "provider-economy",
        "provider-premium",
    ]
    assert record.routing["selected_provider_endpoint"] == "provider-premium"
    assert record.routing["configured_provider_only"] == [
        "provider-economy",
        "provider-premium",
    ]
    assert record.routing["endpoint_snapshot_sha256"] == snapshot.snapshot_sha256
    assert (
        record.routing["endpoint_pricing_sha256"]
        == snapshot.endpoint("provider-premium").pricing_sha256
    )


@pytest.mark.asyncio
async def test_frozen_discovery_authorizes_and_records_exact_canonical_route(
    config_factory,
    tmp_path: Path,
) -> None:
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"canonical"}',
            selected_model=canonical_model,
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert result.answer == "canonical"
    assert record.returned_model == "alpha/atlas-secure"
    assert record.actual_model == canonical_model
    assert record.routing["selected_model"] == canonical_model
    assert (
        record.routing["catalog_identity_binding_sha256"]
        == evidence.catalog_identity_binding_sha256
    )
    assert record.routing["discovery_evidence_sha256"] == evidence.discovery_evidence_sha256
    assert record.identity_strength is OpenRouterIdentityStrength.UNBOUND
    assert record.routing["identity_binding_status"] == "generation_metadata_pending"
    assert not is_creditable_usage_record(record, require_certification=True)

    retrieved_at = datetime.now(UTC)
    generation = validate_openrouter_generation_payload(
        _generation_payload(model=canonical_model),
        requested_generation_id="generation-test",
        retrieved_at=retrieved_at,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    binding = client.bind_generation_identity(
        usage_record=record,
        generation_evidence=generation,
        evaluated_at=retrieved_at,
    )
    credited = client.usage_with_bound_identity(
        usage_record=record,
        identity_binding=binding,
    )
    assert is_creditable_usage_record(credited, require_certification=True)


@pytest.mark.parametrize("fault", ["unbound", "wrong_canonical", "attempt_mismatch"])
@pytest.mark.asyncio
async def test_canonical_route_must_match_one_frozen_identity(
    config_factory,
    tmp_path: Path,
    fault: str,
) -> None:
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        selected_model = (
            "alpha/atlas-secure-20260728" if fault == "wrong_canonical" else canonical_model
        )
        payload = _completion(
            '{"answer":"must reject"}',
            selected_model=selected_model,
            provider="Approved Provider",
        )
        if fault == "attempt_mismatch":
            payload["openrouter_metadata"]["attempts"][0]["model"] = "alpha/atlas-secure"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    try:
        if fault != "unbound":
            client.register_certification_model_discovery(
                evidence=evidence,
                manifest=manifest,
            )
        with pytest.raises((OpenRouterModelError, OpenRouterSchemaError)):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert usage.records[0].status != "success"


@pytest.mark.asyncio
async def test_top_level_canonical_alias_is_accepted_as_provisional_bound_identity(
    config_factory,
    tmp_path: Path,
) -> None:
    requested_model = "alpha/atlas-secure"
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"canonical alias accepted"}',
            model=canonical_model,
            selected_model=canonical_model,
            provider="Approved Provider",
        )
        payload["openrouter_metadata"]["requested"] = requested_model
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        result = await client.complete(
            role="source_audit",
            models=[requested_model],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert result.answer == "canonical alias accepted"
    assert record.requested_model == requested_model
    assert record.returned_model == canonical_model
    assert record.actual_model == canonical_model
    assert record.routing["requested_model"] == requested_model
    assert record.routing["selected_model"] == canonical_model
    assert record.routing["canonical_model"] == canonical_model
    assert record.routing["qualified_exact_model_id"] == requested_model
    assert record.routing["endpoint_snapshot_sha256"] == (
        evidence.endpoint_snapshot.snapshot_sha256
    )
    assert (
        record.routing["catalog_identity_binding_sha256"]
        == evidence.catalog_identity_binding_sha256
    )
    assert not record.fallback_used
    assert not record.substitution_detected
    # Completion metadata can prove this provisional binding, but certification
    # credit remains UNBOUND until generation metadata is independently fetched.
    assert record.identity_strength.value == "UNBOUND"
    assert record.routing["provisional_identity_strength"] == ("CANONICAL_MODEL_AND_ENDPOINT_BOUND")
    assert record.routing["identity_binding_status"] == "generation_metadata_pending"
    assert not is_creditable_usage_record(record, require_certification=True)
    retrieved_at = datetime.now(UTC)
    generation = validate_openrouter_generation_payload(
        _generation_payload(model=canonical_model),
        requested_generation_id="generation-test",
        retrieved_at=retrieved_at,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    bound = client.bind_generation_identity(
        usage_record=record,
        generation_evidence=generation,
        evaluated_at=retrieved_at,
    )
    assert bound.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    assert bound.generation is not None
    assert bound.generation.generation_id == record.openrouter_generation_id
    credited = client.usage_with_bound_identity(
        usage_record=record,
        identity_binding=bound,
    )
    assert (
        credited.identity_strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    )
    assert is_creditable_usage_record(credited, require_certification=True)
    tampered_routing = dict(credited.routing)
    tampered_binding = dict(tampered_routing["identity_binding"])
    tampered_binding["binding_sha256"] = "0" * 64
    tampered_routing["identity_binding"] = tampered_binding
    assert not is_creditable_usage_record(
        credited.model_copy(update={"routing": tampered_routing}),
        require_certification=True,
    )

    real_request_with_mock_generation = client.bind_generation_identity(
        usage_record=record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
        generation_evidence=generation,
        evaluated_at=retrieved_at,
    )
    assert real_request_with_mock_generation.strength is OpenRouterIdentityStrength.UNBOUND
    assert real_request_with_mock_generation.diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_EVIDENCE_UNTRUSTED,
    )


@pytest.mark.asyncio
async def test_missing_generation_metadata_preserves_unbound_identity_result(
    config_factory,
    tmp_path: Path,
) -> None:
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"valid response awaiting generation metadata"}',
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    unbound = client.bind_generation_identity(
        usage_record=usage.records[0],
        generation_evidence=None,
    )
    assert unbound.strength is OpenRouterIdentityStrength.UNBOUND
    assert unbound.generation is None
    assert unbound.diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
    )
    assert unbound.request.validated_response_sha256 == (usage.records[0].validated_response_sha256)
    concluded = client._usage_with_unbound_identity(
        usage_record=usage.records[0],
        identity_binding=unbound,
        trusted_issuer=None,
    )
    assert concluded.identity_strength is OpenRouterIdentityStrength.UNBOUND
    assert concluded.routing["identity_binding_status"] == "generation_metadata_unbound"
    assert concluded.routing["identity_binding_sha256"] == unbound.binding_sha256
    assert concluded.routing["identity_binding"]["diagnostic_codes"] == [
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING.value
    ]
    assert usage.records == [concluded]
    assert not is_creditable_usage_record(concluded, require_certification=True)


@pytest.mark.asyncio
async def test_real_completion_dispatches_through_generation_binding_before_return(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"provisional"}',
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    client.register_certification_model_discovery(
        evidence=evidence,
        manifest=manifest,
    )
    provisional = await client.complete_with_evidence(
        role="source_audit",
        models=["alpha/atlas-secure"],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )
    calls: list[str] = []

    async def completed_without_transport(**_kwargs: Any) -> Any:
        return provisional

    async def bind_before_return(completion: Any) -> Any:
        calls.append(completion.usage_record.request_id)
        return completion

    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    client._qualification_routing = {}
    monkeypatch.setattr(client, "_complete_one", completed_without_transport)
    monkeypatch.setattr(client, "_bind_real_completion_identity", bind_before_return)
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result is provisional
    assert calls == [provisional.usage_record.request_id]


@pytest.mark.asyncio
async def test_real_unbound_generation_result_is_preserved_without_host_model_fallback(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary_manifest, primary_evidence = _model_discovery_run(tmp_path)
    fallback_manifest, fallback_evidence = _model_discovery_run(
        tmp_path,
        exact_model="bravo/borealis-secure",
        canonical_model="bravo/borealis-secure-20260727",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        model = json.loads(request.content)["model"]
        return _completion_response(
            f'{{"answer":"{model}"}}',
            model=model,
            provider="Approved Provider",
        )

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
    )
    client.register_model_discovery(
        evidence=primary_evidence,
        manifest=primary_manifest,
    )
    client.register_model_discovery(
        evidence=fallback_evidence,
        manifest=fallback_manifest,
    )
    primary = await client.complete_with_evidence(
        role="source_audit",
        models=["alpha/atlas-secure"],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )
    fallback = await client.complete_with_evidence(
        role="source_audit",
        models=["bravo/borealis-secure"],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )
    by_model = {
        primary.usage_record.requested_model: primary,
        fallback.usage_record.requested_model: fallback,
    }
    attempts: list[str] = []

    async def completed_without_transport(*, model: str, **_kwargs: Any) -> Any:
        attempts.append(model)
        return by_model[model]

    async def preserve_unbound(completion: Any) -> Any:
        return completion

    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    monkeypatch.setattr(client, "_complete_one", completed_without_transport)
    monkeypatch.setattr(client, "_bind_real_completion_identity", preserve_unbound)
    try:
        result = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result is primary
    assert result.usage_record.identity_strength is OpenRouterIdentityStrength.UNBOUND
    assert attempts == ["alpha/atlas-secure"]


@pytest.mark.asyncio
async def test_response_identity_mismatch_retains_value_without_host_model_fallback(
    config_factory,
    tmp_path: Path,
) -> None:
    primary_manifest, primary_evidence = _model_discovery_run(tmp_path)
    fallback_manifest, fallback_evidence = _model_discovery_run(
        tmp_path,
        exact_model="bravo/borealis-secure",
        canonical_model="bravo/borealis-secure-20260727",
    )
    attempts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested = json.loads(request.content)["model"]
        attempts.append(requested)
        payload = _completion(
            '{"answer":"schema-valid-primary-unbound-canary"}',
            model=requested,
            provider="Approved Provider",
        )
        if requested == "alpha/atlas-secure":
            payload["model"] = "unrelated/vendor-model"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
    )
    client.register_model_discovery(evidence=primary_evidence, manifest=primary_manifest)
    client.register_model_discovery(evidence=fallback_evidence, manifest=fallback_manifest)
    try:
        result = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert attempts == ["alpha/atlas-secure"]
    assert result.value.answer == "schema-valid-primary-unbound-canary"
    assert result.usage_record.status == "unbound_identity"
    assert result.usage_record.routing["identity_binding_status"] == ("response_identity_unbound")
    assert result.usage_record.routing["identity_diagnostic"]["code"] == (
        "returned_model_outside_frozen_identity"
    )
    assert not is_creditable_usage_record(result.usage_record)
    assert client.retained_unbound_completions() == (result,)
    client.clear_retained_unbound_completions()
    assert client.retained_unbound_completions() == ()


@pytest.mark.asyncio
async def test_actual_real_identity_binding_retains_metadata_fetch_failure(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    manifest, evidence = _model_discovery_run(tmp_path)
    qualification = _qualification_routing_for_discovery(evidence)
    mock_client, mock_http_client, _mock_usage = _client(
        config,
        lambda _request: _completion_response(
            '{"answer":"real-metadata-fetch-failure-canary"}',
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(qualification,),
    )
    mock_client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    try:
        provisional = await mock_client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await mock_http_client.aclose()

    real_usage = UsageLedger()
    ledger = AtomicCostLedger.initialize(
        tmp_path / "unbound-metadata-ledger.json",
        cap_usd=Decimal("20"),
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=real_usage,
        base_url=OPENROUTER_DEFAULT_BASE_URL,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(),
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    client._authentication_validated = True
    real_record = UsageRecord.model_validate(
        {
            **provisional.usage_record.model_dump(mode="json"),
            "execution_evidence": ExecutionEvidenceKind.REAL,
        }
    )
    real_record = _attest_owned_real_usage_record(real_record)
    real_usage.add(real_record)
    real_completion = StructuredCompletion(value=provisional.value, usage_record=real_record)

    async def return_provisional(**_kwargs: Any) -> Any:
        return real_completion

    monkeypatch.setattr(client, "_complete_one", return_provisional)
    await client._client.aclose()
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        client.clear_credentials()

    diagnostic_codes = result.usage_record.routing["identity_binding"]["diagnostic_codes"]
    assert diagnostic_codes == [
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INVALID.value,
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING.value,
    ]
    assert result.value.answer == "real-metadata-fetch-failure-canary"
    assert result.usage_record.execution_evidence is ExecutionEvidenceKind.REAL
    assert not is_creditable_usage_record(result.usage_record, require_real=True)
    assert client.retained_unbound_completions() == (result,)
    diagnostic_text = json.dumps(result.usage_record.routing, sort_keys=True)
    assert "real-metadata-fetch-failure-canary" not in diagnostic_text


@pytest.mark.asyncio
async def test_real_ordinary_provider_fallback_is_preserved_as_unbound(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    manifest, evidence = _model_discovery_run(tmp_path)
    mock_client, mock_http_client, _mock_usage = _client(
        config,
        lambda _request: _completion_response(
            '{"answer":"ordinary-provider-fallback-canary"}',
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=True,
        ),
    )
    mock_client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        provisional = await mock_client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await mock_http_client.aclose()

    routing = {
        **provisional.usage_record.routing,
        "selected_provider_endpoint": "fallback-provider",
        "selected_provider_identity": "fallback-provider",
        "selected_provider_name": "Fallback Provider",
        "response_provider_identity": "Fallback Provider",
        "router_strategy": "fallback",
        "router_attempt": 2,
        "router_attempt_count": 2,
        "provider_fallback_used": True,
    }
    real_record = UsageRecord.model_validate(
        {
            **provisional.usage_record.model_dump(mode="json"),
            "provider": "Fallback Provider",
            "actual_provider_endpoint": "fallback-provider",
            "fallback_used": True,
            "execution_evidence": ExecutionEvidenceKind.REAL,
            "routing": routing,
        }
    )
    real_record = _attest_owned_real_usage_record(real_record)
    real_usage = UsageLedger()
    real_usage.add(real_record)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ordinary-provider-fallback-ledger.json",
        cap_usd=Decimal("20"),
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=real_usage,
        base_url=OPENROUTER_DEFAULT_BASE_URL,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=True,
        ),
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    client.provider_policy = OpenRouterProviderPolicy(
        only=("approved-provider", "fallback-provider"),
        allow_fallbacks=True,
    )
    client._authentication_validated = True
    real_completion = StructuredCompletion(value=provisional.value, usage_record=real_record)

    async def return_provisional(**_kwargs: Any) -> Any:
        return real_completion

    monkeypatch.setattr(client, "_complete_one", return_provisional)
    await client._client.aclose()
    try:
        result = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        client.clear_credentials()

    assert result.value.answer == "ordinary-provider-fallback-canary"
    assert result.usage_record.identity_strength is OpenRouterIdentityStrength.UNBOUND
    assert result.usage_record.routing["identity_binding_status"] == ("generation_metadata_unbound")
    assert result.usage_record.routing["identity_binding"]["diagnostic_codes"] == [
        OpenRouterIdentityDiagnosticCode.ENDPOINT_VARIANT_MISMATCH.value,
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_INTEGRITY_REJECTED.value,
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING.value,
        OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH.value,
        OpenRouterIdentityDiagnosticCode.UNAPPROVED_FALLBACK.value,
    ]
    assert not is_creditable_usage_record(result.usage_record, require_real=True)
    assert client.retained_unbound_completions() == (result,)


@pytest.mark.asyncio
async def test_value_only_real_caller_retains_unbound_completion_in_safe_typed_error(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response(
            '{"answer":"unbound-response-content-canary"}',
            model="unrelated/vendor-model",
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    completion = await client.complete_with_evidence(
        role="source_audit",
        models=["alpha/atlas-secure"],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )

    async def return_unbound(**_kwargs: Any) -> Any:
        return completion

    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "complete_with_evidence", return_unbound)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError) as caught:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert caught.value.completion is completion
    assert caught.value.completion.value.answer == "unbound-response-content-canary"
    rendered = "".join(
        traceback.format_exception(
            type(caught.value),
            caught.value,
            caught.value.__traceback__,
        )
    )
    assert "unbound-response-content-canary" not in str(caught.value)
    assert "unbound-response-content-canary" not in repr(caught.value)
    assert "unbound-response-content-canary" not in rendered


@pytest.mark.asyncio
async def test_bound_real_caller_rejects_but_retains_unbound_completion(
    config_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response(
            '{"answer":"bound-caller-content-canary"}',
            model="unrelated/vendor-model",
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    completion = await client.complete_with_evidence(
        role="source_audit",
        models=["alpha/atlas-secure"],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )

    async def return_unbound(**_kwargs: Any) -> Any:
        return completion

    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    monkeypatch.setattr(client, "complete_with_evidence", return_unbound)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError) as caught:
            await client.complete_with_bound_identity(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert caught.value.completion is completion
    assert caught.value.completion.value.answer == "bound-caller-content-canary"
    assert "bound-caller-content-canary" not in str(caught.value)
    assert "bound-caller-content-canary" not in repr(caught.value)


@pytest.mark.asyncio
async def test_unrelated_returned_model_preserves_valid_unbound_evidence_without_credit(
    config_factory,
    tmp_path: Path,
) -> None:
    requested_model = "alpha/atlas-secure"
    canonical_model = "alpha/atlas-secure-20260727"
    unrelated_model = "unrelated/vendor-model"
    raw_content = '{"answer":"schema-valid-unrelated-output-canary"}'
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            raw_content,
            model=requested_model,
            selected_model=canonical_model,
            provider="Approved Provider",
        )
        payload["model"] = unrelated_model
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        with pytest.raises(OpenRouterModelError):
            await client.complete(
                role="source_audit",
                models=[requested_model],
                system_prompt="system-prompt-canary",
                user_prompt="user-prompt-canary",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    expected_response_sha256 = hashlib.sha256(raw_content.encode()).hexdigest()
    assert record.requested_model == requested_model
    assert record.returned_model == unrelated_model
    assert record.response_sha256 == expected_response_sha256
    assert record.validated_response_sha256 == expected_response_sha256
    assert record.identity_strength.value == "UNBOUND"
    assert record.status != "success"
    assert record.validation_status.value == "model_mismatch"
    assert record.substitution_detected
    assert not is_creditable_usage_record(record, require_certification=True)

    diagnostic = record.routing["identity_diagnostic"]
    assert diagnostic["code"] == "returned_model_outside_frozen_identity"
    assert diagnostic["requested_model"] == requested_model
    assert diagnostic["canonical_model"] == canonical_model
    assert diagnostic["returned_model"] == unrelated_model
    diagnostic_text = json.dumps(diagnostic, sort_keys=True)
    assert "system-prompt-canary" not in diagnostic_text
    assert "user-prompt-canary" not in diagnostic_text
    assert "schema-valid-unrelated-output-canary" not in diagnostic_text
    assert "authorization" not in diagnostic_text.casefold()


@pytest.mark.asyncio
async def test_model_identity_registration_rejects_a_spliced_manifest(
    config_factory,
    tmp_path: Path,
) -> None:
    _first_manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model="alpha/atlas-secure-20260727",
    )
    other_manifest, _other_evidence = _model_discovery_run(
        tmp_path,
        canonical_model="alpha/atlas-secure-20260728",
    )
    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="different run provenance"):
            client.register_certification_model_discovery(
                evidence=evidence,
                manifest=other_manifest,
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_owned_alternate_endpoint_is_rejected_before_transport(config_factory) -> None:
    with pytest.raises(OpenRouterPrivacyError, match="canonical OpenRouter"):
        _owned_client(
            config_factory(),
            base_url="https://operator-proxy.invalid/api/v1",
        )


@pytest.mark.asyncio
async def test_structured_request_and_usage(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response('{"answer":"ok"}')

    config = config_factory()
    client, http_client, usage = _client(config, handler)
    assert client.execution_evidence is ExecutionEvidenceKind.MOCK
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "ok"
    body = json.loads(observed[0].content)
    assert "synthetic-key" not in json.dumps(body)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["provider"] == {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
    }
    assert observed[0].headers["Authorization"] == "Bearer synthetic-key"
    assert observed[0].headers["X-OpenRouter-Metadata"] == "enabled"
    assert observed[0].headers["X-OpenRouter-Title"] == "mmaudit"
    assert body["metadata"]["mmaudit_role"] == "source_audit"
    assert len(body["metadata"]["mmaudit_prompt_sha256"]) == 64
    assert body["metadata"]["mmaudit_user_prompt_sha256"] == hashlib.sha256(b"user").hexdigest()
    assert len(body["metadata"]["mmaudit_schema_sha256"]) == 64
    assert usage.records[0].reported_cost_usd == 0.01
    assert usage.records[0].returned_model == "alpha/atlas-secure"
    assert usage.records[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert usage.records[0].openrouter_generation_id == "generation-test"
    assert usage.records[0].actual_provider_endpoint == "synthetic-provider"
    assert usage.records[0].finish_reason == "stop"
    assert usage.records[0].validation_status.value == "valid"
    assert usage.records[0].schema_sha256 == body["metadata"]["mmaudit_schema_sha256"]
    assert usage.records[0].user_prompt_sha256 == hashlib.sha256(b"user").hexdigest()
    assert (
        usage.records[0].validated_response_sha256 == hashlib.sha256(b'{"answer":"ok"}').hexdigest()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("supported_parameters", "structured_output_required", "expected_mode", "expected_format"),
    [
        (
            [
                "json_schema",
                "max_tokens",
                "response_format",
                "structured_outputs",
                "temperature",
            ],
            True,
            "NATIVE_JSON_SCHEMA",
            "json_schema",
        ),
        (
            ["max_tokens", "response_format", "temperature"],
            True,
            "JSON_OBJECT",
            "json_object",
        ),
        (
            ["max_tokens", "temperature"],
            False,
            "VALIDATED_TEXT_JSON",
            None,
        ),
    ],
)
async def test_exact_endpoint_capability_selects_request_output_mode(
    config_factory,
    supported_parameters: list[str],
    structured_output_required: bool,
    expected_mode: str,
    expected_format: str | None,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"ok"}',
            provider="approved-provider",
        )

    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=policy,
    )
    snapshot = _endpoint_snapshot(
        supported_parameters=supported_parameters,
        structured_output_required=structured_output_required,
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert len(observed) == 1
    body = observed[0]
    if expected_format is None:
        assert "response_format" not in body
        assert "require_parameters" not in body["provider"]
        assert "MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL" in body["messages"][0]["content"]
    else:
        assert body["response_format"]["type"] == expected_format
        assert body["provider"]["require_parameters"] is True
    if expected_mode == "NATIVE_JSON_SCHEMA":
        assert "MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL" not in body["messages"][0]["content"]
    else:
        assert len(body["metadata"]["mmaudit_output_protocol_sha256"]) == 64
    assert (
        body["metadata"]["mmaudit_prompt_sha256"]
        == hashlib.sha256(
            json.dumps(
                body["messages"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        ).hexdigest()
    )
    record = usage.records[0]
    assert record.routing["structured_output_mode"] == expected_mode
    assert (
        record.routing["structured_output_capability_sha256"] == snapshot.output_capability_sha256
    )
    assert record.routing["structured_output_request_body_sha256"] == (record.request_body_sha256)
    assert record.routing["structured_output_original_response_sha256"] == (record.response_sha256)
    assert record.routing["structured_output_validated_response_sha256"] == (
        record.validated_response_sha256
    )
    assert is_creditable_usage_record(record)


@pytest.mark.asyncio
async def test_model_endpoint_common_text_downgrade_executes_without_response_format(
    config_factory,
    tmp_path: Path,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="approved-provider",
        )

    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=("max_tokens", "temperature"),
    )
    assert evidence.endpoint_snapshot.structured_output_mode is StructuredOutputMode.JSON_OBJECT
    assert evidence.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert len(observed) == 1
    body = observed[0]
    assert "response_format" not in body
    assert "require_parameters" not in body["provider"]
    assert "MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL" in body["messages"][0]["content"]
    assert (
        usage.records[0].routing["structured_output_mode"]
        == StructuredOutputMode.VALIDATED_TEXT_JSON.value
    )
    assert is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_marker_only_discovery_executes_validated_text_without_provider_parameters(
    config_factory,
    tmp_path: Path,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="approved-provider",
        )

    parameters = ("max_tokens", "structured_outputs", "temperature")
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=parameters,
        endpoint_supported_parameters=parameters,
    )
    assert evidence.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    assert evidence.structured_output_supported is False
    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert len(observed) == 1
    assert "response_format" not in observed[0]
    assert "require_parameters" not in observed[0]["provider"]
    assert is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_capability_discovery_derives_exact_runtime_reasoning_profile(
    config_factory,
    tmp_path: Path,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="approved-provider",
        )

    parameters = ("max_tokens", "reasoning", "temperature")
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=parameters,
        endpoint_supported_parameters=parameters,
    )
    assert "reasoning" not in (evidence.endpoint_snapshot.endpoints[0].required_request_parameters)
    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        reasoning=OpenRouterReasoning(effort="none", exclude=True),
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    identity = client.registered_model_identity_snapshot("alpha/atlas-secure")
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert identity.endpoint_capabilities.required_parameters == (
        "max_tokens",
        "reasoning",
        "temperature",
    )
    assert identity.provider_policy.require_parameters is True
    assert len(observed) == 1
    assert observed[0]["reasoning"] == {"effort": "none", "exclude": True}
    assert observed[0]["provider"]["require_parameters"] is True
    assert is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_alias_only_reasoning_capability_rejects_runtime_reasoning_profile(
    config_factory,
    tmp_path: Path,
) -> None:
    parameters = ("max_tokens", "reasoning_effort", "temperature")
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=parameters,
        endpoint_supported_parameters=parameters,
    )
    assert evidence.reasoning_parameters == ("reasoning_effort",)
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"must not execute"}'),
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        reasoning=OpenRouterReasoning(effort="none", exclude=True),
    )
    try:
        with pytest.raises(
            OpenRouterProviderPolicyError,
            match="requested reasoning",
        ):
            client.register_model_discovery(evidence=evidence, manifest=manifest)
    finally:
        await http_client.aclose()

    assert usage.records == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("supported_parameters", "reasoning_requested", "expected_require_parameters"),
    [
        (
            [
                "json_schema",
                "max_tokens",
                "response_format",
                "structured_outputs",
                "temperature",
            ],
            False,
            True,
        ),
        (
            [
                "json_schema",
                "max_tokens",
                "reasoning",
                "response_format",
                "structured_outputs",
                "temperature",
            ],
            True,
            True,
        ),
        (
            ["max_tokens", "response_format", "temperature"],
            False,
            True,
        ),
        (
            ["max_tokens", "reasoning", "response_format", "temperature"],
            True,
            True,
        ),
        (
            ["max_tokens", "temperature"],
            False,
            False,
        ),
        (
            ["max_tokens", "reasoning", "temperature"],
            True,
            True,
        ),
    ],
)
async def test_require_parameters_binds_all_emitted_endpoint_dependent_parameters(
    config_factory,
    supported_parameters: list[str],
    reasoning_requested: bool,
    expected_require_parameters: bool,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"ok"}',
            provider="approved-provider",
        )

    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        reasoning=(
            OpenRouterReasoning(effort="none", exclude=True) if reasoning_requested else None
        ),
    )
    client.register_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            supported_parameters=supported_parameters,
            reasoning_requested=reasoning_requested,
            structured_output_required=False,
        )
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert len(observed) == 1
    body = observed[0]
    assert ("require_parameters" in body["provider"]) is expected_require_parameters
    if expected_require_parameters:
        assert body["provider"]["require_parameters"] is True
    assert ("reasoning" in body) is reasoning_requested
    structured = usage.records[0].routing["structured_output"]
    assert structured["provider_require_parameters"] is expected_require_parameters
    assert is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_reasoning_request_profile_drift_fails_before_transport(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"must not execute"}',
            provider="approved-provider",
        )

    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        reasoning=OpenRouterReasoning(effort="none", exclude=True),
    )
    client.register_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            supported_parameters=["max_tokens", "reasoning", "temperature"],
            reasoning_requested=False,
            structured_output_required=False,
        )
    )
    try:
        with pytest.raises(
            OpenRouterProviderPolicyError,
            match="request parameter profile",
        ):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.asyncio
async def test_one_syntax_envelope_repair_is_hash_bound_and_noncreditable(
    config_factory,
) -> None:
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 1}),
        lambda _request: _completion_response(
            '```json\n{"answer":"ok"}\n```',
        ),
    )
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert completion.value.answer == "ok"
    assert completion.usage_record is usage.records[0]
    assert completion.usage_record.status == "repaired_noncreditable"
    assert completion.usage_record.routing["repair_used"] is True
    repair = completion.usage_record.routing["repair_evidence"]
    assert repair["semantic_rewrite"] is False
    assert repair["repair_attempt"] == 1
    assert repair["original_response_sha256"] == completion.usage_record.response_sha256
    assert not is_creditable_usage_record(completion.usage_record)


@pytest.mark.asyncio
async def test_router_metadata_supplies_provider_when_success_envelope_omits_extension(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"ok"}')
        payload.pop("provider")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert usage.records[0].provider == "synthetic-provider"
    assert usage.records[0].actual_provider_endpoint == "synthetic-provider"


@pytest.mark.asyncio
async def test_body_generation_id_is_sufficient_when_optional_header_is_absent(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_completion('{"answer":"body-bound"}'),
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "body-bound"
    assert usage.records[0].openrouter_generation_id == "generation-test"


def test_safe_headers_redacts_every_authorization_header() -> None:
    assert safe_headers(
        {
            "Authorization": "Bearer synthetic-canary",
            "Proxy-Authorization": "Bearer proxy-canary",
            "X-API-Key": "synthetic-api-key",
            "Content-Type": "application/json",
        }
    ) == {
        "Authorization": "[REDACTED]",
        "Proxy-Authorization": "[REDACTED]",
        "X-API-Key": "[REDACTED]",
        "Content-Type": "application/json",
    }


@pytest.mark.parametrize(
    ("status", "expected"),
    [(408, True), (429, True), (500, True), (503, True), (400, False), (401, False)],
)
def test_retry_decisions(status: int, expected: bool) -> None:
    assert is_retryable_status(status) is expected


def test_strict_schema_marks_every_property_required() -> None:
    schema = strict_json_schema(OptionalAnswer)
    assert schema["required"] == ["answer", "note"]
    assert "default" not in schema["properties"]["note"]
    assert schema["additionalProperties"] is False


@pytest.mark.asyncio
async def test_local_validation_rejects_omitted_defaulted_field(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _completion_response('{"answer":"ok"}')

    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=OptionalAnswer,
                schema_name="optional_answer",
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_rate_limit_retries_once(config_factory, monkeypatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
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
        return _completion_response('{"answer":"after retry"}')

    config = config_factory(execution={"max_model_retries": 1})
    client, http_client, usage = _client(config, handler)

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "after retry"
    assert calls == 2
    assert usage.records[0].attempts == 2
    assert usage.records[0].accounted_cost_usd > usage.records[0].reported_cost_usd
    assert usage.records[0].accounted_cost_usd == pytest.approx(client.budget.spent_usd)


@pytest.mark.asyncio
async def test_retry_success_emits_complete_ordered_atomic_inventory(
    config_factory,
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
        return _completion_response(
            '{"answer":"after bounded retry"}',
            provider="approved-provider",
        )

    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(evidence=_endpoint_snapshot())

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "after bounded retry"
    assert calls == 2
    record = usage.records[0]
    inventory = record.routing["atomic_token_reservations"]
    inventory_hashes = record.routing["atomic_token_reservation_sha256s"]
    assert record.attempts == 2
    assert [item["request_id"] for item in inventory] == [
        record.request_id,
        f"{record.request_id}:attempt:2",
    ]
    assert inventory_hashes == [item["evidence_sha256"] for item in inventory]
    assert len(set(inventory_hashes)) == 2
    assert record.routing["atomic_token_reservation"] == inventory[-1]
    assert record.routing["atomic_token_reservation_sha256"] == inventory_hashes[-1]
    assert is_creditable_usage_record(record)

    manifest = build_context_manifest(run_id="retry-success", usage_records=[record])
    request = manifest.requests[0]
    assert isinstance(request, ContextRequestEvidence)
    assert request.provider_attempts == 2
    assert request.atomic_token_reservations == tuple(
        type(request.atomic_token_reservation).model_validate(item) for item in inventory
    )
    assert manifest.totals.provider_attempt_count == 2
    assert manifest.totals.atomic_reservation_count == 2


@pytest.mark.asyncio
async def test_retry_reservation_rejection_records_one_attempt_and_plan_bound_preflight(
    config_factory,
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
                "error": {"code": 429, "message": "retry before budget rejection"},
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "cost": 0,
                },
            },
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
    )
    original_reserve = client.budget.reserve
    reserve_calls = 0

    async def reject_second_reservation(*args: Any, **kwargs: Any) -> Any:
        nonlocal reserve_calls
        reserve_calls += 1
        if reserve_calls == 2:
            raise BudgetExhaustedError("synthetic retry reservation rejection")
        return await original_reserve(*args, **kwargs)

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client.budget, "reserve", reject_second_reservation)
    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        with pytest.raises(BudgetExhaustedError, match="retry reservation rejection"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert reserve_calls == 2
    assert len(usage.records) == 1
    failed = usage.records[0]
    assert failed.attempts == 1
    assert failed.retry_count == 0
    assert len(failed.routing["atomic_token_reservations"]) == 1
    assert failed.routing["atomic_token_reservations"][0]["request_id"] == failed.request_id

    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.BUDGET_MANAGER
    assert preflight.reason is ContextPreflightReason.COST_BUDGET
    assert preflight.logical_request_id == failed.request_id
    assert preflight.request_id == f"{failed.request_id}:attempt:2:preflight"
    assert preflight.request_plan is not None
    assert preflight.request_plan_sha256 == failed.routing["request_token_plan_sha256"]

    manifest = build_context_manifest(
        run_id="retry-preflight",
        usage_records=[failed],
        preflight_records=client.context_preflight.records,
    )
    assert manifest.totals.provider_attempt_count == 1
    assert manifest.totals.atomic_reservation_count == 1
    assert manifest.totals.preflight_rejected_request_count == 1


@pytest.mark.asyncio
async def test_endpoint_capacity_planning_failure_is_planless_preflight(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    client, http_client, usage = _client(
        config_factory(execution={"max_output_tokens_per_request": 2_048}),
        handler,
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            context_length=8_192,
            max_prompt_tokens=7_168,
            max_completion_tokens=1_024,
        )
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="endpoint-bound token plan"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.TOKEN_PLANNER
    assert preflight.reason is ContextPreflightReason.ENDPOINT_CAPACITY
    assert preflight.request_plan is None
    assert preflight.request_plan_sha256 is None
    assert preflight.planning_snapshot is not None
    assert preflight.planning_snapshot_sha256 in preflight.decision_evidence_sha256s
    assert preflight.estimated_prompt_tokens == (
        preflight.planning_snapshot.estimated_prompt_tokens
    )
    assert preflight.planning_snapshot.route_state.value == "MEASURED"
    assert preflight.planning_snapshot.prompt_state.value == "MEASURED"
    assert preflight.planning_snapshot.output_state.value == "MEASURED"
    assert not preflight.planning_snapshot.provider_request_sent
    assert not preflight.planning_snapshot.atomic_reservation_created
    assert not preflight.planning_snapshot.review_credit
    assert client.budget.spent_input_tokens == 0
    assert client.budget.reserved_input_tokens == 0
    assert client.budget.spent_output_tokens == 0
    assert client.budget.reserved_output_tokens == 0
    manifest = build_context_manifest(
        run_id="capacity-preflight",
        usage_records=[],
        preflight_records=client.context_preflight.records,
    )
    assert manifest.requests == client.context_preflight.records


@pytest.mark.asyncio
async def test_context_preview_reserves_provider_visible_workflow_bytes(
    config_factory,
) -> None:
    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    config = config_factory()
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(evidence=_endpoint_snapshot())
    configured_workflow_reserve = config.token_budgets.reserved_workflow_tokens
    workflow_prompt = '"\\\n\té🙂' * 3_300
    raw_workflow_bound = len(workflow_prompt.encode("utf-8"))
    provider_visible_workflow_bound = len(
        json.dumps(
            workflow_prompt,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    assert raw_workflow_bound > configured_workflow_reserve
    assert provider_visible_workflow_bound > raw_workflow_bound
    try:
        raw_only_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_byte_upper_bound_tokens=raw_workflow_bound,
        )
        provider_visible_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_byte_upper_bound_tokens=raw_workflow_bound,
            workflow_prompt=workflow_prompt,
        )
    finally:
        await http_client.aclose()

    assert raw_only_budget - provider_visible_budget == (
        provider_visible_workflow_bound - raw_workflow_bound
    )


@pytest.mark.asyncio
async def test_context_preview_deducts_exact_context_json_escape_overhead(
    config_factory,
) -> None:
    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    config = config_factory()
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(evidence=_endpoint_snapshot())
    workflow_prompt = "review the prepared synthetic surface"
    raw_workflow_bound = len(workflow_prompt.encode("utf-8"))
    context_json_escape_overhead_tokens = 4_321
    try:
        baseline_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_byte_upper_bound_tokens=raw_workflow_bound,
            workflow_prompt=workflow_prompt,
        )
        escaped_context_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_byte_upper_bound_tokens=raw_workflow_bound,
            workflow_prompt=workflow_prompt,
            context_json_escape_overhead_tokens=context_json_escape_overhead_tokens,
        )
    finally:
        await http_client.aclose()

    assert baseline_budget - escaped_context_budget == context_json_escape_overhead_tokens


@pytest.mark.asyncio
async def test_context_preview_validates_exact_workflow_and_escape_inputs(
    config_factory,
) -> None:
    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(evidence=_endpoint_snapshot())
    workflow_prompt = '"synthetic"\n🙂'
    raw_workflow_bound = len(workflow_prompt.encode("utf-8"))
    try:
        derived_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_prompt=workflow_prompt,
        )
        validated_budget = client.context_package_byte_budget(
            ["alpha/atlas-secure"],
            workflow_byte_upper_bound_tokens=raw_workflow_bound,
            workflow_prompt=workflow_prompt,
        )
        assert derived_budget == validated_budget

        with pytest.raises(OpenRouterRequestLimitError, match="raw workflow bound"):
            client.context_package_byte_budget(
                ["alpha/atlas-secure"],
                workflow_byte_upper_bound_tokens=raw_workflow_bound + 1,
                workflow_prompt=workflow_prompt,
            )
        with pytest.raises(OpenRouterRequestLimitError, match="workflow prompt"):
            client.context_package_byte_budget(
                ["alpha/atlas-secure"],
                workflow_prompt=object(),  # type: ignore[arg-type]
            )
        for invalid_overhead in (True, -1, 1.5):
            with pytest.raises(OpenRouterRequestLimitError, match="escape overhead"):
                client.context_package_byte_budget(
                    ["alpha/atlas-secure"],
                    context_json_escape_overhead_tokens=invalid_overhead,  # type: ignore[arg-type]
                )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_prompt_envelope_overrun_is_planless_endpoint_preflight(
    config_factory,
) -> None:
    calls = 0
    system_prompt = "system"
    user_prompt = "synthetic local input"
    structured_plan = openrouter_module._structured_output_request_plan(
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_model=Answer,
        schema_name="answer",
    )
    allocations = openrouter_module._prompt_token_allocations(
        plan=structured_plan,
        original_system_prompt=system_prompt,
        response_model=Answer,
        schema_name="answer",
        context_package=None,
    )
    estimated_prompt_tokens = sum(
        allocation.estimate.estimated_tokens for allocation in allocations
    )
    content_byte_upper_bound = sum(
        allocation.estimate.byte_upper_bound_tokens for allocation in allocations
    )
    envelope_upper_bound = openrouter_module._prompt_envelope_byte_upper_bound_tokens(
        structured_plan
    )
    usable_prompt_tokens = int(Decimal(envelope_upper_bound) * Decimal("0.70"))
    assert estimated_prompt_tokens < usable_prompt_tokens
    assert content_byte_upper_bound < usable_prompt_tokens
    assert envelope_upper_bound > usable_prompt_tokens

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    policy = OpenRouterProviderPolicy(only=("approved-provider",))
    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=policy,
    )
    client.register_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            context_length=envelope_upper_bound + 2_048,
            max_prompt_tokens=envelope_upper_bound,
            max_completion_tokens=2_048,
        )
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.TOKEN_PLANNER
    assert preflight.reason is ContextPreflightReason.ENDPOINT_CAPACITY
    assert preflight.request_plan is None
    assert preflight.request_plan_sha256 is None
    assert preflight.planning_snapshot is not None
    assert preflight.planning_snapshot.allocations is not None
    assert preflight.estimated_prompt_tokens == sum(
        allocation.estimate.estimated_tokens
        for allocation in preflight.planning_snapshot.allocations
    )
    assert preflight.planning_snapshot.prompt_envelope_byte_upper_bound_tokens is not None
    assert preflight.planning_snapshot.prompt_content_byte_upper_bound_tokens is not None
    assert (
        preflight.planning_snapshot.prompt_envelope_byte_upper_bound_tokens
        >= preflight.planning_snapshot.prompt_content_byte_upper_bound_tokens
    )
    assert not preflight.planning_snapshot.provider_request_sent


@pytest.mark.asyncio
async def test_plan_time_global_input_budget_failure_is_typed_planless_preflight(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    client, http_client, usage = _client(
        config_factory(
            token_budgets={
                "global_input_token_budget": 1_024,
                "global_output_token_budget": 10_000,
            }
        ),
        handler,
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="x" * 2_000,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.TOKEN_PLANNER
    assert preflight.reason is ContextPreflightReason.GLOBAL_TOKEN_BUDGET
    assert preflight.request_plan is None
    assert preflight.request_plan_sha256 is None
    assert preflight.planning_snapshot is not None
    assert preflight.estimated_prompt_tokens == (
        preflight.planning_snapshot.estimated_prompt_tokens
    )
    assert preflight.planning_snapshot.route_intersection is not None
    assert preflight.planning_snapshot.allocations is not None
    assert preflight.planning_snapshot.output_allocations is not None
    assert client.budget.spent_input_tokens == 0
    assert client.budget.reserved_input_tokens == 0
    assert client.budget.spent_output_tokens == 0
    assert client.budget.reserved_output_tokens == 0


@pytest.mark.asyncio
async def test_context_package_omitted_from_prompt_is_typed_planless_preflight(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    package = ContextPackage(
        role="source_audit",
        byte_budget=10_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=0,
        repository_map=RepositoryMap(
            root_name="synthetic-context-preflight",
            languages={"Solidity": 1},
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
            omitted_files=[],
        ),
        scanner_findings=[],
        excerpts=[],
    )
    package = package.model_copy(
        update={"bytes_used": len(render_context(package).encode("utf-8"))}
    )
    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="The valid context package is deliberately omitted.",
                context_package=package,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.TOKEN_PLANNER
    assert preflight.reason is ContextPreflightReason.CONTEXT_PLAN_INVALID
    assert preflight.request_plan is None
    assert preflight.request_plan_sha256 is None
    assert preflight.estimated_prompt_tokens is None
    assert preflight.planning_snapshot is not None
    assert preflight.planning_snapshot.route_intersection is not None
    assert preflight.planning_snapshot.allocations is None
    assert preflight.planning_snapshot.output_allocations is not None
    assert preflight.planning_snapshot.prompt_envelope_byte_upper_bound_tokens is not None


@pytest.mark.asyncio
async def test_context_package_source_configuration_mismatch_fails_before_transport(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    package = ContextPackage(
        role="source_audit",
        byte_budget=10_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=199_999,
        effective_source_byte_ceiling=0,
        repository_map=RepositoryMap(
            root_name="synthetic-context-mismatch",
            languages={"Solidity": 1},
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
            omitted_files=[],
        ),
        scanner_findings=[],
        excerpts=[],
    )
    package = package.model_copy(
        update={"bytes_used": len(render_context(package).encode("utf-8"))}
    )
    rendered = render_context(package)
    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=rendered,
                context_package=package,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert client.context_preflight.records[-1].reason is (
        ContextPreflightReason.CONTEXT_PLAN_INVALID
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("request_role", "context_role"),
    [
        ("specialist:access_control:arbitrary", "specialist:access_control"),
        ("specialist:access_control", "specialist:reentrancy"),
        ("whole_protocol_review:", "whole_protocol_review"),
        ("whole_protocol_review:00", "whole_protocol_review"),
        ("whole_protocol_review:10000", "whole_protocol_review"),
        ("whole_protocol_review:not-an-index", "whole_protocol_review"),
    ],
)
async def test_request_role_must_have_an_exact_typed_context_relationship(
    config_factory,
    request_role: str,
    context_role: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    package = _empty_context_package(role=context_role)
    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role=request_role,
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=render_context(package),
                context_package=package,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert client.context_preflight.records[-1].reason is (
        ContextPreflightReason.CONTEXT_PLAN_INVALID
    )


@pytest.mark.asyncio
async def test_indexed_whole_protocol_request_has_a_typed_context_relationship(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"reviewed"}')

    package = _empty_context_package(role="whole_protocol_review")
    client, http_client, usage = _client(config_factory(), handler)
    try:
        response = await client.complete(
            role="whole_protocol_review:0",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt=render_context(package),
            context_package=package,
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert response.answer == "reviewed"
    assert calls == 1
    context_evidence = usage.records[0].routing["context_request_evidence"]
    assert context_evidence["request_role"] == "whole_protocol_review:0"
    assert context_evidence["context_role"] == "whole_protocol_review"
    assert context_evidence["relationship"] == "whole_protocol_indexed"


@pytest.mark.asyncio
async def test_stale_context_package_bytes_fail_before_transport(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    package = _empty_context_package()
    stale = package.model_copy(update={"bytes_used": package.bytes_used - 1})
    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=render_context(stale),
                context_package=stale,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert client.context_preflight.records[-1].reason is (
        ContextPreflightReason.CONTEXT_PLAN_INVALID
    )


@pytest.mark.asyncio
async def test_initial_global_token_rejection_is_plan_bound_preflight(
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    config = config_factory(
        token_budgets={
            "global_input_token_budget": 10_000,
            "global_output_token_budget": 10_000,
        }
    )
    client, http_client, usage = _client(config, handler)

    async def reject_after_concurrent_input_reservation(*_args: Any, **_kwargs: Any) -> Any:
        client.budget._spent_input_tokens = config.token_budgets.global_input_token_budget
        raise BudgetExhaustedError("synthetic global input token race")

    monkeypatch.setattr(
        client.budget,
        "reserve",
        reject_after_concurrent_input_reservation,
    )
    try:
        with pytest.raises(BudgetExhaustedError, match="global input token race"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert len(client.context_preflight.records) == 1
    preflight = client.context_preflight.records[0]
    assert preflight.request_state is ContextRequestState.PRE_FLIGHT_REJECTED
    assert preflight.decision_source is ContextPreflightSource.BUDGET_MANAGER
    assert preflight.reason is ContextPreflightReason.GLOBAL_TOKEN_BUDGET
    assert preflight.request_plan is not None
    assert preflight.request_plan_sha256 == preflight.request_plan.plan_sha256
    assert preflight.estimated_prompt_tokens == preflight.request_plan.estimated_prompt_tokens
    manifest = build_context_manifest(
        run_id="global-token-preflight",
        usage_records=[],
        preflight_records=client.context_preflight.records,
    )
    assert manifest.totals.planned_request_count == 1
    assert manifest.totals.preflight_rejected_request_count == 1


@pytest.mark.asyncio
async def test_concurrent_usage_records_account_only_their_own_request_cost(
    config_factory,
) -> None:
    arrived = 0
    both_arrived = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal arrived
        arrived += 1
        if arrived == 2:
            both_arrived.set()
        await both_arrived.wait()
        return _completion_response('{"answer":"concurrent"}', cost=0.01)

    config = config_factory()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    usage = UsageLedger()
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
    )
    try:
        await asyncio.gather(
            client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="first",
                response_model=Answer,
                schema_name="answer",
            ),
            client.complete(
                role="business_logic",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="second",
                response_model=Answer,
                schema_name="answer",
            ),
        )
    finally:
        await http_client.aclose()

    assert arrived == 2
    assert [record.accounted_cost_usd for record in usage.records] == [0.01, 0.01]
    assert usage.accounted_cost_usd == pytest.approx(0.02)
    assert budget.spent_usd == pytest.approx(0.02)


@pytest.mark.asyncio
async def test_complete_with_evidence_binds_exact_concurrent_same_role_record(
    config_factory,
) -> None:
    both_arrived = asyncio.Event()
    arrived = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal arrived
        body = json.loads(request.content)
        user_prompt = body["messages"][1]["content"]
        arrived += 1
        if arrived == 2:
            both_arrived.set()
        await both_arrived.wait()
        generation_id = f"generation-{user_prompt}"
        payload = _completion(
            json.dumps({"answer": user_prompt}),
            cost=0.01,
        )
        payload["id"] = generation_id
        return httpx.Response(
            200,
            headers={"X-Generation-Id": generation_id},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        first, second = await asyncio.gather(
            client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="first",
                response_model=Answer,
                schema_name="answer",
            ),
            client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="second",
                response_model=Answer,
                schema_name="answer",
            ),
        )
    finally:
        await http_client.aclose()

    records_by_generation = {record.openrouter_generation_id: record for record in usage.records}
    assert isinstance(first, StructuredCompletion)
    assert first.value.answer == "first"
    assert first.usage_record is records_by_generation["generation-first"]
    assert second.value.answer == "second"
    assert second.usage_record is records_by_generation["generation-second"]
    assert first.usage_record.request_id != second.usage_record.request_id


@pytest.mark.asyncio
async def test_authentication_failure_is_not_retried(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"error": {"message": "no"}})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterAuthenticationError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1


@pytest.mark.asyncio
async def test_malformed_structured_output_is_not_repaired(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("not json")

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "failed:OpenRouterStructuredOutputError"
    assert usage.records[0].validation_status.value == "invalid_response"


@pytest.mark.asyncio
async def test_duplicate_json_keys_are_rejected_without_review_credit(config_factory) -> None:
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"first","answer":"second"}'),
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 1
    assert usage.records[0].status != "success"
    assert not is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_nonfinite_json_number_is_rejected_without_review_credit(config_factory) -> None:
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"value":NaN}'),
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=NumericAnswer,
                schema_name="numeric_answer",
            )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 1
    assert usage.records[0].status != "success"
    assert not is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("supported_parameters", "structured_output_required"),
    [
        (
            [
                "json_schema",
                "max_tokens",
                "response_format",
                "structured_outputs",
                "temperature",
            ],
            True,
        ),
        (["max_tokens", "response_format", "temperature"], True),
        (["max_tokens", "temperature"], False),
    ],
)
async def test_unexpected_fields_are_rejected_without_review_credit_for_every_output_mode(
    config_factory,
    supported_parameters: list[str],
    structured_output_required: bool,
) -> None:
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response(
            '{"answer":"plausible","unexpected":"must not be discarded"}',
            provider="approved-provider",
        ),
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
    )
    client.register_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            supported_parameters=supported_parameters,
            structured_output_required=structured_output_required,
        )
    )
    try:
        with pytest.raises(OpenRouterStructuredOutputError) as raised:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=LooseAnswer,
                schema_name="loose_answer",
            )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 1
    assert raised.value.failure_code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
    assert usage.records[0].status != "success"
    assert not is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_invalid_repair_is_not_repeated(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("still not json")

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1


@pytest.mark.asyncio
async def test_hard_budget_refuses_before_network(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    config = config_factory(
        execution={
            "budget_usd": 0.000001,
            "conservative_usd_per_million_tokens": 1_000,
        }
    )
    client, http_client, _usage = _client(config, handler)
    try:
        with pytest.raises(BudgetExhaustedError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="large enough",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_serialized_request_limit_refuses_before_network_or_fallback(
    config_factory,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    client, http_client, _usage = _client(
        config_factory(execution={"max_request_bytes": 1_024}),
        handler,
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure", "bravo/borealis-secure"],
                system_prompt="system",
                user_prompt="x" * 2_000,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_models_metadata_shape(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(
            200,
            json={
                "data": [{"id": "alpha/atlas-secure", "supported_parameters": ["response_format"]}]
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        models = await client.list_models()
    finally:
        await http_client.aclose()
    assert models[0]["id"] == "alpha/atlas-secure"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        b'{"data":[],"data":[]}',
        b'{"data":[{"id":"alpha/atlas-secure","score":NaN}]}',
        b'{"data":[{"id":"alpha/atlas-secure","score":1e999}]}',
    ],
)
async def test_metadata_json_rejects_duplicate_keys_and_nonfinite_values(
    config_factory,
    content: bytes,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: httpx.Response(200, content=content),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="valid object"):
            await client.list_models()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_certification_catalog_does_not_filter_privacy_or_output_mode(
    config_factory,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "alpha/atlas-secure"},
                    {"id": "~alpha/atlas-latest"},
                ]
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        assert await client.list_certification_models() == [
            {"id": "alpha/atlas-secure"},
            {"id": "~alpha/atlas-latest"},
        ]
    finally:
        await http_client.aclose()

    assert observed[0].url.path == "/api/v1/models"
    assert dict(observed[0].url.params) == {}


@pytest.mark.asyncio
async def test_refresh_zdr_metadata_preserves_authenticated_empty_catalogue(
    config_factory,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={"data": []})

    client, http_client, usage = _client(config_factory(), handler)
    try:
        assert await client.get_zdr_endpoint_metadata() == {"data": []}
        with pytest.raises(OpenRouterPrivacyError, match="invalid ZDR"):
            await client.list_zdr_endpoints()
    finally:
        await http_client.aclose()

    assert [request.url.path for request in observed] == [
        "/api/v1/endpoints/zdr",
        "/api/v1/endpoints/zdr",
    ]
    assert usage.records == []


@pytest.mark.asyncio
async def test_refresh_exact_endpoint_metadata_preserves_withdrawn_empty_set(
    config_factory,
) -> None:
    model_id = "alpha/atlas-secure"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"id": model_id, "endpoints": []}})

    client, http_client, usage = _client(config_factory(), handler)
    try:
        response = await client.get_refresh_model_endpoint_metadata(model_id)
        assert response["data"]["endpoints"] == []
        with pytest.raises(OpenRouterModelError, match="invalid endpoint"):
            await client.get_model_endpoint_metadata(model_id)
    finally:
        await http_client.aclose()
    assert usage.records == []


@pytest.mark.asyncio
async def test_authentication_validation_uses_key_endpoint(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={"data": {"label": "synthetic"}})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        await client.validate_authentication()
    finally:
        await http_client.aclose()

    assert observed[0].url.path == "/api/v1/key"


@pytest.mark.asyncio
async def test_decoded_metadata_does_not_retain_compression_headers(config_factory) -> None:
    encoded = gzip.compress(b'{"data":{"label":"synthetic"}}')

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=encoded,
            headers={"Content-Encoding": "gzip"},
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        await client.validate_authentication()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_authentication_validation_rejects_invalid_key(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid"})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterAuthenticationError):
            await client.validate_authentication()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_clear_credentials_does_not_mutate_caller_owned_authorization(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        base_url="https://fake.test",
        headers={"Authorization": "Bearer caller-owned"},
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=1_000,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
    )
    client = OpenRouterClient(
        api_key="synthetic-mmaudit-key",
        execution=config_factory().execution,
        privacy=config_factory().privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
    )

    client.clear_credentials()

    assert http_client.headers["Authorization"] == "Bearer caller-owned"
    assert client._headers == {}
    assert client._credential == bytearray()
    await http_client.aclose()


@pytest.mark.asyncio
async def test_request_response_and_timeout_diagnostics_do_not_retain_key(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-timeout-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 0}),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterTransientError) as captured:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    rendered = "".join(traceback.format_exception(captured.value))
    chained = captured.value.__context__
    assert canary not in rendered
    assert canary not in repr(chained)
    serialized_usage = json.dumps(
        [record.model_dump(mode="json") for record in usage.records],
        sort_keys=True,
        default=str,
    )
    assert canary not in serialized_usage


@pytest.mark.asyncio
async def test_key_in_prompt_or_response_is_rejected_without_debug_artifacts(
    config_factory,
    tmp_path: Path,
) -> None:
    canary = "sk-or-v1-synthetic-payload-canary"
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={
                "Authorization": canary,
                "X-Generation-Id": "generation-test",
            },
            json=_completion(json.dumps({"answer": canary})),
        )

    config = config_factory(
        execution={"max_model_retries": 0},
        privacy={"store_raw_responses": True},
    )
    client, http_client, _usage = _client(
        config,
        handler,
        api_key=canary,
        run_dir=tmp_path,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=f"accidental value: {canary}",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert not (tmp_path / "debug").exists()


@pytest.mark.asyncio
async def test_key_in_provider_mapping_key_is_rejected_before_debug_storage(
    config_factory,
    tmp_path: Path,
) -> None:
    canary = "sk-or-v1-synthetic-mapping-key-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"safe"}')
        payload[canary] = "provider-controlled-key"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    config = config_factory(
        execution={"max_model_retries": 0},
        privacy={"store_raw_responses": True},
    )
    client, http_client, _usage = _client(
        config,
        handler,
        api_key=canary,
        run_dir=tmp_path,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert not (tmp_path / "debug").exists()


@pytest.mark.asyncio
async def test_malformed_echoed_response_has_secretless_exception(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-malformed-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {canary}"
        return httpx.Response(
            200,
            content=f"not-json:{canary}".encode(),
            headers={"Authorization": canary},
        )

    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterSchemaError) as captured:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    rendered = "".join(traceback.format_exception(captured.value))
    assert canary not in rendered
    assert canary not in repr(captured.value.__context__)


@pytest.mark.asyncio
async def test_models_metadata_respects_rate_limit_retry(config_factory, monkeypatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"data": [{"id": "alpha/atlas-secure"}]})

    client, http_client, _usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
    )

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        assert await client.list_models() == [{"id": "alpha/atlas-secure"}]
    finally:
        await http_client.aclose()
    assert calls == 2


@pytest.mark.asyncio
async def test_unrelated_returned_model_is_rejected_and_recorded(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"wrong model"}',
            model="unrelated/vendor-model",
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError, match="identity is unbound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status == "unbound_identity"
    assert usage.records[0].returned_model == "unrelated/vendor-model"


@pytest.mark.asyncio
async def test_only_explicit_fallback_is_used(config_factory) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requested.append(body["model"])
        if body["model"] == "alpha/atlas-secure":
            return httpx.Response(404)
        return _completion_response('{"answer":"fallback"}', model=body["model"])

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "fallback"
    assert requested == ["alpha/atlas-secure", "bravo/borealis-secure"]


@pytest.mark.asyncio
async def test_complete_with_evidence_returns_successful_explicit_fallback_record(
    config_factory,
) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        model = body["model"]
        requested.append(model)
        if model == "alpha/atlas-secure":
            return httpx.Response(404)
        return _completion_response('{"answer":"fallback"}', model=model)

    client, http_client, usage = _client(config_factory(), handler)
    try:
        result = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.value.answer == "fallback"
    assert requested == ["alpha/atlas-secure", "bravo/borealis-secure"]
    assert [record.status for record in usage.records] == [
        "failed:OpenRouterModelError",
        "success",
    ]
    assert result.usage_record is usage.records[1]
    assert result.usage_record.fallback_used is True
    assert result.usage_record.routing["host_model_fallback_used"] is True
    assert result.usage_record.routing["provider_fallback_used"] is False
    assert all(
        record.user_prompt_sha256 == hashlib.sha256(b"user").hexdigest() for record in usage.records
    )


@pytest.mark.asyncio
async def test_explicit_host_model_fallback_can_bind_its_own_frozen_identity(
    config_factory,
    tmp_path: Path,
) -> None:
    primary_manifest, primary_evidence = _model_discovery_run(tmp_path)
    fallback_manifest, fallback_evidence = _model_discovery_run(
        tmp_path,
        exact_model="bravo/borealis-secure",
        canonical_model="bravo/borealis-secure-20260727",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        model = json.loads(request.content)["model"]
        if model == "alpha/atlas-secure":
            return httpx.Response(404)
        payload = _completion(
            '{"answer":"identity-bound fallback"}',
            model="bravo/borealis-secure-20260727",
            provider="Approved Provider",
        )
        payload["openrouter_metadata"]["requested"] = model
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            allow_fallbacks=False,
        ),
    )
    client.register_model_discovery(
        evidence=primary_evidence,
        manifest=primary_manifest,
    )
    client.register_model_discovery(
        evidence=fallback_evidence,
        manifest=fallback_manifest,
    )
    try:
        completion = await client.complete_with_evidence(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    record = completion.usage_record
    generation = validate_openrouter_generation_payload(
        _generation_payload(
            model="bravo/borealis-secure-20260727",
        ),
        requested_generation_id="generation-test",
        retrieved_at=datetime.now(UTC),
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    binding = client.bind_generation_identity(
        usage_record=record,
        generation_evidence=generation,
    )
    credited = client.usage_with_bound_identity(
        usage_record=record,
        identity_binding=binding,
    )

    assert record.fallback_used is True
    assert record.routing["host_model_fallback_used"] is True
    assert record.routing["provider_fallback_used"] is False
    assert binding.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    assert usage.records[-1] == credited
    assert is_creditable_usage_record(credited)


@pytest.mark.asyncio
async def test_complete_with_evidence_preserves_non_fallback_exception_behavior(
    config_factory,
) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(json.loads(request.content)["model"])
        return httpx.Response(401, json={"error": {"message": "synthetic rejection"}})

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterAuthenticationError):
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure", "bravo/borealis-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert requested == ["alpha/atlas-secure"]
    assert len(usage.records) == 1
    assert usage.records[0].status == "failed:OpenRouterAuthenticationError"
    assert usage.records[0].user_prompt_sha256 == hashlib.sha256(b"user").hexdigest()


@pytest.mark.asyncio
async def test_complete_remains_value_only_compatibility_wrapper(config_factory) -> None:
    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"compatible"}'),
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert type(result) is Answer
    assert result.answer == "compatible"
    assert len(usage.records) == 1


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/random",
        "vendor/model-auto-router",
        "vendor/model:latest",
        "vendor/latest",
        "~vendor/family-latest",
        "missing-provider",
    ],
)
@pytest.mark.asyncio
async def test_non_exact_model_identifiers_are_rejected_before_network(
    config_factory,
    model: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact author/model"):
            await client.complete(
                role="source_audit",
                models=[model],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_certification_request_pins_provider_reasoning_and_single_model(
    config_factory,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        observed.append(body)
        return _completion_response(
            '{"answer":"ok"}',
            provider="approved-provider",
            reasoning_tokens=3,
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    policy = OpenRouterProviderPolicy(
        certification=True,
        only=("approved-provider",),
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning=OpenRouterReasoning(effort="high"),
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
        with pytest.raises(OpenRouterModelError, match="exactly one"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure", "bravo/borealis-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert result.answer == "ok"
    assert observed[0]["provider"] == {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
        "only": ["approved-provider"],
    }
    assert observed[0]["reasoning"] == {"exclude": False, "effort": "high"}
    assert usage.records[0].configured_provider_endpoints == ["approved-provider"]


def test_reasoning_payload_can_explicitly_disable_optional_reasoning() -> None:
    reasoning = OpenRouterReasoning(effort="none", exclude=True)

    assert reasoning.as_request_payload() == {
        "exclude": True,
        "effort": "none",
    }


def _per_role_reasoning_policy() -> ReasoningPolicyArtifact:
    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    controls = {role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    controls["source_audit"] = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        exclude=True,
        reserved_reasoning_tokens=3,
    )
    return ReasoningPolicyArtifact.build(controls_by_role=controls)


def _qualified_reasoning_routing(
    profile: ReasoningControlProfile,
    policy: ReasoningPolicyArtifact,
) -> OpenRouterQualifiedReasoningRoutingBinding:
    role_policy = policy.role_policy("source_audit")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "binding_status": "exact_evidence_bound",
        "selection_authority": False,
        "exact_model_id": "alpha/atlas-secure",
        "approved_provider_endpoint": "approved-provider",
        "approved_provider_name": "approved-provider",
        "qualified_role": "source_audit",
        "configured_policy_role": "source_audit",
        "control_profile": profile.model_dump(mode="json"),
        "control_profile_sha256": profile.profile_sha256,
        "reasoning_policy_artifact_sha256": policy.artifact_sha256,
        "reasoning_policy_role_binding_sha256": role_policy.binding_sha256,
        "endpoint_reasoning_capability_sha256": "a" * 64,
        "reasoning_benchmark_report_sha256": "b" * 64,
        "reasoning_benchmark_verification_sha256": "2" * 64,
        "reasoning_benchmark_fresh_evidence_sha256": "2" * 64,
        "qualification_report_sha256": "b" * 64,
        "qualification_result_sha256": "5" * 64,
        "qualification_verification_sha256": "2" * 64,
    }
    return OpenRouterQualifiedReasoningRoutingBinding(
        exact_model_id=payload["exact_model_id"],
        approved_provider_endpoint=payload["approved_provider_endpoint"],
        approved_provider_name=payload["approved_provider_name"],
        qualified_role=payload["qualified_role"],
        configured_policy_role=payload["configured_policy_role"],
        control_profile=profile,
        control_profile_sha256=profile.profile_sha256,
        reasoning_policy_artifact_sha256=policy.artifact_sha256,
        reasoning_policy_role_binding_sha256=role_policy.binding_sha256,
        endpoint_reasoning_capability_sha256="a" * 64,
        reasoning_benchmark_report_sha256="b" * 64,
        reasoning_benchmark_verification_sha256="2" * 64,
        reasoning_benchmark_fresh_evidence_sha256="2" * 64,
        qualification_report_sha256="b" * 64,
        qualification_result_sha256="5" * 64,
        qualification_verification_sha256="2" * 64,
        binding_sha256=canonical_sha256(payload),
    )


def test_reasoning_qualification_routing_requires_exact_role_profile_and_capability() -> None:
    policy = _per_role_reasoning_policy()
    profile = policy.control_for_request("source_audit")
    binding = _qualified_reasoning_routing(profile, policy)
    qualification = _qualification_routing(
        reasoning_policy=policy,
        reasoning_bindings=(binding,),
    )

    assert (
        qualification.reasoning_binding_sha256_for(
            role="source_audit",
            control_profile=profile,
            reasoning_policy=policy,
            endpoint_capability_sha256="a" * 64,
        )
        == binding.binding_sha256
    )
    with pytest.raises(OpenRouterQualificationError, match="exact production request"):
        qualification.reasoning_binding_sha256_for(
            role="source_audit",
            control_profile=profile,
            reasoning_policy=policy,
            endpoint_capability_sha256="c" * 64,
        )
    with pytest.raises(OpenRouterQualificationError, match="qualified reasoning profile"):
        qualification.reasoning_binding_sha256_for(
            role="judge",
            control_profile=profile,
            reasoning_policy=policy,
            endpoint_capability_sha256="a" * 64,
        )


def test_per_role_request_shape_requires_the_exact_sealed_reasoning_control(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    policy = _per_role_reasoning_policy()
    client, http_client, _usage = _client(
        config_factory(),
        handler,
        provider_policy=OpenRouterProviderPolicy(only=("approved-provider",)),
        reasoning_policy=policy,
    )
    snapshot = _endpoint_snapshot(
        supported_parameters=[
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ],
        reasoning_requested=False,
        structured_output_required=False,
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    endpoint_policy = client._endpoint_pricing["alpha/atlas-secure"]
    sealed_plan = ReasoningRequestPlanEvidence.build(
        request_role="source_audit",
        policy=policy,
        endpoint_capability_sha256="a" * 64,
        qualification_binding_sha256="b" * 64,
    )
    exact_request = openrouter_module._structured_output_request_plan(
        mode=snapshot.structured_output_mode,
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
        reasoning=OpenRouterReasoning(effort="high", exclude=True),
    )
    drifted_request = openrouter_module._structured_output_request_plan(
        mode=snapshot.structured_output_mode,
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
        reasoning=OpenRouterReasoning(effort="low", exclude=True),
    )
    try:
        openrouter_module._require_matching_request_parameter_profile(
            endpoint_policy,
            exact_request,
            sealed_reasoning_plan=sealed_plan,
        )
        with pytest.raises(
            OpenRouterProviderPolicyError,
            match="exact sealed role plan",
        ):
            openrouter_module._require_matching_request_parameter_profile(
                endpoint_policy,
                drifted_request,
                sealed_reasoning_plan=sealed_plan,
            )
    finally:
        asyncio.run(http_client.aclose())

    assert calls == 0


def test_public_qualification_routing_requires_exact_opaque_authority(config_factory) -> None:
    from mmaudit.orchestration.pipeline import _openrouter_qualification_routing

    config = config_factory(
        models={
            "specialists": {
                "access_control": {
                    "primary": "golf/glacier-secure",
                    "fallbacks": [],
                },
                "accounting_invariant": {
                    "primary": "hotel/harbor-secure",
                    "fallbacks": [],
                },
            }
        }
    )
    now = datetime.now(UTC).replace(microsecond=0)
    authority = synthetic_production_qualification(config, now)
    routing = _openrouter_qualification_routing(authority)

    assert (
        _require_exact_qualification_routing_authority(
            routing=routing,
            qualification=authority,
            now=now,
        )
        is authority
    )
    tampered = (
        replace(routing[0], endpoint_snapshot_sha256="f" * 64),
        *routing[1:],
    )
    with pytest.raises(OpenRouterQualificationError, match="opaque production authority"):
        _require_exact_qualification_routing_authority(
            routing=tampered,
            qualification=authority,
            now=now,
        )


@pytest.mark.asyncio
async def test_real_postqualification_rejects_public_projection_without_opaque_authority(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not be sent"}')

    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    reasoning_policy = ReasoningPolicyArtifact.build(
        controls_by_role={role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    )
    manifest, evidence = _model_discovery_run(tmp_path)
    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(_qualification_routing_for_discovery(evidence),),
        reasoning_policy=reasoning_policy,
    )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    try:
        with pytest.raises(OpenRouterQualificationError, match="opaque qualification authority"):
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0


@pytest.mark.parametrize(
    ("reasoning", "expected_error"),
    [
        (
            None,
            "requires a sealed per-role reasoning policy",
        ),
        (
            OpenRouterReasoning(effort="high"),
            "rejects legacy global reasoning",
        ),
    ],
)
@pytest.mark.asyncio
async def test_real_postqualification_rejects_absent_or_legacy_reasoning_before_transport(
    config_factory,
    reasoning: OpenRouterReasoning | None,
    expected_error: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not be sent"}')

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        reasoning=reasoning,
    )
    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    try:
        with pytest.raises(OpenRouterQualificationError, match=expected_error):
            await client.complete_with_evidence(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.asyncio
async def test_real_postqualification_single_request_cannot_bypass_opaque_or_plan_gate(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not be sent"}')

    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    reasoning_policy = ReasoningPolicyArtifact.build(
        controls_by_role={role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    )
    binding = _qualification_routing(reasoning_policy=reasoning_policy)
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        reasoning_policy=reasoning_policy,
        qualification_routing=(binding,),
    )
    client.execution_evidence = ExecutionEvidenceKind.REAL
    client._owns_client = True
    client._authentication_validated = True
    try:
        with pytest.raises(OpenRouterQualificationError, match="opaque qualification authority"):
            await client._complete_one(
                role="source_audit",
                model="alpha/atlas-secure",
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
                fallback_used=False,
                qualification_binding=binding,
                qualification_bound_reasoning_plan=None,
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.parametrize(
    ("role", "reasoning"),
    [
        ("model_benchmark", None),
        ("real_provider_smoke", OpenRouterReasoning(effort="high")),
    ],
)
def test_real_prequalification_roles_remain_outside_postqualification_reasoning_gate(
    config_factory,
    role: str,
    reasoning: OpenRouterReasoning | None,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"not executed"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        reasoning=reasoning,
    )
    client.execution_evidence = ExecutionEvidenceKind.REAL
    try:
        assert not client._is_real_postqualification_certification(role)
        assert client._reasoning_for_role(role) == reasoning
    finally:
        asyncio.run(http_client.aclose())


def test_real_postqualification_seals_exact_capability_and_qualification_reasoning_plan(
    config_factory,
) -> None:
    from mmaudit.models.runtime import build_reasoning_policy
    from mmaudit.orchestration.pipeline import _openrouter_qualification_routing

    config = config_factory(
        models={
            "reasoning": {
                "effort": "high",
                "reserved_tokens": 3,
                "exclude": True,
            },
            "specialists": {
                "access_control": {
                    "primary": "golf/glacier-secure",
                    "fallbacks": [],
                },
                "accounting_invariant": {
                    "primary": "hotel/harbor-secure",
                    "fallbacks": [],
                },
            },
        }
    )
    checked_at = datetime.now(UTC).replace(microsecond=0)
    authority = synthetic_production_qualification(config, checked_at)
    routing = _openrouter_qualification_routing(authority)
    policy = build_reasoning_policy(config)
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"not executed"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        reasoning_policy=policy,
        qualification_routing=routing,
        production_qualification=authority,
    )
    client.execution_evidence = ExecutionEvidenceKind.REAL
    target = authority.models[0]
    qualification_binding = client._qualification_routing[target.exact_model_id]
    role_binding = next(
        binding
        for binding in qualification_binding.reasoning_bindings
        if binding.qualified_role == "source_audit"
        and binding.configured_policy_role == "source_audit"
    )
    observed_profiles: list[ReasoningControlProfile] = []

    class SyntheticExactCapability:
        exact_model_id = target.exact_model_id
        capability_sha256 = role_binding.endpoint_reasoning_capability_sha256

        def require_compatible_profile(self, profile: ReasoningControlProfile) -> None:
            observed_profiles.append(profile)

    client._reasoning_capabilities[target.exact_model_id] = SyntheticExactCapability()  # type: ignore[assignment]
    try:
        plan = client._require_real_postqualification_reasoning_plan(
            role="source_audit",
            model=target.exact_model_id,
            qualification_binding=qualification_binding,
        )
    finally:
        asyncio.run(http_client.aclose())

    assert plan.binding_state == "qualification_bound"
    assert plan.endpoint_capability_sha256 == role_binding.endpoint_reasoning_capability_sha256
    assert plan.qualification_binding_sha256 == role_binding.binding_sha256
    assert plan.policy_artifact_sha256 == policy.artifact_sha256
    assert plan.policy_role_binding_sha256 == (policy.role_policy("source_audit").binding_sha256)
    assert observed_profiles == [policy.control_for_request("source_audit")]


@pytest.mark.asyncio
async def test_per_role_reasoning_policy_controls_reservation_request_and_usage(
    config_factory,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        observed.append(body)
        return _completion_response(
            '{"answer":"bounded"}',
            reasoning_tokens=(3 if body["metadata"]["mmaudit_role"] == "source_audit" else None),
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    policy = _per_role_reasoning_policy()
    client, http_client, usage = _client(
        config,
        handler,
        reasoning_policy=policy,
    )
    try:
        await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
        await client.complete(
            role="judge",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert observed[0]["reasoning"] == {"exclude": True, "effort": "high"}
    assert "reasoning" not in observed[1]
    assert (
        observed[0]["max_tokens"] - observed[1]["max_tokens"]
        == policy.control_for_request("source_audit").reserved_reasoning_tokens
    )
    assert observed[0]["metadata"]["mmaudit_reasoning_policy_sha256"] == policy.artifact_sha256
    source_evidence = usage.records[0].reasoning_evidence
    judge_evidence = usage.records[1].reasoning_evidence
    assert source_evidence is not None
    assert source_evidence.state == "active_observed"
    assert source_evidence.observed_reasoning_tokens == 3
    assert source_evidence.request_plan.control_profile.effort == "high"
    assert judge_evidence is not None
    assert judge_evidence.state == "disabled_unreported"
    assert judge_evidence.observed_reasoning_tokens is None
    assert source_evidence.request_plan.binding_state == "policy_only"

    missing_execution = usage.records[0].model_dump(mode="json")
    missing_execution["reasoning_evidence"] = None
    with pytest.raises(ValidationError, match="differs from its routed reasoning plan"):
        UsageRecord.model_validate(missing_execution)

    mismatched_execution = ReasoningExecutionEvidence.build(
        request_plan=source_evidence.request_plan,
        observed_reasoning_tokens=source_evidence.observed_reasoning_tokens,
        provider_completion_tokens=source_evidence.provider_completion_tokens,
        request_token_plan_sha256="f" * 64,
        request_body_sha256=source_evidence.request_body_sha256,
    )
    mismatched_payload = usage.records[0].model_dump(mode="json")
    mismatched_payload["reasoning_evidence"] = mismatched_execution.model_dump(mode="json")
    with pytest.raises(ValidationError, match="differs from provider usage"):
        UsageRecord.model_validate(mismatched_payload)


@pytest.mark.asyncio
async def test_per_role_reasoning_policy_rejects_unknown_role_before_transport(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        reasoning_policy=_per_role_reasoning_policy(),
    )
    try:
        with pytest.raises(ValueError, match="recognized exact form"):
            await client.complete(
                role="untrusted_dynamic_role",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


def test_global_and_per_role_reasoning_controls_are_mutually_exclusive(
    config_factory,
) -> None:
    config = config_factory()
    with pytest.raises(OpenRouterRequestLimitError, match="mutually exclusive"):
        OpenRouterClient(
            api_key="synthetic-key",
            execution=config.execution,
            privacy=config.privacy,
            budget=BudgetManager(
                total_usd=config.execution.budget_usd,
                max_output_tokens=config.execution.max_output_tokens_per_request,
                conservative_usd_per_million_tokens=(
                    config.execution.conservative_usd_per_million_tokens
                ),
                max_requests_per_agent=config.execution.max_requests_per_agent,
            ),
            usage=UsageLedger(),
            reasoning=OpenRouterReasoning(effort="high"),
            reasoning_policy=_per_role_reasoning_policy(),
        )


@pytest.mark.parametrize("fault", ["missing", "role", "model", "provider", "expired"])
@pytest.mark.asyncio
async def test_certification_qualification_binding_fails_before_transport(
    config_factory,
    fault: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    policy = OpenRouterProviderPolicy(
        certification=True,
        only=("approved-provider",),
    )
    binding = _qualification_routing(
        model=("bravo/borealis-secure" if fault == "model" else "alpha/atlas-secure"),
        provider=("other-provider" if fault == "provider" else "approved-provider"),
        roles=(("business_logic",) if fault == "role" else ("source_audit",)),
        verified_at=(datetime.now(UTC) - timedelta(days=2) if fault == "expired" else None),
        expires_at=(datetime.now(UTC) - timedelta(days=1) if fault == "expired" else None),
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=policy,
        qualification_routing=(() if fault == "missing" else (binding,)),
    )
    try:
        with pytest.raises(OpenRouterQualificationError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.asyncio
async def test_certification_rejects_qualified_endpoint_snapshot_drift_before_transport(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    snapshot = _endpoint_snapshot(provider_name="approved-provider")
    endpoint = snapshot.endpoint("approved-provider")
    assert endpoint is not None
    binding = _qualification_routing(
        endpoint_snapshot_sha256="f" * 64,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    try:
        with pytest.raises(OpenRouterQualificationError, match="endpoint or pricing snapshot"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.parametrize("fault", ["output_capability", "output_mode"])
@pytest.mark.asyncio
async def test_certification_rejects_qualified_output_capability_drift_before_transport(
    config_factory,
    fault: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    snapshot = _endpoint_snapshot(provider_name="approved-provider")
    endpoint = snapshot.endpoint("approved-provider")
    binding = _qualification_routing(
        endpoint_snapshot_sha256=snapshot.snapshot_sha256,
        output_capability_sha256=(
            "e" * 64 if fault == "output_capability" else snapshot.output_capability_sha256
        ),
        structured_output_mode=(
            StructuredOutputMode.VALIDATED_TEXT_JSON
            if fault == "output_mode"
            else snapshot.structured_output_mode
        ),
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    try:
        with pytest.raises(
            OpenRouterQualificationError,
            match="endpoint or pricing snapshot",
        ):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.parametrize(
    ("endpoint_policy", "model_identity"),
    [
        (None, object()),
        (object(), None),
    ],
)
def test_qualified_production_routing_requires_both_current_runtime_snapshots(
    endpoint_policy: object | None,
    model_identity: object | None,
) -> None:
    binding = _qualification_routing()

    with pytest.raises(OpenRouterQualificationError, match="current model and endpoint snapshots"):
        binding.require_current(
            role="source_audit",
            model=binding.exact_model_id,
            provider_endpoints=(binding.approved_provider_endpoint,),
            now=datetime.now(UTC),
            endpoint_policy=endpoint_policy,  # type: ignore[arg-type]
            model_identity=model_identity,  # type: ignore[arg-type]
            require_runtime_snapshots=True,
        )


@pytest.mark.asyncio
async def test_certification_pins_each_qualified_request_to_its_singleton_endpoint(
    config_factory,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"qualified singleton"}',
            provider="approved-provider",
        )

    snapshot = _endpoint_snapshot(provider_name="approved-provider")
    endpoint = snapshot.endpoint("approved-provider")
    assert endpoint is not None
    binding = _qualification_routing(
        endpoint_snapshot_sha256=snapshot.snapshot_sha256,
        output_capability_sha256=snapshot.output_capability_sha256,
        structured_output_mode=snapshot.structured_output_mode,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider", "other-qualified-provider"),
        ),
        qualification_routing=(binding,),
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "qualified singleton"
    assert observed[0]["provider"]["only"] == ["approved-provider"]
    assert observed[0]["provider"]["allow_fallbacks"] is False
    assert usage.records[0].configured_provider_endpoints == ["approved-provider"]
    assert usage.records[0].routing["configured_provider_only"] == ["approved-provider"]


@pytest.mark.asyncio
async def test_certification_rejects_qualified_model_metadata_snapshot_drift(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"must not execute"}')

    manifest, evidence = _model_discovery_run(tmp_path)
    binding = _qualification_routing_for_discovery(evidence)
    binding = replace(binding, model_metadata_snapshot_sha256="f" * 64)
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    client.register_certification_model_discovery(
        evidence=evidence,
        manifest=manifest,
    )
    try:
        with pytest.raises(OpenRouterQualificationError, match="model identity snapshot"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []


@pytest.mark.asyncio
async def test_certification_records_exact_qualification_hashes_on_request_and_success(
    config_factory,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"qualified"}',
            provider="approved-provider",
        )

    binding = _qualification_routing()
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "qualified"
    expected_metadata = binding.request_metadata()
    assert {key: observed[0]["metadata"][key] for key in expected_metadata} == expected_metadata
    expected_routing = binding.routing_evidence()
    assert {key: usage.records[0].routing[key] for key in expected_routing} == expected_routing


@pytest.mark.asyncio
async def test_certification_normalizes_specialist_role_against_qualification(
    config_factory,
) -> None:
    binding = _qualification_routing(roles=("access_control",))
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"qualified specialist"}',
            provider="approved-provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    try:
        result = await client.complete(
            role="specialist:access_control",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "qualified specialist"
    assert usage.records[0].routing["qualification_result_sha256"] == (
        binding.qualification_result_sha256
    )


@pytest.mark.asyncio
async def test_certification_rejects_returned_provider_name_outside_qualification(
    config_factory,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"wrong provider"}',
            provider="approved-provider",
        )

    endpoint_snapshot = _endpoint_snapshot(
        provider="approved-provider",
        provider_name="Approved Provider",
    )
    endpoint = endpoint_snapshot.endpoint("approved-provider")
    assert endpoint is not None
    binding = _qualification_routing(
        provider_name="Wrong Provider",
        endpoint_snapshot_sha256=endpoint_snapshot.snapshot_sha256,
        output_capability_sha256=endpoint_snapshot.output_capability_sha256,
        structured_output_mode=endpoint_snapshot.structured_output_mode,
        pricing_snapshot_sha256=endpoint.pricing_sha256,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    client.register_certification_endpoint_snapshot(evidence=endpoint_snapshot)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError, match="identity is unbound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert len(usage.records) == 1
    assert usage.records[0].status != "success"
    assert usage.records[0].routing["qualification_result_sha256"] == (
        binding.qualification_result_sha256
    )


@pytest.mark.asyncio
async def test_certification_failure_record_retains_exact_qualification_hashes(
    config_factory,
) -> None:
    binding = _qualification_routing()
    client, http_client, usage = _client(
        config_factory(
            execution={
                "max_json_repair_attempts": 0,
                "max_model_retries": 0,
            }
        ),
        lambda _request: httpx.Response(503, json={"error": {"message": "unavailable"}}),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
        qualification_routing=(binding,),
    )
    try:
        with pytest.raises(OpenRouterTransientError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    expected_routing = binding.routing_evidence()
    assert {key: usage.records[0].routing[key] for key in expected_routing} == expected_routing
    assert usage.records[0].status != "success"


def test_certification_requires_provider_pin_zdr_and_no_repair(config_factory) -> None:
    with pytest.raises(ValueError, match="endpoint allowlist"):
        OpenRouterProviderPolicy(certification=True)
    assert OpenRouterProviderPolicy(
        certification=True,
        only=("approved-provider", "second-provider"),
    ).configured_endpoints == ("approved-provider", "second-provider")
    with pytest.raises(OpenRouterPrivacyError, match="live operator privacy authorization"):
        _client(
            config_factory(
                execution={"max_json_repair_attempts": 0},
                privacy={
                    "profile": "FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT",
                    "require_zdr": False,
                    "maximum_model_retention": "temporary",
                },
            ),
            lambda _request: _completion_response('{"answer":"unexpected"}'),
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=("approved-provider",),
            ),
        )
    with pytest.raises(OpenRouterSchemaError, match="repair is disabled"):
        _client(
            config_factory(execution={"max_json_repair_attempts": 1}),
            lambda _request: _completion_response('{"answer":"unexpected"}'),
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=("approved-provider",),
            ),
        )


@pytest.mark.asyncio
async def test_same_family_model_alias_is_rejected_and_evidence_is_invalid(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"wrong"}',
            model="alpha/atlas-secure:variant",
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError, match="identity is unbound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status == "unbound_identity"
    assert usage.records[0].substitution_detected
    assert usage.records[0].validation_status.value == "model_mismatch"


@pytest.mark.asyncio
async def test_truncated_response_is_rejected_and_not_repaired(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _completion('{"answer":"partial"}')
        payload["choices"][0]["finish_reason"] = "length"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTruncatedResponseError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "rejected_truncated_response"
    assert usage.records[0].validation_status.value == "truncated"


@pytest.mark.asyncio
async def test_native_truncation_cannot_hide_behind_normalized_stop(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _completion('{"answer":"partial"}')
        payload["choices"][0]["finish_reason"] = "stop"
        payload["choices"][0]["native_finish_reason"] = "max_tokens"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTruncatedResponseError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert usage.records[0].status == "rejected_truncated_response"
    assert usage.records[0].validation_status.value == "truncated"


@pytest.mark.asyncio
async def test_native_truncation_is_not_retained_behind_an_identity_mismatch(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"parseable but incomplete"}',
            model="alpha/atlas-secure:variant",
        )
        payload["choices"][0]["native_finish_reason"] = "max_tokens"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTruncatedResponseError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 1
    assert usage.records[0].status == "rejected_truncated_response"
    assert usage.records[0].validated_response_sha256 is None
    assert not is_creditable_usage_record(usage.records[0])


@pytest.mark.asyncio
async def test_router_selected_provider_must_match_certification_policy(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"wrong provider"}',
            provider="unapproved-provider",
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterUnboundIdentityError, match="identity is unbound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].validation_status.value == "provider_mismatch"


@pytest.mark.asyncio
async def test_optional_router_attempts_require_snapshot_bound_provider_display_name(
    config_factory,
) -> None:
    endpoint_snapshot = _endpoint_snapshot(
        provider="google-vertex",
        provider_name="Google Vertex",
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"bound"}',
            provider="Google Vertex",
        )
        payload["openrouter_metadata"].pop("attempts")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("google-vertex",),
        ),
        qualification_routing=(_qualification_routing_for_endpoint_snapshot(endpoint_snapshot),),
    )
    client.register_certification_endpoint_snapshot(evidence=endpoint_snapshot)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "bound"
    record = usage.records[0]
    assert record.provider == "Google Vertex"
    assert record.actual_provider_endpoint == "google-vertex"
    assert record.routing["selected_provider_name"] == "Google Vertex"
    assert record.routing["router_attempt_count"] == 1
    assert record.routing["router_attempts_observed"] is False


@pytest.mark.asyncio
async def test_optional_router_attempts_without_exact_endpoint_binding_fail_closed(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"unbound"}')
        payload["openrouter_metadata"].pop("attempts")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="exact endpoint binding"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert usage.records[0].status != "success"


@pytest.mark.asyncio
async def test_model_endpoint_metadata_uses_exact_documented_path(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "alpha/atlas-secure",
                    "endpoints": [{"name": "approved-provider"}],
                }
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        endpoints = await client.list_model_endpoints("alpha/atlas-secure")
    finally:
        await http_client.aclose()
    assert endpoints == [{"name": "approved-provider"}]
    assert observed[0].url.path == "/api/v1/models/alpha/atlas-secure/endpoints"


@pytest.mark.asyncio
async def test_model_endpoint_metadata_rejects_wrong_model_binding(config_factory) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "bravo/borealis-secure",
                    "endpoints": [{"name": "approved-provider"}],
                }
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact requested model"):
            await client.list_model_endpoints("alpha/atlas-secure")
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_single_model_metadata_uses_alias_resolving_documented_path(
    config_factory,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "alpha/atlas-secure",
                    "canonical_slug": "alpha/atlas-secure-20260727",
                }
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        metadata = await client.get_model_metadata("alpha/atlas-secure")
    finally:
        await http_client.aclose()

    assert metadata["data"]["canonical_slug"] == "alpha/atlas-secure-20260727"
    assert observed[0].url.path == "/api/v1/model/alpha/atlas-secure"


@pytest.mark.asyncio
async def test_single_model_metadata_rejects_cross_author_canonical_identity(
    config_factory,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: httpx.Response(
            200,
            json={
                "data": {
                    "id": "alpha/atlas-secure",
                    "canonical_slug": "bravo/atlas-secure-20260727",
                }
            },
        ),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="canonical identity"):
            await client.get_model_metadata("alpha/atlas-secure")
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_single_model_metadata_rejects_unrelated_same_author_identity(
    config_factory,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: httpx.Response(
            200,
            json={
                "data": {
                    "id": "alpha/unrelated-model",
                    "canonical_slug": "alpha/unrelated-model-20260727",
                }
            },
        ),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="canonical identity"):
            await client.get_model_metadata("alpha/atlas-secure")
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_malformed_initial_response_never_produces_success_usage(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("not-json")

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "failed:OpenRouterStructuredOutputError"
    assert usage.records[0].validation_status.value == "invalid_response"


@pytest.mark.asyncio
async def test_missing_actual_cost_never_produces_success_usage(config_factory) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response('{"answer":"unaccounted"}', cost=None)

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="cost accounting"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].reported_cost_usd is None
    assert usage.records[0].accounted_cost_usd > 0


@pytest.mark.asyncio
async def test_error_inside_success_http_response_is_typed_and_never_credited(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-provider-error"},
            json={
                "error": {"code": 429, "message": "provider-controlled detail"},
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 0,
                    "total_tokens": 10,
                    "cost": 0.003,
                },
            },
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTransientError, match="rate limit"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].reported_cost_usd is None
    assert usage.records[0].accounted_cost_usd > 0.003
    assert usage.records[0].provider_error_classification == "rate_limit"


@pytest.mark.asyncio
async def test_valid_zero_cost_is_reconciled_for_an_unbound_identity_response(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"mismatched"}',
            cost=0,
            model="unrelated/model",
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterUnboundIdentityError, match="identity is unbound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert record.reported_cost_usd == 0.0
    assert record.accounted_cost_usd == 0.0
    assert client.budget.spent_usd == pytest.approx(record.accounted_cost_usd)


@pytest.mark.parametrize(
    ("fault", "expected_error"),
    [
        ("mismatched_generation_header", OpenRouterUnboundIdentityError),
        ("wrong_message_role", OpenRouterSchemaError),
        ("multiple_choices", OpenRouterSchemaError),
        ("inconsistent_usage", OpenRouterSchemaError),
        ("missing_router_metadata", OpenRouterSchemaError),
        ("hidden_router_fallback", OpenRouterModelError),
    ],
)
@pytest.mark.asyncio
async def test_incomplete_provider_envelopes_fail_closed(
    config_factory,
    fault: str,
    expected_error: type[Exception],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"unsafe envelope"}')
        headers = {"X-Generation-Id": "generation-test"}
        if fault == "mismatched_generation_header":
            headers = {"X-Generation-Id": "different-generation"}
        elif fault == "wrong_message_role":
            payload["choices"][0]["message"]["role"] = "user"
        elif fault == "multiple_choices":
            payload["choices"].append(dict(payload["choices"][0]))
        elif fault == "inconsistent_usage":
            payload["usage"]["total_tokens"] = 99
        elif fault == "missing_router_metadata":
            payload.pop("openrouter_metadata")
        elif fault == "hidden_router_fallback":
            payload["openrouter_metadata"]["strategy"] = "fallback"
        return httpx.Response(200, headers=headers, json=payload)

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(expected_error):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].validation_status.value != "valid"


@pytest.mark.asyncio
async def test_reasoning_cached_cost_and_latency_evidence_are_recorded(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"evidenced"}')
        payload["usage"]["completion_tokens_details"] = {"reasoning_tokens": 3}
        payload["usage"]["prompt_tokens_details"] = {"cached_tokens": 4}
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(),
        handler,
        reasoning=OpenRouterReasoning(max_tokens=3),
    )
    try:
        await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    record = usage.records[0]
    assert record.reasoning_tokens == 3
    assert record.cached_tokens == 4
    assert record.reported_cost_usd == 0.01
    assert record.latency_ms is not None
    assert record.started_at is not None
    assert record.ended_at is not None


def test_token_route_intersection_uses_exact_endpoint_minima_and_snapshot_provenance(
    config_factory,
) -> None:
    snapshot = _asymmetric_token_endpoint_snapshot()
    policy = OpenRouterProviderPolicy(
        only=("provider-narrow", "provider-wide"),
        allow_fallbacks=False,
    )
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=policy,
    )
    try:
        client.register_endpoint_snapshot(evidence=snapshot)
        intersection = client._route_token_intersection(
            model="alpha/atlas-secure",
            provider_policy=policy,
            requested_completion_tokens=2_048,
        )
    finally:
        asyncio.run(http_client.aclose())

    assert intersection.context_tokens == 96_000
    assert intersection.max_prompt_tokens == 72_000
    assert intersection.max_completion_tokens == 12_000
    assert intersection.provider_endpoints == ("provider-narrow", "provider-wide")
    route_hashes = {
        route.provider_endpoint: route.endpoint_snapshot_sha256 for route in intersection.routes
    }
    assert route_hashes == {
        endpoint.provider_endpoint: endpoint.endpoint_snapshot_sha256
        for endpoint in snapshot.endpoints
    }
    assert all(
        route.endpoint_snapshot_sha256 != snapshot.snapshot_sha256 for route in intersection.routes
    )


@pytest.mark.asyncio
async def test_context_package_token_plan_binds_category_hashes_and_omissions(
    config_factory,
) -> None:
    source = "contract SyntheticVault { function totalAssets() external pure returns (uint256) {} }"
    source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    source_omission = "src/Generated.sol omitted by deterministic source budget"
    metadata_omission = "supporting role metadata omitted by the context budget"
    package = ContextPackage(
        role="source_audit",
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=200_000,
        effective_source_byte_ceiling=75_000,
        repository_map=RepositoryMap(
            root_name="synthetic-token-context",
            languages={"Solidity": 1},
            frameworks=[],
            manifests=[],
            entry_points=["SyntheticVault.totalAssets"],
            api_surfaces=["SyntheticVault.totalAssets"],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
            omitted_files=[],
        ),
        scanner_findings=[],
        excerpts=[
            ContextExcerpt(
                path="src/SyntheticVault.sol",
                start_line=1,
                end_line=1,
                content_hash=source_sha256,
                content=source,
                categories=["smart_contract", "evm_value"],
            )
        ],
        omissions=[
            ContextOmissionItem.build(
                category=ContextOmissionCategory.CONTEXT_PACKAGE,
                reason=ContextOmissionReason.CONTEXT_BUDGET_EXCLUDED,
                omitted_item_sha256=hashlib.sha256(metadata_omission.encode()).hexdigest(),
            ),
            ContextOmissionItem.build(
                category=ContextOmissionCategory.SOURCE,
                reason=ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                omitted_item_sha256=hashlib.sha256(source_omission.encode()).hexdigest(),
            ),
        ],
    )
    package = package.model_copy(
        update={"bytes_used": len(render_context(package).encode("utf-8"))}
    )
    rendered = render_context(package)
    workflow_prefix = "Review this synthetic context.\n"
    expected_measurements = context_category_measurements(package)

    client, http_client, usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"context reviewed"}'),
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="Review only the supplied synthetic source.",
            user_prompt=workflow_prefix + rendered,
            context_package=package,
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "context reviewed"
    plan = usage.records[0].routing["request_token_plan"]
    allocations = {
        allocation["category"]: allocation["estimate"] for allocation in plan["allocations"]
    }
    for category, measurement in expected_measurements.items():
        if category == PromptAllocationCategory.WORKFLOW.value:
            continue
        assert allocations[category]["content_sha256"] == measurement.content_sha256
        assert allocations[category]["utf8_bytes"] == measurement.utf8_bytes
    assert allocations[PromptAllocationCategory.WORKFLOW.value]["content_sha256"] == (
        hashlib.sha256(workflow_prefix.encode("utf-8")).hexdigest()
    )
    assert plan["context_omission_sha256s"] == sorted(
        item.omitted_item_sha256 for item in package.omissions
    )
    assert plan["source_budget"]["context_package_source_byte_ceiling"] == 75_000
    assert plan["source_budget"]["maximum_source_byte_upper_bound_tokens"] == 75_000
    assert plan["source_budget"]["maximum_source_tokens_per_request"] == 25_000
    assert {(item["category"], item["reason"]) for item in plan["context_omissions"]} == {
        ("context_package", "CONTEXT_BUDGET_EXCLUDED"),
        ("source", "SOURCE_BUDGET_EXCLUDED"),
    }
    context_evidence = usage.records[0].routing["context_request_evidence"]
    assert context_evidence["request_role"] == "source_audit"
    assert context_evidence["context_role"] == "source_audit"
    assert context_evidence["relationship"] == "exact"
    assert context_evidence["declared_bytes_used"] == package.bytes_used
    assert context_evidence["rendered_bytes"] == package.bytes_used
    assert context_evidence["source_bytes"] == len(source.encode("utf-8"))
    assert (
        usage.records[0].routing["context_request_evidence_sha256"]
        == (context_evidence["evidence_sha256"])
    )


@pytest.mark.asyncio
async def test_request_max_tokens_reserves_visible_output_and_reasoning(
    config_factory,
) -> None:
    observed_bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_bodies.append(json.loads(request.content))
        return _completion_response(
            '{"answer":"bounded reasoning"}',
            reasoning_tokens=3,
        )

    config = config_factory(
        execution={
            "max_output_tokens_per_request": 2_048,
        }
    )
    client, http_client, usage = _client(
        config,
        handler,
        reasoning=OpenRouterReasoning(max_tokens=512),
    )
    try:
        await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert len(observed_bodies) == 1
    assert observed_bodies[0]["max_tokens"] == 2_560
    assert observed_bodies[0]["reasoning"]["max_tokens"] == 512
    assert observed_bodies[0]["reasoning"]["exclude"] is False
    routing = usage.records[0].routing
    plan = routing["request_token_plan"]
    atomic = routing["atomic_token_reservation"]
    assert plan["required_output_tokens"] == 2_048
    assert plan["reserved_reasoning_tokens"] == 512
    assert plan["requested_completion_tokens"] == 2_560
    assert plan["prompt_framing_reserve_tokens"] > 0
    assert plan["prompt_byte_upper_bound_tokens"] == (
        plan["prompt_content_byte_upper_bound_tokens"] + plan["prompt_framing_reserve_tokens"]
    )
    assert atomic["planned_prompt_tokens"] == plan["prompt_byte_upper_bound_tokens"]
    assert atomic["planned_completion_tokens"] == 2_560
    assert atomic["request_token_plan_sha256"] == plan["plan_sha256"]


@pytest.mark.asyncio
async def test_provider_token_overrun_fails_closed_and_retains_plan_evidence(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"usage overrun"}')
        payload["usage"].update(
            {
                "prompt_tokens": 1_000_000,
                "completion_tokens": 5,
                "total_tokens": 1_000_005,
            }
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(TokenReservationOverrunError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert len(usage.records) == 1
    failed = usage.records[0]
    assert failed.status != "success"
    assert failed.validation_status is not ModelRequestValidationStatus.VALID
    assert (
        failed.routing["request_token_plan_sha256"]
        == (failed.routing["request_token_plan"]["plan_sha256"])
    )
    assert (
        failed.routing["atomic_token_reservation_sha256"]
        == (failed.routing["atomic_token_reservation"]["evidence_sha256"])
    )
    assert not is_creditable_usage_record(failed)
