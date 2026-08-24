from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.usage as usage_module
from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.openrouter import (
    OpenRouterCostControlError,
    OpenRouterProviderPolicy,
    OpenRouterRequestCostPreviewError,
    OpenRouterStructuredRequestCostPreview,
    preview_openrouter_structured_request_cost,
    validate_openrouter_generation_payload,
)
from mmaudit.models.output_modes import StructuredOutputMode, output_mode_request_parameters
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningPolicyArtifact,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    StructuredOutputEvidence,
    UsageRecord,
    seal_structured_output_evidence,
    structured_output_request_shape_sha256,
)
from mmaudit.models.usage import (
    _structured_output_routing_failure_code,
    is_creditable_usage_record,
    noncrediting_unknown_token_smoke_usage_diagnostics,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit.test_openrouter import (
    Answer,
    _as_v3_unknown_token_smoke_usage,
    _client,
    _completion_response,
    _generation_payload,
    _model_discovery_run,
)

_PROMPT_DOMINATED_CACHE_READ_PRICING = {
    "completion": "0.00001",
    "input_cache_read": "0.0000001",
    "prompt": "0.000001",
    "request": "0",
}


def _disabled_reasoning_policy() -> ReasoningPolicyArtifact:
    return ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="disabled",
                reserved_reasoning_tokens=0,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )


def _high_effort_reasoning_policy() -> ReasoningPolicyArtifact:
    return ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="effort",
                effort="high",
                reserved_reasoning_tokens=4_096,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )


def _effort_none_reasoning_policy() -> ReasoningPolicyArtifact:
    return ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="effort",
                effort="none",
                reserved_reasoning_tokens=0,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )


_PER_ROLE_REASONING_OUTPUT_MATRIX = (
    (
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        False,
        ("json_schema", "max_tokens", "reasoning", "response_format", "temperature"),
    ),
    (
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        True,
        ("json_schema", "max_tokens", "reasoning", "response_format", "temperature"),
    ),
    (
        StructuredOutputMode.JSON_OBJECT,
        False,
        ("max_tokens", "reasoning", "response_format", "temperature"),
    ),
    (
        StructuredOutputMode.JSON_OBJECT,
        True,
        ("max_tokens", "reasoning", "response_format", "temperature"),
    ),
    (
        StructuredOutputMode.VALIDATED_TEXT_JSON,
        False,
        ("max_tokens", "reasoning", "temperature"),
    ),
    (
        StructuredOutputMode.VALIDATED_TEXT_JSON,
        True,
        ("max_tokens", "reasoning", "temperature"),
    ),
)


def _with_structured_reasoning_state(
    record: UsageRecord,
    *,
    reasoning_requested: bool,
) -> UsageRecord:
    """Return canonical output evidence with one explicitly selected reasoning state."""

    evidence = StructuredOutputEvidence.model_validate(record.routing["structured_output"])
    required_parameters = tuple(
        sorted(
            {
                *(
                    parameter
                    for parameter in evidence.required_provider_parameters
                    if parameter != "reasoning"
                ),
                *(("reasoning",) if reasoning_requested else ()),
            }
        )
    )
    reasoning_request_sha256 = (
        evidence.reasoning_request_sha256 or ("a" * 64) if reasoning_requested else None
    )
    request_shape_sha256 = structured_output_request_shape_sha256(
        mode=evidence.requested_mode,
        schema_sha256=evidence.schema_sha256,
        required_provider_parameters=required_parameters,
        reasoning_request_sha256=reasoning_request_sha256,
        strict_protocol_sha256=evidence.strict_protocol_sha256,
    )
    without_reasoning = seal_structured_output_evidence(
        requested_mode=evidence.requested_mode,
        achieved_mode=evidence.achieved_mode,
        configured_provider_endpoints=evidence.configured_provider_endpoints,
        selected_provider_endpoint=evidence.selected_provider_endpoint,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot_sha256,
        output_capability_sha256=evidence.output_capability_sha256,
        endpoint_structured_output_parameters=(evidence.endpoint_structured_output_parameters),
        prompt_sha256=evidence.prompt_sha256,
        request_body_sha256=evidence.request_body_sha256,
        provider_policy_sha256=evidence.provider_policy_sha256,
        schema_sha256=evidence.schema_sha256,
        original_response_sha256=evidence.original_response_sha256,
        decoded_response_sha256=evidence.decoded_response_sha256,
        validated_response_sha256=evidence.validated_response_sha256,
        response_format=evidence.response_format,
        required_provider_parameters=required_parameters,
        provider_require_parameters=bool(required_parameters),
        reasoning_request_sha256=reasoning_request_sha256,
        request_shape_sha256=request_shape_sha256,
        strict_protocol_sha256=evidence.strict_protocol_sha256,
        repair_evidence=evidence.repair_evidence,
    )
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "structured_output": without_reasoning.model_dump(mode="json"),
                "structured_output_request_shape_sha256": request_shape_sha256,
                "structured_output_require_parameters": bool(required_parameters),
                "structured_output_required_provider_parameters": list(required_parameters),
                "structured_output_reasoning_request_sha256": reasoning_request_sha256,
            }
        }
    )


def _preview(
    *,
    config: Any,
    manifest: Any,
    evidence: Any,
    policy: OpenRouterProviderPolicy,
    reasoning_policy: ReasoningPolicyArtifact,
    user_prompt: str = "synthetic provider-free request",
    logical_request_id: str = "authrunner-candidate-case-001",
) -> OpenRouterStructuredRequestCostPreview:
    return preview_openrouter_structured_request_cost(
        execution=config.execution,
        privacy=config.privacy,
        token_budgets=config.token_budgets,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        role="model_benchmark",
        system_prompt="bounded synthetic system prompt",
        user_prompt=user_prompt,
        response_model=Answer,
        schema_name="answer",
        logical_request_id=logical_request_id,
    )


def test_provider_free_request_cost_preview_is_exact_stable_and_nonauthorizing(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    config = config_factory(execution={"max_model_retries": 2, "max_requests_per_agent": 3})
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()

    first = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    second = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )

    assert first == second
    assert first.preview_sha256 == second.preview_sha256
    assert first.maximum_attempts == 3
    assert first.provider_endpoint == "approved-provider"
    assert first.discovery_manifest_sha256 == manifest.manifest_sha256
    assert first.discovery_evidence_sha256 == evidence.discovery_evidence_sha256
    assert first.requested_completion_tokens == (
        first.reserved_output_tokens + first.reserved_reasoning_tokens
    )
    assert Decimal(first.maximum_cost_usd_per_attempt_exact) > Decimal(0)
    assert Decimal(first.maximum_cost_usd_all_attempts_exact) == (
        Decimal(first.maximum_cost_usd_per_attempt_exact) * 3
    )
    components = {component.pricing_field: component for component in first.cost_components}
    raw_endpoint = evidence.endpoint_snapshot.endpoints[0]
    assert raw_endpoint.pricing["input_cache_read"] == "0.0000001"
    assert first.endpoint_pricing_sha256 == raw_endpoint.pricing_sha256
    assert components["input_cache_read"].unit_price_usd_exact == "0.000001"
    assert components["input_cache_read"].maximum_units == first.maximum_priced_prompt_units
    assert components["prompt"].unit_price_usd_exact == "0.000001"
    assert components["prompt"].maximum_units == first.maximum_priced_prompt_units
    additive_input_worst_case = sum(
        Decimal(components[field].unit_price_usd_exact) * components[field].maximum_units
        for field in ("input_cache_read", "prompt")
    )
    assert Decimal(first.maximum_cost_usd_per_attempt_exact) >= (additive_input_worst_case)
    assert not first.authorizes_dispatch
    assert not first.authorizes_budget_reservation
    assert not first.authorizes_provider_transport
    assert not first.grants_review_credit
    assert not first.grants_completion_credit


@pytest.mark.asyncio
async def test_catalog_effort_fallback_dispatches_the_exact_previewed_reasoning_shape(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        endpoint_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        model_reasoning={
            "default_enabled": None,
            "supported_efforts": ["low", "high", "max"],
        },
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )

    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _high_effort_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "catalog-effort-preview-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id="authrunner-candidate-case-001",
            expected_request_cost_preview=preview,
        )
    finally:
        await http_client.aclose()

    assert evidence.reasoning_capability.supported_reasoning_efforts is None
    assert evidence.model_supported_reasoning_efforts == ("low", "high", "max")
    assert preview.reserved_reasoning_tokens == 4_096
    assert preview.schema_version == "1.1"
    assert preview.wire_max_tokens == preview.reserved_output_tokens
    assert preview.requested_completion_tokens == (
        preview.reserved_output_tokens + preview.reserved_reasoning_tokens
    )
    assert len(observed) == 1
    request_body = json.loads(observed[0].content)
    assert request_body["reasoning"] == {
        "effort": "high",
        "exclude": False,
    }
    assert request_body["max_tokens"] == preview.wire_max_tokens
    token_detail = result.usage_record.token_detail_accounting_evidence
    assert token_detail is not None
    assert result.usage_record.prompt_tokens == token_detail.provider_prompt_tokens == 10
    assert result.usage_record.completion_tokens == token_detail.provider_completion_tokens == 5
    assert result.usage_record.reasoning_tokens == token_detail.provider_reasoning_tokens == 6
    assert token_detail.accounted_completion_tokens == preview.requested_completion_tokens
    assert budget.spent_input_tokens == token_detail.accounted_prompt_tokens
    assert budget.spent_output_tokens == token_detail.accounted_completion_tokens
    assert not is_creditable_usage_record(
        result.usage_record,
        require_real=True,
        require_certification=True,
    )
    assert result.usage_record.routing["request_cost_preview_sha256"] == preview.preview_sha256
    assert usage.records == [result.usage_record]


@pytest.mark.parametrize(
    ("smoke_scope", "privacy_proof_kind", "request_segment"),
    (
        (
            "CANDIDATE",
            "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
            "candidate.primary",
        ),
        (
            "JUDGE",
            "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            "judge.primary",
        ),
    ),
)
@pytest.mark.parametrize(
    ("expected_mode", "reasoning_active", "supported_parameters"),
    _PER_ROLE_REASONING_OUTPUT_MATRIX,
)
@pytest.mark.asyncio
async def test_v3_smoke_identity_join_covers_six_per_role_output_reasoning_cases(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    smoke_scope: str,
    privacy_proof_kind: str,
    request_segment: str,
    expected_mode: StructuredOutputMode,
    reasoning_active: bool,
    supported_parameters: tuple[str, ...],
) -> None:
    observed: list[httpx.Request] = []
    effort_none = bool(
        reasoning_active
        and expected_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        and smoke_scope == "CANDIDATE"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=(6 if reasoning_active and not effort_none else None),
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    manifest, discovery = _model_discovery_run(
        tmp_path,
        model_supported_parameters=supported_parameters,
        endpoint_supported_parameters=supported_parameters,
        model_reasoning={
            "default_enabled": False,
            "mandatory": False,
            "supported_efforts": ["none", "low", "high", "max"],
        },
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    provider_policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = (
        (_effort_none_reasoning_policy() if effort_none else _high_effort_reasoning_policy())
        if reasoning_active
        else _disabled_reasoning_policy()
    )
    request_id = f"authrunner.smoke.r1.{request_segment}:{'4' * 64}"
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=discovery,
        policy=provider_policy,
        reasoning_policy=reasoning_policy,
        logical_request_id=request_id,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "smoke-reasoning-identity-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, _usage = _client(
        config,
        handler,
        provider_policy=provider_policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=discovery, manifest=manifest)
    try:
        completion = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id=request_id,
            expected_request_cost_preview=preview,
        )
        retrieved_at = datetime.now(UTC)
        generation = validate_openrouter_generation_payload(
            _generation_payload(),
            requested_generation_id="generation-test",
            retrieved_at=retrieved_at,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        )
        identity_binding = client.bind_generation_identity(
            usage_record=completion.usage_record,
            generation_evidence=generation,
            evaluated_at=retrieved_at,
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert len(observed) == 1
    request_body = json.loads(observed[0].content)
    assert ("reasoning" in request_body) is reasoning_active
    assert ("response_format" in request_body) is bool(
        output_mode_request_parameters(expected_mode)
    )
    routed = completion.usage_record.model_dump(mode="json")
    routed["execution_evidence"] = ExecutionEvidenceKind.REAL.value
    routed["routing"] = {
        **routed["routing"],
        "privacy_source_proof_kind": privacy_proof_kind,
        "identity_binding": identity_binding.model_dump(mode="json"),
    }
    provisional = UsageRecord.model_validate(routed)
    assert provisional.reasoning_evidence is not None
    if effort_none:
        assert provisional.reasoning_evidence.request_plan.control_profile.mode == "effort"
        assert provisional.reasoning_evidence.request_plan.control_profile.effort == "none"
        assert (
            provisional.reasoning_evidence.request_plan.control_profile.reserved_reasoning_tokens
            == 0
        )
    record = _as_v3_unknown_token_smoke_usage(
        provisional,
        reasoning_plan=provisional.reasoning_evidence.request_plan,
    )
    assert usage_module.authrunner_noncrediting_unknown_token_smoke_scope(record) == smoke_scope
    structured = StructuredOutputEvidence.model_validate(record.routing["structured_output"])
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    capabilities = binding.snapshot.endpoint_capabilities
    identity_special_parameters = set(capabilities.required_parameters) - {
        "max_tokens",
        "temperature",
    }
    expected_output_parameters = set(output_mode_request_parameters(expected_mode))

    assert structured.requested_mode is expected_mode
    assert identity_special_parameters == expected_output_parameters
    assert capabilities.reasoning_supported
    assert "reasoning" in capabilities.reasoning_parameters
    assert set(structured.required_provider_parameters) == expected_output_parameters | (
        {"reasoning"} if reasoning_active else set()
    )
    assert set(structured.required_provider_parameters) == {
        parameter for parameter in ("reasoning", "response_format") if parameter in request_body
    }
    assert _structured_output_routing_failure_code(record) == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
        if reasoning_active
        else None
    )
    assert (
        _structured_output_routing_failure_code(
            record,
            allow_noncrediting_unknown_token_accounting=True,
        )
        is None
    )
    assert (
        noncrediting_unknown_token_smoke_usage_diagnostics(
            record,
            require_runtime_attestation=False,
        )
        == ()
    )
    assert not is_creditable_usage_record(
        record,
        require_real=True,
        require_certification=True,
    )

    if reasoning_active:
        for outside_request_id, outside_proof in (
            (
                "authrunner.candidate.primary:case-0123456789abcdef",
                "RELEASE_PINNED_MODEL_BENCHMARK",
            ),
            ("generic-request", "SYNTHETIC_TEST"),
        ):
            outside = record.model_copy(
                update={
                    "request_id": outside_request_id,
                    "routing": {
                        **record.routing,
                        "privacy_source_proof_kind": outside_proof,
                    },
                }
            )
            assert (
                _structured_output_routing_failure_code(
                    outside,
                    allow_noncrediting_unknown_token_accounting=True,
                )
                == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
            )

        omitted_reasoning = _with_structured_reasoning_state(
            record,
            reasoning_requested=False,
        )
        assert (
            set(
                StructuredOutputEvidence.model_validate(
                    omitted_reasoning.routing["structured_output"]
                ).required_provider_parameters
            )
            == identity_special_parameters
        )
        assert (
            _structured_output_routing_failure_code(
                omitted_reasoning,
                allow_noncrediting_unknown_token_accounting=True,
            )
            == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
        )

        raw_plan = record.routing["request_token_plan"]
        assert isinstance(raw_plan, dict)
        malformed_plan = record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    "request_token_plan": {**raw_plan, "plan_sha256": "0" * 64},
                }
            }
        )
        assert (
            _structured_output_routing_failure_code(
                malformed_plan,
                allow_noncrediting_unknown_token_accounting=True,
            )
            == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
        )

        if expected_mode is StructuredOutputMode.JSON_OBJECT and smoke_scope == "CANDIDATE":

            def malformed_scope_classifier(_record: UsageRecord) -> Any:
                return []

            assert (
                _structured_output_routing_failure_code(
                    record,
                    allow_noncrediting_unknown_token_accounting=True,
                    authrunner_smoke_scope_classifier=malformed_scope_classifier,
                )
                == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
            )

            def malformed_join_return(*_args: Any, **_kwargs: Any) -> Any:
                return []

            def unknown_join_return(*_args: Any, **_kwargs: Any) -> Any:
                return "UNKNOWN"

            for malformed_join in (malformed_join_return, unknown_join_return):
                assert (
                    _structured_output_routing_failure_code(
                        record,
                        allow_noncrediting_unknown_token_accounting=True,
                        validate_smoke_reasoning_identity_join=malformed_join,
                    )
                    == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
                )

            unsupported_capabilities = capabilities.model_copy(
                update={
                    "reasoning_parameters": (),
                    "reasoning_supported": False,
                }
            )
            unsupported_binding = binding.model_copy(
                update={
                    "snapshot": binding.snapshot.model_copy(
                        update={"endpoint_capabilities": unsupported_capabilities}
                    )
                }
            )
            with monkeypatch.context() as context:
                context.setattr(
                    usage_module,
                    "_validated_identity_binding",
                    lambda _record: unsupported_binding,
                )
                assert (
                    _structured_output_routing_failure_code(
                        record,
                        allow_noncrediting_unknown_token_accounting=True,
                    )
                    == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
                )

            output_drift_capabilities = capabilities.model_copy(
                update={"required_parameters": ("max_tokens", "temperature")}
            )
            output_drift_binding = binding.model_copy(
                update={
                    "snapshot": binding.snapshot.model_copy(
                        update={"endpoint_capabilities": output_drift_capabilities}
                    )
                }
            )
            with monkeypatch.context() as context:
                context.setattr(
                    usage_module,
                    "_validated_identity_binding",
                    lambda _record: output_drift_binding,
                )
                assert (
                    _structured_output_routing_failure_code(
                        record,
                        allow_noncrediting_unknown_token_accounting=True,
                    )
                    == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
                )

    elif expected_mode is StructuredOutputMode.JSON_OBJECT and smoke_scope == "CANDIDATE":

        def invalid_scope_classifier(_record: UsageRecord) -> Any:
            return "INVALID"

        assert (
            _structured_output_routing_failure_code(
                record,
                allow_noncrediting_unknown_token_accounting=True,
                authrunner_smoke_scope_classifier=invalid_scope_classifier,
            )
            is None
        )
        static_reasoning_record = _with_structured_reasoning_state(
            record,
            reasoning_requested=True,
        )
        static_reasoning_capabilities = capabilities.model_copy(
            update={
                "required_parameters": tuple(
                    sorted({*capabilities.required_parameters, "reasoning"})
                )
            }
        )
        static_reasoning_binding = binding.model_copy(
            update={
                "snapshot": binding.snapshot.model_copy(
                    update={
                        "endpoint_capabilities": static_reasoning_capabilities,
                        "provider_policy": binding.snapshot.provider_policy.model_copy(
                            update={"require_parameters": True}
                        ),
                    }
                )
            }
        )
        with monkeypatch.context() as context:
            context.setattr(
                usage_module,
                "_validated_identity_binding",
                lambda _record: static_reasoning_binding,
            )
            assert _structured_output_routing_failure_code(static_reasoning_record) is None
            assert (
                _structured_output_routing_failure_code(
                    static_reasoning_record,
                    allow_noncrediting_unknown_token_accounting=True,
                )
                == "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
            )


@pytest.mark.parametrize("cache_bound", ["0.0000001", "0.000001000000000001"])
def test_request_cost_preview_rejects_self_resealed_cache_bound_different_from_prompt(
    config_factory: Any,
    tmp_path: Path,
    cache_bound: str,
) -> None:
    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            certification=True,
        ),
        reasoning_policy=_disabled_reasoning_policy(),
    )
    payload = preview.model_dump(mode="python")
    components = payload["cost_components"]
    for component in components:
        if component["pricing_field"] == "input_cache_read":
            component["unit_price_usd_exact"] = cache_bound
    pricing = {
        component["pricing_field"]: component["unit_price_usd_exact"] for component in components
    }
    maximum_units = {
        component["pricing_field"]: component["maximum_units"] for component in components
    }
    rebound = openrouter_module._trusted_endpoint_request_cost_bound_from_pricing(
        exact_model_id=preview.exact_model_id,
        provider_endpoint=preview.provider_endpoint,
        request_material="mmaudit-provider-free-cost-preview",
        pricing=pricing,
        maximum_units=maximum_units,
    )
    rebound_maximum = openrouter_module._trusted_endpoint_request_maximum_cost_usd(rebound)
    payload["endpoint_cost_bound_pricing_sha256"] = rebound.pricing_snapshot_sha256
    payload["endpoint_cost_bound_projection_sha256"] = (
        openrouter_module._endpoint_request_cost_bound_projection_sha256(
            rebound,
            request_material_projection_sha256=preview.request_material_projection_sha256,
        )
    )
    payload["maximum_cost_usd_per_attempt_exact"] = openrouter_module._format_cost_decimal(
        rebound_maximum
    )
    payload["maximum_cost_usd_all_attempts_exact"] = openrouter_module._multiply_cost_decimal(
        rebound_maximum,
        preview.maximum_attempts,
    )
    payload["preview_sha256"] = openrouter_module._canonical_sha256(
        {key: value for key, value in payload.items() if key != "preview_sha256"}
    )

    with pytest.raises(
        ValueError,
        match="input-cache-read bound differs from its prompt-price bound",
    ):
        OpenRouterStructuredRequestCostPreview.model_validate(payload, strict=True)


@pytest.mark.asyncio
async def test_dispatch_enforces_exact_request_cost_preview_and_records_join(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
        )

    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "successful-preview-cost-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id="authrunner-candidate-case-001",
            expected_request_cost_preview=preview,
        )
    finally:
        await http_client.aclose()

    assert result.value.answer == "ok"
    assert len(observed) == 1
    request_body = json.loads(observed[0].content)
    provider_max_price = request_body["provider"]["max_price"]
    assert request_body["provider"]["only"] == ["approved-provider"]
    assert "input_cache_read" not in provider_max_price
    assert Decimal(str(provider_max_price["prompt"])) / Decimal(1_000_000) >= Decimal(
        _PROMPT_DOMINATED_CACHE_READ_PRICING["prompt"]
    )
    assert usage.records == [result.usage_record]
    assert result.usage_record.routing["request_cost_preview_sha256"] == (preview.preview_sha256)
    assert (
        result.usage_record.routing["request_cost_preview_maximum_cost_usd_per_attempt_exact"]
        == preview.maximum_cost_usd_per_attempt_exact
    )
    assert (
        result.usage_record.routing["request_cost_preview_maximum_cost_usd_all_attempts_exact"]
        == preview.maximum_cost_usd_all_attempts_exact
    )


@pytest.mark.asyncio
async def test_request_cost_preview_drift_rejects_before_reserve_or_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    transport_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return _completion_response('{"answer":"must-not-run"}')

    config = config_factory()
    manifest, evidence = _model_discovery_run(tmp_path)
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "drift-preview-cost-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        with pytest.raises(OpenRouterRequestCostPreviewError, match="user_prompt_sha256"):
            await client.complete_with_evidence(
                role="model_benchmark",
                models=["alpha/atlas-secure"],
                system_prompt="bounded synthetic system prompt",
                user_prompt="drifted provider request",
                response_model=Answer,
                schema_name="answer",
                logical_request_id="authrunner-candidate-case-001",
                expected_request_cost_preview=preview,
            )
    finally:
        await http_client.aclose()

    assert transport_calls == 0
    assert usage.records == []
    assert budget.spent_usd_exact == Decimal(0)
    assert budget.reserved_input_tokens == 0
    assert budget.reserved_output_tokens == 0


def test_provider_free_request_cost_preview_rejects_cache_read_above_prompt(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing={
            "completion": "0.00001",
            "input_cache_read": "0.000001000000000001",
            "prompt": "0.000001",
        },
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )

    with pytest.raises(
        OpenRouterCostControlError,
        match="input-cache-read endpoint price exceeds its provider-capped prompt price",
    ):
        _preview(
            config=config,
            manifest=manifest,
            evidence=evidence,
            policy=policy,
            reasoning_policy=_disabled_reasoning_policy(),
        )
