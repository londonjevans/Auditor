"""Explicitly paid, synthetic-only OpenRouter transport smoke test."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.config import ExecutionConfig, PrivacyConfig
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    openrouter_catalog_canonical_slug,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.generation_evidence import GenerationVerificationRequest
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
)
from mmaudit.models.usage import UsageLedger, is_creditable_usage_record
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.release_io import read_json_evidence
from tests.real_provider_harness import (
    REAL_PROVIDER_OPT_IN,
    SMOKE_FIXTURE_PATH,
    SMOKE_MAX_OUTPUT_TOKENS,
    SMOKE_REASONING_EFFORT,
    RealProviderSmokeEvidence,
    SyntheticProviderSmokeResponse,
    load_pinned_synthetic_smoke_fixture,
    load_real_provider_test_settings,
    preflight_real_provider_smoke_output,
    real_provider_smoke_verification_subject_sha256,
    real_provider_tests_enabled,
    seal_real_provider_smoke_evidence,
    validate_smoke_reasoning_off_preflight,
    write_real_provider_smoke_evidence,
)

pytestmark = pytest.mark.skipif(
    not real_provider_tests_enabled(os.environ),
    reason=f"paid provider tests require explicit {REAL_PROVIDER_OPT_IN}=1",
)

_SYNTHETIC_MARKER = "mmaudit-synthetic-provider-smoke-v1"
_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / SMOKE_FIXTURE_PATH
_SMOKE_STAGE_CAP_USD = Decimal("5.00")
_SYSTEM_PROMPT = (
    "This is a synthetic transport validation with no repository or target data. "
    "Return only the strict response schema and do not use tools or external data."
)


@pytest.mark.asyncio
async def test_real_openrouter_exact_private_structured_smoke() -> None:
    """Make exactly one bounded paid call after every explicit gate succeeds."""

    settings = load_real_provider_test_settings(os.environ)
    assert settings.privacy_profile == "STRICT_ZDR"
    fixture_source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(_ROOT)
    preflight_real_provider_smoke_output(
        output_path=settings.evidence_output,
        forbidden_paths=(settings.secret_file, settings.cost_ledger, _FIXTURE),
    )
    user_prompt = (
        "Set status to OK and marker to mmaudit-synthetic-provider-smoke-v1 after "
        "reading this committed synthetic Solidity transport fixture. Do not report "
        "findings.\n"
        f'<synthetic_source path="{SMOKE_FIXTURE_PATH}" '
        f'sha256="{fixture_sha256}">\n'
        f"{fixture_source}\n"
        "</synthetic_source>"
    )
    execution = ExecutionConfig(
        request_timeout_seconds=120,
        max_model_retries=0,
        max_json_repair_attempts=0,
        budget_usd=float(settings.cost_cap_usd),
        max_output_tokens_per_request=SMOKE_MAX_OUTPUT_TOKENS,
        max_requests_per_agent=1,
        conservative_usd_per_million_tokens=60,
    )
    privacy = PrivacyConfig(
        allow_code_egress=True,
        require_zdr=True,
        redact_secrets=True,
        fail_on_detected_secret=True,
        store_raw_prompts=False,
        store_raw_responses=False,
        maximum_model_retention="zero",
    )
    atomic_ledger = AtomicCostLedger.open_existing(
        settings.cost_ledger,
        cap_usd=settings.cost_cap_usd,
    )
    ledger_before = atomic_ledger.snapshot()
    stage_cap = min(settings.cost_cap_usd, _SMOKE_STAGE_CAP_USD)
    budget = BudgetManager(
        total_usd=float(stage_cap),
        max_output_tokens=execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=1,
        atomic_ledger=atomic_ledger,
        require_endpoint_cost_bound=True,
    )
    usage = UsageLedger()
    api_key: str | None = None
    try:
        with load_operator_secrets(
            settings.secret_file,
            environ={},
            required=True,
        ) as secrets:
            api_key = secrets.openrouter_api_key
            client = OpenRouterClient(
                api_key=api_key,
                execution=execution,
                privacy=privacy,
                budget=budget,
                usage=usage,
                provider_policy=OpenRouterProviderPolicy(
                    certification=True,
                    only=settings.provider_endpoint_allowlist,
                    allow_fallbacks=False,
                ),
                reasoning=OpenRouterReasoning(
                    effort=SMOKE_REASONING_EFFORT,
                    exclude=True,
                ),
            )
            async with client:
                await client.validate_authentication()
                models_payload = await client.get_certification_model_metadata()
                models = models_payload.get("data")
                if not isinstance(models, list):
                    raise AssertionError("the certification model catalog is invalid")
                if settings.model_id not in {
                    item.get("id") for item in models if isinstance(item.get("id"), str)
                }:
                    raise AssertionError("the exact allowlisted model is unavailable")
                reasoning_capabilities = validate_smoke_reasoning_off_preflight(
                    models_payload=models_payload,
                    exact_model_id=settings.model_id,
                )
                canonical_slug = openrouter_catalog_canonical_slug(
                    exact_model_id=settings.model_id,
                    models_payload=models_payload,
                )
                single_model_payload = await client.get_model_metadata(settings.model_id)
                endpoint_payload = await client.get_model_endpoint_metadata(settings.model_id)
                zdr_payload = await client.list_zdr_endpoints()
                endpoint_snapshot = validate_openrouter_endpoint_snapshot(
                    exact_model_id=settings.model_id,
                    configured_provider_endpoints=(settings.provider_endpoint_allowlist),
                    provider_policy_mode="only",
                    endpoint_payload=endpoint_payload,
                    require_zdr=True,
                    zdr_payload=zdr_payload,
                )
                discovery_payload = validate_openrouter_model_discovery(
                    exact_model_id=settings.model_id,
                    models_payload=models_payload,
                    single_model_payload=single_model_payload,
                    endpoint_snapshot=endpoint_snapshot,
                )
                assert discovery_payload.canonical_slug == canonical_slug
                _provenance, discovery_evidence = client.seal_real_model_discovery_run(
                    run_id=uuid.uuid4().hex,
                    retrieved_at=datetime.now(UTC).replace(microsecond=0),
                    models_payload=models_payload,
                    zdr_payload=zdr_payload,
                    single_model_payloads={settings.model_id: single_model_payload},
                    endpoint_payloads={settings.model_id: endpoint_payload},
                    candidate_routes=(
                        DiscoveryCandidateRoute(
                            exact_model_id=settings.model_id,
                            approved_provider_endpoint=settings.provider_endpoint_allowlist[0],
                        ),
                    ),
                    payloads=(discovery_payload,),
                )
                client.register_certification_model_discovery(
                    evidence=discovery_evidence[0],
                )

                preview = client.build_request(
                    model=settings.model_id,
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    response_model=SyntheticProviderSmokeResponse,
                    schema_name="mmaudit_real_provider_smoke_v1",
                )
                _assert_private_exact_request(
                    preview,
                    api_key=api_key,
                    secret_file=settings.secret_file,
                    model=settings.model_id,
                    providers=settings.provider_endpoint_allowlist,
                )
                assert preview["max_tokens"] == SMOKE_MAX_OUTPUT_TOKENS
                assert preview["reasoning"] == {
                    "exclude": True,
                    "effort": SMOKE_REASONING_EFFORT,
                }
                response = await client.complete(
                    role="real_provider_smoke",
                    models=[settings.model_id],
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    response_model=SyntheticProviderSmokeResponse,
                    schema_name="mmaudit_real_provider_smoke_v1",
                )
                record = usage.records[0]
                selected_provider_name = record.routing.get("selected_provider_name")
                if not isinstance(selected_provider_name, str):
                    raise AssertionError("provider response omitted its selected provider")
                if (
                    record.openrouter_generation_id is None
                    or record.validated_response_sha256 is None
                    or record.schema_sha256 is None
                ):
                    raise AssertionError("provider smoke response omitted verification bindings")
                verification_subject_sha256 = real_provider_smoke_verification_subject_sha256(
                    fixture_sha256=fixture_sha256,
                    internal_request_id=record.request_id,
                    openrouter_generation_id=record.openrouter_generation_id,
                    requested_model_id=settings.model_id,
                    canonical_model_id=discovery_payload.canonical_slug,
                    validated_response_sha256=record.validated_response_sha256,
                    prompt_sha256=record.prompt_sha256,
                    schema_sha256=record.schema_sha256,
                    endpoint_snapshot_sha256=endpoint_snapshot.snapshot_sha256,
                    discovery_evidence_sha256=(discovery_evidence[0].discovery_evidence_sha256),
                )
                trusted_generation_verification = (
                    await client.create_trusted_generation_verification(
                        (
                            GenerationVerificationRequest(
                                benchmark_report_sha256=verification_subject_sha256,
                                case_id="synthetic-provider-smoke",
                                exact_model_id=settings.model_id,
                                canonical_model_id=discovery_payload.canonical_slug,
                                catalog_identity_binding_sha256=(
                                    discovery_payload.catalog_identity_binding_sha256
                                ),
                                discovery_evidence_sha256=(
                                    discovery_evidence[0].discovery_evidence_sha256
                                ),
                                expected_provider_name=selected_provider_name,
                                usage_record=record,
                            ),
                        )
                    )
                )
                refetched_generation = trusted_generation_verification.attestation_for(
                    benchmark_report_sha256=verification_subject_sha256,
                    case_id="synthetic-provider-smoke",
                    exact_model_id=settings.model_id,
                    canonical_model_id=discovery_payload.canonical_slug,
                    catalog_identity_binding_sha256=(
                        discovery_payload.catalog_identity_binding_sha256
                    ),
                    discovery_evidence_sha256=(discovery_evidence[0].discovery_evidence_sha256),
                    usage_record=record,
                    expected_provider_name=selected_provider_name,
                )

            assert response.status == "OK"
            assert response.marker == _SYNTHETIC_MARKER
            assert len(usage.records) == 1
            record = usage.records[0]
            assert record.execution_evidence is ExecutionEvidenceKind.REAL
            assert record.validation_status is ModelRequestValidationStatus.VALID
            assert record.identity_strength in {
                ModelIdentityStrength.IMMUTABLE_VERSION_BOUND,
                ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND,
            }
            assert is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            assert record.requested_model == settings.model_id
            assert record.returned_model in {
                settings.model_id,
                discovery_payload.canonical_slug,
            }
            assert record.actual_model == discovery_payload.canonical_slug
            assert record.configured_provider_endpoints == list(
                settings.provider_endpoint_allowlist
            )
            assert record.actual_provider_endpoint is not None
            assert record.actual_provider_endpoint in settings.provider_endpoint_allowlist
            assert isinstance(record.routing["selected_provider_name"], str)
            assert record.routing["selected_provider_name"]
            assert record.provider
            assert record.reported_cost_usd is not None
            assert record.started_at is not None
            assert record.ended_at is not None
            assert record.latency_ms is not None
            assert record.openrouter_generation_id
            assert record.user_prompt_sha256 is not None
            assert record.schema_sha256 is not None
            assert record.request_body_sha256 is not None
            assert record.response_sha256 is not None
            assert record.validated_response_sha256 is not None
            assert record.finish_reason == "stop"
            assert record.reasoning_tokens == 0
            assert refetched_generation.generation_id == record.openrouter_generation_id
            assert refetched_generation.exact_model_id in {
                settings.model_id,
                discovery_payload.canonical_slug,
            }
            assert refetched_generation.provider_name == selected_provider_name
            assert refetched_generation.finish_reason == record.finish_reason
            assert refetched_generation.prompt_tokens == record.prompt_tokens
            assert refetched_generation.completion_tokens == record.completion_tokens
            if refetched_generation.reasoning_tokens is not None:
                assert refetched_generation.reasoning_tokens == record.reasoning_tokens
            assert refetched_generation.reasoning_tokens in {None, 0}
            if refetched_generation.cached_tokens is not None:
                assert refetched_generation.cached_tokens == record.cached_tokens
            assert Decimal(refetched_generation.total_cost_usd) == Decimal(
                str(record.reported_cost_usd)
            )
            assert record.routing["endpoint_snapshot_sha256"] == endpoint_snapshot.snapshot_sha256
            assert (
                record.routing["catalog_identity_binding_sha256"]
                == discovery_payload.catalog_identity_binding_sha256
            )
            assert not record.fallback_used
            assert not record.substitution_detected

            snapshot = atomic_ledger.snapshot()
            assert snapshot.active_reserved_usd == 0
            assert not snapshot.over_cap
            assert not snapshot.has_reservation_overrun
            assert snapshot.spent_usd <= settings.cost_cap_usd
            matching_entries = [
                entry for entry in snapshot.entries if entry.request_id == record.request_id
            ]
            assert len(matching_entries) == 1
            ledger_entry = matching_entries[0]
            assert ledger_entry.status is CostEntryStatus.RECONCILED
            assert ledger_entry.actual_cost_usd is not None
            assert ledger_entry.actual_cost_usd == Decimal(str(record.reported_cost_usd))
            assert ledger_entry.accounted_cost_usd == Decimal(str(record.accounted_cost_usd))
            smoke_spend_delta = snapshot.spent_usd - ledger_before.spent_usd
            assert smoke_spend_delta == ledger_entry.accounted_cost_usd
            assert smoke_spend_delta <= _SMOKE_STAGE_CAP_USD

            evidence = seal_real_provider_smoke_evidence(
                {
                    "schema_version": "1.0",
                    "ticket_id": "V3-SMOKE-001",
                    "evidence_kind": "real_openrouter_synthetic_smoke",
                    "status": "SUCCESS",
                    "execution_evidence": record.execution_evidence.value,
                    "fixture_path": SMOKE_FIXTURE_PATH,
                    "fixture_sha256": fixture_sha256,
                    "internal_request_id": record.request_id,
                    "openrouter_generation_id": record.openrouter_generation_id,
                    "requested_model_id": settings.model_id,
                    "canonical_model_id": discovery_payload.canonical_slug,
                    "returned_model_id": record.returned_model,
                    "generation_model_id": refetched_generation.exact_model_id,
                    "approved_provider_endpoint": settings.provider_endpoint_allowlist[0],
                    "actual_provider_endpoint": record.actual_provider_endpoint,
                    "actual_provider_name": selected_provider_name,
                    "provider_policy_sha256": _routing_sha256(
                        record.routing,
                        "provider_policy_sha256",
                    ),
                    "endpoint_snapshot_sha256": endpoint_snapshot.snapshot_sha256,
                    "model_metadata_snapshot_sha256": (
                        discovery_payload.model_metadata_snapshot_sha256
                    ),
                    "discovery_provenance_sha256": (
                        discovery_evidence[0].provenance.provenance_sha256
                    ),
                    "discovery_evidence_sha256": (discovery_evidence[0].discovery_evidence_sha256),
                    "identity_snapshot_sha256": _routing_sha256(
                        record.routing,
                        "identity_snapshot_sha256",
                    ),
                    "generation_evidence_sha256": refetched_generation.evidence_sha256,
                    "verification_subject_sha256": verification_subject_sha256,
                    "prompt_sha256": record.prompt_sha256,
                    "user_prompt_sha256": record.user_prompt_sha256,
                    "schema_sha256": record.schema_sha256,
                    "request_body_sha256": record.request_body_sha256,
                    "response_sha256": record.response_sha256,
                    "validated_response_sha256": record.validated_response_sha256,
                    "started_at": record.started_at,
                    "ended_at": record.ended_at,
                    "latency_ms": record.latency_ms,
                    "finish_reason": record.finish_reason,
                    "prompt_tokens": record.prompt_tokens,
                    "completion_tokens": record.completion_tokens,
                    "reasoning_tokens": record.reasoning_tokens,
                    "cached_tokens": record.cached_tokens,
                    "total_tokens": record.total_tokens,
                    "requested_max_output_tokens": SMOKE_MAX_OUTPUT_TOKENS,
                    "requested_reasoning_effort": SMOKE_REASONING_EFFORT,
                    "requested_reasoning_excluded": True,
                    "model_reasoning_mandatory": reasoning_capabilities.mandatory,
                    "model_reasoning_default_enabled": (reasoning_capabilities.default_enabled),
                    "model_reasoning_supports_max_tokens": (
                        reasoning_capabilities.supports_max_tokens
                    ),
                    "actual_cost_usd": _canonical_money(ledger_entry.actual_cost_usd),
                    "accounted_cost_usd": _canonical_money(ledger_entry.accounted_cost_usd),
                    "ledger_cap_usd": _canonical_money(snapshot.cap_usd),
                    "ledger_spent_before_usd": _canonical_money(ledger_before.spent_usd),
                    "ledger_spent_usd": _canonical_money(snapshot.spent_usd),
                    "smoke_spend_delta_usd": _canonical_money(smoke_spend_delta),
                    "ledger_active_reserved_usd": "0",
                    "ledger_remaining_usd": _canonical_money(snapshot.remaining_usd),
                    "validation_status": record.validation_status.value,
                    "identity_strength": record.identity_strength.value,
                    "privacy_profile": "STRICT_ZDR",
                    "require_zdr": True,
                    "data_collection": "deny",
                    "allow_fallbacks": False,
                    "fallback_used": record.fallback_used,
                    "substitution_detected": record.substitution_detected,
                    "raw_prompts_stored": False,
                    "raw_responses_stored": False,
                    "validated_output": response.model_dump(mode="json"),
                }
            )
            binding = write_real_provider_smoke_evidence(
                output_path=settings.evidence_output,
                evidence=evidence,
                forbidden_values=(
                    api_key,
                    str(settings.secret_file),
                    fixture_source,
                ),
            )
            observed = read_json_evidence(
                evidence_root=settings.evidence_output.parent,
                relative_path=settings.evidence_output.name,
                max_bytes=64_000,
            )
            assert observed.binding == binding
            assert RealProviderSmokeEvidence.model_validate(observed.value) == evidence
    finally:
        api_key = None


def _assert_private_exact_request(
    body: dict[str, object],
    *,
    api_key: str,
    secret_file: Path,
    model: str,
    providers: tuple[str, ...],
) -> None:
    if body.get("model") != model:
        raise AssertionError("provider request did not retain the exact model")
    provider = body.get("provider")
    if not isinstance(provider, dict):
        raise AssertionError("provider request omitted the strict privacy route")
    max_price = provider.get("max_price")
    core_provider = {key: value for key, value in provider.items() if key != "max_price"}
    if core_provider != {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
        "only": list(providers),
    }:
        raise AssertionError("provider request did not retain the strict privacy route")
    if (
        not isinstance(max_price, dict)
        or not {"prompt", "completion"}.issubset(max_price)
        or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0
            for value in max_price.values()
        )
    ):
        raise AssertionError("provider request omitted bounded endpoint price ceilings")
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":"))
    if api_key in serialized:
        raise AssertionError("operator credential entered a model request")
    if str(secret_file) in serialized:
        raise AssertionError("operator secret-file path entered a model request")


def _routing_sha256(routing: Mapping[str, object], key: str) -> str:
    value = routing.get(key)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AssertionError(f"provider evidence omitted the required {key}")
    return value


def _canonical_money(value: Decimal) -> str:
    if not value.is_finite() or value < 0:
        raise AssertionError("provider cost evidence is invalid")
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
