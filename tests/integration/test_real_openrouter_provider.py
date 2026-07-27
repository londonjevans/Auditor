"""Explicitly paid, synthetic-only OpenRouter transport smoke test."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict

from mmaudit.config import ExecutionConfig, PrivacyConfig
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.generation_evidence import GenerationVerificationRequest
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, ModelRequestValidationStatus
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.real_provider_harness import (
    REAL_PROVIDER_OPT_IN,
    load_real_provider_test_settings,
    real_provider_tests_enabled,
)

pytestmark = pytest.mark.skipif(
    not real_provider_tests_enabled(os.environ),
    reason=f"paid provider tests require explicit {REAL_PROVIDER_OPT_IN}=1",
)

_SYNTHETIC_MARKER = "mmaudit-synthetic-provider-smoke-v1"
_SYSTEM_PROMPT = (
    "This is a synthetic transport validation with no repository or target data. "
    "Return only the strict response schema and do not use tools or external data."
)
_USER_PROMPT = (
    "Set status to OK and marker to mmaudit-synthetic-provider-smoke-v1. "
    "There is no source code to analyze."
)


class _SyntheticProviderSmokeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["OK"]
    marker: Literal["mmaudit-synthetic-provider-smoke-v1"]


@pytest.mark.asyncio
async def test_real_openrouter_exact_private_structured_smoke() -> None:
    """Make exactly one bounded paid call after every explicit gate succeeds."""

    settings = load_real_provider_test_settings(os.environ)
    execution = ExecutionConfig(
        request_timeout_seconds=120,
        max_model_retries=0,
        max_json_repair_attempts=0,
        budget_usd=float(settings.cost_cap_usd),
        max_output_tokens_per_request=512,
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
    budget = BudgetManager(
        total_usd=float(settings.cost_cap_usd),
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
                reasoning=OpenRouterReasoning(max_tokens=64, exclude=True),
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
                    endpoint_snapshot=endpoint_snapshot,
                )
                _provenance, discovery_evidence = client.seal_real_model_discovery_run(
                    run_id=uuid.uuid4().hex,
                    retrieved_at=datetime.now(UTC).replace(microsecond=0),
                    models_payload=models_payload,
                    zdr_payload=zdr_payload,
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
                    user_prompt=_USER_PROMPT,
                    response_model=_SyntheticProviderSmokeResponse,
                    schema_name="mmaudit_real_provider_smoke_v1",
                )
                _assert_private_exact_request(
                    preview,
                    api_key=api_key,
                    secret_file=settings.secret_file,
                    model=settings.model_id,
                    providers=settings.provider_endpoint_allowlist,
                )
                assert preview["reasoning"] == {"exclude": True, "max_tokens": 64}
                response = await client.complete(
                    role="real_provider_smoke",
                    models=[settings.model_id],
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=_USER_PROMPT,
                    response_model=_SyntheticProviderSmokeResponse,
                    schema_name="mmaudit_real_provider_smoke_v1",
                )
                record = usage.records[0]
                selected_provider_name = record.routing.get("selected_provider_name")
                if not isinstance(selected_provider_name, str):
                    raise AssertionError("provider response omitted its selected provider")
                trusted_generation_verification = (
                    await client.create_trusted_generation_verification(
                        (
                            GenerationVerificationRequest(
                                benchmark_report_sha256="1" * 64,
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
                    benchmark_report_sha256="1" * 64,
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
    finally:
        api_key = None

    assert response.status == "OK"
    assert response.marker == _SYNTHETIC_MARKER
    assert len(usage.records) == 1
    record = usage.records[0]
    assert record.execution_evidence is ExecutionEvidenceKind.REAL
    assert record.validation_status is ModelRequestValidationStatus.VALID
    assert record.requested_model == settings.model_id
    assert record.returned_model == settings.model_id
    assert record.actual_model == discovery_payload.canonical_slug
    assert record.configured_provider_endpoints == list(settings.provider_endpoint_allowlist)
    assert record.actual_provider_endpoint is not None
    assert record.actual_provider_endpoint in settings.provider_endpoint_allowlist
    assert isinstance(record.routing["selected_provider_name"], str)
    assert record.routing["selected_provider_name"]
    assert record.provider
    assert record.reported_cost_usd is not None
    assert record.latency_ms is not None
    assert record.openrouter_generation_id
    assert refetched_generation.generation_id == record.openrouter_generation_id
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
    assert snapshot.spent_usd <= settings.cost_cap_usd


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
