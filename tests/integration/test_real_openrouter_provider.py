"""Explicitly paid, synthetic-only OpenRouter transport smoke test."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
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
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    GenerationReconciliationMismatchError,
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    _reconcile_generation_evidence_structural,
)
from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterGenerationReconciliationError,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import (
    UsageLedger,
    _has_owned_real_usage_attestation,
    _is_strict_usage_record,
    is_creditable_usage_record,
    is_generation_bindable_usage_record,
)
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence
from tests.real_provider_harness import (
    REAL_PROVIDER_OPT_IN,
    SMOKE_FIXTURE_PATH,
    SMOKE_MAX_OUTPUT_TOKENS,
    SMOKE_REASONING_EFFORT,
    RealProviderSmokeEvidence,
    RealProviderSmokeRejectionEvidence,
    RealProviderSmokeVerificationRejectionEvidence,
    RealProviderTestSettings,
    SyntheticProviderSmokeResponse,
    load_pinned_synthetic_smoke_fixture,
    load_real_provider_test_settings,
    preflight_real_provider_smoke_output,
    real_provider_smoke_rejection_output_path,
    real_provider_smoke_verification_rejection_output_path,
    real_provider_smoke_verification_subject_sha256,
    real_provider_tests_enabled,
    seal_real_provider_smoke_evidence,
    seal_real_provider_smoke_rejection_evidence,
    seal_real_provider_smoke_verification_rejection_evidence,
    validate_smoke_reasoning_off_preflight,
    write_real_provider_smoke_evidence,
    write_real_provider_smoke_rejection_evidence,
    write_real_provider_smoke_verification_rejection_evidence,
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


@dataclass(frozen=True)
class _SmokeLedgerEvidence:
    """One attempt-qualified terminal transition and its prior-state integrity facts."""

    entry: CostEntry
    spend_delta_usd: Decimal
    prior_entries_sha256_before: str
    prior_entries_sha256_after: str
    prior_entries_unchanged: bool
    delta_reconciled: bool


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
                    reasoning_requested=False,
                    structured_output_required=False,
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
                completion = await client.complete_with_evidence(
                    role="real_provider_smoke",
                    models=[settings.model_id],
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    response_model=SyntheticProviderSmokeResponse,
                    schema_name="mmaudit_real_provider_smoke_v1",
                )
                response = completion.value
                record = completion.usage_record
                assert usage.records == [record]
                if record.identity_strength is ModelIdentityStrength.UNBOUND:
                    snapshot = atomic_ledger.snapshot()
                    ledger_evidence = _terminal_smoke_ledger_evidence(
                        snapshot=snapshot,
                        ledger_before=ledger_before,
                        record=record,
                    )
                    rejection_output, rejection = _write_unbound_smoke_rejection(
                        settings=settings,
                        fixture_source=fixture_source,
                        fixture_sha256=fixture_sha256,
                        user_prompt=user_prompt,
                        canonical_model_id=discovery_payload.canonical_slug,
                        endpoint_snapshot_sha256=endpoint_snapshot.snapshot_sha256,
                        model_metadata_snapshot_sha256=(
                            discovery_payload.model_metadata_snapshot_sha256
                        ),
                        discovery_provenance_sha256=(
                            discovery_evidence[0].provenance.provenance_sha256
                        ),
                        discovery_evidence_sha256=(discovery_evidence[0].discovery_evidence_sha256),
                        record=record,
                        response=response,
                        ledger_before=ledger_before,
                        snapshot=snapshot,
                        ledger_evidence=ledger_evidence,
                        api_key=api_key,
                    )
                    client.clear_retained_unbound_completions()
                    diagnostics = ",".join(
                        code.value for code in rejection.identity_diagnostic_codes
                    )
                    raise AssertionError(
                        "provider smoke identity remained unbound; "
                        f"diagnostics={diagnostics}; "
                        f"rejection_artifact={rejection_output.name}"
                    )
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
                verification_request = GenerationVerificationRequest(
                    benchmark_report_sha256=verification_subject_sha256,
                    case_id="synthetic-provider-smoke",
                    exact_model_id=settings.model_id,
                    canonical_model_id=discovery_payload.canonical_slug,
                    catalog_identity_binding_sha256=(
                        discovery_payload.catalog_identity_binding_sha256
                    ),
                    discovery_evidence_sha256=(discovery_evidence[0].discovery_evidence_sha256),
                    expected_provider_name=selected_provider_name,
                    usage_record=record,
                )
                try:
                    trusted_generation_verification = (
                        await client.create_trusted_generation_verification((verification_request,))
                    )
                except OpenRouterGenerationReconciliationError as exc:
                    snapshot = atomic_ledger.snapshot()
                    ledger_evidence = _terminal_smoke_ledger_evidence(
                        snapshot=snapshot,
                        ledger_before=ledger_before,
                        record=record,
                    )
                    rejection_output, verification_rejection = (
                        _write_generation_verification_smoke_rejection(
                            settings=settings,
                            fixture_source=fixture_source,
                            fixture_sha256=fixture_sha256,
                            user_prompt=user_prompt,
                            canonical_model_id=discovery_payload.canonical_slug,
                            verification_subject_sha256=verification_subject_sha256,
                            record=record,
                            response=response,
                            verification_request=verification_request,
                            error=exc,
                            ledger_before=ledger_before,
                            snapshot=snapshot,
                            ledger_evidence=ledger_evidence,
                            api_key=api_key,
                        )
                    )
                    client.clear_retained_unbound_completions()
                    raise AssertionError(
                        "provider smoke generation verification was rejected; "
                        f"mismatch_code={verification_rejection.mismatch_code.name}; "
                        f"attempts={verification_rejection.reconciliation_attempts}; "
                        f"rejection_artifact={rejection_output.name}"
                    ) from None
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
            observed_token_pairs = {
                (
                    refetched_generation.prompt_tokens,
                    refetched_generation.completion_tokens,
                )
            }
            if (
                refetched_generation.native_prompt_tokens is not None
                and refetched_generation.native_completion_tokens is not None
            ):
                observed_token_pairs.add(
                    (
                        refetched_generation.native_prompt_tokens,
                        refetched_generation.native_completion_tokens,
                    )
                )
            assert (record.prompt_tokens, record.completion_tokens) in observed_token_pairs
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
            ledger_evidence = _terminal_smoke_ledger_evidence(
                snapshot=snapshot,
                ledger_before=ledger_before,
                record=record,
            )
            ledger_entry = ledger_evidence.entry
            assert ledger_entry.status is CostEntryStatus.RECONCILED
            assert ledger_entry.actual_cost_usd is not None
            assert ledger_entry.actual_cost_usd == Decimal(str(record.reported_cost_usd))
            assert ledger_entry.accounted_cost_usd == Decimal(str(record.accounted_cost_usd))
            smoke_spend_delta = ledger_evidence.spend_delta_usd
            assert ledger_evidence.prior_entries_unchanged
            assert ledger_evidence.delta_reconciled
            assert snapshot.active_reserved_usd == 0
            assert not snapshot.over_cap
            assert not snapshot.has_reservation_overrun
            assert snapshot.spent_usd <= settings.cost_cap_usd
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


def _terminal_smoke_ledger_evidence(
    *,
    snapshot: CostLedgerSnapshot,
    ledger_before: CostLedgerSnapshot,
    record: UsageRecord,
) -> _SmokeLedgerEvidence:
    attempt_request_id = f"{record.request_id}:attempt:1"
    if any(entry.request_id == attempt_request_id for entry in ledger_before.entries):
        raise AssertionError("provider smoke attempt already existed before the request")
    matching_entries = [
        entry for entry in snapshot.entries if entry.request_id == attempt_request_id
    ]
    if len(matching_entries) != 1:
        raise AssertionError("provider smoke ledger lacks one exact attempt-qualified entry")
    ledger_entry = matching_entries[0]
    if ledger_entry.status not in {
        CostEntryStatus.RECONCILED,
        CostEntryStatus.UNCERTAIN_ACCOUNTED,
        CostEntryStatus.RESERVATION_OVERRUN,
    }:
        raise AssertionError("provider smoke ledger attempt is not terminal")
    if ledger_entry.accounted_cost_usd != Decimal(str(record.accounted_cost_usd)):
        raise AssertionError("provider smoke ledger does not match accounted runtime usage")
    if record.reported_cost_usd is None:
        if (
            ledger_entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
            or ledger_entry.actual_cost_usd is not None
        ):
            raise AssertionError("provider smoke unknown cost lacks conservative accounting")
    elif (
        ledger_entry.actual_cost_usd != Decimal(str(record.reported_cost_usd))
        or ledger_entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    ):
        raise AssertionError("provider smoke reported cost does not match its ledger attempt")

    smoke_spend_delta = snapshot.spent_usd - ledger_before.spent_usd
    if smoke_spend_delta < 0:
        raise AssertionError("provider smoke ledger spend decreased across the request")
    prior_before = _ledger_entries_sha256(ledger_before.entries)
    prior_after = _ledger_entries_sha256(
        tuple(entry for entry in snapshot.entries if entry.request_id != attempt_request_id)
    )
    return _SmokeLedgerEvidence(
        entry=ledger_entry,
        spend_delta_usd=smoke_spend_delta,
        prior_entries_sha256_before=prior_before,
        prior_entries_sha256_after=prior_after,
        prior_entries_unchanged=prior_before == prior_after,
        delta_reconciled=smoke_spend_delta == ledger_entry.accounted_cost_usd,
    )


def _ledger_entries_sha256(entries: tuple[CostEntry, ...]) -> str:
    projection = [
        {
            "request_id": entry.request_id,
            "reservation_id": entry.reservation_id,
            "status": entry.status.value,
            "reserved_usd": _canonical_money(entry.reserved_usd),
            "actual_cost_usd": (
                None if entry.actual_cost_usd is None else _canonical_money(entry.actual_cost_usd)
            ),
            "accounted_cost_usd": _canonical_money(entry.accounted_cost_usd),
            "release_reason": (
                None if entry.release_reason is None else entry.release_reason.value
            ),
            "created_at": entry.created_at.astimezone(UTC).isoformat(),
            "updated_at": entry.updated_at.astimezone(UTC).isoformat(),
        }
        for entry in sorted(entries, key=lambda item: item.request_id)
    ]
    return canonical_sha256(projection)


def _write_unbound_smoke_rejection(
    *,
    settings: RealProviderTestSettings,
    fixture_source: str,
    fixture_sha256: str,
    user_prompt: str,
    canonical_model_id: str,
    endpoint_snapshot_sha256: str,
    model_metadata_snapshot_sha256: str,
    discovery_provenance_sha256: str,
    discovery_evidence_sha256: str,
    record: UsageRecord,
    response: SyntheticProviderSmokeResponse,
    ledger_before: CostLedgerSnapshot,
    snapshot: CostLedgerSnapshot,
    ledger_evidence: _SmokeLedgerEvidence,
    api_key: str,
) -> tuple[Path, RealProviderSmokeRejectionEvidence]:
    ledger_entry = ledger_evidence.entry
    smoke_spend_delta = ledger_evidence.spend_delta_usd
    if (
        record.identity_strength is not ModelIdentityStrength.UNBOUND
        or record.routing.get("identity_binding_status") != "generation_metadata_unbound"
        or not _is_rejection_transport_usage_record(record, ledger_entry=ledger_entry)
        or is_creditable_usage_record(
            record,
            require_real=True,
            require_certification=True,
        )
    ):
        raise AssertionError("provider rejection sink requires one concluded unbound response")
    actual_cost_usd = ledger_entry.actual_cost_usd
    raw_binding = record.routing.get("identity_binding")
    if not isinstance(raw_binding, dict):
        raise AssertionError("provider rejection omitted typed identity binding evidence")
    identity_binding = OpenRouterIdentityBindingResult.model_validate(raw_binding)
    if (
        identity_binding.strength is not ModelIdentityStrength.UNBOUND
        or not identity_binding.diagnostic_codes
        or identity_binding.binding_sha256 != record.routing.get("identity_binding_sha256")
    ):
        raise AssertionError("provider rejection identity binding is inconsistent")
    binding_request = identity_binding.request
    binding_snapshot = identity_binding.snapshot
    started_at = record.started_at
    ended_at = record.ended_at
    selected_provider_name = record.routing.get("selected_provider_name")
    if (
        started_at is None
        or ended_at is None
        or binding_request.execution_evidence != record.execution_evidence.value
        or binding_request.internal_request_id != record.request_id
        or binding_request.requested_slug != settings.model_id
        or binding_request.returned_slug != record.returned_model
        or binding_request.selected_model_slug != record.actual_model
        or binding_request.actual_provider_endpoint != record.actual_provider_endpoint
        or binding_request.actual_provider_name != selected_provider_name
        or binding_request.openrouter_generation_id != record.openrouter_generation_id
        or binding_request.request_body_sha256 != record.request_body_sha256
        or binding_request.response_sha256 != record.response_sha256
        or binding_request.validated_response_sha256 != record.validated_response_sha256
        or binding_request.started_at != started_at.astimezone(UTC).replace(microsecond=0)
        or binding_request.completed_at != ended_at.astimezone(UTC).replace(microsecond=0)
        or binding_request.fallback_used != record.routing.get("provider_fallback_used")
        or binding_snapshot.requested_slug != settings.model_id
        or binding_snapshot.canonical_slug != canonical_model_id
        or binding_snapshot.approved_provider_endpoint != settings.provider_endpoint_allowlist[0]
        or binding_snapshot.provider_name != selected_provider_name
        or binding_snapshot.snapshot_sha256 != record.routing.get("identity_snapshot_sha256")
        or binding_snapshot.endpoint_snapshot_sha256 != endpoint_snapshot_sha256
        or binding_snapshot.model_metadata_snapshot_sha256 != model_metadata_snapshot_sha256
        or binding_snapshot.discovery_provenance_sha256 != discovery_provenance_sha256
        or binding_snapshot.discovery_evidence_sha256 != discovery_evidence_sha256
    ):
        raise AssertionError("provider rejection identity binding does not match runtime evidence")
    raw_generation_observation = record.routing.get("unbound_generation_observation")
    generation_observation = (
        None
        if raw_generation_observation is None
        else OpenRouterGenerationEvidence.model_validate(raw_generation_observation)
    )
    rejection = seal_real_provider_smoke_rejection_evidence(
        {
            "schema_version": "1.0",
            "ticket_id": "V3-SMOKE-001",
            "evidence_kind": "real_openrouter_synthetic_smoke_rejection",
            "status": "REJECTED_IDENTITY_UNBOUND",
            "creditable": False,
            "execution_evidence": record.execution_evidence.value,
            "fixture_path": SMOKE_FIXTURE_PATH,
            "fixture_sha256": fixture_sha256,
            "internal_request_id": record.request_id,
            "openrouter_generation_id": record.openrouter_generation_id,
            "requested_model_id": settings.model_id,
            "canonical_model_id": canonical_model_id,
            "returned_model_id": record.returned_model,
            "selected_model_id": record.actual_model,
            "approved_provider_endpoint": settings.provider_endpoint_allowlist[0],
            "actual_provider_endpoint": record.actual_provider_endpoint,
            "selected_provider_identity": record.routing.get("selected_provider_identity"),
            "selected_provider_name": record.routing.get("selected_provider_name"),
            "response_provider_identity": record.routing.get("response_provider_identity"),
            "model_identity_control_satisfied": (
                record.returned_model in {settings.model_id, canonical_model_id}
                and record.actual_model in {settings.model_id, canonical_model_id}
            ),
            "endpoint_control_satisfied": (
                record.actual_provider_endpoint == settings.provider_endpoint_allowlist[0]
            ),
            "provider_policy_sha256": _routing_sha256(
                record.routing,
                "provider_policy_sha256",
            ),
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
            "discovery_provenance_sha256": discovery_provenance_sha256,
            "discovery_evidence_sha256": discovery_evidence_sha256,
            "identity_snapshot_sha256": _routing_sha256(
                record.routing,
                "identity_snapshot_sha256",
            ),
            "identity_binding_sha256": identity_binding.binding_sha256,
            "identity_binding_status": "generation_metadata_unbound",
            "identity_diagnostic_codes": identity_binding.diagnostic_codes,
            "generation_observation": generation_observation,
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
            "reasoning_control_satisfied": record.reasoning_tokens == 0,
            "output_control_satisfied": (record.completion_tokens <= SMOKE_MAX_OUTPUT_TOKENS),
            "ledger_entry_request_id": ledger_entry.request_id,
            "ledger_entry_status": ledger_entry.status.value,
            "reserved_cost_usd": _canonical_money(ledger_entry.reserved_usd),
            "provider_reported_cost_usd": (
                None
                if record.reported_cost_usd is None
                else _canonical_money(Decimal(str(record.reported_cost_usd)))
            ),
            "actual_cost_usd": (
                None if actual_cost_usd is None else _canonical_money(actual_cost_usd)
            ),
            "accounted_cost_usd": _canonical_money(ledger_entry.accounted_cost_usd),
            "cost_reconciled": ledger_entry.status is CostEntryStatus.RECONCILED,
            "ledger_cap_usd": _canonical_money(snapshot.cap_usd),
            "ledger_spent_before_usd": _canonical_money(ledger_before.spent_usd),
            "ledger_spent_usd": _canonical_money(snapshot.spent_usd),
            "smoke_spend_delta_usd": _canonical_money(smoke_spend_delta),
            "ledger_delta_reconciled": ledger_evidence.delta_reconciled,
            "ledger_prior_entries_sha256_before": (ledger_evidence.prior_entries_sha256_before),
            "ledger_prior_entries_sha256_after": ledger_evidence.prior_entries_sha256_after,
            "ledger_prior_entries_unchanged": ledger_evidence.prior_entries_unchanged,
            "ledger_active_reserved_usd": _canonical_money(snapshot.active_reserved_usd),
            "ledger_reservations_closed": snapshot.active_reserved_usd == 0,
            "ledger_over_cap": snapshot.over_cap,
            "ledger_has_reservation_overrun": snapshot.has_reservation_overrun,
            "ledger_remaining_usd": _canonical_money(snapshot.remaining_usd),
            "stage_cost_control_satisfied": (
                ledger_entry.accounted_cost_usd <= _SMOKE_STAGE_CAP_USD
            ),
            "validation_status": record.validation_status.value,
            "identity_strength": record.identity_strength.value,
            "privacy_profile": settings.privacy_profile,
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
    rejection_output = real_provider_smoke_rejection_output_path(
        success_output=settings.evidence_output,
        internal_request_id=record.request_id,
    )
    file_binding = write_real_provider_smoke_rejection_evidence(
        success_output=settings.evidence_output,
        evidence=rejection,
        forbidden_values=(
            api_key,
            str(settings.secret_file),
            fixture_source,
            _SYSTEM_PROMPT,
            user_prompt,
        ),
    )
    observed = read_json_evidence(
        evidence_root=rejection_output.parent,
        relative_path=rejection_output.name,
        max_bytes=64_000,
    )
    if (
        observed.binding != file_binding
        or RealProviderSmokeRejectionEvidence.model_validate(observed.value) != rejection
        or settings.evidence_output.exists()
    ):
        raise AssertionError("provider rejection artifact did not round-trip safely")
    return rejection_output, rejection


def _write_generation_verification_smoke_rejection(
    *,
    settings: RealProviderTestSettings,
    fixture_source: str,
    fixture_sha256: str,
    user_prompt: str,
    canonical_model_id: str,
    verification_subject_sha256: str,
    record: UsageRecord,
    response: SyntheticProviderSmokeResponse,
    verification_request: GenerationVerificationRequest,
    error: OpenRouterGenerationReconciliationError,
    ledger_before: CostLedgerSnapshot,
    snapshot: CostLedgerSnapshot,
    ledger_evidence: _SmokeLedgerEvidence,
    api_key: str,
) -> tuple[Path, RealProviderSmokeVerificationRejectionEvidence]:
    """Persist a bound response that failed mandatory fresh generation verification."""

    ledger_entry = ledger_evidence.entry
    last_evidence = error.last_evidence
    raw_binding = record.routing.get("identity_binding")
    if (
        not _has_owned_real_usage_attestation(record)
        or not is_generation_bindable_usage_record(record)
        or not is_creditable_usage_record(
            record,
            require_real=True,
            require_certification=True,
        )
        or record.identity_strength
        not in {
            ModelIdentityStrength.IMMUTABLE_VERSION_BOUND,
            ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND,
        }
        or record.routing.get("identity_binding_status") != "generation_metadata_bound"
        or not isinstance(raw_binding, dict)
        or last_evidence is None
        or error.attempts != last_evidence.retrieval_attempts
        or verification_request.usage_record != record
        or not _has_owned_real_usage_attestation(verification_request.usage_record)
    ):
        raise AssertionError("verification rejection sink requires one owned bound REAL response")
    identity_binding = OpenRouterIdentityBindingResult.model_validate(raw_binding)
    if (
        identity_binding.strength is not record.identity_strength
        or identity_binding.generation is None
        or identity_binding.binding_sha256 != record.routing.get("identity_binding_sha256")
    ):
        raise AssertionError("verification rejection identity binding is inconsistent")
    try:
        _reconcile_generation_evidence_structural(
            last_evidence,
            usage_record=record,
            expected_exact_model=verification_request.exact_model_id,
            expected_canonical_model=verification_request.canonical_model_id,
            expected_catalog_identity_binding_sha256=(
                verification_request.catalog_identity_binding_sha256
            ),
            expected_discovery_evidence_sha256=(verification_request.discovery_evidence_sha256),
            expected_provider_name=verification_request.expected_provider_name,
        )
    except GenerationReconciliationMismatchError as mismatch:
        if mismatch.code is not error.mismatch_code:
            raise AssertionError(
                "verification rejection mismatch code differs from its evidence"
            ) from None
    except GenerationEvidenceValidationError:
        raise AssertionError(
            "verification rejection evidence failed structural validation"
        ) from None
    else:
        raise AssertionError("verification rejection evidence unexpectedly reconciled")
    actual_cost_usd = ledger_entry.actual_cost_usd
    rejection = seal_real_provider_smoke_verification_rejection_evidence(
        {
            "schema_version": "1.0",
            "ticket_id": "V3-SMOKE-001",
            "evidence_kind": ("real_openrouter_synthetic_smoke_verification_rejection"),
            "status": "REJECTED_GENERATION_VERIFICATION",
            "creditable": False,
            "fixture_path": SMOKE_FIXTURE_PATH,
            "fixture_sha256": fixture_sha256,
            "canonical_model_id": canonical_model_id,
            "approved_provider_endpoint": settings.provider_endpoint_allowlist[0],
            "verification_subject_sha256": verification_subject_sha256,
            "identity_binding_sha256": identity_binding.binding_sha256,
            "initial_generation_evidence_sha256": (
                identity_binding.generation.generation_evidence_sha256
            ),
            "verification_generation_evidence_sha256": (last_evidence.evidence_sha256),
            "mismatch_code": error.mismatch_code.value,
            "reconciliation_attempts": error.attempts,
            "reconciliation_exhausted": error.exhausted,
            "usage_record": record.model_dump(mode="json"),
            "ledger_entry_request_id": ledger_entry.request_id,
            "ledger_entry_status": ledger_entry.status.value,
            "reserved_cost_usd": _canonical_money(ledger_entry.reserved_usd),
            "actual_cost_usd": (
                None if actual_cost_usd is None else _canonical_money(actual_cost_usd)
            ),
            "accounted_cost_usd": _canonical_money(ledger_entry.accounted_cost_usd),
            "cost_reconciled": ledger_entry.status is CostEntryStatus.RECONCILED,
            "ledger_cap_usd": _canonical_money(snapshot.cap_usd),
            "ledger_spent_before_usd": _canonical_money(ledger_before.spent_usd),
            "ledger_spent_usd": _canonical_money(snapshot.spent_usd),
            "smoke_spend_delta_usd": _canonical_money(ledger_evidence.spend_delta_usd),
            "ledger_delta_reconciled": ledger_evidence.delta_reconciled,
            "ledger_prior_entries_sha256_before": (ledger_evidence.prior_entries_sha256_before),
            "ledger_prior_entries_sha256_after": (ledger_evidence.prior_entries_sha256_after),
            "ledger_prior_entries_unchanged": (ledger_evidence.prior_entries_unchanged),
            "ledger_active_reserved_usd": _canonical_money(snapshot.active_reserved_usd),
            "ledger_reservations_closed": snapshot.active_reserved_usd == 0,
            "ledger_over_cap": snapshot.over_cap,
            "ledger_has_reservation_overrun": snapshot.has_reservation_overrun,
            "ledger_remaining_usd": _canonical_money(snapshot.remaining_usd),
            "stage_cost_control_satisfied": (
                ledger_entry.accounted_cost_usd <= _SMOKE_STAGE_CAP_USD
            ),
            "privacy_profile": settings.privacy_profile,
            "require_zdr": True,
            "data_collection": "deny",
            "allow_fallbacks": False,
            "raw_prompts_stored": False,
            "raw_responses_stored": False,
            "validated_output": response.model_dump(mode="json"),
        }
    )
    rejection_output = real_provider_smoke_verification_rejection_output_path(
        success_output=settings.evidence_output,
        internal_request_id=record.request_id,
    )
    file_binding = write_real_provider_smoke_verification_rejection_evidence(
        success_output=settings.evidence_output,
        evidence=rejection,
        forbidden_values=(
            api_key,
            str(settings.secret_file),
            fixture_source,
            _SYSTEM_PROMPT,
            user_prompt,
        ),
    )
    observed = read_json_evidence(
        evidence_root=rejection_output.parent,
        relative_path=rejection_output.name,
        max_bytes=96_000,
    )
    if (
        observed.binding != file_binding
        or RealProviderSmokeVerificationRejectionEvidence.model_validate(observed.value)
        != rejection
        or settings.evidence_output.exists()
    ):
        raise AssertionError("verification rejection artifact did not round-trip safely")
    return rejection_output, rejection


def _is_rejection_transport_usage_record(
    record: UsageRecord,
    *,
    ledger_entry: CostEntry,
) -> bool:
    """Preserve strict REAL transport checks while allowing only unknown terminal cost."""

    if not _has_owned_real_usage_attestation(record):
        return False
    if is_generation_bindable_usage_record(record):
        return True
    if (
        record.reported_cost_usd is not None
        or ledger_entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
        or ledger_entry.actual_cost_usd is not None
    ):
        return False
    normalized = UsageRecord.model_validate(
        {
            **record.model_dump(mode="json"),
            "reported_cost_usd": record.accounted_cost_usd,
        }
    )
    return _is_strict_usage_record(
        normalized,
        require_real=True,
        require_certification=True,
        allow_unbound_real=True,
        require_runtime_attestation=False,
    )


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
