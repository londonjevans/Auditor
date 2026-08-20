"""Explicitly paid, synthetic-only OpenRouter transport smoke test."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Callable, Mapping
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
from mmaudit.models.provider_smoke import (
    REAL_PROVIDER_SMOKE_MARKER,
    REAL_PROVIDER_SMOKE_ROLE,
    REAL_PROVIDER_SMOKE_SCHEMA_NAME,
    build_provider_smoke_user_prompt,
    provider_smoke_system_prompt,
)
from mmaudit.models.public_lineage_authority import (
    VerifiedPublicModelLineage,
    VerifiedPublicModelLineageBindingProjection,
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
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
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.release_io import read_json_evidence
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceObservation,
    prove_privacy_source_classification,
)
from tests.real_provider_harness import (
    REAL_PROVIDER_OPT_IN,
    SMOKE_FIXTURE_PATH,
    SMOKE_MAX_OUTPUT_TOKENS,
    SMOKE_REASONING_EFFORT,
    SMOKE_STAGE_CAP_USD,
    RealProviderSmokeEvidence,
    RealProviderSmokeRejectionEvidence,
    RealProviderSmokeVerificationRejectionEvidence,
    RealProviderTestConfigurationError,
    RealProviderTestSettings,
    SyntheticProviderSmokeResponse,
    canonical_provider_attempt_request_id,
    load_pinned_synthetic_smoke_fixture,
    load_real_provider_test_settings,
    preflight_real_provider_smoke_output,
    real_provider_smoke_rejection_output_path,
    real_provider_smoke_verification_rejection_output_path,
    real_provider_smoke_verification_subject_sha256,
    real_provider_tests_enabled,
    recover_real_provider_smoke_budget_baseline,
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

_SYNTHETIC_MARKER = REAL_PROVIDER_SMOKE_MARKER
_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / SMOKE_FIXTURE_PATH
_SYSTEM_PROMPT = provider_smoke_system_prompt()


@dataclass(frozen=True)
class _SmokeLedgerEvidence:
    """One attempt-qualified terminal transition and its prior-state integrity facts."""

    entry: CostEntry
    spend_delta_usd: Decimal
    prior_entries_sha256_before: str
    prior_entries_sha256_after: str
    prior_entries_unchanged: bool
    delta_reconciled: bool


@dataclass(frozen=True)
class _SmokeLaunchPreflight:
    """Immutable identity and privacy authority proven before mutable launch state."""

    public_lineage: VerifiedPublicModelLineageBindingProjection
    source_sha256: str
    source_provenance: PrivacySourceProvenanceObservation
    effective_privacy_policy: EffectivePrivacyPolicyEvidence


@pytest.mark.asyncio
async def test_real_openrouter_exact_private_structured_smoke() -> None:
    """Make exactly one bounded paid call after every explicit gate succeeds."""

    settings = load_real_provider_test_settings(os.environ)
    assert settings.privacy_profile == "SYNTHETIC_BENCHMARK"
    fixture_source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(_ROOT)
    preflight_real_provider_smoke_output(
        output_path=settings.evidence_output,
        forbidden_paths=(settings.secret_file, settings.cost_ledger, _FIXTURE),
    )
    launch_preflight = _preflight_real_provider_smoke_launch(
        settings=settings,
        fixture_source=fixture_source,
        fixture_sha256=fixture_sha256,
        observed_at=datetime.now(UTC).replace(microsecond=0),
    )
    user_prompt = build_provider_smoke_user_prompt(
        fixture_path=SMOKE_FIXTURE_PATH,
        fixture_sha256=fixture_sha256,
        fixture_source=fixture_source,
    )
    execution = ExecutionConfig(
        request_timeout_seconds=120,
        max_model_retries=0,
        max_json_repair_attempts=0,
        budget_usd=float(SMOKE_STAGE_CAP_USD),
        max_output_tokens_per_request=SMOKE_MAX_OUTPUT_TOKENS,
        max_requests_per_agent=1,
        conservative_usd_per_million_tokens=60,
    )
    privacy = PrivacyConfig(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
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
    budget = BudgetManager(
        total_usd=float(SMOKE_STAGE_CAP_USD),
        max_output_tokens=execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=1,
        atomic_ledger=atomic_ledger,
        require_endpoint_cost_bound=True,
    )
    await recover_real_provider_smoke_budget_baseline(
        budget=budget,
        atomic_ledger=atomic_ledger,
        ledger_before=ledger_before,
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
                effective_privacy_policy=launch_preflight.effective_privacy_policy,
                source_provenance_observation=launch_preflight.source_provenance,
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
                    schema_name=REAL_PROVIDER_SMOKE_SCHEMA_NAME,
                    request_role=REAL_PROVIDER_SMOKE_ROLE,
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
                    role=REAL_PROVIDER_SMOKE_ROLE,
                    models=[settings.model_id],
                    system_prompt=_SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    response_model=SyntheticProviderSmokeResponse,
                    schema_name=REAL_PROVIDER_SMOKE_SCHEMA_NAME,
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
                        public_lineage=launch_preflight.public_lineage,
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
                            public_lineage=launch_preflight.public_lineage,
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
            assert record.routing["privacy_profile"] == "SYNTHETIC_BENCHMARK"
            assert record.routing["privacy_source_classification"] == "SYNTHETIC_COMMITTED"
            assert record.routing["effective_privacy_policy_sha256"] == (
                launch_preflight.effective_privacy_policy.evidence_sha256
            )
            assert record.routing["privacy_source_sha256"] == launch_preflight.source_sha256
            assert record.routing["privacy_source_provenance_sha256"] == (
                launch_preflight.effective_privacy_policy.source_provenance_sha256
            )
            assert record.routing["privacy_source_proof_kind"] == "DISTRIBUTION_COMMITTED_SYNTHETIC"
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
            assert smoke_spend_delta <= SMOKE_STAGE_CAP_USD

            current_public_lineage = _refresh_smoke_public_lineage(
                settings=settings,
                expected=launch_preflight.public_lineage,
            )
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
                    "public_lineage_exact_model_id": current_public_lineage.exact_model_id,
                    "public_lineage_root": current_public_lineage.root_lineage,
                    "public_lineage_bundle_sha256": current_public_lineage.bundle_sha256,
                    "public_lineage_manifest_file_sha256": (
                        current_public_lineage.manifest_file_sha256
                    ),
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


def _prove_smoke_source_provenance(
    *,
    fixture_source: str,
    fixture_sha256: str,
    observed_at: datetime,
) -> tuple[str, PrivacySourceProvenanceObservation]:
    """Prove the exact committed fixture inventory before any secret or transport access."""

    target_root = _FIXTURE.parent.parent.resolve(strict=True)
    source = _FIXTURE.resolve(strict=True)
    source_bytes = source.read_bytes()
    observed_sha256 = hashlib.sha256(source_bytes).hexdigest()
    observed_source = source_bytes.decode("utf-8", errors="replace")
    if observed_sha256 != fixture_sha256 or observed_source != fixture_source:
        raise AssertionError("provider smoke fixture changed after its pinned preflight")
    discovery = DiscoveryResult(
        root=target_root,
        files=(
            DiscoveredFile(
                absolute_path=source,
                relative_path="src/ProviderSmoke.sol",
                content=observed_source,
                size=len(source_bytes),
                lines=source_bytes.count(b"\n"),
                sha256=observed_sha256,
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    source_sha256 = canonical_sha256(
        [
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in discovery.files
        ]
    )
    observation = prove_privacy_source_classification(
        discovery,
        requested_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_sha256=source_sha256,
        now=observed_at,
    )
    return source_sha256, observation


def _require_smoke_public_lineage(
    *,
    settings: RealProviderTestSettings,
    resolve_lineage: Callable[[], VerifiedPublicModelLineage] = (
        resolve_verified_public_model_lineage
    ),
    require_lineage: Callable[
        [VerifiedPublicModelLineage, str],
        VerifiedPublicModelLineageBindingProjection,
    ] = require_verified_public_model_lineage,
) -> VerifiedPublicModelLineageBindingProjection:
    """Resolve one fresh identity-only documentary binding for the exact smoke model."""

    capability = resolve_lineage()
    projection = require_lineage(capability, settings.model_id)
    if type(projection) is not VerifiedPublicModelLineageBindingProjection:
        raise RealProviderTestConfigurationError(
            "smoke model public lineage binding has an invalid authority type"
        )
    authority_flags = (
        projection.provider_call_authorized,
        projection.source_egress_authorized,
        projection.runner_authority_authorized,
        projection.model_qualification_authorized,
        projection.production_selection_authorized,
        projection.seal_publication_authorized,
        projection.release_authorized,
        projection.benchmark_authorized,
    )
    hashes = (
        projection.bundle_sha256,
        projection.manifest_file_sha256,
    )
    root_hash = projection.root_lineage.removeprefix("sha256:")
    if (
        projection.exact_model_id != settings.model_id
        or projection.lineage_identity_authorized is not True
        or any(flag is not False for flag in authority_flags)
        or not projection.root_lineage.startswith("sha256:")
        or len(root_hash) != 64
        or any(character not in "0123456789abcdef" for character in root_hash)
        or any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in hashes
        )
    ):
        raise RealProviderTestConfigurationError(
            "smoke model lacks an exact identity-only verified public lineage binding"
        )
    return projection


def _refresh_smoke_public_lineage(
    *,
    settings: RealProviderTestSettings,
    expected: VerifiedPublicModelLineageBindingProjection,
    resolve_lineage: Callable[[], VerifiedPublicModelLineage] = (
        resolve_verified_public_model_lineage
    ),
    require_lineage: Callable[
        [VerifiedPublicModelLineage, str],
        VerifiedPublicModelLineageBindingProjection,
    ] = require_verified_public_model_lineage,
) -> VerifiedPublicModelLineageBindingProjection:
    """Re-resolve documentary identity and reject any pre-seal lineage swap."""

    observed = _require_smoke_public_lineage(
        settings=settings,
        resolve_lineage=resolve_lineage,
        require_lineage=require_lineage,
    )
    expected_values = (
        expected.exact_model_id,
        expected.root_lineage,
        expected.bundle_sha256,
        expected.manifest_file_sha256,
    )
    observed_values = (
        observed.exact_model_id,
        observed.root_lineage,
        observed.bundle_sha256,
        observed.manifest_file_sha256,
    )
    if observed_values != expected_values:
        raise RealProviderTestConfigurationError(
            "smoke public lineage binding changed before evidence sealing"
        )
    return observed


def _resolve_smoke_privacy_preflight(
    *,
    settings: RealProviderTestSettings,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    source_provenance: PrivacySourceProvenanceObservation | None,
    observed_at: datetime,
) -> EffectivePrivacyPolicyEvidence:
    """Require exact committed-source evidence before permitting smoke egress."""

    if settings.privacy_profile != "SYNTHETIC_BENCHMARK":
        raise RealProviderTestConfigurationError(
            "prospective provider smoke requires SYNTHETIC_BENCHMARK"
        )
    if source_classification is not PrivacySourceClassification.SYNTHETIC_COMMITTED:
        raise RealProviderTestConfigurationError(
            "prospective provider smoke rejects private or unclassified source"
        )
    if source_provenance is None:
        raise RealProviderTestConfigurationError(
            "prospective provider smoke requires committed-source provenance"
        )
    provenance = source_provenance.evidence
    if (
        provenance.source_classification != "SYNTHETIC_COMMITTED"
        or provenance.source_sha256 != source_sha256
        or provenance.proof_kind != "DISTRIBUTION_COMMITTED_SYNTHETIC"
    ):
        raise RealProviderTestConfigurationError(
            "prospective provider smoke source provenance is not exact and committed"
        )
    return resolve_effective_privacy_policy(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        require_zdr=True,
        consent_observation=None,
        source_sha256=source_sha256,
        source_classification=source_classification,
        source_provenance_observation=source_provenance,
        configured_model_ids=(settings.model_id,),
        configured_provider_endpoints=settings.provider_endpoint_allowlist,
        requested_budget_usd=SMOKE_STAGE_CAP_USD,
        now=observed_at,
    )


def _preflight_real_provider_smoke_launch(
    *,
    settings: RealProviderTestSettings,
    fixture_source: str,
    fixture_sha256: str,
    observed_at: datetime,
    resolve_lineage: Callable[[], VerifiedPublicModelLineage] = (
        resolve_verified_public_model_lineage
    ),
    require_lineage: Callable[
        [VerifiedPublicModelLineage, str],
        VerifiedPublicModelLineageBindingProjection,
    ] = require_verified_public_model_lineage,
) -> _SmokeLaunchPreflight:
    """Build all identity and source authority before ledger, secret, or client state."""

    if settings.privacy_profile != "SYNTHETIC_BENCHMARK":
        raise RealProviderTestConfigurationError(
            "prospective provider smoke requires SYNTHETIC_BENCHMARK"
        )
    public_lineage = _require_smoke_public_lineage(
        settings=settings,
        resolve_lineage=resolve_lineage,
        require_lineage=require_lineage,
    )
    source_sha256, source_provenance = _prove_smoke_source_provenance(
        fixture_source=fixture_source,
        fixture_sha256=fixture_sha256,
        observed_at=observed_at,
    )
    effective_privacy_policy = _resolve_smoke_privacy_preflight(
        settings=settings,
        source_sha256=source_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance=source_provenance,
        observed_at=observed_at,
    )
    return _SmokeLaunchPreflight(
        public_lineage=public_lineage,
        source_sha256=source_sha256,
        source_provenance=source_provenance,
        effective_privacy_policy=effective_privacy_policy,
    )


def _terminal_smoke_ledger_evidence(
    *,
    snapshot: CostLedgerSnapshot,
    ledger_before: CostLedgerSnapshot,
    record: UsageRecord,
) -> _SmokeLedgerEvidence:
    attempt_request_id = canonical_provider_attempt_request_id(record.request_id, attempt=1)
    if any(entry.request_id == attempt_request_id for entry in ledger_before.entries):
        raise AssertionError("provider smoke attempt already existed before the request")
    matching_entries = [
        entry for entry in snapshot.entries if entry.request_id == attempt_request_id
    ]
    if len(matching_entries) != 1:
        raise AssertionError("provider smoke ledger lacks one exact first-attempt entry")
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
    public_lineage: VerifiedPublicModelLineageBindingProjection,
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
    resolve_lineage: Callable[[], VerifiedPublicModelLineage] = (
        resolve_verified_public_model_lineage
    ),
    require_lineage: Callable[
        [VerifiedPublicModelLineage, str],
        VerifiedPublicModelLineageBindingProjection,
    ] = require_verified_public_model_lineage,
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
    current_public_lineage = _refresh_smoke_public_lineage(
        settings=settings,
        expected=public_lineage,
        resolve_lineage=resolve_lineage,
        require_lineage=require_lineage,
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
            "public_lineage_exact_model_id": current_public_lineage.exact_model_id,
            "public_lineage_root": current_public_lineage.root_lineage,
            "public_lineage_bundle_sha256": current_public_lineage.bundle_sha256,
            "public_lineage_manifest_file_sha256": (current_public_lineage.manifest_file_sha256),
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
                ledger_entry.accounted_cost_usd <= SMOKE_STAGE_CAP_USD
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
    public_lineage: VerifiedPublicModelLineageBindingProjection,
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
    resolve_lineage: Callable[[], VerifiedPublicModelLineage] = (
        resolve_verified_public_model_lineage
    ),
    require_lineage: Callable[
        [VerifiedPublicModelLineage, str],
        VerifiedPublicModelLineageBindingProjection,
    ] = require_verified_public_model_lineage,
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
    current_public_lineage = _refresh_smoke_public_lineage(
        settings=settings,
        expected=public_lineage,
        resolve_lineage=resolve_lineage,
        require_lineage=require_lineage,
    )
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
            "public_lineage_exact_model_id": current_public_lineage.exact_model_id,
            "public_lineage_root": current_public_lineage.root_lineage,
            "public_lineage_bundle_sha256": current_public_lineage.bundle_sha256,
            "public_lineage_manifest_file_sha256": (current_public_lineage.manifest_file_sha256),
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
                ledger_entry.accounted_cost_usd <= SMOKE_STAGE_CAP_USD
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
            "reported_cost_usd_exact": record.accounted_cost_usd_exact,
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
