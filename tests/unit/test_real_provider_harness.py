from __future__ import annotations

import inspect
from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from mmaudit.models.generation_evidence import (
    GenerationReconciliationMismatchCode,
    GenerationVerificationRequest,
    validate_openrouter_generation_payload,
)
from mmaudit.models.identity import (
    OpenRouterIdentityBindingResult,
    OpenRouterIdentityDiagnosticCode,
    seal_unbound_openrouter_identity,
)
from mmaudit.models.openrouter import OpenRouterGenerationReconciliationError
from mmaudit.models.public_lineage_authority import (
    VerifiedPublicModelLineage,
    VerifiedPublicModelLineageBindingProjection,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_generation_bindable_usage_record
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacySourceClassification
from mmaudit.release_io import read_json_evidence
from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceObservation
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)
from tests.integration.test_real_openrouter_provider import (
    _preflight_real_provider_smoke_launch,
    _refresh_smoke_public_lineage,
    _resolve_smoke_privacy_preflight,
    _terminal_smoke_ledger_evidence,
    _write_generation_verification_smoke_rejection,
    _write_unbound_smoke_rejection,
)
from tests.integration.test_real_openrouter_provider import (
    test_real_openrouter_exact_private_structured_smoke as _real_provider_smoke_test,
)
from tests.real_provider_harness import (
    REAL_PROVIDER_COST_CAP,
    REAL_PROVIDER_COST_LEDGER,
    REAL_PROVIDER_ENDPOINT_ALLOWLIST,
    REAL_PROVIDER_EVIDENCE_OUTPUT,
    REAL_PROVIDER_MODEL,
    REAL_PROVIDER_MODEL_ALLOWLIST,
    REAL_PROVIDER_OPT_IN,
    REAL_PROVIDER_PRIVACY_PROFILE,
    REAL_PROVIDER_SECRET_FILE,
    SMOKE_FIXTURE_PATH,
    SMOKE_FIXTURE_SHA256,
    SMOKE_MAX_OUTPUT_TOKENS,
    SMOKE_REASONING_EFFORT,
    SMOKE_STAGE_CAP_USD,
    RealProviderSmokeEvidence,
    RealProviderSmokeRejectionEvidence,
    RealProviderSmokeVerificationRejectionEvidence,
    RealProviderTestConfigurationError,
    RealProviderTestSettings,
    SyntheticProviderSmokeResponse,
    _contains_forbidden_authorization_surface,
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


def test_authorization_scan_distinguishes_credentials_from_privacy_evidence() -> None:
    assert _contains_forbidden_authorization_surface('{"Authorization":"synthetic"}')
    assert _contains_forbidden_authorization_surface('{"value":"Bearer synthetic"}')
    assert not _contains_forbidden_authorization_surface(
        '{"privacy_authorization":"STRICT_ZDR_ENFORCED"}'
    )


def test_provider_attempt_request_id_matches_openrouter_ledger_convention() -> None:
    logical_request_id = "request-smoke-1"

    assert (
        canonical_provider_attempt_request_id(logical_request_id, attempt=1) == logical_request_id
    )
    assert (
        canonical_provider_attempt_request_id(logical_request_id, attempt=2)
        == "request-smoke-1:attempt:2"
    )
    with pytest.raises(ValueError, match="positive integer"):
        canonical_provider_attempt_request_id(logical_request_id, attempt=0)


def _valid_environment() -> dict[str, str]:
    return {
        REAL_PROVIDER_OPT_IN: "1",
        REAL_PROVIDER_SECRET_FILE: "/operator/control/openrouter.env",
        REAL_PROVIDER_COST_CAP: "250.00",
        REAL_PROVIDER_COST_LEDGER: "/operator/control/openrouter-cost-ledger.json",
        REAL_PROVIDER_MODEL: "acme/secure-reasoner-v1",
        REAL_PROVIDER_MODEL_ALLOWLIST: (
            "acme/secure-reasoner-v1,second-author/security-reviewer-v2"
        ),
        REAL_PROVIDER_ENDPOINT_ALLOWLIST: "approved-provider",
        REAL_PROVIDER_PRIVACY_PROFILE: "SYNTHETIC_BENCHMARK",
        REAL_PROVIDER_EVIDENCE_OUTPUT: "/operator/control/provider-smoke.json",
    }


class _OptInOnlyEnvironment(Mapping[str, str]):
    """Raise if the guard examines any prerequisite before the opt-in."""

    def __getitem__(self, key: str) -> str:
        if key == REAL_PROVIDER_OPT_IN:
            return "0"
        raise AssertionError("non-opt-in environment value was accessed")

    def __iter__(self) -> Iterator[str]:
        return iter((REAL_PROVIDER_OPT_IN,))

    def __len__(self) -> int:
        return 1


@pytest.mark.parametrize("value", [None, "", "0", "true", "TRUE", " 1", "1 "])
def test_real_provider_opt_in_requires_exact_sentinel(value: str | None) -> None:
    environment = {} if value is None else {REAL_PROVIDER_OPT_IN: value}
    assert not real_provider_tests_enabled(environment)


def test_disabled_gate_stops_before_other_environment_access() -> None:
    with pytest.raises(RealProviderTestConfigurationError, match="require"):
        load_real_provider_test_settings(_OptInOnlyEnvironment())


@pytest.mark.parametrize(
    "cost",
    ["", "0", "-1", "nan", "1e2", "1.25", "249.99", "250.01", "251"],
)
def test_real_provider_cost_cap_requires_existing_250_dollar_ledger(cost: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_COST_CAP] = cost
    with pytest.raises(RealProviderTestConfigurationError, match="COST_CAP"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/random",
        "acme/example-model",
        "acme/reasoner:latest",
        "missing-author",
    ],
)
def test_real_provider_model_must_be_exact_and_non_placeholder(model: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_MODEL] = model
    environment[REAL_PROVIDER_MODEL_ALLOWLIST] = model
    with pytest.raises(RealProviderTestConfigurationError, match="MODEL"):
        load_real_provider_test_settings(environment)


def test_selected_real_provider_model_must_be_allowlisted() -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_MODEL] = "third-author/qualified-security-model"
    with pytest.raises(RealProviderTestConfigurationError, match="appear"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize("path", ["", "relative-ledger.json"])
def test_real_provider_cost_ledger_must_be_explicit_and_absolute(path: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_COST_LEDGER] = path
    with pytest.raises(RealProviderTestConfigurationError, match="COST_LEDGER"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize(
    "providers",
    ["", "Approved Provider,", "fake/provider", "One,One", "Provider-A,Provider-B"],
)
def test_real_provider_endpoint_allowlist_is_nonempty_exact_and_unique(
    providers: str,
) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_ENDPOINT_ALLOWLIST] = providers
    with pytest.raises(RealProviderTestConfigurationError, match="ENDPOINT_ALLOWLIST"):
        load_real_provider_test_settings(environment)


def test_real_provider_gate_returns_only_non_secret_settings() -> None:
    settings = load_real_provider_test_settings(_valid_environment())
    assert settings.cost_cap_usd.as_tuple().exponent == -2
    assert settings.cost_cap_usd == Decimal("250.00")
    assert settings.cost_ledger == Path("/operator/control/openrouter-cost-ledger.json")
    assert settings.model_id == "acme/secure-reasoner-v1"
    assert settings.model_id in settings.model_allowlist
    assert settings.provider_endpoint_allowlist == ("approved-provider",)
    assert settings.privacy_profile == "SYNTHETIC_BENCHMARK"
    assert settings.evidence_output == Path("/operator/control/provider-smoke.json")
    assert "API_KEY" not in repr(settings)


@pytest.mark.parametrize("path", ["", "relative-smoke.json"])
def test_real_provider_evidence_output_is_explicit_and_absolute(path: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_EVIDENCE_OUTPUT] = path
    with pytest.raises(RealProviderTestConfigurationError, match="EVIDENCE_OUTPUT"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize("profile", ["", "strict_zdr", "STRICT_ZDR"])
def test_real_provider_privacy_profile_requires_synthetic_benchmark(profile: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_PRIVACY_PROFILE] = profile
    with pytest.raises(RealProviderTestConfigurationError, match="PRIVACY_PROFILE"):
        load_real_provider_test_settings(environment)


def _verified_public_lineage_projection(
    *,
    exact_model_id: str = "acme/secure-reasoner-v1",
    root_lineage: str = f"sha256:{'1' * 64}",
    bundle_sha256: str = "2" * 64,
    manifest_file_sha256: str = "3" * 64,
) -> VerifiedPublicModelLineageBindingProjection:
    return VerifiedPublicModelLineageBindingProjection(
        exact_model_id=exact_model_id,
        documentary_model_id="Acme Secure Reasoner v1",
        root_lineage=root_lineage,
        decision_sha256="4" * 64,
        bundle_sha256=bundle_sha256,
        manifest_file_sha256=manifest_file_sha256,
        lineage_identity_authorized=True,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_authority_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        benchmark_authorized=False,
    )


def _synthetic_lineage_capability() -> VerifiedPublicModelLineage:
    return cast(VerifiedPublicModelLineage, object())


def _require_synthetic_public_lineage(
    _capability: VerifiedPublicModelLineage,
    exact_model_id: str,
) -> VerifiedPublicModelLineageBindingProjection:
    return _verified_public_lineage_projection(exact_model_id=exact_model_id)


def test_real_smoke_completes_authority_preflight_before_mutable_launch_state() -> None:
    source = inspect.getsource(_real_provider_smoke_test)
    preflight = source.index("launch_preflight = _preflight_real_provider_smoke_launch")

    assert preflight < source.index("AtomicCostLedger.open_existing")
    assert preflight < source.index("load_operator_secrets")
    assert preflight < source.index("OpenRouterClient")
    assert "total_usd=float(SMOKE_STAGE_CAP_USD)" in source
    assert Decimal("5.00") == SMOKE_STAGE_CAP_USD


@pytest.mark.asyncio
async def test_real_smoke_recovers_nonempty_reconciled_ledger_before_new_reservation(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal("250"),
    )
    prior_reservation = ledger.reserve("prior:attempt:1", Decimal("0.002"))
    ledger.reconcile(prior_reservation, Decimal("0.00113946"))
    uncertain_reservation = ledger.reserve("prior:attempt:2", Decimal("0.002"))
    ledger.reconcile(uncertain_reservation, None)
    ledger_before = ledger.snapshot()
    budget = BudgetManager(
        total_usd=5,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=1,
        atomic_ledger=ledger,
    )

    assert budget.recovery_required
    await recover_real_provider_smoke_budget_baseline(
        budget=budget,
        atomic_ledger=ledger,
        ledger_before=ledger_before,
    )

    assert not budget.recovery_required
    assert budget.spent_usd_exact == Decimal("0.00313946")
    assert ledger.snapshot() == ledger_before
    smoke_reservation = await budget.reserve(
        canonical_provider_attempt_request_id("smoke", attempt=1),
        "real_provider_smoke",
        "synthetic prompt",
    )
    reserved_snapshot = ledger.snapshot()
    assert reserved_snapshot.entries[: len(ledger_before.entries)] == ledger_before.entries
    assert len(reserved_snapshot.entries) == len(ledger_before.entries) + 1
    assert reserved_snapshot.entries[-1].status is CostEntryStatus.RESERVED
    await budget.release(smoke_reservation)


@pytest.mark.asyncio
async def test_real_smoke_budget_recovery_rejects_active_ledger_without_mutation(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal("250"),
    )
    ledger.reserve("prior:attempt:1", Decimal("0.002"))
    ledger_before = ledger.snapshot()
    budget = BudgetManager(
        total_usd=5,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=1,
        atomic_ledger=ledger,
    )

    with pytest.raises(RealProviderTestConfigurationError, match="terminally accounted"):
        await recover_real_provider_smoke_budget_baseline(
            budget=budget,
            atomic_ledger=ledger,
            ledger_before=ledger_before,
        )

    assert budget.recovery_required
    assert ledger.snapshot() == ledger_before


def test_real_smoke_invalid_profile_fails_before_lineage_or_mutable_state() -> None:
    settings = replace(
        load_real_provider_test_settings(_valid_environment()),
        privacy_profile=cast(Literal["SYNTHETIC_BENCHMARK"], "STRICT_ZDR"),
    )
    lineage_resolved = False

    def resolve_lineage() -> VerifiedPublicModelLineage:
        nonlocal lineage_resolved
        lineage_resolved = True
        return _synthetic_lineage_capability()

    with pytest.raises(RealProviderTestConfigurationError, match="SYNTHETIC_BENCHMARK"):
        _preflight_real_provider_smoke_launch(
            settings=settings,
            fixture_source="synthetic fixture",
            fixture_sha256=SMOKE_FIXTURE_SHA256,
            observed_at=datetime(2026, 8, 18, tzinfo=UTC),
            resolve_lineage=resolve_lineage,
        )

    assert not lineage_resolved


def test_real_smoke_private_source_fails_before_policy_or_mutable_state() -> None:
    settings = load_real_provider_test_settings(_valid_environment())

    with pytest.raises(RealProviderTestConfigurationError, match="private"):
        _resolve_smoke_privacy_preflight(
            settings=settings,
            source_sha256="a" * 64,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            source_provenance=cast(PrivacySourceProvenanceObservation, object()),
            observed_at=datetime(2026, 8, 18, tzinfo=UTC),
        )


def test_real_smoke_missing_provenance_fails_before_policy_or_mutable_state() -> None:
    settings = load_real_provider_test_settings(_valid_environment())

    with pytest.raises(RealProviderTestConfigurationError, match="provenance"):
        _resolve_smoke_privacy_preflight(
            settings=settings,
            source_sha256="a" * 64,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_provenance=None,
            observed_at=datetime(2026, 8, 18, tzinfo=UTC),
        )


def test_real_smoke_unconfirmed_lineage_fails_before_fixture_or_mutable_state() -> None:
    settings = load_real_provider_test_settings(_valid_environment())
    required_model_ids: list[str] = []

    def require_unconfirmed(
        _capability: VerifiedPublicModelLineage,
        exact_model_id: str,
    ) -> VerifiedPublicModelLineageBindingProjection:
        required_model_ids.append(exact_model_id)
        raise RealProviderTestConfigurationError("public lineage is unconfirmed")

    with pytest.raises(RealProviderTestConfigurationError, match="unconfirmed"):
        _preflight_real_provider_smoke_launch(
            settings=settings,
            fixture_source="must not be inspected",
            fixture_sha256=SMOKE_FIXTURE_SHA256,
            observed_at=datetime(2026, 8, 18, tzinfo=UTC),
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=require_unconfirmed,
        )

    assert required_model_ids == [settings.model_id]


def test_real_smoke_swapped_lineage_fails_before_fixture_or_mutable_state() -> None:
    settings = load_real_provider_test_settings(_valid_environment())

    def require_swapped(
        _capability: VerifiedPublicModelLineage,
        _exact_model_id: str,
    ) -> VerifiedPublicModelLineageBindingProjection:
        return _verified_public_lineage_projection(exact_model_id="other/model-v1")

    with pytest.raises(RealProviderTestConfigurationError, match="exact identity-only"):
        _preflight_real_provider_smoke_launch(
            settings=settings,
            fixture_source="must not be inspected",
            fixture_sha256=SMOKE_FIXTURE_SHA256,
            observed_at=datetime(2026, 8, 18, tzinfo=UTC),
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=require_swapped,
        )


def test_real_smoke_rejects_lineage_swap_on_fresh_preseal_resolution() -> None:
    settings = load_real_provider_test_settings(_valid_environment())
    expected = _verified_public_lineage_projection()

    def require_swapped_root(
        _capability: VerifiedPublicModelLineage,
        _exact_model_id: str,
    ) -> VerifiedPublicModelLineageBindingProjection:
        return _verified_public_lineage_projection(root_lineage=f"sha256:{'f' * 64}")

    with pytest.raises(RealProviderTestConfigurationError, match="changed before"):
        _refresh_smoke_public_lineage(
            settings=settings,
            expected=expected,
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=require_swapped_root,
        )


def test_committed_real_provider_fixture_matches_its_pinned_hash() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(repository_root)

    assert fixture_sha256 == SMOKE_FIXTURE_SHA256
    assert SMOKE_FIXTURE_PATH.endswith("ProviderSmoke.sol")
    assert "contract ProviderSmoke" in source
    assert len(source.encode()) <= 20_000


def test_smoke_reasoning_off_preflight_requires_optional_exact_model_control() -> None:
    payload = {
        "data": [
            {
                "id": "acme/secure-reasoner-v1",
                "supported_parameters": ["max_tokens", "reasoning", "response_format"],
                "reasoning": {
                    "mandatory": False,
                    "default_enabled": True,
                },
            }
        ]
    }

    capabilities = validate_smoke_reasoning_off_preflight(
        models_payload=payload,
        exact_model_id="acme/secure-reasoner-v1",
    )

    assert capabilities.mandatory is False
    assert capabilities.default_enabled is True
    assert capabilities.supports_max_tokens is None
    assert SMOKE_REASONING_EFFORT == "none"
    assert SMOKE_MAX_OUTPUT_TOKENS == 1_024


@pytest.mark.parametrize(
    "reasoning",
    [
        None,
        {"mandatory": True, "default_enabled": True},
        {"mandatory": None, "default_enabled": True},
        {
            "mandatory": False,
            "default_enabled": True,
            "supports_max_tokens": "yes",
        },
    ],
)
def test_smoke_reasoning_off_preflight_rejects_unproven_control(
    reasoning: object,
) -> None:
    with pytest.raises(RealProviderTestConfigurationError, match="reasoning"):
        validate_smoke_reasoning_off_preflight(
            models_payload={
                "data": [
                    {
                        "id": "acme/secure-reasoner-v1",
                        "supported_parameters": ["reasoning"],
                        "reasoning": reasoning,
                    }
                ]
            },
            exact_model_id="acme/secure-reasoner-v1",
        )


def test_smoke_reasoning_off_preflight_accepts_optional_controls_with_unknown_defaults() -> None:
    capabilities = validate_smoke_reasoning_off_preflight(
        models_payload={
            "data": [
                {
                    "id": "acme/secure-reasoner-v1",
                    "supported_parameters": ["reasoning"],
                    "reasoning": {
                        "mandatory": False,
                        "default_enabled": None,
                        "supports_max_tokens": None,
                    },
                }
            ]
        },
        exact_model_id="acme/secure-reasoner-v1",
    )

    assert capabilities.mandatory is False
    assert capabilities.default_enabled is None
    assert capabilities.supports_max_tokens is None


def test_real_provider_smoke_output_preflight_rejects_collisions_and_existing_files(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "operator-secret.json"
    ledger = tmp_path / "ledger.json"
    for protected in (secret_file, ledger):
        with pytest.raises(RealProviderTestConfigurationError, match="collides"):
            preflight_real_provider_smoke_output(
                output_path=protected,
                forbidden_paths=(secret_file, ledger),
            )

    existing = tmp_path / "provider-smoke.json"
    existing.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RealProviderTestConfigurationError, match="fresh"):
        preflight_real_provider_smoke_output(
            output_path=existing,
            forbidden_paths=(),
        )


def test_real_provider_smoke_output_preflight_rejects_linked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(RealProviderTestConfigurationError, match="unsafe parent"):
        preflight_real_provider_smoke_output(
            output_path=linked_parent / "provider-smoke.json",
            forbidden_paths=(),
        )


def test_real_provider_smoke_output_preflight_accepts_only_fresh_json(
    tmp_path: Path,
) -> None:
    output = tmp_path / "provider-smoke.json"
    preflight_real_provider_smoke_output(
        output_path=output,
        forbidden_paths=(),
    )
    assert not output.exists()

    with pytest.raises(RealProviderTestConfigurationError, match="JSON artifact"):
        preflight_real_provider_smoke_output(
            output_path=tmp_path / "provider-smoke.txt",
            forbidden_paths=(),
        )


def _valid_smoke_evidence_payload() -> dict[str, object]:
    started_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    ended_at = datetime(2026, 7, 28, 12, 0, 1, tzinfo=UTC)
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "ticket_id": "V3-SMOKE-001",
        "evidence_kind": "real_openrouter_synthetic_smoke",
        "status": "SUCCESS",
        "execution_evidence": "real",
        "fixture_path": "tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol",
        "fixture_sha256": SMOKE_FIXTURE_SHA256,
        "internal_request_id": "request-smoke-1",
        "openrouter_generation_id": "generation-smoke-1",
        "requested_model_id": "qwen/qwen3.6-35b-a3b",
        "canonical_model_id": "qwen/qwen3.6-35b-a3b-20260415",
        "public_lineage_exact_model_id": "qwen/qwen3.6-35b-a3b",
        "public_lineage_root": f"sha256:{'1' * 64}",
        "public_lineage_bundle_sha256": "2" * 64,
        "public_lineage_manifest_file_sha256": "3" * 64,
        "returned_model_id": "qwen/qwen3.6-35b-a3b",
        "generation_model_id": "qwen/qwen3.6-35b-a3b-20260415",
        "approved_provider_endpoint": "akashml/fp8",
        "actual_provider_endpoint": "akashml/fp8",
        "actual_provider_name": "AkashML",
        "provider_policy_sha256": "2" * 64,
        "endpoint_snapshot_sha256": "3" * 64,
        "model_metadata_snapshot_sha256": "4" * 64,
        "discovery_provenance_sha256": "5" * 64,
        "discovery_evidence_sha256": "6" * 64,
        "identity_snapshot_sha256": "7" * 64,
        "generation_evidence_sha256": "8" * 64,
        "prompt_sha256": "9" * 64,
        "user_prompt_sha256": "a" * 64,
        "schema_sha256": "b" * 64,
        "request_body_sha256": "c" * 64,
        "response_sha256": "d" * 64,
        "validated_response_sha256": "e" * 64,
        "started_at": started_at,
        "ended_at": ended_at,
        "latency_ms": 1000,
        "finish_reason": "stop",
        "prompt_tokens": 30,
        "completion_tokens": 10,
        "reasoning_tokens": 0,
        "cached_tokens": 0,
        "total_tokens": 40,
        "requested_max_output_tokens": SMOKE_MAX_OUTPUT_TOKENS,
        "requested_reasoning_effort": SMOKE_REASONING_EFFORT,
        "requested_reasoning_excluded": True,
        "model_reasoning_mandatory": False,
        "model_reasoning_default_enabled": True,
        "model_reasoning_supports_max_tokens": False,
        "actual_cost_usd": "0.0002",
        "accounted_cost_usd": "0.0002",
        "ledger_cap_usd": "250",
        "ledger_spent_before_usd": "0.00118674",
        "ledger_spent_usd": "0.00138674",
        "smoke_spend_delta_usd": "0.0002",
        "ledger_active_reserved_usd": "0",
        "ledger_remaining_usd": "249.99861326",
        "validation_status": "valid",
        "identity_strength": (ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND.value),
        "privacy_profile": "SYNTHETIC_BENCHMARK",
        "require_zdr": True,
        "data_collection": "deny",
        "allow_fallbacks": False,
        "fallback_used": False,
        "substitution_detected": False,
        "raw_prompts_stored": False,
        "raw_responses_stored": False,
        "validated_output": {
            "status": "OK",
            "marker": "mmaudit-synthetic-provider-smoke-v1",
        },
    }
    payload["verification_subject_sha256"] = real_provider_smoke_verification_subject_sha256(
        fixture_sha256=SMOKE_FIXTURE_SHA256,
        internal_request_id="request-smoke-1",
        openrouter_generation_id="generation-smoke-1",
        requested_model_id="qwen/qwen3.6-35b-a3b",
        canonical_model_id="qwen/qwen3.6-35b-a3b-20260415",
        validated_response_sha256="e" * 64,
        prompt_sha256="9" * 64,
        schema_sha256="b" * 64,
        endpoint_snapshot_sha256="3" * 64,
        discovery_evidence_sha256="6" * 64,
    )
    return payload


def _valid_smoke_rejection_payload() -> dict[str, object]:
    success = _valid_smoke_evidence_payload()
    generation_observation = validate_openrouter_generation_payload(
        {
            "data": {
                "id": success["openrouter_generation_id"],
                "model": success["canonical_model_id"],
                "provider_name": "Different Provider",
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "tokens_prompt": success["prompt_tokens"],
                "tokens_completion": success["completion_tokens"],
                "native_tokens_prompt": success["prompt_tokens"],
                "native_tokens_completion": success["completion_tokens"],
                "native_tokens_reasoning": success["reasoning_tokens"],
                "native_tokens_cached": success["cached_tokens"],
                "total_cost": float(str(success["actual_cost_usd"])),
                "usage": float(str(success["actual_cost_usd"])),
                "cancelled": False,
                "created_at": success["started_at"],
                "prompt": "raw-provider-prompt-canary",
                "completion": "raw-provider-completion-canary",
            }
        },
        requested_generation_id=str(success["openrouter_generation_id"]),
        retrieved_at=datetime(2026, 7, 28, 12, 0, 2, tzinfo=UTC),
        execution_evidence=ExecutionEvidenceKind.REAL,
    )
    return {
        "schema_version": "1.0",
        "ticket_id": "V3-SMOKE-001",
        "evidence_kind": "real_openrouter_synthetic_smoke_rejection",
        "status": "REJECTED_IDENTITY_UNBOUND",
        "creditable": False,
        "execution_evidence": "real",
        "fixture_path": success["fixture_path"],
        "fixture_sha256": success["fixture_sha256"],
        "internal_request_id": success["internal_request_id"],
        "openrouter_generation_id": success["openrouter_generation_id"],
        "requested_model_id": success["requested_model_id"],
        "canonical_model_id": success["canonical_model_id"],
        "public_lineage_exact_model_id": success["public_lineage_exact_model_id"],
        "public_lineage_root": success["public_lineage_root"],
        "public_lineage_bundle_sha256": success["public_lineage_bundle_sha256"],
        "public_lineage_manifest_file_sha256": success["public_lineage_manifest_file_sha256"],
        "returned_model_id": success["returned_model_id"],
        "selected_model_id": success["canonical_model_id"],
        "approved_provider_endpoint": success["approved_provider_endpoint"],
        "actual_provider_endpoint": success["actual_provider_endpoint"],
        "selected_provider_identity": "akashml/fp8",
        "selected_provider_name": success["actual_provider_name"],
        "response_provider_identity": "akashml/fp8",
        "model_identity_control_satisfied": True,
        "endpoint_control_satisfied": True,
        "provider_policy_sha256": success["provider_policy_sha256"],
        "endpoint_snapshot_sha256": success["endpoint_snapshot_sha256"],
        "model_metadata_snapshot_sha256": success["model_metadata_snapshot_sha256"],
        "discovery_provenance_sha256": success["discovery_provenance_sha256"],
        "discovery_evidence_sha256": success["discovery_evidence_sha256"],
        "identity_snapshot_sha256": success["identity_snapshot_sha256"],
        "identity_binding_sha256": "f" * 64,
        "identity_binding_status": "generation_metadata_unbound",
        "identity_diagnostic_codes": [
            OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH.value
        ],
        "generation_observation": generation_observation.model_dump(mode="json"),
        "prompt_sha256": success["prompt_sha256"],
        "user_prompt_sha256": success["user_prompt_sha256"],
        "schema_sha256": success["schema_sha256"],
        "request_body_sha256": success["request_body_sha256"],
        "response_sha256": success["response_sha256"],
        "validated_response_sha256": success["validated_response_sha256"],
        "started_at": success["started_at"],
        "ended_at": success["ended_at"],
        "latency_ms": success["latency_ms"],
        "finish_reason": success["finish_reason"],
        "prompt_tokens": success["prompt_tokens"],
        "completion_tokens": success["completion_tokens"],
        "reasoning_tokens": success["reasoning_tokens"],
        "cached_tokens": success["cached_tokens"],
        "total_tokens": success["total_tokens"],
        "requested_max_output_tokens": success["requested_max_output_tokens"],
        "requested_reasoning_effort": success["requested_reasoning_effort"],
        "requested_reasoning_excluded": success["requested_reasoning_excluded"],
        "reasoning_control_satisfied": True,
        "output_control_satisfied": True,
        "ledger_entry_request_id": success["internal_request_id"],
        "ledger_entry_status": CostEntryStatus.RECONCILED.value,
        "reserved_cost_usd": "0.001",
        "provider_reported_cost_usd": success["actual_cost_usd"],
        "actual_cost_usd": success["actual_cost_usd"],
        "accounted_cost_usd": success["accounted_cost_usd"],
        "cost_reconciled": True,
        "ledger_cap_usd": success["ledger_cap_usd"],
        "ledger_spent_before_usd": success["ledger_spent_before_usd"],
        "ledger_spent_usd": success["ledger_spent_usd"],
        "smoke_spend_delta_usd": success["smoke_spend_delta_usd"],
        "ledger_delta_reconciled": True,
        "ledger_prior_entries_sha256_before": "0" * 64,
        "ledger_prior_entries_sha256_after": "0" * 64,
        "ledger_prior_entries_unchanged": True,
        "ledger_active_reserved_usd": success["ledger_active_reserved_usd"],
        "ledger_reservations_closed": True,
        "ledger_over_cap": False,
        "ledger_has_reservation_overrun": False,
        "ledger_remaining_usd": success["ledger_remaining_usd"],
        "stage_cost_control_satisfied": True,
        "validation_status": success["validation_status"],
        "identity_strength": ModelIdentityStrength.UNBOUND.value,
        "privacy_profile": success["privacy_profile"],
        "require_zdr": success["require_zdr"],
        "data_collection": success["data_collection"],
        "allow_fallbacks": success["allow_fallbacks"],
        "fallback_used": success["fallback_used"],
        "substitution_detected": success["substitution_detected"],
        "raw_prompts_stored": success["raw_prompts_stored"],
        "raw_responses_stored": success["raw_responses_stored"],
        "validated_output": success["validated_output"],
    }


def _synthetic_bound_real_smoke_record() -> UsageRecord:
    success = _valid_smoke_evidence_payload()
    requested_model = str(success["requested_model_id"])
    canonical_model = str(success["canonical_model_id"])
    endpoint = str(success["approved_provider_endpoint"])
    provider_name = str(success["actual_provider_name"])
    started_at = datetime.fromisoformat(str(success["started_at"]))
    ended_at = datetime.fromisoformat(str(success["ended_at"]))
    routing = {
        "generation_id": success["openrouter_generation_id"],
        "provider": provider_name,
        "selected_model": canonical_model,
        "canonical_model": canonical_model,
        "selected_provider_endpoint": endpoint,
        "selected_provider_identity": endpoint,
        "selected_provider_name": provider_name,
        "response_provider_identity": endpoint,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_attempts_observed": True,
        "router_metadata_sha256": "1" * 64,
        "router_pipeline": [],
        "finish_reason": "stop",
        "native_finish_reason": "stop",
        "reasoning_tokens": success["reasoning_tokens"],
        "cached_tokens": success["cached_tokens"],
        "schema_sha256": success["schema_sha256"],
        "provider_policy_sha256": success["provider_policy_sha256"],
        "endpoint_snapshot_sha256": success["endpoint_snapshot_sha256"],
        "endpoint_pricing_sha256": "0" * 64,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": canonical_model,
                "id": requested_model,
            }
        ),
        "catalog_snapshot_sha256": "2" * 64,
        "model_metadata_snapshot_sha256": success["model_metadata_snapshot_sha256"],
        "discovery_provenance_sha256": success["discovery_provenance_sha256"],
        "discovery_evidence_sha256": success["discovery_evidence_sha256"],
        "configured_provider_only": [endpoint],
        "configured_provider_order": [],
        "provider_fallbacks_allowed": False,
        "provider_fallback_used": False,
        "host_model_fallback_used": False,
        "certification_request": True,
        "zdr_requested": True,
        "data_collection": "deny",
        "request_started_at": started_at.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": success["latency_ms"],
        "validation_status": "valid",
        "repair_used": False,
        "repair_request": False,
    }
    provisional = UsageRecord(
        request_id=str(success["internal_request_id"]),
        role="real_provider_smoke",
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=requested_model,
        returned_model=str(success["returned_model_id"]),
        actual_model=canonical_model,
        provider=provider_name,
        model_family="qwen",
        timestamp=started_at,
        prompt_tokens=int(str(success["prompt_tokens"])),
        completion_tokens=int(str(success["completion_tokens"])),
        total_tokens=int(str(success["total_tokens"])),
        reported_cost_usd=float(str(success["actual_cost_usd"])),
        accounted_cost_usd=float(str(success["accounted_cost_usd"])),
        routing=routing,
        prompt_sha256=str(success["prompt_sha256"]),
        user_prompt_sha256=str(success["user_prompt_sha256"]),
        response_sha256=str(success["response_sha256"]),
        validated_response_sha256=str(success["validated_response_sha256"]),
        request_body_sha256=str(success["request_body_sha256"]),
        schema_sha256=str(success["schema_sha256"]),
        openrouter_generation_id=str(success["openrouter_generation_id"]),
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=int(str(success["latency_ms"])),
        finish_reason="stop",
        reasoning_tokens=int(str(success["reasoning_tokens"])),
        cached_tokens=int(str(success["cached_tokens"])),
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        identity_strength=ModelIdentityStrength.UNBOUND,
        fallback_used=False,
        substitution_detected=False,
        status="success",
        attempts=1,
    )
    bound = bind_synthetic_usage_identity(provisional)
    return reattest_synthetic_real_usage(bound)


def _synthetic_unbound_real_smoke_record() -> UsageRecord:
    bound = _synthetic_bound_real_smoke_record()
    bound_identity = OpenRouterIdentityBindingResult.model_validate(
        bound.routing["identity_binding"]
    )
    unbound_identity = seal_unbound_openrouter_identity(
        snapshot=bound_identity.snapshot,
        request=bound_identity.request,
        diagnostic_codes=(OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH,),
        evaluated_at=bound_identity.evaluated_at,
    )
    generation_observation = _valid_smoke_rejection_payload()["generation_observation"]
    unbound = UsageRecord.model_validate(
        {
            **bound.model_dump(mode="json"),
            "identity_strength": ModelIdentityStrength.UNBOUND,
            "routing": {
                **bound.routing,
                "identity_binding": unbound_identity.model_dump(mode="json"),
                "identity_binding_sha256": unbound_identity.binding_sha256,
                "identity_binding_status": "generation_metadata_unbound",
                "unbound_generation_observation": generation_observation,
            },
        }
    )
    return reattest_synthetic_real_usage(unbound)


def test_terminal_smoke_ledger_evidence_accepts_actual_one_attempt_base_id() -> None:
    record = _synthetic_bound_real_smoke_record()
    started_at = record.started_at or datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    ended_at = record.ended_at or datetime(2026, 7, 28, 12, 0, 1, tzinfo=UTC)
    entry = CostEntry(
        request_id=record.request_id,
        reservation_id="reservation-smoke-actual-shape",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("0.001"),
        actual_cost_usd=Decimal("0.0002"),
        accounted_cost_usd=Decimal("0.0002"),
        release_reason=None,
        created_at=started_at,
        updated_at=ended_at,
    )
    ledger_before = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("250"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(),
    )
    snapshot = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0.0002"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("249.9998"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(entry,),
    )

    evidence = _terminal_smoke_ledger_evidence(
        snapshot=snapshot,
        ledger_before=ledger_before,
        record=record,
    )

    assert evidence.entry.request_id == record.request_id
    assert evidence.spend_delta_usd == Decimal("0.0002")
    assert evidence.delta_reconciled


def _valid_smoke_verification_rejection_payload() -> dict[str, object]:
    success = _valid_smoke_evidence_payload()
    record = _synthetic_bound_real_smoke_record()
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    assert binding.generation is not None
    return {
        "schema_version": "1.0",
        "ticket_id": "V3-SMOKE-001",
        "evidence_kind": "real_openrouter_synthetic_smoke_verification_rejection",
        "status": "REJECTED_GENERATION_VERIFICATION",
        "creditable": False,
        "fixture_path": SMOKE_FIXTURE_PATH,
        "fixture_sha256": SMOKE_FIXTURE_SHA256,
        "canonical_model_id": success["canonical_model_id"],
        "public_lineage_exact_model_id": success["public_lineage_exact_model_id"],
        "public_lineage_root": success["public_lineage_root"],
        "public_lineage_bundle_sha256": success["public_lineage_bundle_sha256"],
        "public_lineage_manifest_file_sha256": success["public_lineage_manifest_file_sha256"],
        "approved_provider_endpoint": success["approved_provider_endpoint"],
        "verification_subject_sha256": success["verification_subject_sha256"],
        "identity_binding_sha256": binding.binding_sha256,
        "initial_generation_evidence_sha256": (binding.generation.generation_evidence_sha256),
        "verification_generation_evidence_sha256": "1" * 64,
        "mismatch_code": GenerationReconciliationMismatchCode.REPORTED_COST.value,
        "reconciliation_attempts": 4,
        "reconciliation_exhausted": True,
        "usage_record": record.model_dump(mode="json"),
        "ledger_entry_request_id": record.request_id,
        "ledger_entry_status": CostEntryStatus.RECONCILED.value,
        "reserved_cost_usd": "0.001",
        "actual_cost_usd": success["actual_cost_usd"],
        "accounted_cost_usd": success["accounted_cost_usd"],
        "cost_reconciled": True,
        "ledger_cap_usd": success["ledger_cap_usd"],
        "ledger_spent_before_usd": success["ledger_spent_before_usd"],
        "ledger_spent_usd": success["ledger_spent_usd"],
        "smoke_spend_delta_usd": success["smoke_spend_delta_usd"],
        "ledger_delta_reconciled": True,
        "ledger_prior_entries_sha256_before": "0" * 64,
        "ledger_prior_entries_sha256_after": "0" * 64,
        "ledger_prior_entries_unchanged": True,
        "ledger_active_reserved_usd": success["ledger_active_reserved_usd"],
        "ledger_reservations_closed": True,
        "ledger_over_cap": False,
        "ledger_has_reservation_overrun": False,
        "ledger_remaining_usd": success["ledger_remaining_usd"],
        "stage_cost_control_satisfied": True,
        "privacy_profile": success["privacy_profile"],
        "require_zdr": success["require_zdr"],
        "data_collection": success["data_collection"],
        "allow_fallbacks": success["allow_fallbacks"],
        "raw_prompts_stored": success["raw_prompts_stored"],
        "raw_responses_stored": success["raw_responses_stored"],
        "validated_output": success["validated_output"],
    }


def test_real_provider_smoke_evidence_rejects_unbound_or_substituted_identity() -> None:
    payload = _valid_smoke_evidence_payload()
    payload.pop("public_lineage_manifest_file_sha256")
    with pytest.raises(ValidationError, match="complete public lineage"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["public_lineage_exact_model_id"] = "other-author/other-model"
    with pytest.raises(ValidationError, match="lineage identity"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["identity_strength"] = ModelIdentityStrength.UNBOUND.value
    with pytest.raises(ValidationError, match="identity_strength"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["actual_provider_endpoint"] = "other-provider/fp8"
    with pytest.raises(ValidationError, match="provider endpoint"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["generation_model_id"] = "other-author/other-model"
    with pytest.raises(ValidationError, match="generation model"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["fixture_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="pinned fixture"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["verification_subject_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="subject hash"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["reasoning_tokens"] = 1
    with pytest.raises(ValidationError, match="reasoning was not disabled"):
        seal_real_provider_smoke_evidence(payload)

    payload = _valid_smoke_evidence_payload()
    payload["completion_tokens"] = SMOKE_MAX_OUTPUT_TOKENS + 1
    payload["total_tokens"] = int(str(payload["prompt_tokens"])) + int(
        str(payload["completion_tokens"])
    )
    with pytest.raises(ValidationError, match="requested output ceiling"):
        seal_real_provider_smoke_evidence(payload)


def test_real_provider_smoke_evidence_is_self_hashed_and_typed() -> None:
    evidence = seal_real_provider_smoke_evidence(_valid_smoke_evidence_payload())
    assert evidence.validated_output == SyntheticProviderSmokeResponse(
        status="OK",
        marker="mmaudit-synthetic-provider-smoke-v1",
    )
    assert len(evidence.evidence_sha256) == 64

    tampered = evidence.model_dump(mode="json")
    tampered["latency_ms"] = 999
    with pytest.raises(ValidationError, match="self-hash"):
        RealProviderSmokeEvidence.model_validate(tampered)


def test_historical_strict_zdr_smoke_evidence_remains_read_only_parseable(
    tmp_path: Path,
) -> None:
    historical = seal_real_provider_smoke_evidence(_valid_smoke_evidence_payload()).model_dump(
        mode="json", exclude={"evidence_sha256"}
    )
    historical["privacy_profile"] = "STRICT_ZDR"
    for key in (
        "public_lineage_exact_model_id",
        "public_lineage_root",
        "public_lineage_bundle_sha256",
        "public_lineage_manifest_file_sha256",
    ):
        historical.pop(key)
    with pytest.raises(ValueError, match="read-only"):
        seal_real_provider_smoke_evidence(historical)
    historical["evidence_sha256"] = canonical_sha256(historical)

    parsed = RealProviderSmokeEvidence.model_validate(historical)

    assert parsed.privacy_profile == "STRICT_ZDR"
    assert parsed.public_lineage_exact_model_id is None
    with pytest.raises(ValueError, match="read-only"):
        write_real_provider_smoke_evidence(
            output_path=tmp_path / "historical.json",
            evidence=parsed,
            forbidden_values=(),
        )
    assert not (tmp_path / "historical.json").exists()


def test_real_provider_smoke_evidence_writer_is_fresh_private_and_secret_free(
    tmp_path: Path,
) -> None:
    evidence = seal_real_provider_smoke_evidence(_valid_smoke_evidence_payload())
    output = tmp_path / "provider-smoke.json"
    binding = write_real_provider_smoke_evidence(
        output_path=output,
        evidence=evidence,
        forbidden_values=("synthetic-secret-canary", "/operator/control/openrouter.env"),
    )
    observed = read_json_evidence(
        evidence_root=tmp_path,
        relative_path=output.name,
    )
    assert observed.binding == binding
    assert RealProviderSmokeEvidence.model_validate(observed.value) == evidence
    assert "synthetic-secret-canary" not in observed.content.decode()
    assert output.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValueError, match="fresh"):
        write_real_provider_smoke_evidence(
            output_path=output,
            evidence=evidence,
            forbidden_values=(),
        )


def test_real_provider_smoke_evidence_writer_rejects_forbidden_value(
    tmp_path: Path,
) -> None:
    payload = _valid_smoke_evidence_payload()
    payload["actual_provider_name"] = "synthetic-secret-canary"
    evidence = seal_real_provider_smoke_evidence(payload)
    with pytest.raises(ValueError, match="forbidden"):
        write_real_provider_smoke_evidence(
            output_path=tmp_path / "provider-smoke.json",
            evidence=evidence,
            forbidden_values=("synthetic-secret-canary",),
        )


def test_real_provider_smoke_rejection_is_typed_self_hashed_and_never_success() -> None:
    rejection = seal_real_provider_smoke_rejection_evidence(_valid_smoke_rejection_payload())

    assert rejection.status == "REJECTED_IDENTITY_UNBOUND"
    assert rejection.creditable is False
    assert rejection.identity_strength is ModelIdentityStrength.UNBOUND
    assert rejection.identity_diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH,
    )
    assert rejection.generation_observation is not None
    assert rejection.generation_observation.provider_name == "Different Provider"
    with pytest.raises(ValidationError):
        RealProviderSmokeEvidence.model_validate(rejection.model_dump(mode="json"))

    tampered = rejection.model_dump(mode="json")
    tampered["selected_provider_identity"] = "different/provider"
    with pytest.raises(ValidationError, match="self-hash"):
        RealProviderSmokeRejectionEvidence.model_validate(tampered)


def test_smoke_rejection_evidence_rejects_legacy_first_attempt_suffix() -> None:
    rejection_payload = _valid_smoke_rejection_payload()
    rejection_payload["ledger_entry_request_id"] = (
        f"{rejection_payload['internal_request_id']}:attempt:1"
    )
    with pytest.raises(ValidationError, match="first-attempt-bound"):
        seal_real_provider_smoke_rejection_evidence(rejection_payload)

    verification_payload = _valid_smoke_verification_rejection_payload()
    record = UsageRecord.model_validate(verification_payload["usage_record"])
    verification_payload["ledger_entry_request_id"] = f"{record.request_id}:attempt:1"
    with pytest.raises(ValidationError, match="first-attempt-bound"):
        seal_real_provider_smoke_verification_rejection_evidence(verification_payload)


def test_real_provider_smoke_rejection_preserves_secondary_control_failures() -> None:
    payload = _valid_smoke_rejection_payload()
    payload["actual_provider_endpoint"] = "different-provider/fp8"
    payload["endpoint_control_satisfied"] = False
    payload["reasoning_tokens"] = 1
    payload["reasoning_control_satisfied"] = False

    rejection = seal_real_provider_smoke_rejection_evidence(payload)

    assert rejection.endpoint_control_satisfied is False
    assert rejection.reasoning_control_satisfied is False
    assert rejection.creditable is False


def test_real_provider_smoke_rejection_preserves_missing_generation_diagnostics() -> None:
    payload = _valid_smoke_rejection_payload()
    payload["generation_observation"] = None
    payload["identity_diagnostic_codes"] = [
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING.value,
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_TIMEOUT.value,
    ]

    rejection = seal_real_provider_smoke_rejection_evidence(payload)

    assert rejection.generation_observation is None
    assert rejection.identity_diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_TIMEOUT,
    )


def test_real_provider_smoke_rejection_preserves_uncertain_attempt_cost() -> None:
    payload = _valid_smoke_rejection_payload()
    payload.update(
        {
            "ledger_entry_status": CostEntryStatus.UNCERTAIN_ACCOUNTED.value,
            "reserved_cost_usd": "0.00072452",
            "provider_reported_cost_usd": None,
            "actual_cost_usd": None,
            "accounted_cost_usd": "0.00072452",
            "cost_reconciled": False,
            "ledger_spent_before_usd": "0.00113946",
            "ledger_spent_usd": "0.00186398",
            "smoke_spend_delta_usd": "0.00072452",
            "ledger_remaining_usd": "249.99813602",
        }
    )

    rejection = seal_real_provider_smoke_rejection_evidence(payload)

    assert rejection.ledger_entry_request_id == payload["internal_request_id"]
    assert rejection.ledger_entry_status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert rejection.actual_cost_usd is None
    assert rejection.cost_reconciled is False


@pytest.mark.parametrize(
    "diagnostics",
    [
        [],
        [
            OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH.value,
            OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH.value,
        ],
        [
            OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH.value,
            OpenRouterIdentityDiagnosticCode.GENERATION_PROVIDER_MISMATCH.value,
        ],
    ],
)
def test_real_provider_smoke_rejection_requires_nonempty_sorted_unique_diagnostics(
    diagnostics: list[str],
) -> None:
    payload = _valid_smoke_rejection_payload()
    payload["identity_diagnostic_codes"] = diagnostics

    with pytest.raises(ValidationError, match="diagnostic"):
        seal_real_provider_smoke_rejection_evidence(payload)


def test_real_provider_smoke_rejection_writer_is_separate_fresh_private_and_secret_free(
    tmp_path: Path,
) -> None:
    rejection = seal_real_provider_smoke_rejection_evidence(_valid_smoke_rejection_payload())
    success_output = tmp_path / "provider-smoke.json"
    rejection_output = real_provider_smoke_rejection_output_path(
        success_output=success_output,
        internal_request_id=rejection.internal_request_id,
    )

    assert rejection_output.parent == success_output.parent
    assert rejection_output != success_output
    assert rejection.internal_request_id not in rejection_output.name
    binding = write_real_provider_smoke_rejection_evidence(
        success_output=success_output,
        evidence=rejection,
        forbidden_values=(
            "synthetic-secret-canary",
            "/operator/control/openrouter.env",
            "contract ProviderSmoke",
        ),
    )
    observed = read_json_evidence(
        evidence_root=tmp_path,
        relative_path=rejection_output.name,
    )
    assert observed.binding == binding
    assert RealProviderSmokeRejectionEvidence.model_validate(observed.value) == rejection
    assert "synthetic-secret-canary" not in observed.content.decode()
    assert "contract ProviderSmoke" not in observed.content.decode()
    assert "raw-provider-prompt-canary" not in observed.content.decode()
    assert "raw-provider-completion-canary" not in observed.content.decode()
    assert not success_output.exists()
    assert rejection_output.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValueError, match="fresh"):
        write_real_provider_smoke_rejection_evidence(
            success_output=success_output,
            evidence=rejection,
            forbidden_values=(),
        )


def test_real_provider_smoke_rejection_writer_rejects_forbidden_value(
    tmp_path: Path,
) -> None:
    payload = _valid_smoke_rejection_payload()
    payload["selected_provider_name"] = "synthetic-secret-canary"
    rejection = seal_real_provider_smoke_rejection_evidence(payload)

    with pytest.raises(ValueError, match="forbidden"):
        write_real_provider_smoke_rejection_evidence(
            success_output=tmp_path / "provider-smoke.json",
            evidence=rejection,
            forbidden_values=("synthetic-secret-canary",),
        )


def test_smoke_verification_rejection_is_typed_self_hashed_and_never_success() -> None:
    rejection = seal_real_provider_smoke_verification_rejection_evidence(
        _valid_smoke_verification_rejection_payload()
    )

    assert rejection.status == "REJECTED_GENERATION_VERIFICATION"
    assert rejection.creditable is False
    assert rejection.mismatch_code is GenerationReconciliationMismatchCode.REPORTED_COST
    assert rejection.reconciliation_attempts == 4
    assert rejection.reconciliation_exhausted
    with pytest.raises(ValidationError):
        RealProviderSmokeEvidence.model_validate(rejection.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        RealProviderSmokeRejectionEvidence.model_validate(rejection.model_dump(mode="json"))

    tampered = rejection.model_dump(mode="json")
    tampered["mismatch_code"] = GenerationReconciliationMismatchCode.PROVIDER.value
    with pytest.raises(ValidationError):
        RealProviderSmokeVerificationRejectionEvidence.model_validate(tampered)


def test_smoke_verification_rejection_writer_is_private_and_canary_free(
    tmp_path: Path,
) -> None:
    rejection = seal_real_provider_smoke_verification_rejection_evidence(
        _valid_smoke_verification_rejection_payload()
    )
    success_output = tmp_path / "provider-smoke.json"
    rejection_output = real_provider_smoke_verification_rejection_output_path(
        success_output=success_output,
        internal_request_id=rejection.usage_record.request_id,
    )

    binding = write_real_provider_smoke_verification_rejection_evidence(
        success_output=success_output,
        evidence=rejection,
        forbidden_values=(
            "synthetic-secret-canary",
            "/operator/control/openrouter.env",
            "contract ProviderSmoke",
        ),
    )
    observed = read_json_evidence(
        evidence_root=tmp_path,
        relative_path=rejection_output.name,
        max_bytes=96_000,
    )

    assert observed.binding == binding
    assert (
        RealProviderSmokeVerificationRejectionEvidence.model_validate(observed.value) == rejection
    )
    serialized = observed.content.decode()
    assert "synthetic-secret-canary" not in serialized
    assert "contract ProviderSmoke" not in serialized
    assert "raw-provider-prompt-canary" not in serialized
    assert "raw-provider-completion-canary" not in serialized
    assert not success_output.exists()
    assert rejection_output.stat().st_mode & 0o777 == 0o600


def test_unbound_smoke_integration_branch_requires_live_real_evidence_and_writes_rejection(
    tmp_path: Path,
) -> None:
    original_record = _synthetic_unbound_real_smoke_record()
    record = reattest_synthetic_real_usage(
        UsageRecord.model_validate(
            {
                **original_record.model_dump(mode="json"),
                "reported_cost_usd": None,
                "reported_cost_usd_exact": None,
                "accounted_cost_usd": 0.00072452,
                "accounted_cost_usd_exact": "0.00072452",
            }
        )
    )
    settings = RealProviderTestSettings(
        secret_file=tmp_path / "operator-control.env",
        cost_ledger=tmp_path / "cost-ledger.json",
        cost_cap_usd=Decimal("250"),
        model_id=record.requested_model,
        model_allowlist=(record.requested_model,),
        provider_endpoint_allowlist=(str(record.actual_provider_endpoint),),
        privacy_profile="SYNTHETIC_BENCHMARK",
        evidence_output=tmp_path / "provider-smoke.json",
    )
    entry = CostEntry(
        request_id=record.request_id,
        reservation_id="reservation-smoke-1",
        status=CostEntryStatus.UNCERTAIN_ACCOUNTED,
        reserved_usd=Decimal("0.00072452"),
        actual_cost_usd=None,
        accounted_cost_usd=Decimal("0.00072452"),
        release_reason=None,
        created_at=record.started_at or datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
        updated_at=record.ended_at or datetime(2026, 7, 28, 12, 0, 1, tzinfo=UTC),
    )
    prior_before = CostEntry(
        request_id="prior:attempt:1",
        reservation_id="reservation-prior-1",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("0.002"),
        actual_cost_usd=Decimal("0.00179914"),
        accounted_cost_usd=Decimal("0.00179914"),
        release_reason=None,
        created_at=datetime(2026, 7, 28, 11, 0, tzinfo=UTC),
        updated_at=datetime(2026, 7, 28, 11, 0, 1, tzinfo=UTC),
    )
    prior_after = CostEntry(
        request_id=prior_before.request_id,
        reservation_id=prior_before.reservation_id,
        status=prior_before.status,
        reserved_usd=prior_before.reserved_usd,
        actual_cost_usd=Decimal("0.00113946"),
        accounted_cost_usd=Decimal("0.00113946"),
        release_reason=None,
        created_at=prior_before.created_at,
        updated_at=datetime(2026, 7, 28, 11, 0, 2, tzinfo=UTC),
    )
    ledger_before = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0.00179914"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("249.99820086"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(prior_before,),
    )
    snapshot = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0.00186398"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("249.99813602"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(prior_after, entry),
    )
    ledger_evidence = _terminal_smoke_ledger_evidence(
        snapshot=snapshot,
        ledger_before=ledger_before,
        record=record,
    )
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    repository_root = Path(__file__).resolve().parents[2]
    fixture_source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(repository_root)
    user_prompt = f"synthetic local prompt\n{fixture_source}"

    rejection_output, rejection = _write_unbound_smoke_rejection(
        settings=settings,
        public_lineage=_verified_public_lineage_projection(exact_model_id=settings.model_id),
        fixture_source=fixture_source,
        fixture_sha256=fixture_sha256,
        user_prompt=user_prompt,
        canonical_model_id=binding.snapshot.canonical_slug,
        endpoint_snapshot_sha256=binding.snapshot.endpoint_snapshot_sha256,
        model_metadata_snapshot_sha256=(binding.snapshot.model_metadata_snapshot_sha256),
        discovery_provenance_sha256=binding.snapshot.discovery_provenance_sha256,
        discovery_evidence_sha256=binding.snapshot.discovery_evidence_sha256,
        record=record,
        response=SyntheticProviderSmokeResponse(
            status="OK",
            marker="mmaudit-synthetic-provider-smoke-v1",
        ),
        ledger_before=ledger_before,
        snapshot=snapshot,
        ledger_evidence=ledger_evidence,
        api_key="synthetic-api-key-canary",
        resolve_lineage=_synthetic_lineage_capability,
        require_lineage=_require_synthetic_public_lineage,
    )

    assert rejection.status == "REJECTED_IDENTITY_UNBOUND"
    assert rejection.creditable is False
    assert ledger_evidence.entry.request_id == record.request_id
    assert rejection.ledger_entry_request_id == record.request_id
    assert rejection.ledger_entry_status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert rejection.actual_cost_usd is None
    assert rejection.accounted_cost_usd == "0.00072452"
    assert rejection.smoke_spend_delta_usd == "0.00006484"
    assert not rejection.ledger_delta_reconciled
    assert not rejection.ledger_prior_entries_unchanged
    assert rejection_output.exists()
    assert not settings.evidence_output.exists()
    serialized = rejection_output.read_text(encoding="utf-8")
    assert "synthetic-api-key-canary" not in serialized
    assert fixture_source not in serialized
    assert user_prompt not in serialized

    errored = reattest_synthetic_real_usage(
        UsageRecord.model_validate(
            {
                **record.model_dump(mode="json"),
                "provider_error_classification": "synthetic_transport_error",
            }
        )
    )
    with pytest.raises(AssertionError, match="concluded unbound"):
        _write_unbound_smoke_rejection(
            settings=settings,
            public_lineage=_verified_public_lineage_projection(exact_model_id=settings.model_id),
            fixture_source=fixture_source,
            fixture_sha256=fixture_sha256,
            user_prompt=user_prompt,
            canonical_model_id=binding.snapshot.canonical_slug,
            endpoint_snapshot_sha256=binding.snapshot.endpoint_snapshot_sha256,
            model_metadata_snapshot_sha256=(binding.snapshot.model_metadata_snapshot_sha256),
            discovery_provenance_sha256=(binding.snapshot.discovery_provenance_sha256),
            discovery_evidence_sha256=binding.snapshot.discovery_evidence_sha256,
            record=errored,
            response=SyntheticProviderSmokeResponse(
                status="OK",
                marker="mmaudit-synthetic-provider-smoke-v1",
            ),
            ledger_before=ledger_before,
            snapshot=snapshot,
            ledger_evidence=ledger_evidence,
            api_key="synthetic-api-key-canary",
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=_require_synthetic_public_lineage,
        )


def test_bound_verification_failure_branch_writes_noncreditable_rejection(
    tmp_path: Path,
) -> None:
    record = _synthetic_bound_real_smoke_record()
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    assert binding.generation is not None
    assert record.openrouter_generation_id is not None
    assert record.validated_response_sha256 is not None
    assert record.schema_sha256 is not None
    endpoint_snapshot_sha256 = str(record.routing["endpoint_snapshot_sha256"])
    discovery_evidence_sha256 = str(record.routing["discovery_evidence_sha256"])
    verification_subject_sha256 = real_provider_smoke_verification_subject_sha256(
        fixture_sha256=SMOKE_FIXTURE_SHA256,
        internal_request_id=record.request_id,
        openrouter_generation_id=record.openrouter_generation_id,
        requested_model_id=record.requested_model,
        canonical_model_id=binding.snapshot.canonical_slug,
        validated_response_sha256=record.validated_response_sha256,
        prompt_sha256=record.prompt_sha256,
        schema_sha256=record.schema_sha256,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        discovery_evidence_sha256=discovery_evidence_sha256,
    )
    verification_request = GenerationVerificationRequest(
        benchmark_report_sha256=verification_subject_sha256,
        case_id="synthetic-provider-smoke",
        exact_model_id=record.requested_model,
        canonical_model_id=binding.snapshot.canonical_slug,
        catalog_identity_binding_sha256=str(record.routing["catalog_identity_binding_sha256"]),
        discovery_evidence_sha256=discovery_evidence_sha256,
        expected_provider_name=str(record.routing["selected_provider_name"]),
        usage_record=record,
    )
    generation = validate_openrouter_generation_payload(
        {
            "data": {
                "id": record.openrouter_generation_id,
                "model": binding.snapshot.canonical_slug,
                "provider_name": record.routing["selected_provider_name"],
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "tokens_prompt": record.prompt_tokens,
                "tokens_completion": record.completion_tokens,
                "native_tokens_reasoning": record.reasoning_tokens,
                "native_tokens_cached": record.cached_tokens,
                "total_cost": 0.0003,
                "usage": 0.0003,
                "cancelled": False,
                "created_at": record.started_at,
            }
        },
        requested_generation_id=record.openrouter_generation_id,
        retrieved_at=datetime(2026, 7, 28, 12, 0, 2, tzinfo=UTC),
        retrieval_attempts=7,
        execution_evidence=ExecutionEvidenceKind.REAL,
    )
    error = OpenRouterGenerationReconciliationError(
        GenerationReconciliationMismatchCode.REPORTED_COST,
        attempts=7,
        exhausted=True,
        last_evidence=generation,
    )
    settings = RealProviderTestSettings(
        secret_file=tmp_path / "operator-control.env",
        cost_ledger=tmp_path / "cost-ledger.json",
        cost_cap_usd=Decimal("250"),
        model_id=record.requested_model,
        model_allowlist=(record.requested_model,),
        provider_endpoint_allowlist=(str(record.actual_provider_endpoint),),
        privacy_profile="SYNTHETIC_BENCHMARK",
        evidence_output=tmp_path / "provider-smoke.json",
    )
    prior = CostEntry(
        request_id="prior:attempt:1",
        reservation_id="reservation-prior",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("0.002"),
        actual_cost_usd=Decimal("0.00118674"),
        accounted_cost_usd=Decimal("0.00118674"),
        release_reason=None,
        created_at=datetime(2026, 7, 28, 11, 0, tzinfo=UTC),
        updated_at=datetime(2026, 7, 28, 11, 0, 1, tzinfo=UTC),
    )
    entry = CostEntry(
        request_id=record.request_id,
        reservation_id="reservation-smoke",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("0.001"),
        actual_cost_usd=Decimal("0.0002"),
        accounted_cost_usd=Decimal("0.0002"),
        release_reason=None,
        created_at=record.started_at or datetime(2026, 7, 28, 12, 0, tzinfo=UTC),
        updated_at=record.ended_at or datetime(2026, 7, 28, 12, 0, 1, tzinfo=UTC),
    )
    ledger_before = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0.00118674"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("249.99881326"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(prior,),
    )
    snapshot = CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=Decimal("0.00138674"),
        active_reserved_usd=Decimal("0"),
        remaining_usd=Decimal("249.99861326"),
        over_cap=False,
        has_reservation_overrun=False,
        entries=(prior, entry),
    )
    ledger_evidence = _terminal_smoke_ledger_evidence(
        snapshot=snapshot,
        ledger_before=ledger_before,
        record=record,
    )
    repository_root = Path(__file__).resolve().parents[2]
    fixture_source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(repository_root)
    user_prompt = f"synthetic local prompt\n{fixture_source}"

    rejection_output, rejection = _write_generation_verification_smoke_rejection(
        settings=settings,
        public_lineage=_verified_public_lineage_projection(exact_model_id=settings.model_id),
        fixture_source=fixture_source,
        fixture_sha256=fixture_sha256,
        user_prompt=user_prompt,
        canonical_model_id=binding.snapshot.canonical_slug,
        verification_subject_sha256=verification_subject_sha256,
        record=record,
        response=SyntheticProviderSmokeResponse(
            status="OK",
            marker="mmaudit-synthetic-provider-smoke-v1",
        ),
        verification_request=verification_request,
        error=error,
        ledger_before=ledger_before,
        snapshot=snapshot,
        ledger_evidence=ledger_evidence,
        api_key="synthetic-api-key-canary",
        resolve_lineage=_synthetic_lineage_capability,
        require_lineage=_require_synthetic_public_lineage,
    )

    assert rejection.status == "REJECTED_GENERATION_VERIFICATION"
    assert rejection.creditable is False
    assert rejection.mismatch_code is GenerationReconciliationMismatchCode.REPORTED_COST
    assert rejection.reconciliation_attempts == 7
    assert rejection_output.exists()
    assert not settings.evidence_output.exists()
    serialized = rejection_output.read_text(encoding="utf-8")
    assert "synthetic-api-key-canary" not in serialized
    assert fixture_source not in serialized
    assert user_prompt not in serialized
    assert "0.0003" not in serialized

    unattested = UsageRecord.model_validate(record.model_dump(mode="json"))
    with pytest.raises(AssertionError, match="owned bound REAL"):
        _write_generation_verification_smoke_rejection(
            settings=settings,
            public_lineage=_verified_public_lineage_projection(exact_model_id=settings.model_id),
            fixture_source=fixture_source,
            fixture_sha256=fixture_sha256,
            user_prompt=user_prompt,
            canonical_model_id=binding.snapshot.canonical_slug,
            verification_subject_sha256=verification_subject_sha256,
            record=unattested,
            response=SyntheticProviderSmokeResponse(
                status="OK",
                marker="mmaudit-synthetic-provider-smoke-v1",
            ),
            verification_request=verification_request,
            error=error,
            ledger_before=ledger_before,
            snapshot=snapshot,
            ledger_evidence=ledger_evidence,
            api_key="synthetic-api-key-canary",
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=_require_synthetic_public_lineage,
        )

    unattested = UsageRecord.model_validate(record.model_dump(mode="json"))
    assert not is_generation_bindable_usage_record(unattested)
    with pytest.raises(AssertionError, match="concluded unbound"):
        _write_unbound_smoke_rejection(
            settings=settings,
            public_lineage=_verified_public_lineage_projection(exact_model_id=settings.model_id),
            fixture_source=fixture_source,
            fixture_sha256=fixture_sha256,
            user_prompt=user_prompt,
            canonical_model_id=binding.snapshot.canonical_slug,
            endpoint_snapshot_sha256=binding.snapshot.endpoint_snapshot_sha256,
            model_metadata_snapshot_sha256=(binding.snapshot.model_metadata_snapshot_sha256),
            discovery_provenance_sha256=(binding.snapshot.discovery_provenance_sha256),
            discovery_evidence_sha256=binding.snapshot.discovery_evidence_sha256,
            record=unattested,
            response=SyntheticProviderSmokeResponse(
                status="OK",
                marker="mmaudit-synthetic-provider-smoke-v1",
            ),
            ledger_before=ledger_before,
            snapshot=snapshot,
            ledger_evidence=ledger_evidence,
            api_key="synthetic-api-key-canary",
            resolve_lineage=_synthetic_lineage_capability,
            require_lineage=_require_synthetic_public_lineage,
        )
