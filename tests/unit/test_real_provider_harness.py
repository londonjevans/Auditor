from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import ModelIdentityStrength
from mmaudit.release_io import read_json_evidence
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
    RealProviderSmokeEvidence,
    RealProviderTestConfigurationError,
    SyntheticProviderSmokeResponse,
    load_pinned_synthetic_smoke_fixture,
    load_real_provider_test_settings,
    preflight_real_provider_smoke_output,
    real_provider_smoke_verification_subject_sha256,
    real_provider_tests_enabled,
    seal_real_provider_smoke_evidence,
    write_real_provider_smoke_evidence,
)


def _valid_environment() -> dict[str, str]:
    return {
        REAL_PROVIDER_OPT_IN: "1",
        REAL_PROVIDER_SECRET_FILE: "/operator/control/openrouter.env",
        REAL_PROVIDER_COST_CAP: "1.25",
        REAL_PROVIDER_COST_LEDGER: "/operator/control/openrouter-cost-ledger.json",
        REAL_PROVIDER_MODEL: "acme/secure-reasoner-v1",
        REAL_PROVIDER_MODEL_ALLOWLIST: (
            "acme/secure-reasoner-v1,second-author/security-reviewer-v2"
        ),
        REAL_PROVIDER_ENDPOINT_ALLOWLIST: "approved-provider",
        REAL_PROVIDER_PRIVACY_PROFILE: "STRICT_ZDR",
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


@pytest.mark.parametrize("cost", ["", "0", "-1", "nan", "1e2", "250.01", "251"])
def test_real_provider_cost_cap_is_plain_bounded_decimal(cost: str) -> None:
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
    assert settings.cost_ledger == Path("/operator/control/openrouter-cost-ledger.json")
    assert settings.model_id == "acme/secure-reasoner-v1"
    assert settings.model_id in settings.model_allowlist
    assert settings.provider_endpoint_allowlist == ("approved-provider",)
    assert settings.privacy_profile == "STRICT_ZDR"
    assert settings.evidence_output == Path("/operator/control/provider-smoke.json")
    assert "API_KEY" not in repr(settings)


@pytest.mark.parametrize("path", ["", "relative-smoke.json"])
def test_real_provider_evidence_output_is_explicit_and_absolute(path: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_EVIDENCE_OUTPUT] = path
    with pytest.raises(RealProviderTestConfigurationError, match="EVIDENCE_OUTPUT"):
        load_real_provider_test_settings(environment)


@pytest.mark.parametrize("profile", ["", "strict_zdr", "SYNTHETIC_BENCHMARK"])
def test_real_provider_privacy_profile_requires_explicit_strict_zdr(profile: str) -> None:
    environment = _valid_environment()
    environment[REAL_PROVIDER_PRIVACY_PROFILE] = profile
    with pytest.raises(RealProviderTestConfigurationError, match="PRIVACY_PROFILE"):
        load_real_provider_test_settings(environment)


def test_committed_real_provider_fixture_matches_its_pinned_hash() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    source, fixture_sha256 = load_pinned_synthetic_smoke_fixture(repository_root)

    assert fixture_sha256 == SMOKE_FIXTURE_SHA256
    assert SMOKE_FIXTURE_PATH.endswith("ProviderSmoke.sol")
    assert "contract ProviderSmoke" in source
    assert len(source.encode()) <= 20_000


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
        "privacy_profile": "STRICT_ZDR",
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


def test_real_provider_smoke_evidence_rejects_unbound_or_substituted_identity() -> None:
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
