from __future__ import annotations

import copy
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    OPENROUTER_CATALOG_QUERY,
    OPENROUTER_ZDR_QUERY,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    ModelDiscoveryValidationError,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    _issue_real_openrouter_discovery_run,
    load_model_discovery_evidence,
    load_model_discovery_run,
    openrouter_endpoint_query,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import (
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterPrivacyError
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager


def _endpoint(
    *,
    model: str = "alpha/atlas-secure",
    endpoint_id: str = "approved-provider/fp8",
    context_length: int = 200_000,
    max_prompt_tokens: int | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    return {
        "model_id": model,
        "slug": endpoint_id,
        "provider_name": "Approved Provider",
        "status": 0,
        "context_length": context_length,
        "max_prompt_tokens": max_prompt_tokens,
        "max_completion_tokens": max_completion_tokens,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ],
        "pricing": {
            "completion": "0.000002",
            "prompt": "0.000001",
        },
    }


def _endpoint_snapshot(
    *,
    model: str = "alpha/atlas-secure",
    endpoint_id: str = "approved-provider/fp8",
    context_length: int = 200_000,
    max_completion_tokens: int | None = None,
) -> OpenRouterEndpointSnapshotEvidence:
    exact_endpoint = _endpoint(
        model=model,
        endpoint_id=endpoint_id,
        context_length=context_length,
        max_completion_tokens=max_completion_tokens,
    )
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(endpoint_id,),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": model,
                "endpoints": [
                    {key: value for key, value in exact_endpoint.items() if key != "model_id"}
                ],
            }
        },
        require_zdr=True,
        zdr_payload={"data": [exact_endpoint]},
        reasoning_requested=True,
    )


def _model(
    *,
    model: str = "alpha/atlas-secure",
    canonical_slug: str = "alpha/atlas-secure-20260727",
    context_length: int = 200_000,
    provider_context_length: int | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    return {
        "id": model,
        "canonical_slug": canonical_slug,
        "context_length": context_length,
        "top_provider": {
            "context_length": provider_context_length,
            "max_completion_tokens": max_completion_tokens,
            "is_moderated": False,
        },
        "supported_parameters": [
            "structured_outputs",
            "temperature",
            "response_format",
            "reasoning",
            "max_tokens",
        ],
        "description": "provider-controlled prose excluded from evidence",
        "benchmarks": {"untrusted": [1, 2, 3]},
        "links": {"details": "https://invalid.example/provider-controlled"},
    }


def _discover(
    *,
    models: list[dict[str, Any]] | None = None,
    endpoint_snapshot: OpenRouterEndpointSnapshotEvidence | None = None,
    exact_model_id: str = "alpha/atlas-secure",
) -> OpenRouterModelDiscoveryPayload:
    return validate_openrouter_model_discovery(
        exact_model_id=exact_model_id,
        models_payload={"data": models or [_model()]},
        endpoint_snapshot=endpoint_snapshot or _endpoint_snapshot(),
    )


def _real_evidence(
    payloads: tuple[OpenRouterModelDiscoveryPayload, ...] | None = None,
) -> tuple[OpenRouterModelDiscoveryEvidence, ...]:
    selected = payloads or (_discover(),)
    routes = tuple(
        DiscoveryCandidateRoute(
            exact_model_id=payload.exact_model_id,
            approved_provider_endpoint=payload.approved_provider_endpoint,
        )
        for payload in selected
    )
    endpoint_bindings = tuple(
        DiscoveryEndpointMetadataBinding(
            exact_model_id=payload.exact_model_id,
            api_query=openrouter_endpoint_query(payload.exact_model_id),
            response_snapshot_sha256=payload.endpoint_snapshot.endpoint_metadata_sha256,
        )
        for payload in selected
    )
    provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256="c" * 64,
        zdr_snapshot_sha256="d" * 64,
        candidate_routes=routes,
        endpoint_metadata_bindings=endpoint_bindings,
        payloads=selected,
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    assert provenance.catalog_api_query == OPENROUTER_CATALOG_QUERY
    assert provenance.zdr_api_query == OPENROUTER_ZDR_QUERY
    return evidence


def test_current_like_null_limits_are_derived_and_exact_endpoint_is_bound() -> None:
    payload = _discover()
    evidence = _real_evidence((payload,))[0]

    assert evidence.exact_model_id == "alpha/atlas-secure"
    assert evidence.canonical_slug == "alpha/atlas-secure-20260727"
    assert evidence.catalog_provider_context_size == 200_000
    assert evidence.catalog_provider_context_size_source == "catalog_context"
    assert evidence.catalog_output_limit == 200_000
    assert evidence.catalog_output_limit_source == "provider_context"
    assert evidence.context_size == 200_000
    assert evidence.output_limit == 200_000
    assert evidence.approved_provider_endpoint == "approved-provider/fp8"
    assert evidence.operational is True
    assert evidence.zdr_eligible is True
    assert evidence.data_collection_deny_eligible is True
    assert evidence.structured_output_supported is True
    assert evidence.reasoning_supported is True
    assert len(evidence.catalog_identity_binding_sha256) == 64
    assert len(evidence.model_metadata_snapshot_sha256) == 64
    assert len(evidence.discovery_evidence_sha256) == 64
    assert evidence.provenance.execution_evidence.value == "real"
    assert evidence.provenance.authenticated_metadata is True
    assert evidence.provenance.retrieved_at.microsecond == 0


def test_evidence_is_deterministic_and_excludes_freeform_catalog_fields() -> None:
    first = _model()
    second = copy.deepcopy(first)
    second["supported_parameters"] = list(reversed(second["supported_parameters"]))
    second["description"] = "different untrusted prose"
    second["benchmarks"] = {"forged": True}
    second["links"] = {"details": "https://different.invalid"}

    first_evidence = _discover(models=[first])
    second_evidence = _discover(models=[second])

    assert first_evidence == second_evidence
    serialized = json.dumps(first_evidence.model_dump(mode="json"), sort_keys=True)
    assert "provider-controlled prose" not in serialized
    assert "benchmarks" not in serialized
    assert "invalid.example" not in serialized


@pytest.mark.parametrize(
    "models,error",
    [
        ([_model(), _model()], "duplicate exact model"),
        ([_model(), {"canonical_slug": "beta/other"}], "missing or invalid"),
        ([_model(model="beta/other", canonical_slug="beta/other")], "unavailable"),
    ],
)
def test_catalog_rejects_duplicate_missing_and_unavailable_ids(
    models: list[dict[str, Any]],
    error: str,
) -> None:
    with pytest.raises(ModelDiscoveryValidationError, match=error):
        _discover(models=models)


def test_unrelated_catalog_aliases_are_not_eligible_candidates() -> None:
    payload = _discover(
        models=[
            _model(model="openrouter/auto", canonical_slug="openrouter/auto"),
            _model(),
        ]
    )

    assert payload.exact_model_id == "alpha/atlas-secure"


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/router",
        "alpha/latest",
        "alpha/atlas:free",
        "alpha/atlas:latest",
        "openrouter/auto:online",
        "alpha/atlas:auto",
        "alpha/atlas-free",
        "alpha/atlas-latest",
        "alpha/atlas-online",
    ],
)
def test_requested_model_aliases_are_rejected(model: str) -> None:
    with pytest.raises(ModelDiscoveryValidationError, match="exact non-routed"):
        validate_openrouter_model_discovery(
            exact_model_id=model,
            models_payload={"data": [_model(model=model, canonical_slug=model)]},
            endpoint_snapshot=_endpoint_snapshot(),
        )


def test_canonical_slug_is_explicit_catalog_evidence_not_a_prefix_heuristic() -> None:
    with pytest.raises(ModelDiscoveryValidationError, match="changes the requested model author"):
        _discover(models=[_model(canonical_slug="beta/atlas-secure-20260727")])

    payload = _discover(models=[_model(canonical_slug="alpha/unrelated-model")])
    assert payload.canonical_slug == "alpha/unrelated-model"
    assert payload.catalog_identity_binding_sha256

    with pytest.raises(ValidationError, match="different model"):
        _discover(endpoint_snapshot=_endpoint_snapshot(model="beta/other"))


def test_catalog_and_exact_endpoint_limits_must_be_compatible() -> None:
    with pytest.raises(ValidationError, match="endpoint context exceeds"):
        _discover(
            models=[
                _model(
                    context_length=100_000,
                    provider_context_length=100_000,
                )
            ]
        )

    # The catalog's "top provider" is not necessarily the approved exact
    # endpoint, so its output limit is retained but is not used as a false cap.
    evidence = _discover(
        models=[
            _model(
                max_completion_tokens=20_000,
                provider_context_length=200_000,
            )
        ]
    )
    assert evidence.catalog_output_limit == 20_000
    assert evidence.output_limit == 200_000


def test_catalog_must_support_the_exact_request_shape() -> None:
    model = _model()
    model["supported_parameters"].remove("response_format")
    model["supported_parameters"].remove("structured_outputs")

    with pytest.raises(ModelDiscoveryValidationError, match="required request parameters"):
        _discover(models=[model])


def test_self_hashes_reject_metadata_and_artifact_tampering() -> None:
    structural = _discover()
    payload = structural.model_dump(mode="json")
    payload["model_metadata_snapshot_sha256"] = "a" * 64
    with pytest.raises(ValidationError, match="metadata projection hash"):
        OpenRouterModelDiscoveryPayload.model_validate(payload)

    evidence = _real_evidence((structural,))[0]
    payload = evidence.model_dump(mode="json")
    payload["discovery_evidence_sha256"] = "b" * 64
    with pytest.raises(ValidationError, match="evidence hash"):
        OpenRouterModelDiscoveryEvidence.model_validate(payload)


def test_real_provenance_requires_the_trusted_issuer_and_whole_second_utc() -> None:
    payload = _discover()
    route = DiscoveryCandidateRoute(
        exact_model_id=payload.exact_model_id,
        approved_provider_endpoint=payload.approved_provider_endpoint,
    )
    binding = DiscoveryEndpointMetadataBinding(
        exact_model_id=payload.exact_model_id,
        api_query=openrouter_endpoint_query(payload.exact_model_id),
        response_snapshot_sha256=payload.endpoint_snapshot.endpoint_metadata_sha256,
    )
    arguments = {
        "run_id": "1" * 32,
        "retrieved_at": datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        "client_fingerprint_sha256": "a" * 64,
        "provider_fingerprint_sha256": "b" * 64,
        "catalog_snapshot_sha256": "c" * 64,
        "zdr_snapshot_sha256": "d" * 64,
        "candidate_routes": (route,),
        "endpoint_metadata_bindings": (binding,),
        "payloads": (payload,),
    }

    with pytest.raises(ModelDiscoveryValidationError, match="trusted OpenRouter client"):
        _issue_real_openrouter_discovery_run(**arguments, issuer=object())

    with pytest.raises(ValidationError, match="whole-second UTC"):
        _issue_real_openrouter_discovery_run(
            **{
                **arguments,
                "retrieved_at": datetime(2026, 7, 27, 8, 0, 0, 1, tzinfo=UTC),
            },
            issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
        )


@pytest.mark.asyncio
async def test_mock_transport_cannot_seal_real_discovery_evidence(
    config_factory: Any,
) -> None:
    config = config_factory()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, request=request, json={})
        ),
        base_url=OPENROUTER_DEFAULT_BASE_URL,
    )
    client = OpenRouterClient(
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
        http_client=http_client,
    )
    assert client.execution_evidence.value == "mock"
    try:
        with pytest.raises(OpenRouterPrivacyError, match="authenticated owned provider client"):
            client.seal_real_model_discovery_run(
                run_id="1" * 32,
                retrieved_at=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
                models_payload={},
                zdr_payload={},
                endpoint_payloads={},
                candidate_routes=(),
                payloads=(),
            )
    finally:
        await client.close()
        await http_client.aclose()


def test_atomic_run_write_load_and_reuse_rejection(tmp_path: Path) -> None:
    evidence = _real_evidence()
    destination = tmp_path / "discovery-run"
    manifest = write_model_discovery_run(destination, evidence)

    loaded_manifest, loaded_evidence = load_model_discovery_run(destination)
    assert loaded_manifest == manifest
    assert loaded_evidence == evidence
    assert destination.stat().st_mode & 0o777 == 0o700
    assert all(
        item.stat().st_mode & 0o777 == 0o600 for item in destination.iterdir() if item.is_file()
    )

    with pytest.raises(ValueError, match="fresh"):
        write_model_discovery_run(destination, evidence)

    stale = destination / "candidate-stale.json"
    stale.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale or unmanifested"):
        load_model_discovery_run(destination)


def test_atomic_run_manifest_binds_the_exact_candidate_set(tmp_path: Path) -> None:
    second = _discover(
        exact_model_id="beta/ledger-safe",
        models=[_model(model="beta/ledger-safe", canonical_slug="beta/ledger-safe-20260727")],
        endpoint_snapshot=_endpoint_snapshot(
            model="beta/ledger-safe",
            endpoint_id="second-provider/exact",
        ),
    )
    evidence = _real_evidence((_discover(), second))
    destination = tmp_path / "two-candidate-run"

    manifest = write_model_discovery_run(destination, evidence)
    loaded_manifest, loaded_evidence = load_model_discovery_run(destination)

    assert loaded_manifest == manifest
    assert tuple(item.exact_model_id for item in loaded_evidence) == (
        "alpha/atlas-secure",
        "beta/ledger-safe",
    )
    assert all(
        item.provenance.run_id == loaded_evidence[0].provenance.run_id for item in loaded_evidence
    )
    assert manifest.candidate_set_sha256 == loaded_evidence[0].provenance.candidate_set_sha256


def test_atomic_run_rolls_back_on_manifest_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed-run"

    def fail_manifest_write(_path: Path, _value: bytes) -> None:
        raise OSError("synthetic manifest write failure")

    monkeypatch.setattr("mmaudit.models.discovery._write_private_bytes", fail_manifest_write)
    with pytest.raises(OSError, match="synthetic manifest"):
        write_model_discovery_run(destination, _real_evidence())

    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-run.*.tmp"))


def test_load_and_write_reject_hardlinks_and_oversize_files(tmp_path: Path) -> None:
    evidence = _real_evidence()
    run = tmp_path / "run"
    write_model_discovery_run(run, evidence)
    original = next(run.glob("candidate-*.json"))
    linked = tmp_path / "linked.json"
    os.link(original, linked)

    with pytest.raises(ValueError, match="unshared"):
        load_model_discovery_evidence(linked)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 2_000_001 + b"}")
    with pytest.raises(ValueError, match="bounded"):
        load_model_discovery_evidence(oversized)


def test_parent_symlink_is_rejected(tmp_path: Path) -> None:
    evidence = _real_evidence()
    real = tmp_path / "real"
    real.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="traverse links"):
        write_model_discovery_run(linked_parent / "discovery-run", evidence)
