from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.identity import (
    OpenRouterGenerationIdentityEvidence,
    OpenRouterIdentityBindingResult,
    OpenRouterIdentityDiagnosticCode,
    OpenRouterIdentityEndpointCapabilities,
    OpenRouterIdentityPricingEntry,
    OpenRouterIdentityProviderPolicy,
    OpenRouterIdentityStrength,
    OpenRouterModelEndpointIdentitySnapshot,
    OpenRouterRequestIdentityEvidence,
    seal_bound_openrouter_identity,
    seal_openrouter_identity_provider_policy,
    seal_openrouter_model_endpoint_identity_snapshot,
    seal_unbound_openrouter_identity,
)

_REQUESTED = "alpha/atlas-secure"
_CANONICAL = "alpha/atlas-secure-20260728"
_ENDPOINT = "approved-provider/fp8"
_PROVIDER_NAME = "Approved Provider"
_RETRIEVED = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
_STARTED = datetime(2026, 7, 28, 12, 1, tzinfo=UTC)
_COMPLETED = datetime(2026, 7, 28, 12, 2, tzinfo=UTC)
_GENERATION_RETRIEVED = datetime(2026, 7, 28, 12, 3, tzinfo=UTC)
_EVALUATED = datetime(2026, 7, 28, 12, 4, tzinfo=UTC)
_EXPIRES = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _policy() -> OpenRouterIdentityProviderPolicy:
    return seal_openrouter_identity_provider_policy(
        mode="only",
        configured_endpoints=(_ENDPOINT,),
        allow_fallbacks=False,
        zdr_required=True,
    )


def _capabilities() -> OpenRouterIdentityEndpointCapabilities:
    return OpenRouterIdentityEndpointCapabilities(
        operational=True,
        context_tokens=128_000,
        output_tokens=16_384,
        supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        required_parameters=("max_tokens", "response_format", "temperature"),
        structured_output_parameters=("response_format",),
        reasoning_parameters=("reasoning",),
        structured_output_supported=True,
        reasoning_supported=True,
        zdr_eligible=True,
        data_collection_deny_eligible=True,
    )


def _pricing() -> tuple[OpenRouterIdentityPricingEntry, ...]:
    return (
        OpenRouterIdentityPricingEntry(unit="completion", usd_per_unit="0.000015"),
        OpenRouterIdentityPricingEntry(unit="prompt", usd_per_unit="0.000003"),
    )


def _snapshot(
    *,
    requested_slug: str = _REQUESTED,
    canonical_slug: str = _CANONICAL,
    frozen_aliases: tuple[str, ...] = (_REQUESTED, _CANONICAL),
    canonical_slug_mutable: bool = True,
    immutable_provider_version: str | None = None,
    immutable_provider_version_evidence_sha256: str | None = None,
    expires_at: datetime | None = _EXPIRES,
) -> OpenRouterModelEndpointIdentitySnapshot:
    return seal_openrouter_model_endpoint_identity_snapshot(
        requested_slug=requested_slug,
        canonical_slug=canonical_slug,
        frozen_aliases=frozen_aliases,
        model_author=canonical_slug.split("/", 1)[0],
        model_context_tokens=128_000,
        model_output_tokens=16_384,
        model_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        approved_provider_endpoint=_ENDPOINT,
        endpoint_tag=None,
        endpoint_slug=_ENDPOINT,
        provider_name=_PROVIDER_NAME,
        provider_policy=_policy(),
        endpoint_capabilities=_capabilities(),
        pricing=_pricing(),
        canonical_slug_mutable=canonical_slug_mutable,
        immutable_provider_version=immutable_provider_version,
        immutable_provider_version_evidence_sha256=(immutable_provider_version_evidence_sha256),
        retrieved_at=_RETRIEVED,
        expires_at=expires_at,
        catalog_identity_binding_sha256="1" * 64,
        catalog_snapshot_sha256="2" * 64,
        model_metadata_snapshot_sha256="3" * 64,
        discovery_provenance_sha256="4" * 64,
        discovery_evidence_sha256="5" * 64,
        endpoint_snapshot_sha256="6" * 64,
        pricing_snapshot_sha256="7" * 64,
    )


def _request(**updates: Any) -> OpenRouterRequestIdentityEvidence:
    values: dict[str, Any] = {
        "internal_request_id": "request-identity-1",
        "execution_evidence": "real",
        "requested_slug": _REQUESTED,
        "returned_slug": _CANONICAL,
        "selected_model_slug": _CANONICAL,
        "actual_provider_endpoint": _ENDPOINT,
        "actual_provider_name": _PROVIDER_NAME,
        "openrouter_generation_id": "generation-identity-1",
        "request_body_sha256": "8" * 64,
        "response_sha256": "9" * 64,
        "validated_response_sha256": "a" * 64,
        "started_at": _STARTED,
        "completed_at": _COMPLETED,
        "fallback_used": False,
    }
    return OpenRouterRequestIdentityEvidence.model_validate({**values, **updates})


def _generation(**updates: Any) -> OpenRouterGenerationIdentityEvidence:
    values: dict[str, Any] = {
        "generation_id": "generation-identity-1",
        "execution_evidence": "real",
        "generation_model_slug": _CANONICAL,
        "provider_name": _PROVIDER_NAME,
        "provider_version_id": None,
        "provider_request_id": "provider-request-1",
        "retrieved_at": _GENERATION_RETRIEVED,
        "generation_evidence_sha256": "b" * 64,
    }
    return OpenRouterGenerationIdentityEvidence.model_validate({**values, **updates})


def test_alias_normalization_seals_canonical_model_and_endpoint_identity() -> None:
    snapshot = _snapshot()

    result = seal_bound_openrouter_identity(
        snapshot=snapshot,
        request=_request(),
        generation=_generation(),
        evaluated_at=_EVALUATED,
    )

    assert result.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    assert result.request.requested_slug == _REQUESTED
    assert result.request.returned_slug == _CANONICAL
    assert result.snapshot.resolves_to_canonical(_REQUESTED)
    assert result.snapshot.resolves_to_canonical(_CANONICAL)
    assert len(result.snapshot.snapshot_sha256) == 64
    assert len(result.binding_sha256) == 64


def test_snapshot_is_deeply_frozen_and_rejects_tampered_hashes() -> None:
    snapshot = _snapshot()
    serialized = snapshot.model_dump(mode="json")
    serialized["snapshot_sha256"] = "f" * 64

    with pytest.raises(ValidationError, match="snapshot hash"):
        OpenRouterModelEndpointIdentitySnapshot.model_validate(serialized)
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.model_author = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.provider_policy.mode = "order"  # type: ignore[misc]


def test_snapshot_requires_sorted_complete_frozen_aliases() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        _snapshot(frozen_aliases=(_CANONICAL, _REQUESTED))
    with pytest.raises(ValidationError, match="include requested and canonical"):
        _snapshot(frozen_aliases=(_REQUESTED,))


@pytest.mark.parametrize("unbound_alias", ["alpha/unrelated-model", "bravo/unrelated-model"])
def test_snapshot_rejects_unbound_same_or_cross_author_aliases(
    unbound_alias: str,
) -> None:
    with pytest.raises(ValidationError, match="no unbound aliases"):
        _snapshot(
            frozen_aliases=tuple(sorted({_REQUESTED, _CANONICAL, unbound_alias})),
        )


def test_snapshot_rejects_cross_author_requested_alias() -> None:
    cross_author_requested = "bravo/atlas-secure"

    with pytest.raises(ValidationError, match="requested model author"):
        _snapshot(
            requested_slug=cross_author_requested,
            frozen_aliases=tuple(sorted({cross_author_requested, _CANONICAL})),
        )


@pytest.mark.parametrize(
    ("requested_slug", "canonical_slug", "canonical_slug_mutable"),
    [
        (_REQUESTED, _CANONICAL, True),
        (_CANONICAL, _CANONICAL, True),
    ],
)
def test_mutable_model_or_alias_resolution_requires_expiry(
    requested_slug: str,
    canonical_slug: str,
    canonical_slug_mutable: bool,
) -> None:
    aliases = tuple(sorted({requested_slug, canonical_slug}))

    with pytest.raises(ValidationError, match="requires an expiry"):
        _snapshot(
            requested_slug=requested_slug,
            canonical_slug=canonical_slug,
            frozen_aliases=aliases,
            canonical_slug_mutable=canonical_slug_mutable,
            expires_at=None,
        )


def test_immutable_canonical_claim_requires_explicit_provider_version_evidence() -> None:
    with pytest.raises(ValidationError, match="explicit provider-version evidence"):
        _snapshot(
            requested_slug=_CANONICAL,
            canonical_slug=_CANONICAL,
            frozen_aliases=(_CANONICAL,),
            canonical_slug_mutable=False,
            expires_at=None,
        )


def test_date_like_canonical_slug_is_not_implicitly_immutable() -> None:
    result = seal_bound_openrouter_identity(
        snapshot=_snapshot(canonical_slug_mutable=True),
        request=_request(),
        generation=_generation(),
        evaluated_at=_EVALUATED,
    )

    assert result.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    assert not result.snapshot.has_immutable_provider_version


def test_matching_explicit_provider_version_seals_immutable_identity() -> None:
    snapshot = _snapshot(
        requested_slug=_CANONICAL,
        canonical_slug=_CANONICAL,
        frozen_aliases=(_CANONICAL,),
        canonical_slug_mutable=False,
        immutable_provider_version="provider-version-20260728",
        immutable_provider_version_evidence_sha256="c" * 64,
        expires_at=None,
    )
    request = _request(
        requested_slug=_CANONICAL,
        returned_slug=_CANONICAL,
    )
    generation = _generation(provider_version_id="provider-version-20260728")

    result = seal_bound_openrouter_identity(
        snapshot=snapshot,
        request=request,
        generation=generation,
        evaluated_at=_EVALUATED,
    )

    assert result.strength is OpenRouterIdentityStrength.IMMUTABLE_VERSION_BOUND
    assert result.snapshot.has_immutable_provider_version


def test_missing_generation_version_cannot_claim_immutable_strength() -> None:
    snapshot = _snapshot(
        requested_slug=_CANONICAL,
        canonical_slug=_CANONICAL,
        frozen_aliases=(_CANONICAL,),
        canonical_slug_mutable=False,
        immutable_provider_version="provider-version-20260728",
        immutable_provider_version_evidence_sha256="c" * 64,
        expires_at=None,
    )
    request = _request(
        requested_slug=_CANONICAL,
        returned_slug=_CANONICAL,
    )

    result = seal_bound_openrouter_identity(
        snapshot=snapshot,
        request=request,
        generation=_generation(provider_version_id=None),
        evaluated_at=_EVALUATED,
    )

    assert result.strength is OpenRouterIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND

    tampered = result.model_dump(mode="json")
    tampered["strength"] = OpenRouterIdentityStrength.IMMUTABLE_VERSION_BOUND.value
    with pytest.raises(ValidationError, match="explicit matching provider-version"):
        OpenRouterIdentityBindingResult.model_validate(tampered)


@pytest.mark.parametrize(
    ("request_updates", "generation_updates", "error"),
    [
        (
            {"returned_slug": "alpha/other-model"},
            {},
            "frozen canonical model",
        ),
        (
            {"selected_model_slug": "alpha/other-model"},
            {},
            "frozen canonical model",
        ),
        (
            {"actual_provider_endpoint": "approved-provider/base"},
            {},
            "endpoint variant",
        ),
        (
            {"actual_provider_name": "Other Provider"},
            {},
            "frozen endpoint",
        ),
        (
            {"fallback_used": True},
            {},
            "fallback execution",
        ),
        (
            {},
            {"execution_evidence": "mock"},
            "execution evidence differ",
        ),
        (
            {},
            {"generation_id": "generation-identity-2"},
            "response generation ID",
        ),
        (
            {},
            {"generation_model_slug": "alpha/other-model"},
            "frozen canonical model",
        ),
        (
            {},
            {"provider_name": "Other Provider"},
            "frozen endpoint",
        ),
        (
            {},
            {"retrieved_at": _STARTED},
            "after completion",
        ),
    ],
)
def test_bound_identity_fails_closed_on_model_endpoint_or_generation_mismatch(
    request_updates: dict[str, Any],
    generation_updates: dict[str, Any],
    error: str,
) -> None:
    with pytest.raises(ValidationError, match=error):
        seal_bound_openrouter_identity(
            snapshot=_snapshot(),
            request=_request(**request_updates),
            generation=_generation(**generation_updates),
            evaluated_at=_EVALUATED,
        )


def test_bound_identity_rejects_expired_snapshot() -> None:
    with pytest.raises(ValidationError, match="expired identity snapshot"):
        seal_bound_openrouter_identity(
            snapshot=_snapshot(expires_at=_COMPLETED),
            request=_request(),
            generation=_generation(),
            evaluated_at=_EVALUATED,
        )


def test_unbound_result_preserves_request_evidence_without_generation_binding() -> None:
    result = seal_unbound_openrouter_identity(
        snapshot=_snapshot(),
        request=_request(),
        diagnostic_codes=(OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,),
        evaluated_at=_EVALUATED,
    )

    assert result.strength is OpenRouterIdentityStrength.UNBOUND
    assert result.generation is None
    assert result.request.validated_response_sha256 == "a" * 64
    assert result.diagnostic_codes == (
        OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,
    )


def test_unbound_result_rejects_generation_binding_or_missing_diagnostic() -> None:
    result = seal_unbound_openrouter_identity(
        snapshot=_snapshot(),
        request=_request(),
        diagnostic_codes=(OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING,),
        evaluated_at=_EVALUATED,
    )
    with_generation = result.model_dump(mode="json")
    with_generation["generation"] = _generation().model_dump(mode="json")

    with pytest.raises(ValidationError, match="cannot contain generation"):
        OpenRouterIdentityBindingResult.model_validate(with_generation)
    with pytest.raises(ValidationError, match="requires a non-secret diagnostic"):
        seal_unbound_openrouter_identity(
            snapshot=_snapshot(),
            request=_request(),
            diagnostic_codes=(),
            evaluated_at=_EVALUATED,
        )


def test_diagnostics_are_enum_bounded_sorted_and_unique() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        seal_unbound_openrouter_identity(
            snapshot=_snapshot(),
            request=_request(),
            diagnostic_codes=(
                OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH,
                OpenRouterIdentityDiagnosticCode.MODEL_ALIAS_UNRECOGNIZED,
            ),
            evaluated_at=_EVALUATED,
        )

    payload = seal_unbound_openrouter_identity(
        snapshot=_snapshot(),
        request=_request(),
        diagnostic_codes=(OpenRouterIdentityDiagnosticCode.PROVIDER_MISMATCH,),
        evaluated_at=_EVALUATED,
    ).model_dump(mode="json")
    payload["diagnostic_codes"] = ["provider supplied arbitrary secret text"]
    with pytest.raises(ValidationError):
        OpenRouterIdentityBindingResult.model_validate(payload)


def test_policy_and_binding_hashes_fail_closed_and_extra_fields_are_forbidden() -> None:
    policy = _policy().model_dump(mode="json")
    policy["policy_sha256"] = "d" * 64
    with pytest.raises(ValidationError, match="policy hash"):
        OpenRouterIdentityProviderPolicy.model_validate(policy)

    result = seal_bound_openrouter_identity(
        snapshot=_snapshot(),
        request=_request(),
        generation=_generation(),
        evaluated_at=_EVALUATED,
    )
    payload = result.model_dump(mode="json")
    payload["binding_sha256"] = "e" * 64
    with pytest.raises(ValidationError, match="binding hash"):
        OpenRouterIdentityBindingResult.model_validate(payload)

    snapshot_payload = _snapshot().model_dump(mode="json")
    snapshot_payload["authorization"] = "forbidden"
    with pytest.raises(ValidationError, match="Extra inputs"):
        OpenRouterModelEndpointIdentitySnapshot.model_validate(snapshot_payload)


def test_endpoint_capabilities_and_pricing_are_non_vacuous_and_canonical() -> None:
    values = _capabilities().model_dump(mode="python")
    values["reasoning_supported"] = False
    with pytest.raises(ValidationError, match="reasoning capability"):
        OpenRouterIdentityEndpointCapabilities.model_validate(values)

    with pytest.raises(ValidationError, match="canonical non-negative decimal"):
        OpenRouterIdentityPricingEntry(unit="prompt", usd_per_unit="0.0000030")
