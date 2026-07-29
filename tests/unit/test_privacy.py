from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
import traceback
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.privacy import (
    MAXIMUM_CONSENT_COST_USD,
    REQUIRED_PROHIBITED_CONTENT,
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    EndpointPrivacyDisclosure,
    PrivacyProfile,
    PrivacyRetentionConsent,
    PrivacyRetentionConsentObservation,
    PrivacySourceClassification,
    TrustedPrivacyAuthorization,
    load_privacy_retention_consent,
    resolve_effective_privacy_policy,
    resolve_trusted_privacy_authorization,
    validate_trusted_privacy_authorization,
)

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
SOURCE_SHA256 = "a" * 64
MODELS = ("anthropic/claude-opus-4.1", "openai/gpt-5")
PROVIDERS = ("anthropic:claude", "openai:gpt")


def _canonical_sha256(value: object) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def _disclosures(
    *,
    providers: tuple[str, ...] = PROVIDERS,
    policy_class: EndpointPolicyClass = EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
) -> tuple[EndpointPrivacyDisclosure, ...]:
    return tuple(
        EndpointPrivacyDisclosure(
            provider_endpoint=provider,
            policy_class=policy_class,
            disclosed_retention=f"Operator-reviewed retention terms for {provider}.",
            privacy_policy_reference=f"https://privacy.example.test/{index}",
            privacy_policy_sha256=f"{index + 1:064x}",
        )
        for index, provider in enumerate(providers)
    )


def _consent_payload(
    *,
    profile: PrivacyProfile = PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
    source_classification: PrivacySourceClassification = (
        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
    ),
    source_sha256: str = SOURCE_SHA256,
    models: tuple[str, ...] = MODELS,
    providers: tuple[str, ...] = PROVIDERS,
    policy_class: EndpointPolicyClass = EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
    issued_at: datetime = NOW - timedelta(hours=1),
    expires_at: datetime = NOW + timedelta(hours=1),
    maximum_cost_usd: str = "25",
) -> dict[str, Any]:
    disclosures = _disclosures(providers=providers, policy_class=policy_class)
    provisional = PrivacyRetentionConsent.model_construct(
        schema_version="1.0",
        selected_privacy_profile=profile,
        source_classification=source_classification,
        permitted_source_sha256=source_sha256,
        permitted_model_ids=models,
        permitted_provider_endpoints=providers,
        permitted_endpoint_policy_classes=(policy_class,),
        endpoint_disclosures=disclosures,
        issued_at=issued_at,
        expires_at=expires_at,
        operator_identity_reference="operator-record:corrovera-release",
        signature_reference=None,
        maximum_cost_usd=maximum_cost_usd,
        prohibited_content=REQUIRED_PROHIBITED_CONTENT,
        acknowledges_zdr_not_in_force=(
            policy_class is EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED
        ),
        consent_sha256="0" * 64,
    )
    return provisional.model_dump(mode="json", exclude={"consent_sha256"})


def _consent(**kwargs: Any) -> PrivacyRetentionConsent:
    payload = _consent_payload(**kwargs)
    return PrivacyRetentionConsent.model_validate(
        {
            **payload,
            "consent_sha256": _canonical_sha256(payload),
        }
    )


def _write_consent(path: Path, consent: PrivacyRetentionConsent) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(consent.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _observation(
    tmp_path: Path,
    *,
    consent: PrivacyRetentionConsent | None = None,
) -> tuple[Path, PrivacyRetentionConsentObservation]:
    target_root = tmp_path / "target"
    target_root.mkdir()
    consent_path = tmp_path / "operator-control" / "privacy-consent.json"
    _write_consent(consent_path, consent or _consent())
    return target_root, load_privacy_retention_consent(
        consent_path,
        target_root=target_root,
    )


def _frontier_resolution_kwargs(
    observation: PrivacyRetentionConsentObservation,
) -> dict[str, Any]:
    return {
        "profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
        "require_zdr": False,
        "consent_observation": observation,
        "source_sha256": SOURCE_SHA256,
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "configured_model_ids": MODELS,
        "configured_provider_endpoints": PROVIDERS,
        "requested_budget_usd": Decimal("20"),
        "now": NOW,
    }


def _serialized_exception_projection(error: BaseException) -> str:
    return json.dumps(
        {
            "type": type(error).__name__,
            "args": error.args,
            "message": str(error),
            "repr": repr(error),
            "cause": repr(error.__cause__),
            "context": repr(error.__context__),
            "traceback": "".join(traceback.format_exception(error)),
        },
        default=repr,
        sort_keys=True,
    )


def test_privacy_vocabulary_and_fixed_policy_are_exact() -> None:
    assert tuple(PrivacyProfile) == (
        PrivacyProfile.STRICT_ZDR,
        PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
        PrivacyProfile.SYNTHETIC_BENCHMARK,
    )
    assert tuple(PrivacySourceClassification) == (
        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    )
    assert tuple(EndpointPolicyClass) == (
        EndpointPolicyClass.ZDR,
        EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
    )
    assert REQUIRED_PROHIBITED_CONTENT == (
        "credentials",
        "excluded_content",
        "operator_secrets",
    )
    assert Decimal("250") == MAXIMUM_CONSENT_COST_USD


def test_consent_is_strict_self_hashed_and_binds_complete_disclosures() -> None:
    consent = _consent()
    assert consent.maximum_cost == Decimal("25")
    assert consent.permitted_provider_endpoints == tuple(
        item.provider_endpoint for item in consent.endpoint_disclosures
    )

    tampered = consent.model_dump(mode="json")
    tampered["permitted_source_sha256"] = "b" * 64
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        PrivacyRetentionConsent.model_validate(tampered)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"maximum_cost_usd": "250.0"}, "canonical positive decimal"),
        ({"maximum_cost_usd": "250.01"}, "aggregate provider budget"),
        ({"prohibited_content": ["credentials", "excluded_content", "wallets"]}, "fixed policy"),
        ({"acknowledges_zdr_not_in_force": False}, "true exactly when non-ZDR"),
        ({"operator_identity_reference": None, "signature_reference": None}, "operator identity"),
        (
            {"permitted_provider_endpoints": ["openai:gpt", "anthropic:claude"]},
            "unique and sorted",
        ),
        (
            {"permitted_model_ids": ["openai/auto", "openai/gpt-5"]},
            "exact non-routed",
        ),
    ],
)
def test_consent_rejects_noncanonical_or_incomplete_authority(
    mutation: dict[str, object],
    message: str,
) -> None:
    payload = _consent_payload()
    payload.update(mutation)
    payload["consent_sha256"] = _canonical_sha256(payload)
    with pytest.raises(ValidationError, match=message):
        PrivacyRetentionConsent.model_validate(payload)


def test_consent_rejects_wrong_profile_source_and_disclosure_bindings() -> None:
    strict = _consent_payload(profile=PrivacyProfile.STRICT_ZDR)
    strict["consent_sha256"] = _canonical_sha256(strict)
    with pytest.raises(ValidationError, match="strict ZDR"):
        PrivacyRetentionConsent.model_validate(strict)

    synthetic_private = _consent_payload(profile=PrivacyProfile.SYNTHETIC_BENCHMARK)
    synthetic_private["consent_sha256"] = _canonical_sha256(synthetic_private)
    with pytest.raises(ValidationError, match="cannot authorize private source"):
        PrivacyRetentionConsent.model_validate(synthetic_private)

    incomplete = _consent_payload()
    incomplete["endpoint_disclosures"] = incomplete["endpoint_disclosures"][:1]
    incomplete["consent_sha256"] = _canonical_sha256(incomplete)
    with pytest.raises(ValidationError, match="exactly cover permitted providers"):
        PrivacyRetentionConsent.model_validate(incomplete)


@pytest.mark.parametrize(
    "reference",
    [
        "https://privacy.example.test/terms?revision=7",
        "https://privacy.example.test/terms#retention",
        "https://operator@privacy.example.test/terms",
        "https://operator:secret@privacy.example.test/terms",
    ],
)
def test_privacy_policy_reference_rejects_noncanonical_persisted_url(
    reference: str,
) -> None:
    with pytest.raises(ValidationError, match="without credentials, query, or fragment"):
        EndpointPrivacyDisclosure(
            provider_endpoint="openai:gpt",
            policy_class=EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
            disclosed_retention="Operator-reviewed retention terms.",
            privacy_policy_reference=reference,
            privacy_policy_sha256="1" * 64,
        )


def test_zdr_acknowledgement_is_false_when_non_zdr_is_not_authorized() -> None:
    consent = _consent(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        policy_class=EndpointPolicyClass.ZDR,
    )
    assert consent.acknowledges_zdr_not_in_force is False

    payload = consent.model_dump(mode="json")
    payload["acknowledges_zdr_not_in_force"] = True
    payload["consent_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "consent_sha256"}
    )
    with pytest.raises(ValidationError, match="true exactly when non-ZDR"):
        PrivacyRetentionConsent.model_validate(payload)

    non_boolean = _consent_payload()
    non_boolean["acknowledges_zdr_not_in_force"] = 1
    non_boolean["consent_sha256"] = _canonical_sha256(non_boolean)
    with pytest.raises(ValidationError, match="explicit boolean"):
        PrivacyRetentionConsent.model_validate(non_boolean)


def test_loader_returns_only_path_free_descriptor_safe_evidence(tmp_path: Path) -> None:
    target_root, observation = _observation(tmp_path)
    consent_path = tmp_path / "operator-control" / "privacy-consent.json"
    content = consent_path.read_bytes()

    assert observation.file_sha256 == hashlib.sha256(content).hexdigest()
    assert observation.file_size == len(content)
    assert observation.consent == _consent()
    assert not hasattr(observation, "path")
    assert str(consent_path) not in repr(observation)
    assert target_root.exists()


def test_loader_rejects_relative_in_target_linked_shared_and_writable_files(
    tmp_path: Path,
) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    external = tmp_path / "operator-control" / "privacy-consent.json"
    _write_consent(external, _consent())

    with pytest.raises(ValueError, match="explicit and absolute"):
        load_privacy_retention_consent(Path("privacy-consent.json"), target_root=target_root)

    internal = target_root / "privacy-consent.json"
    _write_consent(internal, _consent())
    with pytest.raises(ValueError, match="outside the target"):
        load_privacy_retention_consent(internal, target_root=target_root)

    linked = tmp_path / "linked-consent.json"
    linked.symlink_to(external)
    with pytest.raises(ValueError, match="unshared regular file"):
        load_privacy_retention_consent(linked, target_root=target_root)

    writable = tmp_path / "writable-consent.json"
    _write_consent(writable, _consent())
    writable.chmod(0o660)
    with pytest.raises(ValueError, match="group/world writable"):
        load_privacy_retention_consent(writable, target_root=target_root)

    shared = tmp_path / "shared-consent.json"
    os.link(external, shared)
    with pytest.raises(ValueError, match="unshared regular file"):
        load_privacy_retention_consent(shared, target_root=target_root)


def test_loader_rejects_linked_parent_and_malformed_json(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    control = tmp_path / "operator-control"
    external = control / "privacy-consent.json"
    _write_consent(external, _consent())

    linked_parent = tmp_path / "linked-control"
    linked_parent.symlink_to(control, target_is_directory=True)
    with pytest.raises(ValueError, match="may not traverse a link"):
        load_privacy_retention_consent(
            linked_parent / external.name,
            target_root=target_root,
        )

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"not":"consent"}', encoding="utf-8")
    malformed.chmod(0o600)
    with pytest.raises(ValueError, match="invalid"):
        load_privacy_retention_consent(malformed, target_root=target_root)


def test_loader_sanitizes_missing_path_from_exception_state(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    control = tmp_path / "operator-control"
    control.mkdir()
    path_canary = "PRIVATE_OPERATOR_PATH_CANARY_7B2F"
    missing = control / f"{path_canary}.json"

    with pytest.raises(ValueError, match="unavailable") as caught:
        load_privacy_retention_consent(missing, target_root=target_root)

    serialized = _serialized_exception_projection(caught.value)
    assert path_canary not in serialized
    assert str(missing) not in serialized
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "content",
    [
        b'{"operator_identity_reference":"MALFORMED_CONTENT_CANARY_6D31"}',
        b'{"broken":"MALFORMED_CONTENT_CANARY_6D31"',
    ],
)
def test_loader_sanitizes_malformed_content_from_exception_state(
    tmp_path: Path,
    content: bytes,
) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    consent_path = tmp_path / "operator-control" / "privacy-consent.json"
    consent_path.parent.mkdir()
    consent_path.write_bytes(content)
    consent_path.chmod(0o600)

    with pytest.raises(ValueError) as caught:
        load_privacy_retention_consent(consent_path, target_root=target_root)

    serialized = _serialized_exception_projection(caught.value)
    assert "MALFORMED_CONTENT_CANARY_6D31" not in serialized
    assert str(consent_path) not in serialized
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_strict_policy_is_default_safe_shape_and_rejects_consent(tmp_path: Path) -> None:
    evidence = resolve_effective_privacy_policy(
        profile=PrivacyProfile.STRICT_ZDR,
        require_zdr=True,
        consent_observation=None,
        source_sha256=SOURCE_SHA256,
        source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        configured_model_ids=MODELS,
        configured_provider_endpoints=PROVIDERS,
        requested_budget_usd=Decimal("20"),
        now=NOW,
    )
    assert evidence.privacy_profile is PrivacyProfile.STRICT_ZDR
    assert evidence.require_zdr is True
    assert evidence.endpoint_policy_classes == (EndpointPolicyClass.ZDR,)
    assert evidence.endpoint_disclosures == ()
    assert evidence.consent_sha256 is None
    assert EffectivePrivacyPolicyEvidence.model_validate(evidence.model_dump()) == evidence

    _, observation = _observation(tmp_path)
    with pytest.raises(ValueError, match="rejects retention-consent"):
        resolve_effective_privacy_policy(
            profile=PrivacyProfile.STRICT_ZDR,
            require_zdr=True,
            consent_observation=observation,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )
    with pytest.raises(ValueError, match="cannot be downgraded"):
        resolve_effective_privacy_policy(
            profile=PrivacyProfile.STRICT_ZDR,
            require_zdr=False,
            consent_observation=None,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )


def test_frontier_policy_resolves_exact_consent_bound_evidence(tmp_path: Path) -> None:
    _, observation = _observation(tmp_path)
    evidence = resolve_effective_privacy_policy(**_frontier_resolution_kwargs(observation))

    assert evidence.privacy_profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT
    assert evidence.source_sha256 == SOURCE_SHA256
    assert evidence.data_collection == "deny"
    assert evidence.require_zdr is False
    assert evidence.permitted_model_ids == MODELS
    assert evidence.permitted_provider_endpoints == PROVIDERS
    assert evidence.endpoint_disclosures == observation.consent.endpoint_disclosures
    assert evidence.consent_file_sha256 == observation.file_sha256
    assert evidence.consent_sha256 == observation.consent.consent_sha256
    assert evidence.requested_budget_usd == "20"
    assert EffectivePrivacyPolicyEvidence.model_validate(evidence.model_dump()) == evidence


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"source_sha256": "b" * 64}, "different source hash"),
        (
            {"source_classification": PrivacySourceClassification.PUBLIC_BENCHMARK},
            "different source classification",
        ),
        ({"configured_model_ids": ("openai/gpt-5",)}, "model set differs"),
        ({"configured_provider_endpoints": ("openai:gpt",)}, "provider set differs"),
        ({"requested_budget_usd": Decimal("26")}, "exceeds the consent maximum"),
        ({"now": NOW - timedelta(hours=2)}, "not yet effective"),
        ({"now": NOW + timedelta(hours=2)}, "has expired"),
        ({"require_zdr": True}, "only ZDR-class"),
    ],
)
def test_frontier_policy_rejects_mismatched_consent_bindings(
    tmp_path: Path,
    override: dict[str, object],
    message: str,
) -> None:
    _, observation = _observation(tmp_path)
    arguments = _frontier_resolution_kwargs(observation)
    arguments.update(override)
    with pytest.raises(ValueError, match=message):
        resolve_effective_privacy_policy(**arguments)


@pytest.mark.parametrize(
    "source_classification",
    [
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    ],
)
def test_synthetic_consent_cannot_replace_trusted_source_provenance(
    tmp_path: Path,
    source_classification: PrivacySourceClassification,
) -> None:
    consent = _consent(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        source_classification=source_classification,
        policy_class=EndpointPolicyClass.ZDR,
    )
    _, observation = _observation(tmp_path, consent=consent)
    with pytest.raises(ValueError, match="trusted source-provenance observation"):
        resolve_effective_privacy_policy(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=True,
            consent_observation=observation,
            source_sha256=SOURCE_SHA256,
            source_classification=source_classification,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )


@pytest.mark.parametrize(
    "source_classification",
    [
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    ],
)
def test_synthetic_zdr_still_requires_trusted_source_provenance(
    source_classification: PrivacySourceClassification,
) -> None:
    with pytest.raises(ValueError, match="trusted source-provenance observation"):
        resolve_effective_privacy_policy(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=True,
            consent_observation=None,
            source_sha256=SOURCE_SHA256,
            source_classification=source_classification,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )


def test_synthetic_non_zdr_consent_cannot_replace_publication_provenance(
    tmp_path: Path,
) -> None:
    consent = _consent(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        source_classification=PrivacySourceClassification.PUBLIC_BENCHMARK,
    )
    _, observation = _observation(tmp_path, consent=consent)
    with pytest.raises(ValueError, match="trusted source-provenance observation"):
        resolve_effective_privacy_policy(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=False,
            consent_observation=observation,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PUBLIC_BENCHMARK,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )


def test_non_strict_resolver_rejects_reconstructed_observation(tmp_path: Path) -> None:
    _, observation = _observation(tmp_path)
    with pytest.raises(TypeError, match="trusted loader"):
        PrivacyRetentionConsentObservation(
            file_sha256=observation.file_sha256,
            file_size=observation.file_size,
            consent=observation.consent,
        )

    reconstructed = PrivacyRetentionConsentObservation(
        file_sha256=observation.file_sha256,
        file_size=observation.file_size,
        consent=observation.consent,
        _issuer=observation._issuer,
    )
    with pytest.raises(ValueError, match="not issued in this process"):
        resolve_effective_privacy_policy(**_frontier_resolution_kwargs(reconstructed))


@pytest.mark.parametrize(
    "mutation",
    [
        "file_sha256",
        "file_size",
        "consent_replacement",
        "consent_content",
    ],
)
def test_live_observation_rejects_object_setattr_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    _, observation = _observation(tmp_path)
    if mutation == "file_sha256":
        object.__setattr__(observation, "file_sha256", "b" * 64)
    elif mutation == "file_size":
        object.__setattr__(observation, "file_size", observation.file_size + 1)
    elif mutation == "consent_replacement":
        object.__setattr__(observation, "consent", _consent(maximum_cost_usd="24"))
    else:
        object.__setattr__(observation.consent, "maximum_cost_usd", "24")

    with pytest.raises(ValueError, match="binding is inconsistent"):
        resolve_effective_privacy_policy(**_frontier_resolution_kwargs(observation))


def test_trusted_authorization_is_live_exact_and_nonserializable(tmp_path: Path) -> None:
    _, observation = _observation(tmp_path)
    arguments = _frontier_resolution_kwargs(observation)
    authorization = resolve_trusted_privacy_authorization(**arguments)
    evidence = authorization.evidence

    assert (
        validate_trusted_privacy_authorization(
            authorization,
            evidence_sha256=evidence.evidence_sha256,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )
        == evidence
    )
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(authorization)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(authorization)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authorization)
    with pytest.raises(TypeError):
        json.dumps(authorization)


@pytest.mark.parametrize(
    "override",
    [
        {"evidence_sha256": "b" * 64},
        {"source_sha256": "b" * 64},
        {"source_classification": PrivacySourceClassification.PUBLIC_BENCHMARK},
        {"configured_model_ids": ("openai/gpt-5",)},
        {"configured_provider_endpoints": ("openai:gpt",)},
        {"requested_budget_usd": Decimal("19")},
        {"now": NOW + timedelta(hours=2)},
    ],
)
def test_trusted_authorization_rejects_request_drift(
    tmp_path: Path,
    override: dict[str, object],
) -> None:
    _, observation = _observation(tmp_path)
    authorization = resolve_trusted_privacy_authorization(
        **_frontier_resolution_kwargs(observation)
    )
    arguments: dict[str, Any] = {
        "evidence_sha256": authorization.evidence.evidence_sha256,
        "source_sha256": SOURCE_SHA256,
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "configured_model_ids": MODELS,
        "configured_provider_endpoints": PROVIDERS,
        "requested_budget_usd": Decimal("20"),
        "now": NOW,
    }
    arguments.update(override)
    with pytest.raises(ValueError):
        validate_trusted_privacy_authorization(authorization, **arguments)


def test_reconstructed_evidence_cannot_forge_trusted_authorization(tmp_path: Path) -> None:
    _, observation = _observation(tmp_path)
    issued = resolve_trusted_privacy_authorization(**_frontier_resolution_kwargs(observation))
    reconstructed = EffectivePrivacyPolicyEvidence.model_validate(
        issued.evidence.model_dump(mode="json")
    )
    forged = object.__new__(TrustedPrivacyAuthorization)
    forged._evidence = reconstructed

    with pytest.raises(ValueError, match="not issued in this process"):
        validate_trusted_privacy_authorization(
            forged,
            evidence_sha256=reconstructed.evidence_sha256,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "evidence_replacement",
        "source_sha256",
        "permitted_model_ids",
        "permitted_provider_endpoints",
        "requested_budget_usd",
        "consent_expires_at",
        "endpoint_disclosure",
    ],
)
def test_live_authorization_rejects_object_setattr_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    _, observation = _observation(tmp_path)
    authorization = resolve_trusted_privacy_authorization(
        **_frontier_resolution_kwargs(observation)
    )
    original = authorization.evidence
    if mutation == "evidence_replacement":
        object.__setattr__(
            authorization,
            "_evidence",
            EffectivePrivacyPolicyEvidence.model_validate(original.model_dump()),
        )
    elif mutation == "source_sha256":
        object.__setattr__(original, "source_sha256", "b" * 64)
    elif mutation == "permitted_model_ids":
        object.__setattr__(original, "permitted_model_ids", ("openai/gpt-5",))
    elif mutation == "permitted_provider_endpoints":
        object.__setattr__(original, "permitted_provider_endpoints", ("openai:gpt",))
    elif mutation == "requested_budget_usd":
        object.__setattr__(original, "requested_budget_usd", "19")
    elif mutation == "consent_expires_at":
        object.__setattr__(original, "consent_expires_at", NOW + timedelta(hours=2))
    else:
        object.__setattr__(
            original.endpoint_disclosures[0],
            "disclosed_retention",
            "Tampered retention disclosure.",
        )

    with pytest.raises(ValueError, match="binding is inconsistent"):
        validate_trusted_privacy_authorization(
            authorization,
            evidence_sha256=original.evidence_sha256,
            source_sha256=SOURCE_SHA256,
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
            configured_model_ids=MODELS,
            configured_provider_endpoints=PROVIDERS,
            requested_budget_usd=Decimal("20"),
            now=NOW,
        )
