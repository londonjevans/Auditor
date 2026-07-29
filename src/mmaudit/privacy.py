"""Typed, fail-closed privacy authorization for provider-visible source.

Consent evidence is deliberately separate from normal audit configuration.  A
non-ZDR request is authorized only by a descriptor-safe observation of an
operator-controlled consent file and an opaque process-local capability issued
for the exact effective policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import weakref
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import require_exact_openrouter_model_id

if TYPE_CHECKING:
    from mmaudit.repository.privacy_provenance import (
        PrivacySourceProvenanceEvidence,
        PrivacySourceProvenanceObservation,
    )

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PROVIDER_ENDPOINT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_MAX_CONSENT_BYTES = 262_144
MAXIMUM_CONSENT_COST_USD = Decimal("250")
REQUIRED_PROHIBITED_CONTENT = (
    "credentials",
    "excluded_content",
    "operator_secrets",
)
_TRUSTED_OBSERVATION_ISSUER = object()
_AUTHORIZATION_LOCK = threading.Lock()


class PrivacyProfile(StrEnum):
    """Explicit source-disclosure policy selected for one provider campaign."""

    STRICT_ZDR = "STRICT_ZDR"
    FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT = "FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT"
    SYNTHETIC_BENCHMARK = "SYNTHETIC_BENCHMARK"


class PrivacySourceClassification(StrEnum):
    """Operator-controlled classification of the provider-visible source scope."""

    PRIVATE_OPERATOR_SOURCE = "PRIVATE_OPERATOR_SOURCE"
    SYNTHETIC_COMMITTED = "SYNTHETIC_COMMITTED"
    PUBLIC_BENCHMARK = "PUBLIC_BENCHMARK"


class EndpointPolicyClass(StrEnum):
    """Retention class independently disclosed for an exact provider endpoint."""

    ZDR = "ZDR"
    NON_ZDR_DATA_COLLECTION_DENIED = "NON_ZDR_DATA_COLLECTION_DENIED"


class EndpointPrivacyDisclosure(BaseModel):
    """Bounded operator-reviewed privacy disclosure for one exact endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_endpoint: str = Field(min_length=1, max_length=200)
    policy_class: EndpointPolicyClass
    disclosed_retention: str = Field(min_length=1, max_length=2_000)
    privacy_policy_reference: str = Field(min_length=9, max_length=2_048)
    privacy_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("provider_endpoint")
    @classmethod
    def endpoint_is_exact(cls, value: str) -> str:
        return _validate_provider_endpoint(value)

    @field_validator("disclosed_retention")
    @classmethod
    def retention_is_bounded_printable_text(cls, value: str) -> str:
        return _validate_printable_reference(value, label="disclosed retention")

    @field_validator("privacy_policy_reference")
    @classmethod
    def policy_reference_is_https(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("privacy policy reference must be canonical printable text")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "privacy policy reference must be an HTTPS URL without credentials, "
                "query, or fragment"
            )
        return value


class PrivacyRetentionConsent(BaseModel):
    """Self-hashed operator-authored authorization for one non-strict source scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    selected_privacy_profile: PrivacyProfile
    source_classification: PrivacySourceClassification
    permitted_source_sha256: str = Field(pattern=_SHA256_PATTERN)
    permitted_model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    permitted_provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=128)
    permitted_endpoint_policy_classes: tuple[EndpointPolicyClass, ...] = Field(
        min_length=1,
        max_length=2,
    )
    endpoint_disclosures: tuple[EndpointPrivacyDisclosure, ...] = Field(
        min_length=1,
        max_length=128,
    )
    issued_at: datetime
    expires_at: datetime
    operator_identity_reference: str | None = Field(default=None, min_length=1, max_length=500)
    signature_reference: str | None = Field(default=None, min_length=1, max_length=2_048)
    maximum_cost_usd: str = Field(min_length=1, max_length=32)
    prohibited_content: tuple[str, ...] = Field(min_length=3, max_length=3)
    acknowledges_zdr_not_in_force: bool
    consent_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("permitted_model_ids")
    @classmethod
    def models_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_model_ids(value, label="consent models")

    @field_validator("permitted_provider_endpoints")
    @classmethod
    def endpoints_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_provider_endpoints(value, label="consent provider endpoints")

    @field_validator("permitted_endpoint_policy_classes")
    @classmethod
    def policy_classes_are_sorted_unique(
        cls,
        value: tuple[EndpointPolicyClass, ...],
    ) -> tuple[EndpointPolicyClass, ...]:
        return _validate_policy_classes(value)

    @field_validator("endpoint_disclosures")
    @classmethod
    def disclosures_are_sorted_unique(
        cls,
        value: tuple[EndpointPrivacyDisclosure, ...],
    ) -> tuple[EndpointPrivacyDisclosure, ...]:
        endpoints = tuple(item.provider_endpoint for item in value)
        if endpoints != tuple(sorted(set(endpoints))):
            raise ValueError("endpoint privacy disclosures must be unique and sorted")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def consent_times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _validate_utc_second(value, label="consent timestamp")

    @field_validator("operator_identity_reference", "signature_reference")
    @classmethod
    def operator_references_are_bounded(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        return _validate_printable_reference(value, label="operator reference")

    @field_validator("maximum_cost_usd")
    @classmethod
    def maximum_cost_is_canonical_and_bounded(cls, value: str) -> str:
        parsed = _parse_canonical_positive_cost(value, label="consent maximum cost")
        if parsed > MAXIMUM_CONSENT_COST_USD:
            raise ValueError("consent maximum cost exceeds the aggregate provider budget")
        return value

    @field_validator("prohibited_content")
    @classmethod
    def prohibited_content_is_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != REQUIRED_PROHIBITED_CONTENT:
            raise ValueError("consent prohibited content does not match the required fixed policy")
        return value

    @field_validator("acknowledges_zdr_not_in_force", mode="before")
    @classmethod
    def zdr_acknowledgement_is_explicit_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("consent ZDR acknowledgement must be an explicit boolean")
        return value

    @model_validator(mode="after")
    def consent_is_coherent_and_self_hashed(self) -> Self:
        if self.selected_privacy_profile is PrivacyProfile.STRICT_ZDR:
            raise ValueError("strict ZDR does not accept a retention-consent artifact")
        if (
            self.selected_privacy_profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT
            and self.source_classification
            is not PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
        ):
            raise ValueError("frontier retention consent must bind private operator source")
        if (
            self.selected_privacy_profile is PrivacyProfile.SYNTHETIC_BENCHMARK
            and self.source_classification
            not in {
                PrivacySourceClassification.SYNTHETIC_COMMITTED,
                PrivacySourceClassification.PUBLIC_BENCHMARK,
            }
        ):
            raise ValueError("synthetic benchmark consent cannot authorize private source")
        if self.expires_at <= self.issued_at:
            raise ValueError("consent expiry must follow its issue time")
        if self.operator_identity_reference is None and self.signature_reference is None:
            raise ValueError("consent requires an operator identity or signature reference")
        disclosure_endpoints = tuple(item.provider_endpoint for item in self.endpoint_disclosures)
        if disclosure_endpoints != self.permitted_provider_endpoints:
            raise ValueError("consent disclosures do not exactly cover permitted providers")
        disclosure_classes = tuple(
            sorted(
                {item.policy_class for item in self.endpoint_disclosures},
                key=lambda item: item.value,
            )
        )
        if disclosure_classes != self.permitted_endpoint_policy_classes:
            raise ValueError("consent disclosures do not exactly cover permitted policy classes")
        if (
            self.selected_privacy_profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT
            and EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED
            not in self.permitted_endpoint_policy_classes
        ):
            raise ValueError("frontier consent must cover at least one non-ZDR endpoint")
        non_zdr_authorized = (
            EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED
            in self.permitted_endpoint_policy_classes
        )
        if self.acknowledges_zdr_not_in_force is not non_zdr_authorized:
            raise ValueError(
                "consent ZDR acknowledgement must be true exactly when non-ZDR routing "
                "is authorized"
            )
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"consent_sha256"}))
        if self.consent_sha256 != expected:
            raise ValueError("privacy retention consent hash is inconsistent")
        return self

    @property
    def maximum_cost(self) -> Decimal:
        """Return the validated consent ceiling as an exact decimal."""

        return Decimal(self.maximum_cost_usd)


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class PrivacyRetentionConsentObservation:
    """Path-free descriptor-safe observation of one operator consent artifact."""

    file_sha256: str
    file_size: int
    consent: PrivacyRetentionConsent
    _issuer: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        file_sha256: str,
        file_size: int,
        consent: PrivacyRetentionConsent,
        _issuer: object | None = None,
    ) -> None:
        if _issuer is not _TRUSTED_OBSERVATION_ISSUER:
            raise TypeError("privacy consent observations are issued only by the trusted loader")
        object.__setattr__(self, "file_sha256", file_sha256)
        object.__setattr__(self, "file_size", file_size)
        object.__setattr__(self, "consent", consent)
        object.__setattr__(self, "_issuer", _issuer)


@dataclass(frozen=True, slots=True)
class _ObservationBinding:
    file_sha256: str
    file_size: int
    consent: PrivacyRetentionConsent = field(repr=False, compare=False)
    consent_content_sha256: str


@dataclass(frozen=True, slots=True)
class _ValidatedConsentObservation:
    file_sha256: str
    file_size: int
    consent: PrivacyRetentionConsent


class EffectivePrivacyPolicyEvidence(BaseModel):
    """Self-hashed non-secret projection of the policy effective for one source scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    privacy_profile: PrivacyProfile
    source_classification: PrivacySourceClassification
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_proof_kind: Literal[
        "PRIVATE_DEFAULT",
        "DISTRIBUTION_COMMITTED_SYNTHETIC",
        "PACKAGE_PINNED_SYNTHETIC",
    ]
    source_distribution_commit: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40,64}$",
    )
    source_distribution_scope: str | None = Field(default=None, min_length=1, max_length=1_024)
    source_synthetic_declaration_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    source_synthetic_declaration_entry_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    require_zdr: bool
    data_collection: Literal["deny"]
    permitted_model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    permitted_provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=128)
    endpoint_policy_classes: tuple[EndpointPolicyClass, ...] = Field(
        min_length=1,
        max_length=2,
    )
    endpoint_disclosures: tuple[EndpointPrivacyDisclosure, ...] = Field(max_length=128)
    consent_file_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    consent_file_size: int | None = Field(default=None, ge=1, le=_MAX_CONSENT_BYTES)
    consent_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    consent_issued_at: datetime | None = None
    consent_expires_at: datetime | None = None
    operator_reference_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    consent_maximum_cost_usd: str | None = Field(default=None, min_length=1, max_length=32)
    requested_budget_usd: str = Field(min_length=1, max_length=32)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=32)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("permitted_model_ids")
    @classmethod
    def evidence_models_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_model_ids(value, label="effective privacy models")

    @field_validator("permitted_provider_endpoints")
    @classmethod
    def evidence_endpoints_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_provider_endpoints(value, label="effective privacy provider endpoints")

    @field_validator("endpoint_policy_classes")
    @classmethod
    def evidence_policy_classes_are_canonical(
        cls,
        value: tuple[EndpointPolicyClass, ...],
    ) -> tuple[EndpointPolicyClass, ...]:
        return _validate_policy_classes(value)

    @field_validator("endpoint_disclosures")
    @classmethod
    def evidence_disclosures_are_canonical(
        cls,
        value: tuple[EndpointPrivacyDisclosure, ...],
    ) -> tuple[EndpointPrivacyDisclosure, ...]:
        endpoints = tuple(item.provider_endpoint for item in value)
        if endpoints != tuple(sorted(set(endpoints))):
            raise ValueError("effective endpoint disclosures must be unique and sorted")
        return value

    @field_validator("consent_issued_at", "consent_expires_at")
    @classmethod
    def evidence_consent_times_are_utc(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None
        return _validate_utc_second(value, label="effective consent timestamp")

    @field_validator("consent_maximum_cost_usd")
    @classmethod
    def evidence_consent_cost_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = _parse_canonical_positive_cost(value, label="effective consent maximum cost")
        if parsed > MAXIMUM_CONSENT_COST_USD:
            raise ValueError("effective consent maximum cost exceeds the aggregate budget")
        return value

    @field_validator("requested_budget_usd")
    @classmethod
    def evidence_requested_budget_is_canonical(cls, value: str) -> str:
        parsed = _parse_canonical_positive_cost(value, label="effective requested budget")
        if parsed > MAXIMUM_CONSENT_COST_USD:
            raise ValueError("effective requested budget exceeds the aggregate provider budget")
        return value

    @field_validator("limitations")
    @classmethod
    def evidence_limitations_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("effective privacy limitations must be unique and sorted")
        for item in value:
            _validate_printable_reference(item, label="effective privacy limitation")
        return value

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> Self:
        synthetic_provenance = (
            self.source_distribution_scope,
            self.source_synthetic_declaration_sha256,
            self.source_synthetic_declaration_entry_sha256,
        )
        if self.source_classification is PrivacySourceClassification.SYNTHETIC_COMMITTED:
            if (
                self.source_proof_kind
                not in {
                    "DISTRIBUTION_COMMITTED_SYNTHETIC",
                    "PACKAGE_PINNED_SYNTHETIC",
                }
                or any(value is None for value in synthetic_provenance)
                or (
                    self.source_proof_kind == "DISTRIBUTION_COMMITTED_SYNTHETIC"
                    and self.source_distribution_commit is None
                )
                or (
                    self.source_proof_kind == "PACKAGE_PINNED_SYNTHETIC"
                    and self.source_distribution_commit is not None
                )
            ):
                raise ValueError("synthetic privacy policy lacks approved source provenance")
        elif self.source_classification is PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE and (
            self.source_proof_kind != "PRIVATE_DEFAULT"
            or self.source_distribution_commit is not None
            or any(value is not None for value in synthetic_provenance)
        ):
            raise ValueError("private privacy policy cannot claim committed source provenance")
        elif self.source_classification is PrivacySourceClassification.PUBLIC_BENCHMARK:
            raise ValueError("public benchmark privacy policy lacks publication provenance")
        consent_values = (
            self.consent_file_sha256,
            self.consent_file_size,
            self.consent_sha256,
            self.consent_issued_at,
            self.consent_expires_at,
            self.operator_reference_sha256,
            self.consent_maximum_cost_usd,
        )
        has_any_consent_binding = any(value is not None for value in consent_values)
        has_complete_consent_binding = all(value is not None for value in consent_values)
        if self.privacy_profile is PrivacyProfile.STRICT_ZDR:
            if not self.require_zdr:
                raise ValueError("strict privacy evidence must require ZDR")
            if has_any_consent_binding:
                raise ValueError("strict privacy evidence cannot retain consent authority")
            if self.endpoint_policy_classes != (EndpointPolicyClass.ZDR,):
                raise ValueError("strict privacy evidence must use only the ZDR policy class")
            if self.endpoint_disclosures:
                raise ValueError("strict privacy evidence cannot claim consent disclosures")
        elif not has_any_consent_binding:
            if (
                self.privacy_profile is not PrivacyProfile.SYNTHETIC_BENCHMARK
                or not self.require_zdr
            ):
                raise ValueError(
                    "consent-free privacy evidence is limited to synthetic ZDR routing"
                )
            if self.endpoint_policy_classes != (EndpointPolicyClass.ZDR,):
                raise ValueError("consent-free synthetic evidence must use only ZDR")
            if self.endpoint_disclosures:
                raise ValueError("consent-free synthetic evidence cannot claim consent disclosures")
        else:
            if not has_complete_consent_binding:
                raise ValueError("non-strict privacy evidence requires complete consent bindings")
            disclosure_endpoints = tuple(
                item.provider_endpoint for item in self.endpoint_disclosures
            )
            if disclosure_endpoints != self.permitted_provider_endpoints:
                raise ValueError(
                    "effective privacy disclosures do not exactly cover permitted providers"
                )
            disclosure_classes = tuple(
                sorted(
                    {item.policy_class for item in self.endpoint_disclosures},
                    key=lambda item: item.value,
                )
            )
            if disclosure_classes != self.endpoint_policy_classes:
                raise ValueError(
                    "effective privacy disclosures do not exactly cover policy classes"
                )
            assert self.consent_maximum_cost_usd is not None
            if Decimal(self.requested_budget_usd) > Decimal(self.consent_maximum_cost_usd):
                raise ValueError("effective budget exceeds the consent maximum")
        if self.privacy_profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT and (
            self.source_classification is not PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
            or self.require_zdr
            or EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED
            not in self.endpoint_policy_classes
        ):
            raise ValueError("frontier privacy evidence is not a consent-bound non-ZDR route")
        if self.privacy_profile is PrivacyProfile.SYNTHETIC_BENCHMARK:
            if self.source_classification not in {
                PrivacySourceClassification.SYNTHETIC_COMMITTED,
                PrivacySourceClassification.PUBLIC_BENCHMARK,
            }:
                raise ValueError("synthetic privacy evidence cannot authorize private source")
            _validate_zdr_policy_classes(
                require_zdr=self.require_zdr,
                policy_classes=self.endpoint_policy_classes,
            )
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("effective privacy evidence hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _AuthorizationBinding:
    evidence: EffectivePrivacyPolicyEvidence = field(repr=False, compare=False)
    evidence_sha256: str
    evidence_content_sha256: str


class TrustedPrivacyAuthorization:
    """Opaque, process-local non-ZDR authority that cannot be serialized."""

    __slots__ = ("__weakref__", "_evidence")
    _evidence: EffectivePrivacyPolicyEvidence

    def __init__(self) -> None:
        raise TypeError("trusted privacy authorizations are issued by the privacy resolver")

    @property
    def evidence(self) -> EffectivePrivacyPolicyEvidence:
        """Return the non-secret evidence projection bound to this capability."""

        return self._evidence

    def __copy__(self) -> TrustedPrivacyAuthorization:
        raise TypeError("trusted privacy authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> TrustedPrivacyAuthorization:
        del memo
        raise TypeError("trusted privacy authorizations cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("trusted privacy authorizations cannot be serialized")


_LIVE_AUTHORIZATIONS: weakref.WeakKeyDictionary[
    TrustedPrivacyAuthorization,
    _AuthorizationBinding,
] = weakref.WeakKeyDictionary()
_LIVE_OBSERVATIONS: weakref.WeakKeyDictionary[
    PrivacyRetentionConsentObservation,
    _ObservationBinding,
] = weakref.WeakKeyDictionary()


def load_privacy_retention_consent(
    path: Path,
    *,
    target_root: Path,
    max_bytes: int = _MAX_CONSENT_BYTES,
) -> PrivacyRetentionConsentObservation:
    """Read one explicit external consent file without retaining its path."""

    from mmaudit.release_io import read_json_evidence

    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("privacy retention consent path must be explicit and absolute")
    if not isinstance(target_root, Path) or not target_root.is_absolute():
        raise ValueError("privacy consent target root must be explicit and absolute")
    if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_CONSENT_BYTES:
        raise ValueError("privacy retention consent byte bound is invalid")

    consent_path = _normalized_absolute_path(path, label="privacy retention consent")
    target = _validated_unlinked_directory(target_root, label="privacy consent target root")
    if consent_path == target or consent_path.is_relative_to(target):
        raise ValueError("privacy retention consent must remain outside the target repository")
    parent = _validated_unlinked_directory(
        consent_path.parent,
        label="privacy retention consent parent",
    )
    if parent == target or parent.is_relative_to(target):
        raise ValueError("privacy retention consent must remain outside the target repository")

    before = _validated_consent_file_metadata(consent_path, max_bytes=max_bytes)
    observation: Any = None
    read_failed = False
    try:
        observation = read_json_evidence(
            evidence_root=parent,
            relative_path=consent_path.name,
            max_bytes=max_bytes,
        )
    except Exception:
        read_failed = True
    if read_failed:
        raise ValueError("privacy retention consent could not be read safely")
    after = _validated_consent_file_metadata(consent_path, max_bytes=max_bytes)
    if _stat_identity(before) != _stat_identity(after):
        raise ValueError("privacy retention consent changed while it was observed")
    consent: PrivacyRetentionConsent | None = None
    validation_failed = False
    try:
        consent = PrivacyRetentionConsent.model_validate_json(
            observation.content,
            strict=True,
        )
    except Exception:
        validation_failed = True
    if validation_failed or consent is None:
        raise ValueError("privacy retention consent is invalid")
    issued_observation = PrivacyRetentionConsentObservation(
        file_sha256=observation.binding.sha256,
        file_size=observation.binding.size,
        consent=consent,
        _issuer=_TRUSTED_OBSERVATION_ISSUER,
    )
    with _AUTHORIZATION_LOCK:
        _LIVE_OBSERVATIONS[issued_observation] = _ObservationBinding(
            file_sha256=issued_observation.file_sha256,
            file_size=issued_observation.file_size,
            consent=consent,
            consent_content_sha256=_model_content_sha256(consent),
        )
    return issued_observation


def resolve_effective_privacy_policy(
    *,
    profile: PrivacyProfile,
    require_zdr: bool,
    consent_observation: PrivacyRetentionConsentObservation | None,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    source_provenance_observation: PrivacySourceProvenanceObservation | None = None,
    configured_model_ids: Sequence[str],
    configured_provider_endpoints: Sequence[str],
    requested_budget_usd: Decimal,
    now: datetime,
) -> EffectivePrivacyPolicyEvidence:
    """Resolve and self-hash the exact privacy policy without granting authority."""

    if not isinstance(profile, PrivacyProfile):
        raise ValueError("privacy profile must be a typed profile")
    if type(require_zdr) is not bool:
        raise ValueError("privacy ZDR selection must be explicit")
    if not isinstance(source_classification, PrivacySourceClassification):
        raise ValueError("privacy source classification must be typed")
    _validate_sha256(source_sha256, label="privacy source")
    models = _validate_model_ids(
        _sequence_tuple(configured_model_ids, label="configured model IDs"),
        label="configured model IDs",
    )
    providers = _validate_provider_endpoints(
        _sequence_tuple(
            configured_provider_endpoints,
            label="configured provider endpoints",
        ),
        label="configured provider endpoints",
    )
    requested_budget = _validate_requested_budget(requested_budget_usd)
    observed_at = _validate_utc_second(now, label="privacy policy evaluation time")

    consent: PrivacyRetentionConsent | None = None
    policy_classes: tuple[EndpointPolicyClass, ...]
    disclosures: tuple[EndpointPrivacyDisclosure, ...]
    consent_fields: dict[str, Any]
    limitations: tuple[str, ...]
    if profile is PrivacyProfile.STRICT_ZDR:
        if not require_zdr:
            raise ValueError("STRICT_ZDR cannot be downgraded")
        if consent_observation is not None:
            raise ValueError("STRICT_ZDR rejects retention-consent artifacts")
        policy_classes = (EndpointPolicyClass.ZDR,)
        disclosures = ()
        consent_fields = {
            "consent_file_sha256": None,
            "consent_file_size": None,
            "consent_sha256": None,
            "consent_issued_at": None,
            "consent_expires_at": None,
            "operator_reference_sha256": None,
            "consent_maximum_cost_usd": None,
        }
        limitations = ("STRICT_ZDR can exclude otherwise eligible non-ZDR frontier endpoints.",)
    elif (
        profile is PrivacyProfile.SYNTHETIC_BENCHMARK
        and require_zdr
        and consent_observation is None
    ):
        policy_classes = (EndpointPolicyClass.ZDR,)
        disclosures = ()
        consent_fields = {
            "consent_file_sha256": None,
            "consent_file_size": None,
            "consent_sha256": None,
            "consent_issued_at": None,
            "consent_expires_at": None,
            "operator_reference_sha256": None,
            "consent_maximum_cost_usd": None,
        }
        limitations = ("Synthetic or public benchmark source uses ZDR without retention consent.",)
    else:
        observation = _require_trusted_observation(consent_observation)
        consent = observation.consent
        if consent.selected_privacy_profile is not profile:
            raise ValueError("consent authorizes a different privacy profile")
        if consent.source_classification is not source_classification:
            raise ValueError("consent authorizes a different source classification")
        if consent.permitted_source_sha256 != source_sha256:
            raise ValueError("consent authorizes a different source hash")
        if consent.permitted_model_ids != models:
            raise ValueError("consent model set differs from the configured exact set")
        if consent.permitted_provider_endpoints != providers:
            raise ValueError("consent provider set differs from the configured exact set")
        if consent.issued_at > observed_at:
            raise ValueError("privacy retention consent is not yet effective")
        if consent.expires_at <= observed_at:
            raise ValueError("privacy retention consent has expired")
        if requested_budget > consent.maximum_cost:
            raise ValueError("requested provider budget exceeds the consent maximum")
        if consent.prohibited_content != REQUIRED_PROHIBITED_CONTENT:
            raise ValueError("consent prohibited-content policy is incomplete")
        policy_classes = consent.permitted_endpoint_policy_classes
        disclosures = consent.endpoint_disclosures
        _validate_zdr_policy_classes(
            require_zdr=require_zdr,
            policy_classes=policy_classes,
        )
        operator_reference_sha256 = _canonical_sha256(
            {
                "operator_identity_reference": consent.operator_identity_reference,
                "signature_reference": consent.signature_reference,
            }
        )
        consent_fields = {
            "consent_file_sha256": observation.file_sha256,
            "consent_file_size": observation.file_size,
            "consent_sha256": consent.consent_sha256,
            "consent_issued_at": consent.issued_at,
            "consent_expires_at": consent.expires_at,
            "operator_reference_sha256": operator_reference_sha256,
            "consent_maximum_cost_usd": consent.maximum_cost_usd,
        }
        limitations = (
            ("At least one consent-bound provider endpoint does not enforce zero-data-retention.")
            if not require_zdr
            else "Authorization is limited to the consent-bound benchmark source.",
        )

    if profile is PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT and (
        source_classification is not PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
        or require_zdr
    ):
        raise ValueError("frontier profile requires private source and explicit non-ZDR consent")
    if profile is PrivacyProfile.SYNTHETIC_BENCHMARK and source_classification not in {
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    }:
        raise ValueError("synthetic benchmark profile cannot authorize private source")
    source_provenance = _resolve_source_provenance(
        source_provenance_observation,
        source_sha256=source_sha256,
        source_classification=source_classification,
        observed_at=observed_at,
    )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "privacy_profile": profile,
        "source_classification": source_classification,
        "source_sha256": source_sha256,
        "source_provenance_sha256": source_provenance.evidence_sha256,
        "source_proof_kind": source_provenance.proof_kind,
        "source_distribution_commit": source_provenance.distribution_commit,
        "source_distribution_scope": source_provenance.distribution_scope,
        "source_synthetic_declaration_sha256": (source_provenance.synthetic_declaration_sha256),
        "source_synthetic_declaration_entry_sha256": (
            source_provenance.synthetic_declaration_entry_sha256
        ),
        "require_zdr": require_zdr,
        "data_collection": "deny",
        "permitted_model_ids": models,
        "permitted_provider_endpoints": providers,
        "endpoint_policy_classes": policy_classes,
        "endpoint_disclosures": disclosures,
        **consent_fields,
        "requested_budget_usd": _canonical_decimal(requested_budget),
        "limitations": tuple(sorted(limitations)),
    }
    provisional = EffectivePrivacyPolicyEvidence.model_construct(
        **payload,
        evidence_sha256="0" * 64,
    )
    serialized = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
    return EffectivePrivacyPolicyEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": _canonical_sha256(serialized),
        }
    )


def resolve_trusted_privacy_authorization(
    *,
    profile: PrivacyProfile,
    require_zdr: bool,
    consent_observation: PrivacyRetentionConsentObservation | None,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    source_provenance_observation: PrivacySourceProvenanceObservation | None = None,
    configured_model_ids: Sequence[str],
    configured_provider_endpoints: Sequence[str],
    requested_budget_usd: Decimal,
    now: datetime,
) -> TrustedPrivacyAuthorization:
    """Resolve and issue an opaque capability for one exact non-ZDR policy."""

    evidence = resolve_effective_privacy_policy(
        profile=profile,
        require_zdr=require_zdr,
        consent_observation=consent_observation,
        source_sha256=source_sha256,
        source_classification=source_classification,
        source_provenance_observation=source_provenance_observation,
        configured_model_ids=configured_model_ids,
        configured_provider_endpoints=configured_provider_endpoints,
        requested_budget_usd=requested_budget_usd,
        now=now,
    )
    _require_trusted_observation(consent_observation)
    if evidence.privacy_profile is PrivacyProfile.STRICT_ZDR or evidence.require_zdr:
        raise ValueError("trusted privacy authorization is reserved for explicit non-ZDR policy")
    authorization = object.__new__(TrustedPrivacyAuthorization)
    authorization._evidence = evidence
    with _AUTHORIZATION_LOCK:
        _LIVE_AUTHORIZATIONS[authorization] = _AuthorizationBinding(
            evidence=evidence,
            evidence_sha256=evidence.evidence_sha256,
            evidence_content_sha256=_model_content_sha256(evidence),
        )
    return authorization


def validate_trusted_privacy_authorization(
    authorization: TrustedPrivacyAuthorization,
    *,
    evidence_sha256: str,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    source_provenance_sha256: str | None = None,
    configured_model_ids: Sequence[str],
    configured_provider_endpoints: Sequence[str],
    requested_budget_usd: Decimal,
    now: datetime,
) -> EffectivePrivacyPolicyEvidence:
    """Revalidate one live opaque capability against an exact pending request."""

    if type(authorization) is not TrustedPrivacyAuthorization:
        raise ValueError("privacy authorization capability is not trusted")
    with _AUTHORIZATION_LOCK:
        binding = _LIVE_AUTHORIZATIONS.get(authorization)
    if binding is None:
        raise ValueError("privacy authorization capability was not issued in this process")
    evidence = authorization.evidence
    if evidence is not binding.evidence:
        raise ValueError("privacy authorization capability binding is inconsistent")
    validated_evidence = _revalidate_effective_evidence_snapshot(evidence)
    if validated_evidence is None:
        raise ValueError("privacy authorization capability binding is inconsistent")
    if (
        binding.evidence_sha256 != validated_evidence.evidence_sha256
        or binding.evidence_content_sha256 != _model_content_sha256(validated_evidence)
    ):
        raise ValueError("privacy authorization capability binding is inconsistent")
    evidence = validated_evidence
    _validate_sha256(evidence_sha256, label="effective privacy evidence")
    if evidence.evidence_sha256 != evidence_sha256:
        raise ValueError("privacy authorization binds different effective evidence")
    _validate_sha256(source_sha256, label="privacy source")
    if (
        evidence.source_sha256 != source_sha256
        or evidence.source_classification is not source_classification
    ):
        raise ValueError("privacy authorization binds a different source")
    if source_provenance_sha256 is not None:
        _validate_sha256(source_provenance_sha256, label="privacy source provenance")
        if evidence.source_provenance_sha256 != source_provenance_sha256:
            raise ValueError("privacy authorization binds different source provenance")
    models = _validate_model_ids(
        _sequence_tuple(configured_model_ids, label="configured model IDs"),
        label="configured model IDs",
    )
    providers = _validate_provider_endpoints(
        _sequence_tuple(
            configured_provider_endpoints,
            label="configured provider endpoints",
        ),
        label="configured provider endpoints",
    )
    if evidence.permitted_model_ids != models or evidence.permitted_provider_endpoints != providers:
        raise ValueError("privacy authorization binds a different exact route")
    requested_budget = _validate_requested_budget(requested_budget_usd)
    if Decimal(evidence.requested_budget_usd) != requested_budget:
        raise ValueError("privacy authorization binds a different requested budget")
    observed_at = _validate_utc_second(now, label="privacy authorization validation time")
    if evidence.consent_issued_at is None or evidence.consent_expires_at is None:
        raise ValueError("privacy authorization omits consent time bounds")
    if evidence.consent_issued_at > observed_at or evidence.consent_expires_at <= observed_at:
        raise ValueError("privacy authorization is not currently valid")
    if evidence.require_zdr or evidence.privacy_profile is PrivacyProfile.STRICT_ZDR:
        raise ValueError("privacy authorization does not represent a non-ZDR policy")
    return evidence


def _require_trusted_observation(
    observation: PrivacyRetentionConsentObservation | None,
) -> _ValidatedConsentObservation:
    if (
        type(observation) is not PrivacyRetentionConsentObservation
        or observation._issuer is not _TRUSTED_OBSERVATION_ISSUER
    ):
        raise ValueError("non-strict privacy requires descriptor-safe consent evidence")
    with _AUTHORIZATION_LOCK:
        binding = _LIVE_OBSERVATIONS.get(observation)
    if binding is None:
        raise ValueError("privacy consent observation was not issued in this process")
    if (
        type(observation.file_sha256) is not str
        or re.fullmatch(_SHA256_PATTERN, observation.file_sha256) is None
        or type(observation.file_size) is not int
        or observation.file_size < 1
        or observation.file_size > _MAX_CONSENT_BYTES
        or type(observation.consent) is not PrivacyRetentionConsent
        or observation.file_sha256 != binding.file_sha256
        or observation.file_size != binding.file_size
        or observation.consent is not binding.consent
    ):
        raise ValueError("privacy consent observation binding is inconsistent")
    validated_consent = _revalidate_consent_snapshot(observation.consent)
    if validated_consent is None:
        raise ValueError("privacy consent observation binding is inconsistent")
    if binding.consent_content_sha256 != _model_content_sha256(validated_consent):
        raise ValueError("privacy consent observation binding is inconsistent")
    return _ValidatedConsentObservation(
        file_sha256=binding.file_sha256,
        file_size=binding.file_size,
        consent=validated_consent,
    )


def _resolve_source_provenance(
    observation: PrivacySourceProvenanceObservation | None,
    *,
    source_sha256: str,
    source_classification: PrivacySourceClassification,
    observed_at: datetime,
) -> PrivacySourceProvenanceEvidence:
    """Resolve live classification evidence; only private default may be implicit."""

    from mmaudit.repository.privacy_provenance import (
        PrivacySourceProvenanceEvidence,
        validate_privacy_source_provenance_observation,
    )

    if observation is not None:
        return validate_privacy_source_provenance_observation(
            observation,
            source_sha256=source_sha256,
            source_classification=source_classification,
        )
    if source_classification is not PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE:
        raise ValueError(
            "non-private privacy policy requires a live trusted source-provenance observation"
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "source_classification": source_classification.value,
        "source_sha256": source_sha256,
        "proof_kind": "PRIVATE_DEFAULT",
        "distribution_commit": None,
        "distribution_scope": None,
        "committed_file_count": 0,
        "committed_file_inventory_sha256": None,
        "synthetic_declaration_path": None,
        "synthetic_declaration_sha256": None,
        "synthetic_declaration_entry_sha256": None,
        "observed_at": observed_at,
        "limitations": (
            "Private is the fail-closed default; no public or synthetic provenance is claimed.",
        ),
    }
    return PrivacySourceProvenanceEvidence.model_validate(
        {
            **payload,
            "evidence_sha256": _canonical_sha256(
                PrivacySourceProvenanceEvidence.model_construct(
                    **payload,
                    evidence_sha256="0" * 64,
                ).model_dump(mode="json", exclude={"evidence_sha256"})
            ),
        }
    )


def _validated_unlinked_directory(path: Path, *, label: str) -> Path:
    absolute = _normalized_absolute_path(path, label=label)
    current = Path(absolute.anchor)
    metadata: os.stat_result | None = None
    resolved: Path | None = None
    unavailable = False
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError(f"{label} may not traverse a link")
        metadata = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError):
        unavailable = True
    if unavailable or metadata is None or resolved is None:
        raise ValueError(f"{label} is unavailable")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory")
    return resolved


def _normalized_absolute_path(path: Path, *, label: str) -> Path:
    raw = str(path)
    normalized = Path(os.path.normpath(raw))
    if not path.is_absolute() or raw != str(normalized):
        raise ValueError(f"{label} path must be normalized and absolute")
    return normalized


def _validated_consent_file_metadata(path: Path, *, max_bytes: int) -> os.stat_result:
    metadata: os.stat_result | None = None
    unavailable = False
    try:
        metadata = path.lstat()
    except OSError:
        unavailable = True
    if unavailable or metadata is None:
        raise ValueError("privacy retention consent is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or path.is_junction()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= max_bytes
    ):
        raise ValueError("privacy retention consent must be a bounded unshared regular file")
    if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("privacy retention consent may not be group/world writable")
    return metadata


def _revalidate_consent_snapshot(
    consent: object,
) -> PrivacyRetentionConsent | None:
    if type(consent) is not PrivacyRetentionConsent:
        return None
    serialized: dict[str, Any] | None = None
    with suppress(Exception):
        serialized = consent.model_dump(mode="python", round_trip=True)
    if serialized is None:
        return None
    validated: PrivacyRetentionConsent | None = None
    with suppress(Exception):
        validated = PrivacyRetentionConsent.model_validate(serialized, strict=True)
    return validated


def _revalidate_effective_evidence_snapshot(
    evidence: object,
) -> EffectivePrivacyPolicyEvidence | None:
    if type(evidence) is not EffectivePrivacyPolicyEvidence:
        return None
    serialized: dict[str, Any] | None = None
    with suppress(Exception):
        serialized = evidence.model_dump(mode="python", round_trip=True)
    if serialized is None:
        return None
    validated: EffectivePrivacyPolicyEvidence | None = None
    with suppress(Exception):
        validated = EffectivePrivacyPolicyEvidence.model_validate(serialized, strict=True)
    return validated


def _model_content_sha256(
    model: PrivacyRetentionConsent | EffectivePrivacyPolicyEvidence,
) -> str:
    return _canonical_sha256(model.model_dump(mode="json"))


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_model_ids(value: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if not value:
        raise ValueError(f"{label} cannot be empty")
    validated = tuple(require_exact_openrouter_model_id(item, label=label) for item in value)
    if validated != tuple(sorted(set(validated))):
        raise ValueError(f"{label} must be unique and sorted")
    return validated


def _validate_provider_endpoint(value: str) -> str:
    if _PROVIDER_ENDPOINT_PATTERN.fullmatch(value) is None:
        raise ValueError("provider endpoint must be an exact safe identifier")
    return value


def _validate_provider_endpoints(value: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if not value:
        raise ValueError(f"{label} cannot be empty")
    validated = tuple(_validate_provider_endpoint(item) for item in value)
    if validated != tuple(sorted(set(validated))):
        raise ValueError(f"{label} must be unique and sorted")
    return validated


def _validate_policy_classes(
    value: tuple[EndpointPolicyClass, ...],
) -> tuple[EndpointPolicyClass, ...]:
    if not value:
        raise ValueError("endpoint policy classes cannot be empty")
    if value != tuple(sorted(set(value), key=lambda item: item.value)):
        raise ValueError("endpoint policy classes must be unique and sorted")
    return value


def _validate_zdr_policy_classes(
    *,
    require_zdr: bool,
    policy_classes: tuple[EndpointPolicyClass, ...],
) -> None:
    if require_zdr and policy_classes != (EndpointPolicyClass.ZDR,):
        raise ValueError("ZDR routing requires only ZDR-class endpoint disclosures")
    if not require_zdr and EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED not in policy_classes:
        raise ValueError("non-ZDR routing requires an explicitly disclosed non-ZDR endpoint")


def _validate_utc_second(value: datetime, *, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def _validate_printable_reference(value: str, *, label: str) -> str:
    if value != value.strip() or any(not character.isprintable() for character in value):
        raise ValueError(f"{label} must be canonical printable text")
    return value


def _validate_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{label} hash must be lowercase SHA-256")
    return value


def _parse_canonical_positive_cost(value: str, *, label: str) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a canonical decimal string") from exc
    if not parsed.is_finite() or parsed <= 0 or _canonical_decimal(parsed) != value:
        raise ValueError(f"{label} must be a canonical positive decimal")
    return parsed


def _validate_requested_budget(value: Decimal) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise ValueError("requested privacy budget must be a positive Decimal")
    if value > MAXIMUM_CONSENT_COST_USD:
        raise ValueError("requested privacy budget exceeds the aggregate provider budget")
    return value


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered if rendered not in {"", "-0"} else "0"


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sequence_tuple(value: Sequence[str], *, label: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an explicit sequence")
    return tuple(value)
