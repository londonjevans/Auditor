"""Authenticated authority for one exact model-policy selection decision.

Structural policy artifacts and evaluations are evidence, not authority.  This
module grants only a short-lived, process-local capability after an exact SSHSIG
Ed25519 signature has been checked against an operator-pinned trust anchor.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.policy_eligibility import (
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyAuditContext,
    PolicyEligibilityEvaluation,
    PolicyEligibilityRoute,
    PolicyEligibilitySourceReferenceObservation,
    evaluate_model_policy_eligibility,
    policy_eligibility_candidate_routes_sha256,
    policy_review_signal,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence, write_json_evidence

POLICY_ELIGIBILITY_AUTHORITY_FILENAME = "model-policy-eligibility-authority.json"
POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE: Literal["mmaudit-model-policy-eligibility-v1"] = (
    "mmaudit-model-policy-eligibility-v1"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PRINCIPAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$"
_MAX_SIGNATURE_BYTES = 16_384
_MAX_AUTHORITY_BYTES = 262_144
_MAX_VALIDITY = timedelta(days=31)
_MAX_SOURCE_OBSERVATION_VALIDITY = timedelta(hours=24)
_VERIFY_TIMEOUT_SECONDS = 10


class ModelPolicyEligibilityAuthorityError(ValueError):
    """Raised when exact signed policy-selection authority cannot be established."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelPolicyEligibilityTrustAnchor(_FrozenModel):
    """Operator-pinned SSH Ed25519 identity and verifier executable."""

    schema_version: Literal["1.0"] = "1.0"
    operator_principal: str = Field(pattern=_PRINCIPAL_PATTERN)
    public_key: str = Field(min_length=68, max_length=256)
    public_key_sha256: str = Field(pattern=_SHA256_PATTERN)
    verifier_executable_sha256: str = Field(pattern=_SHA256_PATTERN)
    trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("public_key")
    @classmethod
    def public_key_is_canonical_ed25519(cls, value: str) -> str:
        _decode_ed25519_public_key(value)
        return value

    @model_validator(mode="after")
    def hashes_are_exact(self) -> Self:
        expected_key = hashlib.sha256((self.public_key + "\n").encode("ascii")).hexdigest()
        if self.public_key_sha256 != expected_key:
            raise ValueError("policy trust-anchor public-key hash is inconsistent")
        expected_anchor = canonical_sha256(
            self.model_dump(mode="json", exclude={"trust_anchor_sha256"})
        )
        if self.trust_anchor_sha256 != expected_anchor:
            raise ValueError("policy trust-anchor self-hash is inconsistent")
        return self


class PolicyEligibilitySourceCommitment(_FrozenModel):
    """Per-reference current source observations for one exact eligible route."""

    schema_version: Literal["1.0"] = "1.0"
    route: PolicyEligibilityRoute
    determination_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_reference_observations: tuple[PolicyEligibilitySourceReferenceObservation, ...] = Field(
        min_length=1, max_length=32
    )
    commitment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("source_reference_observations")
    @classmethod
    def source_observations_are_canonical(
        cls,
        value: tuple[PolicyEligibilitySourceReferenceObservation, ...],
    ) -> tuple[PolicyEligibilitySourceReferenceObservation, ...]:
        references = tuple(item.reference_sha256 for item in value)
        if references != tuple(sorted(set(references))):
            raise ValueError(
                "policy source-reference observations must be exact, unique, and sorted"
            )
        return value

    @model_validator(mode="after")
    def commitment_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"commitment_sha256"}))
        if self.commitment_sha256 != expected:
            raise ValueError("policy source commitment self-hash is inconsistent")
        return self


class PolicyEligibilitySourceObservation(_FrozenModel):
    """Bounded current-source observation required at issue and every use."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    expires_at: datetime
    source_commitments: tuple[PolicyEligibilitySourceCommitment, ...] = Field(
        min_length=0,
        max_length=128,
    )
    source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at", "expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy source observation time")

    @model_validator(mode="after")
    def observation_is_canonical_bounded_and_self_hashed(self) -> Self:
        identities = tuple(item.route.identity for item in self.source_commitments)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("policy source commitments must be exact, unique, and sorted")
        if (
            self.expires_at <= self.observed_at
            or self.expires_at - self.observed_at > _MAX_SOURCE_OBSERVATION_VALIDITY
        ):
            raise ValueError("policy source observation validity window is invalid")
        expected_set = canonical_sha256(
            [item.model_dump(mode="json") for item in self.source_commitments]
        )
        if self.source_commitment_set_sha256 != expected_set:
            raise ValueError("policy source commitment-set hash is inconsistent")
        expected_observation = canonical_sha256(
            self.model_dump(mode="json", exclude={"observation_sha256"})
        )
        if self.observation_sha256 != expected_observation:
            raise ValueError("policy source observation self-hash is inconsistent")
        return self


class ModelPolicyEligibilityAuthorityStatement(_FrozenModel):
    """Canonical domain-separated statement signed by the policy operator."""

    schema_version: Literal["1.0"] = "1.0"
    signature_namespace: Literal["mmaudit-model-policy-eligibility-v1"] = (
        POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE
    )
    signed_at: datetime
    expires_at: datetime
    operator_principal: str = Field(pattern=_PRINCIPAL_PATTERN)
    trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_observation_expires_at: datetime
    candidate_route_sha256s: tuple[str, ...] = Field(min_length=1, max_length=512)
    eligible_route_sha256s: tuple[str, ...] = Field(min_length=1, max_length=512)
    eligible_model_ids: tuple[str, ...] = Field(min_length=1, max_length=512)
    purpose: Literal["POLICY_SELECTION_ONLY"] = "POLICY_SELECTION_ONLY"
    operator_decision_authenticity: Literal["SSHSIG_ED25519_VERIFIED"] = "SSHSIG_ED25519_VERIFIED"
    policy_selection_authorized: Literal[True] = True
    qualification_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    general_production_authorized: Literal[False] = False
    statement_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("signed_at", "expires_at", "source_observation_expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy authority time")

    @field_validator("candidate_route_sha256s", "eligible_route_sha256s")
    @classmethod
    def route_hashes_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None for item in value
        ):
            raise ValueError("policy authority route hashes must be canonical, unique, and sorted")
        return value

    @field_validator("eligible_model_ids")
    @classmethod
    def eligible_models_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(not item for item in value):
            raise ValueError("policy authority model IDs must be canonical, unique, and sorted")
        return value

    @field_validator(
        "policy_selection_authorized",
        "qualification_authorized",
        "source_egress_authorized",
        "general_production_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("policy authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def statement_is_bounded_and_self_hashed(self) -> Self:
        if self.expires_at <= self.signed_at or self.expires_at - self.signed_at > _MAX_VALIDITY:
            raise ValueError("policy authority validity window is invalid")
        if self.expires_at > self.source_observation_expires_at:
            raise ValueError("policy authority outlives its initial source observation")
        if not set(self.eligible_route_sha256s).issubset(self.candidate_route_sha256s):
            raise ValueError("eligible policy routes must be a subset of candidate routes")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"statement_sha256"}))
        if self.statement_sha256 != expected:
            raise ValueError("policy authority statement self-hash is inconsistent")
        return self


class ModelPolicyEligibilityAuthorityEnvelope(_FrozenModel):
    """Bounded detached SSHSIG envelope for one exact policy statement."""

    schema_version: Literal["1.0"] = "1.0"
    signature_algorithm: Literal["SSHSIG_ED25519"] = "SSHSIG_ED25519"
    statement: ModelPolicyEligibilityAuthorityStatement
    detached_signature: str = Field(min_length=100, max_length=_MAX_SIGNATURE_BYTES)
    signature_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("detached_signature")
    @classmethod
    def signature_is_canonical_armor(cls, value: str) -> str:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("policy authority signature must be ASCII armor") from exc
        if (
            len(encoded) > _MAX_SIGNATURE_BYTES
            or not value.startswith("-----BEGIN SSH SIGNATURE-----\n")
            or not value.endswith("-----END SSH SIGNATURE-----\n")
            or "\r" in value
            or any(character not in "\n" and not character.isprintable() for character in value)
        ):
            raise ValueError("policy authority signature armor is invalid")
        return value

    @model_validator(mode="after")
    def signature_and_envelope_hashes_are_exact(self) -> Self:
        expected_signature = hashlib.sha256(self.detached_signature.encode("ascii")).hexdigest()
        if self.signature_sha256 != expected_signature:
            raise ValueError("policy authority signature hash is inconsistent")
        expected_envelope = canonical_sha256(
            self.model_dump(mode="json", exclude={"authority_envelope_sha256"})
        )
        if self.authority_envelope_sha256 != expected_envelope:
            raise ValueError("policy authority envelope self-hash is inconsistent")
        return self


class ModelPolicyEligibilityAuthorityVerificationReceipt(_FrozenModel):
    """Self-hashed evidence of verification; it is deliberately not authority."""

    schema_version: Literal["1.0"] = "1.0"
    verified_at: datetime
    signed_at: datetime
    expires_at: datetime
    operator_principal: str = Field(pattern=_PRINCIPAL_PATTERN)
    trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    eligible_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_source_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commitment_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_observation_expires_at: datetime
    statement_sha256: str = Field(pattern=_SHA256_PATTERN)
    signature_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)
    purpose: Literal["POLICY_SELECTION_ONLY"] = "POLICY_SELECTION_ONLY"
    policy_selection_authorized: Literal[False] = False
    qualification_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    general_production_authorized: Literal[False] = False
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "verified_at",
        "signed_at",
        "expires_at",
        "source_observation_expires_at",
    )
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy authority receipt time")

    @field_validator(
        "policy_selection_authorized",
        "qualification_authorized",
        "source_egress_authorized",
        "general_production_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("policy receipt flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def receipt_is_self_hashed(self) -> Self:
        if self.verified_at < self.signed_at or self.verified_at >= self.expires_at:
            raise ValueError("policy verification receipt time is outside signed validity")
        if self.expires_at > self.source_observation_expires_at:
            raise ValueError("policy verification receipt outlives its source observation")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if self.receipt_sha256 != expected:
            raise ValueError("policy verification receipt self-hash is inconsistent")
        return self


class ModelPolicyEligibilityAuthorityEvidenceProjection(_FrozenModel):
    """Complete durable signed-authority evidence that grants no runtime authority."""

    schema_version: Literal["1.0"] = "1.0"
    initial_source_observation: PolicyEligibilitySourceObservation
    authority_statement: ModelPolicyEligibilityAuthorityStatement
    authority_envelope: ModelPolicyEligibilityAuthorityEnvelope
    trust_anchor: ModelPolicyEligibilityTrustAnchor
    verification_receipt: ModelPolicyEligibilityAuthorityVerificationReceipt
    policy_selection_authorized: Literal[False] = False
    qualification_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    general_production_authorized: Literal[False] = False
    projection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "policy_selection_authorized",
        "qualification_authorized",
        "source_egress_authorized",
        "general_production_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("policy authority evidence flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def evidence_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        statement = self.authority_statement
        receipt = self.verification_receipt
        if (
            self.authority_envelope.statement != statement
            or statement.trust_anchor_sha256 != self.trust_anchor.trust_anchor_sha256
            or statement.operator_principal != self.trust_anchor.operator_principal
            or statement.initial_source_observation_sha256
            != self.initial_source_observation.observation_sha256
            or statement.source_commitment_set_sha256
            != self.initial_source_observation.source_commitment_set_sha256
            or statement.source_observation_expires_at != self.initial_source_observation.expires_at
            or receipt
            != _build_verification_receipt(
                statement=statement,
                envelope=self.authority_envelope,
                verified_at=receipt.verified_at,
            )
        ):
            raise ValueError("policy authority evidence projection has inconsistent exact joins")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"projection_sha256"}))
        if self.projection_sha256 != expected:
            raise ValueError("policy authority evidence projection self-hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _RuntimeAuthorityState:
    artifact_sha256: str
    evaluation_sha256: str
    audit_context_sha256: str
    client_constraints_sha256: str
    technical_route_set_sha256: str
    eligible_route_set_sha256: str
    source_commitment_set_sha256: str
    signed_at: datetime
    expires_at: datetime
    verified_at: datetime
    receipt: ModelPolicyEligibilityAuthorityVerificationReceipt
    evidence_projection: ModelPolicyEligibilityAuthorityEvidenceProjection


class TrustedModelPolicyEligibilitySelectionVerification:
    """Opaque process-local proof for policy selection, and for no other purpose."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedModelPolicyEligibilitySelectionVerification:
        del cls
        raise TypeError("trusted policy-selection verification cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def require_for_policy_selection(
        self,
        *,
        artifact: ModelPolicyEligibilityArtifact,
        evaluation: PolicyEligibilityEvaluation,
        audit_context: PolicyAuditContext,
        client_constraints: ClientPolicyConstraints,
        candidate_routes: tuple[PolicyEligibilityRoute, ...],
        source_observation: PolicyEligibilitySourceObservation,
        observed_at: datetime,
    ) -> ModelPolicyEligibilityAuthorityVerificationReceipt:
        """Require the exact evidence, audit, client, routes, and current validity."""

        return _require_trusted_policy_eligibility_capability(
            self,
            artifact,
            evaluation,
            audit_context,
            client_constraints,
            candidate_routes,
            source_observation,
            observed_at,
        )

    def evidence_projection(self) -> ModelPolicyEligibilityAuthorityEvidenceProjection:
        """Return exact durable verification evidence without live authority."""

        return _project_trusted_policy_eligibility_evidence(self)

    def __copy__(self) -> Never:
        raise TypeError("trusted policy-selection verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("trusted policy-selection verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted policy-selection verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted policy-selection verification cannot be serialized")


def build_model_policy_eligibility_trust_anchor(
    *,
    operator_principal: str,
    public_key: str,
    verifier_executable_sha256: str,
) -> ModelPolicyEligibilityTrustAnchor:
    """Build a self-hashed trust anchor from explicit operator-controlled pins."""

    key = public_key.strip()
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "operator_principal": operator_principal,
        "public_key": key,
        "public_key_sha256": hashlib.sha256((key + "\n").encode("ascii")).hexdigest(),
        "verifier_executable_sha256": verifier_executable_sha256,
    }
    values["trust_anchor_sha256"] = canonical_sha256(values)
    return ModelPolicyEligibilityTrustAnchor.model_validate(values)


def build_policy_eligibility_source_commitment(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    route: PolicyEligibilityRoute,
    source_reference_observations: tuple[PolicyEligibilitySourceReferenceObservation, ...],
) -> PolicyEligibilitySourceCommitment:
    """Commit one current observation for every cited official reference."""

    artifact = ModelPolicyEligibilityArtifact.model_validate_json(
        artifact.model_dump_json(), strict=True
    )
    route = PolicyEligibilityRoute.model_validate_json(route.model_dump_json(), strict=True)
    observations = tuple(
        PolicyEligibilitySourceReferenceObservation.model_validate_json(
            item.model_dump_json(), strict=True
        )
        for item in source_reference_observations
    )
    determination, expected_references = _expected_source_evidence(artifact, route)
    if (
        tuple((item.reference_sha256, item.expected_content_sha256) for item in observations)
        != expected_references
    ):
        raise ModelPolicyEligibilityAuthorityError(
            "policy source commitment must exactly cover cited official references"
        )
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "route": route,
        "determination_sha256": determination,
        "source_reference_observations": observations,
    }
    values["commitment_sha256"] = canonical_sha256(
        {
            **values,
            "route": route.model_dump(mode="json"),
            "source_reference_observations": [
                item.model_dump(mode="json") for item in observations
            ],
        }
    )
    return PolicyEligibilitySourceCommitment.model_validate(values)


def build_policy_eligibility_source_observation(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    observed_at: datetime,
    expires_at: datetime,
    source_commitments: tuple[PolicyEligibilitySourceCommitment, ...],
) -> PolicyEligibilitySourceObservation:
    """Build one bounded current observation without granting selection authority."""

    artifact = ModelPolicyEligibilityArtifact.model_validate_json(
        artifact.model_dump_json(), strict=True
    )
    commitments = tuple(
        PolicyEligibilitySourceCommitment.model_validate_json(item.model_dump_json(), strict=True)
        for item in source_commitments
    )
    for commitment in commitments:
        _require_source_commitment_matches_artifact(artifact, commitment)
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "artifact_sha256": artifact.artifact_sha256,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "source_commitments": commitments,
        "source_commitment_set_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in commitments]
        ),
    }
    values["observation_sha256"] = canonical_sha256(
        {
            **values,
            "observed_at": _utc_json_time(observed_at),
            "expires_at": _utc_json_time(expires_at),
            "source_commitments": [item.model_dump(mode="json") for item in commitments],
        }
    )
    return PolicyEligibilitySourceObservation.model_validate(values)


def build_model_policy_eligibility_authority_statement(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    candidate_routes: tuple[PolicyEligibilityRoute, ...],
    source_observation: PolicyEligibilitySourceObservation,
    trust_anchor: ModelPolicyEligibilityTrustAnchor,
    signed_at: datetime,
    expires_at: datetime,
) -> ModelPolicyEligibilityAuthorityStatement:
    """Build the only statement shape accepted by the policy signature verifier."""

    evidence = _validated_evidence(
        artifact,
        evaluation,
        audit_context,
        client_constraints,
        candidate_routes,
    )
    artifact, evaluation, audit_context, client_constraints, candidate_routes = evidence
    anchor = ModelPolicyEligibilityTrustAnchor.model_validate_json(
        trust_anchor.model_dump_json(), strict=True
    )
    signed_at = _whole_second_utc(signed_at, label="policy signature time")
    expires_at = _whole_second_utc(expires_at, label="policy signature expiry")
    source_observation = _validated_source_observation(
        artifact,
        evaluation,
        source_observation,
        used_at=signed_at,
    )
    if evaluation.expires_at is None:
        raise ModelPolicyEligibilityAuthorityError(
            "policy evaluation without an expiry cannot grant selection authority"
        )
    if signed_at < evaluation.evaluated_at or expires_at > evaluation.expires_at:
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority validity must stay within the evaluation window"
        )
    if expires_at > source_observation.expires_at:
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority validity must stay within the source-observation window"
        )
    candidate_hashes = _canonical_route_hashes(candidate_routes, label="candidate")
    eligible_hashes = _canonical_route_hashes(evaluation.eligible_routes, label="eligible")
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "signature_namespace": POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
        "signed_at": signed_at,
        "expires_at": expires_at,
        "operator_principal": anchor.operator_principal,
        "trust_anchor_sha256": anchor.trust_anchor_sha256,
        "artifact_sha256": artifact.artifact_sha256,
        "evaluation_sha256": evaluation.evaluation_sha256,
        "audit_context_sha256": audit_context.context_sha256,
        "client_constraints_sha256": client_constraints.constraints_sha256,
        "technical_route_set_sha256": evaluation.technical_route_set_sha256,
        "eligible_route_set_sha256": evaluation.eligible_route_set_sha256,
        "initial_source_observation_sha256": source_observation.observation_sha256,
        "source_commitment_set_sha256": source_observation.source_commitment_set_sha256,
        "source_observation_expires_at": source_observation.expires_at,
        "candidate_route_sha256s": candidate_hashes,
        "eligible_route_sha256s": eligible_hashes,
        "eligible_model_ids": tuple(sorted(evaluation.eligible_model_ids)),
        "purpose": "POLICY_SELECTION_ONLY",
        "operator_decision_authenticity": "SSHSIG_ED25519_VERIFIED",
        "policy_selection_authorized": True,
        "qualification_authorized": False,
        "source_egress_authorized": False,
        "general_production_authorized": False,
    }
    values["statement_sha256"] = canonical_sha256(
        {
            **values,
            "signed_at": _utc_json_time(signed_at),
            "expires_at": _utc_json_time(expires_at),
            "source_observation_expires_at": _utc_json_time(source_observation.expires_at),
        }
    )
    return ModelPolicyEligibilityAuthorityStatement.model_validate(values)


def model_policy_eligibility_authority_statement_bytes(
    statement: ModelPolicyEligibilityAuthorityStatement,
) -> bytes:
    """Return the exact bytes covered by the policy-specific SSHSIG signature."""

    validated = ModelPolicyEligibilityAuthorityStatement.model_validate_json(
        statement.model_dump_json(), strict=True
    )
    return json.dumps(
        validated.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def build_model_policy_eligibility_authority_envelope(
    *,
    statement: ModelPolicyEligibilityAuthorityStatement,
    detached_signature: bytes | str,
) -> ModelPolicyEligibilityAuthorityEnvelope:
    """Bind one externally produced detached signature without granting authority."""

    validated = ModelPolicyEligibilityAuthorityStatement.model_validate_json(
        statement.model_dump_json(), strict=True
    )
    try:
        signature = (
            detached_signature.decode("ascii")
            if isinstance(detached_signature, bytes)
            else detached_signature
        )
    except UnicodeDecodeError as exc:
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority signature must be ASCII"
        ) from exc
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "signature_algorithm": "SSHSIG_ED25519",
        "statement": validated,
        "detached_signature": signature,
        "signature_sha256": hashlib.sha256(signature.encode("ascii")).hexdigest(),
    }
    values["authority_envelope_sha256"] = canonical_sha256(
        {**values, "statement": validated.model_dump(mode="json")}
    )
    return ModelPolicyEligibilityAuthorityEnvelope.model_validate(values)


def write_model_policy_eligibility_authority_envelope(
    output_dir: Path,
    envelope: ModelPolicyEligibilityAuthorityEnvelope,
) -> None:
    """Write one fresh private canonical signed policy-authority envelope."""

    validated = ModelPolicyEligibilityAuthorityEnvelope.model_validate_json(
        envelope.model_dump_json(), strict=True
    )
    write_json_evidence(
        evidence_root=output_dir,
        relative_path=POLICY_ELIGIBILITY_AUTHORITY_FILENAME,
        value=validated,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )


def load_model_policy_eligibility_authority_envelope(
    output_dir: Path,
) -> ModelPolicyEligibilityAuthorityEnvelope:
    """Load one descriptor-safe signed policy-authority envelope."""

    observation = read_json_evidence(
        evidence_root=output_dir,
        relative_path=POLICY_ELIGIBILITY_AUTHORITY_FILENAME,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority envelope must be a JSON object"
        )
    try:
        return ModelPolicyEligibilityAuthorityEnvelope.model_validate_json(
            observation.content, strict=True
        )
    except ValueError as exc:
        raise ModelPolicyEligibilityAuthorityError("policy authority envelope is invalid") from exc


def load_model_policy_eligibility_trust_anchor(path: Path) -> ModelPolicyEligibilityTrustAnchor:
    """Load an explicit descriptor-safe operator trust-anchor JSON file."""

    observation = read_json_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ModelPolicyEligibilityAuthorityError("policy trust anchor must be a JSON object")
    try:
        return ModelPolicyEligibilityTrustAnchor.model_validate_json(
            observation.content, strict=True
        )
    except ValueError as exc:
        raise ModelPolicyEligibilityAuthorityError("policy trust anchor is invalid") from exc


def _build_policy_eligibility_runtime_authority() -> tuple[
    Callable[
        ...,
        tuple[
            ModelPolicyEligibilityAuthorityVerificationReceipt,
            TrustedModelPolicyEligibilitySelectionVerification,
        ],
    ],
    Callable[..., ModelPolicyEligibilityAuthorityVerificationReceipt],
    Callable[
        [TrustedModelPolicyEligibilitySelectionVerification],
        ModelPolicyEligibilityAuthorityEvidenceProjection,
    ],
]:
    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedModelPolicyEligibilitySelectionVerification],
            _RuntimeAuthorityState,
        ],
    ] = {}
    lock = threading.RLock()

    def issue(
        *,
        artifact: ModelPolicyEligibilityArtifact,
        evaluation: PolicyEligibilityEvaluation,
        audit_context: PolicyAuditContext,
        client_constraints: ClientPolicyConstraints,
        candidate_routes: tuple[PolicyEligibilityRoute, ...],
        source_observation: PolicyEligibilitySourceObservation,
        envelope: ModelPolicyEligibilityAuthorityEnvelope,
        trust_anchor: ModelPolicyEligibilityTrustAnchor,
        expected_trust_anchor_sha256: str,
        expected_operator_principal: str,
        observed_at: datetime,
    ) -> tuple[
        ModelPolicyEligibilityAuthorityVerificationReceipt,
        TrustedModelPolicyEligibilitySelectionVerification,
    ]:
        evidence = _validated_evidence(
            artifact,
            evaluation,
            audit_context,
            client_constraints,
            candidate_routes,
        )
        artifact, evaluation, audit_context, client_constraints, candidate_routes = evidence
        signed = ModelPolicyEligibilityAuthorityEnvelope.model_validate_json(
            envelope.model_dump_json(), strict=True
        )
        anchor = ModelPolicyEligibilityTrustAnchor.model_validate_json(
            trust_anchor.model_dump_json(), strict=True
        )
        _require_expected_trust_anchor(
            anchor,
            expected_trust_anchor_sha256=expected_trust_anchor_sha256,
            expected_operator_principal=expected_operator_principal,
        )
        observed_at = _whole_second_utc(observed_at, label="policy authority observation time")
        source_observation = _validated_source_observation(
            artifact,
            evaluation,
            source_observation,
            used_at=observed_at,
        )
        _require_statement_matches_evidence(
            signed.statement,
            artifact,
            evaluation,
            audit_context,
            client_constraints,
            candidate_routes,
            source_observation,
            anchor,
        )
        if observed_at < signed.statement.signed_at or observed_at >= signed.statement.expires_at:
            raise ModelPolicyEligibilityAuthorityError(
                "policy authority is future-dated or expired"
            )
        executable = _trusted_ssh_keygen(anchor.verifier_executable_sha256)
        _verify_sshsig(
            executable=executable,
            trust_anchor=anchor,
            statement=signed.statement,
            signature=signed.detached_signature,
        )
        if _sha256_file(executable) != anchor.verifier_executable_sha256:
            raise ModelPolicyEligibilityAuthorityError(
                "policy signature verifier changed during use"
            )
        receipt = _build_verification_receipt(
            statement=signed.statement,
            envelope=signed,
            verified_at=observed_at,
        )
        evidence_projection = build_model_policy_eligibility_authority_evidence_projection(
            initial_source_observation=source_observation,
            statement=signed.statement,
            envelope=signed,
            trust_anchor=anchor,
            receipt=receipt,
        )
        state = _RuntimeAuthorityState(
            artifact_sha256=artifact.artifact_sha256,
            evaluation_sha256=evaluation.evaluation_sha256,
            audit_context_sha256=audit_context.context_sha256,
            client_constraints_sha256=client_constraints.constraints_sha256,
            technical_route_set_sha256=evaluation.technical_route_set_sha256,
            eligible_route_set_sha256=evaluation.eligible_route_set_sha256,
            source_commitment_set_sha256=source_observation.source_commitment_set_sha256,
            signed_at=signed.statement.signed_at,
            expires_at=signed.statement.expires_at,
            verified_at=observed_at,
            receipt=receipt,
            evidence_projection=evidence_projection,
        )
        capability = object.__new__(TrustedModelPolicyEligibilitySelectionVerification)
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[TrustedModelPolicyEligibilitySelectionVerification],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return receipt, capability

    def require(
        capability: TrustedModelPolicyEligibilitySelectionVerification,
        artifact: ModelPolicyEligibilityArtifact,
        evaluation: PolicyEligibilityEvaluation,
        audit_context: PolicyAuditContext,
        client_constraints: ClientPolicyConstraints,
        candidate_routes: tuple[PolicyEligibilityRoute, ...],
        source_observation: PolicyEligibilitySourceObservation,
        observed_at: datetime,
    ) -> ModelPolicyEligibilityAuthorityVerificationReceipt:
        if type(capability) is not TrustedModelPolicyEligibilitySelectionVerification:
            raise ValueError("trusted policy-selection verification is absent or forged")
        with lock:
            registered = registry.get(id(capability))
        state = registered[1] if registered is not None and registered[0]() is capability else None
        if state is None:
            raise ValueError("trusted policy-selection verification is absent or forged")
        evidence = _validated_evidence(
            artifact,
            evaluation,
            audit_context,
            client_constraints,
            candidate_routes,
        )
        artifact, evaluation, audit_context, client_constraints, _routes = evidence
        source_observation = _validated_source_observation(
            artifact,
            evaluation,
            source_observation,
            used_at=observed_at,
        )
        if (
            state.artifact_sha256 != artifact.artifact_sha256
            or state.evaluation_sha256 != evaluation.evaluation_sha256
            or state.audit_context_sha256 != audit_context.context_sha256
            or state.client_constraints_sha256 != client_constraints.constraints_sha256
            or state.technical_route_set_sha256 != evaluation.technical_route_set_sha256
            or state.eligible_route_set_sha256 != evaluation.eligible_route_set_sha256
            or state.source_commitment_set_sha256 != source_observation.source_commitment_set_sha256
            or source_observation != state.evidence_projection.initial_source_observation
        ):
            raise ValueError(
                "current policy source observation was not independently authorized by the "
                "live signed verification"
            )
        observed_at = _whole_second_utc(observed_at, label="policy authority use time")
        if observed_at < state.verified_at or observed_at >= min(
            state.expires_at,
            _required_evaluation_expiry(evaluation.expires_at),
            source_observation.expires_at,
        ):
            raise ValueError("trusted policy-selection verification is not currently valid")
        return state.receipt

    def project(
        capability: TrustedModelPolicyEligibilitySelectionVerification,
    ) -> ModelPolicyEligibilityAuthorityEvidenceProjection:
        if type(capability) is not TrustedModelPolicyEligibilitySelectionVerification:
            raise ValueError("trusted policy-selection verification is absent or forged")
        with lock:
            registered = registry.get(id(capability))
        state = registered[1] if registered is not None and registered[0]() is capability else None
        if state is None:
            raise ValueError("trusted policy-selection verification is absent or forged")
        return ModelPolicyEligibilityAuthorityEvidenceProjection.model_validate_json(
            state.evidence_projection.model_dump_json(),
            strict=True,
        )

    return issue, require, project


(
    verify_operator_model_policy_eligibility_authority,
    _require_trusted_policy_eligibility_capability,
    _project_trusted_policy_eligibility_evidence,
) = _build_policy_eligibility_runtime_authority()
del _build_policy_eligibility_runtime_authority


def verify_model_policy_eligibility_authority_evidence(
    *,
    evidence: ModelPolicyEligibilityAuthorityEvidenceProjection,
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    candidate_routes: tuple[PolicyEligibilityRoute, ...],
    expected_trust_anchor_sha256: str,
    expected_operator_principal: str,
) -> ModelPolicyEligibilityAuthorityEvidenceProjection:
    """Cryptographically replay durable policy evidence without issuing live authority."""

    projection = ModelPolicyEligibilityAuthorityEvidenceProjection.model_validate_json(
        evidence.model_dump_json(),
        strict=True,
    )
    validated = _validated_evidence(
        artifact,
        evaluation,
        audit_context,
        client_constraints,
        candidate_routes,
    )
    artifact, evaluation, audit_context, client_constraints, routes = validated
    anchor = projection.trust_anchor
    _require_expected_trust_anchor(
        anchor,
        expected_trust_anchor_sha256=expected_trust_anchor_sha256,
        expected_operator_principal=expected_operator_principal,
    )
    initial_source = _validated_source_observation(
        artifact,
        evaluation,
        projection.initial_source_observation,
        used_at=projection.verification_receipt.verified_at,
    )
    _require_statement_matches_evidence(
        projection.authority_statement,
        artifact,
        evaluation,
        audit_context,
        client_constraints,
        routes,
        initial_source,
        anchor,
    )
    executable = _trusted_ssh_keygen(anchor.verifier_executable_sha256)
    _verify_sshsig(
        executable=executable,
        trust_anchor=anchor,
        statement=projection.authority_statement,
        signature=projection.authority_envelope.detached_signature,
    )
    if _sha256_file(executable) != anchor.verifier_executable_sha256:
        raise ModelPolicyEligibilityAuthorityError(
            "policy signature verifier changed during evidence replay"
        )
    expected_receipt = _build_verification_receipt(
        statement=projection.authority_statement,
        envelope=projection.authority_envelope,
        verified_at=projection.verification_receipt.verified_at,
    )
    if projection.verification_receipt != expected_receipt:
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority evidence receipt differs from cryptographic replay"
        )
    return projection


def validate_policy_eligibility_source_observation(
    *,
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    source_observation: PolicyEligibilitySourceObservation,
    used_at: datetime,
) -> PolicyEligibilitySourceObservation:
    """Structurally replay one current source observation without granting authority."""

    artifact = ModelPolicyEligibilityArtifact.model_validate_json(
        artifact.model_dump_json(),
        strict=True,
    )
    evaluation = PolicyEligibilityEvaluation.model_validate_json(
        evaluation.model_dump_json(),
        strict=True,
    )
    return _validated_source_observation(
        artifact,
        evaluation,
        source_observation,
        used_at=used_at,
    )


def trusted_policy_eligibility_ssh_keygen_sha256() -> str:
    """Observe the fixed system SSH verifier hash for trust-anchor provisioning."""

    for candidate in (Path("/usr/bin/ssh-keygen"), Path("/bin/ssh-keygen")):
        if _executable_is_trusted(candidate):
            return _sha256_file(candidate)
    raise ModelPolicyEligibilityAuthorityError("fixed trusted ssh-keygen is unavailable")


def _validated_evidence(
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    candidate_routes: tuple[PolicyEligibilityRoute, ...],
) -> tuple[
    ModelPolicyEligibilityArtifact,
    PolicyEligibilityEvaluation,
    PolicyAuditContext,
    ClientPolicyConstraints,
    tuple[PolicyEligibilityRoute, ...],
]:
    artifact = ModelPolicyEligibilityArtifact.model_validate_json(
        artifact.model_dump_json(), strict=True
    )
    evaluation = PolicyEligibilityEvaluation.model_validate_json(
        evaluation.model_dump_json(), strict=True
    )
    audit_context = PolicyAuditContext.model_validate_json(
        audit_context.model_dump_json(), strict=True
    )
    client_constraints = ClientPolicyConstraints.model_validate_json(
        client_constraints.model_dump_json(), strict=True
    )
    routes = tuple(
        PolicyEligibilityRoute.model_validate_json(route.model_dump_json(), strict=True)
        for route in candidate_routes
    )
    if not routes:
        raise ModelPolicyEligibilityAuthorityError("policy authority requires candidate routes")
    expected_evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=client_constraints,
        audit_context=audit_context,
        technical_routes=routes,
        observed_at=evaluation.evaluated_at,
    )
    if evaluation != expected_evaluation:
        raise ModelPolicyEligibilityAuthorityError(
            "policy evaluation differs from deterministic eligibility replay"
        )
    candidate_set_sha256 = policy_eligibility_candidate_routes_sha256(routes)
    eligible_set_sha256 = policy_eligibility_candidate_routes_sha256(evaluation.eligible_routes)
    if (
        evaluation.artifact_sha256 != artifact.artifact_sha256
        or evaluation.client_constraints_sha256 != client_constraints.constraints_sha256
        or evaluation.audit_context_sha256 != audit_context.context_sha256
        or evaluation.technical_route_set_sha256 != candidate_set_sha256
        or evaluation.eligible_route_set_sha256 != eligible_set_sha256
    ):
        raise ModelPolicyEligibilityAuthorityError(
            "policy evaluation differs from artifact, audit, client, or route evidence"
        )
    candidate_hashes = set(_canonical_route_hashes(routes, label="candidate"))
    eligible_hashes = set(
        _canonical_route_hashes(
            evaluation.eligible_routes,
            label="eligible",
            allow_empty=True,
        )
    )
    if not eligible_hashes.issubset(candidate_hashes):
        raise ModelPolicyEligibilityAuthorityError(
            "policy evaluation has an eligible route outside the candidate set"
        )
    return artifact, evaluation, audit_context, client_constraints, routes


def _expected_source_evidence(
    artifact: ModelPolicyEligibilityArtifact,
    route: PolicyEligibilityRoute,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    determination = next(
        (item for item in artifact.determinations if item.route.identity == route.identity),
        None,
    )
    if determination is None:
        raise ModelPolicyEligibilityAuthorityError(
            "policy source commitment has no exact artifact determination"
        )
    evidence_by_hash = {
        item.reference_sha256: item.content_sha256 for item in artifact.official_evidence
    }
    cited_references = tuple(
        sorted(
            {
                reference
                for assessment in determination.assessments
                for reference in assessment.evidence_reference_sha256s
            }
        )
    )
    expected = tuple((reference, evidence_by_hash[reference]) for reference in cited_references)
    if not expected:
        raise ModelPolicyEligibilityAuthorityError(
            "policy source commitment has no expected official evidence"
        )
    return determination.determination_sha256, expected


def _require_source_commitment_matches_artifact(
    artifact: ModelPolicyEligibilityArtifact,
    commitment: PolicyEligibilitySourceCommitment,
) -> None:
    determination_sha256, expected_references = _expected_source_evidence(
        artifact,
        commitment.route,
    )
    observed_references = tuple(
        (item.reference_sha256, item.expected_content_sha256)
        for item in commitment.source_reference_observations
    )
    if (
        commitment.determination_sha256 != determination_sha256
        or observed_references != expected_references
    ):
        raise ModelPolicyEligibilityAuthorityError(
            "policy source commitment differs from artifact evidence"
        )


def _validated_source_observation(
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    source_observation: PolicyEligibilitySourceObservation,
    *,
    used_at: datetime,
) -> PolicyEligibilitySourceObservation:
    observation = PolicyEligibilitySourceObservation.model_validate_json(
        source_observation.model_dump_json(), strict=True
    )
    used_at = _whole_second_utc(used_at, label="policy source observation use time")
    evaluation_expiry = _required_evaluation_expiry(evaluation.expires_at)
    if observation.artifact_sha256 != artifact.artifact_sha256:
        raise ModelPolicyEligibilityAuthorityError(
            "policy source observation differs from its artifact"
        )
    observed_routes = tuple(item.route for item in observation.source_commitments)
    if observed_routes != evaluation.eligible_routes:
        raise ModelPolicyEligibilityAuthorityError(
            "policy source observation must cover every eligible route exactly"
        )
    if (
        observation.observed_at < evaluation.evaluated_at
        or observation.expires_at > evaluation_expiry
        or used_at < observation.observed_at
        or used_at >= observation.expires_at
    ):
        raise ModelPolicyEligibilityAuthorityError(
            "policy source observation is future-dated, stale, or outside evaluation validity"
        )
    for commitment in observation.source_commitments:
        _require_source_commitment_matches_artifact(artifact, commitment)
        signal = policy_review_signal(
            artifact=artifact,
            route=commitment.route,
            observed_at=observation.observed_at,
            source_reference_observations=commitment.source_reference_observations,
        )
        if signal is not None:
            raise ModelPolicyEligibilityAuthorityError(
                "policy source observation requires review and cannot authorize selection"
            )
    return observation


def _require_expected_trust_anchor(
    anchor: ModelPolicyEligibilityTrustAnchor,
    *,
    expected_trust_anchor_sha256: str,
    expected_operator_principal: str,
) -> None:
    if (
        re.fullmatch(_SHA256_PATTERN, expected_trust_anchor_sha256) is None
        or re.fullmatch(_PRINCIPAL_PATTERN, expected_operator_principal) is None
        or anchor.trust_anchor_sha256 != expected_trust_anchor_sha256
        or anchor.operator_principal != expected_operator_principal
    ):
        raise ModelPolicyEligibilityAuthorityError(
            "policy trust anchor differs from independently expected authority"
        )


def _required_evaluation_expiry(value: datetime | None) -> datetime:
    if value is None:
        raise ModelPolicyEligibilityAuthorityError(
            "policy evaluation without an expiry cannot grant selection authority"
        )
    return value


def _canonical_route_hashes(
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    label: str,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    hashes = tuple(sorted(route.route_sha256 for route in routes))
    if (not allow_empty and not hashes) or len(hashes) != len(set(hashes)):
        raise ModelPolicyEligibilityAuthorityError(
            f"policy authority {label} routes must be nonempty and unique"
        )
    return hashes


def _require_statement_matches_evidence(
    statement: ModelPolicyEligibilityAuthorityStatement,
    artifact: ModelPolicyEligibilityArtifact,
    evaluation: PolicyEligibilityEvaluation,
    audit_context: PolicyAuditContext,
    client_constraints: ClientPolicyConstraints,
    candidate_routes: tuple[PolicyEligibilityRoute, ...],
    source_observation: PolicyEligibilitySourceObservation,
    anchor: ModelPolicyEligibilityTrustAnchor,
) -> None:
    expected = build_model_policy_eligibility_authority_statement(
        artifact=artifact,
        evaluation=evaluation,
        audit_context=audit_context,
        client_constraints=client_constraints,
        candidate_routes=candidate_routes,
        source_observation=source_observation,
        trust_anchor=anchor,
        signed_at=statement.signed_at,
        expires_at=statement.expires_at,
    )
    if statement != expected:
        raise ModelPolicyEligibilityAuthorityError(
            "policy authority statement differs from its exact evidence"
        )


def _build_verification_receipt(
    *,
    statement: ModelPolicyEligibilityAuthorityStatement,
    envelope: ModelPolicyEligibilityAuthorityEnvelope,
    verified_at: datetime,
) -> ModelPolicyEligibilityAuthorityVerificationReceipt:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "verified_at": verified_at,
        "signed_at": statement.signed_at,
        "expires_at": statement.expires_at,
        "operator_principal": statement.operator_principal,
        "trust_anchor_sha256": statement.trust_anchor_sha256,
        "artifact_sha256": statement.artifact_sha256,
        "evaluation_sha256": statement.evaluation_sha256,
        "audit_context_sha256": statement.audit_context_sha256,
        "client_constraints_sha256": statement.client_constraints_sha256,
        "technical_route_set_sha256": statement.technical_route_set_sha256,
        "eligible_route_set_sha256": statement.eligible_route_set_sha256,
        "initial_source_observation_sha256": statement.initial_source_observation_sha256,
        "source_commitment_set_sha256": statement.source_commitment_set_sha256,
        "source_observation_expires_at": statement.source_observation_expires_at,
        "statement_sha256": statement.statement_sha256,
        "signature_sha256": envelope.signature_sha256,
        "authority_envelope_sha256": envelope.authority_envelope_sha256,
        "purpose": "POLICY_SELECTION_ONLY",
        "policy_selection_authorized": False,
        "qualification_authorized": False,
        "source_egress_authorized": False,
        "general_production_authorized": False,
    }
    values["receipt_sha256"] = canonical_sha256(
        {
            **values,
            "verified_at": _utc_json_time(verified_at),
            "signed_at": _utc_json_time(statement.signed_at),
            "expires_at": _utc_json_time(statement.expires_at),
            "source_observation_expires_at": _utc_json_time(
                statement.source_observation_expires_at
            ),
        }
    )
    return ModelPolicyEligibilityAuthorityVerificationReceipt.model_validate(values)


def build_model_policy_eligibility_authority_evidence_projection(
    *,
    initial_source_observation: PolicyEligibilitySourceObservation,
    statement: ModelPolicyEligibilityAuthorityStatement,
    envelope: ModelPolicyEligibilityAuthorityEnvelope,
    trust_anchor: ModelPolicyEligibilityTrustAnchor,
    receipt: ModelPolicyEligibilityAuthorityVerificationReceipt,
) -> ModelPolicyEligibilityAuthorityEvidenceProjection:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "initial_source_observation": initial_source_observation,
        "authority_statement": statement,
        "authority_envelope": envelope,
        "trust_anchor": trust_anchor,
        "verification_receipt": receipt,
        "policy_selection_authorized": False,
        "qualification_authorized": False,
        "source_egress_authorized": False,
        "general_production_authorized": False,
    }
    values["projection_sha256"] = canonical_sha256(
        {
            key: (value.model_dump(mode="json") if isinstance(value, BaseModel) else value)
            for key, value in values.items()
        }
    )
    return ModelPolicyEligibilityAuthorityEvidenceProjection.model_validate(values)


def _trusted_ssh_keygen(expected_sha256: str) -> Path:
    for candidate in (Path("/usr/bin/ssh-keygen"), Path("/bin/ssh-keygen")):
        if _executable_is_trusted(candidate) and _sha256_file(candidate) == expected_sha256:
            return candidate
    raise ModelPolicyEligibilityAuthorityError("trusted pinned ssh-keygen is unavailable")


def _executable_is_trusted(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ModelPolicyEligibilityAuthorityError(
            "policy signature verifier is unavailable"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ModelPolicyEligibilityAuthorityError(
                "policy signature verifier is not a regular file"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ModelPolicyEligibilityAuthorityError(
                "policy signature verifier changed while hashing"
            )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _verify_sshsig(
    *,
    executable: Path,
    trust_anchor: ModelPolicyEligibilityTrustAnchor,
    statement: ModelPolicyEligibilityAuthorityStatement,
    signature: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="mmaudit-policy-authority-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        allowed_signers = root / "allowed_signers"
        signature_path = root / "policy.sig"
        _write_private_file(
            allowed_signers,
            f"{trust_anchor.operator_principal} {trust_anchor.public_key}\n".encode("ascii"),
        )
        _write_private_file(signature_path, signature.encode("ascii"))
        try:
            result = subprocess.run(
                [
                    str(executable),
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed_signers),
                    "-I",
                    trust_anchor.operator_principal,
                    "-n",
                    POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=model_policy_eligibility_authority_statement_bytes(statement),
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=_VERIFY_TIMEOUT_SECONDS,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                shell=False,
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ModelPolicyEligibilityAuthorityError(
                "policy SSH signature verification failed"
            ) from exc
        if result.returncode != 0:
            raise ModelPolicyEligibilityAuthorityError("policy SSH signature is not trusted")


def _write_private_file(path: Path, content: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private policy-authority file made no write progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ModelPolicyEligibilityAuthorityError(
            "private policy verifier file could not be written"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _decode_ed25519_public_key(value: str) -> bytes:
    parts = value.split(" ")
    if len(parts) != 2 or parts[0] != "ssh-ed25519" or not parts[1]:
        raise ValueError("policy trust anchor requires a canonical ssh-ed25519 public key")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("policy trust-anchor public key is malformed") from exc
    if base64.b64encode(decoded).decode("ascii") != parts[1]:
        raise ValueError("policy trust-anchor public key is not canonically encoded")
    algorithm, remainder = _read_ssh_string(decoded)
    key, remainder = _read_ssh_string(remainder)
    if algorithm != b"ssh-ed25519" or len(key) != 32 or remainder:
        raise ValueError("policy trust anchor is not an exact Ed25519 public key")
    return key


def _read_ssh_string(value: bytes) -> tuple[bytes, bytes]:
    if len(value) < 4:
        raise ValueError("policy SSH public key is truncated")
    size = int.from_bytes(value[:4], "big")
    if size > len(value) - 4:
        raise ValueError("policy SSH public key has an invalid field length")
    return value[4 : 4 + size], value[4 + size :]


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    value = _utc_time(value, label=label)
    if value.microsecond != 0:
        raise ModelPolicyEligibilityAuthorityError(f"{label} must be a whole-second UTC timestamp")
    return value


def _utc_time(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ModelPolicyEligibilityAuthorityError(f"{label} must be UTC")
    return value


def _utc_json_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
