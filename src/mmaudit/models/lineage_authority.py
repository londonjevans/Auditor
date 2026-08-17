"""Authenticated, calibration-only authority for operator lineage decisions.

The signed envelope never authorizes source egress or production selection.  It
only permits an exact, pending candidate registry to contribute operator-reviewed
root identities to a non-dispositive calibration artifact.
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

from mmaudit.models.discovery import OpenRouterModelDiscoveryRunManifest
from mmaudit.models.lineage_review import (
    ModelLineageReviewArtifact,
    load_model_lineage_review_artifact,
)
from mmaudit.models.qualification import CandidateRegistry, LineageReviewStatus
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence, write_json_evidence

LINEAGE_AUTHORITY_FILENAME = "model-lineage-authority.json"
LINEAGE_AUTHORITY_NAMESPACE: Literal["mmaudit-model-lineage-review-v1"] = (
    "mmaudit-model-lineage-review-v1"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PRINCIPAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$"
_MAX_SIGNATURE_BYTES = 16_384
_MAX_AUTHORITY_BYTES = 262_144
_MAX_VALIDITY = timedelta(days=31)
_VERIFY_TIMEOUT_SECONDS = 10


class ModelLineageAuthorityError(ValueError):
    """Raised when signed lineage authority cannot be established exactly."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelLineageTrustAnchor(_FrozenModel):
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
            raise ValueError("lineage trust-anchor public-key hash is inconsistent")
        expected_anchor = canonical_sha256(
            self.model_dump(mode="json", exclude={"trust_anchor_sha256"})
        )
        if self.trust_anchor_sha256 != expected_anchor:
            raise ValueError("lineage trust-anchor self-hash is inconsistent")
        return self


class ModelLineageAuthorityStatement(_FrozenModel):
    """Canonical domain-separated statement signed by the operator."""

    schema_version: Literal["1.0"] = "1.0"
    signature_namespace: Literal["mmaudit-model-lineage-review-v1"] = LINEAGE_AUTHORITY_NAMESPACE
    signed_at: datetime
    expires_at: datetime
    operator_principal: str = Field(pattern=_PRINCIPAL_PATTERN)
    trust_anchor_sha256: str = Field(pattern=_SHA256_PATTERN)
    review_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    approved_root_lineages: tuple[str, ...] = Field(max_length=128)
    source_scope: Literal["PUBLIC_OPEN_SOURCE_ONLY"] = "PUBLIC_OPEN_SOURCE_ONLY"
    purpose: Literal["LINEAGE_IDENTITY_ONLY"] = "LINEAGE_IDENTITY_ONLY"
    operator_decision_authenticity: Literal["SSHSIG_ED25519_VERIFIED"] = "SSHSIG_ED25519_VERIFIED"
    provider_observation_authenticity: Literal["NOT_INDEPENDENTLY_PROVEN"] = (
        "NOT_INDEPENDENTLY_PROVEN"
    )
    calibration_identity_authorized: Literal[True] = True
    source_egress_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    statement_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("signed_at", "expires_at")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="lineage authority time")

    @field_validator("approved_root_lineages")
    @classmethod
    def roots_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", root) is None for root in value
        ):
            raise ValueError("lineage authority roots must be canonical, unique, and sorted")
        return value

    @field_validator(
        "calibration_identity_authorized",
        "source_egress_authorized",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("lineage authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def statement_is_bounded_and_self_hashed(self) -> Self:
        if self.expires_at <= self.signed_at or self.expires_at - self.signed_at > _MAX_VALIDITY:
            raise ValueError("lineage authority validity window is invalid")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"statement_sha256"}))
        if self.statement_sha256 != expected:
            raise ValueError("lineage authority statement self-hash is inconsistent")
        return self


class ModelLineageAuthorityEnvelope(_FrozenModel):
    """Bounded detached SSHSIG envelope for one exact authority statement."""

    schema_version: Literal["1.0"] = "1.0"
    signature_algorithm: Literal["SSHSIG_ED25519"] = "SSHSIG_ED25519"
    statement: ModelLineageAuthorityStatement
    detached_signature: str = Field(min_length=100, max_length=_MAX_SIGNATURE_BYTES)
    signature_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("detached_signature")
    @classmethod
    def signature_is_canonical_armor(cls, value: str) -> str:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("lineage authority signature must be ASCII armor") from exc
        if (
            len(encoded) > _MAX_SIGNATURE_BYTES
            or not value.startswith("-----BEGIN SSH SIGNATURE-----\n")
            or not value.endswith("-----END SSH SIGNATURE-----\n")
            or "\r" in value
            or any(character not in "\n" and not character.isprintable() for character in value)
        ):
            raise ValueError("lineage authority signature armor is invalid")
        return value

    @model_validator(mode="after")
    def signature_and_envelope_hashes_are_exact(self) -> Self:
        expected_signature = hashlib.sha256(self.detached_signature.encode("ascii")).hexdigest()
        if self.signature_sha256 != expected_signature:
            raise ValueError("lineage authority signature hash is inconsistent")
        expected_envelope = canonical_sha256(
            self.model_dump(mode="json", exclude={"authority_envelope_sha256"})
        )
        if self.authority_envelope_sha256 != expected_envelope:
            raise ValueError("lineage authority envelope self-hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedModelLineageCandidate:
    """One signed candidate decision exposed only after capability validation."""

    exact_model_id: str
    decision: LineageReviewStatus
    root_lineage: str | None
    reviewed_at: datetime
    lineage_binding_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedModelLineageAuthority:
    """Exact signed lineage projection returned by a live opaque capability."""

    review_artifact_sha256: str
    authority_envelope_sha256: str
    candidates: tuple[VerifiedModelLineageCandidate, ...]


@dataclass(frozen=True, slots=True)
class _RuntimeAuthorityState:
    review_artifact_sha256: str
    authority_envelope_sha256: str
    candidate_registry_sha256: str
    discovery_manifest_sha256: str
    discovery_candidate_set_sha256: str
    signed_at: datetime
    expires_at: datetime
    candidates: tuple[VerifiedModelLineageCandidate, ...]


class TrustedModelLineageReviewVerification:
    """Opaque process-local proof of an exact operator SSH signature."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> TrustedModelLineageReviewVerification:
        del cls
        raise TypeError("trusted lineage verification cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def require_for(
        self,
        *,
        candidate_registry: CandidateRegistry,
        discovery_manifest: OpenRouterModelDiscoveryRunManifest,
        campaign_started_at: datetime,
        observed_at: datetime,
    ) -> VerifiedModelLineageAuthority:
        """Require exact registry, discovery, campaign, and validity bindings."""

        return _require_trusted_lineage_capability(
            self,
            candidate_registry,
            discovery_manifest,
            campaign_started_at,
            observed_at,
        )

    def __copy__(self) -> Never:
        raise TypeError("trusted lineage verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("trusted lineage verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted lineage verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted lineage verification cannot be serialized")


def build_model_lineage_trust_anchor(
    *,
    operator_principal: str,
    public_key: str,
    verifier_executable_sha256: str,
) -> ModelLineageTrustAnchor:
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
    return ModelLineageTrustAnchor.model_validate(values)


def build_model_lineage_authority_statement(
    *,
    artifact: ModelLineageReviewArtifact,
    trust_anchor: ModelLineageTrustAnchor,
    signed_at: datetime,
    expires_at: datetime,
) -> ModelLineageAuthorityStatement:
    """Build the only statement shape accepted by the signature verifier."""

    review = ModelLineageReviewArtifact.model_validate(artifact.model_dump(mode="json"))
    anchor = ModelLineageTrustAnchor.model_validate_json(
        trust_anchor.model_dump_json(),
        strict=True,
    )
    signed_at = _whole_second_utc(signed_at, label="lineage signature time")
    expires_at = _whole_second_utc(expires_at, label="lineage signature expiry")
    freshness_deadline = review.refresh_retrieved_at + timedelta(hours=review.soft_max_age_hours)
    if (
        signed_at < review.created_at
        or expires_at > review.expires_at
        or expires_at > freshness_deadline
    ):
        raise ModelLineageAuthorityError(
            "lineage authority validity must stay within the review and current-refresh window"
        )
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "signature_namespace": LINEAGE_AUTHORITY_NAMESPACE,
        "signed_at": signed_at,
        "expires_at": expires_at,
        "operator_principal": anchor.operator_principal,
        "trust_anchor_sha256": anchor.trust_anchor_sha256,
        "review_artifact_sha256": review.artifact_sha256,
        "candidate_registry_sha256": review.candidate_registry_sha256,
        "discovery_manifest_sha256": review.discovery_manifest_sha256,
        "discovery_candidate_set_sha256": review.discovery_candidate_set_sha256,
        "refresh_source_evidence_sha256": review.refresh_source_evidence_sha256,
        "refresh_snapshot_sha256": review.refresh_snapshot_sha256,
        "refresh_semantic_sha256": review.refresh_semantic_sha256,
        "candidate_binding_set_sha256": canonical_sha256(
            [binding.model_dump(mode="json") for binding in review.candidate_bindings]
        ),
        "approved_root_lineages": review.approved_root_lineages,
        "source_scope": "PUBLIC_OPEN_SOURCE_ONLY",
        "purpose": "LINEAGE_IDENTITY_ONLY",
        "operator_decision_authenticity": "SSHSIG_ED25519_VERIFIED",
        "provider_observation_authenticity": "NOT_INDEPENDENTLY_PROVEN",
        "calibration_identity_authorized": True,
        "source_egress_authorized": False,
        "production_selection_authorized": False,
    }
    values["statement_sha256"] = canonical_sha256(
        {
            **values,
            "signed_at": _utc_json_time(signed_at),
            "expires_at": _utc_json_time(expires_at),
        }
    )
    return ModelLineageAuthorityStatement.model_validate(values)


def model_lineage_authority_statement_bytes(
    statement: ModelLineageAuthorityStatement,
) -> bytes:
    """Return the exact bytes covered by the SSHSIG namespace signature."""

    validated = ModelLineageAuthorityStatement.model_validate_json(
        statement.model_dump_json(),
        strict=True,
    )
    return json.dumps(
        validated.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def build_model_lineage_authority_envelope(
    *,
    statement: ModelLineageAuthorityStatement,
    detached_signature: bytes | str,
) -> ModelLineageAuthorityEnvelope:
    """Bind one externally produced detached signature without granting authority."""

    validated = ModelLineageAuthorityStatement.model_validate_json(
        statement.model_dump_json(),
        strict=True,
    )
    try:
        signature = (
            detached_signature.decode("ascii")
            if isinstance(detached_signature, bytes)
            else detached_signature
        )
    except UnicodeDecodeError as exc:
        raise ModelLineageAuthorityError("lineage authority signature must be ASCII") from exc
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
    return ModelLineageAuthorityEnvelope.model_validate(values)


def write_model_lineage_authority_envelope(
    output_dir: Path,
    envelope: ModelLineageAuthorityEnvelope,
) -> None:
    """Write one fresh private canonical signed-authority envelope."""

    validated = ModelLineageAuthorityEnvelope.model_validate_json(
        envelope.model_dump_json(),
        strict=True,
    )
    write_json_evidence(
        evidence_root=output_dir,
        relative_path=LINEAGE_AUTHORITY_FILENAME,
        value=validated,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )


def load_model_lineage_authority_envelope(output_dir: Path) -> ModelLineageAuthorityEnvelope:
    """Load one descriptor-safe signed-authority envelope."""

    observation = read_json_evidence(
        evidence_root=output_dir,
        relative_path=LINEAGE_AUTHORITY_FILENAME,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ModelLineageAuthorityError("lineage authority envelope must be a JSON object")
    try:
        return ModelLineageAuthorityEnvelope.model_validate_json(observation.content, strict=True)
    except ValueError as exc:
        raise ModelLineageAuthorityError("lineage authority envelope is invalid") from exc


def load_model_lineage_trust_anchor(path: Path) -> ModelLineageTrustAnchor:
    """Load an explicit descriptor-safe operator trust-anchor JSON file."""

    observation = read_json_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ModelLineageAuthorityError("lineage trust anchor must be a JSON object")
    try:
        return ModelLineageTrustAnchor.model_validate_json(observation.content, strict=True)
    except ValueError as exc:
        raise ModelLineageAuthorityError("lineage trust anchor is invalid") from exc


def load_model_lineage_authority_bundle(
    output_dir: Path,
) -> tuple[ModelLineageReviewArtifact, ModelLineageAuthorityEnvelope]:
    """Load the structural review and its detached authority envelope together."""

    return (
        load_model_lineage_review_artifact(output_dir),
        load_model_lineage_authority_envelope(output_dir),
    )


def _build_lineage_runtime_authority() -> tuple[
    Callable[..., TrustedModelLineageReviewVerification],
    Callable[..., VerifiedModelLineageAuthority],
]:
    registry: dict[
        int,
        tuple[weakref.ReferenceType[TrustedModelLineageReviewVerification], _RuntimeAuthorityState],
    ] = {}
    lock = threading.RLock()

    def issue(
        *,
        artifact: ModelLineageReviewArtifact,
        envelope: ModelLineageAuthorityEnvelope,
        trust_anchor: ModelLineageTrustAnchor,
        observed_at: datetime,
    ) -> TrustedModelLineageReviewVerification:
        review = ModelLineageReviewArtifact.model_validate(artifact.model_dump(mode="json"))
        signed = ModelLineageAuthorityEnvelope.model_validate_json(
            envelope.model_dump_json(),
            strict=True,
        )
        anchor = ModelLineageTrustAnchor.model_validate_json(
            trust_anchor.model_dump_json(),
            strict=True,
        )
        observed_at = _whole_second_utc(observed_at, label="lineage authority observation time")
        _require_statement_matches_review(signed.statement, review, anchor)
        if observed_at < signed.statement.signed_at or observed_at >= signed.statement.expires_at:
            raise ModelLineageAuthorityError("lineage authority is future-dated or expired")
        executable = _trusted_ssh_keygen(anchor.verifier_executable_sha256)
        _verify_sshsig(
            executable=executable,
            trust_anchor=anchor,
            statement=signed.statement,
            signature=signed.detached_signature,
        )
        if _sha256_file(executable) != anchor.verifier_executable_sha256:
            raise ModelLineageAuthorityError("lineage signature verifier changed during use")
        reviews = {item.review_sha256: item for item in review.reviews}
        candidates = tuple(
            VerifiedModelLineageCandidate(
                exact_model_id=binding.exact_model_id,
                decision=binding.decision,
                root_lineage=binding.root_lineage,
                reviewed_at=_required_reviewed_at(reviews[binding.review_sha256].reviewed_at),
                lineage_binding_sha256=binding.binding_sha256,
            )
            for binding in review.candidate_bindings
        )
        state = _RuntimeAuthorityState(
            review_artifact_sha256=review.artifact_sha256,
            authority_envelope_sha256=signed.authority_envelope_sha256,
            candidate_registry_sha256=review.candidate_registry_sha256,
            discovery_manifest_sha256=review.discovery_manifest_sha256,
            discovery_candidate_set_sha256=review.discovery_candidate_set_sha256,
            signed_at=signed.statement.signed_at,
            expires_at=signed.statement.expires_at,
            candidates=candidates,
        )
        capability = object.__new__(TrustedModelLineageReviewVerification)
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[TrustedModelLineageReviewVerification],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return capability

    def require(
        capability: TrustedModelLineageReviewVerification,
        candidate_registry: CandidateRegistry,
        discovery_manifest: OpenRouterModelDiscoveryRunManifest,
        campaign_started_at: datetime,
        observed_at: datetime,
    ) -> VerifiedModelLineageAuthority:
        if type(capability) is not TrustedModelLineageReviewVerification:
            raise ValueError("trusted lineage verification is absent or forged")
        with lock:
            registered = registry.get(id(capability))
        state = registered[1] if registered is not None and registered[0]() is capability else None
        if state is None:
            raise ValueError("trusted lineage verification is absent or forged")
        candidate_registry = CandidateRegistry.model_validate(
            candidate_registry.model_dump(mode="json")
        )
        discovery_manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
            discovery_manifest.model_dump(mode="json")
        )
        campaign_started_at = _utc_time(
            campaign_started_at,
            label="lineage-authorized campaign start",
        )
        observed_at = _whole_second_utc(observed_at, label="lineage authority use time")
        candidate_ids = tuple(item.exact_model_id for item in candidate_registry.candidates)
        signed_ids = tuple(item.exact_model_id for item in state.candidates)
        if (
            state.candidate_registry_sha256 != candidate_registry.registry_sha256
            or state.discovery_manifest_sha256 != discovery_manifest.manifest_sha256
            or state.discovery_candidate_set_sha256 != discovery_manifest.candidate_set_sha256
            or candidate_registry.discovery_run_sha256 != discovery_manifest.manifest_sha256
            or candidate_ids != signed_ids
        ):
            raise ValueError("trusted lineage verification differs from candidate evidence")
        if (
            campaign_started_at < state.signed_at
            or any(item.reviewed_at > campaign_started_at for item in state.candidates)
            or observed_at < campaign_started_at
            or observed_at >= state.expires_at
        ):
            raise ValueError("trusted lineage verification is not valid for the campaign time")
        return VerifiedModelLineageAuthority(
            review_artifact_sha256=state.review_artifact_sha256,
            authority_envelope_sha256=state.authority_envelope_sha256,
            candidates=state.candidates,
        )

    return issue, require


(
    verify_operator_model_lineage_authority,
    _require_trusted_lineage_capability,
) = _build_lineage_runtime_authority()


def trusted_ssh_keygen_sha256() -> str:
    """Observe the fixed system SSH verifier hash for trust-anchor provisioning."""

    for candidate in (Path("/usr/bin/ssh-keygen"), Path("/bin/ssh-keygen")):
        if _executable_is_trusted(candidate):
            return _sha256_file(candidate)
    raise ModelLineageAuthorityError("fixed trusted ssh-keygen is unavailable")


def _require_statement_matches_review(
    statement: ModelLineageAuthorityStatement,
    review: ModelLineageReviewArtifact,
    anchor: ModelLineageTrustAnchor,
) -> None:
    expected = build_model_lineage_authority_statement(
        artifact=review,
        trust_anchor=anchor,
        signed_at=statement.signed_at,
        expires_at=statement.expires_at,
    )
    if statement != expected:
        raise ModelLineageAuthorityError("lineage authority statement differs from its evidence")


def _trusted_ssh_keygen(expected_sha256: str) -> Path:
    for candidate in (Path("/usr/bin/ssh-keygen"), Path("/bin/ssh-keygen")):
        if _executable_is_trusted(candidate) and _sha256_file(candidate) == expected_sha256:
            return candidate
    raise ModelLineageAuthorityError("trusted pinned ssh-keygen is unavailable")


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
        raise ModelLineageAuthorityError("lineage signature verifier is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ModelLineageAuthorityError("lineage signature verifier is not a regular file")
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
            raise ModelLineageAuthorityError("lineage signature verifier changed while hashing")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _verify_sshsig(
    *,
    executable: Path,
    trust_anchor: ModelLineageTrustAnchor,
    statement: ModelLineageAuthorityStatement,
    signature: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="mmaudit-lineage-authority-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        allowed_signers = root / "allowed_signers"
        signature_path = root / "review.sig"
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
                    LINEAGE_AUTHORITY_NAMESPACE,
                    "-s",
                    str(signature_path),
                ],
                input=model_lineage_authority_statement_bytes(statement),
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
            raise ModelLineageAuthorityError("lineage SSH signature verification failed") from exc
        if result.returncode != 0:
            raise ModelLineageAuthorityError("lineage SSH signature is not trusted")


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
                raise OSError("private lineage file made no write progress")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise ModelLineageAuthorityError(
            "private lineage verifier file could not be written"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _decode_ed25519_public_key(value: str) -> bytes:
    parts = value.split(" ")
    if len(parts) != 2 or parts[0] != "ssh-ed25519" or not parts[1]:
        raise ValueError("lineage trust anchor requires a canonical ssh-ed25519 public key")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("lineage trust-anchor public key is malformed") from exc
    if base64.b64encode(decoded).decode("ascii") != parts[1]:
        raise ValueError("lineage trust-anchor public key is not canonically encoded")
    algorithm, remainder = _read_ssh_string(decoded)
    key, remainder = _read_ssh_string(remainder)
    if algorithm != b"ssh-ed25519" or len(key) != 32 or remainder:
        raise ValueError("lineage trust anchor is not an exact Ed25519 public key")
    return key


def _read_ssh_string(value: bytes) -> tuple[bytes, bytes]:
    if len(value) < 4:
        raise ValueError("lineage SSH public key is truncated")
    size = int.from_bytes(value[:4], "big")
    if size > len(value) - 4:
        raise ValueError("lineage SSH public key has an invalid field length")
    return value[4 : 4 + size], value[4 + size :]


def _required_reviewed_at(value: datetime | None) -> datetime:
    if value is None:
        raise ModelLineageAuthorityError("signed lineage decision lacks a review time")
    return value


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    value = _utc_time(value, label=label)
    if value.microsecond != 0:
        raise ModelLineageAuthorityError(f"{label} must be a whole-second UTC timestamp")
    return value


def _utc_time(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ModelLineageAuthorityError(f"{label} must be UTC")
    return value


def _utc_json_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
