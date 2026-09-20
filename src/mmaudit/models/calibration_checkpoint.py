"""Versioned checkpoint publication preimages, never authenticated log or chain evidence."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.models import evidence_seal_authority as _transparency
from mmaudit.models.evidence_seal_authority import EvidenceTransparencyPrefixProof
from mmaudit.orchestration.calibration_publication import (
    CalibrationPublicationSubject,
    PublicationPhase,
    _PublicationData,
    calibration_publication_subject_bytes,
    read_calibration_publication_subject,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES = 2_000_000
MAX_CALIBRATION_CHECKPOINT_LOG_LEAVES = _transparency._MAX_LOG_LEAVES
_SHA = r"^[0-9a-f]{64}$"


class CalibrationCheckpointSubject(_PublicationData):
    """Explicitly domain-separated subject binding one population phase to its log history."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["CALIBRATION_CHECKPOINT_SUBJECT"] = "CALIBRATION_CHECKPOINT_SUBJECT"
    publication_profile: Literal["CALIBRATION_TRANSPARENCY_CHECKPOINT_V1"] = (
        "CALIBRATION_TRANSPARENCY_CHECKPOINT_V1"
    )
    phase: PublicationPhase
    population_subject_sha256: str = Field(pattern=_SHA)
    registration_event_sha256: str = Field(pattern=_SHA)
    registration_checkpoint_subject_sha256: str | None = Field(pattern=_SHA)
    transparency_proof: EvidenceTransparencyPrefixProof
    subject_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def phase_inclusion_and_hash_are_exact(self) -> Self:
        if (
            self.transparency_proof.authority_subject_sha256 != self.population_subject_sha256
            or (self.phase == "POPULATION_REGISTRATION")
            != (self.registration_checkpoint_subject_sha256 is None)
            or (
                self.phase == "MEASURED_POPULATION"
                and self.transparency_proof.previous_checkpoint is None
            )
            or self.subject_sha256
            != canonical_sha256(self.model_dump(mode="json", exclude={"subject_sha256"}))
        ):
            raise ValueError("checkpoint subject phase, inclusion or hash differs")
        return self


def read_calibration_checkpoint_subject(raw: bytes) -> CalibrationCheckpointSubject:
    """Read bounded canonical data without authenticating its asserted log identity."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES:
        raise ValueError("checkpoint subject bytes are absent or over bound")
    subject = CalibrationCheckpointSubject.model_validate_json(raw, strict=True)
    if stable_json(subject.model_dump(mode="json")).encode() != raw:
        raise ValueError("checkpoint subject bytes are not canonical")
    return subject


def calibration_checkpoint_subject_bytes(subject: CalibrationCheckpointSubject) -> bytes:
    if type(subject) is not CalibrationCheckpointSubject:
        raise ValueError("checkpoint publication requires its exact subject type")
    raw = stable_json(subject.model_dump(mode="json")).encode()
    read_calibration_checkpoint_subject(raw)
    return raw


def calibration_checkpoint_publication_request(subject: CalibrationCheckpointSubject) -> bytes:
    """Return the checkpoint-envelope digest, never the old population-only digest."""

    validated = read_calibration_checkpoint_subject(calibration_checkpoint_subject_bytes(subject))
    return bytes.fromhex(validated.subject_sha256)


def _require_pin(value: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("checkpoint publication requires an exact original checkpoint pin")


def _proof_bytes(proof: EvidenceTransparencyPrefixProof) -> bytes:
    if type(proof) is not EvidenceTransparencyPrefixProof:
        raise ValueError("checkpoint publication requires its exact inclusion/extension proof")
    raw = stable_json(proof.model_dump(mode="json")).encode()
    if len(raw) > MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES:
        raise ValueError("checkpoint inclusion/extension proof exceeds its byte bound")
    checked = EvidenceTransparencyPrefixProof.model_validate_json(raw, strict=True)
    if stable_json(checked.model_dump(mode="json")).encode() != raw:
        raise ValueError("checkpoint proof is not canonical")
    return raw


def build_calibration_checkpoint_subject(
    *,
    subject: CalibrationPublicationSubject,
    transparency_proof: EvidenceTransparencyPrefixProof,
    expected_checkpoint_sha256: str,
    registration: CalibrationCheckpointSubject | None = None,
) -> CalibrationCheckpointSubject:
    """Bind exact supplied data; a source owner must separately retain original custody."""

    _require_pin(expected_checkpoint_sha256)
    population = read_calibration_publication_subject(
        calibration_publication_subject_bytes(subject)
    )
    proof = EvidenceTransparencyPrefixProof.model_validate_json(_proof_bytes(transparency_proof))
    if (
        proof.checkpoint.checkpoint_sha256 != expected_checkpoint_sha256
        or proof.authority_subject_sha256 != population.subject_sha256
    ):
        raise ValueError("checkpoint proof differs from the original checkpoint or population")
    prior = None
    if population.phase == "POPULATION_REGISTRATION":
        if registration is not None:
            raise ValueError("registration checkpoint cannot name a calibration predecessor")
    else:
        if type(registration) is not CalibrationCheckpointSubject:
            raise ValueError("measurement checkpoint requires its original registration")
        prior = read_calibration_checkpoint_subject(
            calibration_checkpoint_subject_bytes(registration)
        )
        first = prior.transparency_proof
        if (
            prior.phase != "POPULATION_REGISTRATION"
            or prior.registration_event_sha256 != population.population_events[0].event_sha256
            or proof.previous_checkpoint != first.checkpoint
            or proof.leaf_sha256s[: first.checkpoint.tree_size] != first.leaf_sha256s
            or proof.subject_leaf_index < first.checkpoint.tree_size
        ):
            raise ValueError("measurement checkpoint does not extend its original registration")
    provisional = CalibrationCheckpointSubject.model_construct(
        phase=population.phase,
        population_subject_sha256=population.subject_sha256,
        registration_event_sha256=population.population_events[0].event_sha256,
        registration_checkpoint_subject_sha256=prior.subject_sha256 if prior is not None else None,
        transparency_proof=proof,
        subject_sha256="0" * 64,
    )
    material = provisional.model_dump(mode="json", exclude={"subject_sha256"})
    return read_calibration_checkpoint_subject(
        stable_json({**material, "subject_sha256": canonical_sha256(material)}).encode()
    )


def extend_calibration_checkpoint_proof(
    *,
    population_subject_sha256: str,
    log_id_sha256: str,
    previous: EvidenceTransparencyPrefixProof | None,
) -> EvidenceTransparencyPrefixProof:
    """Append one actual subject using original Merkle primitives; no history is authenticated."""

    _require_pin(population_subject_sha256)
    _require_pin(log_id_sha256)
    if previous is None:
        return _transparency.build_transparency_prefix_proof(
            log_id_sha256=log_id_sha256,
            authority_subject_sha256s=(population_subject_sha256,),
        )
    if (
        type(previous) is not EvidenceTransparencyPrefixProof
        or not 0 < len(previous.leaf_sha256s) < MAX_CALIBRATION_CHECKPOINT_LOG_LEAVES
    ):
        raise ValueError("checkpoint extension requires a bounded original prefix")
    prior = EvidenceTransparencyPrefixProof.model_validate_json(_proof_bytes(previous))
    if prior.checkpoint.log_id_sha256 != log_id_sha256:
        raise ValueError("checkpoint extension changed its original log identity")
    leaf = _transparency._subject_leaf_sha256(population_subject_sha256)
    leaves = (*prior.leaf_sha256s, leaf)
    checkpoint_data = {
        "schema_version": "1.0",
        "log_id_sha256": log_id_sha256,
        "tree_size": len(leaves),
        "tree_root_sha256": _transparency._tree_root_sha256(leaves),
        "previous_checkpoint_sha256": prior.checkpoint.checkpoint_sha256,
    }
    proof = {
        "schema_version": "1.0",
        "previous_checkpoint": prior.checkpoint.model_dump(mode="json"),
        "checkpoint": {
            **checkpoint_data,
            "checkpoint_sha256": canonical_sha256(checkpoint_data),
        },
        "authority_subject_sha256": population_subject_sha256,
        "subject_leaf_index": len(leaves) - 1,
        "subject_leaf_sha256": leaf,
        "leaf_sha256s": leaves,
    }
    return EvidenceTransparencyPrefixProof.model_validate_json(
        stable_json({**proof, "prefix_proof_sha256": canonical_sha256(proof)}), strict=True
    )
