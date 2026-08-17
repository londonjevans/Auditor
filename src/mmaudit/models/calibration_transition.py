"""Provider-free proof of the only permitted calibration release config change.

This module is deliberately non-authorizing.  It proves that one calibrated
qualification successor release changes the effective audit configuration only at
``maximum_assurance.qualification.policy_sha256``.  Production selection still
requires the separate opaque release-pinned capability.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import Field, model_validator

from mmaudit.config import AuditConfig
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    verify_calibrated_qualification_policy_structure,
)
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.models.schemas import AuditProfile, StrictModel
from mmaudit.orchestration.manifest import canonical_sha256

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_QUALIFICATION_POLICY_CONFIG_PATH = "maximum_assurance.qualification.policy_sha256"
_POLICY_INDEPENDENT_SENTINEL = "<qualification-policy-sha256-excluded>"


class CalibrationReleaseTransitionArtifact(StrictModel):
    """Self-hashed P1/C1-to-A-to-P2/C2 structural transition evidence.

    Hashes bind the complete predecessor and successor effective configurations.
    ``policy_independent_config_sha256`` proves both full configurations share one
    canonical projection after excluding the single permitted field.  This record
    is structural evidence only and grants no runtime or production authority.
    """

    schema_version: Literal["1.0"] = "1.0"
    transition_kind: Literal["qualification_policy_only"] = "qualification_policy_only"
    production_selection_authority: Literal[False] = False
    allowed_config_path: Literal["maximum_assurance.qualification.policy_sha256"] = (
        "maximum_assurance.qualification.policy_sha256"
    )
    predecessor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    predecessor_effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    calibration_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    successor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    successor_effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    successor_release_bindings_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_independent_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    allowed_delta_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def hashes_are_canonical_and_non_authorizing(
        self,
    ) -> CalibrationReleaseTransitionArtifact:
        if self.predecessor_policy_sha256 == self.successor_policy_sha256:
            raise ValueError("calibration release transition requires a successor policy")
        expected_delta = _allowed_delta_sha256(
            predecessor_policy_sha256=self.predecessor_policy_sha256,
            predecessor_effective_config_sha256=self.predecessor_effective_config_sha256,
            successor_policy_sha256=self.successor_policy_sha256,
            successor_effective_config_sha256=self.successor_effective_config_sha256,
            policy_independent_config_sha256=self.policy_independent_config_sha256,
        )
        if self.allowed_delta_sha256 != expected_delta:
            raise ValueError("calibration release allowed-delta hash is inconsistent")
        expected_artifact = canonical_sha256(
            self.model_dump(mode="json", exclude={"artifact_sha256"})
        )
        if self.artifact_sha256 != expected_artifact:
            raise ValueError("calibration release transition self-hash is inconsistent")
        return self


def effective_config_sha256_with_qualification_policy(
    config: AuditConfig,
    *,
    policy_sha256: str,
) -> str:
    """Hash the complete config after replacing only the qualification-policy pin.

    The returned digest does not validate the replacement as this source release's
    active pin.  It is used only to reconstruct the predecessor C1 digest from a
    typed successor C2 configuration (or vice versa) for structural comparison.
    """

    if type(config) is not AuditConfig:
        raise ValueError("config transition hashing requires an exact typed AuditConfig")
    if not _is_sha256(policy_sha256):
        raise ValueError("config transition policy hash is malformed")
    validated = AuditConfig.model_validate(config.model_dump(mode="python", by_alias=True))
    payload = validated.model_dump(mode="json", by_alias=True)
    _replace_qualification_policy(payload, policy_sha256)
    return _canonical_audit_config_payload_sha256(payload)


def qualification_policy_independent_config_sha256(config: AuditConfig) -> str:
    """Hash the full effective config with only its qualification-policy pin excluded."""

    if type(config) is not AuditConfig:
        raise ValueError("config projection requires an exact typed AuditConfig")
    validated = AuditConfig.model_validate(config.model_dump(mode="python", by_alias=True))
    payload = validated.model_dump(mode="json", by_alias=True)
    _replace_qualification_policy(payload, _POLICY_INDEPENDENT_SENTINEL)
    return _canonical_audit_config_payload_sha256(payload)


def build_calibration_release_transition_artifact(
    *,
    predecessor_policy: QualificationPolicy,
    calibration: ModelCalibrationArtifact,
    successor_policy: QualificationPolicy,
    successor_effective_config: AuditConfig,
    successor_release_bindings: Any,
) -> CalibrationReleaseTransitionArtifact:
    """Build the exact non-authorizing P1/C1-to-A-to-P2/C2 transition proof.

    C1 is reconstructed from the complete typed C2 configuration by replacing the
    one allowed policy-pin field with P1.  Its resulting full hash must be the exact
    effective-config hash recorded by calibration A.  Any other configuration drift
    therefore changes that reconstructed hash and fails closed.
    """

    from mmaudit.models.qualification_workflow import QualificationReleaseBindings

    if type(predecessor_policy) is not QualificationPolicy:
        raise ValueError("calibration transition requires a typed predecessor policy")
    if type(calibration) is not ModelCalibrationArtifact:
        raise ValueError("calibration transition requires a typed calibration artifact")
    if type(successor_policy) is not QualificationPolicy:
        raise ValueError("calibration transition requires a typed successor policy")
    if type(successor_effective_config) is not AuditConfig:
        raise ValueError("calibration transition requires a typed successor config")
    if type(successor_release_bindings) is not QualificationReleaseBindings:
        raise ValueError("calibration transition requires typed successor release bindings")

    predecessor = QualificationPolicy.model_validate(predecessor_policy.model_dump(mode="json"))
    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    successor = QualificationPolicy.model_validate(successor_policy.model_dump(mode="json"))
    config = AuditConfig.model_validate(
        successor_effective_config.model_dump(mode="python", by_alias=True)
    )
    bindings = QualificationReleaseBindings.model_validate(
        successor_release_bindings.model_dump(mode="json")
    )

    if predecessor.schema_version != "1.0":
        raise ValueError("calibration transition predecessor policy must be schema v1")
    if successor.schema_version != "2.0":
        raise ValueError("calibration transition successor policy must be schema v2")
    if artifact.benchmark_policy_sha256 != predecessor.policy_sha256:
        raise ValueError("calibration artifact differs from predecessor policy P1")
    verify_calibrated_qualification_policy_structure(
        calibration=artifact,
        policy=successor,
    )

    if (
        config.profile is not AuditProfile.MAXIMUM_ASSURANCE
        or config.maximum_assurance.allow_downgrade
        or config != config.effective()
    ):
        raise ValueError(
            "calibration transition requires an effective non-downgradable "
            "maximum-assurance successor config"
        )
    pins = config.maximum_assurance.qualification
    if pins.policy_sha256 != successor.policy_sha256:
        raise ValueError("successor config does not pin successor policy P2")
    if bindings.effective_config_sha256 != config.stable_hash():
        raise ValueError("successor release bindings differ from full successor config C2")
    if (
        bindings.benchmark_corpus_version != pins.corpus_version
        or bindings.benchmark_ground_truth_version != pins.ground_truth_version
    ):
        raise ValueError("successor release bindings differ from successor benchmark versions")
    calibration_suite = (
        artifact.benchmark_corpus_version,
        artifact.benchmark_corpus_sha256,
        artifact.benchmark_ground_truth_version,
        artifact.benchmark_ground_truth_sha256,
    )
    successor_suite = (
        pins.corpus_version,
        pins.corpus_sha256,
        pins.ground_truth_version,
        pins.ground_truth_sha256,
    )
    if calibration_suite != successor_suite:
        raise ValueError("successor config benchmark pins differ from calibration A")

    predecessor_config_sha256 = effective_config_sha256_with_qualification_policy(
        config,
        policy_sha256=predecessor.policy_sha256,
    )
    if predecessor_config_sha256 != artifact.effective_config_sha256:
        raise ValueError(
            "reconstructed predecessor config C1 differs beyond the allowed policy-pin delta"
        )
    projection_sha256 = qualification_policy_independent_config_sha256(config)
    delta_sha256 = _allowed_delta_sha256(
        predecessor_policy_sha256=predecessor.policy_sha256,
        predecessor_effective_config_sha256=predecessor_config_sha256,
        successor_policy_sha256=successor.policy_sha256,
        successor_effective_config_sha256=config.stable_hash(),
        policy_independent_config_sha256=projection_sha256,
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "transition_kind": "qualification_policy_only",
        "production_selection_authority": False,
        "allowed_config_path": _QUALIFICATION_POLICY_CONFIG_PATH,
        "predecessor_policy_sha256": predecessor.policy_sha256,
        "predecessor_effective_config_sha256": predecessor_config_sha256,
        "calibration_artifact_sha256": artifact.artifact_sha256,
        "successor_policy_sha256": successor.policy_sha256,
        "successor_effective_config_sha256": config.stable_hash(),
        "successor_release_bindings_sha256": bindings.bindings_sha256,
        "policy_independent_config_sha256": projection_sha256,
        "allowed_delta_sha256": delta_sha256,
    }
    payload["artifact_sha256"] = canonical_sha256(payload)
    return CalibrationReleaseTransitionArtifact.model_validate(payload)


def verify_calibration_release_transition_artifact(
    *,
    transition: CalibrationReleaseTransitionArtifact,
    predecessor_policy: QualificationPolicy,
    calibration: ModelCalibrationArtifact,
    successor_policy: QualificationPolicy,
    successor_effective_config: AuditConfig,
    successor_release_bindings: Any,
) -> None:
    """Rebuild and require one exact transition; never issue runtime authority."""

    if type(transition) is not CalibrationReleaseTransitionArtifact:
        raise ValueError("calibration transition verification requires a typed artifact")
    validated = CalibrationReleaseTransitionArtifact.model_validate(
        transition.model_dump(mode="json")
    )
    rebuilt = build_calibration_release_transition_artifact(
        predecessor_policy=predecessor_policy,
        calibration=calibration,
        successor_policy=successor_policy,
        successor_effective_config=successor_effective_config,
        successor_release_bindings=successor_release_bindings,
    )
    if rebuilt != validated:
        raise ValueError("calibration release transition differs from exact source evidence")


def _replace_qualification_policy(payload: dict[str, Any], value: str) -> None:
    try:
        maximum_assurance = payload["maximum_assurance"]
        qualification = maximum_assurance["qualification"]
        current = qualification["policy_sha256"]
    except (KeyError, TypeError) as exc:
        raise ValueError("audit config lacks the qualification-policy pin path") from exc
    if not isinstance(current, str) or not isinstance(qualification, dict):
        raise ValueError("audit config qualification-policy pin path is malformed")
    qualification["policy_sha256"] = value


def _canonical_audit_config_payload_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _allowed_delta_sha256(
    *,
    predecessor_policy_sha256: str,
    predecessor_effective_config_sha256: str,
    successor_policy_sha256: str,
    successor_effective_config_sha256: str,
    policy_independent_config_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "transition_kind": "qualification_policy_only",
            "allowed_config_path": _QUALIFICATION_POLICY_CONFIG_PATH,
            "predecessor_policy_sha256": predecessor_policy_sha256,
            "predecessor_effective_config_sha256": predecessor_effective_config_sha256,
            "successor_policy_sha256": successor_policy_sha256,
            "successor_effective_config_sha256": successor_effective_config_sha256,
            "policy_independent_config_sha256": policy_independent_config_sha256,
        }
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
