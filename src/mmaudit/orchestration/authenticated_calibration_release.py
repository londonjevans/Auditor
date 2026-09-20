"""Join native calibration proposals to observed successor-release inputs.

This is not policy admission. Detached population data still needs its external
seal and independent replay, and J2 must qualify independently. The returned
transition is the existing nonauthorizing structural record, never a recreated
native proof or a legacy signed calibration artifact.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import mmaudit.config as _config
import mmaudit.models.calibration_transition as _transition
import mmaudit.models.release_attestation as _release
from mmaudit.config import AuditConfig
from mmaudit.models.calibration_transition import CalibrationReleaseTransitionArtifact
from mmaudit.models.qualification_workflow import QualificationReleaseBindings
from mmaudit.models.release_attestation import TrustedReleaseBindingObservation
from mmaudit.orchestration import authenticated_calibration_config as _proposal
from mmaudit.orchestration.authenticated_calibration_config import (
    AuthenticatedCalibrationConfigProposal,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

_COMPILED_NATIVE_RELEASE_PINS = (
    _config.MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256,
    _config.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
    _config.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
    _config.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
    _config.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
)


def _build_native_release_input_validator(
    *,
    source_release_pins: tuple[str, str, str, str, str] = _COMPILED_NATIVE_RELEASE_PINS,
) -> Callable[..., CalibrationReleaseTransitionArtifact]:
    source_pins = source_release_pins
    dependencies = (
        (_proposal, "authenticated_calibration_config_proposal_bytes"),
        (_proposal, "read_authenticated_calibration_config_proposal"),
        (_config, "canonical_audit_config_json"),
        (_config, "parse_canonical_audit_config"),
        (_release, "_require_trusted_release_observation"),
        (_transition, "qualification_policy_independent_config_sha256"),
        (_transition, "_allowed_delta_sha256"),
    )
    functions = tuple(getattr(module, name) for module, name in dependencies)
    codes = tuple(function.__code__ for function in functions)
    encode_proposal, read_proposal, encode_config, read_config, require_release, project, delta = (
        functions
    )

    def require_original_inputs() -> None:
        if any(
            getattr(module, name) is not function or function.__code__ is not code
            for (module, name), function, code in zip(dependencies, functions, codes, strict=True)
        ):
            raise ValueError("native release-input validation dependency changed")
        current = (
            _config.MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256,
            _config.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
            _config.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
            _config.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
            _config.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
        )
        if current != source_pins:
            raise ValueError("native release-input source pins changed")

    def validate(
        *,
        proposal: AuthenticatedCalibrationConfigProposal,
        successor_config: AuditConfig,
        release_bindings: QualificationReleaseBindings,
        trusted_release_observation: TrustedReleaseBindingObservation,
    ) -> CalibrationReleaseTransitionArtifact:
        """Require exact native P1/C1/P2/C2 and observed source release, without authority."""

        require_original_inputs()
        for value, expected in (
            (proposal, AuthenticatedCalibrationConfigProposal),
            (successor_config, AuditConfig),
            (release_bindings, QualificationReleaseBindings),
            (trusted_release_observation, TrustedReleaseBindingObservation),
        ):
            if type(value) is not expected:
                raise ValueError("native release-input validation requires exact input types")
        proposal_raw = encode_proposal(proposal)
        retained = read_proposal(proposal_raw)
        policy = retained.measurement_subject.policy
        calibration = retained.measurement_subject.calibration
        if policy is None or calibration is None or policy.policy_sha256 != source_pins[0]:
            raise ValueError("native proposal policy is not pinned by this source release")
        config_raw = encode_config(successor_config)
        config = read_config(config_raw)
        pins = config.maximum_assurance.qualification
        if (
            pins.policy_sha256,
            pins.corpus_version,
            pins.corpus_sha256,
            pins.ground_truth_version,
            pins.ground_truth_sha256,
        ) != source_pins:
            raise ValueError("native successor config differs from source release pins")
        if config_raw != retained.successor_effective_config_json:
            raise ValueError("native successor config differs from the complete proposed C2")
        bindings_raw = stable_json(release_bindings.model_dump(mode="json"))
        bindings = QualificationReleaseBindings.model_validate_json(bindings_raw)
        if (
            bindings.effective_config_sha256 != retained.successor_effective_config_sha256
            or bindings.benchmark_corpus_version != pins.corpus_version
            or bindings.benchmark_ground_truth_version != pins.ground_truth_version
        ):
            raise ValueError("native successor release bindings differ from C2 or truth versions")
        require_release(trusted_release_observation, bindings)
        projection_sha256 = project(config)
        if projection_sha256 != retained.policy_independent_config_sha256:
            raise ValueError("native successor release changes a protected configuration field")
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "transition_kind": "qualification_policy_only",
            "production_selection_authority": False,
            "allowed_config_path": retained.allowed_config_path,
            "predecessor_policy_sha256": retained.predecessor_policy.policy_sha256,
            "predecessor_effective_config_sha256": retained.predecessor_effective_config_sha256,
            "calibration_artifact_sha256": calibration.artifact_sha256,
            "successor_policy_sha256": policy.policy_sha256,
            "successor_effective_config_sha256": retained.successor_effective_config_sha256,
            "successor_release_bindings_sha256": bindings.bindings_sha256,
            "policy_independent_config_sha256": projection_sha256,
            "allowed_delta_sha256": delta(
                predecessor_policy_sha256=retained.predecessor_policy.policy_sha256,
                predecessor_effective_config_sha256=retained.predecessor_effective_config_sha256,
                successor_policy_sha256=policy.policy_sha256,
                successor_effective_config_sha256=retained.successor_effective_config_sha256,
                policy_independent_config_sha256=projection_sha256,
            ),
        }
        values["artifact_sha256"] = canonical_sha256(values)
        transition = CalibrationReleaseTransitionArtifact.model_validate(values)
        require_release(trusted_release_observation, bindings)
        # Recheck caller objects after the last original release observation. No
        # self-consistent replacement during validation can change this join.
        if (
            encode_proposal(proposal) != proposal_raw
            or encode_config(successor_config) != config_raw
            or stable_json(release_bindings.model_dump(mode="json")) != bindings_raw
        ):
            raise ValueError("native release inputs changed during validation")
        require_original_inputs()
        return transition

    return validate


validate_authenticated_calibration_successor_release_inputs = (
    _build_native_release_input_validator()
)
del _build_native_release_input_validator
del _COMPILED_NATIVE_RELEASE_PINS
