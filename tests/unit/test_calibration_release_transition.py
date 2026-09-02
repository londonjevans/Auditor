from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.config as config_module
from mmaudit.config import AuditConfig
from mmaudit.models.calibration import ModelCalibrationArtifact
from mmaudit.models.calibration_transition import (
    CalibrationReleaseTransitionArtifact,
    build_calibration_release_transition_artifact,
    effective_config_sha256_with_qualification_policy,
    qualification_policy_independent_config_sha256,
    verify_calibration_release_transition_artifact,
)
from mmaudit.models.qualification import QualificationPolicy, load_qualification_policy
from mmaudit.models.qualification_workflow import (
    QualificationReleaseBindings,
    seal_qualification_release_bindings,
)
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit import test_qualification_policy_calibration as policy_fixtures
from tests.unit import test_qualification_workflow as workflow_fixtures

ROOT = Path(__file__).parents[2]
PREDECESSOR_POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"


def _rehashed_calibration(
    calibration: ModelCalibrationArtifact,
    *,
    predecessor_policy_sha256: str,
    predecessor_effective_config_sha256: str,
) -> ModelCalibrationArtifact:
    payload = calibration.model_dump(mode="json")
    payload.update(
        benchmark_policy_sha256=predecessor_policy_sha256,
        effective_config_sha256=predecessor_effective_config_sha256,
    )
    payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )
    return ModelCalibrationArtifact.model_validate(payload)


def _successor_config(
    *,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    policy_sha256: str,
) -> AuditConfig:
    # This is structural successor-release simulation only.  The production issuer
    # separately captures immutable source pins and cannot be enabled this way.
    monkeypatch.setattr(
        config_module,
        "MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256",
        policy_sha256,
    )
    return config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={
            "allow_downgrade": False,
            "qualification": {
                "policy_sha256": policy_sha256,
                "corpus_version": config_module.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
                "corpus_sha256": config_module.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
                "ground_truth_version": (
                    config_module.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION
                ),
                "ground_truth_sha256": (
                    config_module.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256
                ),
            },
        },
    ).effective()


def _release_bindings(config: AuditConfig) -> QualificationReleaseBindings:
    pins = config.maximum_assurance.qualification
    return seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256=config.stable_hash(),
        prompt_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        toolchain_sha256="5" * 64,
        isolation_sha256="6" * 64,
        benchmark_corpus_version=pins.corpus_version,
        benchmark_ground_truth_version=pins.ground_truth_version,
    )


async def _transition_inputs(
    *,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    QualificationPolicy,
    ModelCalibrationArtifact,
    QualificationPolicy,
    AuditConfig,
    QualificationReleaseBindings,
    CalibrationReleaseTransitionArtifact,
]:
    predecessor = load_qualification_policy(PREDECESSOR_POLICY_PATH)
    predecessor_config = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE).effective()
    template = policy_fixtures._expanded_artifact(
        await policy_fixtures._calibration_template(tmp_path)
    )
    calibration = _rehashed_calibration(
        template,
        predecessor_policy_sha256=predecessor.policy_sha256,
        predecessor_effective_config_sha256=predecessor_config.stable_hash(),
    )
    successor = policy_fixtures._seal_policy_for_artifact(calibration)
    successor_config = _successor_config(
        config_factory=config_factory,
        monkeypatch=monkeypatch,
        policy_sha256=successor.policy_sha256,
    )
    bindings = _release_bindings(successor_config)
    transition = build_calibration_release_transition_artifact(
        predecessor_policy=predecessor,
        calibration=calibration,
        successor_policy=successor,
        successor_effective_config=successor_config,
        successor_release_bindings=bindings,
    )
    return predecessor, calibration, successor, successor_config, bindings, transition


def test_policy_replacement_hash_uses_stable_config_canonicalization(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE).effective()

    assert config.actor_model == config_module.ActorModelConfig()
    assert (
        effective_config_sha256_with_qualification_policy(
            config,
            policy_sha256=config.maximum_assurance.qualification.policy_sha256,
        )
        == config.stable_hash()
    )


@pytest.mark.asyncio
async def test_exact_policy_only_transition_is_canonical_and_non_authorizing(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    predecessor, calibration, successor, config, bindings, transition = await _transition_inputs(
        tmp_path=tmp_path,
        config_factory=config_factory,
        monkeypatch=monkeypatch,
    )

    assert transition.predecessor_policy_sha256 == predecessor.policy_sha256
    assert transition.predecessor_effective_config_sha256 == calibration.effective_config_sha256
    assert transition.calibration_artifact_sha256 == calibration.artifact_sha256
    assert transition.successor_policy_sha256 == successor.policy_sha256
    assert transition.successor_effective_config_sha256 == config.stable_hash()
    assert transition.successor_release_bindings_sha256 == bindings.bindings_sha256
    assert transition.production_selection_authority is False
    assert transition.allowed_config_path == ("maximum_assurance.qualification.policy_sha256")
    assert (
        effective_config_sha256_with_qualification_policy(
            config,
            policy_sha256=predecessor.policy_sha256,
        )
        == calibration.effective_config_sha256
    )
    assert (
        transition.policy_independent_config_sha256
        == qualification_policy_independent_config_sha256(config)
    )
    assert (
        verify_calibration_release_transition_artifact(
            transition=transition,
            predecessor_policy=predecessor,
            calibration=calibration,
            successor_policy=successor,
            successor_effective_config=config,
            successor_release_bindings=bindings,
        )
        is None
    )

    payload = transition.model_dump(mode="json")
    payload["production_selection_authority"] = True
    with pytest.raises(ValidationError):
        CalibrationReleaseTransitionArtifact.model_validate(payload)


@pytest.mark.asyncio
async def test_transition_rejects_wrong_predecessor_policy(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, calibration, successor, config, bindings, _ = await _transition_inputs(
        tmp_path=tmp_path,
        config_factory=config_factory,
        monkeypatch=monkeypatch,
    )

    with pytest.raises(ValueError, match="predecessor policy P1"):
        build_calibration_release_transition_artifact(
            predecessor_policy=workflow_fixtures._policy(),
            calibration=calibration,
            successor_policy=successor,
            successor_effective_config=config,
            successor_release_bindings=bindings,
        )


@pytest.mark.asyncio
async def test_transition_rejects_wrong_calibration_or_successor_policy(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    predecessor, calibration, successor, config, bindings, _ = await _transition_inputs(
        tmp_path=tmp_path,
        config_factory=config_factory,
        monkeypatch=monkeypatch,
    )
    wrong_calibration = _rehashed_calibration(
        calibration,
        predecessor_policy_sha256=predecessor.policy_sha256,
        predecessor_effective_config_sha256="f" * 64,
    )

    with pytest.raises(ValueError, match="calibration artifact"):
        build_calibration_release_transition_artifact(
            predecessor_policy=predecessor,
            calibration=wrong_calibration,
            successor_policy=successor,
            successor_effective_config=config,
            successor_release_bindings=bindings,
        )
    with pytest.raises(ValueError, match="calibration artifact"):
        build_calibration_release_transition_artifact(
            predecessor_policy=predecessor,
            calibration=calibration,
            successor_policy=policy_fixtures._seal_structural_v2(),
            successor_effective_config=config,
            successor_release_bindings=bindings,
        )


@pytest.mark.asyncio
async def test_transition_rejects_unrelated_effective_config_drift(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    predecessor, calibration, successor, config, _, _ = await _transition_inputs(
        tmp_path=tmp_path,
        config_factory=config_factory,
        monkeypatch=monkeypatch,
    )
    drifted = config.model_copy(
        update={"reporting": config.reporting.model_copy(update={"markdown": False})}
    )
    drifted_bindings = _release_bindings(drifted)

    with pytest.raises(ValueError, match="differs beyond the allowed policy-pin delta"):
        build_calibration_release_transition_artifact(
            predecessor_policy=predecessor,
            calibration=calibration,
            successor_policy=successor,
            successor_effective_config=drifted,
            successor_release_bindings=drifted_bindings,
        )


@pytest.mark.asyncio
async def test_transition_rejects_wrong_c2_release_binding_or_artifact(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    predecessor, calibration, successor, config, bindings, transition = await _transition_inputs(
        tmp_path=tmp_path,
        config_factory=config_factory,
        monkeypatch=monkeypatch,
    )
    wrong_bindings = seal_qualification_release_bindings(
        source_commit=bindings.source_commit,
        source_tree_sha256=bindings.source_tree_sha256,
        effective_config_sha256="e" * 64,
        prompt_sha256=bindings.prompt_sha256,
        response_schema_sha256=bindings.response_schema_sha256,
        toolchain_sha256=bindings.toolchain_sha256,
        isolation_sha256=bindings.isolation_sha256,
        benchmark_corpus_version=bindings.benchmark_corpus_version,
        benchmark_ground_truth_version=bindings.benchmark_ground_truth_version,
    )
    with pytest.raises(ValueError, match="full successor config C2"):
        build_calibration_release_transition_artifact(
            predecessor_policy=predecessor,
            calibration=calibration,
            successor_policy=successor,
            successor_effective_config=config,
            successor_release_bindings=wrong_bindings,
        )

    payload = transition.model_dump(mode="json")
    payload["successor_release_bindings_sha256"] = "d" * 64
    payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )
    rebuilt_declaration = CalibrationReleaseTransitionArtifact.model_validate(payload)
    with pytest.raises(ValueError, match="differs from exact source evidence"):
        verify_calibration_release_transition_artifact(
            transition=rebuilt_declaration,
            predecessor_policy=predecessor,
            calibration=calibration,
            successor_policy=successor,
            successor_effective_config=config,
            successor_release_bindings=bindings,
        )
