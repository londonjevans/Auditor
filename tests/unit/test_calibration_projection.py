"""The shared numeric projection changes neither frozen policy nor authority checks."""

from dataclasses import dataclass
from pathlib import Path

import pytest

from mmaudit.models.calibration import (
    ModelCalibrationCandidateObservation,
    ModelCalibrationDimensionDistribution,
    _derive_calibration_policy_components,
    derive_calibrated_qualification_policy,
)
from tests.unit.test_qualification_policy_calibration import (
    _baseline_policy_inputs,
    _calibration_template,
    _expanded_artifact,
)


@dataclass(frozen=True)
class _Measurements:
    """Synthetic read-only values, deliberately lacking any authority or artifact type."""

    candidates: tuple[ModelCalibrationCandidateObservation, ...]
    distributions: tuple[ModelCalibrationDimensionDistribution, ...]


@pytest.mark.asyncio
async def test_projection_matches_existing_frozen_policy_without_mutating_evidence(
    tmp_path: Path,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    original = artifact.model_dump_json()
    values = _Measurements(artifact.candidates, artifact.distributions)
    expected = _baseline_policy_inputs(artifact)
    assert _derive_calibration_policy_components(artifact) == expected
    assert _derive_calibration_policy_components(values) == expected
    assert artifact.model_dump_json() == original


@pytest.mark.asyncio
async def test_numeric_projection_cannot_replace_live_legacy_verification(tmp_path: Path) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    values = _Measurements(artifact.candidates, artifact.distributions)
    with pytest.raises(ValueError, match="typed artifact"):
        derive_calibrated_qualification_policy(
            calibration=values, trusted_calibration_verification=None
        )
    with pytest.raises(ValueError, match="live calibration verification"):
        derive_calibrated_qualification_policy(
            calibration=artifact, trusted_calibration_verification=None
        )
