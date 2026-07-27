from __future__ import annotations

from pathlib import Path

from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
    build_traceability_matrix,
    validate_traceability_evidence,
    write_traceability_artifact,
)

ROOT = Path(__file__).resolve().parents[2]


def test_traceability_artifact_is_generated_and_revalidated(tmp_path: Path) -> None:
    artifact = tmp_path / "maximum_assurance_traceability.json"
    matrix = build_traceability_matrix("integration-test")
    runtime_artifacts = {
        artifact_name
        for requirement in matrix.requirements
        if requirement.implementation_status is ImplementationStatus.IMPLEMENTED
        for artifact_name in requirement.runtime_artifacts
    }
    validate_traceability_evidence(
        matrix,
        repository_root=ROOT,
        runtime_artifacts=runtime_artifacts,
    )
    write_traceability_artifact(artifact, matrix)
    loaded = MaximumAssuranceTraceability.model_validate_json(artifact.read_text(encoding="utf-8"))
    assert loaded == matrix
    assert any(
        requirement.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED
        for requirement in loaded.requirements
    )
