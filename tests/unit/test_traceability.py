from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
    TraceabilityRequirement,
    build_traceability_matrix,
    validate_traceability_evidence,
)

ROOT = Path(__file__).resolve().parents[2]


def test_implemented_requirement_requires_code_test_and_artifact() -> None:
    with pytest.raises(ValidationError):
        TraceabilityRequirement(
            requirement_id="MA-BAD-001",
            description="An unsupported claim.",
            implementation_status=ImplementationStatus.IMPLEMENTED,
            implementation_paths=["src/mmaudit/traceability.py"],
            last_verified_commit="test",
            required_for_complete=True,
        )


def test_current_implemented_rows_have_repository_and_runtime_evidence() -> None:
    matrix = build_traceability_matrix("test-commit")
    artifacts = {
        artifact
        for requirement in matrix.requirements
        if requirement.implementation_status is ImplementationStatus.IMPLEMENTED
        for artifact in requirement.runtime_artifacts
    }
    validate_traceability_evidence(
        matrix,
        repository_root=ROOT,
        runtime_artifacts=artifacts,
    )


def test_model_ensemble_traceability_names_qualification_runtime_evidence() -> None:
    matrix = build_traceability_matrix("test-commit")
    requirement = next(
        item for item in matrix.requirements if item.requirement_id == "MA-MODEL-ENSEMBLE"
    )

    assert "src/mmaudit/models/qualification.py" in requirement.implementation_paths
    assert "tests/unit/test_model_qualification.py" in requirement.unit_tests
    assert "model-qualification-runtime.json" in requirement.runtime_artifacts
    assert requirement.implementation_status is ImplementationStatus.PARTIALLY_IMPLEMENTED


def test_manifest_traceability_names_effective_configuration_and_replay_evidence() -> None:
    matrix = build_traceability_matrix("test-commit")
    evidence = next(
        item for item in matrix.requirements if item.requirement_id == "MA-EVIDENCE-MANIFEST"
    )
    replay = next(
        item for item in matrix.requirements if item.requirement_id == "MA-REPLAY-MANIFEST"
    )

    assert "src/mmaudit/config.py" in evidence.implementation_paths
    assert "tests/unit/test_config.py" in evidence.unit_tests
    assert "src/mmaudit/cli.py" in replay.implementation_paths
    assert "src/mmaudit/orchestration/certification.py" in replay.implementation_paths
    assert "tests/unit/test_certification.py" in replay.unit_tests


def test_report_bundle_traceability_names_complete_delivery_and_cost_custody() -> None:
    matrix = build_traceability_matrix("test-commit")
    report = next(item for item in matrix.requirements if item.requirement_id == "MA-REPORT-BUNDLE")

    assert "src/mmaudit/forensic_export.py" in report.implementation_paths
    assert "src/mmaudit/release_io.py" in report.implementation_paths
    assert "schemas/forensic_delivery_descriptor.schema.json" in report.implementation_paths
    assert "tests/unit/test_forensic_export.py" in report.unit_tests
    assert "tests/unit/test_forensic_cost_ledger.py" in report.unit_tests
    assert "forensic-report.md" in report.runtime_artifacts
    assert "run-evidence-manifest.json" in report.runtime_artifacts


@pytest.mark.parametrize(
    ("missing_kind", "expected"),
    [
        ("implementation", "outside or missing"),
        ("test", "outside or missing"),
        ("artifact", "lacks runtime artifacts"),
    ],
)
def test_validator_rejects_each_missing_evidence_form(
    tmp_path: Path,
    missing_kind: str,
    expected: str,
) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "capability.py").write_text("VALUE = True\n", encoding="utf-8")
    (tmp_path / "tests" / "test_capability.py").write_text(
        "def test_capability(): assert True\n",
        encoding="utf-8",
    )
    requirement = TraceabilityRequirement(
        requirement_id="MA-EVIDENCE-001",
        description="Synthetic evidence boundary.",
        implementation_status=ImplementationStatus.IMPLEMENTED,
        implementation_paths=[
            "src/missing.py" if missing_kind == "implementation" else "src/capability.py"
        ],
        unit_tests=[
            "tests/test_missing.py" if missing_kind == "test" else "tests/test_capability.py"
        ],
        runtime_artifacts=["capability.json"],
        required_for_complete=True,
        last_verified_commit="test",
    )
    matrix = MaximumAssuranceTraceability(
        last_verified_commit="test",
        requirements=[requirement],
    )
    artifacts = set() if missing_kind == "artifact" else {"capability.json"}
    with pytest.raises(ValueError, match=expected):
        validate_traceability_evidence(
            matrix,
            repository_root=tmp_path,
            runtime_artifacts=artifacts,
        )


def test_documentation_cannot_count_as_implemented_code(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs" / "claim.md").write_text("claim\n", encoding="utf-8")
    (tmp_path / "tests" / "test_claim.py").write_text(
        "def test_claim(): assert True\n",
        encoding="utf-8",
    )
    matrix = MaximumAssuranceTraceability(
        last_verified_commit="test",
        requirements=[
            TraceabilityRequirement(
                requirement_id="MA-DOCS-001",
                description="Documentation-only capability.",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                implementation_paths=["docs/claim.md"],
                unit_tests=["tests/test_claim.py"],
                runtime_artifacts=["claim.json"],
                required_for_complete=True,
                last_verified_commit="test",
            )
        ],
    )
    with pytest.raises(ValueError, match="not executable code"):
        validate_traceability_evidence(
            matrix,
            repository_root=tmp_path,
            runtime_artifacts={"claim.json"},
        )


def test_symlinked_evidence_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    outside = tmp_path / "real.py"
    outside.write_text("VALUE = True\n", encoding="utf-8")
    (tmp_path / "src" / "capability.py").symlink_to(outside)
    (tmp_path / "tests" / "test_capability.py").write_text(
        "def test_capability(): assert True\n",
        encoding="utf-8",
    )
    matrix = MaximumAssuranceTraceability(
        last_verified_commit="test",
        requirements=[
            TraceabilityRequirement(
                requirement_id="MA-LINK-001",
                description="Symlinked evidence.",
                implementation_status=ImplementationStatus.IMPLEMENTED,
                implementation_paths=["src/capability.py"],
                unit_tests=["tests/test_capability.py"],
                runtime_artifacts=["capability.json"],
                required_for_complete=True,
                last_verified_commit="test",
            )
        ],
    )
    with pytest.raises(ValueError, match="symlink"):
        validate_traceability_evidence(
            matrix,
            repository_root=tmp_path,
            runtime_artifacts={"capability.json"},
        )


def test_traceability_schema_rejects_duplicate_ids() -> None:
    matrix = build_traceability_matrix("test-commit")
    payload = matrix.model_dump(mode="json")
    payload["requirements"].append(payload["requirements"][0])
    with pytest.raises(ValidationError):
        MaximumAssuranceTraceability.model_validate(payload)
