"""Validate safe local release evidence without contacting external services."""

from __future__ import annotations

import json
from pathlib import Path

from mmaudit.adversarial_acceptance import load_adversarial_acceptance_manifest
from mmaudit.benchmark.engine import load_manifest, validate_benchmark_ground_truth
from mmaudit.benchmark.models import load_model_benchmark_corpus
from mmaudit.economic_acceptance import load_economic_acceptance_manifest
from mmaudit.full_protocol_acceptance import load_full_protocol_acceptance_manifest
from mmaudit.release import ReleaseStatus, load_release_gate_report
from mmaudit.snapshots.compare import (
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import load_deployment_snapshot
from mmaudit.traceability import (
    ImplementationStatus,
    build_traceability_matrix,
    validate_traceability_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Validate schemas, manifests, artifacts, and the non-overstated release report."""

    schema_paths = sorted((ROOT / "schemas").glob("*.json"))
    if not schema_paths:
        raise ValueError("release validation found no published schemas")
    for path in schema_paths:
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise ValueError(f"release schema is not an unshared regular file: {path.name}")
        schema = json.loads(path.read_text(encoding="utf-8"))
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"release schema does not declare draft 2020-12: {path.name}")
        if schema.get("additionalProperties") is not False:
            raise ValueError(f"release schema root is not strict: {path.name}")

    benchmark = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    ground_truth = validate_benchmark_ground_truth(
        benchmark,
        workspace_root=ROOT,
    )
    model_corpus = load_model_benchmark_corpus(
        ROOT / "benchmarks" / "model_corpus" / "manifest.json"
    )
    economic = load_economic_acceptance_manifest(
        ROOT / "tests" / "fixtures" / "solidity" / "maximum_assurance_economic" / "manifest.json",
        repository_root=ROOT,
    )
    adversarial = load_adversarial_acceptance_manifest(
        ROOT / "tests" / "fixtures" / "adversarial_repository" / "cases.json"
    )
    full_root = ROOT / "tests" / "fixtures" / "full_protocol_offline"
    full_protocol = load_full_protocol_acceptance_manifest(full_root / "manifest.json")

    snapshot = load_deployment_snapshot(full_root / full_protocol.expectations.snapshot_path)
    compiler_artifacts = load_compiler_contract_artifacts(
        full_root,
        [Path(full_protocol.expectations.compiler_artifact_path)],
    )
    comparison = compare_deployment_snapshot(snapshot, compiler_artifacts)
    if comparison.status is not SnapshotComparisonStatus.MATCHED:
        raise ValueError("release full-protocol compiler artifact does not match the snapshot")

    foundry_ast = (
        ROOT / "tests" / "fixtures" / "solidity" / "foundry" / "out" / "Vault.sol" / "Vault.json"
    )
    if foundry_ast.is_symlink() or not foundry_ast.is_file() or foundry_ast.stat().st_nlink != 1:
        raise ValueError("release compiler AST fixture is unavailable or linked")
    foundry_payload = json.loads(foundry_ast.read_text(encoding="utf-8"))
    if not isinstance(foundry_payload.get("ast"), dict):
        raise ValueError("release compiler AST fixture has no normalized AST")

    traceability = build_traceability_matrix("UNCOMMITTED-WORKTREE")
    runtime_artifacts = {
        artifact
        for requirement in traceability.requirements
        if requirement.implementation_status is ImplementationStatus.IMPLEMENTED
        for artifact in requirement.runtime_artifacts
    }
    validate_traceability_evidence(
        traceability,
        repository_root=ROOT,
        runtime_artifacts=runtime_artifacts,
    )

    release = load_release_gate_report(ROOT / "docs" / "release_gate_report.json")
    if release.status is ReleaseStatus.FAILED or not release.safe_local_gates_complete:
        raise ValueError("safe local release gates are not complete")
    print(
        "release evidence valid: "
        f"schemas={len(schema_paths)} "
        f"benchmark_sources={len(ground_truth)} "
        f"model_cases={len(model_corpus.cases)} "
        f"economic_cases={len(economic.cases)} "
        f"adversarial_cases={len(adversarial.cases)} "
        f"full_protocol_files={len(full_protocol.fixture_files)} "
        f"release_status={release.status.value}"
    )


if __name__ == "__main__":
    main()
