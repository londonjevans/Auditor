"""Validate safe local release evidence without contacting external services."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from mmaudit.adversarial_acceptance import load_adversarial_acceptance_manifest
from mmaudit.benchmark.engine import load_manifest, validate_benchmark_ground_truth
from mmaudit.benchmark.models import load_model_benchmark_corpus
from mmaudit.economic_acceptance import load_economic_acceptance_manifest
from mmaudit.full_protocol_acceptance import load_full_protocol_acceptance_manifest
from mmaudit.release import ReleaseStatus, load_release_gate_report
from mmaudit.release_artifacts import (
    observe_release_artifacts,
    write_release_artifact_evidence,
)
from mmaudit.snapshots.compare import (
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import load_deployment_snapshot

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> None:
    """Validate schemas, manifests, artifacts, and the non-overstated release report."""

    parser = argparse.ArgumentParser(
        description="Validate local release evidence against an emitted mmaudit run."
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="Exact emitted run directory containing run-evidence-manifest.json.",
    )
    parser.add_argument(
        "--artifact-evidence-output",
        type=Path,
        help="Optional destination for the sealed observed artifact evidence.",
    )
    arguments = parser.parse_args(argv)

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

    artifact_evidence = observe_release_artifacts(
        run_dir=arguments.run_dir,
        repository_root=ROOT,
    )

    release = load_release_gate_report(ROOT / "docs" / "release_gate_report.json")
    if release.status is ReleaseStatus.FAILED or not release.safe_local_gates_complete:
        raise ValueError("safe local release gates are not complete")
    if arguments.artifact_evidence_output is not None:
        absolute_output = Path(os.path.abspath(arguments.artifact_evidence_output))
        if _directory_contains_output(
            directory=Path(os.path.abspath(arguments.run_dir)),
            output=absolute_output,
        ):
            raise ValueError("release artifact evidence output must be outside the emitted run")
        write_release_artifact_evidence(
            absolute_output,
            artifact_evidence,
        )
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


def _directory_contains_output(*, directory: Path, output: Path) -> bool:
    """Compare ancestor identities so case aliases cannot bypass containment."""

    try:
        directory_metadata = directory.stat()
        current = output.parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError("release artifact evidence paths are unavailable") from exc
    while True:
        if os.path.samestat(current.stat(), directory_metadata):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


if __name__ == "__main__":
    main()
