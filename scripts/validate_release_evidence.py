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
from mmaudit.release_artifacts import (
    observe_release_artifacts,
    write_release_artifact_evidence,
)
from mmaudit.release_validation import validate_release_report
from mmaudit.snapshots.compare import (
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import load_deployment_snapshot

ROOT = Path(__file__).resolve().parents[1]


def _explicit_path(value: str) -> Path:
    """Reject empty CLI path values instead of interpreting them as the current directory."""

    if (
        not value.strip()
        or len(value.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("path must be explicit bounded single-line text")
    return Path(value)


def _explicit_relative_path(value: str) -> str:
    """Retain a non-empty relative path for descriptor-safe validation downstream."""

    if (
        not value.strip()
        or len(value.encode("utf-8")) > 4_096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("relative path must be explicit bounded single-line text")
    return value


def main(argv: list[str] | None = None) -> None:
    """Observe artifacts or authoritatively validate one explicit release report."""

    parser = argparse.ArgumentParser(
        description="Observe run artifacts or validate an explicit mmaudit release report."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--artifact-only",
        action="store_true",
        help="Observe one emitted run without loading or validating a release report.",
    )
    mode.add_argument(
        "--full",
        action="store_true",
        help="Authoritatively validate an explicit release report and all bound evidence.",
    )
    parser.add_argument(
        "--run-dir",
        type=_explicit_path,
        help="Exact emitted run directory containing run-evidence-manifest.json.",
    )
    parser.add_argument(
        "--artifact-evidence-output",
        type=_explicit_path,
        help="Artifact-only destination for the sealed observed artifact evidence.",
    )
    parser.add_argument(
        "--report-root",
        type=_explicit_path,
        help="Full-mode root beneath which the report path must resolve.",
    )
    parser.add_argument(
        "--report-path",
        "--report-relative-path",
        dest="report_path",
        type=_explicit_relative_path,
        help="Full-mode report path relative to --report-root.",
    )
    parser.add_argument(
        "--evidence-root",
        type=_explicit_path,
        help="Full-mode root containing the report's five fixed evidence inputs.",
    )
    parser.add_argument(
        "--release-repository",
        "--release-repository-root",
        dest="release_repository",
        type=_explicit_path,
        help="Full-mode mmaudit release-candidate repository root.",
    )
    parser.add_argument(
        "--target-repository",
        "--target-repository-root",
        dest="target_repository",
        type=_explicit_path,
        help="Full-mode audited target repository root.",
    )
    parser.add_argument(
        "--artifact-evidence-file",
        "--artifact-evidence-path",
        dest="artifact_evidence_file",
        type=_explicit_path,
        help="Full-mode raw artifact-evidence file used to bind the emitted run.",
    )
    parser.add_argument(
        "--run-verification-file",
        "--run-verification-path",
        dest="run_verification_file",
        type=_explicit_path,
        help="Full-mode raw verify-run output file used by authoritative re-observation.",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Full mode only: fail unless all twelve real maximum-assurance gates passed.",
    )
    arguments = parser.parse_args(argv)

    if arguments.artifact_only:
        _run_artifact_only(parser, arguments)
        return
    _run_full_validation(parser, arguments)


def _run_artifact_only(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
) -> None:
    """Observe one run without accepting any release-report input."""

    if arguments.run_dir is None:
        parser.error("--artifact-only requires --run-dir")
    full_only = {
        "--report-root": arguments.report_root,
        "--report-path": arguments.report_path,
        "--evidence-root": arguments.evidence_root,
        "--release-repository": arguments.release_repository,
        "--target-repository": arguments.target_repository,
        "--artifact-evidence-file": arguments.artifact_evidence_file,
        "--run-verification-file": arguments.run_verification_file,
        "--require-complete": arguments.require_complete,
    }
    supplied = [flag for flag, value in full_only.items() if value not in {None, False}]
    if supplied:
        parser.error("--artifact-only does not accept full-report options: " + ", ".join(supplied))

    _validate_committed_local_inputs()
    artifact_evidence = observe_release_artifacts(
        run_dir=arguments.run_dir,
        repository_root=ROOT,
    )
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
        "release artifact observation valid: "
        f"run_id={artifact_evidence.run_id} "
        f"artifacts={artifact_evidence.artifact_count}"
    )


def _run_full_validation(
    parser: argparse.ArgumentParser,
    arguments: argparse.Namespace,
) -> None:
    """Run authoritative validation with no implicit report or repository paths."""

    if arguments.artifact_evidence_output is not None:
        parser.error("--full does not accept --artifact-evidence-output")
    required = {
        "--report-root": arguments.report_root,
        "--report-path": arguments.report_path,
        "--evidence-root": arguments.evidence_root,
        "--release-repository": arguments.release_repository,
        "--run-dir": arguments.run_dir,
        "--target-repository": arguments.target_repository,
        "--artifact-evidence-file": arguments.artifact_evidence_file,
        "--run-verification-file": arguments.run_verification_file,
    }
    missing = [flag for flag, value in required.items() if value is None]
    if missing:
        parser.error("--full requires explicit arguments: " + ", ".join(missing))

    report = validate_release_report(
        report_root=arguments.report_root,
        report_relative_path=arguments.report_path,
        evidence_root=arguments.evidence_root,
        release_repository_root=arguments.release_repository,
        emitted_run_dir=arguments.run_dir,
        target_repository_root=arguments.target_repository,
        artifact_evidence_path=arguments.artifact_evidence_file,
        run_verification_path=arguments.run_verification_file,
        require_complete=arguments.require_complete,
    )
    print(
        "release report integrity valid: "
        f"release_status={report.status.value} "
        f"passed_gates={report.passed_gates}/{report.total_gates}"
    )


def _validate_committed_local_inputs() -> None:
    """Preserve deterministic component checks for artifact observation mode."""

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
    validate_benchmark_ground_truth(
        benchmark,
        workspace_root=ROOT,
    )
    load_model_benchmark_corpus(ROOT / "benchmarks" / "model_corpus" / "manifest.json")
    load_economic_acceptance_manifest(
        ROOT / "tests" / "fixtures" / "solidity" / "maximum_assurance_economic" / "manifest.json",
        repository_root=ROOT,
    )
    load_adversarial_acceptance_manifest(
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
