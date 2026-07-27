from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.snapshots.compare import (
    DeploymentSnapshotComparisonReport,
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
    write_snapshot_comparison,
)
from mmaudit.snapshots.schema import load_deployment_snapshot

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"


def test_matching_offline_compiler_artifact_reports_links_and_immutables(
    tmp_path: Path,
) -> None:
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    artifacts = load_compiler_contract_artifacts(
        FIXTURES,
        [Path("compiler_artifacts/matching-compiler-artifact.json")],
    )
    report = compare_deployment_snapshot(snapshot, artifacts)

    assert report.status is SnapshotComparisonStatus.MATCHED
    assert report.snapshot_sha256 == snapshot.snapshot_sha256
    assert report.contracts_expected == report.contracts_compared == 1
    assert report.contracts_matched == 1
    comparison = report.comparisons[0]
    assert comparison.artifact_hash_match
    assert comparison.bytecode_length_match
    assert comparison.bytecode_match
    assert comparison.compiler_setting_differences == []
    assert comparison.library_links[0].matched
    assert (
        comparison.library_links[0].deployed_value == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert comparison.immutables[0].matched
    assert comparison.immutables[0].deployed_value == "0x0000002a"

    output = tmp_path / "snapshot-comparison.json"
    write_snapshot_comparison(output, report)
    assert (
        DeploymentSnapshotComparisonReport.model_validate_json(output.read_text(encoding="utf-8"))
        == report
    )


def test_mismatching_offline_artifact_reports_code_links_and_compiler_settings() -> None:
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    artifacts = load_compiler_contract_artifacts(
        FIXTURES,
        [Path("compiler_artifacts/mismatching-compiler-artifact.json")],
    )
    report = compare_deployment_snapshot(snapshot, artifacts)

    assert report.status is SnapshotComparisonStatus.MISMATCHED
    assert report.contracts_matched == 0
    comparison = report.comparisons[0]
    assert not comparison.artifact_hash_match
    assert comparison.bytecode_length_match
    assert not comparison.bytecode_match
    assert {item.field for item in comparison.compiler_setting_differences} == {
        "compiler_version",
        "evm_version",
        "metadata_bytecode_hash",
        "optimizer_runs",
        "settings_sha256",
        "via_ir",
    }
    assert not comparison.library_links[0].matched
    assert (
        comparison.library_links[0].compiler_address == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    assert comparison.immutables[0].matched


def test_missing_compiler_artifact_is_inconclusive_not_a_match() -> None:
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    report = compare_deployment_snapshot(snapshot, [])

    assert report.status is SnapshotComparisonStatus.INCONCLUSIVE
    assert report.contracts_compared == report.contracts_matched == 0
    assert report.comparisons[0].limitation is not None
    assert "unavailable" in report.comparisons[0].limitation


def test_comparison_report_rejects_hash_tampering() -> None:
    snapshot = load_deployment_snapshot(FIXTURES / "valid.json")
    artifacts = load_compiler_contract_artifacts(
        FIXTURES,
        [Path("compiler_artifacts/matching-compiler-artifact.json")],
    )
    report = compare_deployment_snapshot(snapshot, artifacts)
    payload = report.model_dump(mode="json")
    payload["contracts_matched"] = 0

    with pytest.raises(ValidationError):
        DeploymentSnapshotComparisonReport.model_validate(payload)


def test_build_info_projection_is_parsed_without_repository_execution(
    tmp_path: Path,
) -> None:
    metadata = json.loads(
        (FIXTURES / "compiler_artifacts" / "matching-compiler-artifact.json").read_text(
            encoding="utf-8"
        )
    )["metadata"]
    settings = metadata["settings"]
    artifact = {
        "solcLongVersion": metadata["compiler"]["version"],
        "input": {"settings": settings},
        "output": {
            "contracts": {
                "src/SyntheticVault.sol": {
                    "SyntheticVault": {
                        "metadata": json.dumps(metadata),
                        "evm": {
                            "deployedBytecode": {
                                "object": ("0x6000" + ("00" * 20) + "00000000" + "00006001"),
                                "linkReferences": {
                                    "lib/SyntheticLibrary.sol": {
                                        "SyntheticLibrary": [{"start": 2, "length": 20}]
                                    }
                                },
                                "immutableReferences": {"42": [{"start": 22, "length": 4}]},
                            }
                        },
                    }
                }
            }
        },
    }
    path = tmp_path / "build-info.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")

    projections = load_compiler_contract_artifacts(tmp_path, [Path("build-info.json")])

    assert len(projections) == 1
    assert projections[0].source_path == "src/SyntheticVault.sol"
    assert projections[0].contract_name == "SyntheticVault"
    assert projections[0].compiler.settings_sha256
    assert projections[0].library_references[0].configured_address is not None


def test_compiler_artifact_loader_refuses_links_and_path_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-compiler-artifact.json"
    outside.write_text(
        (FIXTURES / "compiler_artifacts" / "matching-compiler-artifact.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="regular non-link"):
        load_compiler_contract_artifacts(tmp_path, [Path("linked.json")])
    with pytest.raises(ValueError, match="escaped"):
        load_compiler_contract_artifacts(tmp_path, [outside])
