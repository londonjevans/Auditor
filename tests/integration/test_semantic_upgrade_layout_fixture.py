from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import SolidityGraphKind, SolidityProvenance
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects

FIXTURE = Path("tests/fixtures/solidity/semantic_upgrade_layout")


def test_real_foundry_storage_layout_artifacts_drive_compatibility_graphs(
    tmp_path: Path,
    config_factory,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    assert not Path(forge).resolve().is_relative_to(FIXTURE.resolve())
    source = FIXTURE / "src" / "UpgradeLayouts.sol"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    out = tmp_path / "out"
    build_info = tmp_path / "build-info"
    result = subprocess.run(
        [
            forge,
            "build",
            "--root",
            str(FIXTURE),
            "--offline",
            "--color",
            "never",
            "--cache-path",
            str(tmp_path / "cache"),
            "--out",
            str(out),
            "--build-info",
            "--build-info-path",
            str(build_info),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    config = config_factory()
    discovery = discover_repository(FIXTURE, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [out, build_info])
    graphs = build_solidity_graphs(discovery, build)
    compiler_layout = [
        entry for entry in graphs.storage_layout if entry.provenance is SolidityProvenance.COMPILER
    ]
    assert len(compiler_layout) == 15
    assert {
        entry.declaring_contract_name for entry in compiler_layout if entry.variable_name == "owner"
    } == {"BaseAccessStorage"}

    comparisons = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.UPGRADE_COMPATIBILITY
        and edge.metadata.get("comparison") == "versioned_layout"
    ]
    assert comparisons
    assert {
        edge.metadata.get("compatibility")
        for edge in comparisons
        if edge.metadata.get("to_contract") == "LayoutV2Safe"
    } == {"compatible"}
    assert any(
        edge.metadata.get("compatibility") == "incompatible"
        for edge in comparisons
        if edge.metadata.get("to_contract") == "LayoutV2Unsafe"
    )
    assert all(edge.provenance is SolidityProvenance.COMPILER for edge in comparisons)

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
