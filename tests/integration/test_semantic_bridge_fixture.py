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

FIXTURE = Path("tests/fixtures/solidity/semantic_bridge")


def test_real_compiler_event_facts_do_not_promote_message_assumptions(
    tmp_path: Path,
    config_factory,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    assert not Path(forge).resolve().is_relative_to(FIXTURE.resolve())
    source = FIXTURE / "src" / "BridgeRelayer.sol"
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
    assert build.index.ast_sources == ["src/BridgeRelayer.sol"]
    assert any(
        edge.graph is SolidityGraphKind.EVENT_FLOW
        and edge.provenance is SolidityProvenance.COMPILER
        and edge.metadata.get("event_resolution") == "referenced_declaration"
        for edge in graphs.edges
    )
    assumption_edges = [
        edge
        for edge in graphs.edges
        if edge.graph
        in {
            SolidityGraphKind.CROSS_CHAIN,
            SolidityGraphKind.OFFCHAIN_DEPENDENCY,
        }
    ]
    assert assumption_edges
    assert all(
        edge.provenance is SolidityProvenance.HEURISTIC
        and edge.metadata.get("deterministic_fact") is False
        for edge in assumption_edges
    )

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
