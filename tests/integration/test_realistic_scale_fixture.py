from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import SolidityGraphKind, SolidityProvenance
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects

pytestmark = [pytest.mark.large_scale, pytest.mark.slow]

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPOSITORY_ROOT / "tests" / "fixtures" / "solidity" / "realistic_scale" / "solidity_005k"


def _explicit_test_compiler() -> Path:
    raw = os.environ.get("MMAUDIT_TEST_SOLC_EXECUTABLE", "")
    if not raw:
        pytest.skip("real scale-fixture AST validation requires an explicit test compiler")
    compiler = Path(raw)
    try:
        metadata = compiler.lstat()
        resolved = compiler.resolve(strict=True)
    except OSError:
        pytest.skip("the explicit scale-fixture compiler is unavailable")
    if (
        not compiler.is_absolute()
        or compiler.is_symlink()
        or resolved != compiler
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or resolved.is_relative_to(REPOSITORY_ROOT)
    ):
        pytest.skip("the explicit scale-fixture compiler is not a trusted canonical file")
    return compiler


def _external_forge() -> Path:
    raw = shutil.which("forge")
    if raw is None:
        pytest.skip("real scale-fixture AST validation requires external Forge")
    forge = Path(raw).resolve(strict=True)
    metadata = forge.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or forge.is_relative_to(REPOSITORY_ROOT)
    ):
        pytest.skip("external Forge is not a trusted read-only tool")
    return forge


def test_real_scale_fixture_compiler_ast_exercises_inheritance_graph(
    tmp_path: Path,
    config_factory,
) -> None:
    compiler = _explicit_test_compiler()
    forge = _external_forge()
    compiler_identity = subprocess.run(
        [str(compiler), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "HOME": str(tmp_path / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
        },
        shell=False,
    )
    if (
        compiler_identity.returncode != 0
        or re.search(r"\bVersion:\s*0\.8\.30\b", compiler_identity.stdout) is None
    ):
        pytest.skip("the explicit scale-fixture compiler is not Solidity 0.8.30")

    source_hashes = {
        path.relative_to(FIXTURE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((FIXTURE / "src").rglob("*.sol"))
    }
    output = tmp_path / "out"
    build_info = tmp_path / "build-info"
    result = subprocess.run(
        [
            str(forge),
            "build",
            "--root",
            str(FIXTURE),
            "--offline",
            "--color",
            "never",
            "--use",
            str(compiler),
            "--cache-path",
            str(tmp_path / "cache"),
            "--out",
            str(output),
            "--build-info",
            "--build-info-path",
            str(build_info),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "HOME": str(tmp_path / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
        },
        shell=False,
    )
    assert result.returncode == 0, result.stdout[-4_000:] + result.stderr[-4_000:]

    config = config_factory(
        repository={
            "max_files": 500,
            "max_walk_entries": 2_000,
            "max_file_bytes": 48_000,
            "max_discovery_bytes": 10_000_000,
        }
    )
    discovery = discover_repository(FIXTURE, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index_build = build_solidity_index(discovery, projects, [output, build_info])
    graphs = build_solidity_graphs(discovery, index_build)
    solidity_paths = {item.relative_path for item in discovery.files if item.language == "Solidity"}
    inheritance = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.INHERITANCE]

    assert set(index_build.index.ast_sources) == solidity_paths
    assert not index_build.index.fallback_sources
    assert inheritance
    assert all(edge.provenance is SolidityProvenance.COMPILER for edge in inheritance)
    assert any("SyntheticAccounting" in edge.label for edge in inheritance)
    assert {
        path.relative_to(FIXTURE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((FIXTURE / "src").rglob("*.sol"))
    } == source_hashes
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
