from __future__ import annotations

import hashlib
import json
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import DependencyPreparationConfig
from mmaudit.isolation.dependencies import dependency_tree_sha256, prepare_dependencies
from mmaudit.models.schemas import (
    DependencyPreparationStatus,
    DependencySbom,
    DependencyScanStatus,
    RepositoryCodeExecutionState,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.compile import compile_solidity_projects
from mmaudit.solidity.projects import discover_solidity_projects

FIXTURES = Path(__file__).parents[1] / "fixtures" / "dependency_preparation"
_INTEGRITY = (
    "sha512-"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


class _DependencyAwareIsolation:
    """Mock the off-host boundary while inspecting only its disposable workspace."""

    name = "mocked-dependency-aware-container"

    def __init__(self) -> None:
        self.compile_calls = 0
        self.saw_validated_dependency = False
        self.saw_snapshot_material = False

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del command, workspace, private_dir, rpc_port
        raise AssertionError("Hardhat must use the repository-JavaScript isolation entry point")

    def wrap_repository_javascript(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del private_dir, rpc_port
        if command[-1] == "--version":
            return [sys.executable, "-c", "print('synthetic hardhat 1.0')"]
        self.compile_calls += 1
        self.saw_validated_dependency = (
            workspace / "node_modules" / "safe-dep" / "index.js"
        ).is_file()
        self.saw_snapshot_material = (workspace / ".mmaudit-dependencies").exists()
        artifact = json.dumps(
            {
                "contractName": "Prepared",
                "sourceName": "contracts/UsesDependency.sol",
                "abi": [],
            }
        )
        code = (
            "from pathlib import Path; "
            "target = Path('artifacts/contracts/UsesDependency.sol'); "
            "target.mkdir(parents=True, exist_ok=True); "
            f"(target / 'Prepared.json').write_text({artifact!r}, encoding='utf-8')"
        )
        return [sys.executable, "-c", code]


def _copy_fixture(tmp_path: Path, name: str) -> Path:
    root = tmp_path / "repository"
    shutil.copytree(FIXTURES / name, root)
    return root


def _projects(root: Path, config_factory):
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    return discover_solidity_projects(discovery, config.smart_contracts)


def _snapshot_config(
    root: Path,
    *,
    package_name: str,
    lockfile_sha256: str | None = None,
    advisories: list[dict[str, Any]] | None = None,
) -> DependencyPreparationConfig:
    snapshot_dir = root / ".mmaudit-dependencies"
    package_root = snapshot_dir / "packages" / package_name
    lockfile = root / "package-lock.json"
    snapshot = {
        "schema_version": "1.0",
        "projects": [
            {
                "project_root": ".",
                "lockfile": "package-lock.json",
                "lockfile_sha256": lockfile_sha256
                or hashlib.sha256(lockfile.read_bytes()).hexdigest(),
                "packages": [
                    {
                        "lock_path": f"node_modules/{package_name}",
                        "name": package_name,
                        "version": "1.0.0",
                        "source": f"packages/{package_name}",
                        "tree_sha256": dependency_tree_sha256(package_root),
                    }
                ],
            }
        ],
        "advisories": advisories or [],
    }
    snapshot_path = snapshot_dir / "snapshot.json"
    snapshot_path.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return DependencyPreparationConfig(
        enabled=True,
        required=True,
        offline_snapshot_path=".mmaudit-dependencies/snapshot.json",
        offline_snapshot_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
    )


def test_dependency_preparation_is_disabled_by_default(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")

    run = prepare_dependencies(
        root,
        _projects(root, config_factory),
        DependencyPreparationConfig(),
        tmp_path / "private-disabled",
    )

    assert run.results[0].status is DependencyPreparationStatus.DISABLED
    assert run.prepared_roots == {}
    assert run.sboms == []


def test_safe_offline_snapshot_is_checked_scanned_copied_and_serialized(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")
    config = _snapshot_config(root, package_name="safe-dep")

    run = prepare_dependencies(
        root,
        _projects(root, config_factory),
        config,
        tmp_path / "private" / "dependency-preparation",
    )

    result = run.results[0]
    assert result.status is DependencyPreparationStatus.PREPARED
    assert result.scan_status is DependencyScanStatus.PASSED
    assert result.checks and all(result.checks.values())
    assert result.packages[0].integrity == _INTEGRITY
    assert result.copied_files == 2
    prepared = run.prepared_roots["."]
    assert (prepared / "safe-dep" / "index.js").is_file()
    assert (prepared / "safe-dep" / "package.json").is_file()
    assert not (prepared / "not-required").exists()
    assert not (prepared / "safe-dep" / "index.js").stat().st_mode & (
        stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )
    assert not (root / "postinstall-executed.marker").exists()

    sbom_payload = run.sboms[0].model_dump(mode="json", by_alias=True)
    assert sbom_payload["bomFormat"] == "CycloneDX"
    assert sbom_payload["specVersion"] == "1.5"
    assert sbom_payload["components"][0]["bom-ref"].startswith("pkg:npm/safe-dep@1.0.0")
    assert DependencySbom.model_validate(sbom_payload) == run.sboms[0]


def test_validated_dependencies_are_overlaid_only_in_the_private_compile_workspace(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")
    dependency_config = _snapshot_config(root, package_name="safe-dep")
    projects = _projects(root, config_factory)
    private_root = tmp_path / "private"
    prepared = prepare_dependencies(
        root,
        projects,
        dependency_config,
        private_root / "dependency-preparation",
    )
    backend = _DependencyAwareIsolation()
    compilation = compile_solidity_projects(
        root,
        projects,
        config_factory(smart_contracts={"compile": True}).smart_contracts,
        private_root / "solidity-compile",
        backend=backend,
        prepared_dependencies=prepared.prepared_roots,
        require_prepared_dependencies=True,
        excluded_repository_paths=(".mmaudit-dependencies",),
    )

    result = compilation.results[0]
    assert result.status == "success"
    assert result.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
    assert backend.compile_calls == 1
    assert backend.saw_validated_dependency
    assert not backend.saw_snapshot_material
    assert not (root / "node_modules").exists()


def test_required_dependencies_fail_closed_before_repository_javascript_execution(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")
    projects = _projects(root, config_factory)
    backend = _DependencyAwareIsolation()

    compilation = compile_solidity_projects(
        root,
        projects,
        config_factory(smart_contracts={"compile": True}).smart_contracts,
        tmp_path / "private-missing-dependencies" / "solidity-compile",
        backend=backend,
        require_prepared_dependencies=True,
    )

    result = compilation.results[0]
    assert result.status == "unavailable"
    assert result.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
    assert "validated offline dependencies are unavailable" in result.errors[0]
    assert backend.compile_calls == 0


def test_postinstall_is_rejected_without_executing_repository_javascript(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "unsafe_postinstall")
    config = _snapshot_config(root, package_name="unsafe-dep")

    run = prepare_dependencies(
        root,
        _projects(root, config_factory),
        config,
        tmp_path / "private-postinstall",
    )

    result = run.results[0]
    assert result.status is DependencyPreparationStatus.REJECTED
    assert result.scan_status is DependencyScanStatus.FAILED
    assert result.checks["lifecycle_scripts_disabled"] is False
    assert "lifecycle scripts" in result.errors[0]
    assert run.prepared_roots == {}
    assert not (root / "postinstall-executed.marker").exists()


def test_lockfile_hash_mismatch_rejects_before_copy(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")
    config = _snapshot_config(
        root,
        package_name="safe-dep",
        lockfile_sha256="f" * 64,
    )

    run = prepare_dependencies(
        root,
        _projects(root, config_factory),
        config,
        tmp_path / "private-lock-mismatch",
    )

    result = run.results[0]
    assert result.status is DependencyPreparationStatus.REJECTED
    assert result.checks["lockfile_sha256"] is False
    assert "lockfile SHA-256" in result.errors[0]
    assert run.prepared_roots == {}


def test_offline_advisory_scan_rejects_an_affected_exact_version(
    tmp_path: Path,
    config_factory,
) -> None:
    root = _copy_fixture(tmp_path, "safe_project")
    config = _snapshot_config(
        root,
        package_name="safe-dep",
        advisories=[
            {
                "advisory_id": "SYNTHETIC-ADVISORY-1",
                "package_name": "safe-dep",
                "versions": ["1.0.0"],
                "severity": "high",
                "summary": "Synthetic local advisory used for deterministic rejection.",
            }
        ],
    )

    run = prepare_dependencies(
        root,
        _projects(root, config_factory),
        config,
        tmp_path / "private-advisory",
    )

    result = run.results[0]
    assert result.status is DependencyPreparationStatus.REJECTED
    assert result.scan_status is DependencyScanStatus.FAILED
    assert result.scan_findings[0].advisory_id == "SYNTHETIC-ADVISORY-1"
    assert result.packages[0].tree_sha256 == run.sboms[0].components[0].sha256
    assert run.prepared_roots == {}


def test_dependency_preparation_configuration_requires_explicit_pinned_snapshot() -> None:
    with pytest.raises(ValidationError, match="checksum-pinned"):
        DependencyPreparationConfig(enabled=True)
    with pytest.raises(ValidationError, match="must be enabled"):
        DependencyPreparationConfig(required=True)
    with pytest.raises(ValidationError, match="dedicated repository-relative"):
        DependencyPreparationConfig(
            enabled=True,
            offline_snapshot_path="../snapshot.json",
            offline_snapshot_sha256="a" * 64,
        )


def test_published_dependency_schemas_are_strict_and_bounded() -> None:
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    snapshot = json.loads(
        (schema_root / "dependency_snapshot.schema.json").read_text(encoding="utf-8")
    )
    sbom = json.loads((schema_root / "dependency_sbom.schema.json").read_text(encoding="utf-8"))
    snapshot_project = snapshot["properties"]["projects"]["items"]
    snapshot_package = snapshot_project["properties"]["packages"]["items"]
    sbom_document = sbom["properties"]["documents"]["items"]
    sbom_component = sbom_document["properties"]["components"]["items"]

    assert snapshot["additionalProperties"] is False
    assert snapshot["properties"]["projects"]["maxItems"] == 200
    assert snapshot_project["additionalProperties"] is False
    assert snapshot_project["properties"]["packages"]["maxItems"] == 10_000
    assert snapshot_package["additionalProperties"] is False
    assert snapshot_package["properties"]["tree_sha256"]["pattern"] == "^[0-9a-f]{64}$"
    assert sbom["additionalProperties"] is False
    assert sbom_document["additionalProperties"] is False
    assert sbom_document["properties"]["components"]["maxItems"] == 10_000
    assert sbom_component["additionalProperties"] is False
    assert sbom_component["properties"]["integrity"]["pattern"].startswith("^sha512-")
