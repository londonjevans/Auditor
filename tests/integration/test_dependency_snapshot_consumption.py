"""Real local dependency preparation from authenticated synthetic archives."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.config import DependencyPreparationConfig
from mmaudit.constants import ExitCode
from mmaudit.isolation.dependencies import prepare_dependencies
from mmaudit.isolation.dependency_snapshot import build_managed_dependency_snapshot
from mmaudit.models.schemas import (
    DependencyPreparationStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.orchestration.managed_provisioning import (
    ManagedProvisioningObservationStatus,
    ManagedProvisioningRefusalCode,
    parse_managed_provisioning_receipt,
)
from mmaudit.orchestration.managed_provisioning_runtime import (
    ManagedDependencySource,
    provision_managed_local_receipt,
    provision_managed_local_run,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainError,
    ManagedToolchainRole,
    load_packaged_managed_toolchain_bundle,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners.base import scanner_trust_pin_error, scanner_workspace_sha256
from tests.dependency_snapshot_support import setup_snapshot_inputs
from tests.managed_toolchain_support import synthetic_pinned_bundle


@pytest.mark.parametrize("partial_bundle", [False, True])
@pytest.mark.parametrize("conflicting_pin", [False, True])
def test_toolchain_pin_handoff_composes_with_real_dependency_setup_and_consumer_checks(
    tmp_path, monkeypatch, config_factory, partial_bundle, conflicting_pin
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    output = tmp_path / "receipts"
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    bundle = synthetic_pinned_bundle()
    semgrep = next(
        member for member in bundle.members if member.role is ManagedToolchainRole.SEMGREP
    )
    if partial_bundle:
        original_bundle = load_packaged_managed_toolchain_bundle()
        bundle = seal_managed_toolchain_bundle(
            members=tuple(
                semgrep if member.role is semgrep.role else member
                for member in original_bundle.members
            ),
            target_platform=original_bundle.target_platform,
        )
    scanner = {"enabled": True, "required": True}
    if conflicting_pin:
        scanner.update(version="9.9.9", sha256="c" * 64)
    config = config_factory(
        scanners={"semgrep": scanner}, reproduction={"isolation_backend": "bubblewrap"}
    )
    original_config = config.model_dump(mode="json")
    original_source = scanner_workspace_sha256(repository)
    forbidden_calls: list[str] = []

    def forbidden(*_args, **_kwargs):
        forbidden_calls.append("external")
        raise AssertionError("synthetic setup must not execute tools or access a network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    arguments = dict(
        repository=repository,
        config=config,
        output_dir=output,
        bundle=bundle,
        dependency_source=ManagedDependencySource(
            archive_root=archives, advisory_path=advisories, advisory_sha256=digest
        ),
    )
    if conflicting_pin:
        with pytest.raises(ManagedToolchainError, match="trust pins conflict"):
            provision_managed_local_run(**arguments, verify_only=False)
        assert list(output.iterdir()) == []
        assert not (repository / ".mmaudit").exists()
    else:
        run = provision_managed_local_run(**arguments, verify_only=False)
        returned = run.config
        assert returned.scanners.semgrep.version == semgrep.version
        assert returned.scanners.semgrep.sha256 == semgrep.sha256
        prepared = prepare_dependencies(
            repository,
            [SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.HARDHAT)],
            returned.dependency_preparation,
            tmp_path / "prepared",
        )
        assert prepared.results[0].status is DependencyPreparationStatus.PREPARED
        assert (prepared.prepared_roots["."] / "safe-dep/DependencyBase.sol").is_file()
        assert (
            parse_managed_provisioning_receipt(next(output.iterdir()).read_bytes()) == run.receipt
        )
        assert returned.stable_hash() == run.receipt.plan.effective_config_sha256
        assert run.receipt.runtime_authority is run.receipt.managed_run_ready is False
        assert run.receipt.state.installed_members_verified is False
        assert provision_managed_local_run(**arguments, verify_only=True) == run
        # Exercise the existing consumer predicate with synthetic observations only; no tool ran.
        for mismatch in ("version", "digest"):
            assert (
                scanner_trust_pin_error(
                    version="9.9.9" if mismatch == "version" else semgrep.version,
                    executable_sha256="c" * 64 if mismatch == "digest" else semgrep.sha256,
                    expected_version=returned.scanners.semgrep.version,
                    expected_sha256=returned.scanners.semgrep.sha256,
                )
                is not None
            )
    assert forbidden_calls == []
    assert config.model_dump(mode="json") == original_config
    assert scanner_workspace_sha256(repository) == original_source


@pytest.mark.parametrize("negative_advisory", [False, True])
def test_automatic_setup_config_feeds_real_preparation_without_manual_pins(
    tmp_path, monkeypatch, config_factory, negative_advisory
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    if negative_advisory:
        advisories.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "advisories": [
                        {
                            "advisory_id": "SYNTHETIC-HANDOFF-001",
                            "package_name": "safe-dep",
                            "versions": ["1.0.0"],
                            "severity": "high",
                            "summary": "Synthetic prohibited dependency version.",
                        }
                    ],
                }
            )
        )
        digest = hashlib.sha256(advisories.read_bytes()).hexdigest()
    output = tmp_path / "receipts"
    output.mkdir(mode=0o700)
    output.chmod(0o700)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("automatic local setup must remain offline and nonexecuting")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    ledger.chmod(0o700)
    config = config_factory(execution={"cost_ledger_path": str(ledger / "synthetic-costs.json")})
    run = provision_managed_local_run(
        repository=repository,
        config=config,
        output_dir=output,
        verify_only=False,
        bundle=load_packaged_managed_toolchain_bundle(),
        dependency_source=ManagedDependencySource(
            archive_root=archives,
            advisory_path=advisories,
            advisory_sha256=digest,
        ),
    )
    prepared = prepare_dependencies(
        repository,
        [SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.HARDHAT)],
        run.config.dependency_preparation,
        tmp_path / "prepared",
    )
    if negative_advisory:
        assert prepared.results[0].status is DependencyPreparationStatus.REJECTED
        assert not prepared.prepared_roots
        assert "dependency-snapshot" not in run.receipt.state.verified_requirement_ids
    else:
        assert prepared.results[0].status is DependencyPreparationStatus.PREPARED
        assert all(prepared.results[0].checks.values())
        assert (prepared.prepared_roots["."] / "safe-dep/DependencyBase.sol").is_file()
    assert run.config.stable_hash() == run.receipt.plan.effective_config_sha256
    assert "cost-ledger" in run.receipt.state.verified_requirement_ids
    assert (ledger / "synthetic-costs.json").is_file()
    assert config.dependency_preparation.enabled is False
    assert run.receipt.runtime_authority is run.receipt.managed_run_ready is False


def test_real_automatic_cli_selects_config_without_profile_rewrite_or_ambient_inputs(
    tmp_path, monkeypatch
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    fixture = Path(__file__).parents[1] / "fixtures/dependency_snapshot/setup.toml"
    profile = repository / "audit.toml"
    profile.write_bytes(fixture.read_bytes())
    before = profile.read_bytes()
    output = tmp_path / "receipts"
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    monkeypatch.setenv("MMAUDIT_COST_LEDGER_PATH", str(tmp_path / "must-not-exist.json"))
    monkeypatch.setenv("MMAUDIT_ALLOW_CODE_EGRESS", "true")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("combined setup CLI must not execute or contact a network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    args = [
        "managed",
        "provision",
        "--repo",
        str(repository),
        "--output-dir",
        str(output),
        "--config",
        str(profile),
        "--archive-root",
        str(archives),
        "--advisory-path",
        str(advisories),
        "--advisory-sha256",
        digest,
        "--no-color",
    ]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == ExitCode.INCOMPLETE, first.output
    receipt = parse_managed_provisioning_receipt(next(output.iterdir()).read_bytes())
    assert receipt.state.verified_requirement_ids == ("dependency-snapshot",)
    repeat = CliRunner().invoke(app, [*args, "--verify-only"])
    assert repeat.exit_code == first.exit_code, repeat.output
    assert len(list(output.iterdir())) == 1
    assert profile.read_bytes() == before
    assert not (tmp_path / "must-not-exist.json").exists()
    assert receipt.managed_run_ready is False


def test_real_snapshot_and_ledger_provisioning_preserve_an_incomplete_receipt(
    tmp_path, monkeypatch, config_factory
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("local receipt integration must not execute or access a network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=digest,
    )
    output = tmp_path / "receipts"
    ledger_parent = tmp_path / "ledger"
    for directory in (output, ledger_parent):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    config = config_factory(
        dependency_preparation=built.config.model_dump(),
        execution={
            "cost_ledger_path": str(ledger_parent / "synthetic-costs.json"),
            "budget_usd": 20.0,
        },
    )
    arguments = dict(
        repository=repository,
        config=config,
        output_dir=output,
        bundle=load_packaged_managed_toolchain_bundle(),
    )
    first = provision_managed_local_receipt(**arguments, verify_only=False)
    assert first.state.verified_requirement_ids == ("cost-ledger", "dependency-snapshot")
    assert (
        first.state.observations.dependency_snapshot.status
        is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING
    )
    assert first.state.status == "REFUSED_INCOMPLETE"
    assert first.runtime_authority is first.managed_run_ready is False
    repeat = provision_managed_local_receipt(**arguments, verify_only=True)
    assert provision_managed_local_receipt(**arguments, verify_only=True) == repeat
    persisted = [parse_managed_provisioning_receipt(path.read_bytes()) for path in output.iterdir()]
    assert len(persisted) == 2 and first in persisted and repeat in persisted


def test_real_builder_advisory_match_cannot_become_a_verified_provisioning_input(
    tmp_path, config_factory
):
    repository, archives, advisories, _ = setup_snapshot_inputs(tmp_path)
    advisories.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "advisories": [
                    {
                        "advisory_id": "SYNTHETIC-NEGATIVE-001",
                        "package_name": "safe-dep",
                        "versions": ["1.0.0"],
                        "severity": "high",
                        "summary": "Synthetic prohibited dependency version.",
                    }
                ],
            }
        )
    )
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=hashlib.sha256(advisories.read_bytes()).hexdigest(),
    )
    output = tmp_path / "receipts"
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    receipt = provision_managed_local_receipt(
        config=config_factory(dependency_preparation=built.config.model_dump()),
        bundle=load_packaged_managed_toolchain_bundle(),
        repository=repository,
        output_dir=output,
        verify_only=True,
    )
    assert (
        receipt.state.observations.dependency_snapshot.refusal_code
        is ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
    )
    assert "dependency-snapshot" not in receipt.state.verified_requirement_ids
    assert receipt.managed_run_ready is False


def test_real_builder_output_is_consumed_without_network_or_package_execution(
    tmp_path, monkeypatch
):
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("inert dependency provisioning must not execute or use a network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=digest,
    )
    prepared = prepare_dependencies(
        repository,
        [SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.HARDHAT)],
        built.config,
        tmp_path / "private",
    )
    assert prepared.results[0].status is DependencyPreparationStatus.PREPARED
    assert prepared.results[0].checks and all(prepared.results[0].checks.values())
    package = prepared.prepared_roots["."] / "safe-dep"
    assert (package / "DependencyBase.sol").read_bytes().startswith(b"// Synthetic")
    assert built.config.offline_snapshot_path is not None
    config_path = (repository / built.config.offline_snapshot_path).with_name("dependencies.toml")
    projected = DependencyPreparationConfig.model_validate(
        tomllib.loads(config_path.read_text())["dependency_preparation"]
    )
    assert projected == built.config
    assert built.runtime_authority is False


def test_supplied_advisory_is_retained_and_existing_consumer_rejects_match(tmp_path: Path) -> None:
    repository, archives, advisories, _digest = setup_snapshot_inputs(tmp_path)
    advisories.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "advisories": [
                    {
                        "advisory_id": "SYNTHETIC-INVARIANT-001",
                        "package_name": "safe-dep",
                        "versions": ["1.0.0"],
                        "severity": "high",
                        "summary": "Synthetic negative advisory; no real vulnerability claim.",
                    }
                ],
            }
        )
    )
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisories,
        advisory_sha256=hashlib.sha256(advisories.read_bytes()).hexdigest(),
    )
    prepared = prepare_dependencies(
        repository,
        [SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.HARDHAT)],
        built.config,
        tmp_path / "private",
    )
    assert prepared.results[0].status is DependencyPreparationStatus.REJECTED
    assert prepared.results[0].scan_findings[0].advisory_id == "SYNTHETIC-INVARIANT-001"
    assert not prepared.prepared_roots


def test_managed_cli_builds_and_verifies_without_ambient_config(
    tmp_path: Path, monkeypatch
) -> None:
    repository, archives, advisories, digest = setup_snapshot_inputs(tmp_path)
    monkeypatch.setenv("MMAUDIT_ALLOW_CODE_EGRESS", "true")
    monkeypatch.setenv("MMAUDIT_COST_LEDGER_PATH", str(tmp_path / "must-not-exist.json"))
    arguments = [
        "managed",
        "build-dependency-snapshot",
        "--repo",
        str(repository),
        "--archive-root",
        str(archives),
        "--advisory-path",
        str(advisories),
        "--advisory-sha256",
        digest,
        "--no-color",
    ]
    runner = CliRunner()
    built = runner.invoke(app, arguments)
    assert built.exit_code == 0, built.output
    assert "CREATED" in built.output and "NONAUTHORIZING" in built.output
    verified = runner.invoke(app, [*arguments, "--verify-only"])
    assert verified.exit_code == 0, verified.output
    assert "VERIFIED_EXISTING" in verified.output
    assert not (tmp_path / "must-not-exist.json").exists()
    refused = runner.invoke(app, [*arguments[:-3], "--advisory-sha256", "0" * 64, "--no-color"])
    assert refused.exit_code != 0
    assert "no authority granted" in refused.output
