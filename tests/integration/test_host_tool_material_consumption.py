"""Real local material/consumer handoff using only a trusted Python host tool."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

from mmaudit.isolation.dependencies import prepare_dependencies
from mmaudit.models.schemas import (
    DependencyPreparationStatus,
    ExecutionEvidenceKind,
    ScannerFinding,
    ScannerStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import (
    ManagedDependencySource,
    provision_managed_local_run,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import base
from tests.dependency_snapshot_support import setup_snapshot_inputs
from tests.host_tool_material_support import setup_host_material_inputs

_SAFE_CODE = "print('{}')"


@pytest.mark.parametrize("repeated", [False, True])
def test_host_material_and_real_dependency_setup_share_the_final_consumer_config(
    tmp_path, config_factory, monkeypatch, repeated
):
    repository, archives, advisory, advisory_digest = setup_snapshot_inputs(tmp_path)
    config = config_factory(
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={"isolation_backend": "bubblewrap"},
    )
    original_config = config.model_dump(mode="json")
    original_source = base.scanner_workspace_sha256(repository)
    host_case = tmp_path / "host-case"
    host_case.mkdir()
    _, store, output, bundle = setup_host_material_inputs(host_case, config)

    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: combined local preparation must not execute or use a network")

    monkeypatch.setattr(base.subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    arguments = dict(
        bundle=bundle,
        config=config,
        repository=repository,
        output_dir=output,
        dependency_source=ManagedDependencySource(
            archive_root=archives, advisory_path=advisory, advisory_sha256=advisory_digest
        ),
    )
    run = provision_managed_local_run(
        **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    receipt = run.receipt.model_dump_json()
    if repeated:
        run = provision_managed_local_run(
            **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
        )
        assert run.receipt.model_dump_json() == receipt
        assert run.host_tools is not None
        assert run.host_tools.action == "VERIFIED_EXISTING"
    assert run.host_tools is not None
    assert run.host_tools.config == run.config
    assert run.config.stable_hash() != config.stable_hash()
    assert run.host_tools.manifest.effective_config_sha256 == run.config.stable_hash()
    assert run.receipt.plan.effective_config_sha256 == run.config.stable_hash()
    assert "dependency-snapshot" in run.receipt.state.verified_requirement_ids
    prepared = prepare_dependencies(
        repository,
        [SolidityProjectMetadata(project_root=".", project_type=SolidityProjectType.HARDHAT)],
        run.config.dependency_preparation,
        tmp_path / "prepared",
    )
    assert prepared.results[0].status is DependencyPreparationStatus.PREPARED
    assert (prepared.prepared_roots["."] / "safe-dep/DependencyBase.sol").is_file()
    assert run.host_tools.executable_for(ManagedToolchainRole.SEMGREP).is_relative_to(output)
    assert config.model_dump(mode="json") == original_config
    assert base.scanner_workspace_sha256(repository) == original_source
    assert run.receipt.state.installed_members_verified is False
    assert run.host_tools.runtime_authority is run.receipt.runtime_authority is False
    assert run.host_tools.managed_run_ready is run.receipt.managed_run_ready is False


class _MaterialPythonScanner(base.ScannerAdapter):
    name = "synthetic-material-consumer"

    def __init__(self, executable: Path) -> None:
        self.executable = str(executable)

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        return [self.executable, "-c", _SAFE_CODE]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        assert stdout.strip() == "{}"
        return []


class _FixedLocalBackend:
    """Constrain this synthetic integration to two known harmless command arrays."""

    name = "synthetic-host-material-test"
    supports_local_fork_rpc = False

    def __init__(self, executable: Path) -> None:
        self.executable = str(executable)

    def wrap(
        self, command: list[str], *, workspace: Path, private_dir: Path, rpc_port: int
    ) -> list[str]:
        assert rpc_port == 0
        assert command in ([self.executable, "--version"], [self.executable, "-c", _SAFE_CODE])
        return command


@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize("source_bound", [False, True])
@pytest.mark.parametrize("mismatched_pin", [False, True])
def test_materialized_trusted_python_reaches_only_the_matching_pinned_consumer(
    tmp_path, config_factory, monkeypatch, repeated, source_bound, mismatched_pin
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    # This is an existing trusted host test runtime, not an executable from audited source.
    # The other role's synthetic inert blob is prepared but never invoked.
    trusted_python = Path(sys.executable).resolve(strict=True)
    assert not trusted_python.is_relative_to(repository)
    with trusted_python.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    version = ".".join(str(value) for value in sys.version_info[:3])
    blob = store / f"{digest}.blob"
    shutil.copyfile(trusted_python, blob)
    blob.chmod(0o600)
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"sha256": digest, "version": version})
            if member.role is ManagedToolchainRole.PYTHON_RUNTIME
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    arguments = dict(bundle=bundle, config=config, repository=repository, output_dir=output)
    calls: list[list[str]] = []
    real_popen = base.subprocess.Popen

    def no_process_during_setup(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: preparation must not execute even a trusted supplied tool")

    def no_network(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: local material-consumer integration must not access a network")

    monkeypatch.setattr(base.subprocess, "Popen", no_process_during_setup)
    monkeypatch.setattr(socket, "socket", no_network)
    prepared = provision_managed_local_run(
        **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    assert prepared.host_tools is not None
    if repeated:
        prepared = provision_managed_local_run(
            **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
        )
        assert prepared.host_tools is not None
        assert prepared.host_tools.action == "VERIFIED_EXISTING"
    executable = prepared.host_tools.executable_for(ManagedToolchainRole.PYTHON_RUNTIME)
    assert executable != trusted_python
    assert executable.is_relative_to(output)
    assert not executable.is_relative_to(repository)
    assert prepared.host_tools.config == prepared.config
    assert prepared.receipt.state.installed_members_verified is False
    assert prepared.receipt.state.managed_run_ready is False
    assert prepared.host_tools.manifest.architecture_verified is False
    assert prepared.host_tools.manifest.transitive_dependency_closure_verified is False

    def guarded_popen(command: list[str], *args: Any, **kwargs: Any) -> Any:
        assert command in ([str(executable), "--version"], [str(executable), "-c", _SAFE_CODE])
        assert kwargs["shell"] is False
        calls.append(command.copy())
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(base.subprocess, "Popen", guarded_popen)
    scanner = _MaterialPythonScanner(executable)
    options = dict(
        backend=_FixedLocalBackend(executable),
        expected_version=version,
        expected_sha256="0" * 64 if mismatched_pin else digest,
    )
    private = tmp_path / "consumer-private"
    if source_bound:
        result = scanner.run_source_bound(
            repository,
            private,
            3,
            expected_repository_sha256=base.scanner_workspace_sha256(repository),
            audited_relative_paths=("ControlB.sol",),
            **options,
        )
    else:
        result = scanner.run(repository, private, 3, **options)
    assert result.status is (ScannerStatus.FAILED if mismatched_pin else ScannerStatus.SUCCESS)
    assert calls == (
        []
        if mismatched_pin
        else [[str(executable), "--version"], [str(executable), "-c", _SAFE_CODE]]
    )
    # Running a fixed local control does not attest a scanner portfolio or toolchain closure.
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert prepared.receipt.state.managed_run_ready is False
