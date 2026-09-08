"""Configured managed-runner plumbing with a fixed trusted-Python control, not Semgrep evidence."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import base
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.semgrep import SemgrepScanner
from tests.host_tool_material_support import setup_host_material_inputs

_CONTROL_CODE = 'print(\'{"results":[],"errors":[]}\')'


class _FixedControlBackend:
    name = "synthetic-managed-runner-control"
    supports_local_fork_rpc = False

    def __init__(self, executable: Path) -> None:
        self.executable = str(executable)

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        assert rpc_port == 0
        assert command in (
            [self.executable, "--version"],
            [self.executable, "-c", _CONTROL_CODE],
        )
        return command


@pytest.mark.asyncio
@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize("mutation", ["none", "adapter_view", "bytes", "missing", "config"])
async def test_actual_configured_runner_consumes_only_its_verified_material_without_path(
    tmp_path, config_factory, monkeypatch, repeated, mutation
):
    config = config_factory(
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={"isolation_backend": "bubblewrap"},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    original_source = base.scanner_workspace_sha256(repository)
    trusted_python = Path(sys.executable).resolve(strict=True)
    assert not trusted_python.is_relative_to(repository)
    with trusted_python.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    version = ".".join(str(value) for value in sys.version_info[:3])
    blob = store / f"{digest}.blob"
    shutil.copyfile(trusted_python, blob)
    blob.chmod(0o600)
    # This role binding is explicitly synthetic plumbing. Only the trusted Python
    # control runs; neither a real Semgrep version nor scanner portfolio is attested.
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"sha256": digest, "version": version})
            if member.role is ManagedToolchainRole.SEMGREP
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    arguments = dict(config=config, bundle=bundle, repository=repository, output_dir=output)
    real_popen = base.subprocess.Popen
    original_build = SemgrepScanner.build_command
    calls = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: managed setup/selection must not execute, discover PATH or connect")

    with monkeypatch.context() as patch:
        patch.setattr(base.subprocess, "Popen", forbidden)
        patch.setattr(shutil, "which", forbidden)
        patch.setattr(socket, "socket", forbidden)
        patch.setenv("PATH", str(tmp_path / "must-not-search"))
        run = provision_managed_local_run(
            **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
        )
        if repeated:
            run = provision_managed_local_run(
                **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
            )
        assert run.host_tools is not None
        executable = run.host_tools.executable_for(ManagedToolchainRole.SEMGREP)
        backend = _FixedControlBackend(executable)
        runner = ScannerRunner(run.config, host_tools=run.host_tools, backend=backend)

        def control_build(adapter, root, private_dir):
            # Preserve the real bundled-resource staging and subsequent verification.
            command = original_build(adapter, root, private_dir)
            assert command[0] == str(executable)
            return [adapter.executable, "-c", _CONTROL_CODE]

        def guarded_popen(command, *args, **kwargs):
            assert command in (
                [str(executable), "--version"],
                [str(executable), "-c", _CONTROL_CODE],
            )
            assert kwargs["shell"] is False
            # Even a regression must never execute modified or synthetic inert bytes.
            with executable.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
            calls.append(command.copy())
            return real_popen(command, *args, **kwargs)

        patch.setattr(SemgrepScanner, "build_command", control_build)
        patch.setattr(base.subprocess, "Popen", guarded_popen)
        if mutation == "adapter_view":
            runner.adapters["semgrep"].executable = "must-not-find-shadow"
        elif mutation == "bytes":
            executable.chmod(0o600)
            executable.write_bytes(b"Synthetic changed material; must not execute.\n")
            executable.chmod(0o500)
        elif mutation == "missing":
            executable.unlink()
        elif mutation == "config":
            runner.config.scanners.semgrep.sha256 = "0" * 64
        kwargs = dict(
            root=repository,
            private_dir=tmp_path / "scanner-private",
            audited_relative_paths=("ControlB.sol",),
            expected_repository_sha256=original_source,
        )
        if mutation in {"bytes", "missing", "config"}:
            with pytest.raises(ValueError, match=r"managed|material"):
                await runner.run_all(**kwargs)
            assert calls == []
        else:
            outcomes = await runner.run_all(**kwargs)
            control = next(item for item in outcomes if item.scanner == "semgrep")
            assert control.status is ScannerStatus.SUCCESS
            assert control.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
            assert control.executable_sha256 == digest
            assert control.version == f"Python {version}"
            assert control.findings == []
            assert runner.required_failures(outcomes) == []
            assert calls == [
                [str(executable), "--version"],
                [str(executable), "-c", _CONTROL_CODE],
            ]
            assert all(
                item.status is ScannerStatus.SKIPPED
                for item in outcomes
                if item.scanner != "semgrep"
            )
        assert base.scanner_workspace_sha256(repository) == original_source
        assert run.receipt.managed_run_ready is run.receipt.runtime_authority is False
        assert run.receipt.state.installed_members_verified is False
