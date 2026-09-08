"""Real offline setup/compiler plumbing using fixed Python controls, not Forge evidence."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import CompilationStatus, SolidityProjectMetadata, SolidityProjectType
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import base
from mmaudit.solidity.compile import compile_solidity_projects
from mmaudit.solidity.projects import _build_command
from tests.host_tool_material_support import setup_host_material_inputs

_CONTROL = (
    "from pathlib import Path; "
    "assert Path('ControlB.sol').is_file(); "
    "Path('out').mkdir(); "
    "Path('out/ControlB.json').write_text('{\"contractName\":\"SyntheticControlB\"}'); "
    "print('fixed local compiler plumbing control')"
)


class _FixedCompilerControl:
    name = "unverified-managed-compiler-control"

    def __init__(self, forge, solc, mutation):
        self.forge, self.solc, self.mutation = forge, solc, mutation
        self.commands = []

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        self.commands.append(command.copy())
        assert workspace.is_relative_to(private_dir)
        if command in ([str(self.forge), "--version"], [str(self.solc), "--version"]):
            assert rpc_port == 0
            if self.mutation == "version-wrap" and command[0] == str(self.forge):
                # Same bytes but a changed retained inode must refuse before the real probe.
                self._replace(self.forge)
            return command
        assert command == [
            str(self.forge),
            *_build_command(SolidityProjectType.FOUNDRY, False)[1:],
            "--no-auto-detect",
            "--use",
            str(self.solc),
        ]
        assert rpc_port == 1
        if self.mutation == "build-wrap":
            self._replace(self.solc)
        return [str(self.forge), "-I", "-c", _CONTROL]

    @staticmethod
    def _replace(path):
        replacement = path.with_name(path.name + ".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o500)
        replacement.replace(path)


@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize("mutation", ["none", "forge", "solc", "version-wrap", "build-wrap"])
def test_prepared_material_reaches_real_compiler_control_with_no_path_or_network(
    tmp_path, config_factory, monkeypatch, repeated, mutation
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    original_source = base.scanner_workspace_sha256(repository)
    trusted = Path(sys.executable).resolve(strict=True)
    assert not trusted.is_relative_to(Path(__file__).resolve().parents[2])
    with trusted.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    blob = store / f"{digest}.blob"
    shutil.copyfile(trusted, blob)
    blob.chmod(0o600)
    version = ".".join(str(value) for value in sys.version_info[:3])
    # Both roles deliberately bind trusted Python, not a real compiler/Forge distribution.
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"sha256": digest, "version": version})
            if member.role in {ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC}
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    real_popen = base.subprocess.Popen
    launches = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: offline setup cannot launch, resolve PATH or contact a network")

    monkeypatch.setattr(base.subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setenv("PATH", str(tmp_path / "no-ambient-tools"))
    arguments = dict(config=config, bundle=bundle, repository=repository, output_dir=output)
    prepared = provision_managed_local_run(
        **arguments, verify_only=False, host_tool_source=ManagedHostToolSource(blob_root=store)
    )
    if repeated:
        prepared = provision_managed_local_run(
            **arguments, verify_only=True, host_tool_source=ManagedHostToolSource()
        )
    material = prepared.host_tools
    assert material is not None
    forge = material.executable_for(ManagedToolchainRole.FORGE)
    solc = material.executable_for(ManagedToolchainRole.SOLC)
    backend = _FixedCompilerControl(forge, solc, mutation)

    def guarded_popen(command, *args, **kwargs):
        assert command in (
            [str(forge), "--version"],
            [str(solc), "--version"],
            [str(forge), "-I", "-c", _CONTROL],
        )
        assert kwargs["shell"] is False
        assert not {"OPENROUTER_API_KEY", "MMAUDIT_SECRETS_ENV_FILE"}.intersection(kwargs["env"])
        # A regression may never execute the intentionally changed or inert role bytes.
        with Path(command[0]).open("rb") as handle:
            assert hashlib.file_digest(handle, "sha256").hexdigest() == digest
        launches.append(command.copy())
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr(base.subprocess, "Popen", guarded_popen)
    if mutation in {"forge", "solc"}:
        selected = forge if mutation == "forge" else solc
        selected.chmod(0o600)
        selected.write_bytes(b"Changed inert fixture; never executable.\n")
        selected.chmod(0o500)
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        build_command=_build_command(SolidityProjectType.FOUNDRY, False),
    )
    arguments = dict(
        repository_root=repository,
        projects=[project],
        config=prepared.config.smart_contracts,
        private_dir=tmp_path / "compiler-private",
        backend=backend,
        host_tools=material,
    )
    if mutation != "none":
        with pytest.raises(ValueError, match=r"managed|material|identity"):
            compile_solidity_projects(**arguments)
        assert len(launches) == (2 if mutation == "build-wrap" else 0)
    else:
        result = compile_solidity_projects(**arguments)
        assert len(result.results) == 1
        compiled = result.results[0]
        assert compiled.status is CompilationStatus.SUCCESS
        assert compiled.executable_sha256 == digest
        assert compiled.tool_versions == {"forge": f"Python {version}", "solc": f"Python {version}"}
        assert compiled.contracts_compiled == ["SyntheticControlB"]
        assert compiled.ast_available is compiled.source_maps_available is False
        assert len(result.artifact_roots) == 1
        assert launches == [
            [str(forge), "--version"],
            [str(solc), "--version"],
            [str(forge), "-I", "-c", _CONTROL],
        ]
    assert base.scanner_workspace_sha256(repository) == original_source
    assert prepared.receipt.runtime_authority is prepared.receipt.managed_run_ready is False
    assert material.manifest.installed_members_verified is False
