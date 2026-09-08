"""Real offline formal-runner plumbing with fixed trusted Python, not formal proof."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, FormalToolStatus, InvariantSuite
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.repository import discovery as repository_discovery
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.scanners import base
from mmaudit.solidity.formal import FormalRunner
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from tests.host_tool_material_support import setup_host_material_inputs

_CONTROL = (
    "from pathlib import Path; "
    "assert Path('ControlB.sol').is_file(); "
    "assert Path('PreparedFormalProperties.sol').is_file(); "
    "print('{}')"
)
_CONTROL_ROLES = {
    ManagedToolchainRole.SOLC,
    ManagedToolchainRole.FORGE,
    ManagedToolchainRole.HALMOS,
    ManagedToolchainRole.HALMOS_Z3,
}


def _replace(path):
    replacement = path.with_name(path.name + ".replacement")
    shutil.copyfile(path, replacement)
    replacement.chmod(0o500)
    replacement.replace(path)


class _FixedFormalControl:
    name = "unverified-managed-formal-control"

    def __init__(self, paths, mutation):
        self.paths, self.mutation = paths, mutation
        self.commands = []

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        self.commands.append(command.copy())
        assert workspace.is_relative_to(private_dir)
        assert Path(command[0]) in self.paths.values()
        if command == [command[0], "--version"]:
            assert rpc_port == 0
            selected = self.paths[
                ManagedToolchainRole.HALMOS_Z3
                if self.mutation == "solver-version-wrap"
                else ManagedToolchainRole.SOLC
            ]
            if self.mutation in {"version-wrap", "solver-version-wrap"} and command[0] == str(
                selected
            ):
                _replace(selected)
            return command
        assert rpc_port == 1
        role = next(role for role, path in self.paths.items() if str(path) == command[0])
        if role is ManagedToolchainRole.SOLC:
            assert command[1:] == [
                "--model-checker-engine",
                "all",
                "--model-checker-targets",
                "assert",
                "--model-checker-timeout",
                "300000",
                "--base-path",
                ".",
                "ControlB.sol",
                "PreparedFormalProperties.sol",
            ]
        elif role is ManagedToolchainRole.FORGE:
            assert command[1:] == [
                "test",
                "--offline",
                "--match-test",
                "invariant_",
                "-vv",
                "--no-auto-detect",
                "--use",
                str(self.paths[ManagedToolchainRole.SOLC]),
            ]
        else:
            assert role is ManagedToolchainRole.HALMOS
            assert command[command.index("--solver-command") + 1] == str(
                self.paths[ManagedToolchainRole.HALMOS_Z3]
            )
            assert command[command.index("--config") + 1] == "mmaudit-halmos/halmos.toml"
        if self.mutation == "execution-wrap":
            _replace(self.paths[ManagedToolchainRole.HALMOS_Z3])
        return [command[0], "-I", "-c", _CONTROL]


@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "primary-bytes",
        "solver-bytes",
        "version-wrap",
        "solver-version-wrap",
        "execution-wrap",
        "outcome",
    ],
)
def test_real_local_formal_consumer_preserves_prepared_paths_and_rejects_drift(
    tmp_path, config_factory, monkeypatch, repeated, mutation
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        formal={
            "enabled": True,
            "run_mythril": False,
            "run_echidna": False,
            "run_medusa": False,
            "run_kontrol": False,
        },
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    shutil.copyfile(
        Path(__file__).parents[1]
        / "fixtures/solidity/development_review/PreparedFormalProperties.sol",
        repository / "PreparedFormalProperties.sol",
    )
    original_source = base.scanner_workspace_sha256(repository)
    trusted = Path(sys.executable).resolve(strict=True)
    assert not trusted.is_relative_to(Path(__file__).resolve().parents[2])
    with trusted.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    blob = store / f"{digest}.blob"
    shutil.copyfile(trusted, blob)
    blob.chmod(0o600)
    version = ".".join(str(value) for value in sys.version_info[:3])
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"sha256": digest, "version": version})
            if member.role in _CONTROL_ROLES
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    real_popen = base.subprocess.Popen
    launches = []

    def forbidden(*args, **kwargs):
        pytest.fail(
            "invariant: offline formal preparation cannot execute, find PATH tools or network"
        )

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
    paths = {role: material.executable_for(role) for role in _CONTROL_ROLES}

    def guarded_popen(command, *args, **kwargs):
        assert Path(command[0]) in paths.values()
        assert command[1:] in (["--version"], ["-I", "-c", _CONTROL])
        assert kwargs["shell"] is False
        assert not {"OPENROUTER_API_KEY", "MMAUDIT_SECRETS_ENV_FILE"}.intersection(kwargs["env"])
        with Path(command[0]).open("rb") as handle:
            assert hashlib.file_digest(handle, "sha256").hexdigest() == digest
        launches.append(command.copy())
        process = real_popen(command, *args, **kwargs)
        if mutation == "outcome" and command[1] == "-I":
            _replace(paths[ManagedToolchainRole.HALMOS_Z3])
        return process

    # This disposable source tree has no VCS identity; discovery must not probe ambient Git.
    monkeypatch.setattr(repository_discovery, "_git_commit", lambda root: None)
    discovery = repository_discovery.discover_repository(
        repository, prepared.config.repository, IgnoreMatcher()
    )
    projects = discover_solidity_projects(discovery, prepared.config.smart_contracts)
    index = build_solidity_index(discovery, projects, []).index
    assert any(item.name == "invariant_SyntheticConstantIsPreserved" for item in index.entities)
    monkeypatch.setattr(base.subprocess, "Popen", guarded_popen)
    if mutation in {"primary-bytes", "solver-bytes"}:
        path = paths[
            ManagedToolchainRole.SOLC
            if mutation == "primary-bytes"
            else ManagedToolchainRole.HALMOS_Z3
        ]
        path.chmod(0o600)
        path.write_bytes(b"Changed inert fixture; never execute.\n")
        path.chmod(0o500)

    def run():
        runner = FormalRunner(
            prepared.config.formal,
            host_tools=material,
            backend=_FixedFormalControl(paths, mutation),
        )
        return runner.run(
            repository_root=repository,
            projects=projects,
            index=index,
            invariants=InvariantSuite(),
            private_dir=tmp_path / "formal-private",
        )

    if mutation != "none":
        with pytest.raises(ValueError, match=r"managed|material|identity"):
            run()
        assert (
            len(launches)
            == {
                "primary-bytes": 0,
                "solver-bytes": 0,
                "version-wrap": 0,
                "solver-version-wrap": 6,
                "execution-wrap": 1,
                "outcome": 2,
            }[mutation]
        )
    else:
        results = run()
        assert [item.tool for item in results] == ["solc-smtchecker", "foundry-invariant", "halmos"]
        assert all(item.status is FormalToolStatus.SUCCESS for item in results)
        assert all(item.execution_evidence is ExecutionEvidenceKind.UNVERIFIED for item in results)
        assert all(item.version == f"Python {version}" for item in results)
        assert all(not item.evidence and not item.machine_output_validated for item in results)
        assert [[item.name for item in result.dependencies] for result in results] == [
            [],
            ["solc"],
            ["z3"],
        ]
        assert [Path(command[0]).name for command in launches] == [
            "solc",
            "solc",
            "forge",
            "solc",
            "forge",
            "halmos",
            "z3",
            "halmos",
        ]
    assert base.scanner_workspace_sha256(repository) == original_source
    assert prepared.receipt.runtime_authority is prepared.receipt.managed_run_ready is False
    assert material.manifest.installed_members_verified is False
