"""Offline prepared-tool process controls, never actual fork or Solidity evidence."""

from __future__ import annotations

import hashlib
import shutil
import socket
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ReproductionState
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import base
from mmaudit.solidity import reproduction
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_reproduction_fork_support import (
    install_no_network_reproduction_lease_control,
    reproduction_archive_source,
)
from tests.managed_reproduction_support import (
    SYNTHETIC_RPC,
    SYNTHETIC_RPC_ENV,
    SYNTHETIC_TARGET,
    managed_reproduction_inputs,
)

_CONTROL = (
    "from pathlib import Path; "
    "assert 'abstract contract ControlB' in Path('ControlB.sol').read_text(); "
    "text = Path('test/mmaudit_generated/AdministratorRequired.t.sol').read_text(); "
    "assert 'assertFalse(success_UnauthorizedChange' in text; "
    "assert 'assertEq(block.chainid, 31337' in text; "
    "assert not Path('test/mmaudit_generated/toolchain/solc').exists(); "
    "print('Fixed local handoff control: no Solidity execution or RPC connection.')"
)


def _replace(path):
    replacement = path.with_name(path.name + ".replacement")
    shutil.copyfile(path, replacement)
    replacement.chmod(0o500)
    replacement.replace(path)


class _FixedReproductionControl:
    name = "unverified-offline-reproduction-control"
    supports_local_fork_rpc = True

    def __init__(self, forge, solc, mutation):
        self.forge, self.solc, self.mutation = forge, solc, mutation
        self.executions = 0

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        assert workspace.is_relative_to(private_dir)
        if command in ([str(self.forge), "--version"], [str(self.solc), "--version"]):
            assert rpc_port == 0
            if (self.mutation, command[0]) in (
                ("forge-version-wrap", str(self.forge)),
                ("solc-version-wrap", str(self.solc)),
            ):
                _replace(Path(command[0]))
            return command
        assert rpc_port == 18547
        assert command == [
            str(self.forge),
            "test",
            "--root",
            str(workspace),
            "--match-path",
            "test/mmaudit_generated/AdministratorRequired.t.sol",
            "--match-test",
            "test_MMAudit_AdministratorRequired",
            "--fork-url",
            SYNTHETIC_RPC,
            "--offline",
            "--color",
            "never",
            "-vvv",
            "--no-auto-detect",
            "--use",
            str(self.solc),
            "--fork-block-number",
            "7",
        ]
        self.executions += 1
        if self.mutation == "execution-wrap":
            _replace(self.solc)
        elif self.mutation == "replay-wrap" and self.executions == 2:
            _replace(self.forge)
        # Exact fixed Python only: never forward the fork URL or execute the generated Solidity.
        return [str(self.forge), "-I", "-c", _CONTROL]


@pytest.mark.parametrize("repeated", [False, True])
@pytest.mark.parametrize(
    "mutation",
    [
        "none",
        "forge",
        "solc",
        "forge-version-wrap",
        "solc-version-wrap",
        "execution-wrap",
        "replay-wrap",
        "outcome",
    ],
)
def test_prepared_reproduction_tools_reach_real_local_controls_without_rpc(
    tmp_path, config_factory, candidate_factory, monkeypatch, repeated, mutation
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={
            "compile": False,
            "allow_fork_probing": True,
            "fork_rpc_url_env": SYNTHETIC_RPC_ENV,
        },
        reproduction={
            "enabled": True,
            "isolation_backend": "bubblewrap",
            "targets": {"ControlB": SYNTHETIC_TARGET},
            "pinned_block_number": 7,
            "expected_chain_id": 31337,
        },
        invariants={"enabled": False},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    project, specification = managed_reproduction_inputs()
    candidate = candidate_factory(
        candidate_id=specification.candidate_id,
        path="ControlB.sol",
        title="Synthetic administrator invariant",
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
            if member.role in {ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC}
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    real_popen = base.subprocess.Popen
    launches = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: preparation cannot execute/discover tools or connect any socket")

    monkeypatch.setattr(base.subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(reproduction, "_external_executable", forbidden)
    monkeypatch.setenv("PATH", str(tmp_path / "no-ambient-tools"))
    monkeypatch.setenv(SYNTHETIC_RPC_ENV, SYNTHETIC_RPC)
    source, _ = reproduction_archive_source(tmp_path)
    # These tests exercise actual trusted Python processes, not RPC or Solidity execution.
    # Real owned-transport consumption is covered in the separate reproduction archive module.
    leases = install_no_network_reproduction_lease_control(monkeypatch)
    arguments = dict(
        config=config,
        bundle=bundle,
        repository=repository,
        output_dir=output,
        offline_fork_source=source,
    )
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

    def guarded_popen(command, *args, **kwargs):
        assert command in (
            [str(forge), "--version"],
            [str(solc), "--version"],
            [str(forge), "-I", "-c", _CONTROL],
        )
        assert SYNTHETIC_RPC not in command and kwargs["shell"] is False
        assert not {
            "OPENROUTER_API_KEY",
            "MMAUDIT_SECRETS_ENV_FILE",
            SYNTHETIC_RPC_ENV,
        }.intersection(kwargs["env"])
        with Path(command[0]).open("rb") as handle:
            assert hashlib.file_digest(handle, "sha256").hexdigest() == digest
        if command[1] == "-I":
            assert kwargs["env"]["FOUNDRY_FFI"] == "false"
        launches.append(command.copy())
        process = real_popen(command, *args, **kwargs)
        if mutation == "outcome" and command[1] == "-I":
            _replace(solc)
        return process

    monkeypatch.setattr(base.subprocess, "Popen", guarded_popen)
    if mutation in {"forge", "solc"}:
        selected = forge if mutation == "forge" else solc
        selected.chmod(0o600)
        selected.write_bytes(b"Changed inert reproduction control; never execute.\n")
        selected.chmod(0o500)

    def run():
        return reproduction.ForkReproductionRunner(
            prepared.config.reproduction,
            prepared.config.smart_contracts,
            host_tools=material,
            offline_forks=prepared.offline_forks,
            backend=_FixedReproductionControl(forge, solc, mutation),
        ).run(
            repository_root=repository,
            project=project,
            specification=specification,
            candidate=candidate,
            private_dir=tmp_path / "reproduction-private",
        )

    if mutation != "none":
        with pytest.raises(ValueError, match=r"managed|material|identity"):
            run()
        assert (
            len(launches)
            == {
                "forge": 0,
                "solc": 0,
                "forge-version-wrap": 0,
                "solc-version-wrap": 1,
                "execution-wrap": 2,
                "replay-wrap": 3,
                "outcome": 3,
            }[mutation]
        )
    else:
        result = run()
        assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED, result.limitations
        assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        assert result.executable_sha256 == digest
        assert result.attempts == result.successful_attempts == 2
        assert all(item.fresh_workspace for item in result.attempt_evidence)
        assert result.specification_sha256 == reproduction._specification_hash(specification)
        assert [Path(command[0]).name for command in launches] == [
            "forge",
            "solc",
            "forge",
            "forge",
        ]
        assert "[PINNED_SOLC]" in result.command and str(solc) not in result.command
        assert not list((tmp_path / "reproduction-private").rglob("toolchain/solc"))
    assert base.scanner_workspace_sha256(repository) == original_source
    assert prepared.receipt.runtime_authority is prepared.receipt.managed_run_ready is False
    assert material.manifest.installed_members_verified is False
    assert all(lease.stopped_cleanly for lease in leases)
