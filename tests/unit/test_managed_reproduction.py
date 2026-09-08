"""Prepared reproduction handoff using inert blobs, with no socket or real engine."""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.models.schemas import ExecutionEvidenceKind, ReproductionState
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.scanners import base
from mmaudit.scanners.diagnostics import ExecutableVersionProbe, ExecutableVersionProbeStatus
from mmaudit.solidity import reproduction
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_reproduction_fork_support import (
    install_no_network_reproduction_lease_control,
    prepare_tool_control_archives,
)
from tests.managed_reproduction_support import (
    SYNTHETIC_RPC,
    SYNTHETIC_RPC_ENV,
    SYNTHETIC_TARGET,
    managed_reproduction_inputs,
)


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail(
            "invariant: inert reproduction handoff cannot execute or discover tools/use sockets"
        )

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(reproduction, "_external_executable", forbidden)
    monkeypatch.setenv(SYNTHETIC_RPC_ENV, SYNTHETIC_RPC)


class _Backend:
    name = "unverified-prepared-reproduction-control"
    supports_local_fork_rpc = True

    def __init__(self, mutate=None):
        self.commands = []
        self.mutate = mutate

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        assert rpc_port == 18547
        self.commands.append(command.copy())
        if self.mutate is not None:
            self.mutate()
        return command


@pytest.fixture
def prepared(tmp_path, config_factory, candidate_factory, request):
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
    if hasattr(request, "param"):
        branch, field, value = request.param
        setattr(getattr(config, branch), field, value)
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    project, specification = managed_reproduction_inputs()
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    candidate = candidate_factory(
        candidate_id=specification.candidate_id,
        path="ControlB.sol",
        title="Synthetic administrator invariant",
    )
    return repository, material, project, specification, candidate


def _runner(prepared, **kwargs):
    material = prepared[1]
    offline_forks = (
        kwargs.pop("offline_forks")
        if "offline_forks" in kwargs
        else prepare_tool_control_archives(
            material, prepared[0], prepared[0].parent / "reproduction-private"
        )
    )
    return reproduction.ForkReproductionRunner(
        kwargs.pop("reproduction", material.config.reproduction),
        kwargs.pop("smart_contracts", material.config.smart_contracts),
        host_tools=kwargs.pop("host_tools", material),
        offline_forks=offline_forks,
        backend=kwargs.pop("backend", _Backend()),
        **kwargs,
    )


def _run(runner, prepared, tmp_path, **kwargs):
    return runner.run(
        repository_root=kwargs.pop("repository_root", prepared[0]),
        project=kwargs.pop("project", prepared[2]),
        specification=kwargs.pop("specification", prepared[3]),
        candidate=kwargs.pop("candidate", prepared[4]),
        private_dir=kwargs.pop("private_dir", tmp_path / "reproduction-private"),
        **kwargs,
    )


def _change(material, role, mutation="bytes"):
    path = material.executable_for(role)
    if mutation == "replacement":
        replacement = path.with_name(path.name + ".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o500)
        replacement.replace(path)
    else:
        path.chmod(0o600)
        path.write_bytes(b"Changed inert reproduction control; never execute.\n")
        path.chmod(0o500)


def _fake_execution(
    monkeypatch, material, *, during_probe=None, after_run=None, wrong_version=None
):
    install_no_network_reproduction_lease_control(monkeypatch)
    probes, launches = [], []
    versions = {item.locator: item.version for item in material.manifest.files}

    def probe(executable, environment, backend, workspace, private_dir, **kwargs):
        assert private_dir.stat().st_mode & 0o777 == 0o700
        assert workspace.stat().st_mode & 0o777 == 0o700
        assert kwargs["expected_host_observation"].sha256
        assert kwargs["timeout_seconds"] <= 15
        probes.append(executable.name)
        if during_probe is not None:
            during_probe(executable)
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.SUCCESS,
            version="wrong-version"
            if executable.name == wrong_version
            else versions[executable.name],
            diagnostic=None,
            return_code=0,
        )

    class Process:
        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    def launch(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["env"]["FOUNDRY_FFI"] == "false"
        assert command[0] == str(material.executable_for(ManagedToolchainRole.FORGE))
        launches.append(command.copy())
        kwargs["stdout"].write(b"Fixed synthetic process control; not Solidity proof.\n")
        if after_run is not None:
            after_run(len(launches))
        return Process()

    monkeypatch.setattr(base, "isolated_executable_version_probe", probe)
    monkeypatch.setattr(subprocess, "Popen", launch)
    return probes, launches


def test_prepared_forge_and_solc_are_used_directly_through_clean_replay(
    prepared, tmp_path, monkeypatch
):
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(_runner(prepared), prepared, tmp_path)
    assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert result.attempts == result.successful_attempts == 2
    assert all(item.fresh_workspace for item in result.attempt_evidence)
    assert probes == ["forge", "solc"] and len(launches) == 2
    compiler = prepared[1].executable_for(ManagedToolchainRole.SOLC)
    for command in launches:
        assert command[command.index("--use") + 1] == str(compiler)
        assert "--no-auto-detect" in command and "--offline" in command
        assert command[command.index("--fork-block-number") + 1] == "7"
    assert str(compiler) not in result.command and "[PINNED_SOLC]" in result.command
    assert SYNTHETIC_RPC not in result.command
    assert not list((tmp_path / "reproduction-private").rglob("toolchain/solc"))


@pytest.mark.parametrize("bad", [object(), {}, "material"])
def test_wrong_material_type_refuses_before_backend_selection(prepared, bad):
    with pytest.raises(ValueError, match=r"exact|material"):
        _runner(prepared, host_tools=bad, backend=None)


@pytest.mark.parametrize(
    "branch,field,value",
    [
        ("reproduction", "repetitions", 3),
        ("smart_contracts", "fork_rpc_url_env", "MMAUDIT_CHANGED_RPC"),
    ],
)
def test_mismatched_config_refuses_before_writes(prepared, tmp_path, branch, field, value):
    config = getattr(prepared[1].config, branch)
    setattr(config, field, value)
    with pytest.raises(ValueError, match="config"):
        _runner(prepared, **{branch: config})
    assert not (tmp_path / "reproduction-private").exists()


def test_explicit_path_override_cannot_mix_with_prepared_material(prepared):
    with pytest.raises(ValueError, match="override"):
        _runner(prepared, forge_executable=Path("/never/execute"))


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("mutation", ["bytes", "replacement"])
def test_tool_drift_refuses_before_rpc_and_writes(prepared, tmp_path, monkeypatch, role, mutation):
    runner = _runner(prepared)
    _change(prepared[1], role, mutation)
    monkeypatch.setattr(
        reproduction, "_local_rpc", lambda *args: pytest.fail("must refuse before RPC")
    )
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(runner, prepared, tmp_path)
    assert not (tmp_path / "reproduction-private").exists()


@pytest.mark.parametrize("wrong_version", ["forge", "solc"])
def test_version_mismatch_blocks_before_replay_source_copy(
    prepared, tmp_path, monkeypatch, wrong_version
):
    probes, launches = _fake_execution(monkeypatch, prepared[1], wrong_version=wrong_version)
    result = _run(_runner(prepared), prepared, tmp_path)
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert not launches and probes[-1] == wrong_version
    assert not list((tmp_path / "reproduction-private").rglob("AdministratorRequired.t.sol"))


@pytest.mark.parametrize(
    "prepared",
    [
        ("reproduction", "enabled", False),
        ("smart_contracts", "enabled", False),
        ("smart_contracts", "allow_fork_probing", False),
    ],
    indirect=True,
)
def test_disabled_or_unacknowledged_mode_cannot_probe_or_read_rpc(prepared, tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail("disabled/unacknowledged reproduction cannot probe isolation or read RPC")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    monkeypatch.setattr(reproduction, "_local_rpc", forbidden)
    runner = _runner(prepared, backend=None)
    assert runner.backend is None
    assert _run(runner, prepared, tmp_path).state is ReproductionState.ENVIRONMENT_BLOCKED
    assert not (tmp_path / "reproduction-private").exists()


@pytest.mark.parametrize(
    "prepared",
    [("reproduction", "pinned_block_number", None), ("reproduction", "expected_chain_id", None)],
    indirect=True,
)
def test_missing_prepared_fork_pin_refuses_before_rpc(prepared, tmp_path, monkeypatch):
    monkeypatch.setattr(reproduction, "_local_rpc", lambda *args: pytest.fail("missing fork pin"))
    result = _run(_runner(prepared), prepared, tmp_path)
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert not (tmp_path / "reproduction-private").exists()


@pytest.mark.parametrize("location", ["repository", "private", "parent"])
def test_material_cannot_overlap_source_or_writable_state(prepared, tmp_path, location):
    material = prepared[1]
    arguments = (
        {"repository_root": material.directory}
        if location == "repository"
        else {
            "private_dir": material.directory
            if location == "private"
            else material.directory.parent
        }
    )
    with pytest.raises(ValueError, match="overlap"):
        _run(_runner(prepared), prepared, tmp_path, **arguments)


def test_incompatible_network_isolation_refuses_before_rpc_or_tools(
    prepared, tmp_path, monkeypatch
):
    backend = _Backend()
    backend.supports_local_fork_rpc = False
    monkeypatch.setattr(
        reproduction, "_local_rpc", lambda *args: pytest.fail("incompatible isolation")
    )
    result = _run(_runner(prepared, backend=backend), prepared, tmp_path)
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert not (tmp_path / "reproduction-private").exists()


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("boundary", ["probe", "wrapper", "outcome", "replay"])
def test_retained_identity_catches_drift_across_execution_boundaries(
    prepared, tmp_path, monkeypatch, role, boundary
):
    material = prepared[1]

    def during_probe(executable):
        if boundary == "probe":
            _change(material, role, "replacement")

    def after_run(attempt):
        if boundary == "outcome":
            _change(material, role, "replacement")

    probes, launches = _fake_execution(
        monkeypatch, material, during_probe=during_probe, after_run=after_run
    )
    backend = _Backend()

    def wrapped():
        if boundary == "wrapper" or (boundary == "replay" and len(backend.commands) == 2):
            _change(material, role, "replacement")

    backend.mutate = wrapped
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(_runner(prepared, backend=backend), prepared, tmp_path)
    assert len(launches) == (1 if boundary in {"outcome", "replay"} else 0)
    assert len(probes) == (1 if boundary == "probe" else 2)


def test_mutable_forge_view_cannot_redirect_prepared_execution(prepared, tmp_path, monkeypatch):
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    runner = _runner(prepared)
    runner.forge_executable = Path("/never/execute")
    _run(runner, prepared, tmp_path)
    assert probes == ["forge", "solc"] and len(launches) == 2


def test_typed_inputs_are_detached_before_version_probes(prepared, tmp_path, monkeypatch):
    expected_hash = reproduction._specification_hash(prepared[3])

    def mutate(executable):
        prepared[2].project_root = "missing"
        prepared[3].name = "ChangedAfterAdmission"
        prepared[4].candidate_id = "changed-candidate"

    _fake_execution(monkeypatch, prepared[1], during_probe=mutate)
    result = _run(_runner(prepared), prepared, tmp_path)
    assert result.specification_sha256 == expected_hash
    assert result.test_name == "AdministratorRequired"
    assert result.candidate_id == "candidate-managed-control"


@pytest.mark.parametrize("field", ["project", "candidate", "specification"])
def test_non_exact_typed_input_refuses_before_writes(prepared, tmp_path, field):
    with pytest.raises(ValueError, match="exact typed"):
        _run(_runner(prepared), prepared, tmp_path, **{field: object()})
    assert not (tmp_path / "reproduction-private").exists()


def test_unvalidated_specification_copy_cannot_skip_revalidation(prepared, tmp_path):
    specification = prepared[3].model_copy(update={"attack_calls": []})
    with pytest.raises(ValueError):
        _run(_runner(prepared), prepared, tmp_path, specification=specification)
    assert not (tmp_path / "reproduction-private").exists()


def test_specification_must_belong_to_the_selected_candidate(prepared, tmp_path):
    prepared[3].candidate_id = "different-candidate"
    with pytest.raises(ValueError, match="different candidate"):
        _run(_runner(prepared), prepared, tmp_path)
    assert not (tmp_path / "reproduction-private").exists()


@pytest.mark.parametrize("boundary", ["probe", "wrapper"])
@pytest.mark.parametrize("reassign", [False, True])
def test_config_mutation_or_reassignment_cannot_escape_execution_checks(
    prepared, tmp_path, monkeypatch, boundary, reassign
):
    backend = _Backend()
    runner = _runner(prepared, backend=backend)

    def change_config(*args):
        if reassign:
            runner.reproduction = runner.reproduction.model_copy(update={"repetitions": 3})
        else:
            runner.reproduction.repetitions = 3

    probes, launches = _fake_execution(
        monkeypatch, prepared[1], during_probe=change_config if boundary == "probe" else None
    )
    if boundary == "wrapper":
        backend.mutate = change_config
    with pytest.raises(ValueError, match="config"):
        _run(runner, prepared, tmp_path)
    assert not launches and len(probes) == (1 if boundary == "probe" else 2)


def test_private_stream_setup_cannot_replace_tool_before_launch(prepared, tmp_path, monkeypatch):
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    original = Path.open

    def opened(path, *args, **kwargs):
        handle = original(path, *args, **kwargs)
        if path.name == "attempt-1.stderr.txt":
            _change(prepared[1], ManagedToolchainRole.SOLC, "replacement")
        return handle

    monkeypatch.setattr(Path, "open", opened)
    with pytest.raises(ValueError, match="identity"):
        _run(_runner(prepared), prepared, tmp_path)
    assert probes == ["forge", "solc"] and not launches


def test_regression_artifact_publication_cannot_hide_tool_drift(prepared, tmp_path, monkeypatch):
    _, launches = _fake_execution(monkeypatch, prepared[1])
    original = shutil.copy2

    def copied(source, destination, **kwargs):
        result = original(source, destination, **kwargs)
        if Path(destination).parent.name == "regression-tests":
            _change(prepared[1], ManagedToolchainRole.FORGE, "replacement")
        return result

    monkeypatch.setattr(shutil, "copy2", copied)
    with pytest.raises(ValueError, match="identity"):
        _run(_runner(prepared), prepared, tmp_path)
    assert len(launches) == 2


@pytest.mark.parametrize(
    "rpc",
    [
        "",
        "https://127.0.0.1:18547",
        "http://192.0.2.1:18547",
        "http://127.0.0.1:18547?secret=synthetic",
        "http://127.0.0.1",
    ],
)
def test_missing_managed_archive_cannot_fall_back_to_ambient_rpc(
    prepared, tmp_path, monkeypatch, rpc
):
    monkeypatch.setenv(SYNTHETIC_RPC_ENV, rpc)
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(_runner(prepared, offline_forks=None), prepared, tmp_path)
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert result.limitations == ["managed reproduction fork archive is unavailable"]
    assert not probes and not launches
    assert not (tmp_path / "reproduction-private").exists()


def test_omitted_backend_uses_managed_factory_without_ambient_fallback(prepared, monkeypatch):
    backend = _Backend()
    calls = []

    def factory(material):
        assert material is prepared[1]
        calls.append(material)
        return backend

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    assert _runner(prepared, backend=None).backend is backend
    assert _runner(prepared, backend=backend).backend is backend
    assert len(calls) == 1

    def unavailable(material):
        raise ValueError("managed backend unavailable")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", unavailable)
    monkeypatch.setattr(
        reproduction,
        "default_isolation_backend",
        lambda *args, **kwargs: pytest.fail("no ambient fallback"),
    )
    with pytest.raises(ValueError, match="managed backend unavailable"):
        _runner(prepared, backend=None)
