"""Prepared compiler selection uses inert tools and never executes target code."""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.models.schemas import CompilationStatus, SolidityProjectMetadata, SolidityProjectType
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.solidity import compile as compiler
from mmaudit.solidity.projects import _build_command
from tests.host_tool_material_support import setup_host_material_inputs


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: inert unit material must not execute or resolve ambient tools")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


class _Backend:
    name = "synthetic-managed-compiler"

    def __init__(self, mutate=None):
        self.commands = []
        self.mutate = mutate

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        self.commands.append(command.copy())
        if self.mutate is not None:
            self.mutate()
        return command


@pytest.fixture
def prepared(tmp_path, config_factory):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["."],
        build_command=_build_command(SolidityProjectType.FOUNDRY, False),
    )
    return repository, material, project


def _run(prepared, tmp_path, **kwargs):
    repository, material, project = prepared
    return compiler.compile_solidity_projects(
        repository,
        [project],
        kwargs.pop("config", material.config.smart_contracts),
        tmp_path / "compiler-private",
        host_tools=kwargs.pop("host_tools", material),
        backend=kwargs.pop("backend", _Backend()),
        **kwargs,
    )


def _fake_execution(monkeypatch, material, *, during_probe=None, after_build=None):
    probes = []
    launches = []
    versions = {item.locator: item.version for item in material.manifest.files}

    def probe(executable, backend, workspace, private_dir, environment, **kwargs):
        path = Path(executable)
        assert kwargs["expected_host_observation"].sha256
        probes.append(path.name)
        if during_probe is not None:
            during_probe(path)
        return {path.name: versions[path.name]}, None

    class Process:
        returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            return self.returncode

    def launch(command, **kwargs):
        assert kwargs["shell"] is False
        assert command[0] == str(material.executable_for(ManagedToolchainRole.FORGE))
        assert command[1] == "build"
        launches.append(command.copy())
        if after_build is not None:
            after_build()
        return Process()

    monkeypatch.setattr(compiler, "_isolated_tool_versions", probe)
    monkeypatch.setattr(subprocess, "Popen", launch)
    return probes, launches


def _change(material, role, mutation="bytes"):
    path = material.directory / role.value
    if mutation == "missing":
        path.unlink()
    elif mutation == "replacement":
        original = path.read_bytes()
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(original)
        replacement.chmod(0o500)
        replacement.replace(path)
    else:
        path.chmod(0o600)
        path.write_bytes(b"Changed inert fixture; must never execute.\n")
        path.chmod(0o500)


def test_actual_compiler_receives_both_exact_paths_and_probes_before_build(
    prepared, tmp_path, monkeypatch
):
    _, material, _ = prepared
    probes, launches = _fake_execution(monkeypatch, material)
    result = _run(prepared, tmp_path).results[0]
    assert result.status is CompilationStatus.SUCCESS
    assert probes == ["forge", "solc"]
    assert len(launches) == 1
    command = launches[0]
    assert "--offline" in command and "--no-auto-detect" in command
    assert command[command.index("--use") + 1] == str(
        material.executable_for(ManagedToolchainRole.SOLC)
    )
    assert set(result.tool_versions) == {"forge", "solc"}
    assert result.executable_sha256 == material.config.scanners.foundry_fork.sha256
    assert material.runtime_authority is material.managed_run_ready is False


@pytest.mark.parametrize("bad_material", [False, {}, "material", object()])
def test_wrong_material_type_refuses_before_writes(prepared, tmp_path, bad_material):
    with pytest.raises(ValueError, match=r"managed|material"):
        _run(prepared, tmp_path, host_tools=bad_material)
    assert not (tmp_path / "compiler-private").exists()


@pytest.mark.parametrize("field,value", [("allow_network", True), ("solc_sha256", "0" * 64)])
def test_mixed_config_refuses_before_writes(prepared, tmp_path, field, value):
    config = prepared[1].config.smart_contracts.model_copy(update={field: value})
    with pytest.raises(ValueError, match=r"managed|material"):
        _run(prepared, tmp_path, config=config)
    assert not (tmp_path / "compiler-private").exists()


@pytest.mark.parametrize(
    "command",
    [
        ["sh", "-c", "never execute"],
        ["forge", "test"],
        ["forge", "build", "--ffi"],
        ["/private/forbidden/forge", "build"],
        ["forge", "build", "--use", "repository-solc"],
    ],
)
def test_repository_command_tail_cannot_override_managed_build(prepared, tmp_path, command):
    prepared[2].build_command = command
    with pytest.raises(ValueError, match=r"managed|command"):
        _run(prepared, tmp_path)
    assert not (tmp_path / "compiler-private").exists()


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("mutation", ["bytes", "missing"])
def test_changed_material_refuses_before_any_invocation(prepared, tmp_path, role, mutation):
    _change(prepared[1], role, mutation)
    with pytest.raises(ValueError, match=r"managed|material"):
        _run(prepared, tmp_path)


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("boundary", ["copy", "probe", "wrap", "return"])
def test_same_bytes_replacement_breaks_retained_compiler_identity(
    prepared, tmp_path, monkeypatch, role, boundary
):
    _, material, _ = prepared

    def mutate():
        _change(material, role, "replacement")

    probes, launches = _fake_execution(
        monkeypatch,
        material,
        during_probe=(lambda _: mutate()) if boundary == "probe" else None,
        after_build=mutate if boundary == "return" else None,
    )
    backend = _Backend(mutate if boundary == "wrap" else None)
    if boundary == "copy":
        original_copy = compiler._copy_project

        def changed_copy(*args, **kwargs):
            original_copy(*args, **kwargs)
            mutate()

        monkeypatch.setattr(compiler, "_copy_project", changed_copy)
    with pytest.raises(ValueError, match=r"managed|identity"):
        _run(prepared, tmp_path, backend=backend)
    assert len(launches) == (1 if boundary == "return" else 0)
    assert len(probes) <= 2


def test_automatic_backend_uses_only_selected_material(prepared, tmp_path, monkeypatch):
    _, material, _ = prepared
    backend = _Backend()
    selected = []

    def factory(value):
        selected.append(value)
        return backend

    monkeypatch.setattr(compiler, "managed_isolation_backend", factory)
    _fake_execution(monkeypatch, material)
    assert _run(prepared, tmp_path, backend=None).results[0].status is CompilationStatus.SUCCESS
    assert selected == [material]


def test_managed_factory_failure_never_discovers_default_backend(prepared, tmp_path, monkeypatch):
    def refused(_):
        raise ValueError("managed isolation unavailable")

    monkeypatch.setattr(compiler, "managed_isolation_backend", refused)
    monkeypatch.setattr(compiler, "default_isolation_backend", lambda _: pytest.fail("fallback"))
    with pytest.raises(ValueError, match="managed isolation"):
        _run(prepared, tmp_path, backend=None)


def test_plain_project_stays_skipped_without_invocation(prepared, tmp_path):
    prepared[2].project_type = SolidityProjectType.PLAIN
    prepared[2].build_command = []
    assert _run(prepared, tmp_path).results[0].status is CompilationStatus.SKIPPED


def test_hardhat_retains_off_host_refusal(prepared, tmp_path):
    prepared[2].project_type = SolidityProjectType.HARDHAT
    prepared[2].build_command = ["hardhat", "compile"]
    result = _run(prepared, tmp_path).results[0]
    assert result.status is CompilationStatus.UNAVAILABLE
    assert result.repository_code_execution == "blocked"
    assert "off-host" in result.errors[0]


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("failure", ["wrong-version", "missing-version", "probe-error"])
def test_any_version_preflight_failure_prevents_compilation(
    prepared, tmp_path, monkeypatch, role, failure
):
    _, material, _ = prepared
    _, launches = _fake_execution(monkeypatch, material)
    original_probe = compiler._isolated_tool_versions

    def refusing_probe(executable, *args, **kwargs):
        if Path(executable).name == role.value:
            if failure == "wrong-version":
                return {role.value: "synthetic-unmatched-version"}, None
            if failure == "missing-version":
                return {}, None
            return {}, "synthetic probe refusal"
        return original_probe(executable, *args, **kwargs)

    monkeypatch.setattr(compiler, "_isolated_tool_versions", refusing_probe)
    result = _run(prepared, tmp_path)
    assert result.results[0].status is CompilationStatus.UNAVAILABLE
    assert "managed compiler preflight refused" in result.results[0].errors[0]
    assert result.artifact_roots == [] and launches == []


@pytest.mark.parametrize("scope", ["same", "ancestor", "descendant", "source"])
def test_material_cannot_overlap_compiler_source_or_writable_roots(prepared, tmp_path, scope):
    repository, material, project = prepared
    private = {
        "same": material.directory,
        "ancestor": material.directory.parent,
        "descendant": material.directory / "compiler-output",
        "source": tmp_path / "compiler-private",
    }[scope]
    with pytest.raises(ValueError, match="overlaps"):
        compiler.compile_solidity_projects(
            material.directory if scope == "source" else repository,
            [project],
            material.config.smart_contracts,
            private,
            backend=_Backend(),
            host_tools=material,
        )


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
def test_material_pin_is_compared_to_the_retained_admission_before_probes(
    prepared, tmp_path, monkeypatch, role
):
    observe = compiler._observe_scanner_executable

    def changed_observation(path):
        original = observe(path)
        return replace(original, sha256="0" * 64) if path.name == role.value else original

    monkeypatch.setattr(compiler, "_observe_scanner_executable", changed_observation)
    with pytest.raises(ValueError, match="selected pin"):
        _run(prepared, tmp_path)


def test_empty_project_list_never_constructs_a_backend(prepared, tmp_path, monkeypatch):
    repository, material, _ = prepared
    monkeypatch.setattr(compiler, "managed_isolation_backend", lambda _: pytest.fail("factory"))
    result = compiler.compile_solidity_projects(
        repository,
        [],
        material.config.smart_contracts,
        tmp_path / "empty-private",
        host_tools=material,
    )
    assert result.results == result.artifact_roots == []
    assert not (tmp_path / "empty-private").exists()


def test_prepared_disabled_compilation_does_not_construct_or_probe_tools(
    tmp_path, config_factory, monkeypatch
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        build_command=["disabled"],
    )
    monkeypatch.setattr(compiler, "managed_isolation_backend", lambda _: pytest.fail("factory"))
    assert (
        _run((repository, material, project), tmp_path).results[0].status
        is CompilationStatus.SKIPPED
    )


def test_explicit_backend_is_preserved_and_ambient_solc_setting_is_not_read(
    prepared, tmp_path, monkeypatch
):
    _, material, _ = prepared
    monkeypatch.setattr(compiler, "managed_isolation_backend", lambda _: pytest.fail("factory"))
    environment_get = compiler.os.environ.get
    compiler_environment_key = material.config.smart_contracts.solc_executable_env

    def guarded_get(key, default=None):
        assert key != compiler_environment_key
        return environment_get(key, default)

    monkeypatch.setattr(compiler.os.environ, "get", guarded_get)
    _, launches = _fake_execution(monkeypatch, material)
    backend = _Backend()
    assert _run(prepared, tmp_path, backend=backend).results[0].status is CompilationStatus.SUCCESS
    assert backend.commands == launches


def test_project_command_mutation_during_copy_cannot_change_frozen_build(
    prepared, tmp_path, monkeypatch
):
    _, material, project = prepared
    original_copy = compiler._copy_project
    _, launches = _fake_execution(monkeypatch, material)

    def changed_copy(*args, **kwargs):
        original_copy(*args, **kwargs)
        project.build_command[:] = ["never", "execute"]

    monkeypatch.setattr(compiler, "_copy_project", changed_copy)
    assert _run(prepared, tmp_path).results[0].status is CompilationStatus.SUCCESS
    assert launches[0][1] == "build" and "never" not in launches[0]


def test_config_drift_during_copy_refuses_before_version_or_build(prepared, tmp_path, monkeypatch):
    config = prepared[1].config.smart_contracts
    original_copy = compiler._copy_project

    def changed_copy(*args, **kwargs):
        original_copy(*args, **kwargs)
        config.allow_network = True

    monkeypatch.setattr(compiler, "_copy_project", changed_copy)
    with pytest.raises(ValueError, match="managed compiler config"):
        _run(prepared, tmp_path, config=config)
