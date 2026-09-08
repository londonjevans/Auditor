"""Prepared formal-tool selection with inert executables and no target execution."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    FormalToolStatus,
    InvariantSuite,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.solidity import formal
from tests.host_tool_material_support import setup_host_material_inputs

_ROLES = {
    "solc-smtchecker": ManagedToolchainRole.SOLC,
    "mythril": ManagedToolchainRole.MYTHRIL,
    "echidna": ManagedToolchainRole.ECHIDNA,
    "medusa": ManagedToolchainRole.MEDUSA,
    "foundry-invariant": ManagedToolchainRole.FORGE,
    "halmos": ManagedToolchainRole.HALMOS,
    "certora": ManagedToolchainRole.CERTORA_CLI,
    "kontrol": ManagedToolchainRole.KONTROL,
}


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: inert formal material cannot execute, find PATH tools or network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


class _Backend:
    name = "synthetic-managed-formal"

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
        smart_contracts={"compile": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        formal={"enabled": True, "required_tools": ["certora"]},
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
        project_type=SolidityProjectType.PLAIN,
        project_root=".",
        source_directories=["."],
    )
    index = SoliditySymbolIndex(
        projects=[project],
        entities=[
            SolidityEntity(
                id="function:ControlB:setLimit",
                kind=SolidityEntityKind.FUNCTION,
                name="setLimit",
                contract_name="ControlB",
                path="ControlB.sol",
                start_line=14,
                end_line=17,
                byte_start=0,
                byte_end=1,
                source_hash=hashlib.sha256((repository / "ControlB.sol").read_bytes()).hexdigest(),
                provenance=SolidityProvenance.FALLBACK,
                confidence=0.5,
                transformation="synthetic_test_entity",
                visibility="external",
            )
        ],
    )
    return repository, material, project, index


def _runner(prepared, **kwargs):
    return formal.FormalRunner(
        kwargs.pop("config", prepared[1].config.formal),
        host_tools=kwargs.pop("host_tools", prepared[1]),
        backend=kwargs.pop("backend", _Backend()),
        **kwargs,
    )


def _run(runner, prepared, tmp_path, **kwargs):
    repository, _, project, index = prepared
    return runner.run(
        repository_root=kwargs.pop("repository_root", repository),
        projects=kwargs.pop("projects", [project]),
        index=index,
        invariants=InvariantSuite(),
        private_dir=kwargs.pop("private_dir", tmp_path / "formal-private"),
        **kwargs,
    )


def _change(material, role, mutation="bytes"):
    path = material.executable_for(role)
    if mutation == "replacement":
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o500)
        replacement.replace(path)
    else:
        path.chmod(0o600)
        path.write_bytes(b"Changed inert formal fixture; must never execute.\n")
        path.chmod(0o500)


def _fake_execution(monkeypatch, material, *, during_probe=None, after_run=None, version=None):
    probes, launches = [], []
    versions = {item.locator: item.version for item in material.manifest.files}

    def probe(executable, **kwargs):
        assert kwargs["expected_host_observation"].sha256
        probes.append(executable.name)
        if during_probe is not None:
            during_probe(executable)
        return versions[executable.name] if version is None else version

    class Process:
        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    def launch(command, **kwargs):
        assert kwargs["shell"] is False
        assert Path(command[0]).parent == material.directory
        launches.append(command.copy())
        if after_run is not None:
            after_run()
        return Process()

    monkeypatch.setattr(formal, "_isolated_tool_version", probe)
    monkeypatch.setattr(subprocess, "Popen", launch)
    return probes, launches


def test_fixed_eight_engine_portfolio_uses_prepared_paths(prepared):
    runner = _runner(prepared)
    assert [item.name for item in runner.adapters] == list(_ROLES)
    for adapter in runner.adapters:
        assert adapter.executable == str(prepared[1].executable_for(_ROLES[adapter.name]))
    assert not runner.config.certora.enabled
    assert runner.isolation_available is False


@pytest.mark.parametrize("bad_material", [False, {}, "material", object()])
def test_wrong_material_type_refuses_before_backend_factory(prepared, bad_material, monkeypatch):
    def forbidden(*args):
        pytest.fail("material validation must precede backend construction")

    monkeypatch.setattr(formal, "default_isolation_backend", forbidden)
    with pytest.raises(ValueError, match=r"managed|material"):
        _runner(prepared, host_tools=bad_material, backend=None)


@pytest.mark.parametrize("field,value", [("timeout_seconds", 17), ("halmos_sha256", "0" * 64)])
def test_mixed_config_refuses_before_writes(prepared, tmp_path, field, value):
    config = prepared[1].config.formal.model_copy(update={field: value})
    with pytest.raises(ValueError, match=r"managed|material"):
        _runner(prepared, config=config)
    assert not (tmp_path / "formal-private").exists()


@pytest.mark.parametrize("adapters", [[], [formal.SolcSMTCheckerAdapter()]])
def test_custom_adapters_refuse_in_managed_mode(prepared, adapters):
    with pytest.raises(ValueError, match=r"managed|adapter"):
        _runner(prepared, adapters=adapters)


@pytest.mark.parametrize("role", [ManagedToolchainRole.SOLC, ManagedToolchainRole.HALMOS_Z3])
@pytest.mark.parametrize("mutation", ["bytes", "replacement"])
def test_material_drift_after_selection_refuses_before_probe(prepared, tmp_path, role, mutation):
    runner = _runner(prepared)
    _change(prepared[1], role, mutation)
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(runner, prepared, tmp_path)
    assert not (tmp_path / "formal-private").exists()


@pytest.mark.parametrize("root", ["source", "private", "ancestor"])
def test_material_must_be_disjoint_from_source_and_private(prepared, tmp_path, root):
    runner = _runner(prepared)
    material_root = prepared[1].directory
    kwargs = (
        {"repository_root": material_root}
        if root == "source"
        else {"private_dir": material_root if root == "private" else material_root.parent}
    )
    with pytest.raises(ValueError, match=r"managed|overlap"):
        _run(runner, prepared, tmp_path, **kwargs)


def test_smt_and_mythril_are_pinned_and_probed_before_target_run(prepared, tmp_path, monkeypatch):
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(_runner(prepared), prepared, tmp_path)
    assert probes == ["solc", "myth"]
    assert [Path(command[0]).name for command in launches] == probes
    assert all(item.execution_evidence is ExecutionEvidenceKind.UNVERIFIED for item in result)
    assert [item.tool for item in result if item.status is FormalToolStatus.SKIPPED] == [
        "echidna",
        "medusa",
        "foundry-invariant",
        "halmos",
        "kontrol",
    ]


def test_wrong_primary_version_prevents_target_execution(prepared, tmp_path, monkeypatch):
    probes, launches = _fake_execution(monkeypatch, prepared[1], version="wrong-version")
    result = _run(_runner(prepared), prepared, tmp_path)
    assert probes == ["solc", "myth"]
    assert not launches
    assert all(
        item.status is FormalToolStatus.INCONCLUSIVE
        for item in result
        if item.tool in {"solc-smtchecker", "mythril"}
    )


@pytest.mark.parametrize("stage", ["probe", "wrap", "outcome"])
def test_same_byte_replacement_during_execution_cannot_return_a_result(
    prepared, tmp_path, monkeypatch, stage
):
    def mutate(*args):
        _change(prepared[1], ManagedToolchainRole.HALMOS_Z3, "replacement")

    probes, launches = _fake_execution(
        monkeypatch,
        prepared[1],
        during_probe=mutate if stage == "probe" else None,
        after_run=mutate if stage == "outcome" else None,
    )
    runner = _runner(prepared, backend=_Backend(mutate if stage == "wrap" else None))
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(runner, prepared, tmp_path)
    assert probes == ["solc"]
    assert len(launches) == (1 if stage == "outcome" else 0)


def test_mutated_adapter_view_cannot_replace_fixed_portfolio(prepared, tmp_path, monkeypatch):
    runner = _runner(prepared)
    runner.adapters[0].executable = "/forbidden/custom-tool"
    runner.adapters.clear()
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(runner, prepared, tmp_path)
    assert probes == ["solc", "myth"] and len(launches) == 2
    assert len(result) == 7


@pytest.mark.parametrize(
    "name,dependency,flag",
    [
        ("halmos", ManagedToolchainRole.HALMOS_Z3, "--solver-command"),
        ("foundry-invariant", ManagedToolchainRole.SOLC, "--use"),
    ],
)
def test_dependency_command_uses_exact_prepared_path(prepared, tmp_path, name, dependency, flag):
    repository, material, _, index = prepared
    runner = _runner(prepared)
    adapter = next(item for item in runner.adapters if item.name == name)
    dependencies, error = adapter.dependencies(repository_root=repository, config=runner.config)
    assert not error and len(dependencies) == 1
    path = material.executable_for(dependency)
    assert dependencies[0].executable == path
    command = adapter.build_command_with_dependencies(
        Path(adapter.executable),
        tmp_path,
        tmp_path / "result.json",
        index,
        runner.config,
        dependencies,
    )
    assert command[command.index(flag) + 1] == str(path)
    if name == "foundry-invariant":
        assert "--no-auto-detect" in command and "--offline" in command


def test_omitted_backend_uses_only_managed_factory(prepared, monkeypatch):
    selected = []
    backend = _Backend()

    def factory(material):
        selected.append(material)
        return backend

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    runner = _runner(prepared, backend=None)
    assert runner.backend is backend and selected == [prepared[1]]


def test_unavailable_managed_backend_does_not_fall_back(prepared, monkeypatch):
    def unavailable(material):
        raise ValueError("managed isolation unavailable in this synthetic case")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", unavailable)
    with pytest.raises(ValueError, match="managed isolation unavailable"):
        _runner(prepared, backend=None)
    backend = _Backend()
    assert _runner(prepared, backend=backend).backend is backend


def test_disabled_formal_material_needs_no_backend_or_execution(
    tmp_path, config_factory, monkeypatch
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False},
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

    def forbidden(*args):
        pytest.fail("disabled formal execution must not construct a backend")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    runner = formal.FormalRunner(material.config.formal, host_tools=material)
    assert runner.backend is None
    assert (
        runner.run(
            repository_root=repository,
            projects=[],
            index=SoliditySymbolIndex(projects=[], entities=[]),
            invariants=InvariantSuite(),
            private_dir=tmp_path / "formal-private",
        )
        == []
    )
    assert not (tmp_path / "formal-private").exists()


def test_missing_project_is_skipped_not_a_pass(prepared, tmp_path):
    results = _run(_runner(prepared), prepared, tmp_path, projects=[])
    assert len(results) == 7 and all(item.status is FormalToolStatus.SKIPPED for item in results)
    assert not (tmp_path / "formal-private").exists()


@pytest.mark.parametrize("stage", ["selection", "probe", "outcome"])
def test_changed_config_refuses_before_a_result(prepared, tmp_path, monkeypatch, stage):
    runner = _runner(prepared)

    def mutate(*args):
        runner.config.timeout_seconds = 19

    _, launches = _fake_execution(
        monkeypatch,
        prepared[1],
        during_probe=mutate if stage == "probe" else None,
        after_run=mutate if stage == "outcome" else None,
    )
    if stage == "selection":
        mutate()
    with pytest.raises(ValueError, match=r"managed|config"):
        _run(runner, prepared, tmp_path)
    assert len(launches) == (1 if stage == "outcome" else 0)


def test_output_preparation_cannot_replace_dependency_before_popen(prepared, tmp_path, monkeypatch):
    runner = _runner(prepared)
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    original_open = Path.open

    def guarded_open(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        if path.name == "stderr.txt" and mode == "wb":
            _change(prepared[1], ManagedToolchainRole.HALMOS_Z3, "replacement")
        return handle

    monkeypatch.setattr(Path, "open", guarded_open)
    with pytest.raises(ValueError, match=r"managed|identity"):
        _run(runner, prepared, tmp_path)
    assert probes == ["solc"] and not launches


@pytest.mark.parametrize("name", ["halmos", "foundry-invariant"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_sha256", "0" * 64),
        ("expected_version", "9.8.7"),
        ("executable", Path("/forbidden/ambient-dependency")),
    ],
)
def test_dependency_pin_or_path_redirection_refuses_before_dependency_probe(
    prepared, tmp_path, monkeypatch, name, field, value
):
    runner = _runner(prepared)
    adapter = next(item for item in runner.adapters if item.name == name)
    specs, error = adapter.dependencies(repository_root=prepared[0], config=runner.config)
    assert not error and len(specs) == 1
    changed = replace(specs[0], **{field: value})
    monkeypatch.setattr(type(adapter), "dependencies", lambda *args, **kwargs: ([changed], ""))
    monkeypatch.setattr(type(adapter), "applicable_with_corpus", lambda *args: (True, ""))
    # Select one branch of the fixed portfolio; only inert unit process doubles are used.
    monkeypatch.setattr(runner, "_enabled", lambda selected: selected == name)
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    results = _run(runner, prepared, tmp_path)
    assert probes == [Path(adapter.executable).name] and not launches
    assert len(results) == 1 and results[0].status is FormalToolStatus.FAILED


@pytest.mark.parametrize("name", ["halmos", "foundry-invariant"])
def test_dependency_version_mismatch_is_inconclusive_not_execution(
    prepared, tmp_path, monkeypatch, name
):
    runner = _runner(prepared)
    adapter = next(item for item in runner.adapters if item.name == name)
    monkeypatch.setattr(type(adapter), "applicable_with_corpus", lambda *args: (True, ""))
    monkeypatch.setattr(runner, "_enabled", lambda selected: selected == name)
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    initial_probe = formal._isolated_tool_version

    def probe(executable, **kwargs):
        observed = initial_probe(executable, **kwargs)
        return observed if len(probes) == 1 else "wrong dependency version"

    monkeypatch.setattr(formal, "_isolated_tool_version", probe)
    results = _run(runner, prepared, tmp_path)
    assert len(probes) == 2 and not launches
    assert results[0].status is FormalToolStatus.INCONCLUSIVE
    assert len(results[0].dependencies) == 1
