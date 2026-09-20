"""Pinned, offline property-engine compiler handoff over inert local tools."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
from dataclasses import replace

import pytest

from mmaudit.config import FormalConfig, ScannerConfig, SmartContractsConfig
from mmaudit.solidity import formal
from tests.unit.test_echidna import FIXTURE, _inputs


@pytest.fixture(params=[formal.EchidnaAdapter, formal.MedusaAdapter])
def compiler_case(request, tmp_path, monkeypatch, config_factory):
    repository = tmp_path / "repo"
    shutil.copytree(FIXTURE, repository)
    _, index, _, corpus = _inputs(repository, config_factory())
    tools = tmp_path / "host-tools"
    tools.mkdir()
    paths = {}
    for name in ("forge", "solc"):
        path = tools / name
        path.write_bytes(f"Inert pinned {name}; must never execute.\n".encode())
        path.chmod(0o500)
        paths[name] = path
    monkeypatch.setattr(shutil, "which", lambda name: str(paths[name]) if name in paths else None)
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(paths["solc"]))
    compiler = SmartContractsConfig(
        solc_version="0.8.30", solc_sha256=hashlib.sha256(paths["solc"].read_bytes()).hexdigest()
    )
    forge = ScannerConfig(
        version="1.5.1", sha256=hashlib.sha256(paths["forge"].read_bytes()).hexdigest()
    )

    def forbidden(*args, **kwargs):
        pytest.fail("inert compiler handoff must not execute or access a network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    adapter = request.param(compiler_config=compiler, forge_config=forge)
    return adapter, repository, index, corpus, compiler, forge, paths


def _prepare(compiler_case, tmp_path):
    adapter, repository, index, corpus, *_ = compiler_case
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    formal.sanitized_scanner_environment(private)
    workspace = private / "workspace"
    shutil.copytree(repository, workspace)
    config = FormalConfig(enabled=True)
    dependencies, reason = adapter.dependencies(repository_root=repository, config=config)
    assert not reason
    prepared = adapter.prepare_workspace_with_dependencies(
        repository_root=repository,
        workspace=workspace,
        index=index,
        property_corpus=corpus,
        config=config,
        dependencies=dependencies,
    )
    return private, workspace, config, dependencies, prepared


def test_declares_exact_forge_and_solc_dependencies(compiler_case):
    adapter, repository, _, _, compiler, forge, paths = compiler_case
    dependencies, reason = adapter.dependencies(repository_root=repository, config=FormalConfig())
    assert not reason
    assert [(item.name, item.executable) for item in dependencies] == [
        (name, paths[name]) for name in ("forge", "solc")
    ]
    assert dependencies[0].expected_sha256 == forge.sha256
    assert dependencies[1].expected_sha256 == compiler.solc_sha256


def test_stages_exact_tools_and_retains_foundry_settings(compiler_case, tmp_path):
    adapter, repository, _, _, _, _, paths = compiler_case
    private, workspace, config, dependencies, prepared = _prepare(compiler_case, tmp_path)
    assert prepared is not None and prepared.property_map
    for name, source in paths.items():
        staged = private / "toolchain" / name
        assert staged.read_bytes() == source.read_bytes()
        assert staged.stat().st_mode & 0o777 == 0o500
        assert staged.stat().st_nlink == 1
    assert (workspace / "foundry.toml").read_bytes() == (repository / "foundry.toml").read_bytes()
    if adapter.name == "medusa":
        retained = json.loads((workspace / prepared.configuration_path).read_text())
        assert retained == json.loads(prepared.configuration)
        assert retained["compilation"]["platformConfig"]["target"] == str(
            workspace / prepared.source_path
        )
        assert retained["compilation"]["platformConfig"]["args"] == [
            "--compile-force-framework",
            "foundry",
        ]
    extension = adapter.execution_environment_with_dependencies(
        config=config,
        private_dir=private,
        dependencies=dependencies,
        environment={"PATH": "/usr/bin:/bin"},
    )
    assert extension.variables == {
        "PATH": str(private / "toolchain") + os.pathsep + "/usr/bin:/bin",
        "FOUNDRY_SOLC": str(private / "toolchain" / "solc"),
        "FOUNDRY_OFFLINE": "true",
        "FOUNDRY_FFI": "false",
    }
    adapter.validate_pre_execution_inputs(private_dir=private, dependencies=dependencies)


@pytest.mark.parametrize("tool", ["forge", "solc"])
def test_wrong_compiler_pin_refuses_before_probe(compiler_case, monkeypatch, tool):
    adapter, repository, _, _, _, _, paths = compiler_case
    paths[tool].chmod(0o700)
    paths[tool].write_bytes(b"Different inert executable.\n")

    def forbidden(*args, **kwargs):
        pytest.fail("a mismatched compiler must not be executed")

    monkeypatch.setattr(formal, "_isolated_tool_version", forbidden)
    dependencies, reason = adapter.dependencies(repository_root=repository, config=FormalConfig())
    assert not dependencies and "pin" in reason.lower()


@pytest.mark.parametrize("mutation", ["bytes", "mode", "link", "hardlink"])
def test_staged_compiler_drift_refuses_before_dispatch(compiler_case, tmp_path, mutation):
    adapter, *_ = compiler_case
    private, _, _, dependencies, _ = _prepare(compiler_case, tmp_path)
    staged = private / "toolchain" / "solc"
    if mutation == "bytes":
        staged.chmod(0o700)
        staged.write_bytes(b"Changed inert compiler.\n")
        staged.chmod(0o500)
    elif mutation == "mode":
        staged.chmod(0o700)
    elif mutation == "link":
        retained = staged.with_name("solc-retained")
        staged.rename(retained)
        staged.symlink_to(retained)
    else:
        os.link(staged, staged.with_name("solc-alias"))
    with pytest.raises(ValueError, match=r"compiler|toolchain"):
        adapter.validate_pre_execution_inputs(private_dir=private, dependencies=dependencies)


@pytest.mark.parametrize("missing", ["solc", "forge"])
def test_configured_compiler_never_falls_back_without_pins(compiler_case, missing):
    adapter, repository, _, _, compiler, forge, _ = compiler_case
    configured = type(adapter)(
        compiler_config=SmartContractsConfig() if missing == "solc" else compiler,
        forge_config=ScannerConfig() if missing == "forge" else forge,
    )
    dependencies, reason = configured.dependencies(
        repository_root=repository, config=FormalConfig()
    )
    assert not dependencies and "pin" in reason.lower()


def test_fixed_default_runner_receives_existing_compiler_configuration(compiler_case):
    _, _, _, _, compiler, forge, _ = compiler_case
    runner = formal.FormalRunner(
        FormalConfig(), compiler_config=compiler, forge_config=forge, backend=object()
    )
    selected = [item for item in runner.adapters if item.name in {"echidna", "medusa"}]
    assert len(selected) == 2
    assert all(item.compiler_config == compiler and item.forge_config == forge for item in selected)


@pytest.mark.parametrize("mutation", ["repository", "symlink", "hardlink", "relative", "missing"])
def test_unsafe_source_compiler_is_not_admitted(compiler_case, tmp_path, monkeypatch, mutation):
    adapter, repository, _, _, _, _, paths = compiler_case
    dependencies, reason = adapter.dependencies(repository_root=repository, config=FormalConfig())
    assert not reason
    selected = paths["solc"]
    if mutation == "repository":
        selected = repository / "solc"
        shutil.copyfile(paths["solc"], selected)
        selected.chmod(0o500)
    elif mutation == "symlink":
        selected = tmp_path / "solc-link"
        selected.symlink_to(paths["solc"])
    elif mutation == "hardlink":
        os.link(selected, tmp_path / "solc-link")
    elif mutation == "relative":
        monkeypatch.chdir(tmp_path)
        selected = paths["solc"].relative_to(tmp_path)
    else:
        selected = tmp_path / "not-present"
    prepared = type(adapter)(
        compiler_dependencies=(dependencies[0], replace(dependencies[1], executable=selected))
    )
    actual, error = prepared.dependencies(repository_root=repository, config=FormalConfig())
    assert not actual and error


def test_missing_source_never_falls_back_to_an_ambient_compiler(compiler_case, monkeypatch):
    adapter, repository, *_ = compiler_case
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(repository / "not-present"))
    actual, error = adapter.dependencies(repository_root=repository, config=FormalConfig())
    assert not actual and error


def test_staging_bound_remains_enforced(compiler_case, tmp_path, monkeypatch):
    adapter, repository, *_ = compiler_case
    monkeypatch.setattr(formal, "_MAX_PROPERTY_COMPILER_BYTES", 1)
    actual, error = adapter.dependencies(repository_root=repository, config=FormalConfig())
    assert not actual and error
    assert not (tmp_path / "private").exists()


def test_non_foundry_settings_are_not_silently_discarded(compiler_case, tmp_path):
    _, repository, *_ = compiler_case
    (repository / "foundry.toml").rename(repository / "synthetic-settings.toml")
    with pytest.raises(ValueError, match="requires a Foundry project"):
        _prepare(compiler_case, tmp_path)
    assert not (tmp_path / "private" / "toolchain").exists()


def test_legacy_adapter_does_not_claim_compiler_provenance(compiler_case):
    adapter, repository, *_ = compiler_case
    dependencies, reason = type(adapter)().dependencies(
        repository_root=repository, config=FormalConfig()
    )
    assert dependencies == [] and reason == ""


@pytest.mark.parametrize("mutate_on_wrap", [False, True])
def test_runner_consumes_and_rechecks_declared_compiler_handoff(
    compiler_case, tmp_path, monkeypatch, mutate_on_wrap
):
    adapter, repository, index, corpus, _, _, _ = compiler_case
    engine = tmp_path / "engine"
    engine.write_bytes(b"Inert property engine; never execute.\n")
    engine.chmod(0o500)
    monkeypatch.setattr(adapter, "available", lambda root: engine)
    probes, launches = [], []

    def version(path, **kwargs):
        probes.append(path.name)
        return "0.8.30" if path.name == "solc" else "1.5.1"

    class Backend:
        name = "inert-property-compiler-test"

        def wrap(self, command, *, workspace, private_dir, rpc_port):
            if mutate_on_wrap:
                compiler = private_dir / "toolchain" / "solc"
                compiler.chmod(0o700)
                compiler.write_bytes(b"Changed before dispatch.\n")
                compiler.chmod(0o500)
            return command

    def process(command, **kwargs):
        launches.append(command)
        private = kwargs["cwd"].parent
        assert kwargs["environment"]["FOUNDRY_SOLC"] == str(private / "toolchain" / "solc")
        assert kwargs["environment"]["PATH"].split(os.pathsep)[0] == str(private / "toolchain")
        assert kwargs["environment"]["FOUNDRY_OFFLINE"] == "true"
        assert kwargs["environment"]["FOUNDRY_FFI"] == "false"
        kwargs["stdout_path"].write_text("")
        kwargs["stderr_path"].write_text("")
        return 0

    monkeypatch.setattr(formal, "_isolated_tool_version", version)
    monkeypatch.setattr(formal, "_bounded_process", process)
    settings = {
        f"{adapter.name}_version": "1.5.1",
        f"{adapter.name}_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
    }
    runner = formal.FormalRunner(
        FormalConfig(enabled=True, **settings), adapters=[adapter], backend=Backend()
    )
    result = runner.run(
        repository_root=repository,
        projects=index.projects,
        index=index,
        invariants=formal.InvariantSuite(),
        property_corpus=corpus,
        private_dir=tmp_path / "run",
    )[0]
    assert probes == ["engine", "forge", "solc"]
    assert [item.name for item in result.dependencies] == ["forge", "solc"]
    assert result.execution_evidence is formal.ExecutionEvidenceKind.UNVERIFIED
    if mutate_on_wrap:
        assert not launches and result.status is formal.FormalToolStatus.FAILED
    else:
        assert len(launches) == 1
        assert result.status is formal.FormalToolStatus.SUCCESS
        assert not result.machine_output_validated and not result.evidence


def test_pipeline_passes_existing_compiler_pins_without_model_execution(
    compiler_case, tmp_path, config_factory
):
    from mmaudit.orchestration.pipeline import AuditPipeline

    _, repository, _, _, compiler, forge, _ = compiler_case
    config = config_factory(
        smart_contracts=compiler.model_dump(mode="json"),
        scanners={"foundry_fork": forge.model_dump(mode="json")},
        formal={"enabled": False},
        reproduction={"enabled": False},
    )
    pipeline = AuditPipeline(config, repo=repository, output=tmp_path / "audit-output")
    adapters = [
        item for item in pipeline.formal_runner.adapters if item.name in {"echidna", "medusa"}
    ]
    assert len(adapters) == 2
    assert all(item.compiler_config == config.smart_contracts for item in adapters)
    assert all(item.forge_config == config.scanners.foundry_fork for item in adapters)


def test_custom_adapter_selection_cannot_silently_ignore_compiler_config(compiler_case):
    adapter, _, _, _, compiler, forge, _ = compiler_case
    with pytest.raises(ValueError, match="declare their own compiler selection"):
        formal.FormalRunner(
            FormalConfig(), adapters=[adapter], compiler_config=compiler, forge_config=forge
        )
