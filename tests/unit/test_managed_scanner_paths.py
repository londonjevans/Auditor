"""Verified managed scanner paths never fall back to ambient tools or compiler selection."""

from __future__ import annotations

import shutil
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mmaudit.models.schemas import ScannerRun, ScannerStatus
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.scanners import foundry, slither
from mmaudit.scanners import runner as runner_module
from mmaudit.scanners.base import ScannerAdapter
from mmaudit.scanners.runner import ScannerRunner, configured_scanner_adapters
from tests.host_tool_material_support import setup_host_material_inputs

HOST_SCANNERS = {
    "semgrep": ManagedToolchainRole.SEMGREP,
    "gitleaks": ManagedToolchainRole.GITLEAKS,
    "trivy": ManagedToolchainRole.TRIVY,
    "osv": ManagedToolchainRole.OSV_SCANNER,
    "codeql": ManagedToolchainRole.CODEQL,
    "slither": ManagedToolchainRole.SLITHER,
    "foundry_fork": ManagedToolchainRole.FORGE,
}


class _NoExecutionBackend:
    name = "synthetic-no-execution"

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        pytest.fail("invariant: inert managed unit material must never execute")


@pytest.fixture(autouse=True)
def forbid_external_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: no process, network or ambient PATH resolution in this unit test")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"enabled": True, "compile": False},
        formal={"enabled": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        execution={"concurrency": 1},
        scanners={name: {"enabled": True, "required": True} for name in HOST_SCANNERS},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    return repository, material


@pytest.mark.parametrize("name", HOST_SCANNERS)
def test_fixed_portfolio_receives_exact_selected_host_paths(prepared, name):
    _, material = prepared
    adapters = configured_scanner_adapters(material.config, host_tools=material)
    assert adapters[name].executable == str(material.executable_for(HOST_SCANNERS[name]))
    assert adapters["hardhat_fork"].executable == "hardhat"
    assert adapters["hardhat_fork"].available() is False
    assert material.managed_run_ready is material.runtime_authority is False


def test_foundry_runtime_clone_retains_primary_and_compiler_paths(prepared):
    _, material = prepared
    adapters = configured_scanner_adapters(material.config, host_tools=material)
    original = adapters["foundry_fork"]
    clone = original.with_runtime_context(allow_fork_probing=False, projects=())
    assert clone is not original
    assert (
        clone.executable
        == original.executable
        == str(material.executable_for(ManagedToolchainRole.FORGE))
    )
    assert (
        clone.solc_path == original.solc_path == material.executable_for(ManagedToolchainRole.SOLC)
    )
    assert adapters["slither"].solc_path == clone.solc_path


@pytest.mark.parametrize("missing", [False, True])
def test_absolute_scanner_path_availability_never_uses_path(prepared, missing):
    _, material = prepared
    adapter = configured_scanner_adapters(material.config, host_tools=material)["semgrep"]
    if missing:
        Path(adapter.executable).unlink()
    assert adapter.available() is not missing


@pytest.mark.parametrize("consumer", ["slither", "foundry"])
def test_explicit_compiler_path_is_consumed_without_reading_its_environment(
    tmp_path, monkeypatch, prepared, consumer
):
    repository, material = prepared
    config = material.config.smart_contracts
    compiler = material.executable_for(ManagedToolchainRole.SOLC)
    environment = slither.os.environ
    real_get = environment.get

    def guarded_get(key, default=None):
        assert key != config.solc_executable_env, (
            "explicit compiler must not read its ambient source"
        )
        return real_get(key, default)

    monkeypatch.setattr(environment, "get", guarded_get)
    if consumer == "foundry":
        selected, digest = foundry._resolve_pinned_solidity_compiler(
            repository, config, explicit_path=compiler
        )
        assert selected == compiler
        assert digest == config.solc_sha256
    else:
        private = tmp_path / "scanner-private"
        private.mkdir(mode=0o700)
        selected = slither._stage_pinned_compiler(
            repository, private, config, explicit_path=compiler
        )
        assert selected != compiler
        assert selected.read_bytes() == compiler.read_bytes()


@pytest.mark.parametrize("conflict", ["config", "backend", "adapters"])
def test_managed_runner_rejects_mixed_selection_or_unavailable_backend(
    prepared, conflict, monkeypatch
):
    _, material = prepared
    config = material.config
    kwargs = {"host_tools": material, "backend": _NoExecutionBackend()}
    if conflict == "config":
        config.execution.scanner_timeout_seconds += 1
    elif conflict == "backend":
        kwargs["backend"] = None

        def unavailable(_material):
            raise ValueError("managed backend is unavailable")

        monkeypatch.setattr(runner_module, "managed_isolation_backend", unavailable)
    else:
        kwargs["adapters"] = {}
    with pytest.raises(ValueError, match="managed"):
        ScannerRunner(config, **kwargs)


def _control_result(name):
    instant = datetime(2026, 1, 1, tzinfo=UTC)
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.SUCCESS,
        started_at=instant,
        finished_at=instant,
        duration_seconds=0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["entry", "queued", "terminal"])
@pytest.mark.parametrize("drift", ["bytes", "config"])
async def test_managed_worker_rechecks_material_and_config_at_each_run_boundary(
    prepared, tmp_path, monkeypatch, boundary, drift
):
    repository, material = prepared
    runner = ScannerRunner(material.config, host_tools=material, backend=_NoExecutionBackend())
    tool = material.executable_for(ManagedToolchainRole.GIT)
    calls = []

    def mutate():
        if drift == "config":
            runner.config.execution.scanner_timeout_seconds += 1
        else:
            tool.chmod(0o600)
            tool.write_bytes(b"Synthetic drift; never executable.\n")
            tool.chmod(0o500)

    def control(adapter, *args, **kwargs):
        assert Path(adapter.executable).is_absolute()
        assert kwargs["expected_sha256"] == getattr(material.config.scanners, adapter.name).sha256
        calls.append(adapter.name)
        if (boundary == "queued" and adapter.name == "semgrep") or (
            boundary == "terminal" and adapter.name == "foundry_fork"
        ):
            mutate()
        return _control_result(adapter.name)

    monkeypatch.setattr(ScannerAdapter, "run_source_bound", control)
    monkeypatch.setattr(runner_module, "_invoke_builtin_foundry_adapter", control)
    if boundary == "entry":
        mutate()
    with pytest.raises(ValueError, match=r"managed|material"):
        await runner.run_all(
            repository, tmp_path / "private", audited_relative_paths=("ControlB.sol",)
        )
    assert calls == (
        [] if boundary == "entry" else ["semgrep"] if boundary == "queued" else list(HOST_SCANNERS)
    )
    assert material.managed_run_ready is False


@pytest.mark.asyncio
async def test_managed_runner_detaches_config_and_rebuilds_its_fixed_adapter_view(
    prepared, tmp_path, monkeypatch
):
    repository, material = prepared
    config = material.config
    runner = ScannerRunner(config, host_tools=material, backend=_NoExecutionBackend())
    config.execution.scanner_timeout_seconds += 1
    runner.adapters.clear()
    calls = []

    def control(adapter, *args, **kwargs):
        assert (
            Path(adapter.executable)
            == material.directory
            / {item.role: item.locator for item in material.manifest.files}[
                HOST_SCANNERS[adapter.name]
            ]
        )
        calls.append(adapter.name)
        return _control_result(adapter.name)

    monkeypatch.setattr(ScannerAdapter, "run_source_bound", control)
    monkeypatch.setattr(runner_module, "_invoke_builtin_foundry_adapter", control)
    results = await runner.run_all(
        repository, tmp_path / "private", audited_relative_paths=("ControlB.sol",)
    )
    assert calls == list(HOST_SCANNERS)
    assert len(results) == 8
    assert (
        next(item for item in results if item.scanner == "hardhat_fork").status
        is ScannerStatus.SKIPPED
    )
    assert runner.config == material.config


@pytest.mark.parametrize("consumer", ["slither", "foundry"])
@pytest.mark.parametrize("invalid", ["missing", "relative", "linked", "digest"])
def test_bad_explicit_compiler_never_falls_back_to_the_environment(
    prepared, tmp_path, monkeypatch, consumer, invalid
):
    repository, material = prepared
    config = material.config.smart_contracts
    compiler = material.executable_for(ManagedToolchainRole.SOLC)
    if invalid == "missing":
        selected = compiler.with_name("absent-solc")
    elif invalid == "relative":
        selected = Path("solc")
    elif invalid == "linked":
        selected = tmp_path / "compiler-link"
        selected.symlink_to(compiler)
    else:
        selected = material.executable_for(ManagedToolchainRole.GIT)

    environment = slither.os.environ
    real_get = environment.get

    def guarded_get(key, default=None):
        assert key != config.solc_executable_env, "bad explicit compiler must not read a fallback"
        return real_get(key, default)

    monkeypatch.setattr(environment, "get", guarded_get)
    with pytest.raises(ValueError):
        if consumer == "foundry":
            foundry._resolve_pinned_solidity_compiler(repository, config, explicit_path=selected)
        else:
            slither._stage_pinned_compiler(
                repository, tmp_path / "private", config, explicit_path=selected
            )
