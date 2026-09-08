"""Primary Foundry selection/lifecycle controls cannot supply engine or isolation authority."""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveSource
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.scanners import foundry, runtime_evidence
from mmaudit.scanners import runner as scanner_module
from mmaudit.scanners.runner import ScannerRunner, configured_scanner_adapters
from tests.managed_offline_fork_support import prepared_archives
from tests.unit.test_managed_fork_archives import _prepare
from tests.unit.test_managed_fork_matrix import _Backend
from tests.unit.test_managed_offline_fork_consumers import _UnitLease
from tests.unit.test_managed_scanner_paths import _control_result


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    original_socket = socket.socket

    def forbidden(*args, **kwargs):
        pytest.fail(
            "invariant: primary consumer unit controls cannot execute, connect or discover PATH"
        )

    def guarded_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        # asyncio wraps already-created local wake-up socketpair descriptors.
        if family == socket.AF_UNIX and fileno is not None:
            return original_socket(family, type, proto, fileno)
        forbidden()

    monkeypatch.setattr(socket, "socket", guarded_socket)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_archives(tmp_path, config_factory, primary=True)


def add_foundry_target(prepared):
    fixture = Path(__file__).parents[1] / "fixtures/solidity/foundry"
    for name in ("foundry.toml", "src/Vault.sol", "test/audit/VaultAudit.t.sol"):
        destination = prepared[0] / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(fixture / name, destination)


def primary_adapter(prepared, *, selected=None):
    if selected is None:
        selected = _prepare(prepared)
    return configured_scanner_adapters(
        prepared[1].config, host_tools=prepared[1], offline_forks=selected
    )["foundry_fork"].with_runtime_context(allow_fork_probing=True, projects=())


def invoke_primary(adapter, prepared, *, captured=False, backend=None):
    kwargs = dict(
        backend=backend or _Backend(),
        expected_version=prepared[1].config.scanners.foundry_fork.version,
        expected_sha256=prepared[1].config.scanners.foundry_fork.sha256,
    )
    if captured:
        return runtime_evidence._invoke_builtin_foundry_adapter(
            adapter, prepared[0], prepared[2], 1, **kwargs
        )
    return adapter.run(prepared[0], prepared[2], 1, **kwargs)


def test_fixed_scanner_and_pipeline_retain_one_primary_archive_selection(prepared):
    selected = _prepare(prepared)
    pipeline = AuditPipeline(
        prepared[1].config,
        repo=prepared[0],
        output=prepared[2],
        host_tools=prepared[1],
        offline_forks=selected,
        managed_backend=_Backend(),
    )
    scanner = pipeline.scanner_runner.adapters["foundry_fork"]
    assert scanner.offline_forks is pipeline.scanner_runner.offline_forks is selected
    assert pipeline.repository_fork_matrix_runner.offline_forks is selected
    assert scanner.managed_primary_fork is True
    clone = scanner.with_runtime_context(allow_fork_probing=True, projects=())
    assert clone is not scanner and clone.offline_forks is selected
    assert clone.managed_primary_fork is True
    assert clone.config == scanner.config and clone.reproduction == scanner.reproduction
    pipeline._verify_managed_tools()
    assert selected.runtime_authority is selected.complete_state is False


@pytest.mark.parametrize("consumer", ["factory", "runner"])
@pytest.mark.parametrize("mutation", ["wrong_type", "missing_host", "source"])
def test_invalid_primary_inputs_refuse_before_backend_setup(
    prepared, monkeypatch, consumer, mutation
):
    selected, material = _prepare(prepared), prepared[1]
    if mutation == "wrong_type":
        selected = object()
    elif mutation == "missing_host":
        material = None
    else:
        prepared[4].write_text("{}")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: rejected primary selection cannot dispatch backend preflight")

    monkeypatch.setattr(scanner_module, "managed_isolation_backend", forbidden)
    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="managed"):
        if consumer == "factory":
            configured_scanner_adapters(
                prepared[1].config, host_tools=material, offline_forks=selected
            )
        else:
            ScannerRunner(prepared[1].config, host_tools=material, offline_forks=selected)


@pytest.mark.parametrize(
    "mutation", ["removed", "replaced", "flag", "endpoint", "config", "source"]
)
def test_adapter_selection_drift_cannot_enter_an_execution_body(prepared, monkeypatch, mutation):
    adapter = primary_adapter(prepared)
    if mutation == "removed":
        adapter.offline_forks = None
    elif mutation == "replaced":
        adapter.offline_forks = _prepare(prepared)
    elif mutation == "flag":
        adapter.managed_primary_fork = False
    elif mutation == "endpoint":
        adapter.fork_rpc_url_override = "http://127.0.0.1:18545"
    elif mutation == "config":
        adapter.reproduction.pinned_block_number = 8
    else:
        prepared[4].write_text("{}")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: changed primary selection cannot invoke the scanner body")

    monkeypatch.setattr(adapter, "_run_repository_suite", forbidden)
    with pytest.raises(ValueError, match="managed"):
        invoke_primary(adapter, prepared)
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("timeout", [True, 0.5, 2, float("nan"), float("inf")])
def test_prepared_scanner_requires_its_original_timeout_policy(prepared, timeout):
    with pytest.raises(ValueError, match="timeout"):
        primary_adapter(prepared).run(prepared[0], prepared[2], timeout, backend=_Backend())
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("captured", [False, True])
def test_unattested_backend_refuses_before_opening_primary_rpc(prepared, captured):
    add_foundry_target(prepared)
    run = invoke_primary(primary_adapter(prepared), prepared, captured=captured)
    assert run.status is ScannerStatus.UNAVAILABLE
    assert "isolation" in run.error or "loopback" in run.error
    assert not runtime_evidence.has_host_repository_suite_runtime_authority(run)


def test_managed_missing_primary_never_reads_ambient_rpc_even_after_unit_admission(
    prepared, monkeypatch
):
    add_foundry_target(prepared)
    selected = _prepare(
        prepared, source=ManagedForkArchiveSource(archive_root=prepared[3].archive_root)
    )
    adapter = primary_adapter(prepared, selected=selected)
    backend = _Backend()
    backend.supports_local_fork_rpc = True
    monkeypatch.setattr(
        foundry, "isolation_execution_evidence", lambda backend: ExecutionEvidenceKind.REAL
    )
    monkeypatch.setattr(foundry, "isolation_attestation_sha256", lambda backend: "a" * 64)
    # Unit-only admission control. No actual backend probe, engine or authority is supplied.
    real_get = foundry.os.environ.get

    def guarded_get(key, default=None):
        assert key != adapter.config.fork_rpc_url_env
        return real_get(key, default)

    monkeypatch.setattr(foundry.os.environ, "get", guarded_get)
    run = invoke_primary(adapter, prepared, backend=backend)
    assert run.status is ScannerStatus.UNAVAILABLE
    assert run.error == "managed primary Foundry fork archive is unavailable"
    assert not runtime_evidence.has_host_repository_suite_runtime_authority(run)


@pytest.mark.parametrize("selected", [False, True])
def test_managed_command_builder_cannot_discover_or_expose_an_endpoint(
    prepared, monkeypatch, selected
):
    adapter = (
        primary_adapter(prepared)
        if selected
        else configured_scanner_adapters(prepared[1].config, host_tools=prepared[1])["foundry_fork"]
    )

    class ForbiddenEnvironment(dict):
        def get(self, *args, **kwargs):
            pytest.fail("invariant: managed command building cannot inspect ambient RPC")

    with monkeypatch.context() as patch:
        patch.setattr(foundry.os, "environ", ForbiddenEnvironment())
        with pytest.raises(ValueError, match="owned execution"):
            adapter.build_command(prepared[0], prepared[2])


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["entry", "terminal"])
async def test_scanner_runner_rechecks_archive_bytes_and_rejects_drift(
    prepared, monkeypatch, boundary
):
    selected = _prepare(prepared)
    runner = ScannerRunner(
        prepared[1].config, host_tools=prepared[1], offline_forks=selected, backend=_Backend()
    )
    calls = []

    def control(adapter, *args, **kwargs):
        assert adapter.offline_forks is selected and adapter.managed_primary_fork
        prepared[4].write_text("{}")
        calls.append(adapter.name)
        return _control_result(adapter.name)

    monkeypatch.setattr(scanner_module, "_invoke_builtin_foundry_adapter", control)
    if boundary == "entry":
        prepared[4].write_text("{}")
    with pytest.raises(ValueError, match="managed"):
        await runner.run_all(prepared[0], prepared[2], audited_relative_paths=("ControlB.sol",))
    assert calls == ([] if boundary == "entry" else ["foundry_fork"])


@pytest.mark.parametrize("captured", [False, True])
@pytest.mark.parametrize("outcome", ["return", "exception", "interrupt", "stop_failure"])
def test_both_execution_paths_close_leases_and_custody_before_return_or_authority(
    prepared, monkeypatch, captured, outcome
):
    adapter = primary_adapter(prepared)
    failure = (
        ValueError("synthetic primary shutdown failure") if outcome == "stop_failure" else None
    )
    lease = _UnitLease(failure)
    closed = []
    result = _control_result("foundry_fork")
    original = (
        KeyboardInterrupt() if outcome == "interrupt" else RuntimeError("synthetic body failure")
    )

    def producer(self, *args, **kwargs):
        kwargs["offline_lease_guard"].append((lease, 100.0))
        kwargs["workspace_custody_guard"].append(
            SimpleNamespace(close=lambda: closed.append("closed"))
        )
        if outcome in {"exception", "interrupt"}:
            raise original
        return result

    monkeypatch.setattr(foundry.FoundryForkScanner, "_run_repository_suite", producer)
    if captured:
        # Private test factory captures the control body; the global production issuer is untouched.
        invoke, contains, *_ = runtime_evidence._build_foundry_runtime_authority()

        def execute():
            return invoke(
                adapter,
                prepared[0],
                prepared[2],
                1,
                backend=_Backend(),
                expected_version=None,
                expected_sha256=None,
            )
    else:
        contains = runtime_evidence.has_host_repository_suite_runtime_authority

        def execute():
            return invoke_primary(adapter, prepared)

    if outcome == "return":
        assert execute() is result
    else:
        error = failure if outcome == "stop_failure" else original
        with pytest.raises(type(error)) as raised:
            execute()
        assert raised.value is error
    assert lease.stops == [100.0] and closed == ["closed"]
    assert not contains(result)
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
