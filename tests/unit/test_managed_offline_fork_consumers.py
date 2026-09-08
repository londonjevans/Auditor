"""Managed handoff and lifecycle controls: no engine, socket or real isolation credit."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.models.schemas import RepositoryExecutionStateObservationStatus
from mmaudit.orchestration import managed_provisioning_runtime as runtime
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveError, ManagedForkArchives
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.scanners import fork_matrix
from mmaudit.scanners.fork_rpc import ForkRpcUnavailableError
from tests.managed_offline_fork_support import prepared_archives
from tests.unit.test_managed_fork_archives import _prepare, _state
from tests.unit.test_managed_fork_matrix import _Backend, _run, _runner


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: prepared consumer controls cannot execute, connect or search PATH")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_archives(tmp_path, config_factory)


def _setup(prepared, tmp_path, **kwargs):
    output = tmp_path / "managed-setup"
    output.mkdir(mode=0o700, exist_ok=True)
    return runtime.provision_managed_local_run(
        config=prepared[1].config,
        bundle=prepared[1].bundle,
        repository=prepared[0],
        output_dir=output,
        verify_only=kwargs.pop("verify_only", False),
        host_tool_source=ManagedHostToolSource(blob_root=tmp_path / "host-blobs"),
        offline_fork_source=prepared[3],
        **kwargs,
    )


@pytest.mark.parametrize("phase", ["prepared", "published"])
@pytest.mark.parametrize("existing", [False, True])
def test_source_drift_at_publication_cannot_publish_a_new_receipt(
    prepared, tmp_path, monkeypatch, phase, existing
):
    if existing:
        _setup(prepared, tmp_path)
    output = tmp_path / "managed-setup"
    previous = {path.name: path.read_bytes() for path in output.glob("*receipt-*.json")}
    method = "prepare" if phase == "prepared" else "_publish_or_verify_locked"
    original = getattr(runtime._PrivateOutputCustody, method)

    def drift(self, *args):
        result = original(self, *args)
        prepared[4].write_text("{}")
        return result

    monkeypatch.setattr(runtime._PrivateOutputCustody, method, drift)
    with pytest.raises(ManagedForkArchiveError):
        _setup(prepared, tmp_path)
    assert {path.name: path.read_bytes() for path in output.glob("*receipt-*.json")} == previous
    assert not list(output.glob(".*.tmp"))


def test_unavailable_archive_refuses_before_host_or_ledger_materialization(
    prepared, tmp_path, monkeypatch
):
    prepared[4].rename(prepared[4].with_suffix(".not-selected"))

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: missing declared archive must refuse before host or ledger writes")

    monkeypatch.setattr(runtime, "materialize_managed_host_tools", forbidden)
    monkeypatch.setattr(runtime, "_managed_cost_ledger_observation", forbidden)
    with pytest.raises(ManagedForkArchiveError):
        _setup(prepared, tmp_path)
    assert not list((tmp_path / "managed-setup").iterdir())


@pytest.mark.parametrize("value", [object(), {}, "archive"])
def test_setup_result_rejects_nonprepared_archive_handles(prepared, tmp_path, value):
    result = _setup(prepared, tmp_path)
    with pytest.raises(runtime.ManagedProvisioningRuntimeError, match="archive material"):
        replace(result, offline_forks=value)


@pytest.mark.parametrize("consumer", ["matrix", "pipeline"])
@pytest.mark.parametrize("kind", ["wrong_type", "config", "missing_host"])
def test_fixed_consumers_require_exact_prepared_material(prepared, consumer, kind):
    selected = _prepare(prepared)
    host_tools = prepared[1]
    if kind == "wrong_type":
        selected = object()
    elif kind == "config":
        config = host_tools.config
        config.smart_contracts.foundry_fuzz_runs += 1
        selected = _prepare(prepared, config=config)
    else:
        host_tools = None
    with pytest.raises(ValueError, match="managed"):
        if consumer == "matrix":
            _runner(prepared, host_tools=host_tools, offline_forks=selected)
        else:
            AuditPipeline(
                prepared[1].config,
                repo=prepared[0],
                output=prepared[2],
                host_tools=host_tools,
                managed_backend=_Backend(),
                offline_forks=selected,
            )


@pytest.mark.parametrize("mutation", ["removed", "replaced", "source"])
def test_retained_matrix_archive_selection_drift_refuses_before_output(prepared, mutation):
    runner = _runner(prepared, offline_forks=_prepare(prepared))
    if mutation == "removed":
        runner.offline_forks = None
    elif mutation == "replaced":
        runner.offline_forks = _prepare(prepared)
    else:
        prepared[4].write_text("{}")
    with pytest.raises(ValueError, match="managed"):
        _run(runner, prepared)
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("mutation", ["wrong_type", "source"])
def test_invalid_archive_selection_refuses_before_automatic_backend_setup(
    prepared, monkeypatch, mutation
):
    selected = _prepare(prepared)
    if mutation == "wrong_type":
        selected = object()
    else:
        prepared[4].write_text("{}")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: invalid archive input cannot dispatch isolation setup")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="managed"):
        _runner(prepared, offline_forks=selected, managed_backend=None)


class _UnitLease:
    """Lifecycle double only; never used to build or publish runtime evidence."""

    endpoint = "http://127.0.0.1:18545"

    def __init__(self, failure=None):
        self.failure = failure
        self.stops = []
        self.stopped_cleanly = False

    def stop(self, deadline):
        self.stops.append(deadline)
        if self.failure is not None:
            raise self.failure
        self.stopped_cleanly = True


def _state_control(prepared, monkeypatch, *, selected=True, lease=None):
    runner = _runner(prepared, offline_forks=_prepare(prepared) if selected else None)
    # Deliberately bypass isolation only inside this private orchestration unit test.
    # It must not execute scanners, create reports or claim an actual matrix result.
    monkeypatch.setattr(runner, "_verify_managed_execution", lambda backend: None)
    starts = []
    if lease is not None:

        def start(self, state, **kwargs):
            assert self is runner.offline_forks and state == _state(prepared)
            starts.append(kwargs)
            return lease

        monkeypatch.setattr(ManagedForkArchives, "start", start)

    def unavailable(*args, **kwargs):
        raise ForkRpcUnavailableError("synthetic missing observation")

    runner.dependencies = replace(runner.dependencies, observer=unavailable)
    custody = SimpleNamespace(path=prepared[2], device=1, inode=1, assert_stable=lambda: None)
    monkeypatch.setattr(
        runner, "_fresh_attempt_dir", lambda *a, **kw: (custody, "a" * 64, "b" * 64)
    )
    kwargs = dict(
        root=prepared[0],
        private_root=prepared[2],
        matrix_custody=custody,
        matrix_nonce_sha256="c" * 64,
        projects=(),
        repository_sha256="d" * 64,
        repository_exclusion_root=prepared[2],
        backend=runner.backend,
        absolute_deadline=time.monotonic() + 100,
        clock=fork_matrix._MonotonicClock(time.monotonic),
        expected_forge_version=None,
        expected_forge_sha256=None,
        limitations=[],
    )
    return runner, kwargs, starts


def test_managed_missing_archive_never_reads_ambient_rpc(prepared, monkeypatch):
    runner, kwargs, _ = _state_control(prepared, monkeypatch, selected=False)

    class ForbiddenEnvironment(dict):
        def get(self, *args, **kwargs):
            pytest.fail("invariant: managed missing archives cannot select an ambient endpoint")

    with monkeypatch.context() as patch:
        patch.setattr(fork_matrix.os, "environ", ForbiddenEnvironment())
        raw = runner._execute_state_inner(
            _state(prepared), **kwargs, lifecycle=fork_matrix._StateLifecycle()
        )
    assert raw.observation_status is RepositoryExecutionStateObservationStatus.UNAVAILABLE
    assert "no prepared offline archive" in raw.observation_detail
    assert raw.clean_attestation is None
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("failure", [None, ValueError("synthetic stop failure")])
def test_normal_state_path_stops_owned_lease_once_without_clean_attestation(
    prepared, monkeypatch, failure
):
    lease = _UnitLease(failure)
    runner, kwargs, starts = _state_control(prepared, monkeypatch, lease=lease)
    lifecycle = fork_matrix._StateLifecycle()
    raw = runner._execute_state_inner(_state(prepared), **kwargs, lifecycle=lifecycle)
    assert starts == [
        dict(
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=kwargs["absolute_deadline"],
        )
    ]
    assert lease.stops == [kwargs["absolute_deadline"]]
    assert lifecycle.offline_lease is lease and lifecycle.offline_stop_attempted is True
    assert raw.clean_attestation is None
    expected = RepositoryExecutionStateObservationStatus
    assert raw.observation_status is (expected.FAILED if failure else expected.UNAVAILABLE)
    if failure:
        assert "did not close" in raw.observation_detail


@pytest.mark.parametrize(
    "failure", [RuntimeError("synthetic interruption"), KeyboardInterrupt(), SystemExit()]
)
def test_exception_after_acquisition_still_stops_the_owned_lease(prepared, monkeypatch, failure):
    lease = _UnitLease()
    runner, kwargs, starts = _state_control(prepared, monkeypatch, lease=lease)

    def interrupted(*args, **kwargs):
        raise failure

    monkeypatch.setattr(runner, "_fresh_attempt_dir", interrupted)
    with pytest.raises(type(failure)) as raised:
        runner._execute_state(_state(prepared), **kwargs)
    assert raised.value is failure
    assert len(starts) == 1
    assert lease.stops == [kwargs["absolute_deadline"]] and lease.stopped_cleanly


def test_failed_offline_stop_cannot_skip_other_owned_cleanup():
    failure = RuntimeError("synthetic stop failure")
    offline, clean = _UnitLease(failure), _UnitLease()
    lifecycle = fork_matrix._StateLifecycle(offline_lease=offline, clean_lease=clean)
    assert (
        fork_matrix.RepositoryForkMatrixRunner._cleanup_state_lifecycle(
            lifecycle, absolute_deadline=100
        )
        is failure
    )
    assert offline.stops == clean.stops == [100]
    assert lifecycle.aggregate_disposal is None
