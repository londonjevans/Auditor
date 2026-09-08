"""Owned reproduction input and cleanup controls provide no engine or isolation authority."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ReproductionState
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveError, ManagedForkArchives
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.solidity import reproduction
from tests.managed_reproduction_fork_support import (
    prepare_reproduction_archives,
    prepared_reproduction_archives,
)
from tests.managed_reproduction_support import SYNTHETIC_RPC


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: reproduction lifecycle controls cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(reproduction, "_external_executable", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory, candidate_factory):
    return prepared_reproduction_archives(tmp_path, config_factory, candidate_factory)


class ControlBackend:
    name = "unverified-reproduction-archive-control"
    supports_local_fork_rpc = True

    def wrap(self, command, **kwargs):
        return command


def runner_for(prepared, **kwargs):
    return reproduction.ForkReproductionRunner(
        prepared[1].config.reproduction,
        prepared[1].config.smart_contracts,
        host_tools=kwargs.pop("host_tools", prepared[1]),
        backend=kwargs.pop("backend", ControlBackend()),
        offline_forks=(
            kwargs.pop("offline_forks")
            if "offline_forks" in kwargs
            else prepare_reproduction_archives(prepared)
        ),
        **kwargs,
    )


def run_prepared(runner, prepared):
    return runner.run(
        repository_root=prepared[0],
        private_dir=prepared[2],
        project=prepared[5],
        specification=prepared[6],
        candidate=prepared[7],
    )


def test_fixed_pipeline_shares_exact_archives_with_reproduction(prepared):
    selected = prepare_reproduction_archives(prepared)
    pipeline = AuditPipeline(
        prepared[1].config,
        repo=prepared[0],
        output=prepared[2],
        host_tools=prepared[1],
        offline_forks=selected,
        managed_backend=ControlBackend(),
    )
    assert pipeline.reproduction_runner.offline_forks is selected
    assert pipeline.scanner_runner.offline_forks is selected
    assert pipeline.repository_fork_matrix_runner.offline_forks is selected
    pipeline._verify_managed_tools()
    pipeline.reproduction_runner.offline_forks = None
    with pytest.raises(ValueError, match="managed"):
        pipeline._verify_managed_tools()


@pytest.mark.parametrize("mutation", ["removed", "replaced", "managed_removed", "source", "config"])
def test_changed_reproduction_selection_refuses_before_any_output(prepared, mutation):
    runner = runner_for(prepared)
    if mutation == "removed":
        runner.offline_forks = None
    elif mutation == "replaced":
        runner.offline_forks = prepare_reproduction_archives(prepared)
    elif mutation == "managed_removed":
        runner._managed = None
    elif mutation == "source":
        prepared[4].write_text("{}")
    else:
        runner.reproduction.timeout_seconds += 1
    with pytest.raises(ValueError, match="managed"):
        run_prepared(runner, prepared)
    assert not prepared[2].exists()


@pytest.mark.parametrize("mutation", ["wrong_type", "missing_tools", "changed_source"])
def test_invalid_archive_selection_refuses_before_backend_dispatch(prepared, monkeypatch, mutation):
    selected = prepare_reproduction_archives(prepared)
    kwargs = {"offline_forks": selected, "backend": None}
    if mutation == "wrong_type":
        kwargs["offline_forks"] = object()
    elif mutation == "missing_tools":
        kwargs["host_tools"] = None
    else:
        prepared[4].write_text("{}")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: invalid archive cannot select ambient or managed isolation")

    from mmaudit.isolation import managed

    monkeypatch.setattr(managed, "managed_isolation_backend", forbidden)
    monkeypatch.setattr(reproduction, "default_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="managed"):
        runner_for(prepared, **kwargs)


@pytest.mark.parametrize("boundary", ["missing", "isolation", "specification"])
def test_ineligible_reproduction_cannot_read_ambient_rpc_or_start_a_lease(
    prepared, monkeypatch, boundary
):
    runner = (
        runner_for(prepared, offline_forks=None) if boundary == "missing" else runner_for(prepared)
    )
    if boundary == "isolation":
        runner.backend.supports_local_fork_rpc = False
    if boundary == "specification":
        prepared[6].required_block_number = 8
    original_get = reproduction.os.environ.get

    def guarded_get(key, default=None):
        assert key != runner.smart_contracts.fork_rpc_url_env
        return original_get(key, default)

    monkeypatch.setattr(reproduction.os.environ, "get", guarded_get)
    result = run_prepared(runner, prepared)
    assert result.state is (
        ReproductionState.GENERATION_FAILED
        if boundary == "specification"
        else ReproductionState.ENVIRONMENT_BLOCKED
    )
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert result.attempts == 0 and not prepared[2].exists()


@pytest.mark.parametrize(
    "outcome", ["return", "exception", "interrupt", "exit", "stop_failure", "source"]
)
def test_each_replay_closes_its_owned_lease_before_evidence_or_return(
    prepared, monkeypatch, outcome
):
    runner = runner_for(prepared)
    leases = []
    sentinel = {"interrupt": KeyboardInterrupt(), "exit": SystemExit(2)}.get(
        outcome, RuntimeError("synthetic execution failure")
    )

    class Lease:
        endpoint = SYNTHETIC_RPC
        stopped_cleanly = False

        def __init__(self):
            self.stops = []

        def stop(self, deadline=None):
            self.stops.append(deadline)
            if outcome == "stop_failure":
                raise ValueError("synthetic shutdown failure")
            self.stopped_cleanly = True

    def start(self, **kwargs):
        self.verify_reproduction_execution_budget(kwargs["absolute_deadline"])
        lease = Lease()
        leases.append(lease)
        return lease

    def execute(command, *, private_dir, **kwargs):
        assert command[command.index("--fork-url") + 1] == SYNTHETIC_RPC
        assert kwargs["absolute_deadline"] > time.monotonic()
        if outcome in {"exception", "interrupt", "exit"}:
            raise sentinel
        if outcome == "source":
            prepared[4].write_text("{}")
        stdout, stderr = private_dir / "control.stdout", private_dir / "control.stderr"
        stdout.write_text("Synthetic non-executing control.\n")
        stderr.write_text("")
        return reproduction._Execution(ReproductionState.NOT_REPRODUCED, stdout, stderr, [])

    monkeypatch.setattr(ManagedForkArchives, "start_reproduction_attempt", start)
    monkeypatch.setattr(runner, "_preflight_managed_tools", lambda private: None)
    monkeypatch.setattr(runner, "_execute", execute)
    if outcome == "return":
        result = run_prepared(runner, prepared)
        assert result.state is ReproductionState.NOT_REPRODUCED
        assert result.attempts == 2 and result.successful_attempts == 0
        assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        assert SYNTHETIC_RPC not in result.command
    else:
        error = (
            ManagedForkArchiveError
            if outcome == "source"
            else ValueError
            if outcome == "stop_failure"
            else type(sentinel)
        )
        with pytest.raises(error):
            run_prepared(runner, prepared)
        assert not (prepared[2] / "regression-tests").exists()
    assert len(leases) == (2 if outcome == "return" else 1)
    assert len({id(lease) for lease in leases}) == len(leases)
    assert all(len(lease.stops) == 1 for lease in leases)
    assert all(lease.stopped_cleanly is (outcome != "stop_failure") for lease in leases)


@pytest.mark.parametrize("phase", ["before", "after", "interrupt", "exception"])
def test_child_budget_and_unexpected_exits_cannot_leave_a_started_process(
    prepared, monkeypatch, phase
):
    runner = runner_for(prepared)
    workspace = prepared[2] / "workspace"
    workspace.mkdir(parents=True)
    checks, starts, stops = [], [], []
    sentinel = (
        KeyboardInterrupt() if phase == "interrupt" else RuntimeError("synthetic child error")
    )

    def budget(self, deadline):
        checks.append(deadline)
        if phase == "before" or (phase == "after" and len(checks) == 2):
            raise ManagedForkArchiveError("synthetic exhausted startup budget")

    class Process:
        def poll(self):
            raise sentinel

    process = Process()

    def start(*args, **kwargs):
        starts.append(process)
        return process

    monkeypatch.setattr(ManagedForkArchives, "verify_reproduction_execution_budget", budget)
    monkeypatch.setattr(subprocess, "Popen", start)
    monkeypatch.setattr(reproduction, "_stop_process", lambda child: stops.append(child))
    with pytest.raises(ManagedForkArchiveError if phase in {"before", "after"} else type(sentinel)):
        runner._execute(
            [str(runner.forge_executable)],
            workspace=workspace,
            private_dir=prepared[2],
            rpc_port=18547,
            attempt=1,
            absolute_deadline=time.monotonic() + 33,
        )
    assert starts == stops == ([] if phase == "before" else [process])
    assert runner.reproduction.timeout_seconds == 1


@pytest.mark.parametrize("interrupt", [False, True])
def test_process_cleanup_failure_cannot_replace_the_original_execution_exception(
    prepared, monkeypatch, interrupt
):
    runner = runner_for(prepared)
    workspace = prepared[2] / "workspace"
    workspace.mkdir(parents=True)
    original = KeyboardInterrupt() if interrupt else RuntimeError("synthetic original failure")
    stops = []

    class Process:
        def poll(self):
            raise original

    process = Process()

    def failed_stop(child):
        stops.append(child)
        raise ValueError("synthetic child shutdown failure")

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(reproduction, "_stop_process", failed_stop)
    with pytest.raises(type(original)) as raised:
        runner._execute(
            [str(runner.forge_executable)],
            workspace=workspace,
            private_dir=prepared[2],
            rpc_port=18547,
            attempt=1,
            absolute_deadline=time.monotonic() + 33,
        )
    assert raised.value is original and stops == [process]
