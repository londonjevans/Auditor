"""Owned invariant input and cleanup controls provide no engine or isolation authority."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    InvariantExecutionStatus,
    SolidityProjectType,
)
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveError, ManagedForkArchives
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.solidity import invariant_execution as invariant
from tests.managed_invariant_fork_support import (
    prepare_invariant_archives,
    prepared_invariant_archives,
)
from tests.managed_reproduction_support import SYNTHETIC_RPC


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: invariant lifecycle controls cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(invariant, "_external_executable", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_invariant_archives(tmp_path, config_factory)


class ControlBackend:
    name = "unverified-invariant-archive-control"
    supports_local_fork_rpc = True

    def wrap(self, command, **kwargs):
        return command


def runner_for(prepared, **kwargs):
    return invariant.FoundryInvariantRunner(
        prepared[1].config.reproduction,
        prepared[1].config.smart_contracts,
        host_tools=kwargs.pop("host_tools", prepared[1]),
        backend=kwargs.pop("backend", ControlBackend()),
        offline_forks=(
            kwargs.pop("offline_forks")
            if "offline_forks" in kwargs
            else prepare_invariant_archives(prepared)
        ),
        **kwargs,
    )


def run_prepared(runner, prepared):
    return runner.run(
        repository_root=prepared[0],
        private_dir=prepared[2],
        project=prepared[5],
        specification=prepared[6],
    )


def stub_preflight(monkeypatch, prepared):
    """Run real retained-tool checks with fixed version-probe responses; never execute."""

    material = prepared[1]
    members = {material.directory / item.locator: item for item in material.manifest.files}
    calls = []

    def probe(path, **kwargs):
        assert path in members
        assert kwargs["expected_host_observation"].sha256 == members[path].sha256
        calls.append(path)
        return members[path].version

    monkeypatch.setattr(invariant, "_external_executable_version", probe)
    return calls


def test_fixed_pipeline_shares_exact_archives_with_invariants(prepared):
    selected = prepare_invariant_archives(prepared)
    pipeline = AuditPipeline(
        prepared[1].config,
        repo=prepared[0],
        output=prepared[2],
        host_tools=prepared[1],
        offline_forks=selected,
        managed_backend=ControlBackend(),
    )
    assert pipeline.invariant_runner.offline_forks is selected
    assert pipeline.scanner_runner.offline_forks is selected
    assert pipeline.repository_fork_matrix_runner.offline_forks is selected
    pipeline._verify_managed_tools()
    pipeline.invariant_runner.offline_forks = None
    with pytest.raises(ValueError, match="managed"):
        pipeline._verify_managed_tools()


@pytest.mark.parametrize("mutation", ["removed", "replaced", "managed_removed", "source", "config"])
def test_changed_invariant_selection_refuses_before_any_output(prepared, mutation):
    runner = runner_for(prepared)
    if mutation == "removed":
        runner.offline_forks = None
    elif mutation == "replaced":
        runner.offline_forks = prepare_invariant_archives(prepared)
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
    selected = prepare_invariant_archives(prepared)
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
    monkeypatch.setattr(invariant, "default_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="managed"):
        runner_for(prepared, **kwargs)


@pytest.mark.parametrize("boundary", ["missing", "isolation", "project"])
def test_ineligible_invariants_cannot_read_ambient_rpc_or_start_a_lease(
    prepared, monkeypatch, boundary
):
    runner = (
        runner_for(prepared, offline_forks=None) if boundary == "missing" else runner_for(prepared)
    )
    if boundary == "isolation":
        runner.backend.supports_local_fork_rpc = False
    if boundary == "project":
        prepared[5].project_type = SolidityProjectType.HARDHAT
    original_get = invariant.os.environ.get

    def guarded_get(key, default=None):
        assert key != runner.smart_contracts.fork_rpc_url_env
        return original_get(key, default)

    monkeypatch.setattr(invariant.os.environ, "get", guarded_get)
    result = run_prepared(runner, prepared)
    assert result.status is (
        InvariantExecutionStatus.GENERATION_FAILED
        if boundary == "project"
        else InvariantExecutionStatus.ENVIRONMENT_BLOCKED
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
    recorded_attempts = []
    original_evidence = invariant.InvariantExecutionAttemptEvidence
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
        self.verify_invariant_execution_budget(kwargs["absolute_deadline"])
        lease = Lease()
        leases.append(lease)
        return lease

    def execute(command, *, private_dir, **kwargs):
        assert command[command.index("--fork-url") + 1] == SYNTHETIC_RPC
        assert kwargs["absolute_deadline"] > time.monotonic()
        assert command[command.index("--fork-block-number") + 1] == "7"
        assert "--no-auto-detect" in command and "--offline" in command
        assert command[command.index("--use") + 1] == str(runner.solc_executable)
        if outcome in {"exception", "interrupt", "exit"}:
            raise sentinel
        if outcome == "source":
            prepared[4].write_text("{}")
        stdout, stderr = private_dir / "control.stdout", private_dir / "control.stderr"
        stdout.write_text("Synthetic non-executing control.\n")
        stderr.write_text("")
        return invariant._InvariantExecution(InvariantExecutionStatus.PASSED, stdout, stderr, [])

    def record_attempt(**kwargs):
        assert leases[-1].stopped_cleanly and len(leases[-1].stops) == 1
        recorded_attempts.append(kwargs["attempt"])
        return original_evidence(**kwargs)

    monkeypatch.setattr(invariant, "InvariantExecutionAttemptEvidence", record_attempt)
    monkeypatch.setattr(ManagedForkArchives, "start_invariant_attempt", start)
    stub_preflight(monkeypatch, prepared)
    monkeypatch.setattr(runner, "_execute", execute)
    if outcome == "return":
        result = run_prepared(runner, prepared)
        assert result.status is InvariantExecutionStatus.PASSED
        assert result.attempts == 2 and result.replay_confirmed
        assert all(not item.machine_output_validated for item in result.attempt_evidence)
        assert recorded_attempts == [1, 2]
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
        assert recorded_attempts == []
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

    monkeypatch.setattr(ManagedForkArchives, "verify_invariant_execution_budget", budget)
    monkeypatch.setattr(subprocess, "Popen", start)
    monkeypatch.setattr(invariant, "_stop_process", lambda child: stops.append(child))
    with pytest.raises(ManagedForkArchiveError if phase in {"before", "after"} else type(sentinel)):
        runner._execute(
            [str(runner.forge_executable)],
            workspace=workspace,
            private_dir=prepared[2],
            rpc_port=18547,
            runs=2,
            depth=1,
            seed=7,
            action_functions={},
            property_ids=set(),
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
    monkeypatch.setattr(invariant, "_stop_process", failed_stop)
    with pytest.raises(type(original)) as raised:
        runner._execute(
            [str(runner.forge_executable)],
            workspace=workspace,
            private_dir=prepared[2],
            rpc_port=18547,
            runs=2,
            depth=1,
            seed=7,
            action_functions={},
            property_ids=set(),
            absolute_deadline=time.monotonic() + 33,
        )
    assert raised.value is original and stops == [process]


@pytest.mark.parametrize("with_archive", [False, True])
def test_source_local_harness_never_starts_fork_reads_even_with_prepared_archives(
    prepared, monkeypatch, with_archive
):
    runner = runner_for(
        prepared, offline_forks=prepare_invariant_archives(prepared) if with_archive else None
    )
    calls = stub_preflight(monkeypatch, prepared)
    commands = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: source-local harness cannot select or start fork reads")

    def execute(command, *, private_dir, **kwargs):
        assert "--fork-url" not in command and "--fork-block-number" not in command
        assert "absolute_deadline" not in kwargs and kwargs["rpc_port"] == 0
        assert command[command.index("--use") + 1] == str(runner.solc_executable)
        commands.append(command)
        stdout, stderr = private_dir / "control.stdout", private_dir / "control.stderr"
        stdout.write_text("Non-executing source-local control.\n")
        stderr.write_text("")
        return invariant._InvariantExecution(InvariantExecutionStatus.PASSED, stdout, stderr, [])

    monkeypatch.setattr(ManagedForkArchives, "start_invariant_attempt", forbidden)
    monkeypatch.setattr(invariant, "_local_rpc", forbidden)
    monkeypatch.setattr(runner, "_execute", execute)
    local = (*prepared[:6], prepared[7], prepared[7])
    result = run_prepared(runner, local)
    assert len(calls) == 2 and len(commands) == 2 and result.replay_confirmed
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert all(not attempt.machine_output_validated for attempt in result.attempt_evidence)


@pytest.mark.parametrize("role", ["forge", "solc"])
def test_managed_fork_tool_version_mismatch_refuses_before_any_lease(prepared, monkeypatch, role):
    runner = runner_for(prepared)
    calls = []

    def probe(path, **kwargs):
        calls.append(path)
        return "unmatched-version" if path.name == role else "1.2.3"

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: failed tool admission cannot start archive reads")

    monkeypatch.setattr(invariant, "_external_executable_version", probe)
    monkeypatch.setattr(ManagedForkArchives, "start_invariant_attempt", forbidden)
    result = run_prepared(runner, prepared)
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert result.attempts == 0 and len(calls) == (1 if role == "forge" else 2)
    assert not prepared[2].exists()
