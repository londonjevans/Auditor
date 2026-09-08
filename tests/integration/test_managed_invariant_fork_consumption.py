"""Actual owned invariant reads; fixed controls never execute Solidity or qualify an audit."""

from __future__ import annotations

import json
import socket
import time
from contextlib import suppress

import httpx
import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, InvariantExecutionStatus
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveError, ManagedForkArchives
from mmaudit.orchestration.managed_host_tools import ManagedHostToolSource
from mmaudit.orchestration.managed_provisioning import ManagedProvisioningObservationStatus
from mmaudit.orchestration.managed_provisioning_runtime import provision_managed_local_run
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.repository import discovery
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.offline_fork_service import OfflineForkRpcLeaseError
from mmaudit.solidity import invariant_execution as invariant
from tests.integration.test_offline_fork_service_consumption import (
    owned_loopback_only,  # noqa: F401
)
from tests.managed_invariant_fork_support import (
    prepare_invariant_archives,
    prepared_invariant_archives,
)
from tests.unit.test_managed_invariant_forks import (
    ControlBackend,
    run_prepared,
    runner_for,
    stub_preflight,
)
from tests.unit.test_offline_fork_rpc import ADDRESS, BLOCK_HASH, _request


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_invariant_archives(tmp_path, config_factory)


@pytest.mark.parametrize("repetitions", [2, 10])
def test_invariant_attempts_read_exact_state_through_independent_full_lifetimes(
    prepared, repetitions
):
    config = prepared[1].config
    config.reproduction.repetitions = repetitions
    selected = prepare_invariant_archives(prepared, config=config)
    previous = None
    original = prepared[4].read_bytes()
    for _ in range(repetitions):
        lease = selected.start_invariant_attempt(
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + selected.invariant_attempt_lifetime_seconds,
        )
        assert lease is not previous
        try:
            observed = observe_pinned_fork_rpc(
                lease.endpoint, expected_chain_id=31337, pinned_block_number=7, timeout_seconds=1
            )
            assert observed.block_hash == BLOCK_HASH and observed == lease.observation
            with httpx.Client(trust_env=False, timeout=1) as client:
                response = client.post(
                    lease.endpoint,
                    content=_request("eth_getBalance", [ADDRESS, "0x7"]),
                    headers={"Content-Type": "application/json"},
                )
            assert response.json()["result"] == "0x5"
        finally:
            lease.stop(time.monotonic() + 2)
        assert lease.stopped_cleanly
        assert lease._worker is None or not lease._worker.is_alive()
        assert lease._listener is lease._active is None
        previous = lease
    selected.verify(config)
    assert prepared[4].read_bytes() == original
    assert selected.runtime_authority is selected.complete_state is False


@pytest.mark.parametrize(
    "outcome", ["return", "exception", "interrupt", "exit", "source", "missing_read"]
)
def test_real_consumer_reads_close_before_evidence_on_every_exit(prepared, monkeypatch, outcome):
    selected = prepare_invariant_archives(prepared)
    runner = runner_for(prepared, offline_forks=selected)
    original_start = ManagedForkArchives.start_invariant_attempt
    original_source = scanner_workspace_sha256(prepared[0])
    leases, observations, endpoints = [], [], []
    recorded_attempts = []
    original_evidence = invariant.InvariantExecutionAttemptEvidence
    sentinel = {"interrupt": KeyboardInterrupt(), "exit": SystemExit(2)}.get(
        outcome, RuntimeError("synthetic post-read failure")
    )

    def start(self, **kwargs):
        assert self is selected
        lease = original_start(self, **kwargs)
        leases.append(lease)
        endpoints.append(lease.endpoint)
        return lease

    def consume(command, *, private_dir, **kwargs):
        endpoint = command[command.index("--fork-url") + 1]
        assert endpoint == leases[-1].endpoint
        assert command[command.index("--fork-block-number") + 1] == "7"
        assert "--offline" in command and "--no-auto-detect" in command
        selected.verify_invariant_execution_budget(kwargs["absolute_deadline"])
        observed = observe_pinned_fork_rpc(
            endpoint, expected_chain_id=31337, pinned_block_number=7, timeout_seconds=1
        )
        assert observed.block_hash == BLOCK_HASH
        observations.append(observed)
        if outcome in {"exception", "interrupt", "exit"}:
            raise sentinel
        if outcome == "source":
            prepared[4].write_text("{}")
        if outcome == "missing_read":
            with httpx.Client(trust_env=False, timeout=1) as client:
                response = client.post(
                    endpoint,
                    content=_request("eth_getCode", [ADDRESS, "0x7"]),
                    headers={"Content-Type": "application/json"},
                )
            assert response.status_code == 503 and "result" not in response.json()
            raise ManagedForkArchiveError("synthetic required state read unavailable")
        stdout, stderr = private_dir / "control.stdout", private_dir / "control.stderr"
        stdout.write_text("Transport observation only; no invariant was executed.\n")
        stderr.write_text("")
        return invariant._InvariantExecution(InvariantExecutionStatus.PASSED, stdout, stderr, [])

    def record_attempt(**kwargs):
        lease = leases[-1]
        assert lease.stopped_cleanly and lease._listener is lease._active is None
        assert lease._worker is None or not lease._worker.is_alive()
        recorded_attempts.append(kwargs["attempt"])
        return original_evidence(**kwargs)

    monkeypatch.setattr(invariant, "InvariantExecutionAttemptEvidence", record_attempt)
    monkeypatch.setattr(ManagedForkArchives, "start_invariant_attempt", start)
    stub_preflight(monkeypatch, prepared)
    monkeypatch.setattr(runner, "_execute", consume)
    try:
        if outcome == "return":
            for index in range(2):
                current = (*prepared[:2], prepared[2] / f"run-{index}", *prepared[3:])
                result = run_prepared(runner, current)
                assert result.status is InvariantExecutionStatus.PASSED, result.limitations
                assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
                assert result.attempts == 2 and result.replay_confirmed
                assert all(not item.machine_output_validated for item in result.attempt_evidence)
                assert all(endpoint not in result.model_dump_json() for endpoint in endpoints)
            assert len(leases) == 4
            assert recorded_attempts == [1, 2, 1, 2]
            # Reusing an occupied private workspace must refuse, not reuse old evidence.
            refused = run_prepared(runner, current)
            assert refused.status is InvariantExecutionStatus.GENERATION_FAILED
            assert any("FileExistsError" in item for item in refused.limitations)
            assert len(leases) == 4
        else:
            error = (
                OfflineForkRpcLeaseError
                if outcome == "source"
                else ManagedForkArchiveError
                if outcome == "missing_read"
                else type(sentinel)
            )
            with pytest.raises(error):
                run_prepared(runner, prepared)
            assert recorded_attempts == []
            assert len(leases) == 1
        assert len(leases) == len(observations) == len({id(lease) for lease in leases})
        for lease in leases:
            assert lease.stopped_cleanly is (outcome != "source")
            assert lease._worker is None or not lease._worker.is_alive()
            assert lease._listener is lease._active is None
    finally:
        for lease in leases:
            with suppress(OfflineForkRpcLeaseError):
                lease.stop()
    assert scanner_workspace_sha256(prepared[0]) == original_source
    assert selected.complete_state is selected.runtime_authority is False


@pytest.mark.asyncio
@pytest.mark.parametrize("repeat", [False, True])
async def test_setup_and_fixed_pipeline_retain_invariant_reads_without_promoting_readiness(
    prepared, tmp_path, monkeypatch, repeat
):
    output = tmp_path / "managed-setup"
    output.mkdir(mode=0o700)
    original = scanner_workspace_sha256(prepared[0])

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: preparation and unavailable pipeline cannot start RPC or engines")

    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        kwargs = dict(
            config=prepared[1].config,
            bundle=prepared[1].bundle,
            repository=prepared[0],
            output_dir=output,
            host_tool_source=ManagedHostToolSource(blob_root=tmp_path / "host-blobs"),
            offline_fork_source=prepared[3],
        )
        setup = provision_managed_local_run(**kwargs, verify_only=False)
        if repeat:
            repeated = provision_managed_local_run(**kwargs, verify_only=True)
            assert repeated.receipt == setup.receipt
            assert repeated.offline_forks is not setup.offline_forks
            setup = repeated
        assert setup.offline_forks.invariant_source_binding is not None
        assert setup.receipt.state.managed_run_ready is False
        assert setup.receipt.state.installed_members_verified is False
        assert setup.receipt.state.observations.fork_rpcs
        assert all(
            item.status is ManagedProvisioningObservationStatus.REFUSED
            for item in setup.receipt.state.observations.fork_rpcs
        )
        audit = AuditPipeline(
            setup.config,
            repo=prepared[0],
            output=prepared[2],
            host_tools=setup.host_tools,
            offline_forks=setup.offline_forks,
            managed_backend=ControlBackend(),
        )
        assert audit.invariant_runner.offline_forks is setup.offline_forks
        assert audit.invariant_runner.isolation_available is False
        for _ in range(2 if repeat else 1):
            result = await audit.run(scanner_only=True)
            assert result.report.completed is False and result.report.usage == []
            assert (
                json.loads((result.run_dir / "final-findings.json").read_text())["completed"]
                is False
            )
            validate_manifest_artifacts(
                load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
                result.run_dir,
            )
    assert scanner_workspace_sha256(prepared[0]) == original
    assert audit.client is None and audit.api_key == "" and audit._run_log_handler is None
