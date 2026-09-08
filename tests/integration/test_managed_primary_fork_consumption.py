"""Owned primary reads and early refusals; controls never attest isolation or an engine."""

from __future__ import annotations

import json
import socket
import time
from contextlib import suppress

import httpx
import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchives
from mmaudit.orchestration.managed_provisioning import ManagedProvisioningObservationStatus
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.repository import discovery
from mmaudit.scanners import foundry, runtime_evidence
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import ForkRpcBindingError, observe_pinned_fork_rpc
from mmaudit.scanners.offline_fork_service import OfflineForkRpcLease, OfflineForkRpcLeaseError
from tests.integration.test_offline_fork_service_consumption import (
    owned_loopback_only,  # noqa: F401
)
from tests.managed_offline_fork_support import prepared_archives
from tests.unit.test_managed_fork_archives import _prepare
from tests.unit.test_managed_fork_matrix import _Backend
from tests.unit.test_managed_offline_fork_consumers import _setup
from tests.unit.test_managed_primary_foundry import (
    add_foundry_target,
    invoke_primary,
    primary_adapter,
)
from tests.unit.test_offline_fork_rpc import ADDRESS, BLOCK_HASH, _request


@pytest.mark.parametrize("matrix", [False, True])
def test_primary_selection_creates_fresh_owned_reads_without_complete_state_credit(
    tmp_path, config_factory, matrix
):
    prepared = prepared_archives(tmp_path, config_factory, primary=True, matrix=matrix)
    selected = _prepare(prepared)
    original = prepared[4].read_bytes()
    previous = None
    for _ in range(2):
        lease = selected.start_primary(
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + selected.primary_timeout_seconds,
        )
        assert type(lease) is OfflineForkRpcLease and lease is not previous
        try:
            observed = observe_pinned_fork_rpc(
                lease.endpoint, expected_chain_id=31337, pinned_block_number=7, timeout_seconds=1
            )
            assert observed.block_hash == BLOCK_HASH
            assert observed == lease.observation
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
    selected.verify(prepared[1].config)
    assert prepared[4].read_bytes() == original
    assert selected.runtime_authority is selected.complete_state is False


@pytest.mark.parametrize("captured", [False, True])
@pytest.mark.parametrize("outcome", ["refusal", "exception", "interrupt", "exit", "drift"])
def test_actual_primary_observation_closes_on_every_exit_before_any_engine_or_authority(
    tmp_path, config_factory, monkeypatch, captured, outcome
):
    prepared = prepared_archives(tmp_path, config_factory, primary=True)
    add_foundry_target(prepared)
    selected = _prepare(prepared)
    adapter = primary_adapter(prepared, selected=selected)
    backend = _Backend()
    backend.supports_local_fork_rpc = True
    # Test-only admission controls reach the real transport. No actual isolation is attested.
    monkeypatch.setattr(
        foundry, "isolation_execution_evidence", lambda backend: ExecutionEvidenceKind.REAL
    )
    monkeypatch.setattr(foundry, "isolation_attestation_sha256", lambda backend: "a" * 64)
    original_start = ManagedForkArchives.start_primary
    original_observe = foundry.observe_pinned_fork_rpc
    leases, observations = [], []

    def tracked_start(self, **kwargs):
        assert self is selected
        lease = original_start(self, **kwargs)
        leases.append(lease)
        return lease

    sentinel = {
        "refusal": ForkRpcBindingError("synthetic stop before engine execution"),
        "drift": ForkRpcBindingError("synthetic stop before engine execution"),
        "exception": RuntimeError("synthetic post-observation failure"),
        "interrupt": KeyboardInterrupt(),
        "exit": SystemExit(2),
    }[outcome]

    def observe_then_stop(*args, **kwargs):
        observed = original_observe(*args, **kwargs)
        observations.append(observed)
        assert observed.block_hash == BLOCK_HASH
        if outcome == "drift":
            prepared[4].write_text("{}")
        raise sentinel

    monkeypatch.setattr(ManagedForkArchives, "start_primary", tracked_start)
    monkeypatch.setattr(foundry, "observe_pinned_fork_rpc", observe_then_stop)
    try:
        for _ in range(2 if outcome == "refusal" else 1):
            if outcome == "refusal":
                run = invoke_primary(adapter, prepared, captured=captured, backend=backend)
                assert run.status is ScannerStatus.FAILED
                assert run.error == str(sentinel)
                assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
                assert not runtime_evidence.has_host_repository_suite_runtime_authority(run)
            else:
                error = OfflineForkRpcLeaseError if outcome == "drift" else type(sentinel)
                with pytest.raises(error) as raised:
                    invoke_primary(adapter, prepared, captured=captured, backend=backend)
                if outcome != "drift":
                    assert raised.value is sentinel
        assert len(leases) == len(observations) == (2 if outcome == "refusal" else 1)
        assert len({id(lease) for lease in leases}) == len(leases)
        for lease in leases:
            assert lease.stopped_cleanly is (outcome != "drift")
            assert lease._worker is None or not lease._worker.is_alive()
            assert lease._listener is lease._active is None
        assert selected.runtime_authority is selected.complete_state is False
    finally:
        for lease in leases:
            with suppress(OfflineForkRpcLeaseError):
                lease.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("matrix", [False, True])
async def test_setup_primary_handoff_and_repeat_cannot_promote_missing_isolation(
    tmp_path, config_factory, monkeypatch, matrix
):
    prepared = prepared_archives(tmp_path, config_factory, primary=True, matrix=matrix)
    add_foundry_target(prepared)
    original_source = scanner_workspace_sha256(prepared[0])

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: prepared primary data cannot bypass unsupported isolation")

    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        setup = _setup(prepared, tmp_path)
        repeated = _setup(prepared, tmp_path, verify_only=True)
        assert repeated.receipt == setup.receipt
        assert repeated.offline_forks is not setup.offline_forks
        setup = repeated
        assert type(setup.offline_forks) is ManagedForkArchives
        assert setup.offline_forks.primary_source_binding is not None
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
            managed_backend=_Backend(),
        )
        for _ in range(2):
            result = await audit.run(scanner_only=True)
            assert result.report.completed is False and result.report.usage == []
            primary = [run for run in result.report.scanner_runs if run.scanner == "foundry_fork"]
            assert len(primary) == 1
            assert primary[0].status is ScannerStatus.UNAVAILABLE
            assert "loopback" in primary[0].error or "isolation" in primary[0].error
            assert not runtime_evidence.has_host_repository_suite_runtime_authority(primary[0])
            published = json.loads((result.run_dir / "final-findings.json").read_text())
            assert published["completed"] is False
            validate_manifest_artifacts(
                load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
                result.run_dir,
            )
    assert scanner_workspace_sha256(prepared[0]) == original_source
    assert audit.client is None and audit.api_key == "" and audit._run_log_handler is None
