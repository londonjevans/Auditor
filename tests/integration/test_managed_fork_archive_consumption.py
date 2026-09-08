"""Owned synthetic archive transport and truthful managed setup/pipeline consumption."""

from __future__ import annotations

import json
import socket
import time
from contextlib import suppress

import httpx
import pytest

from mmaudit.models.schemas import RepositoryDifferentialRunStatus
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchiveError, ManagedForkArchives
from mmaudit.orchestration.managed_provisioning import ManagedProvisioningObservationStatus
from mmaudit.orchestration.manifest import load_run_evidence_manifest, validate_manifest_artifacts
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.repository import discovery
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_rpc import observe_pinned_fork_rpc
from mmaudit.scanners.offline_fork_service import OfflineForkRpcLease, OfflineForkRpcLeaseError
from tests.integration.test_offline_fork_service_consumption import (
    owned_loopback_only,  # noqa: F401
)
from tests.managed_offline_fork_support import prepared_archives
from tests.unit.test_managed_fork_archives import _prepare, _state
from tests.unit.test_managed_fork_matrix import _Backend
from tests.unit.test_managed_offline_fork_consumers import _setup
from tests.unit.test_offline_fork_rpc import ADDRESS, BLOCK_HASH, _request


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_archives(tmp_path, config_factory)


@pytest.mark.parametrize("repeat", [False, True])
def test_prepared_handle_creates_fresh_owned_reads_and_closes_every_lease(prepared, repeat):
    selected = _prepare(prepared)
    previous = None
    for _ in range(2 if repeat else 1):
        lease = selected.start(
            _state(prepared),
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + 100,
        )
        assert type(lease) is OfflineForkRpcLease and lease is not previous
        try:
            observed = observe_pinned_fork_rpc(
                lease.endpoint, expected_chain_id=31337, pinned_block_number=7, timeout_seconds=2
            )
            assert observed.block_hash == BLOCK_HASH
            with httpx.Client(trust_env=False, timeout=2) as client:
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
    assert selected.runtime_authority is selected.complete_state is False


def test_archive_drift_after_actual_start_refuses_verified_close_and_future_leases(prepared):
    selected = _prepare(prepared)
    lease = selected.start(
        _state(prepared),
        repository=prepared[0],
        output=prepared[2],
        absolute_deadline=time.monotonic() + 100,
    )
    try:
        prepared[4].write_text("{}")
        with pytest.raises(OfflineForkRpcLeaseError):
            lease.stop(time.monotonic() + 2)
        assert lease.stopped_cleanly is False
        with pytest.raises(ManagedForkArchiveError):
            selected.start(
                _state(prepared),
                repository=prepared[0],
                output=prepared[2],
                absolute_deadline=time.monotonic() + 100,
            )
    finally:
        with suppress(OfflineForkRpcLeaseError):
            lease.stop()
    assert lease._worker is None or not lease._worker.is_alive()
    assert lease._listener is lease._active is None


@pytest.mark.asyncio
@pytest.mark.parametrize("repeat", [False, True])
async def test_real_setup_handoff_preserves_receipt_and_pipeline_refusals(
    prepared, tmp_path, monkeypatch, repeat
):
    original_source = scanner_workspace_sha256(prepared[0])

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: prepared inputs cannot bypass the missing isolation or baseline")

    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(discovery, "_git_commit", lambda root: None)
        setup = _setup(prepared, tmp_path)
        assert type(setup.offline_forks) is ManagedForkArchives
        assert setup.offline_forks.config == setup.config
        assert setup.receipt.state.managed_run_ready is False
        assert setup.receipt.state.installed_members_verified is False
        assert setup.receipt.state.observations.fork_rpcs
        assert all(
            item.status is ManagedProvisioningObservationStatus.REFUSED
            for item in setup.receipt.state.observations.fork_rpcs
        )
        if repeat:
            repeated = _setup(prepared, tmp_path, verify_only=True)
            assert repeated.receipt == setup.receipt
            assert repeated.offline_forks is not setup.offline_forks
            setup = repeated
        audit = AuditPipeline(
            setup.config,
            repo=prepared[0],
            output=prepared[2],
            host_tools=setup.host_tools,
            offline_forks=setup.offline_forks,
            managed_backend=_Backend(),
        )
        for _ in range(2 if repeat else 1):
            result = await audit.run(scanner_only=True)
            matrix = result.report.repository_suite_differential
            assert matrix.status is RepositoryDifferentialRunStatus.FAILED
            assert matrix.matrix is None and any("isolation" in item for item in matrix.limitations)
            assert result.report.completed is False and result.report.usage == []
            published = json.loads((result.run_dir / "final-findings.json").read_text())
            assert published["completed"] is False
            validate_manifest_artifacts(
                load_run_evidence_manifest(result.run_dir / "run-evidence-manifest.json"),
                result.run_dir,
            )
            assert not (result.run_dir / "private/repository-fork-matrix").exists()
    assert scanner_workspace_sha256(prepared[0]) == original_source
    assert audit.client is None and audit.api_key == "" and audit._run_log_handler is None
