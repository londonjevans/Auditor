from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import quote

import pytest

from mmaudit.config import (
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkSuiteConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.models.schemas import (
    REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
    EvidenceStrength,
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    ForkRpcReadOnlyEgressEvidence,
    FoundryTestExecutionSummary,
    Location,
    RepositoryCleanExecPathBindingKind,
    RepositoryCleanListenerOwnershipKind,
    RepositoryCleanRuntimeExecutableIdentityKind,
    RepositoryCleanStateAttestationEvidence,
    RepositoryCodeExecutionState,
    RepositoryDifferentialClassification,
    RepositoryDifferentialRunStatus,
    RepositoryExecutionStateKind,
    RepositoryExecutionStateObservationStatus,
    RepositoryStateConsensusStatus,
    RepositoryStateInconclusiveReason,
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositorySuiteWorkspaceCopyEvidence,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestForkRpcScopeEvidence,
    RepositoryTestForkRpcScopeStatus,
    RepositoryTestKind,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityProjectMetadata,
)
from mmaudit.scanners import fork_matrix as fork_matrix_module
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.fork_matrix import (
    CleanStateLease,
    ForkMatrixDependencies,
    ForkMatrixScanner,
    RepositoryForkMatrixRunner,
    _baseline_limitation,
    fork_rpc_egress_from_snapshot,
)
from mmaudit.scanners.fork_rpc import ForkRpcUnavailableError, PinnedForkObservation
from mmaudit.scanners.read_only_rpc import (
    ReadOnlyRpcBridgeSnapshot,
    ReadOnlyRpcTestScopeSnapshot,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
BLOCK_HASH = "0x" + HASH_A
PINNED_BLOCK_HASH = "0x" + HASH_B
SEED = "0x" + ("0" * 63) + "1"
BASE_TIME = datetime(2026, 7, 29, 12, tzinfo=UTC)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _state(
    *,
    observed: bool = True,
    chain_id: int = 31_337,
) -> RepositorySuiteExecutionStateEvidence:
    return RepositorySuiteExecutionStateEvidence.sealed(
        state_id="pinned-local",
        kind=RepositoryExecutionStateKind.PINNED_FORK,
        rpc_url_env="MMAUDIT_PINNED_LOCAL_RPC_URL",
        state_source_sha256=HASH_B,
        expected_chain_id=chain_id,
        pinned_block_number=42,
        observation_status=(
            RepositoryExecutionStateObservationStatus.OBSERVED
            if observed
            else RepositoryExecutionStateObservationStatus.UNAVAILABLE
        ),
        observed_chain_id=chain_id if observed else None,
        observed_block_number=42 if observed else None,
        observed_block_hash=BLOCK_HASH if observed else None,
        observation_detail=None if observed else "Configured local state was unavailable.",
    )


def _snapshot(
    *,
    selected_test_scope_snapshot_sha256s: tuple[str, ...] = (),
) -> ReadOnlyRpcBridgeSnapshot:
    observation_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
        expected_chain_id=31_337,
        pinned_block_number=42,
        pinned_block_hash=BLOCK_HASH,
    )
    values = {
        "schema_version": "2.0",
        "status": "enforced",
        "policy_sha256": HASH_A,
        "expected_chain_id": 31_337,
        "pinned_block_number": 42,
        "pinned_block_hash": BLOCK_HASH,
        "preflight_origin_observation_sha256": observation_sha256,
        "postflight_origin_observation_sha256": observation_sha256,
        "origin_state_stable": True,
        "http_request_count": 2,
        "permitted_rpc_call_count": 2,
        "origin_attempted_rpc_call_count": 1,
        "origin_validated_rpc_call_count": 1,
        "synthetic_rpc_call_count": 1,
        "denied_request_count": 0,
        "malformed_request_count": 0,
        "limit_exceeded_request_count": 0,
        "upstream_error_request_count": 0,
        "allowed_method_counts": [
            {"method": "eth_chainId", "count": 1},
            {"method": "eth_getCode", "count": 1},
        ],
        "method_log_sha256": HASH_B,
        "stopped_cleanly": True,
    }
    if selected_test_scope_snapshot_sha256s:
        values["selected_test_scope_snapshot_sha256s"] = list(selected_test_scope_snapshot_sha256s)
    return ReadOnlyRpcBridgeSnapshot(
        schema_version="2.0",
        status="enforced",
        policy_sha256=HASH_A,
        expected_chain_id=31_337,
        pinned_block_number=42,
        pinned_block_hash=BLOCK_HASH,
        preflight_origin_observation_sha256=observation_sha256,
        postflight_origin_observation_sha256=observation_sha256,
        origin_state_stable=True,
        http_request_count=2,
        permitted_rpc_call_count=2,
        origin_attempted_rpc_call_count=1,
        origin_validated_rpc_call_count=1,
        synthetic_rpc_call_count=1,
        denied_request_count=0,
        malformed_request_count=0,
        limit_exceeded_request_count=0,
        upstream_error_request_count=0,
        allowed_method_counts=(("eth_chainId", 1), ("eth_getCode", 1)),
        method_log_sha256=HASH_B,
        stopped_cleanly=True,
        snapshot_sha256=_canonical_sha256(values),
        selected_test_scope_snapshot_sha256s=selected_test_scope_snapshot_sha256s,
    )


def _scope_evidence(
    snapshot: ReadOnlyRpcTestScopeSnapshot,
) -> RepositoryTestForkRpcScopeEvidence:
    return RepositoryTestForkRpcScopeEvidence.sealed(
        schema_version=snapshot.schema_version,
        attempt_binding_sha256=snapshot.attempt_binding_sha256,
        selection_sha256=snapshot.selection_sha256,
        descriptor_sha256=snapshot.descriptor_sha256,
        sequence_index=snapshot.sequence_index,
        bridge_policy_sha256=snapshot.policy_sha256,
        expected_chain_id=snapshot.expected_chain_id,
        pinned_block_number=snapshot.pinned_block_number,
        pinned_block_hash=snapshot.pinned_block_hash,
        status=RepositoryTestForkRpcScopeStatus(snapshot.status),
        http_request_count=snapshot.http_request_count,
        permitted_rpc_call_count=snapshot.permitted_rpc_call_count,
        origin_attempted_rpc_call_count=snapshot.origin_attempted_rpc_call_count,
        origin_validated_rpc_call_count=snapshot.origin_validated_rpc_call_count,
        synthetic_rpc_call_count=snapshot.synthetic_rpc_call_count,
        denied_request_count=snapshot.denied_request_count,
        malformed_request_count=snapshot.malformed_request_count,
        limit_exceeded_request_count=snapshot.limit_exceeded_request_count,
        upstream_error_request_count=snapshot.upstream_error_request_count,
        allowed_method_counts=tuple(
            ForkRpcMethodCount(method=method, count=count)
            for method, count in snapshot.allowed_method_counts
        ),
        method_log_sha256=snapshot.method_log_sha256,
        boundary_drained=snapshot.boundary_drained,
        transaction_capable_request_forwarded=False,
        credentials_forwarded=False,
        raw_payloads_retained=False,
        rpc_endpoint_recorded=False,
        bridge_scope_snapshot_sha256=snapshot.snapshot_sha256,
    )


def test_bridge_snapshot_converts_to_exact_endpoint_free_egress_evidence() -> None:
    snapshot = _snapshot()

    evidence = fork_rpc_egress_from_snapshot(snapshot, _state())

    assert evidence.bridge_snapshot_sha256 == snapshot.snapshot_sha256
    assert evidence.permitted_rpc_call_count == 2
    assert evidence.origin_attempted_rpc_call_count == 1
    assert evidence.origin_validated_rpc_call_count == 1
    assert evidence.synthetic_rpc_call_count == 1
    assert [item.model_dump(mode="json") for item in evidence.allowed_method_counts] == [
        {"method": "eth_chainId", "count": 1},
        {"method": "eth_getCode", "count": 1},
    ]
    serialized = evidence.model_dump_json()
    assert "http://" not in serialized
    assert "127.0.0.1" not in serialized


def test_bridge_snapshot_conversion_preserves_ordered_scope_ledger_on_round_trip() -> None:
    selected_scope_hashes = (HASH_D, HASH_C)
    snapshot = _snapshot(
        selected_test_scope_snapshot_sha256s=selected_scope_hashes,
    )

    evidence = fork_rpc_egress_from_snapshot(snapshot, _state())
    restored = ForkRpcReadOnlyEgressEvidence.model_validate_json(evidence.model_dump_json())

    assert evidence.selected_test_scope_snapshot_sha256s == selected_scope_hashes
    assert restored.selected_test_scope_snapshot_sha256s == selected_scope_hashes
    assert restored == evidence


@pytest.mark.parametrize(
    "state",
    [
        _state(observed=False),
        _state(chain_id=31_338),
    ],
)
def test_bridge_snapshot_conversion_rejects_unobserved_or_mismatched_state(
    state: RepositorySuiteExecutionStateEvidence,
) -> None:
    with pytest.raises(ValueError, match="observed state identity"):
        fork_rpc_egress_from_snapshot(_snapshot(), state)


class _Backend:
    name = "synthetic-hardened-isolation"
    supports_local_fork_rpc = True

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


@dataclass
class _Clock:
    value: float = 0

    def __call__(self) -> float:
        return self.value


@dataclass
class _SequenceClock:
    values: list[float]
    last: float = 0

    def __call__(self) -> float:
        if self.values:
            self.last = self.values.pop(0)
        return self.last


def _clean_attestation() -> RepositoryCleanStateAttestationEvidence:
    return RepositoryCleanStateAttestationEvidence.sealed(
        schema_version="2.0",
        launcher_kind="trusted_internal_anvil",
        launcher_policy_version="2.0",
        execution_evidence=ExecutionEvidenceKind.REAL,
        configured_tool_version="anvil Version: 1.3.2-stable",
        observed_tool_version="anvil Version: 1.3.2-stable",
        configured_tool_sha256=HASH_A,
        observed_tool_sha256=HASH_A,
        trust_pin_validated=True,
        launch_configuration_sha256=HASH_B,
        environment_policy_sha256=HASH_C,
        process_attestation_sha256=HASH_D,
        target_arguments_inherited=False,
        target_environment_inherited=False,
        fork_or_state_arguments_present=False,
        target_state_input_present=False,
        listener_scope="numeric_loopback",
        listener_ownership_kind=RepositoryCleanListenerOwnershipKind.DARWIN_ROOT_OWNED_LSOF,
        listener_owner_pid_bound=True,
        runtime_executable_identity_kind=(
            RepositoryCleanRuntimeExecutableIdentityKind.DARWIN_PROC_PIDPATH
        ),
        runtime_executable_matches_pinned_copy=True,
        exec_path_binding_kind=(
            RepositoryCleanExecPathBindingKind.DARWIN_PRIVATE_PATH_POST_SPAWN_HASH
        ),
        version_probe_process_group_absent=True,
        outbound_network_isolation="not_attested",
        expected_chain_id=31_337,
        observed_chain_id=31_337,
        genesis_block_number=0,
        genesis_block_hash=BLOCK_HASH,
        initial_head_block_number=0,
        initial_head_block_hash=BLOCK_HASH,
        initial_head_state_root="0x" + HASH_B,
        final_head_block_number=0,
        final_head_block_hash=BLOCK_HASH,
        final_head_state_root="0x" + HASH_B,
        pristine_head_pre_post_match=True,
        startup_completed=True,
        startup_duration_seconds=0.1,
        termination_method="term",
        termination_duration_seconds=0.1,
        process_group_absent=True,
        collector_threads_closed=True,
        executable_descriptor_closed=True,
        private_workspace_removed=True,
        ancestor_config_absent=True,
        no_upstream_fork_configuration=True,
        endpoint_retained=False,
        executable_path_retained=False,
        port_retained=False,
        process_id_retained=False,
        raw_output_retained=False,
    )


class _CleanLease:
    endpoint = "http://127.0.0.1:9100"

    def __init__(self, *, stop_failure: BaseException | None = None) -> None:
        self.stopped = False
        self.stop_attempted = False
        self._stop_failure = stop_failure

    def stop(self, deadline: float) -> None:
        del deadline
        self.stop_attempted = True
        if self._stop_failure is not None:
            raise self._stop_failure
        self.stopped = True

    def attestation(self) -> RepositoryCleanStateAttestationEvidence:
        assert self.stopped
        return _clean_attestation()


class _CleanProvider:
    def __init__(self, harness: _Harness) -> None:
        self._harness = harness
        self.leases: list[_CleanLease] = []

    def start(
        self,
        config: RepositoryCleanForkMatrixStateConfig,
        repository_root: Path,
        private_root: Path,
        absolute_deadline: float,
    ) -> CleanStateLease:
        del config, absolute_deadline
        assert repository_root.is_dir()
        assert private_root.is_dir()
        lease = _CleanLease(stop_failure=self._harness.clean_stop_failure)
        self.leases.append(lease)
        if self._harness.clean_start_callback is not None:
            self._harness.clean_start_callback(private_root)
        return lease


class _Bridge:
    def __init__(
        self,
        harness: _Harness,
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
    ) -> None:
        self._harness = harness
        self._chain_id = expected_chain_id
        self._block_number = pinned_block_number
        self._block_hash = pinned_block_hash
        self._started = False
        self._stopped = False
        self._bridge_index = len(harness.bridges) + 1
        self._active_scope: tuple[str, str, str, int] | None = None
        self._sealed_scope_status: RepositoryTestForkRpcScopeStatus | None = None
        self._sealed_scope_snapshot_sha256s: list[str] = []

    @property
    def endpoint(self) -> str:
        assert self._started and not self._stopped
        return f"http://127.0.0.1:{10_000 + self._bridge_index}"

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        assert self._started
        assert self._active_scope is None
        self._stopped = True

    @property
    def stopped(self) -> bool:
        return self._stopped

    def begin_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> None:
        assert self._started and not self._stopped
        assert self._active_scope is None
        self._active_scope = (
            attempt_binding_sha256,
            selection_sha256,
            descriptor_sha256,
            sequence_index,
        )

    def end_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> ReadOnlyRpcTestScopeSnapshot:
        assert self._started and not self._stopped
        expected_identity = (
            attempt_binding_sha256,
            selection_sha256,
            descriptor_sha256,
            sequence_index,
        )
        assert self._active_scope == expected_identity
        self._active_scope = None
        scope_attempt_binding = (
            self._harness.scope_attempt_binding_override or attempt_binding_sha256
        )
        status = self._harness.scope_status
        origin_attempted = 1 if status is RepositoryTestForkRpcScopeStatus.VALIDATED else 0
        origin_validated = origin_attempted
        synthetic = 1 if status is RepositoryTestForkRpcScopeStatus.NOT_OBSERVED else 0
        denied = 1 if status is RepositoryTestForkRpcScopeStatus.VIOLATION else 0
        method_counts = (
            (("eth_getCode", 1),)
            if origin_attempted
            else ((("eth_chainId", 1),) if synthetic else ())
        )
        self._sealed_scope_status = status
        values = {
            "schema_version": "1.0",
            "attempt_binding_sha256": scope_attempt_binding,
            "selection_sha256": selection_sha256,
            "descriptor_sha256": descriptor_sha256,
            "sequence_index": sequence_index,
            "policy_sha256": self._harness.scope_bridge_policy_sha256,
            "expected_chain_id": self._chain_id,
            "pinned_block_number": self._block_number,
            "pinned_block_hash": self._block_hash,
            "status": status.value,
            "http_request_count": origin_attempted + synthetic + denied,
            "permitted_rpc_call_count": origin_attempted + synthetic,
            "origin_attempted_rpc_call_count": origin_attempted,
            "origin_validated_rpc_call_count": origin_validated,
            "synthetic_rpc_call_count": synthetic,
            "denied_request_count": denied,
            "malformed_request_count": 0,
            "limit_exceeded_request_count": 0,
            "upstream_error_request_count": 0,
            "allowed_method_counts": [
                {"method": method, "count": count} for method, count in method_counts
            ],
            "method_log_sha256": HASH_F,
            "boundary_drained": True,
        }
        snapshot_sha256 = _canonical_sha256(values)
        self._sealed_scope_snapshot_sha256s.append(snapshot_sha256)
        return ReadOnlyRpcTestScopeSnapshot(
            schema_version="1.0",
            attempt_binding_sha256=scope_attempt_binding,
            selection_sha256=selection_sha256,
            descriptor_sha256=descriptor_sha256,
            sequence_index=sequence_index,
            policy_sha256=self._harness.scope_bridge_policy_sha256,
            expected_chain_id=self._chain_id,
            pinned_block_number=self._block_number,
            pinned_block_hash=self._block_hash,
            status=status.value,
            http_request_count=origin_attempted + synthetic + denied,
            permitted_rpc_call_count=origin_attempted + synthetic,
            origin_attempted_rpc_call_count=origin_attempted,
            origin_validated_rpc_call_count=origin_validated,
            synthetic_rpc_call_count=synthetic,
            denied_request_count=denied,
            malformed_request_count=0,
            limit_exceeded_request_count=0,
            upstream_error_request_count=0,
            allowed_method_counts=method_counts,
            method_log_sha256=HASH_F,
            boundary_drained=True,
            snapshot_sha256=snapshot_sha256,
        )

    def snapshot(self) -> ReadOnlyRpcBridgeSnapshot:
        assert self._stopped
        scope_status = self._sealed_scope_status
        origin_attempted = (
            1 if scope_status in {None, RepositoryTestForkRpcScopeStatus.VALIDATED} else 0
        )
        synthetic = 1 if scope_status is RepositoryTestForkRpcScopeStatus.NOT_OBSERVED else 0
        denied = 1 if scope_status is RepositoryTestForkRpcScopeStatus.VIOLATION else 0
        permitted = origin_attempted + synthetic
        status = "violation" if denied else "enforced"
        method_counts = (
            (("eth_getCode", 1),)
            if origin_attempted
            else ((("eth_chainId", 1),) if synthetic else ())
        )
        observation_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
            expected_chain_id=self._chain_id,
            pinned_block_number=self._block_number,
            pinned_block_hash=self._block_hash,
        )
        values = {
            "schema_version": "2.0",
            "status": status,
            "policy_sha256": HASH_E,
            "expected_chain_id": self._chain_id,
            "pinned_block_number": self._block_number,
            "pinned_block_hash": self._block_hash,
            "preflight_origin_observation_sha256": observation_sha256,
            "postflight_origin_observation_sha256": observation_sha256,
            "origin_state_stable": True,
            "http_request_count": permitted + denied,
            "permitted_rpc_call_count": permitted,
            "origin_attempted_rpc_call_count": origin_attempted,
            "origin_validated_rpc_call_count": origin_attempted,
            "synthetic_rpc_call_count": synthetic,
            "denied_request_count": denied,
            "malformed_request_count": 0,
            "limit_exceeded_request_count": 0,
            "upstream_error_request_count": 0,
            "allowed_method_counts": [
                {"method": method, "count": count} for method, count in method_counts
            ],
            "method_log_sha256": HASH_F,
            "stopped_cleanly": True,
        }
        if self._sealed_scope_snapshot_sha256s:
            values["selected_test_scope_snapshot_sha256s"] = list(
                self._sealed_scope_snapshot_sha256s
            )
        return ReadOnlyRpcBridgeSnapshot(
            schema_version="2.0",
            status=status,
            policy_sha256=HASH_E,
            expected_chain_id=self._chain_id,
            pinned_block_number=self._block_number,
            pinned_block_hash=self._block_hash,
            preflight_origin_observation_sha256=observation_sha256,
            postflight_origin_observation_sha256=observation_sha256,
            origin_state_stable=True,
            http_request_count=permitted + denied,
            permitted_rpc_call_count=permitted,
            origin_attempted_rpc_call_count=origin_attempted,
            origin_validated_rpc_call_count=origin_attempted,
            synthetic_rpc_call_count=synthetic,
            denied_request_count=denied,
            malformed_request_count=0,
            limit_exceeded_request_count=0,
            upstream_error_request_count=0,
            allowed_method_counts=method_counts,
            method_log_sha256=HASH_F,
            stopped_cleanly=True,
            snapshot_sha256=_canonical_sha256(values),
            selected_test_scope_snapshot_sha256s=tuple(self._sealed_scope_snapshot_sha256s),
        )


class _Scanner:
    def __init__(
        self,
        harness: _Harness,
        *,
        chain_id: int,
        block_number: int,
        endpoint: str,
        scope_recorder: _Bridge,
        attempt_binding_sha256: str,
    ) -> None:
        self._harness = harness
        self._chain_id = chain_id
        self._block_number = block_number
        self._endpoint = endpoint
        self._scope_recorder = scope_recorder
        self._attempt_binding_sha256 = attempt_binding_sha256

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun:
        del timeout_seconds, backend
        assert private_dir.is_dir()
        self._harness.attempt_directories.append(private_dir)
        workspace = private_dir / "workspace"
        workspace.mkdir(mode=0o700)
        source_stat = root.stat()
        workspace_parent_stat = private_dir.stat()
        workspace_stat = workspace.stat()
        workspace_copy = RepositorySuiteWorkspaceCopyEvidence.sealed(
            attempt_binding_sha256=self._attempt_binding_sha256,
            selection_sha256=self._harness.selection.selection_sha256,
            repository_sha256=HASH_B,
            copy_policy_sha256=REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
            source_inventory_sha256_before=HASH_B,
            source_inventory_sha256_after=HASH_B,
            workspace_inventory_sha256_after_copy=HASH_B,
            workspace_inventory_sha256_after_execution=HASH_B,
            source_root_device_before=source_stat.st_dev,
            source_root_inode_before=source_stat.st_ino,
            source_root_device_after=source_stat.st_dev,
            source_root_inode_after=source_stat.st_ino,
            workspace_root_device_before=workspace_stat.st_dev,
            workspace_root_inode_before=workspace_stat.st_ino,
            workspace_root_device_after=workspace_stat.st_dev,
            workspace_root_inode_after=workspace_stat.st_ino,
            workspace_parent_device=workspace_parent_stat.st_dev,
            workspace_parent_inode=workspace_parent_stat.st_ino,
        )
        if self._harness.scanner_private_callback is not None:
            self._harness.scanner_private_callback(private_dir)
        self._harness.scanner_endpoints.append(self._endpoint)
        self._harness.scanner_trust_pins.append((expected_version, expected_sha256))
        if self._harness.scanner_failure is not None:
            raise self._harness.scanner_failure
        invocation = self._harness.scanner_invocations.get(self._chain_id, 0)
        self._harness.scanner_invocations[self._chain_id] = invocation + 1
        outcomes = self._harness.outcomes[self._chain_id]
        scanner_status, test_status, result_hash = outcomes[min(invocation, len(outcomes) - 1)]
        if scanner_status is not ScannerStatus.SUCCESS:
            return ScannerRun(
                scanner="foundry_fork",
                status=scanner_status,
                started_at=BASE_TIME,
                finished_at=BASE_TIME,
                duration_seconds=0,
                error="Synthetic matrix attempt unavailable.",
            )
        block_hash = BLOCK_HASH if self._chain_id == 31_337 else PINNED_BLOCK_HASH
        if self._harness.omit_scope:
            scope = None
        else:
            self._scope_recorder.begin_selected_test_scope(
                attempt_binding_sha256=self._attempt_binding_sha256,
                selection_sha256=self._harness.selection.selection_sha256,
                descriptor_sha256=self._harness.descriptor.descriptor_sha256,
                sequence_index=1,
            )
            scope = _scope_evidence(
                self._scope_recorder.end_selected_test_scope(
                    attempt_binding_sha256=self._attempt_binding_sha256,
                    selection_sha256=self._harness.selection.selection_sha256,
                    descriptor_sha256=self._harness.descriptor.descriptor_sha256,
                    sequence_index=1,
                )
            )
        run = self._harness.execution_run(
            chain_id=self._chain_id,
            block_number=self._block_number,
            block_hash=block_hash,
            test_status=test_status,
            machine_result_sha256=result_hash,
            scope=scope,
            workspace_copy=workspace_copy,
        )
        if self._harness.child_tool_mismatch:
            run = run.model_copy(
                update={
                    "version": "forge 9.9.9-unapproved",
                    "executable_sha256": HASH_F,
                }
            )
        if self._harness.retain_endpoint_in_run or self._harness.retained_diagnostic is not None:
            payload = run.model_dump(mode="python")
            payload["error"] = (
                self._harness.retained_diagnostic(private_dir)
                if self._harness.retained_diagnostic is not None
                else f"Synthetic diagnostic retained {self._endpoint}"
            )
            payload["execution_observation_sha256"] = None
            provisional = ScannerRun.model_validate(payload)
            payload["execution_observation_sha256"] = (
                provisional.expected_execution_observation_sha256()
            )
            run = ScannerRun.model_validate(payload)
        if (
            self._harness.advance_clock_after_first_scan
            and sum(self._harness.scanner_invocations.values()) == 1
        ):
            self._harness.clock.value = 101
        return run


class _Harness:
    def __init__(self, *, repetitions: int = 2) -> None:
        clean = RepositoryCleanForkMatrixStateConfig(
            state_id="clean-local",
            expected_chain_id=31_337,
            anvil_version="anvil Version: 1.3.2-stable",
            anvil_sha256=HASH_A,
            hardfork="cancun",
            genesis_timestamp=1,
            startup_timeout_seconds=1,
            shutdown_timeout_seconds=1,
        )
        pinned = RepositoryPinnedForkMatrixStateConfig(
            state_id="pinned-local",
            rpc_url_env="MMAUDIT_PINNED_LOCAL_RPC_URL",
            expected_chain_id=31_338,
            pinned_block_number=42,
            state_source_sha256=HASH_B,
        )
        suite = RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=("test/*.t.sol",),
            foundry_include_tests=("test*",),
            hardhat_include_paths=(),
            hardhat_include_tests=(),
            fuzz_seed=SEED,
            fork_matrix_states=(clean, pinned),
            fork_matrix_repetitions=repetitions,
        )
        self.smart_contracts = SmartContractsConfig(
            allow_fork_probing=True,
            repository_suite=suite,
        )
        self.reproduction = ReproductionConfig()
        self.descriptor = RepositorySuiteTestDescriptor.sealed(
            framework=RepositorySuiteFramework.FOUNDRY,
            project_root="contracts",
            path="contracts/test/Vault.t.sol",
            suite_name="VaultTest",
            test_name="testAccounting",
            source_sha256=HASH_A,
            start_line=10,
            end_line=12,
        )
        self.selection = RepositorySuiteSelection.sealed(
            profile="explicit",
            repository_sha256=HASH_B,
            repository_exclusion_path=".mmaudit",
            configuration_sha256=suite.stable_hash(),
            candidate_file_count=1,
            candidate_test_count=1,
            selected_file_count=1,
            selected_test_count=1,
            omitted_file_count=0,
            omitted_test_count=0,
            limit_reached=False,
            tests=(self.descriptor,),
        )
        self.clock = _Clock()
        self.clean_start_callback: Callable[[Path], None] | None = None
        self.scanner_private_callback: Callable[[Path], None] | None = None
        self.clean_stop_failure: BaseException | None = None
        self.clean_provider = _CleanProvider(self)
        self.environment = {
            "MMAUDIT_PINNED_LOCAL_RPC_URL": "http://127.0.0.1:9200",
        }
        self.observer_calls: list[str] = []
        self.bridges: list[_Bridge] = []
        self.attempt_directories: list[Path] = []
        self.scanner_endpoints: list[str] = []
        self.scanner_trust_pins: list[tuple[str | None, str | None]] = []
        self.scanner_invocations: dict[int, int] = {}
        self.observer_failure: BaseException | None = None
        self.scanner_failure: BaseException | None = None
        self.child_tool_mismatch = False
        self.unavailable_pinned = False
        self.drift_pinned = False
        self.advance_clock_after_first_scan = False
        self.retain_endpoint_in_run = False
        self.retained_diagnostic: Callable[[Path], str] | None = None
        self.omit_scope = False
        self.scope_status = RepositoryTestForkRpcScopeStatus.VALIDATED
        self.scope_attempt_binding_override: str | None = None
        self.scope_bridge_policy_sha256 = HASH_E
        self.outcomes: dict[
            int,
            list[
                tuple[
                    ScannerStatus,
                    RepositoryTestExecutionStatus,
                    str,
                ]
            ],
        ] = {
            31_337: [
                (
                    ScannerStatus.SUCCESS,
                    RepositoryTestExecutionStatus.PASSED,
                    HASH_D,
                )
            ],
            31_338: [
                (
                    ScannerStatus.SUCCESS,
                    RepositoryTestExecutionStatus.ASSERTION_FAILED,
                    HASH_F,
                )
            ],
        }
        self.baseline = self.execution_run(
            chain_id=31_337,
            block_number=0,
            block_hash=BLOCK_HASH,
            test_status=RepositoryTestExecutionStatus.PASSED,
            machine_result_sha256=HASH_D,
        )

    def policy(
        self,
        *,
        chain_id: int,
        block_number: int,
        block_hash: str,
    ) -> RepositorySuiteExecutionPolicy:
        return RepositorySuiteExecutionPolicy.sealed(
            selection_sha256=self.selection.selection_sha256,
            selection_configuration_sha256=self.selection.configuration_sha256,
            chain_id=chain_id,
            block_number=block_number,
            block_hash=block_hash,
            tool_version="forge 1.3.2",
            tool_sha256=HASH_A,
            compiler_version="solc 0.8.30",
            compiler_sha256=HASH_B,
            isolation_backend="synthetic-hardened-isolation",
            isolation_attestation_sha256=HASH_C,
            fuzz_seed=SEED,
            fuzz_runs=self.smart_contracts.foundry_fuzz_runs,
            invariant_runs=self.smart_contracts.foundry_invariant_runs,
            per_test_timeout_seconds=(
                self.smart_contracts.repository_suite.per_test_timeout_seconds
            ),
            total_timeout_seconds=(self.smart_contracts.repository_suite.total_timeout_seconds),
            max_output_bytes_per_test=(
                self.smart_contracts.repository_suite.max_output_bytes_per_test
            ),
            max_total_output_bytes=(self.smart_contracts.repository_suite.max_total_output_bytes),
        )

    def execution_run(
        self,
        *,
        chain_id: int,
        block_number: int,
        block_hash: str,
        test_status: RepositoryTestExecutionStatus,
        machine_result_sha256: str,
        scope: RepositoryTestForkRpcScopeEvidence | None = None,
        workspace_copy: RepositorySuiteWorkspaceCopyEvidence | None = None,
    ) -> ScannerRun:
        policy = self.policy(
            chain_id=chain_id,
            block_number=block_number,
            block_hash=block_hash,
        )
        passed = test_status is RepositoryTestExecutionStatus.PASSED
        execution = RepositoryTestExecution.sealed(
            selection_sha256=self.selection.selection_sha256,
            descriptor_sha256=self.descriptor.descriptor_sha256,
            framework=RepositorySuiteFramework.FOUNDRY,
            project_root=self.descriptor.project_root,
            path=self.descriptor.path,
            suite_name=self.descriptor.suite_name,
            test_name=self.descriptor.test_name,
            chain_id=chain_id,
            block_number=block_number,
            block_hash=block_hash,
            fuzz_seed=SEED,
            test_kind=RepositoryTestKind.UNIT,
            status=test_status,
            terminal_detail=None if passed else "Synthetic invariant mismatch.",
            duration_seconds=0.1,
            command_sha256=HASH_C,
            output_sha256=HASH_D,
            output_bytes=10,
            machine_result_sha256=machine_result_sha256,
            process_exit_code=0 if passed else 1,
            machine_output_validated=True,
            execution_evidence=ExecutionEvidenceKind.REAL,
            repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
            isolation_backend="synthetic-hardened-isolation",
            isolation_attestation_sha256=HASH_C,
            compiler_version="solc 0.8.30",
            compiler_sha256=HASH_B,
            execution_policy_sha256=policy.policy_sha256,
        )
        run = ScannerRun(
            scanner="foundry_fork",
            status=ScannerStatus.SUCCESS,
            execution_evidence=ExecutionEvidenceKind.REAL,
            version="forge 1.3.2",
            executable_sha256=HASH_A,
            command=[
                "forge",
                "test",
                "[BOUNDED_PER_TEST_REPOSITORY_SUITE]",
                self.selection.selection_sha256,
            ],
            started_at=BASE_TIME,
            finished_at=BASE_TIME,
            duration_seconds=0.1,
            findings=(
                []
                if passed
                else [
                    ScannerFinding(
                        scanner="foundry_fork",
                        rule_id="repository-test-assertion",
                        title="Synthetic accounting invariant failed",
                        severity=Severity.HIGH,
                        message=(
                            "A synthetic local execution observed an incorrect state transition."
                        ),
                        locations=[
                            Location(
                                path=self.descriptor.path,
                                start_line=self.descriptor.start_line,
                                end_line=self.descriptor.end_line,
                            )
                        ],
                        metadata={"repository_test_execution_sha256": execution.execution_sha256},
                        evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
                        fingerprint=HASH_E,
                    )
                ]
            ),
            process_exit_code=0 if passed else 1,
            isolation_backend="synthetic-hardened-isolation",
            isolation_attestation_sha256=HASH_C,
            machine_output_validated=True,
            foundry_summary=FoundryTestExecutionSummary(
                unit_tests=1,
                fuzz_tests=0,
                invariant_tests=0,
                passed_tests=1 if passed else 0,
                failed_tests=0 if passed else 1,
                skipped_tests=0,
                fuzz_cases=0,
                invariant_runs=0,
                invariant_calls=0,
            ),
            repository_suite_selection=self.selection,
            repository_suite_execution_policy=policy,
            repository_suite_workspace_copy=workspace_copy,
            repository_test_executions=[execution],
            repository_test_fork_rpc_scopes=[] if scope is None else [scope],
            repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        )
        return ScannerRun.model_validate(
            {
                **run.model_dump(mode="json"),
                "execution_observation_sha256": run.expected_execution_observation_sha256(),
            }
        )

    def observe(
        self,
        endpoint: str,
        *,
        expected_chain_id: int | None,
        pinned_block_number: int | None,
        timeout_seconds: float,
    ) -> PinnedForkObservation:
        assert timeout_seconds > 0
        self.observer_calls.append(endpoint)
        if self.observer_failure is not None:
            raise self.observer_failure
        if endpoint == self.environment["MMAUDIT_PINNED_LOCAL_RPC_URL"]:
            if self.unavailable_pinned:
                raise ForkRpcUnavailableError("synthetic unavailable")
            pinned_calls = sum(item == endpoint for item in self.observer_calls)
            block_hash = (
                "0x" + HASH_C if self.drift_pinned and pinned_calls in {2, 4} else PINNED_BLOCK_HASH
            )
            return PinnedForkObservation(
                chain_id=cast(int, expected_chain_id),
                block_number=cast(int, pinned_block_number),
                block_hash=block_hash,
            )
        return PinnedForkObservation(
            chain_id=cast(int, expected_chain_id),
            block_number=cast(int, pinned_block_number),
            block_hash=BLOCK_HASH,
        )

    def bridge_factory(
        self,
        origin_endpoint: str,
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
        timeout_seconds: float,
    ) -> _Bridge:
        del origin_endpoint
        assert timeout_seconds > 0
        bridge = _Bridge(
            self,
            expected_chain_id=expected_chain_id,
            pinned_block_number=pinned_block_number,
            pinned_block_hash=pinned_block_hash,
        )
        self.bridges.append(bridge)
        return bridge

    def scanner_factory(
        self,
        config: SmartContractsConfig,
        *,
        reproduction: ReproductionConfig,
        projects: Sequence[SolidityProjectMetadata],
        allow_fork_probing: bool,
        expected_repository_sha256: str,
        repository_exclusion_root: Path,
        fork_rpc_url_override: str,
        fork_rpc_scope_recorder: _Bridge,
        attempt_binding_sha256: str,
    ) -> ForkMatrixScanner:
        del config, projects, repository_exclusion_root
        assert allow_fork_probing is True
        assert expected_repository_sha256 == HASH_B
        assert reproduction.expected_chain_id is not None
        assert reproduction.pinned_block_number is not None
        return _Scanner(
            self,
            chain_id=reproduction.expected_chain_id,
            block_number=reproduction.pinned_block_number,
            endpoint=fork_rpc_url_override,
            scope_recorder=fork_rpc_scope_recorder,
            attempt_binding_sha256=attempt_binding_sha256,
        )

    def dependencies(self, *, clean: bool = True) -> ForkMatrixDependencies:
        return ForkMatrixDependencies(
            observer=self.observe,
            bridge_factory=self.bridge_factory,
            scanner_factory=self.scanner_factory,
            clean_state_provider=self.clean_provider if clean else None,
            environment=self.environment,
            monotonic=self.clock,
            now=lambda: BASE_TIME,
            nonce=lambda: HASH_F,
        )

    def run(
        self,
        tmp_path: Path,
        *,
        clean: bool = True,
        deadline: float = 100,
        private_root: Path | None = None,
        repository_exclusion_root: Path | None = None,
        backend: ScannerIsolationBackend | None = None,
    ) -> RepositorySuiteDifferentialRun:
        tmp_path.mkdir(parents=True, exist_ok=True)
        selected_private_root = private_root or tmp_path / ".private"
        selected_exclusion_root = repository_exclusion_root or selected_private_root
        result = RepositoryForkMatrixRunner(
            self.smart_contracts,
            self.reproduction,
            dependencies=self.dependencies(clean=clean),
        ).run(
            tmp_path,
            selected_private_root,
            projects=(),
            repository_sha256=HASH_B,
            repository_exclusion_root=selected_exclusion_root,
            backend=backend or _Backend(),
            baseline_run=self.baseline,
            absolute_deadline=deadline,
        )
        assert result is not None
        return result


def test_runner_emits_repeated_real_divergence_without_top_level_child_runs(
    tmp_path: Path,
) -> None:
    harness = _Harness()

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.COMPLETE
    assert result.matrix is not None
    assert len(result.matrix.attempts) == 4
    assert (
        result.matrix.comparisons[0].classification is RepositoryDifferentialClassification.DIVERGED
    )
    assert all(attempt.scanner_run.scanner == "foundry_fork" for attempt in result.matrix.attempts)
    assert harness.baseline.fork_rpc_egress is None
    assert len({path for path in harness.attempt_directories}) == 4
    assert all(not path.exists() for path in harness.attempt_directories)
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    for cleanup in result.matrix.state_workspace_cleanups:
        state_attempts = tuple(
            attempt for attempt in result.matrix.attempts if attempt.state_id == cleanup.state_id
        )
        cleanup_order = tuple(reversed(state_attempts))
        assert cleanup.attempt_cleanup_sequence_lifecycle_sha256s == tuple(
            attempt.workspace_lifecycle.lifecycle_evidence_sha256 for attempt in cleanup_order
        )
        assert cleanup.attempt_cumulative_removed_entry_counts[-1] == sum(
            attempt.workspace_lifecycle.removed_entry_count for attempt in cleanup_order
        )
        assert cleanup.removed_entry_count <= cleanup.removal_entry_limit
        assert cleanup.removal_duration_seconds <= cleanup.removal_timeout_seconds
    serialized = result.model_dump_json()
    for prohibited in ("http://", "127.0.0.1", str(tmp_path)):
        assert prohibited not in serialized


def test_runner_reuses_same_nonce_after_removing_prior_matrix_tree(tmp_path: Path) -> None:
    harness = _Harness()
    private_root = tmp_path / ".private"

    first = harness.run(tmp_path, private_root=private_root)
    second = harness.run(tmp_path, private_root=private_root)

    assert first.status is RepositoryDifferentialRunStatus.COMPLETE
    assert second.status is RepositoryDifferentialRunStatus.COMPLETE
    assert all(not path.exists() for path in harness.attempt_directories)
    assert not any(private_root.iterdir())


def test_runner_removes_symlink_without_following_external_sentinel(tmp_path: Path) -> None:
    harness = _Harness()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("operator-owned\n", encoding="utf-8")

    def add_external_symlink(private_dir: Path) -> None:
        (private_dir / "external").symlink_to(outside, target_is_directory=True)

    harness.scanner_private_callback = add_external_symlink

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.COMPLETE
    assert sentinel.read_text(encoding="utf-8") == "operator-owned\n"
    assert all(not path.exists() for path in harness.attempt_directories)


def test_runner_refuses_replaced_attempt_without_deleting_foreign_tree(tmp_path: Path) -> None:
    harness = _Harness()
    displaced: list[Path] = []
    foreign_sentinels: list[Path] = []

    def replace_attempt(private_dir: Path) -> None:
        displaced_path = private_dir.with_name(private_dir.name + "-displaced")
        private_dir.rename(displaced_path)
        private_dir.mkdir(mode=0o700)
        foreign_sentinel = private_dir / "foreign-sentinel.txt"
        foreign_sentinel.write_text("do-not-delete\n", encoding="utf-8")
        displaced.append(displaced_path)
        foreign_sentinels.append(foreign_sentinel)

    harness.scanner_private_callback = replace_attempt

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert displaced and all(path.is_dir() for path in displaced)
    assert foreign_sentinels
    assert all(path.read_text(encoding="utf-8") == "do-not-delete\n" for path in foreign_sentinels)


def test_runner_cleanup_failure_prevents_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness()
    real_rmdir = fork_matrix_module.os.rmdir

    def fail_attempt_removal(
        path: str | bytes,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if str(path).endswith("attempt-1"):
            raise PermissionError("synthetic descriptor-anchored removal failure")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(fork_matrix_module.os, "rmdir", fail_attempt_removal)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None


def test_runner_cleanup_entry_ceiling_prevents_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness()

    def add_two_entries(private_dir: Path) -> None:
        (private_dir / "one").write_text("1", encoding="utf-8")
        (private_dir / "two").write_text("2", encoding="utf-8")

    harness.scanner_private_callback = add_two_entries
    real_start = fork_matrix_module._DirectoryRemovalBudget.start

    def constrained_start() -> fork_matrix_module._DirectoryRemovalBudget:
        budget = real_start()
        budget.entry_limit = 1
        return budget

    monkeypatch.setattr(
        fork_matrix_module._DirectoryRemovalBudget,
        "start",
        staticmethod(constrained_start),
    )

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None


def test_runner_cleanup_time_ceiling_prevents_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness()
    first = True

    def expired_cleanup_clock() -> float:
        nonlocal first
        if first:
            first = False
            return 0.0
        return fork_matrix_module.REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS + 1.0

    monkeypatch.setattr(fork_matrix_module.time, "monotonic", expired_cleanup_clock)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None


def test_state_cleanup_shares_one_aggregate_deadline_across_custodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_budget_ids: list[int] = []
    cleanup_times = iter((0.0, 3.0, 6.0))

    @dataclass
    class _SyntheticCustody:
        device: int
        inode: int
        closed: bool = False

        def remove_owned_tree(
            self,
            *,
            budget: fork_matrix_module._DirectoryRemovalBudget,
        ) -> fork_matrix_module._DirectoryDisposalObservation:
            observed_budget_ids.append(id(budget))
            budget.checkpoint()
            self.closed = True
            return fork_matrix_module._DirectoryDisposalObservation(
                attempt_root_device=self.device,
                attempt_root_inode=self.inode,
                removal_entry_limit=budget.entry_limit,
                removed_entry_count=1,
                removal_depth_limit=(
                    fork_matrix_module.REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT
                ),
                maximum_removed_depth=0,
                removal_timeout_seconds=(
                    fork_matrix_module.REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
                ),
                removal_duration_seconds=0.0,
                aggregate_removed_entry_count=budget.removed_entry_count,
                aggregate_removal_duration_seconds=(
                    budget.last_observed_at - budget.started_at
                    if budget.last_observed_at is not None
                    else 0.0
                ),
                attempt_descriptor_closed=True,
                workspace_path_absent=True,
                attempt_path_absent=True,
            )

        def close(self) -> bool:
            self.closed = True
            return True

    monkeypatch.setattr(
        fork_matrix_module,
        "_bounded_monotonic",
        lambda: next(cleanup_times),
    )
    lifecycle = fork_matrix_module._StateLifecycle(
        directories=[
            cast(fork_matrix_module._DirectoryCustody, _SyntheticCustody(1, 2)),
            cast(fork_matrix_module._DirectoryCustody, _SyntheticCustody(3, 4)),
        ]
    )

    cleanup_error = RepositoryForkMatrixRunner._cleanup_state_lifecycle(
        lifecycle,
        absolute_deadline=100.0,
    )

    assert isinstance(cleanup_error, fork_matrix_module._MatrixEvidenceError)
    assert len(observed_budget_ids) == 2
    assert len(set(observed_budget_ids)) == 1
    assert lifecycle.directories == []


def test_runner_close_failure_does_not_abort_later_owned_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness()
    real_close = fork_matrix_module._DirectoryCustody.close
    failure_reported = False

    def report_one_close_failure(
        custody: fork_matrix_module._DirectoryCustody,
    ) -> bool:
        nonlocal failure_reported
        closed = real_close(custody)
        if not failure_reported and custody.name == "clean-local-attempt-2":
            failure_reported = True
            return False
        return closed

    monkeypatch.setattr(
        fork_matrix_module._DirectoryCustody,
        "close",
        report_one_close_failure,
    )

    result = harness.run(tmp_path)

    assert failure_reported is True
    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert len(harness.attempt_directories) == 2
    assert all(not path.exists() for path in harness.attempt_directories)


@pytest.mark.parametrize("missing_capability", ["O_DIRECTORY", "O_NOFOLLOW"])
def test_runner_fails_before_custody_or_execution_without_required_open_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_capability: str,
) -> None:
    harness = _Harness()
    monkeypatch.delattr(fork_matrix_module.os, missing_capability)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert harness.clean_provider.leases == []
    assert harness.scanner_invocations == {}
    assert harness.attempt_directories == []


@pytest.mark.parametrize("failure_point", ["open", "fstat"])
def test_runner_transactionally_removes_child_after_post_mkdir_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    harness = _Harness()
    private_root = tmp_path / ".private"
    real_open = fork_matrix_module.os.open
    real_fstat = fork_matrix_module.os.fstat
    matrix_descriptors: set[int] = set()

    def guarded_open(
        path: str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if failure_point == "open" and str(path).startswith("repository-fork-matrix-"):
            raise OSError("synthetic child open failure")
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path).startswith("repository-fork-matrix-"):
            matrix_descriptors.add(descriptor)
        return descriptor

    def guarded_fstat(descriptor: int) -> object:
        if failure_point == "fstat" and descriptor in matrix_descriptors:
            matrix_descriptors.remove(descriptor)
            raise OSError("synthetic child fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(fork_matrix_module.os, "open", guarded_open)
    monkeypatch.setattr(fork_matrix_module.os, "fstat", guarded_fstat)

    result = harness.run(tmp_path, private_root=private_root)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert private_root.is_dir()
    assert not any(private_root.iterdir())


def test_runner_consistent_control_is_not_reported_as_divergent(tmp_path: Path) -> None:
    harness = _Harness()
    harness.outcomes[31_338] = [
        (
            ScannerStatus.SUCCESS,
            RepositoryTestExecutionStatus.PASSED,
            HASH_D,
        )
    ]

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.COMPLETE
    assert result.matrix is not None
    assert (
        result.matrix.comparisons[0].classification
        is RepositoryDifferentialClassification.CONSISTENT_PASS
    )


def test_matrix_baseline_accepts_exact_pre_scope_legacy_digest() -> None:
    harness = _Harness()
    payload = harness.baseline.model_dump(mode="json")
    payload.pop("repository_test_fork_rpc_scopes", None)
    payload["execution_observation_sha256"] = (
        harness.baseline.expected_legacy_execution_observation_sha256()
    )
    harness.baseline = ScannerRun.model_validate_json(json.dumps(payload, sort_keys=True))

    assert harness.baseline.execution_observation_sha256_is_valid()
    assert (
        _baseline_limitation(
            harness.baseline,
            repository_sha256=HASH_B,
            smart_contracts=harness.smart_contracts,
            backend=_Backend(),
        )
        is None
    )


@pytest.mark.parametrize(
    "configure",
    [
        lambda harness: setattr(harness, "omit_scope", True),
        lambda harness: setattr(
            harness,
            "scope_status",
            RepositoryTestForkRpcScopeStatus.NOT_OBSERVED,
        ),
        lambda harness: setattr(
            harness,
            "scope_status",
            RepositoryTestForkRpcScopeStatus.VIOLATION,
        ),
        lambda harness: setattr(harness, "scope_attempt_binding_override", HASH_A),
        lambda harness: setattr(harness, "scope_bridge_policy_sha256", HASH_A),
    ],
    ids=[
        "missing",
        "synthetic-only",
        "violation",
        "cross-attempt",
        "bridge-policy-mismatch",
    ],
)
def test_runner_does_not_credit_unproven_per_test_state_reads(
    tmp_path: Path,
    configure: Callable[[_Harness], None],
) -> None:
    harness = _Harness()
    configure(harness)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert all(
        RepositoryStateInconclusiveReason.STATE_READ_UNPROVEN in consensus.inconclusive_reasons
        for consensus in result.matrix.state_consensuses
    )
    assert all(
        comparison.classification is RepositoryDifferentialClassification.INCONCLUSIVE
        for comparison in result.matrix.comparisons
    )


def test_runner_unavailable_pinned_state_is_typed_inconclusive(tmp_path: Path) -> None:
    harness = _Harness()
    harness.unavailable_pinned = True

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    pinned = next(state for state in result.matrix.states if state.state_id == "pinned-local")
    assert pinned.observation_status is RepositoryExecutionStateObservationStatus.UNAVAILABLE
    assert (
        result.matrix.comparisons[0].classification
        is RepositoryDifferentialClassification.INCONCLUSIVE
    )


@pytest.mark.parametrize("disagree", [False, True])
def test_runner_single_or_disagreeing_observations_are_inconclusive(
    tmp_path: Path,
    disagree: bool,
) -> None:
    harness = _Harness()
    harness.outcomes[31_338] = (
        [
            (
                ScannerStatus.SUCCESS,
                RepositoryTestExecutionStatus.ASSERTION_FAILED,
                HASH_F,
            ),
            (
                ScannerStatus.SUCCESS,
                RepositoryTestExecutionStatus.PASSED,
                HASH_D,
            ),
        ]
        if disagree
        else [
            (
                ScannerStatus.SUCCESS,
                RepositoryTestExecutionStatus.ASSERTION_FAILED,
                HASH_F,
            ),
            (
                ScannerStatus.UNAVAILABLE,
                RepositoryTestExecutionStatus.ASSERTION_FAILED,
                HASH_F,
            ),
        ]
    )

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    pinned_consensus = next(
        consensus
        for consensus in result.matrix.state_consensuses
        if consensus.state_id == "pinned-local"
    )
    assert pinned_consensus.status is RepositoryStateConsensusStatus.INCONCLUSIVE


def test_runner_absolute_deadline_stops_new_attempts_and_still_cleans_up(
    tmp_path: Path,
) -> None:
    harness = _Harness()
    harness.advance_clock_after_first_scan = True

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert sum(harness.scanner_invocations.values()) == 1
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    assert any(
        attempt.scanner_run.status is ScannerStatus.TIMED_OUT for attempt in result.matrix.attempts
    )
    assert all(not path.exists() for path in harness.attempt_directories)
    clean = next(state for state in result.matrix.states if state.state_id == "clean-local")
    assert clean.observation_status is RepositoryExecutionStateObservationStatus.FAILED


def test_runner_does_not_mutate_environment_and_uses_fresh_bridge_per_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MMAUDIT_PINNED_LOCAL_RPC_URL", "unchanged")
    before = dict(__import__("os").environ)
    harness = _Harness()

    result = harness.run(tmp_path)

    assert result.matrix is not None
    assert dict(__import__("os").environ) == before
    assert len(harness.bridges) == 4
    assert len({attempt.workspace_identity_sha256 for attempt in result.matrix.attempts}) == 4
    assert len({attempt.attempt_sha256 for attempt in result.matrix.attempts}) == 4


def test_runner_origin_drift_and_missing_clean_attestor_fail_closed(
    tmp_path: Path,
) -> None:
    drift = _Harness()
    drift.drift_pinned = True

    drift_result = drift.run(tmp_path / "drift")
    missing_clean_result = _Harness().run(tmp_path / "missing", clean=False)

    assert drift_result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert drift_result.matrix is not None
    pinned = next(state for state in drift_result.matrix.states if state.state_id == "pinned-local")
    assert pinned.observation_status is RepositoryExecutionStateObservationStatus.FAILED
    assert missing_clean_result.status is RepositoryDifferentialRunStatus.FAILED
    assert missing_clean_result.matrix is None


def test_runner_rejects_child_evidence_that_retains_bridge_endpoint(
    tmp_path: Path,
) -> None:
    harness = _Harness()
    harness.retain_endpoint_in_run = True

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert "http://127.0.0.1:" not in result.model_dump_json()
    assert all(
        attempt.scanner_run.status is ScannerStatus.FAILED for attempt in result.matrix.attempts
    )


def test_runner_rejects_nonqualifying_baseline_before_launch(tmp_path: Path) -> None:
    harness = _Harness()
    harness.baseline = harness.baseline.model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.MOCK,
            "execution_observation_sha256": None,
        }
    )

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), float("-inf")])
def test_runner_rejects_non_numeric_or_non_finite_deadline_before_custody(
    tmp_path: Path,
    deadline: float,
) -> None:
    harness = _Harness()

    result = harness.run(tmp_path, deadline=deadline)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not (tmp_path / ".private").exists()
    assert not harness.clean_provider.leases
    assert not harness.bridges


def test_runner_rejects_regressing_clock_before_clean_launch(tmp_path: Path) -> None:
    harness = _Harness()
    harness.clock = cast(_Clock, _SequenceClock([10, 9]))

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


@pytest.mark.parametrize("next_time", [float("nan"), -1.0])
def test_runner_rejects_invalid_clock_after_clean_acquisition_and_stops_lease(
    tmp_path: Path,
    next_time: float,
) -> None:
    harness = _Harness()
    harness.clock.value = 10
    harness.clean_start_callback = lambda _path: setattr(harness.clock, "value", next_time)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert harness.clean_provider.leases
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    assert not harness.bridges


def test_runner_typed_failure_after_clean_acquisition_cleans_every_lease(
    tmp_path: Path,
) -> None:
    harness = _Harness()
    harness.observer_failure = TypeError("synthetic typed adapter failure")

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert harness.clean_provider.leases
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    assert all(bridge.stopped for bridge in harness.bridges)
    assert all(not path.exists() for path in harness.attempt_directories)


def test_runner_failed_clean_stop_cannot_preserve_complete_status(tmp_path: Path) -> None:
    harness = _Harness()
    harness.clean_stop_failure = RuntimeError("synthetic clean stop failure")

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert harness.clean_provider.leases
    assert all(lease.stop_attempted for lease in harness.clean_provider.leases)
    assert all(bridge.stopped for bridge in harness.bridges)
    assert result.limitations


def test_runner_keyboard_interrupt_propagates_after_lifecycle_cleanup(tmp_path: Path) -> None:
    harness = _Harness()
    harness.scanner_failure = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        harness.run(tmp_path)

    assert harness.clean_provider.leases
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    assert harness.bridges
    assert all(bridge.stopped for bridge in harness.bridges)
    assert all(not path.exists() for path in harness.attempt_directories)


def test_runner_preserves_original_interrupt_when_clean_stop_also_interrupts(
    tmp_path: Path,
) -> None:
    harness = _Harness()
    harness.scanner_failure = KeyboardInterrupt("scanner interrupted")
    harness.clean_stop_failure = SystemExit("cleanup interrupted")

    with pytest.raises(KeyboardInterrupt, match="scanner interrupted"):
        harness.run(tmp_path)

    assert harness.clean_provider.leases
    assert all(lease.stop_attempted for lease in harness.clean_provider.leases)
    assert harness.bridges
    assert all(bridge.stopped for bridge in harness.bridges)
    assert all(not path.exists() for path in harness.attempt_directories)


def test_runner_passes_baseline_forge_trust_pin_to_every_child(tmp_path: Path) -> None:
    harness = _Harness()

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.COMPLETE
    assert len(harness.scanner_trust_pins) == 4
    assert set(harness.scanner_trust_pins) == {
        (harness.baseline.version, harness.baseline.executable_sha256)
    }


def test_runner_rejects_child_forge_identity_outside_baseline_pin(tmp_path: Path) -> None:
    harness = _Harness()
    harness.child_tool_mismatch = True

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert all(
        attempt.scanner_run.status is ScannerStatus.FAILED for attempt in result.matrix.attempts
    )
    assert any("child Forge identity" in item for item in result.limitations)


@pytest.mark.parametrize(
    "config_update",
    [
        {"foundry_fuzz_runs": 257},
        {"foundry_invariant_runs": 65},
        {"solc_version": "solc 0.8.31", "solc_sha256": HASH_F},
    ],
)
def test_runner_rejects_baseline_policy_drift_before_launch(
    tmp_path: Path,
    config_update: dict[str, object],
) -> None:
    harness = _Harness()
    harness.smart_contracts = harness.smart_contracts.model_copy(update=config_update)

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


def test_runner_rejects_supplied_backend_drift_before_launch(tmp_path: Path) -> None:
    harness = _Harness()

    class _OtherBackend(_Backend):
        name = "different-hardened-isolation"

    result = harness.run(tmp_path, backend=_OtherBackend())

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


def test_runner_rejects_repository_root_as_private_root(tmp_path: Path) -> None:
    harness = _Harness()

    result = harness.run(
        tmp_path,
        private_root=tmp_path,
        repository_exclusion_root=tmp_path,
    )

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


def test_runner_rejects_symlinked_or_world_writable_private_root(tmp_path: Path) -> None:
    symlink_harness = _Harness()
    symlink_target = tmp_path / "symlink-target"
    symlink_target.mkdir(mode=0o700)
    symlink_private = tmp_path / "symlink-private"
    symlink_private.symlink_to(symlink_target, target_is_directory=True)

    symlink_result = symlink_harness.run(
        tmp_path,
        private_root=symlink_private,
        repository_exclusion_root=symlink_private,
    )

    writable_root = tmp_path / "world-writable"
    writable_root.mkdir(mode=0o700)
    writable_root.chmod(0o777)
    writable_harness = _Harness()
    writable_result = writable_harness.run(
        tmp_path,
        private_root=writable_root,
        repository_exclusion_root=writable_root,
    )

    assert symlink_result.status is RepositoryDifferentialRunStatus.FAILED
    assert writable_result.status is RepositoryDifferentialRunStatus.FAILED
    assert not symlink_harness.clean_provider.leases
    assert not writable_harness.clean_provider.leases


def test_runner_rejects_repository_overlap_outside_validated_exclusion(
    tmp_path: Path,
) -> None:
    harness = _Harness()

    result = harness.run(
        tmp_path,
        private_root=tmp_path / "not-excluded",
        repository_exclusion_root=tmp_path / ".mmaudit",
    )

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert not harness.clean_provider.leases
    assert not harness.bridges


def test_runner_detects_private_root_path_swap_after_clean_acquisition(
    tmp_path: Path,
) -> None:
    harness = _Harness()
    private_root = tmp_path / ".private"
    displaced = tmp_path / "displaced-private"

    def swap_private_root(_clean_private: Path) -> None:
        private_root.rename(displaced)
        private_root.symlink_to(displaced, target_is_directory=True)

    harness.clean_start_callback = swap_private_root

    result = harness.run(tmp_path, private_root=private_root)

    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert harness.clean_provider.leases
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    assert not harness.bridges


def test_runner_preserves_material_limitation_and_cannot_complete(tmp_path: Path) -> None:
    harness = _Harness()

    class _LimitingRunner(RepositoryForkMatrixRunner):
        def _execute_state(  # type: ignore[override]
            self,
            state_config: object,
            **kwargs: object,
        ) -> object:
            limitations = cast(list[str], kwargs["limitations"])
            observed = super()._execute_state(state_config, **kwargs)  # type: ignore[arg-type]
            limitations.append("Synthetic material matrix limitation.")
            return observed

    result = _LimitingRunner(
        harness.smart_contracts,
        harness.reproduction,
        dependencies=harness.dependencies(),
    ).run(
        tmp_path,
        tmp_path / ".private",
        projects=(),
        repository_sha256=HASH_B,
        repository_exclusion_root=tmp_path / ".private",
        backend=_Backend(),
        baseline_run=harness.baseline,
        absolute_deadline=100,
    )

    assert result is not None
    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert "Synthetic material matrix limitation." in result.limitations


@pytest.mark.parametrize(
    "diagnostic",
    [
        lambda private_dir: (
            "private evidence file://"
            + quote(str(private_dir.parent.parent), safe="")
            + "/artifact.json"
        ),
        lambda _private_dir: "normalized endpoint HTTP://LOCALHOST:19999/evidence",
        lambda _private_dir: "normalized endpoint http://127.1:19999/evidence",
        lambda private_dir: (
            "multiply encoded private path "
            + quote(
                quote(
                    quote(
                        quote(str(private_dir.parent.parent), safe=""),
                        safe="",
                    ),
                    safe="",
                ),
                safe="",
            )
        ),
        lambda private_dir: "case-folded private path " + str(private_dir.parent.parent).swapcase(),
    ],
)
def test_runner_recursively_rejects_normalized_private_path_and_loopback_uri_leaks(
    tmp_path: Path,
    diagnostic: Callable[[Path], str],
) -> None:
    harness = _Harness()
    harness.retained_diagnostic = diagnostic

    result = harness.run(tmp_path)

    assert result.status is RepositoryDifferentialRunStatus.INCONCLUSIVE
    assert result.matrix is not None
    assert all(
        attempt.scanner_run.status is ScannerStatus.FAILED for attempt in result.matrix.attempts
    )
    serialized = result.model_dump_json()
    assert str(tmp_path / ".private") not in serialized
    assert "localhost" not in serialized.lower()
    assert "127.1" not in serialized


def test_runner_without_configured_states_returns_none(tmp_path: Path) -> None:
    harness = _Harness()
    smart_contracts = harness.smart_contracts.model_copy(
        update={
            "repository_suite": RepositoryForkSuiteConfig(
                profile="explicit",
                foundry_include_paths=("test/*.t.sol",),
                foundry_include_tests=("test*",),
                hardhat_include_paths=(),
                hardhat_include_tests=(),
            )
        }
    )

    result = RepositoryForkMatrixRunner(
        smart_contracts,
        harness.reproduction,
        dependencies=harness.dependencies(),
    ).run(
        tmp_path,
        tmp_path / ".private",
        projects=(),
        repository_sha256=HASH_B,
        repository_exclusion_root=tmp_path / ".private",
        backend=_Backend(),
        baseline_run=harness.baseline,
        absolute_deadline=100,
    )

    assert result is None
