from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from mmaudit.config import (
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkSuiteConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
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
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityProjectMetadata,
)
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.fork_matrix import (
    CleanStateLease,
    ForkMatrixDependencies,
    ForkMatrixScanner,
    RepositoryForkMatrixRunner,
    fork_rpc_egress_from_snapshot,
)
from mmaudit.scanners.fork_rpc import ForkRpcUnavailableError, PinnedForkObservation
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridgeSnapshot

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


def _snapshot() -> ReadOnlyRpcBridgeSnapshot:
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

    def __init__(self) -> None:
        self.stopped = False

    def stop(self, deadline: float) -> None:
        del deadline
        self.stopped = True

    def attestation(self) -> RepositoryCleanStateAttestationEvidence:
        assert self.stopped
        return _clean_attestation()


class _CleanProvider:
    def __init__(self) -> None:
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
        lease = _CleanLease()
        self.leases.append(lease)
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

    @property
    def endpoint(self) -> str:
        assert self._started and not self._stopped
        return f"http://127.0.0.1:{10_000 + self._bridge_index}"

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        assert self._started
        self._stopped = True

    def snapshot(self) -> ReadOnlyRpcBridgeSnapshot:
        assert self._stopped
        observation_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
            expected_chain_id=self._chain_id,
            pinned_block_number=self._block_number,
            pinned_block_hash=self._block_hash,
        )
        values = {
            "schema_version": "2.0",
            "status": "enforced",
            "policy_sha256": HASH_E,
            "expected_chain_id": self._chain_id,
            "pinned_block_number": self._block_number,
            "pinned_block_hash": self._block_hash,
            "preflight_origin_observation_sha256": observation_sha256,
            "postflight_origin_observation_sha256": observation_sha256,
            "origin_state_stable": True,
            "http_request_count": 1,
            "permitted_rpc_call_count": 1,
            "origin_attempted_rpc_call_count": 1,
            "origin_validated_rpc_call_count": 1,
            "synthetic_rpc_call_count": 0,
            "denied_request_count": 0,
            "malformed_request_count": 0,
            "limit_exceeded_request_count": 0,
            "upstream_error_request_count": 0,
            "allowed_method_counts": [{"method": "eth_getCode", "count": 1}],
            "method_log_sha256": HASH_F,
            "stopped_cleanly": True,
        }
        return ReadOnlyRpcBridgeSnapshot(
            schema_version="2.0",
            status="enforced",
            policy_sha256=HASH_E,
            expected_chain_id=self._chain_id,
            pinned_block_number=self._block_number,
            pinned_block_hash=self._block_hash,
            preflight_origin_observation_sha256=observation_sha256,
            postflight_origin_observation_sha256=observation_sha256,
            origin_state_stable=True,
            http_request_count=1,
            permitted_rpc_call_count=1,
            origin_attempted_rpc_call_count=1,
            origin_validated_rpc_call_count=1,
            synthetic_rpc_call_count=0,
            denied_request_count=0,
            malformed_request_count=0,
            limit_exceeded_request_count=0,
            upstream_error_request_count=0,
            allowed_method_counts=(("eth_getCode", 1),),
            method_log_sha256=HASH_F,
            stopped_cleanly=True,
            snapshot_sha256=_canonical_sha256(values),
        )


class _Scanner:
    def __init__(
        self,
        harness: _Harness,
        *,
        chain_id: int,
        block_number: int,
        endpoint: str,
    ) -> None:
        self._harness = harness
        self._chain_id = chain_id
        self._block_number = block_number
        self._endpoint = endpoint

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
        del root, timeout_seconds, backend, expected_version, expected_sha256
        assert private_dir.is_dir()
        self._harness.attempt_directories.append(private_dir)
        self._harness.scanner_endpoints.append(self._endpoint)
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
        run = self._harness.execution_run(
            chain_id=self._chain_id,
            block_number=self._block_number,
            block_hash=block_hash,
            test_status=test_status,
            machine_result_sha256=result_hash,
        )
        if self._harness.retain_endpoint_in_run:
            payload = run.model_dump(mode="python")
            payload["error"] = f"Synthetic diagnostic retained {self._endpoint}"
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
        self.clean_provider = _CleanProvider()
        self.environment = {
            "MMAUDIT_PINNED_LOCAL_RPC_URL": "http://127.0.0.1:9200",
        }
        self.observer_calls: list[str] = []
        self.bridges: list[_Bridge] = []
        self.attempt_directories: list[Path] = []
        self.scanner_endpoints: list[str] = []
        self.scanner_invocations: dict[int, int] = {}
        self.unavailable_pinned = False
        self.drift_pinned = False
        self.advance_clock_after_first_scan = False
        self.retain_endpoint_in_run = False
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
            repository_test_executions=[execution],
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
    ) -> RepositorySuiteDifferentialRun:
        result = RepositoryForkMatrixRunner(
            self.smart_contracts,
            self.reproduction,
            dependencies=self.dependencies(clean=clean),
        ).run(
            tmp_path,
            tmp_path / ".private",
            projects=(),
            repository_sha256=HASH_B,
            repository_exclusion_root=tmp_path / ".private",
            backend=_Backend(),
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
    assert all(path.is_dir() for path in harness.attempt_directories)
    assert all(lease.stopped for lease in harness.clean_provider.leases)
    serialized = result.model_dump_json()
    for prohibited in ("http://", "127.0.0.1", str(tmp_path)):
        assert prohibited not in serialized


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
