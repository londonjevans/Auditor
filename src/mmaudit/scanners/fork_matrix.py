"""Deterministic repeated-state repository-suite execution.

This module keeps matrix evidence separate from the qualifying scanner portfolio.
Only endpoint-free bridge snapshots and typed runtime observations may enter the
serialized result.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from mmaudit.config import (
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkMatrixStateConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    ForkRpcReadOnlyEgressEvidence,
    RepositoryCleanStateAttestationEvidence,
    RepositoryCodeExecutionState,
    RepositoryDifferentialClassification,
    RepositoryDifferentialRunStatus,
    RepositoryExecutionStateKind,
    RepositoryExecutionStateObservationStatus,
    RepositoryForkEgressStatus,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteStateAttempt,
    RepositorySuiteTestComparison,
    RepositorySuiteTestStateConsensus,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
)
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    PinnedForkObservation,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge, ReadOnlyRpcBridgeSnapshot

_OBSERVATION_TIMEOUT_SECONDS = 5.0
_BRIDGE_SHUTDOWN_RESERVE_SECONDS = 1.0
_SCHEDULING_SLACK_SECONDS = 0.1
_ATTEMPT_CLEANUP_RESERVE_SECONDS = (
    _OBSERVATION_TIMEOUT_SECONDS + _BRIDGE_SHUTDOWN_RESERVE_SECONDS + _SCHEDULING_SLACK_SECONDS
)
_WORKSPACE_DISPOSAL_POLICY_SHA256 = hashlib.sha256(
    b'{"disposition":"private-root-lifecycle","endpoint_retained":false,'
    b'"path_retained":false,"version":"1.0"}'
).hexdigest()


class ForkMatrixScanner(Protocol):
    """Injected repository-suite scanner used by one matrix attempt."""

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun: ...


class ForkMatrixBridge(Protocol):
    """Small lifecycle surface required from a read-only RPC bridge."""

    @property
    def endpoint(self) -> str: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def snapshot(self) -> ReadOnlyRpcBridgeSnapshot: ...


class CleanStateLease(Protocol):
    """Trusted internally launched clean-chain lease."""

    @property
    def endpoint(self) -> str: ...

    def stop(self, deadline: float) -> None:
        """Stop the clean chain inside the caller's absolute deadline."""

    def attestation(self) -> RepositoryCleanStateAttestationEvidence:
        """Return endpoint-free evidence only after a clean stop."""


class CleanStateProvider(Protocol):
    """Injected clean-chain launcher; target repositories cannot provide it."""

    def start(
        self,
        config: RepositoryCleanForkMatrixStateConfig,
        repository_root: Path,
        private_root: Path,
        absolute_deadline: float,
    ) -> CleanStateLease: ...


class ForkStateObserver(Protocol):
    def __call__(
        self,
        endpoint: str,
        *,
        expected_chain_id: int | None,
        pinned_block_number: int | None,
        timeout_seconds: float,
    ) -> PinnedForkObservation: ...


class ForkBridgeFactory(Protocol):
    def __call__(
        self,
        origin_endpoint: str,
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
        timeout_seconds: float,
    ) -> ForkMatrixBridge: ...


class ForkScannerFactory(Protocol):
    def __call__(
        self,
        config: SmartContractsConfig,
        *,
        reproduction: ReproductionConfig,
        projects: Sequence[SolidityProjectMetadata],
        allow_fork_probing: bool,
        expected_repository_sha256: str,
        repository_exclusion_root: Path,
        fork_rpc_url_override: str,
    ) -> ForkMatrixScanner: ...


def _default_bridge_factory(
    origin_endpoint: str,
    *,
    expected_chain_id: int,
    pinned_block_number: int,
    pinned_block_hash: str,
    timeout_seconds: float,
) -> ForkMatrixBridge:
    return ReadOnlyRpcBridge(
        origin_endpoint,
        expected_chain_id=expected_chain_id,
        pinned_block_number=pinned_block_number,
        pinned_block_hash=pinned_block_hash,
        timeout_seconds=timeout_seconds,
        shutdown_timeout_seconds=min(
            _BRIDGE_SHUTDOWN_RESERVE_SECONDS,
            timeout_seconds,
        ),
    )


def _default_scanner_factory(
    config: SmartContractsConfig,
    *,
    reproduction: ReproductionConfig,
    projects: Sequence[SolidityProjectMetadata],
    allow_fork_probing: bool,
    expected_repository_sha256: str,
    repository_exclusion_root: Path,
    fork_rpc_url_override: str,
) -> ForkMatrixScanner:
    return FoundryForkScanner(
        config,
        reproduction=reproduction,
        projects=projects,
        allow_fork_probing=allow_fork_probing,
        expected_repository_sha256=expected_repository_sha256,
        repository_exclusion_root=repository_exclusion_root,
        fork_rpc_url_override=fork_rpc_url_override,
    )


@dataclass(frozen=True)
class ForkMatrixDependencies:
    """Trusted dependencies injected so unit tests never bind sockets or execute tools."""

    observer: ForkStateObserver = observe_pinned_fork_rpc
    bridge_factory: ForkBridgeFactory = _default_bridge_factory
    scanner_factory: ForkScannerFactory = _default_scanner_factory
    clean_state_provider: CleanStateProvider | None = None
    environment: Mapping[str, str] | None = None
    monotonic: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    nonce: Callable[[], str] = field(default=lambda: secrets.token_hex(32))


@dataclass
class _RawAttempt:
    index: int
    workspace_identity_sha256: str
    workspace_freshness_attestation_sha256: str
    scanner_run: ScannerRun
    snapshot: ReadOnlyRpcBridgeSnapshot | None = None


@dataclass
class _RawState:
    config: RepositoryForkMatrixStateConfig
    attempts: list[_RawAttempt]
    observations: list[PinnedForkObservation]
    observation_status: RepositoryExecutionStateObservationStatus
    observation_detail: str | None
    clean_attestation: RepositoryCleanStateAttestationEvidence | None = None


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _unavailable_run(
    detail: str,
    *,
    now: Callable[[], datetime],
    status: ScannerStatus = ScannerStatus.UNAVAILABLE,
) -> ScannerRun:
    observed_at = now()
    return ScannerRun(
        scanner="foundry_fork",
        status=status,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        started_at=observed_at,
        finished_at=observed_at,
        duration_seconds=0,
        error=detail,
    )


def _reseal_run(
    run: ScannerRun,
    *,
    egress: ForkRpcReadOnlyEgressEvidence | None,
) -> ScannerRun:
    """Attach endpoint-free egress, discard private paths, and rebind the observation."""

    payload = run.model_dump(mode="python")
    payload["raw_output_path"] = None
    payload["fork_rpc_egress"] = egress
    payload["execution_observation_sha256"] = None
    provisional = ScannerRun.model_validate(payload)
    payload["execution_observation_sha256"] = provisional.expected_execution_observation_sha256()
    return ScannerRun.model_validate(payload)


def _remove_ephemeral_run_data(
    run: ScannerRun,
    *,
    origin_endpoint: str,
    bridge_endpoint: str,
    attempt_dir: Path,
    matrix_root: Path,
) -> ScannerRun:
    """Reject evidence that retains an endpoint or private workspace identity."""

    sanitized = _reseal_run(run, egress=None)
    serialized = sanitized.model_dump_json()
    prohibited = (
        origin_endpoint,
        bridge_endpoint,
        str(attempt_dir),
        str(matrix_root),
        "http://localhost:",
        "http://127.0.0.1:",
        "http://[::1]:",
    )
    if any(value and value in serialized for value in prohibited):
        return _unavailable_run(
            "The matrix attempt retained prohibited ephemeral execution data.",
            now=lambda: sanitized.finished_at,
            status=ScannerStatus.FAILED,
        )
    return sanitized


def _baseline_limitation(
    run: ScannerRun,
    *,
    repository_sha256: str,
    smart_contracts: SmartContractsConfig,
) -> str | None:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    if (
        run.scanner != "foundry_fork"
        or run.status is not ScannerStatus.SUCCESS
        or run.execution_evidence is not ExecutionEvidenceKind.REAL
        or run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
        or run.isolation_backend is None
        or run.isolation_attestation_sha256 is None
        or not run.machine_output_validated
        or run.execution_observation_sha256 is None
        or run.execution_observation_sha256 != run.expected_execution_observation_sha256()
        or selection is None
        or policy is None
        or not selection.tests
    ):
        return "The qualifying baseline Foundry execution evidence was incomplete."
    if (
        selection.repository_sha256 != repository_sha256
        or selection.configuration_sha256 != smart_contracts.repository_suite.stable_hash()
        or policy.selection_sha256 != selection.selection_sha256
        or policy.selection_configuration_sha256 != selection.configuration_sha256
        or policy.fuzz_seed != smart_contracts.repository_suite.fuzz_seed
        or policy.isolation_backend != run.isolation_backend
        or policy.isolation_attestation_sha256 != run.isolation_attestation_sha256
    ):
        return "The qualifying baseline Foundry identity differed from the matrix configuration."
    descriptor_hashes = {descriptor.descriptor_sha256 for descriptor in selection.tests}
    executions_by_descriptor = {
        execution.descriptor_sha256: execution for execution in run.repository_test_executions
    }
    if set(executions_by_descriptor) != descriptor_hashes or any(
        execution.execution_evidence is not ExecutionEvidenceKind.REAL
        or not execution.machine_output_validated
        for execution in executions_by_descriptor.values()
    ):
        return "The qualifying baseline did not bind every selected test to real machine output."
    return None


class RepositoryForkMatrixRunner:
    """Execute a configured clean-versus-pinned matrix under one absolute deadline."""

    def __init__(
        self,
        smart_contracts: SmartContractsConfig,
        reproduction: ReproductionConfig,
        *,
        dependencies: ForkMatrixDependencies | None = None,
    ) -> None:
        self.smart_contracts = smart_contracts
        self.reproduction = reproduction
        self.dependencies = dependencies or ForkMatrixDependencies()

    def run(
        self,
        root: Path,
        private_root: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: ScannerIsolationBackend,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun | None:
        suite = self.smart_contracts.repository_suite
        configured_states = tuple(suite.fork_matrix_states)
        if not configured_states:
            return None
        configuration_sha256 = suite.stable_hash()
        requested_state_ids = tuple(state.state_id for state in configured_states)

        def failed(detail: str) -> RepositorySuiteDifferentialRun:
            return RepositorySuiteDifferentialRun.sealed(
                status=RepositoryDifferentialRunStatus.FAILED,
                configuration_sha256=configuration_sha256,
                requested_state_ids=requested_state_ids,
                required_repetitions=suite.fork_matrix_repetitions,
                matrix=None,
                limitations=(detail,),
            )

        baseline_error = _baseline_limitation(
            baseline_run,
            repository_sha256=repository_sha256,
            smart_contracts=self.smart_contracts,
        )
        if baseline_error is not None:
            return failed(baseline_error)
        if self.dependencies.clean_state_provider is None:
            return failed("The trusted internal clean-state launcher was unavailable.")
        if self.dependencies.monotonic() >= absolute_deadline:
            return failed("The differential matrix deadline expired before execution.")

        try:
            private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            matrix_nonce = self.dependencies.nonce()
            if (
                not matrix_nonce
                or len(matrix_nonce) > 256
                or any(ord(character) < 33 or ord(character) > 126 for character in matrix_nonce)
            ):
                return failed("The fresh-workspace nonce source returned invalid data.")
            matrix_nonce_sha256 = hashlib.sha256(matrix_nonce.encode("utf-8")).hexdigest()
            matrix_root = private_root / f"repository-fork-matrix-{matrix_nonce_sha256[:16]}"
            matrix_root.mkdir(mode=0o700, exist_ok=False)
        except OSError:
            return failed("The private differential workspace could not be created.")

        limitations: list[str] = []
        raw_states: list[_RawState] = []
        try:
            for state_config in configured_states:
                raw_states.append(
                    self._execute_state(
                        state_config,
                        root=root,
                        matrix_root=matrix_root,
                        matrix_nonce_sha256=matrix_nonce_sha256,
                        projects=projects,
                        repository_sha256=repository_sha256,
                        repository_exclusion_root=repository_exclusion_root,
                        backend=backend,
                        absolute_deadline=absolute_deadline,
                        limitations=limitations,
                    )
                )
            states = tuple(
                self._seal_state(raw_state)
                for raw_state in sorted(raw_states, key=lambda item: item.config.state_id)
            )
        except (OSError, RuntimeError, ValueError):
            return failed("The differential state evidence failed closed.")
        snapshots = [
            attempt.snapshot
            for raw_state in raw_states
            for attempt in raw_state.attempts
            if attempt.snapshot is not None
        ]
        if not snapshots:
            return failed("No stopped read-only RPC bridge produced matrix evidence.")
        policy_hashes = tuple(sorted({snapshot.policy_sha256 for snapshot in snapshots}))
        fork_rpc_policy_sha256 = policy_hashes[0]
        if len(policy_hashes) != 1:
            limitations.append("Read-only RPC bridge policies differed across matrix attempts.")

        states_by_id = {state.state_id: state for state in states}
        attempts: list[RepositorySuiteStateAttempt] = []
        for raw_state in sorted(raw_states, key=lambda item: item.config.state_id):
            state = states_by_id[raw_state.config.state_id]
            for raw_attempt in sorted(raw_state.attempts, key=lambda item: item.index):
                egress: ForkRpcReadOnlyEgressEvidence | None = None
                if (
                    raw_attempt.snapshot is not None
                    and raw_attempt.scanner_run.repository_suite_execution_policy is not None
                ):
                    try:
                        egress = fork_rpc_egress_from_snapshot(raw_attempt.snapshot, state)
                    except (TypeError, ValueError):
                        limitations.append(
                            f"State {state.state_id} had bridge evidence that did not bind "
                            "its final state identity."
                        )
                run = _reseal_run(raw_attempt.scanner_run, egress=egress)
                attempts.append(
                    RepositorySuiteStateAttempt.sealed(
                        state_id=state.state_id,
                        state_sha256=state.state_sha256,
                        attempt_index=raw_attempt.index,
                        workspace_kind="fresh_disposable_copy",
                        workspace_identity_sha256=raw_attempt.workspace_identity_sha256,
                        workspace_freshness_attestation_sha256=(
                            raw_attempt.workspace_freshness_attestation_sha256
                        ),
                        workspace_disposal_policy_sha256=(_WORKSPACE_DISPOSAL_POLICY_SHA256),
                        fork_rpc_egress_sha256=(
                            egress.evidence_sha256 if egress is not None else None
                        ),
                        scanner_run=run,
                    )
                )

        selection = baseline_run.repository_suite_selection
        policy = baseline_run.repository_suite_execution_policy
        assert selection is not None
        assert policy is not None
        descriptor_sha256s = tuple(
            sorted(descriptor.descriptor_sha256 for descriptor in selection.tests)
        )
        execution_configuration_sha256 = (
            RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(policy)
        )
        attempts_tuple = tuple(
            sorted(attempts, key=lambda item: (item.state_id, item.attempt_index))
        )
        matrix_shell = RepositorySuiteDifferentialMatrix.model_construct(
            repository_sha256=repository_sha256,
            selection_sha256=selection.selection_sha256,
            selection_configuration_sha256=selection.configuration_sha256,
            descriptor_sha256s=descriptor_sha256s,
            required_repetitions=suite.fork_matrix_repetitions,
            fuzz_seed=suite.fuzz_seed,
            execution_configuration_sha256=execution_configuration_sha256,
            fork_rpc_policy_sha256=fork_rpc_policy_sha256,
            states=states,
            attempts=attempts_tuple,
            state_consensuses=(),
            comparisons=(),
            safety_claim=False,
            matrix_sha256="0" * 64,
        )
        consensuses: list[RepositorySuiteTestStateConsensus] = []
        for state in states:
            state_attempts = tuple(
                attempt for attempt in attempts_tuple if attempt.state_id == state.state_id
            )
            for descriptor_sha256 in descriptor_sha256s:
                (
                    consensus_status,
                    observed_status,
                    machine_result_sha256,
                    reasons,
                ) = matrix_shell._expected_consensus(
                    state,
                    state_attempts,
                    descriptor_sha256,
                )
                consensuses.append(
                    RepositorySuiteTestStateConsensus.sealed(
                        state_id=state.state_id,
                        state_sha256=state.state_sha256,
                        descriptor_sha256=descriptor_sha256,
                        status=consensus_status,
                        attempt_sha256s=tuple(
                            sorted(attempt.attempt_sha256 for attempt in state_attempts)
                        ),
                        observed_status=observed_status,
                        machine_result_sha256=machine_result_sha256,
                        inconclusive_reasons=reasons,
                    )
                )
        consensus_tuple = tuple(
            sorted(
                consensuses,
                key=lambda item: (item.state_id, item.descriptor_sha256),
            )
        )
        consensus_by_key = {
            (consensus.state_id, consensus.descriptor_sha256): consensus
            for consensus in consensus_tuple
        }
        clean = next(
            state for state in states if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL
        )
        comparisons: list[RepositorySuiteTestComparison] = []
        for pinned in (
            state for state in states if state.kind is RepositoryExecutionStateKind.PINNED_FORK
        ):
            for descriptor_sha256 in descriptor_sha256s:
                clean_consensus = consensus_by_key[(clean.state_id, descriptor_sha256)]
                pinned_consensus = consensus_by_key[(pinned.state_id, descriptor_sha256)]
                classification, direction = RepositorySuiteDifferentialMatrix._expected_comparison(
                    clean_consensus,
                    pinned_consensus,
                )
                comparisons.append(
                    RepositorySuiteTestComparison.sealed(
                        clean_state_id=clean.state_id,
                        clean_state_sha256=clean.state_sha256,
                        pinned_state_id=pinned.state_id,
                        pinned_state_sha256=pinned.state_sha256,
                        descriptor_sha256=descriptor_sha256,
                        clean_consensus_sha256=clean_consensus.consensus_sha256,
                        pinned_consensus_sha256=pinned_consensus.consensus_sha256,
                        classification=classification,
                        direction=direction,
                    )
                )
        comparisons_tuple = tuple(
            sorted(
                comparisons,
                key=lambda item: (item.pinned_state_id, item.descriptor_sha256),
            )
        )
        try:
            matrix = RepositorySuiteDifferentialMatrix.sealed(
                repository_sha256=repository_sha256,
                selection_sha256=selection.selection_sha256,
                selection_configuration_sha256=selection.configuration_sha256,
                descriptor_sha256s=descriptor_sha256s,
                required_repetitions=suite.fork_matrix_repetitions,
                fuzz_seed=suite.fuzz_seed,
                execution_configuration_sha256=execution_configuration_sha256,
                fork_rpc_policy_sha256=fork_rpc_policy_sha256,
                states=states,
                attempts=attempts_tuple,
                state_consensuses=consensus_tuple,
                comparisons=comparisons_tuple,
                safety_claim=False,
            )
        except ValueError:
            return failed("The differential matrix evidence failed typed validation.")

        has_inconclusive = any(
            comparison.classification is RepositoryDifferentialClassification.INCONCLUSIVE
            for comparison in matrix.comparisons
        )
        if has_inconclusive:
            limitations.append("At least one clean-versus-pinned comparison was inconclusive.")
        unique_limitations = tuple(dict.fromkeys(limitations))
        status = (
            RepositoryDifferentialRunStatus.INCONCLUSIVE
            if has_inconclusive
            else RepositoryDifferentialRunStatus.COMPLETE
        )
        if status is RepositoryDifferentialRunStatus.COMPLETE:
            unique_limitations = ()
        return RepositorySuiteDifferentialRun.sealed(
            status=status,
            configuration_sha256=configuration_sha256,
            requested_state_ids=requested_state_ids,
            required_repetitions=suite.fork_matrix_repetitions,
            matrix=matrix,
            limitations=unique_limitations,
        )

    def _execute_state(
        self,
        state_config: RepositoryForkMatrixStateConfig,
        *,
        root: Path,
        matrix_root: Path,
        matrix_nonce_sha256: str,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: ScannerIsolationBackend,
        absolute_deadline: float,
        limitations: list[str],
    ) -> _RawState:
        repetitions = self.smart_contracts.repository_suite.fork_matrix_repetitions
        attempts: list[_RawAttempt] = []
        observations: list[PinnedForkObservation] = []
        completed_observation_pairs = 0
        observation_status = RepositoryExecutionStateObservationStatus.OBSERVED
        observation_detail: str | None = None
        clean_lease: CleanStateLease | None = None
        endpoint: str | None = None

        if isinstance(state_config, RepositoryCleanForkMatrixStateConfig):
            provider = self.dependencies.clean_state_provider
            assert provider is not None
            try:
                if (
                    self.dependencies.monotonic() + state_config.shutdown_timeout_seconds
                    >= absolute_deadline
                ):
                    raise TimeoutError
                clean_private = matrix_root / f"{state_config.state_id}-clean-origin"
                clean_private.mkdir(mode=0o700, exist_ok=False)
                clean_lease = provider.start(
                    state_config,
                    root,
                    clean_private,
                    absolute_deadline,
                )
                endpoint = clean_lease.endpoint
                local_fork_rpc_port(endpoint)
            except (ForkRpcBindingError, OSError, RuntimeError, TimeoutError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The trusted clean-state launcher failed closed."
        else:
            environment = self.dependencies.environment
            if environment is None:
                environment = os.environ
            endpoint = environment.get(state_config.rpc_url_env)
            if not endpoint:
                observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                observation_detail = "The configured local pinned state was unavailable."
            else:
                try:
                    local_fork_rpc_port(endpoint)
                except ForkRpcBindingError:
                    endpoint = None
                    observation_status = RepositoryExecutionStateObservationStatus.FAILED
                    observation_detail = "The configured pinned state endpoint was invalid."

        state_execution_deadline = (
            absolute_deadline - state_config.shutdown_timeout_seconds
            if isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
            else absolute_deadline
        )
        for index in range(1, repetitions + 1):
            try:
                attempt_dir, identity_sha256, freshness_sha256 = self._fresh_attempt_dir(
                    matrix_root,
                    matrix_nonce_sha256=matrix_nonce_sha256,
                    state_id=state_config.state_id,
                    attempt_index=index,
                    repository_sha256=repository_sha256,
                )
            except OSError:
                if clean_lease is not None:
                    with suppress(OSError, RuntimeError, ValueError):
                        clean_lease.stop(absolute_deadline)
                raise
            if endpoint is None or self.dependencies.monotonic() >= state_execution_deadline:
                detail = (
                    observation_detail
                    or "The differential matrix deadline expired before this attempt."
                )
                if endpoint is not None:
                    limitations.append(
                        f"State {state_config.state_id} exceeded the matrix deadline."
                    )
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        scanner_run=_unavailable_run(
                            detail,
                            now=self.dependencies.now,
                            status=(
                                ScannerStatus.TIMED_OUT
                                if endpoint is not None
                                else ScannerStatus.UNAVAILABLE
                            ),
                        ),
                    )
                )
                continue

            expected_chain_id = state_config.expected_chain_id
            pinned_block_number = (
                0
                if isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
                else state_config.pinned_block_number
            )
            remaining = state_execution_deadline - self.dependencies.monotonic()
            try:
                pre = self.dependencies.observer(
                    endpoint,
                    expected_chain_id=expected_chain_id,
                    pinned_block_number=pinned_block_number,
                    timeout_seconds=min(_OBSERVATION_TIMEOUT_SECONDS, remaining),
                )
                observations.append(pre)
            except ForkRpcUnavailableError:
                observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                observation_detail = "The configured local state was unavailable."
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        scanner_run=_unavailable_run(
                            observation_detail,
                            now=self.dependencies.now,
                        ),
                    )
                )
                continue
            except (ForkRpcBindingError, RuntimeError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The configured local state identity was invalid."
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        scanner_run=_unavailable_run(
                            observation_detail,
                            now=self.dependencies.now,
                            status=ScannerStatus.FAILED,
                        ),
                    )
                )
                continue

            bridge: ForkMatrixBridge | None = None
            snapshot: ReadOnlyRpcBridgeSnapshot | None = None
            run = _unavailable_run(
                "The read-only RPC bridge was unavailable.",
                now=self.dependencies.now,
            )
            try:
                remaining = state_execution_deadline - self.dependencies.monotonic()
                if remaining <= _ATTEMPT_CLEANUP_RESERVE_SECONDS:
                    raise TimeoutError
                bridge = self.dependencies.bridge_factory(
                    endpoint,
                    expected_chain_id=pre.chain_id,
                    pinned_block_number=pre.block_number,
                    pinned_block_hash=pre.block_hash,
                    timeout_seconds=min(_OBSERVATION_TIMEOUT_SECONDS, remaining),
                )
                bridge.start()
                bridge_endpoint = bridge.endpoint
                state_smart_contracts = self.smart_contracts.model_copy(
                    update={
                        "fork_rpc_url_env": (
                            state_config.rpc_url_env
                            if isinstance(
                                state_config,
                                RepositoryPinnedForkMatrixStateConfig,
                            )
                            else self.smart_contracts.fork_rpc_url_env
                        )
                    }
                )
                state_reproduction = self.reproduction.model_copy(
                    update={
                        "expected_chain_id": pre.chain_id,
                        "pinned_block_number": pre.block_number,
                    }
                )
                scanner = self.dependencies.scanner_factory(
                    state_smart_contracts,
                    reproduction=state_reproduction,
                    projects=projects,
                    allow_fork_probing=True,
                    expected_repository_sha256=repository_sha256,
                    repository_exclusion_root=repository_exclusion_root,
                    fork_rpc_url_override=bridge_endpoint,
                )
                remaining = state_execution_deadline - self.dependencies.monotonic()
                if remaining <= _ATTEMPT_CLEANUP_RESERVE_SECONDS:
                    raise TimeoutError
                run = scanner.run(
                    root,
                    attempt_dir,
                    remaining - _ATTEMPT_CLEANUP_RESERVE_SECONDS,
                    backend=backend,
                )
                run = _remove_ephemeral_run_data(
                    run,
                    origin_endpoint=endpoint,
                    bridge_endpoint=bridge_endpoint,
                    attempt_dir=attempt_dir,
                    matrix_root=matrix_root,
                )
            except TimeoutError:
                run = _unavailable_run(
                    "The differential matrix deadline expired during this attempt.",
                    now=self.dependencies.now,
                    status=ScannerStatus.TIMED_OUT,
                )
                limitations.append(f"State {state_config.state_id} exceeded the matrix deadline.")
            except (OSError, RuntimeError, ValueError):
                run = _unavailable_run(
                    "The differential repository-suite attempt failed closed.",
                    now=self.dependencies.now,
                    status=ScannerStatus.FAILED,
                )
            finally:
                if bridge is not None:
                    try:
                        bridge.stop()
                        snapshot = bridge.snapshot()
                    except (OSError, RuntimeError, ValueError):
                        snapshot = None
                        limitations.append(
                            f"State {state_config.state_id} had an unverified RPC bridge stop."
                        )

            if self.dependencies.monotonic() >= state_execution_deadline:
                run = _unavailable_run(
                    "The differential matrix absolute deadline was exceeded.",
                    now=self.dependencies.now,
                    status=ScannerStatus.TIMED_OUT,
                )
                limitations.append(f"State {state_config.state_id} exceeded the matrix deadline.")
            else:
                try:
                    post = self.dependencies.observer(
                        endpoint,
                        expected_chain_id=expected_chain_id,
                        pinned_block_number=pinned_block_number,
                        timeout_seconds=min(
                            _OBSERVATION_TIMEOUT_SECONDS,
                            state_execution_deadline - self.dependencies.monotonic(),
                        ),
                    )
                    observations.append(post)
                    completed_observation_pairs += 1
                    if post != pre:
                        observation_status = RepositoryExecutionStateObservationStatus.FAILED
                        observation_detail = (
                            "The configured local state identity changed during execution."
                        )
                except ForkRpcUnavailableError:
                    observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                    observation_detail = (
                        "The configured local state became unavailable after execution."
                    )
                except (ForkRpcBindingError, RuntimeError, ValueError):
                    observation_status = RepositoryExecutionStateObservationStatus.FAILED
                    observation_detail = (
                        "The configured local state identity could not be revalidated."
                    )
            attempts.append(
                _RawAttempt(
                    index=index,
                    workspace_identity_sha256=identity_sha256,
                    workspace_freshness_attestation_sha256=freshness_sha256,
                    scanner_run=run,
                    snapshot=snapshot,
                )
            )

        clean_attestation: RepositoryCleanStateAttestationEvidence | None = None
        if clean_lease is not None:
            try:
                clean_lease.stop(absolute_deadline)
                clean_attestation = clean_lease.attestation()
            except (OSError, RuntimeError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The trusted clean state did not stop with attested evidence."
        if (
            not observations
            and observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
        ):
            observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
            observation_detail = "The configured local state produced no identity observation."
        elif observations and len(set(observations)) != 1:
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = "The configured local state identity changed during execution."
        elif (
            observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
            and completed_observation_pairs != repetitions
        ):
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = (
                "The configured local state lacked complete pre/post attempt observations."
            )
        if (
            isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
            and clean_attestation is None
        ):
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = "The trusted clean state lacked final process attestation."
        return _RawState(
            config=state_config,
            attempts=attempts,
            observations=observations,
            observation_status=observation_status,
            observation_detail=observation_detail,
            clean_attestation=clean_attestation,
        )

    def _fresh_attempt_dir(
        self,
        matrix_root: Path,
        *,
        matrix_nonce_sha256: str,
        state_id: str,
        attempt_index: int,
        repository_sha256: str,
    ) -> tuple[Path, str, str]:
        attempt_dir = matrix_root / f"{state_id}-attempt-{attempt_index}"
        attempt_dir.mkdir(mode=0o700, exist_ok=False)
        stat = attempt_dir.stat()
        identity_sha256 = _canonical_sha256(
            {
                "matrix_nonce_sha256": matrix_nonce_sha256,
                "repository_sha256": repository_sha256,
                "state_id": state_id,
                "attempt_index": attempt_index,
            }
        )
        freshness_sha256 = _canonical_sha256(
            {
                "workspace_identity_sha256": identity_sha256,
                "created_with_exist_ok_false": True,
                "device": stat.st_dev,
                "inode": stat.st_ino,
            }
        )
        return attempt_dir, identity_sha256, freshness_sha256

    @staticmethod
    def _seal_state(raw: _RawState) -> RepositorySuiteExecutionStateEvidence:
        config = raw.config
        observed = (
            raw.observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
            and raw.observations
            and len(set(raw.observations)) == 1
        )
        observation = raw.observations[0] if observed else None
        if isinstance(config, RepositoryCleanForkMatrixStateConfig):
            attestation = raw.clean_attestation
            if attestation is None:
                observed = False
                observation = None
                state_source_sha256 = config.anvil_sha256
                attestation = None
            else:
                state_source_sha256 = attestation.expected_state_source_sha256()
            return RepositorySuiteExecutionStateEvidence.sealed(
                state_id=config.state_id,
                kind=RepositoryExecutionStateKind.CLEAN_LOCAL,
                rpc_url_env=None,
                state_source_sha256=state_source_sha256,
                expected_chain_id=config.expected_chain_id,
                pinned_block_number=0,
                observation_status=(
                    RepositoryExecutionStateObservationStatus.OBSERVED
                    if observed
                    else raw.observation_status
                ),
                observed_chain_id=observation.chain_id if observation is not None else None,
                observed_block_number=(
                    observation.block_number if observation is not None else None
                ),
                observed_block_hash=observation.block_hash if observation is not None else None,
                clean_state_attestation=attestation if observed else None,
                observation_detail=(
                    None
                    if observed
                    else raw.observation_detail or "The trusted clean state was not observed."
                ),
            )
        return RepositorySuiteExecutionStateEvidence.sealed(
            state_id=config.state_id,
            kind=RepositoryExecutionStateKind.PINNED_FORK,
            rpc_url_env=config.rpc_url_env,
            state_source_sha256=config.state_source_sha256,
            expected_chain_id=config.expected_chain_id,
            pinned_block_number=config.pinned_block_number,
            observation_status=(
                RepositoryExecutionStateObservationStatus.OBSERVED
                if observed
                else raw.observation_status
            ),
            observed_chain_id=observation.chain_id if observation is not None else None,
            observed_block_number=observation.block_number if observation is not None else None,
            observed_block_hash=observation.block_hash if observation is not None else None,
            observation_detail=(
                None if observed else raw.observation_detail or "The pinned state was not observed."
            ),
        )


def run_repository_fork_matrix(
    smart_contracts: SmartContractsConfig,
    reproduction: ReproductionConfig,
    root: Path,
    private_root: Path,
    *,
    projects: Sequence[SolidityProjectMetadata],
    repository_sha256: str,
    repository_exclusion_root: Path,
    backend: ScannerIsolationBackend,
    baseline_run: ScannerRun,
    absolute_deadline: float,
    dependencies: ForkMatrixDependencies | None = None,
) -> RepositorySuiteDifferentialRun | None:
    """Functional wrapper used by orchestration without adding child runs to its portfolio."""

    return RepositoryForkMatrixRunner(
        smart_contracts,
        reproduction,
        dependencies=dependencies,
    ).run(
        root,
        private_root,
        projects=projects,
        repository_sha256=repository_sha256,
        repository_exclusion_root=repository_exclusion_root,
        backend=backend,
        baseline_run=baseline_run,
        absolute_deadline=absolute_deadline,
    )


def fork_rpc_egress_from_snapshot(
    snapshot: ReadOnlyRpcBridgeSnapshot,
    state: RepositorySuiteExecutionStateEvidence,
) -> ForkRpcReadOnlyEgressEvidence:
    """Bind one stopped bridge snapshot to its already observed execution state."""

    if (
        state.observation_status is not RepositoryExecutionStateObservationStatus.OBSERVED
        or state.observed_chain_id != snapshot.expected_chain_id
        or state.observed_block_number != snapshot.pinned_block_number
        or state.observed_block_hash != snapshot.pinned_block_hash
    ):
        raise ValueError("read-only bridge snapshot differs from its observed state identity")
    return ForkRpcReadOnlyEgressEvidence.sealed(
        status=RepositoryForkEgressStatus(snapshot.status),
        state_id=state.state_id,
        state_source_sha256=state.state_source_sha256,
        expected_chain_id=snapshot.expected_chain_id,
        pinned_block_number=snapshot.pinned_block_number,
        pinned_block_hash=snapshot.pinned_block_hash,
        policy_sha256=snapshot.policy_sha256,
        method_log_sha256=snapshot.method_log_sha256,
        preflight_origin_observation_sha256=(snapshot.preflight_origin_observation_sha256),
        postflight_origin_observation_sha256=(snapshot.postflight_origin_observation_sha256),
        origin_state_stable=snapshot.origin_state_stable,
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
        stopped_cleanly=snapshot.stopped_cleanly,
        bridge_snapshot_sha256=snapshot.snapshot_sha256,
    )
