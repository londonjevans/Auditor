from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    _TRUSTED_READ_ONLY_FORK_RPC_METHODS,
    AuditReport,
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
    RepositoryDivergenceDirection,
    RepositoryExecutionStateKind,
    RepositoryExecutionStateObservationStatus,
    RepositoryForkEgressStatus,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositoryStateConsensusStatus,
    RepositoryStateInconclusiveReason,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteStateAttempt,
    RepositorySuiteTestComparison,
    RepositorySuiteTestDescriptor,
    RepositorySuiteTestStateConsensus,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.reporting.markdown import render_markdown
from mmaudit.scanners.read_only_rpc import _ALLOWED_METHODS, ReadOnlyRpcBridgeSnapshot

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
SEED = "0x" + ("0" * 63) + "1"
BASE_TIME = datetime(2026, 7, 29, 12, tzinfo=UTC)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _descriptor() -> RepositorySuiteTestDescriptor:
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root="contracts",
        path="contracts/test/Vault.t.sol",
        suite_name="VaultTest",
        test_name="testAccountingInvariant",
        source_sha256=HASH_A,
        start_line=10,
        end_line=12,
    )


def _selection(
    descriptor: RepositorySuiteTestDescriptor,
) -> RepositorySuiteSelection:
    return RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=HASH_B,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=HASH_C,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )


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
        environment_policy_sha256=HASH_D,
        process_attestation_sha256=HASH_C,
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
        genesis_block_hash="0x" + HASH_A,
        initial_head_block_number=0,
        initial_head_block_hash="0x" + HASH_A,
        initial_head_state_root="0x" + HASH_B,
        final_head_block_number=0,
        final_head_block_hash="0x" + HASH_A,
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


def _states(
    *,
    pinned_observation_status: RepositoryExecutionStateObservationStatus = (
        RepositoryExecutionStateObservationStatus.OBSERVED
    ),
) -> tuple[
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteExecutionStateEvidence,
]:
    clean_attestation = _clean_attestation()
    clean = RepositorySuiteExecutionStateEvidence.sealed(
        state_id="clean-local",
        kind=RepositoryExecutionStateKind.CLEAN_LOCAL,
        state_source_sha256=clean_attestation.expected_state_source_sha256(),
        expected_chain_id=31_337,
        pinned_block_number=0,
        observation_status=RepositoryExecutionStateObservationStatus.OBSERVED,
        observed_chain_id=31_337,
        observed_block_number=0,
        observed_block_hash="0x" + HASH_A,
        clean_state_attestation=clean_attestation,
    )
    observed = pinned_observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
    pinned = RepositorySuiteExecutionStateEvidence.sealed(
        state_id="pinned-state",
        kind=RepositoryExecutionStateKind.PINNED_FORK,
        rpc_url_env="MMAUDIT_PINNED_RPC_URL",
        state_source_sha256=HASH_D,
        expected_chain_id=31_338,
        pinned_block_number=77,
        observation_status=pinned_observation_status,
        observed_chain_id=31_338 if observed else None,
        observed_block_number=77 if observed else None,
        observed_block_hash=("0x" + HASH_D) if observed else None,
        observation_detail=None if observed else "The configured local endpoint was unavailable.",
    )
    return clean, pinned


def _egress(
    state: RepositorySuiteExecutionStateEvidence,
    *,
    status: RepositoryForkEgressStatus = RepositoryForkEgressStatus.ENFORCED,
) -> ForkRpcReadOnlyEgressEvidence:
    assert state.observed_block_hash is not None
    violation = 1 if status is RepositoryForkEgressStatus.VIOLATION else 0
    method_counts = (
        ForkRpcMethodCount(method="eth_chainId", count=1),
        ForkRpcMethodCount(method="eth_getCode", count=1),
    )
    observation_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
        expected_chain_id=state.expected_chain_id,
        pinned_block_number=state.pinned_block_number,
        pinned_block_hash=state.observed_block_hash,
    )
    snapshot_values = {
        "schema_version": "2.0",
        "status": status,
        "policy_sha256": HASH_E,
        "expected_chain_id": state.expected_chain_id,
        "pinned_block_number": state.pinned_block_number,
        "pinned_block_hash": state.observed_block_hash,
        "preflight_origin_observation_sha256": observation_sha256,
        "postflight_origin_observation_sha256": observation_sha256,
        "origin_state_stable": True,
        "http_request_count": 2 + violation,
        "permitted_rpc_call_count": 2,
        "origin_attempted_rpc_call_count": 1,
        "origin_validated_rpc_call_count": 1,
        "synthetic_rpc_call_count": 1,
        "denied_request_count": violation,
        "malformed_request_count": 0,
        "limit_exceeded_request_count": 0,
        "upstream_error_request_count": 0,
        "allowed_method_counts": [item.model_dump(mode="json") for item in method_counts],
        "method_log_sha256": HASH_F,
        "stopped_cleanly": True,
    }
    bridge_snapshot_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(
        snapshot_values
    )
    return ForkRpcReadOnlyEgressEvidence.sealed(
        status=status,
        state_id=state.state_id,
        state_source_sha256=state.state_source_sha256,
        expected_chain_id=state.expected_chain_id,
        pinned_block_number=state.pinned_block_number,
        pinned_block_hash=state.observed_block_hash,
        boundary_kind="trusted_read_only_loopback_bridge",
        network_scope="single_loopback_origin",
        policy_sha256=HASH_E,
        method_log_sha256=HASH_F,
        preflight_origin_observation_sha256=observation_sha256,
        postflight_origin_observation_sha256=observation_sha256,
        origin_state_stable=True,
        allowed_method_counts=method_counts,
        http_request_count=2 + violation,
        permitted_rpc_call_count=2,
        origin_attempted_rpc_call_count=1,
        origin_validated_rpc_call_count=1,
        synthetic_rpc_call_count=1,
        denied_request_count=violation,
        malformed_request_count=0,
        limit_exceeded_request_count=0,
        upstream_error_request_count=0,
        stopped_cleanly=True,
        transaction_capable_request_forwarded=False,
        credentials_forwarded=False,
        raw_payloads_retained=False,
        rpc_endpoint_recorded=False,
        bridge_snapshot_sha256=bridge_snapshot_sha256,
    )


def _policy(
    selection: RepositorySuiteSelection,
    state: RepositorySuiteExecutionStateEvidence,
) -> RepositorySuiteExecutionPolicy:
    assert state.observed_block_hash is not None
    return RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=state.expected_chain_id,
        block_number=state.pinned_block_number,
        block_hash=state.observed_block_hash,
        tool_version="forge 1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_D,
        isolation_backend="synthetic-hardened-isolation",
        isolation_attestation_sha256=HASH_C,
        fuzz_seed=SEED,
        fuzz_runs=256,
        invariant_runs=64,
        per_test_timeout_seconds=120,
        total_timeout_seconds=900,
        max_output_bytes_per_test=1_000_000,
        max_total_output_bytes=10_000_000,
    )


def _run(
    selection: RepositorySuiteSelection,
    descriptor: RepositorySuiteTestDescriptor,
    state: RepositorySuiteExecutionStateEvidence,
    *,
    attempt_index: int,
    status: RepositoryTestExecutionStatus,
    machine_result_sha256: str,
    evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    scanner_status: ScannerStatus = ScannerStatus.SUCCESS,
    egress_status: RepositoryForkEgressStatus = RepositoryForkEgressStatus.ENFORCED,
) -> ScannerRun:
    policy = _policy(selection, state)
    failed = status is not RepositoryTestExecutionStatus.PASSED
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=state.expected_chain_id,
        block_number=state.pinned_block_number,
        block_hash=state.observed_block_hash,
        fuzz_seed=SEED,
        test_kind=RepositoryTestKind.UNIT,
        status=status,
        terminal_detail="Synthetic invariant mismatch." if failed else None,
        duration_seconds=0.25,
        command_sha256=HASH_B,
        output_sha256=HASH_C,
        output_bytes=123,
        machine_result_sha256=machine_result_sha256,
        process_exit_code=1 if failed else 0,
        machine_output_validated=True,
        execution_evidence=evidence,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-hardened-isolation",
        isolation_attestation_sha256=HASH_C,
        compiler_version="solc 0.8.30",
        compiler_sha256=HASH_D,
        execution_policy_sha256=policy.policy_sha256,
    )
    findings = []
    if failed:
        findings = [
            ScannerFinding(
                scanner="foundry_fork",
                rule_id="repository-test-assertion",
                title="Synthetic accounting invariant failed",
                severity=Severity.HIGH,
                message="A synthetic local execution observed an incorrect state transition.",
                locations=[Location(path=descriptor.path, start_line=10, end_line=12)],
                metadata={"repository_test_execution_sha256": execution.execution_sha256},
                evidence_strength=(
                    EvidenceStrength.DETERMINISTIC_ANALYZER
                    if evidence is ExecutionEvidenceKind.REAL
                    else EvidenceStrength.NONE
                ),
                fingerprint=HASH_F,
            )
        ]
    egress = _egress(state, status=egress_status)
    observed_at = BASE_TIME + timedelta(seconds=attempt_index)
    run = ScannerRun(
        scanner="foundry_fork",
        status=scanner_status,
        execution_evidence=evidence,
        version="forge 1.3.2",
        executable_sha256=HASH_A,
        command=[
            "forge",
            "test",
            "[BOUNDED_PER_TEST_REPOSITORY_SUITE]",
            selection.selection_sha256,
        ],
        started_at=observed_at,
        finished_at=observed_at + timedelta(milliseconds=250),
        duration_seconds=0.25,
        findings=findings,
        process_exit_code=1 if failed else 0,
        isolation_backend="synthetic-hardened-isolation",
        isolation_attestation_sha256=HASH_C,
        machine_output_validated=True,
        foundry_summary=FoundryTestExecutionSummary(
            unit_tests=1,
            fuzz_tests=0,
            invariant_tests=0,
            passed_tests=0 if failed else 1,
            failed_tests=1 if failed else 0,
            skipped_tests=0,
            fuzz_cases=0,
            invariant_runs=0,
            invariant_calls=0,
        ),
        repository_suite_selection=selection,
        repository_suite_execution_policy=policy,
        repository_test_executions=[execution],
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        fork_rpc_egress=egress,
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _attempt(
    selection: RepositorySuiteSelection,
    descriptor: RepositorySuiteTestDescriptor,
    state: RepositorySuiteExecutionStateEvidence,
    *,
    attempt_index: int,
    status: RepositoryTestExecutionStatus,
    machine_result_sha256: str,
    evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    egress_status: RepositoryForkEgressStatus = RepositoryForkEgressStatus.ENFORCED,
) -> RepositorySuiteStateAttempt:
    run = _run(
        selection,
        descriptor,
        state,
        attempt_index=attempt_index,
        status=status,
        machine_result_sha256=machine_result_sha256,
        evidence=evidence,
        egress_status=egress_status,
    )
    workspace_digit = attempt_index + (
        0 if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL else 2
    )
    return RepositorySuiteStateAttempt.sealed(
        state_id=state.state_id,
        state_sha256=state.state_sha256,
        attempt_index=attempt_index,
        workspace_kind="fresh_disposable_copy",
        workspace_identity_sha256=(f"{workspace_digit:x}" * 64),
        workspace_freshness_attestation_sha256=(f"{workspace_digit + 4:x}" * 64),
        workspace_disposal_policy_sha256=(f"{workspace_digit + 8:x}" * 64),
        fork_rpc_egress_sha256=(
            run.fork_rpc_egress.evidence_sha256 if run.fork_rpc_egress is not None else None
        ),
        scanner_run=run,
    )


def _consensus(
    state: RepositorySuiteExecutionStateEvidence,
    descriptor: RepositorySuiteTestDescriptor,
    attempts: tuple[RepositorySuiteStateAttempt, ...],
    *,
    status: RepositoryStateConsensusStatus,
    observed_status: RepositoryTestExecutionStatus | None,
    machine_result_sha256: str | None,
    reasons: tuple[RepositoryStateInconclusiveReason, ...] = (),
) -> RepositorySuiteTestStateConsensus:
    return RepositorySuiteTestStateConsensus.sealed(
        state_id=state.state_id,
        state_sha256=state.state_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        status=status,
        attempt_sha256s=tuple(sorted(attempt.attempt_sha256 for attempt in attempts)),
        observed_status=observed_status,
        machine_result_sha256=machine_result_sha256,
        inconclusive_reasons=reasons,
    )


def _comparison(
    clean: RepositorySuiteExecutionStateEvidence,
    pinned: RepositorySuiteExecutionStateEvidence,
    descriptor: RepositorySuiteTestDescriptor,
    clean_consensus: RepositorySuiteTestStateConsensus,
    pinned_consensus: RepositorySuiteTestStateConsensus,
    *,
    classification: RepositoryDifferentialClassification,
    direction: RepositoryDivergenceDirection | None,
) -> RepositorySuiteTestComparison:
    return RepositorySuiteTestComparison.sealed(
        clean_state_id=clean.state_id,
        clean_state_sha256=clean.state_sha256,
        pinned_state_id=pinned.state_id,
        pinned_state_sha256=pinned.state_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        clean_consensus_sha256=clean_consensus.consensus_sha256,
        pinned_consensus_sha256=pinned_consensus.consensus_sha256,
        classification=classification,
        direction=direction,
    )


def _matrix(
    *,
    pinned_attempt_statuses: tuple[
        RepositoryTestExecutionStatus,
        RepositoryTestExecutionStatus,
    ] = (
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    ),
    pinned_hashes: tuple[str, str] = (HASH_F, HASH_F),
    pinned_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    clean_egress_status: RepositoryForkEgressStatus = RepositoryForkEgressStatus.ENFORCED,
    pinned_egress_status: RepositoryForkEgressStatus = RepositoryForkEgressStatus.ENFORCED,
    pinned_observation_status: RepositoryExecutionStateObservationStatus = (
        RepositoryExecutionStateObservationStatus.OBSERVED
    ),
    pinned_consensus_status: RepositoryStateConsensusStatus = (
        RepositoryStateConsensusStatus.CONSISTENT_FAILURE
    ),
    classification: RepositoryDifferentialClassification = (
        RepositoryDifferentialClassification.DIVERGED
    ),
    direction: RepositoryDivergenceDirection | None = (
        RepositoryDivergenceDirection.CLEAN_PASS_PINNED_FAILURE
    ),
    reasons: tuple[RepositoryStateInconclusiveReason, ...] = (),
) -> RepositorySuiteDifferentialMatrix:
    descriptor = _descriptor()
    selection = _selection(descriptor)
    clean, pinned = _states(pinned_observation_status=pinned_observation_status)
    clean_attempts = tuple(
        _attempt(
            selection,
            descriptor,
            clean,
            attempt_index=index,
            status=RepositoryTestExecutionStatus.PASSED,
            machine_result_sha256=HASH_E,
            egress_status=clean_egress_status,
        )
        for index in (1, 2)
    )
    if pinned_observation_status is RepositoryExecutionStateObservationStatus.OBSERVED:
        pinned_attempts = tuple(
            _attempt(
                selection,
                descriptor,
                pinned,
                attempt_index=index,
                status=pinned_attempt_statuses[index - 1],
                machine_result_sha256=pinned_hashes[index - 1],
                evidence=pinned_evidence,
                egress_status=pinned_egress_status,
            )
            for index in (1, 2)
        )
    else:
        pinned_attempts = tuple(
            RepositorySuiteStateAttempt.sealed(
                state_id=pinned.state_id,
                state_sha256=pinned.state_sha256,
                attempt_index=index,
                workspace_kind="fresh_disposable_copy",
                workspace_identity_sha256=(str(index + 6) * 64),
                workspace_freshness_attestation_sha256=(f"{index + 7:x}" * 64),
                workspace_disposal_policy_sha256=(f"{index + 10:x}" * 64),
                scanner_run=ScannerRun(
                    scanner="foundry_fork",
                    status=ScannerStatus.UNAVAILABLE,
                    started_at=BASE_TIME,
                    finished_at=BASE_TIME,
                    duration_seconds=0,
                    error="Configured local state endpoint was unavailable.",
                ),
            )
            for index in (1, 2)
        )
    clean_consensus = _consensus(
        clean,
        descriptor,
        clean_attempts,
        status=RepositoryStateConsensusStatus.CONSISTENT_PASS,
        observed_status=RepositoryTestExecutionStatus.PASSED,
        machine_result_sha256=HASH_E,
    )
    pinned_consensus = _consensus(
        pinned,
        descriptor,
        pinned_attempts,
        status=pinned_consensus_status,
        observed_status=(
            pinned_attempt_statuses[0]
            if pinned_consensus_status is not RepositoryStateConsensusStatus.INCONCLUSIVE
            else None
        ),
        machine_result_sha256=(
            pinned_hashes[0]
            if pinned_consensus_status is not RepositoryStateConsensusStatus.INCONCLUSIVE
            else None
        ),
        reasons=reasons,
    )
    comparison = _comparison(
        clean,
        pinned,
        descriptor,
        clean_consensus,
        pinned_consensus,
        classification=classification,
        direction=direction,
    )
    policy = _policy(selection, clean)
    execution_configuration_sha256 = (
        RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(policy)
    )
    return RepositorySuiteDifferentialMatrix.sealed(
        repository_sha256=selection.repository_sha256,
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        descriptor_sha256s=(descriptor.descriptor_sha256,),
        required_repetitions=2,
        fuzz_seed=SEED,
        execution_configuration_sha256=execution_configuration_sha256,
        fork_rpc_policy_sha256=HASH_E,
        states=tuple(sorted((clean, pinned), key=lambda state: state.state_id)),
        attempts=tuple(
            sorted(
                (*clean_attempts, *pinned_attempts),
                key=lambda attempt: (attempt.state_id, attempt.attempt_index),
            )
        ),
        state_consensuses=tuple(
            sorted(
                (clean_consensus, pinned_consensus),
                key=lambda consensus: (consensus.state_id, consensus.descriptor_sha256),
            )
        ),
        comparisons=(comparison,),
    )


def test_repeated_real_isolated_state_divergence_round_trips_and_is_self_hashed() -> None:
    matrix = _matrix()

    restored = RepositorySuiteDifferentialMatrix.model_validate_json(matrix.model_dump_json())

    assert restored == matrix
    assert restored.comparisons[0].classification is RepositoryDifferentialClassification.DIVERGED
    assert (
        restored.comparisons[0].direction is RepositoryDivergenceDirection.CLEAN_PASS_PINNED_FAILURE
    )
    assert restored.matrix_sha256 == restored.expected_matrix_sha256()


def test_single_qualifying_observation_cannot_claim_conclusive_state() -> None:
    matrix = _matrix()
    payload = matrix.model_dump(mode="json")
    pinned_attempt = next(
        attempt for attempt in matrix.attempts if attempt.state_id == "pinned-state"
    )
    broken_run = pinned_attempt.scanner_run.model_copy(
        update={
            "status": ScannerStatus.UNAVAILABLE,
            "execution_evidence": ExecutionEvidenceKind.UNVERIFIED,
            "repository_suite_selection": None,
            "repository_suite_execution_policy": None,
            "repository_test_executions": [],
            "foundry_summary": None,
            "machine_output_validated": False,
            "fork_rpc_egress": None,
            "execution_observation_sha256": None,
        }
    )
    broken_attempt = RepositorySuiteStateAttempt.sealed(
        **{
            **pinned_attempt.model_dump(
                mode="python",
                exclude={"attempt_sha256", "scanner_run", "fork_rpc_egress_sha256"},
            ),
            "fork_rpc_egress_sha256": None,
            "scanner_run": broken_run,
        }
    )
    attempts = [
        broken_attempt if attempt.attempt_sha256 == pinned_attempt.attempt_sha256 else attempt
        for attempt in matrix.attempts
    ]
    payload["attempts"] = [
        attempt.model_dump(mode="json")
        for attempt in sorted(attempts, key=lambda item: (item.state_id, item.attempt_index))
    ]

    with pytest.raises(ValidationError, match="inconclusive"):
        RepositorySuiteDifferentialMatrix.model_validate(
            {
                **payload,
                "matrix_sha256": RepositorySuiteDifferentialMatrix.calculate_matrix_sha256(payload),
            }
        )


@pytest.mark.parametrize(
    ("pinned_hashes", "pinned_evidence", "egress_status", "reason"),
    [
        (
            (HASH_E, HASH_F),
            ExecutionEvidenceKind.REAL,
            RepositoryForkEgressStatus.ENFORCED,
            "disagree",
        ),
        (
            (HASH_F, HASH_F),
            ExecutionEvidenceKind.MOCK,
            RepositoryForkEgressStatus.ENFORCED,
            "real",
        ),
        (
            (HASH_F, HASH_F),
            ExecutionEvidenceKind.REAL,
            RepositoryForkEgressStatus.VIOLATION,
            "egress",
        ),
    ],
)
def test_disagreement_mock_or_egress_violation_cannot_claim_divergence(
    pinned_hashes: tuple[str, str],
    pinned_evidence: ExecutionEvidenceKind,
    egress_status: RepositoryForkEgressStatus,
    reason: str,
) -> None:
    with pytest.raises(ValidationError, match=reason):
        _matrix(
            pinned_hashes=pinned_hashes,
            pinned_evidence=pinned_evidence,
            pinned_egress_status=egress_status,
        )


def test_observed_clean_state_without_enforced_egress_cannot_claim_consensus() -> None:
    with pytest.raises(ValidationError, match="egress"):
        _matrix(clean_egress_status=RepositoryForkEgressStatus.VIOLATION)


def test_clean_state_requires_cross_bound_inspectable_process_attestation() -> None:
    attestation = _clean_attestation()
    serialized = attestation.model_dump_json()

    assert attestation.expected_chain_id == 31_337
    assert attestation.genesis_block_hash == "0x" + HASH_A
    assert attestation.outbound_network_isolation == "not_attested"
    for prohibited in ("http://", "127.0.0.1", "/private/", '"port":', '"process_id":'):
        assert prohibited not in serialized

    with pytest.raises(ValidationError, match="source identity"):
        RepositorySuiteExecutionStateEvidence.sealed(
            state_id="clean-local",
            kind=RepositoryExecutionStateKind.CLEAN_LOCAL,
            state_source_sha256=HASH_B,
            expected_chain_id=31_337,
            pinned_block_number=0,
            observation_status=RepositoryExecutionStateObservationStatus.OBSERVED,
            observed_chain_id=31_337,
            observed_block_number=0,
            observed_block_hash="0x" + HASH_A,
            clean_state_attestation=attestation,
        )


@pytest.mark.parametrize(
    "field",
    [
        "listener_ownership_kind",
        "listener_owner_pid_bound",
        "runtime_executable_identity_kind",
        "runtime_executable_matches_pinned_copy",
        "exec_path_binding_kind",
        "version_probe_process_group_absent",
        "initial_head_block_number",
        "initial_head_block_hash",
        "initial_head_state_root",
        "final_head_block_number",
        "final_head_block_hash",
        "final_head_state_root",
        "pristine_head_pre_post_match",
        "collector_threads_closed",
        "executable_descriptor_closed",
        "private_workspace_removed",
        "ancestor_config_absent",
    ],
)
def test_clean_state_v2_requires_every_explicit_process_and_head_fact(field: str) -> None:
    evidence = _clean_attestation()
    values = evidence.model_dump(mode="python", exclude={"attestation_sha256"})
    values.pop(field)

    with pytest.raises(ValidationError, match=field):
        RepositoryCleanStateAttestationEvidence.sealed(**values)


@pytest.mark.parametrize(
    "field",
    [
        "listener_owner_pid_bound",
        "runtime_executable_matches_pinned_copy",
        "version_probe_process_group_absent",
        "pristine_head_pre_post_match",
        "collector_threads_closed",
        "executable_descriptor_closed",
        "private_workspace_removed",
        "ancestor_config_absent",
    ],
)
def test_clean_state_v2_rejects_false_safety_facts(field: str) -> None:
    evidence = _clean_attestation()
    values = evidence.model_dump(mode="python", exclude={"attestation_sha256"})
    values[field] = False

    with pytest.raises(ValidationError):
        RepositoryCleanStateAttestationEvidence.sealed(**values)


def test_clean_state_v2_requires_one_coherent_platform_identity_bundle() -> None:
    evidence = _clean_attestation()
    values = evidence.model_dump(mode="python", exclude={"attestation_sha256"})
    values["listener_ownership_kind"] = RepositoryCleanListenerOwnershipKind.LINUX_PROC_SOCKET_INODE

    with pytest.raises(ValidationError, match="platform"):
        RepositoryCleanStateAttestationEvidence.sealed(**values)


@pytest.mark.parametrize(
    "updates",
    [
        {"initial_head_block_number": False},
        {"final_head_block_number": 1},
        {"initial_head_block_hash": "0x" + HASH_C},
        {"final_head_block_hash": "0x" + HASH_C},
        {"initial_head_state_root": None},
        {"final_head_state_root": None},
        {"final_head_state_root": "0x" + HASH_C},
    ],
)
def test_clean_state_v2_rejects_non_pristine_or_inconsistent_head_facts(
    updates: dict[str, object],
) -> None:
    evidence = _clean_attestation()
    values = evidence.model_dump(mode="python", exclude={"attestation_sha256"})
    values.update(updates)

    with pytest.raises(ValidationError, match=r"head|state root|integer"):
        RepositoryCleanStateAttestationEvidence.sealed(**values)


def test_clean_state_v2_state_source_hash_binds_every_attestation_fact() -> None:
    evidence = _clean_attestation()
    payload = evidence.model_dump(mode="json", exclude={"attestation_sha256"})

    assert evidence.schema_version == "2.0"
    assert evidence.launcher_policy_version == "2.0"
    assert not hasattr(evidence, "pre_post_identity_match")
    assert evidence.expected_state_source_sha256() == _canonical_sha256(
        {
            "domain": "mmaudit.repository-clean-state-source.v2",
            "attestation": payload,
        }
    )


def test_unavailable_state_serializes_only_as_inconclusive() -> None:
    matrix = _matrix(
        pinned_observation_status=RepositoryExecutionStateObservationStatus.UNAVAILABLE,
        pinned_consensus_status=RepositoryStateConsensusStatus.INCONCLUSIVE,
        classification=RepositoryDifferentialClassification.INCONCLUSIVE,
        direction=None,
        reasons=(RepositoryStateInconclusiveReason.STATE_UNOBSERVED,),
    )

    assert matrix.state_consensuses[-1].status is RepositoryStateConsensusStatus.INCONCLUSIVE
    assert matrix.comparisons[0].classification is RepositoryDifferentialClassification.INCONCLUSIVE


def test_matrix_requires_exact_clean_pinned_attempt_and_comparison_cartesian_sets() -> None:
    matrix = _matrix()
    for field, missing_index, message in (
        ("states", 1, r"at least 2|clean state"),
        ("attempts", 0, "attempt"),
        ("state_consensuses", 0, "consensus"),
        ("comparisons", 0, "comparison"),
    ):
        payload = matrix.model_dump(mode="json")
        payload[field].pop(missing_index)
        payload["matrix_sha256"] = RepositorySuiteDifferentialMatrix.calculate_matrix_sha256(
            payload
        )
        with pytest.raises(ValidationError, match=message):
            RepositorySuiteDifferentialMatrix.model_validate(payload)


def test_matrix_nested_hash_tampering_and_endpoint_fields_are_rejected() -> None:
    matrix = _matrix()
    egress = next(
        attempt.scanner_run.fork_rpc_egress
        for attempt in matrix.attempts
        if attempt.scanner_run.fork_rpc_egress is not None
    )
    assert egress is not None
    with pytest.raises(ValidationError, match=r"accounting|egress evidence hash"):
        ForkRpcReadOnlyEgressEvidence.model_validate(
            {
                **egress.model_dump(mode="json"),
                "permitted_rpc_call_count": egress.permitted_rpc_call_count + 1,
            }
        )
    with pytest.raises(ValidationError, match="extra"):
        ForkRpcReadOnlyEgressEvidence.model_validate(
            {**egress.model_dump(mode="json"), "rpc_url": "http://127.0.0.1:8545"}
        )


@pytest.mark.parametrize(
    "counter",
    [
        "denied_request_count",
        "malformed_request_count",
        "limit_exceeded_request_count",
        "upstream_error_request_count",
    ],
)
def test_enforced_egress_rejects_every_bridge_rejection_or_error_counter(
    counter: str,
) -> None:
    clean, _pinned = _states()
    evidence = _egress(clean)
    values = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256", "bridge_snapshot_sha256"},
    )
    values["allowed_method_counts"] = evidence.allowed_method_counts
    values[counter] = 1
    values["http_request_count"] += 1
    values["bridge_snapshot_sha256"] = (
        ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(values)
    )

    with pytest.raises(ValidationError, match="enforced"):
        ForkRpcReadOnlyEgressEvidence.sealed(**values)


def test_enforced_egress_requires_at_least_one_origin_validated_call() -> None:
    clean, _pinned = _states()
    evidence = _egress(clean)
    values = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256", "bridge_snapshot_sha256"},
    )
    values["allowed_method_counts"] = evidence.allowed_method_counts
    values["origin_attempted_rpc_call_count"] = 0
    values["origin_validated_rpc_call_count"] = 0
    values["synthetic_rpc_call_count"] = evidence.permitted_rpc_call_count
    values["bridge_snapshot_sha256"] = (
        ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(values)
    )

    with pytest.raises(ValidationError, match="nonempty fully validated"):
        ForkRpcReadOnlyEgressEvidence.sealed(**values)


def test_bridge_snapshot_hash_and_allowed_method_accounting_are_bound() -> None:
    clean, _pinned = _states()
    evidence = _egress(clean)
    assert evidence.bridge_snapshot_sha256 == evidence.expected_bridge_snapshot_sha256()
    assert sum(item.count for item in evidence.allowed_method_counts) == 2
    snapshot = ReadOnlyRpcBridgeSnapshot(
        schema_version="2.0",
        status="enforced",
        policy_sha256=evidence.policy_sha256,
        expected_chain_id=evidence.expected_chain_id,
        pinned_block_number=evidence.pinned_block_number,
        pinned_block_hash=evidence.pinned_block_hash,
        preflight_origin_observation_sha256=evidence.preflight_origin_observation_sha256,
        postflight_origin_observation_sha256=evidence.postflight_origin_observation_sha256,
        origin_state_stable=True,
        http_request_count=evidence.http_request_count,
        permitted_rpc_call_count=evidence.permitted_rpc_call_count,
        origin_attempted_rpc_call_count=evidence.origin_attempted_rpc_call_count,
        origin_validated_rpc_call_count=evidence.origin_validated_rpc_call_count,
        synthetic_rpc_call_count=evidence.synthetic_rpc_call_count,
        denied_request_count=evidence.denied_request_count,
        malformed_request_count=evidence.malformed_request_count,
        limit_exceeded_request_count=evidence.limit_exceeded_request_count,
        upstream_error_request_count=evidence.upstream_error_request_count,
        allowed_method_counts=tuple(
            (item.method, item.count) for item in evidence.allowed_method_counts
        ),
        method_log_sha256=evidence.method_log_sha256,
        stopped_cleanly=True,
        snapshot_sha256=evidence.bridge_snapshot_sha256,
    )
    assert snapshot.verify()

    with pytest.raises(ValidationError, match="bridge snapshot hash"):
        ForkRpcReadOnlyEgressEvidence.model_validate(
            {
                **evidence.model_dump(mode="json"),
                "bridge_snapshot_sha256": HASH_A,
            }
        )
    with pytest.raises(ValidationError, match="extra"):
        ForkRpcMethodCount.model_validate(
            {
                "method": "eth_getCode",
                "count": 1,
                "rejected_count": 1,
            }
        )
    values = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256", "bridge_snapshot_sha256"},
    )
    values["allowed_method_counts"] = (
        *evidence.allowed_method_counts,
        ForkRpcMethodCount(method="eth_sendRawTransaction", count=1),
    )
    values["permitted_rpc_call_count"] += 1
    values["origin_attempted_rpc_call_count"] += 1
    values["origin_validated_rpc_call_count"] += 1
    values["bridge_snapshot_sha256"] = (
        ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(values)
    )
    with pytest.raises(ValidationError, match="read-only bridge vocabulary"):
        ForkRpcReadOnlyEgressEvidence.sealed(**values)


def test_bridge_observation_hashes_must_bind_the_declared_chain_and_block() -> None:
    clean, _pinned = _states()
    evidence = _egress(clean)
    values = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256", "bridge_snapshot_sha256"},
    )
    values["allowed_method_counts"] = evidence.allowed_method_counts
    values["preflight_origin_observation_sha256"] = HASH_F
    values["postflight_origin_observation_sha256"] = HASH_F
    values["bridge_snapshot_sha256"] = evidence.bridge_snapshot_sha256

    with pytest.raises(ValidationError, match="canonical pinned observation"):
        ForkRpcReadOnlyEgressEvidence.sealed(**values)
    with pytest.raises(ValueError, match="canonical pinned observation"):
        ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(values)


def test_configured_differential_result_wraps_complete_inconclusive_and_failed_runs() -> None:
    complete_matrix = _matrix()
    complete = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.COMPLETE,
        configuration_sha256=complete_matrix.selection_configuration_sha256,
        requested_state_ids=tuple(state.state_id for state in complete_matrix.states),
        required_repetitions=2,
        matrix=complete_matrix,
        limitations=(),
    )
    assert (
        RepositorySuiteDifferentialRun.model_validate_json(complete.model_dump_json()) == complete
    )

    inconclusive_matrix = _matrix(
        pinned_observation_status=RepositoryExecutionStateObservationStatus.UNAVAILABLE,
        pinned_consensus_status=RepositoryStateConsensusStatus.INCONCLUSIVE,
        classification=RepositoryDifferentialClassification.INCONCLUSIVE,
        direction=None,
        reasons=(RepositoryStateInconclusiveReason.STATE_UNOBSERVED,),
    )
    inconclusive = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.INCONCLUSIVE,
        configuration_sha256=HASH_A,
        requested_state_ids=tuple(state.state_id for state in inconclusive_matrix.states),
        required_repetitions=2,
        matrix=inconclusive_matrix,
        limitations=("One configured local state was unavailable.",),
    )
    assert inconclusive.status is RepositoryDifferentialRunStatus.INCONCLUSIVE

    failed = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.FAILED,
        configuration_sha256=HASH_A,
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=None,
        limitations=("The baseline suite selection was unavailable.",),
    )
    assert failed.matrix is None

    with pytest.raises(ValidationError, match="conclusive matrix"):
        RepositorySuiteDifferentialRun.sealed(
            status=RepositoryDifferentialRunStatus.COMPLETE,
            configuration_sha256=HASH_A,
            requested_state_ids=("clean-local", "pinned-state"),
            required_repetitions=2,
            matrix=None,
            limitations=(),
        )


def test_complete_differential_binds_top_level_and_selection_configuration() -> None:
    matrix = _matrix()
    assert matrix.selection_configuration_sha256 != HASH_A

    with pytest.raises(ValidationError, match="configuration"):
        RepositorySuiteDifferentialRun.sealed(
            status=RepositoryDifferentialRunStatus.COMPLETE,
            configuration_sha256=HASH_A,
            requested_state_ids=tuple(state.state_id for state in matrix.states),
            required_repetitions=matrix.required_repetitions,
            matrix=matrix,
            limitations=(),
        )


def test_fork_rpc_privacy_projection_is_endpoint_free_and_result_bound() -> None:
    matrix = _matrix()
    result = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.COMPLETE,
        configuration_sha256=matrix.selection_configuration_sha256,
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=matrix,
        limitations=(),
    )

    privacy = RepositoryForkRpcPrivacyEvidence.from_differential(result)

    assert privacy.status is RepositoryForkEgressStatus.ENFORCED
    assert privacy.differential_result_sha256 == result.result_sha256
    assert privacy.attempt_count == 4
    assert privacy.egress_evidence_count == 4
    assert privacy.origin_validated_rpc_call_count == 4
    assert privacy.transaction_capable_request_forwarded is False
    assert privacy.rpc_endpoint_recorded is False
    serialized = privacy.model_dump_json()
    assert "http://" not in serialized
    assert "127.0.0.1" not in serialized
    assert "MMAUDIT_" not in serialized

    with pytest.raises(ValidationError, match="hash"):
        RepositoryForkRpcPrivacyEvidence.model_validate(
            {
                **privacy.model_dump(mode="json"),
                "differential_result_sha256": HASH_B,
            }
        )


def test_serialized_fork_rpc_method_vocabulary_matches_the_runtime_bridge() -> None:
    assert _TRUSTED_READ_ONLY_FORK_RPC_METHODS == _ALLOWED_METHODS


def test_report_requires_and_renders_differential_privacy_evidence() -> None:
    matrix = _matrix()
    differential = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.COMPLETE,
        configuration_sha256=matrix.selection_configuration_sha256,
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=matrix,
        limitations=(),
    )
    fork_rpc_privacy = RepositoryForkRpcPrivacyEvidence.from_differential(differential)
    report = AuditReport(
        schema_version="1.0",
        run_id="differential-report",
        generated_at=BASE_TIME,
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=["foundry.toml"],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=["foundry.toml"],
            sensitive_processing=[],
            security_tests=["test/Vault.t.sol"],
            files=[],
        ),
        configuration_hash=HASH_A,
        model_configuration_hash=HASH_B,
        privacy={
            "code_egress_enabled": False,
            "fork_rpc_egress": fork_rpc_privacy.model_dump(mode="json"),
        },
        scanner_runs=[],
        repository_suite_differential=differential,
        usage=[],
        budget_usd=250,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
    )

    assert AuditReport.model_validate_json(report.model_dump_json()) == report
    rendered = render_markdown(report)
    assert "Repository suite differential execution" in rendered
    assert "trusted read-only loopback bridge" in rendered
    assert "Transaction-capable requests forwarded: **False**" in rendered
    assert "clean-pass / pinned-failure" in rendered
    assert "http://" not in rendered

    payload = report.model_dump(mode="python")
    payload["privacy"] = {"code_egress_enabled": False}
    with pytest.raises(ValidationError, match="explicit fork RPC privacy"):
        AuditReport.model_validate(payload)


def test_scanner_egress_identity_must_match_its_execution_policy() -> None:
    matrix = _matrix()
    attempt = next(item for item in matrix.attempts if item.state_id == "pinned-state")
    assert attempt.scanner_run.fork_rpc_egress is not None
    egress_values = attempt.scanner_run.fork_rpc_egress.model_dump(
        mode="python",
        exclude={"evidence_sha256"},
    )
    egress_values["allowed_method_counts"] = (
        attempt.scanner_run.fork_rpc_egress.allowed_method_counts
    )
    egress_values["expected_chain_id"] = 99
    observation_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
        expected_chain_id=99,
        pinned_block_number=egress_values["pinned_block_number"],
        pinned_block_hash=egress_values["pinned_block_hash"],
    )
    egress_values["preflight_origin_observation_sha256"] = observation_sha256
    egress_values["postflight_origin_observation_sha256"] = observation_sha256
    egress_values["bridge_snapshot_sha256"] = (
        ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(egress_values)
    )
    mismatched = ForkRpcReadOnlyEgressEvidence.sealed(**egress_values)
    with pytest.raises(ValidationError, match="execution policy"):
        ScannerRun.model_validate(
            {
                **attempt.scanner_run.model_dump(mode="json"),
                "fork_rpc_egress": mismatched.model_dump(mode="json"),
                "execution_observation_sha256": None,
            }
        )
