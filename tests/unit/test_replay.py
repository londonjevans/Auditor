from __future__ import annotations

import asyncio
import hashlib
import json
import math
import socket
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    RepositoryCleanForkMatrixStateConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
    audit_config_overrides,
)
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import (
    AnalysisState,
    AttackerCapabilityPolicy,
    AuditProfile,
    AuditReport,
    ExecutionEvidenceKind,
    ForkActor,
    ForkAssertion,
    ForkCallStep,
    ForkRpcReadOnlyEgressEvidence,
    ForkTestType,
    FoundryInvariantHarnessSpec,
    FoundryTestExecutionSummary,
    GeneratedFoundryTestSpec,
    InvariantCategory,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    RepositoryCodeExecutionState,
    RepositoryDifferentialRunStatus,
    RepositoryFile,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteStateAttempt,
    RepositorySuiteStateWorkspaceCleanupEvidence,
    RepositorySuiteTestComparison,
    RepositorySuiteTestDescriptor,
    RepositorySuiteTestStateConsensus,
    RepositorySuiteWorkspaceCopyEvidence,
    RepositorySuiteWorkspaceLifecycleEvidence,
    RepositorySuiteWorkspaceLifecycleStatus,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestForkRpcScopeEvidence,
    RepositoryTestKind,
    ReproductionAttemptEvidence,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    StatefulActionSpec,
)
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    build_run_evidence_manifest,
    canonical_sha256,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayOrchestrator,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
    _load_replay_artifacts,
    _repository_differential_is_qualifying,
    _repository_differential_projection,
    write_offline_replay,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.fork_matrix import (
    REPOSITORY_FORK_MATRIX_RETURN_CLEANUP_RESERVE_SECONDS,
    ForkMatrixDependencies,
    repository_fork_matrix_timeout_budget_seconds,
)
from tests.unit.test_repository_fork_differential_schema import (
    _matrix as _repository_differential_matrix,
)

runner = CliRunner()
_NOW = datetime(2026, 7, 27, tzinfo=UTC)


class _LocalScannerRunner:
    def __init__(self, runs: list[ScannerRun]) -> None:
        self.runs = runs
        self.calls = 0

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
    ) -> list[ScannerRun]:
        del (
            root,
            private_dir,
            projects,
            expected_repository_sha256,
            repository_exclusion_root,
        )
        assert not skip_codeql
        assert not allow_fork_probing
        self.calls += 1
        return self.runs


class _ForkAwareScannerRunner:
    def __init__(
        self,
        runs: list[ScannerRun],
        *,
        before_return: Callable[[], None] | None = None,
        backend: object | None = None,
    ) -> None:
        self.runs = runs
        self.before_return = before_return
        self.backend = backend
        self.allow_fork_probing: list[bool] = []
        self.expected_repository_sha256: list[str | None] = []
        self.repository_exclusion_root: list[Path | None] = []

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
    ) -> list[ScannerRun]:
        del root, private_dir, projects
        assert not skip_codeql
        self.allow_fork_probing.append(allow_fork_probing)
        self.expected_repository_sha256.append(expected_repository_sha256)
        self.repository_exclusion_root.append(repository_exclusion_root)
        if self.before_return is not None:
            self.before_return()
        return self.runs


class _LocalInvariantRunner:
    def __init__(
        self,
        result: InvariantExecutionResult,
        *,
        backend: object | None = None,
    ) -> None:
        self.result = result
        self.backend = backend
        self.calls = 0

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        specification: FoundryInvariantHarnessSpec,
        private_dir: Path,
    ) -> InvariantExecutionResult:
        del repository_root, private_dir
        assert project.project_root == "."
        assert specification.invariant_id == self.result.invariant_id
        self.calls += 1
        return self.result


class _LocalReproductionRunner:
    def __init__(
        self,
        result: ReproductionResult,
        *,
        backend: object | None = None,
    ) -> None:
        self.result = result
        self.backend = backend
        self.calls = 0

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult:
        del repository_root, private_dir
        assert project.project_root == "."
        assert candidate.candidate_id == specification.candidate_id
        self.calls += 1
        return self.result


class _LocalDifferentialRunner:
    def __init__(
        self,
        result: RepositorySuiteDifferentialRun | None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls = 0
        self.baseline_runs: list[ScannerRun] = []
        self.repository_sha256s: list[str] = []
        self.exclusion_roots: list[Path] = []

    def run(
        self,
        repository_root: Path,
        private_dir: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun | None:
        del repository_root, private_dir, projects
        assert absolute_deadline > 0
        self.calls += 1
        self.baseline_runs.append(baseline_run)
        self.repository_sha256s.append(repository_sha256)
        self.exclusion_roots.append(repository_exclusion_root)
        if self.error is not None:
            raise self.error
        return self.result


class _LocalIsolationBackend:
    name = "synthetic-isolation"

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


class _DefaultDifferentialRunnerFactory:
    def __init__(
        self,
        result: RepositorySuiteDifferentialRun,
        expected_backend: _LocalIsolationBackend,
        expected_clean_state_provider: object,
    ) -> None:
        self.result = result
        self.expected_backend = expected_backend
        self.expected_clean_state_provider = expected_clean_state_provider
        self.constructed_smart_contracts: list[SmartContractsConfig] = []
        self.constructed_reproduction: list[ReproductionConfig] = []
        self.absolute_deadlines: list[float] = []
        self.calls = 0

    def __call__(
        self,
        smart_contracts: SmartContractsConfig,
        reproduction: ReproductionConfig,
        *,
        dependencies: ForkMatrixDependencies,
    ) -> _DefaultDifferentialRunnerFactory:
        assert dependencies.clean_state_provider is self.expected_clean_state_provider
        self.constructed_smart_contracts.append(smart_contracts)
        self.constructed_reproduction.append(reproduction)
        return self

    def run(
        self,
        repository_root: Path,
        private_dir: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: object,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun:
        del (
            repository_root,
            private_dir,
            projects,
            repository_sha256,
            repository_exclusion_root,
            baseline_run,
        )
        assert absolute_deadline > 0
        assert backend is self.expected_backend
        self.absolute_deadlines.append(absolute_deadline)
        self.calls += 1
        return self.result


def _scanner_run() -> ScannerRun:
    return ScannerRun(
        scanner="synthetic-local",
        status=ScannerStatus.SUCCESS,
        version="1.0.0",
        executable_sha256="1" * 64,
        started_at=_NOW,
        finished_at=_NOW,
        duration_seconds=0,
        findings=[],
        isolation_backend="synthetic-no-network",
    )


def _repository_suite_scanner_run(
    *,
    private_command_root: str = "/private/replay-one",
    scanner_duration_seconds: float = 0.25,
    execution_duration_seconds: float = 0.25,
    block_hash: str = "0x" + ("4" * 64),
    compiler_sha256: str = "5" * 64,
    policy_fuzz_runs: int = 256,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
    repository_sha256: str = "2" * 64,
    repository_exclusion_path: str = ".mmaudit",
) -> ScannerRun:
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/audit/ReplaySuite.t.sol",
        suite_name="ReplaySuiteTest",
        test_name="testPinnedState",
        source_sha256="1" * 64,
        start_line=10,
        end_line=12,
    )
    selection = RepositorySuiteSelection.sealed(
        profile="legacy_audit",
        repository_sha256=repository_sha256,
        repository_exclusion_path=repository_exclusion_path,
        configuration_sha256="3" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=42,
        block_hash=block_hash,
        tool_version="forge 1.3.2",
        tool_sha256="a" * 64,
        compiler_version="solc 0.8.30",
        compiler_sha256=compiler_sha256,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256="9" * 64,
        fuzz_seed="0x" + ("0" * 63) + "1",
        fuzz_runs=policy_fuzz_runs,
        invariant_runs=64,
        per_test_timeout_seconds=120,
        total_timeout_seconds=900,
        max_output_bytes_per_test=1_000_000,
        max_total_output_bytes=10_000_000,
    )
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=31_337,
        block_number=42,
        block_hash=block_hash,
        fuzz_seed="0x" + ("0" * 63) + "1",
        test_kind=RepositoryTestKind.UNIT,
        status=RepositoryTestExecutionStatus.PASSED,
        duration_seconds=execution_duration_seconds,
        command_sha256="7" * 64,
        output_sha256="8" * 64,
        output_bytes=128,
        machine_result_sha256="c" * 64,
        process_exit_code=0,
        machine_output_validated=True,
        execution_evidence=execution_evidence,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256="9" * 64,
        compiler_version="solc 0.8.30",
        compiler_sha256=compiler_sha256,
        execution_policy_sha256=policy.policy_sha256,
    )
    return ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=execution_evidence,
        version="forge 1.3.2",
        executable_sha256="a" * 64,
        command=[
            f"{private_command_root}/forge",
            "test",
            "--cache-path",
            f"{private_command_root}/cache",
        ],
        started_at=_NOW,
        finished_at=_NOW,
        duration_seconds=scanner_duration_seconds,
        findings=[],
        raw_output_path=f"{private_command_root}/scanner-output.json",
        raw_output_sha256=hashlib.sha256(private_command_root.encode()).hexdigest(),
        raw_output_bytes=256,
        process_exit_code=0,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256="9" * 64,
        machine_output_validated=True,
        foundry_summary=FoundryTestExecutionSummary(
            unit_tests=1,
            fuzz_tests=0,
            invariant_tests=0,
            passed_tests=1,
            failed_tests=0,
            skipped_tests=0,
            fuzz_cases=0,
            invariant_runs=0,
            invariant_calls=0,
        ),
        repository_suite_selection=selection,
        repository_suite_execution_policy=policy,
        repository_test_executions=[execution],
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
    )


def _config_with_repository_differential(config: AuditConfig) -> AuditConfig:
    suite = config.smart_contracts.repository_suite.model_copy(
        update={
            "fork_matrix_states": (
                RepositoryCleanForkMatrixStateConfig(
                    state_id="clean-local",
                    expected_chain_id=31_337,
                    anvil_version="anvil Version: 1.3.2-stable",
                    anvil_sha256="a" * 64,
                    hardfork="shanghai",
                    genesis_timestamp=1_700_000_000,
                    startup_timeout_seconds=5,
                    shutdown_timeout_seconds=5,
                ),
                RepositoryPinnedForkMatrixStateConfig(
                    state_id="pinned-state",
                    rpc_url_env="MMAUDIT_PINNED_RPC_URL",
                    expected_chain_id=31_338,
                    pinned_block_number=77,
                    state_source_sha256="d" * 64,
                ),
            ),
            "fork_matrix_repetitions": 2,
        }
    )
    smart_contracts = config.smart_contracts.model_copy(update={"repository_suite": suite})
    return AuditConfig.model_validate(
        config.model_copy(update={"smart_contracts": smart_contracts}).model_dump(mode="python")
    )


def _rootless_repository_differential_config(config: AuditConfig) -> AuditConfig:
    configured = _config_with_repository_differential(config)
    reproduction = configured.reproduction.model_copy(
        update={
            "isolation_backend": "rootless-container",
            "rootless_container_image": ("registry.invalid/mmaudit-replay@sha256:" + ("a" * 64)),
            "rootless_container_runtime": "podman",
        }
    )
    return AuditConfig.model_validate(
        configured.model_copy(update={"reproduction": reproduction}).model_dump(mode="python")
    )


def _rebind_differential_repository(
    matrix: RepositorySuiteDifferentialMatrix,
    repository_sha256: str,
    configuration_sha256: str,
) -> RepositorySuiteDifferentialMatrix:
    baseline_selection = matrix.attempts[0].scanner_run.repository_suite_selection
    assert baseline_selection is not None
    selection = RepositorySuiteSelection.sealed(
        **{
            **baseline_selection.model_dump(
                mode="python",
                exclude={
                    "selection_sha256",
                    "repository_sha256",
                    "configuration_sha256",
                    "tests",
                },
            ),
            "repository_sha256": repository_sha256,
            "configuration_sha256": configuration_sha256,
            "tests": baseline_selection.tests,
        }
    )
    attempts: list[RepositorySuiteStateAttempt] = []
    execution_hashes: dict[str, str] = {}
    for prior_attempt in matrix.attempts:
        prior_run = prior_attempt.scanner_run
        prior_policy = prior_run.repository_suite_execution_policy
        assert prior_policy is not None
        policy = RepositorySuiteExecutionPolicy.sealed(
            **{
                **prior_policy.model_dump(
                    mode="python",
                    exclude={
                        "policy_sha256",
                        "selection_sha256",
                        "selection_configuration_sha256",
                    },
                ),
                "selection_sha256": selection.selection_sha256,
                "selection_configuration_sha256": selection.configuration_sha256,
            }
        )
        executions: list[RepositoryTestExecution] = []
        for prior_execution in prior_run.repository_test_executions:
            execution = RepositoryTestExecution.sealed(
                **{
                    **prior_execution.model_dump(
                        mode="python",
                        exclude={
                            "execution_sha256",
                            "selection_sha256",
                            "execution_policy_sha256",
                        },
                    ),
                    "selection_sha256": selection.selection_sha256,
                    "execution_policy_sha256": policy.policy_sha256,
                }
            )
            executions.append(execution)
            execution_hashes[prior_execution.execution_sha256] = execution.execution_sha256
        findings = []
        for finding in prior_run.findings:
            metadata = dict(finding.metadata)
            prior_reference = metadata.get("repository_test_execution_sha256")
            if isinstance(prior_reference, str):
                metadata["repository_test_execution_sha256"] = execution_hashes[prior_reference]
            findings.append(finding.model_copy(update={"metadata": metadata}))
        prior_workspace_copy = prior_run.repository_suite_workspace_copy
        assert prior_workspace_copy is not None
        workspace_copy = RepositorySuiteWorkspaceCopyEvidence.sealed(
            **{
                **prior_workspace_copy.model_dump(
                    mode="python",
                    exclude={
                        "copy_evidence_sha256",
                        "selection_sha256",
                        "repository_sha256",
                        "source_inventory_sha256_before",
                        "source_inventory_sha256_after",
                        "workspace_inventory_sha256_after_copy",
                        "workspace_inventory_sha256_after_execution",
                    },
                ),
                "selection_sha256": selection.selection_sha256,
                "repository_sha256": repository_sha256,
                "source_inventory_sha256_before": repository_sha256,
                "source_inventory_sha256_after": repository_sha256,
                "workspace_inventory_sha256_after_copy": repository_sha256,
                "workspace_inventory_sha256_after_execution": repository_sha256,
                "workspace_parent_device": (prior_attempt.workspace_lifecycle.attempt_root_device),
                "workspace_parent_inode": (prior_attempt.workspace_lifecycle.attempt_root_inode),
                "workspace_parent_descriptor_custody_validated": True,
            }
        )
        scopes: list[RepositoryTestForkRpcScopeEvidence] = []
        for prior_scope in prior_run.repository_test_fork_rpc_scopes:
            scope_values = {
                **prior_scope.model_dump(
                    mode="python",
                    exclude={
                        "evidence_sha256",
                        "selection_sha256",
                        "bridge_scope_snapshot_sha256",
                    },
                ),
                "selection_sha256": selection.selection_sha256,
                "allowed_method_counts": prior_scope.allowed_method_counts,
            }
            scope_values["bridge_scope_snapshot_sha256"] = (
                RepositoryTestForkRpcScopeEvidence.calculate_bridge_scope_snapshot_sha256(
                    scope_values
                )
            )
            scopes.append(RepositoryTestForkRpcScopeEvidence.sealed(**scope_values))
        prior_egress = prior_run.fork_rpc_egress
        assert prior_egress is not None
        egress_values = {
            **prior_egress.model_dump(
                mode="python",
                exclude={
                    "evidence_sha256",
                    "bridge_snapshot_sha256",
                    "selected_test_scope_snapshot_sha256s",
                },
            ),
            "allowed_method_counts": prior_egress.allowed_method_counts,
            "selected_test_scope_snapshot_sha256s": tuple(
                scope.bridge_scope_snapshot_sha256 for scope in scopes
            ),
        }
        egress_values["bridge_snapshot_sha256"] = (
            ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(egress_values)
        )
        egress = ForkRpcReadOnlyEgressEvidence.sealed(**egress_values)
        run = prior_run.model_copy(
            update={
                "repository_suite_selection": selection,
                "repository_suite_execution_policy": policy,
                "repository_suite_workspace_copy": workspace_copy,
                "repository_test_executions": executions,
                "repository_test_fork_rpc_scopes": scopes,
                "fork_rpc_egress": egress,
                "findings": findings,
                "execution_observation_sha256": None,
            }
        )
        run = ScannerRun.model_validate(
            {
                **run.model_dump(mode="json"),
                "execution_observation_sha256": run.expected_execution_observation_sha256(),
            }
        )
        lifecycle = RepositorySuiteWorkspaceLifecycleEvidence.sealed(
            **{
                **prior_attempt.workspace_lifecycle.model_dump(
                    mode="python",
                    exclude={
                        "lifecycle_evidence_sha256",
                        "selection_sha256",
                        "repository_sha256",
                        "workspace_copy_evidence_sha256",
                        "scanner_execution_observation_sha256",
                    },
                ),
                "selection_sha256": selection.selection_sha256,
                "repository_sha256": repository_sha256,
                "workspace_copy_evidence_sha256": workspace_copy.copy_evidence_sha256,
                "scanner_execution_observation_sha256": run.execution_observation_sha256,
            }
        )
        attempts.append(
            RepositorySuiteStateAttempt.sealed(
                **{
                    **prior_attempt.model_dump(
                        mode="python",
                        exclude={
                            "attempt_sha256",
                            "scanner_run",
                            "fork_rpc_egress_sha256",
                            "workspace_lifecycle",
                        },
                    ),
                    "fork_rpc_egress_sha256": (
                        run.fork_rpc_egress.evidence_sha256
                        if run.fork_rpc_egress is not None
                        else None
                    ),
                    "workspace_lifecycle": lifecycle,
                    "scanner_run": run,
                }
            )
        )
    attempts_by_state = {
        state.state_id: tuple(attempt for attempt in attempts if attempt.state_id == state.state_id)
        for state in matrix.states
    }
    consensuses = tuple(
        RepositorySuiteTestStateConsensus.sealed(
            **{
                **prior.model_dump(
                    mode="python",
                    exclude={"consensus_sha256", "attempt_sha256s"},
                ),
                "attempt_sha256s": tuple(
                    sorted(attempt.attempt_sha256 for attempt in attempts_by_state[prior.state_id])
                ),
            }
        )
        for prior in matrix.state_consensuses
    )
    consensus_by_key = {(item.state_id, item.descriptor_sha256): item for item in consensuses}
    comparisons = tuple(
        RepositorySuiteTestComparison.sealed(
            **{
                **prior.model_dump(
                    mode="python",
                    exclude={
                        "comparison_sha256",
                        "clean_consensus_sha256",
                        "pinned_consensus_sha256",
                    },
                ),
                "clean_consensus_sha256": consensus_by_key[
                    (prior.clean_state_id, prior.descriptor_sha256)
                ].consensus_sha256,
                "pinned_consensus_sha256": consensus_by_key[
                    (prior.pinned_state_id, prior.descriptor_sha256)
                ].consensus_sha256,
            }
        )
        for prior in matrix.comparisons
    )
    state_workspace_cleanups: list[RepositorySuiteStateWorkspaceCleanupEvidence] = []
    for prior_cleanup in matrix.state_workspace_cleanups:
        cleanup_order = tuple(
            reversed(
                tuple(attempt for attempt in attempts if attempt.state_id == prior_cleanup.state_id)
            )
        )
        cumulative_entries: list[int] = []
        cumulative_durations: list[float] = []
        entry_total = 0
        duration_total = 0.0
        for attempt in cleanup_order:
            lifecycle = attempt.workspace_lifecycle
            entry_total += lifecycle.removed_entry_count
            duration_total = math.fsum((duration_total, lifecycle.removal_duration_seconds))
            cumulative_entries.append(entry_total)
            cumulative_durations.append(duration_total)
        state_workspace_cleanups.append(
            RepositorySuiteStateWorkspaceCleanupEvidence.sealed(
                **{
                    **prior_cleanup.model_dump(
                        mode="python",
                        exclude={
                            "aggregate_evidence_sha256",
                            "attempt_cleanup_sequence_lifecycle_sha256s",
                            "attempt_cumulative_removed_entry_counts",
                            "attempt_cumulative_removal_duration_seconds",
                        },
                    ),
                    "attempt_cleanup_sequence_lifecycle_sha256s": tuple(
                        attempt.workspace_lifecycle.lifecycle_evidence_sha256
                        for attempt in cleanup_order
                    ),
                    "attempt_cumulative_removed_entry_counts": tuple(cumulative_entries),
                    "attempt_cumulative_removal_duration_seconds": tuple(cumulative_durations),
                }
            )
        )
    first_policy = attempts[0].scanner_run.repository_suite_execution_policy
    assert first_policy is not None
    return RepositorySuiteDifferentialMatrix.sealed(
        **{
            **matrix.model_dump(
                mode="python",
                exclude={
                    "matrix_sha256",
                    "repository_sha256",
                    "selection_sha256",
                    "selection_configuration_sha256",
                    "execution_configuration_sha256",
                    "states",
                    "attempts",
                    "state_workspace_cleanups",
                    "state_consensuses",
                    "comparisons",
                },
            ),
            "repository_sha256": repository_sha256,
            "selection_sha256": selection.selection_sha256,
            "selection_configuration_sha256": selection.configuration_sha256,
            "execution_configuration_sha256": (
                RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(
                    first_policy
                )
            ),
            "states": matrix.states,
            "attempts": tuple(attempts),
            "state_workspace_cleanups": tuple(state_workspace_cleanups),
            "state_consensuses": consensuses,
            "comparisons": comparisons,
        }
    )


def _differential_result(
    config: AuditConfig,
    repository_sha256: str,
) -> RepositorySuiteDifferentialRun:
    configuration_sha256 = config.smart_contracts.repository_suite.stable_hash()
    matrix = _rebind_differential_repository(
        _repository_differential_matrix(),
        repository_sha256,
        configuration_sha256,
    )
    return RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.COMPLETE,
        configuration_sha256=configuration_sha256,
        requested_state_ids=tuple(state.state_id for state in matrix.states),
        required_repetitions=matrix.required_repetitions,
        matrix=matrix,
        limitations=(),
    )


def _differential_baseline(result: RepositorySuiteDifferentialRun) -> ScannerRun:
    assert result.matrix is not None
    run = result.matrix.attempts[0].scanner_run.model_copy(
        update={
            "fork_rpc_egress": None,
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _harness() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-replay-counterexample",
        name="ReplayCounterexample",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="Touch",
                target="Vault",
                function_signature="touch()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="StateRemainsZero",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="state()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=2,
        depth=1,
        seed=7,
    )


def _invariant_result(
    status: InvariantExecutionStatus = InvariantExecutionStatus.COUNTEREXAMPLE,
) -> InvariantExecutionResult:
    return InvariantExecutionResult(
        invariant_id="inv-replay-counterexample",
        harness_name="ReplayCounterexample",
        status=status,
        source_sha256="2" * 64,
        runs=2,
        depth=1,
        seed=7,
        attempts=1,
        successful_attempts=1,
        attempt_evidence=[
            InvariantExecutionAttemptEvidence(
                attempt=1,
                status=status,
                source_sha256="2" * 64,
                fresh_workspace=True,
                stdout_sha256="3" * 64,
                stderr_sha256="4" * 64,
                stdout_path="attempt-1.stdout.txt",
                stderr_path="attempt-1.stderr.txt",
            )
        ],
    )


def _test_specification() -> GeneratedFoundryTestSpec:
    return GeneratedFoundryTestSpec(
        candidate_id="candidate-replay",
        name="SavedRemediationTest",
        test_type=ForkTestType.AUTHORIZATION_MATRIX,
        rationale="Validate the saved synthetic remediation boundary.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
        ),
        attack_calls=[
            ForkCallStep(
                step_id="touch",
                actor="attacker",
                target="Vault",
                function_signature="touch()",
            )
        ],
        assertions=[ForkAssertion(kind="call_reverts", step_id="touch")],
        assumptions=["The local synthetic fixture is unchanged"],
    )


def _reproduction_result() -> ReproductionResult:
    return ReproductionResult(
        candidate_id="candidate-replay",
        test_name="SavedRemediationTest",
        state=ReproductionState.NOT_REPRODUCED,
        specification_sha256=canonical_sha256(_test_specification().model_dump(mode="json")),
        generated_test_sha256="6" * 64,
        attempts=1,
        successful_attempts=0,
        original_steps=1,
        minimized_steps=1,
        repository_sha256="7" * 64,
        attempt_evidence=[
            ReproductionAttemptEvidence(
                attempt=1,
                state=ReproductionState.NOT_REPRODUCED,
                repository_sha256="7" * 64,
                generated_test_sha256="6" * 64,
                fresh_workspace=True,
                stdout_sha256="8" * 64,
                stderr_sha256="9" * 64,
            )
        ],
    )


def _invariant_suite(source_hash: str) -> InvariantSuite:
    return InvariantSuite(
        invariants=[
            InvariantSpec(
                id="inv-replay-counterexample",
                title="Synthetic replay counterexample",
                category=InvariantCategory.STATE_MACHINE,
                description="A local fixture exposes a deterministic incorrect state transition.",
                locations=[
                    {
                        "path": "src/Vault.sol",
                        "start_line": 1,
                        "end_line": 1,
                        "content_hash": source_hash,
                    }
                ],
                entity_ids=[],
                state_variables=["state"],
                functions=["touch"],
                protocol_profiles=["synthetic"],
                assumptions=["Local synthetic fixture only"],
                provenance=SolidityProvenance.HEURISTIC,
                confidence=0.9,
                template_available=True,
                executable=True,
                analysis_state=AnalysisState.DETERMINISTIC,
                evidence_hash="a" * 64,
            )
        ],
        protocol_profiles=["synthetic"],
        templates_available_count=1,
        executable_count=1,
    )


def _write_replay_run(
    root: Path,
    config: AuditConfig,
    candidate,
    *,
    file_config: AuditConfig | None = None,
    cli_overrides: AuditConfigOverrides | None = None,
    with_repository_differential: bool = False,
) -> tuple[Path, Path, Path]:
    base_config = file_config or config
    environment_overrides = AuditConfigOverrides()
    invocation_overrides = cli_overrides or AuditConfigOverrides()
    run_options = AuditRunOptions()
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_text = "contract Vault { uint256 public state; function touch() external {} }\n"
    source.write_text(source_text, encoding="utf-8")
    source_hash = hashlib.sha256(source_text.encode()).hexdigest()
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
        test_directories=["test"],
        build_command=["forge", "build"],
        test_command=["forge", "test"],
    )
    repository_sha256 = scanner_workspace_sha256(repository, repository / ".mmaudit")
    differential = (
        _differential_result(config, repository_sha256) if with_repository_differential else None
    )
    scanner = _differential_baseline(differential) if differential is not None else _scanner_run()
    harness = _harness()
    invariant_result = _invariant_result()
    specification = _test_specification()
    reproduction = _reproduction_result()
    privacy: dict[str, object] = {"code_egress_enabled": False}
    if differential is not None:
        privacy["fork_rpc_egress"] = RepositoryForkRpcPrivacyEvidence.from_differential(
            differential
        ).model_dump(mode="json")
    report = AuditReport(
        schema_version="1.0",
        run_id="offline-replay-test",
        generated_at=_NOW,
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name=repository.name,
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[
                RepositoryFile(
                    path="src/Vault.sol",
                    size=len(source_text.encode()),
                    lines=1,
                    sha256=source_hash,
                    language="Solidity",
                )
            ],
        ),
        configuration_hash=config.stable_hash(),
        model_configuration_hash=config.model_hash(),
        privacy=privacy,
        scanner_runs=[scanner],
        repository_suite_differential=differential,
        usage=[],
        budget_usd=20,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=config.profile,
        metadata={
            "run_options": run_options.model_dump(mode="json"),
            "configuration_provenance": {
                "file_config_sha256": base_config.stable_hash(),
                "environment_overrides_sha256": environment_overrides.stable_hash(),
                "cli_overrides_sha256": invocation_overrides.stable_hash(),
                "run_options_sha256": run_options.stable_hash(),
            },
        },
    )
    run_dir = root / "run"
    run_dir.mkdir()
    artifacts = {
        "scanner-results.json": {
            "schema_version": "1.0",
            "runs": [scanner.model_dump(mode="json")],
        },
        "solidity-projects.json": {
            "schema_version": "1.0",
            "projects": [project.model_dump(mode="json")],
        },
        "solidity-compilation.json": {"schema_version": "1.0", "results": []},
        "solidity-invariants.json": {
            "schema_version": "1.0",
            "invariants": _invariant_suite(source_hash).model_dump(mode="json"),
        },
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": [harness.model_dump(mode="json")],
            "limitations": [],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": {
                "schema_version": "1.0",
                "properties": [],
                "limitations": [],
                "corpus_hash": "b" * 64,
            },
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "harnesses": [harness.model_dump(mode="json")],
            "results": [invariant_result.model_dump(mode="json")],
        },
        "candidate-findings.json": {
            "schema_version": "1.0",
            "findings": [candidate.model_dump(mode="json")],
        },
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [specification.model_dump(mode="json")],
            "results": [reproduction.model_dump(mode="json")],
            "falsification_decisions": [],
        },
        "formal-results.json": {"schema_version": "1.0", "runs": []},
        "solidity-coverage.json": {"schema_version": "1.0", "coverage": None},
        "model-review-coverage.json": {"schema_version": "1.0", "coverage": None},
        "scope-assessment.json": {"schema_version": "1.0", "assessment": None},
    }
    for name, payload in artifacts.items():
        write_json(run_dir / name, payload)
    if differential is not None:
        write_json(run_dir / "repository-suite-differential.json", differential)
        write_json(
            run_dir / "privacy-fork-rpc-egress.json",
            RepositoryForkRpcPrivacyEvidence.from_differential(differential),
        )
    write_json(
        run_dir / "metadata.json",
        {
            "schema_version": report.schema_version,
            "run_id": report.run_id,
            "generated_at": report.generated_at.isoformat(),
            "completed": report.completed,
            "incomplete_reasons": report.incomplete_reasons,
            "configuration_hash": report.configuration_hash,
            "model_configuration_hash": report.model_configuration_hash,
            "privacy": report.privacy,
            "metadata": report.metadata,
            "repository_suite_differential": (
                differential.model_dump(mode="json") if differential is not None else None
            ),
        },
    )
    write_json(run_dir / "final-findings.json", report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        file_config=base_config,
        environment_overrides=environment_overrides,
        cli_overrides=invocation_overrides,
        run_options=run_options,
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    return repository, run_dir, manifest_path


def _orchestrator(
    config: AuditConfig | None,
) -> tuple[
    OfflineReplayOrchestrator,
    _LocalScannerRunner,
    _LocalInvariantRunner,
    _LocalReproductionRunner,
]:
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result())
    reproduction = _LocalReproductionRunner(_reproduction_result())
    return (
        OfflineReplayOrchestrator(
            config,
            scanner_runner=scanner,
            invariant_runner=invariant,
            reproduction_runner=reproduction,
        ),
        scanner,
        invariant,
        reproduction,
    )


@pytest.mark.asyncio
async def test_sealed_repository_suite_replay_acknowledges_fork_probing(
    tmp_path: Path,
) -> None:
    repository_sha256 = scanner_workspace_sha256(tmp_path, tmp_path / ".mmaudit")
    baseline = _repository_suite_scanner_run(repository_sha256=repository_sha256)
    scanner = _ForkAwareScannerRunner([baseline])
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)

    components = await orchestrator._replay_scanners(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[baseline],
    )

    assert scanner.allow_fork_probing == [True]
    assert scanner.expected_repository_sha256 == [repository_sha256]
    assert scanner.repository_exclusion_root == [tmp_path / ".mmaudit"]
    assert len(components) == 1
    assert components[0].identifier == "foundry_fork"
    assert components[0].status is ReplayComponentStatus.MATCHED


@pytest.mark.asyncio
async def test_repository_suite_replay_ignores_volatility_but_retains_identities(
    tmp_path: Path,
) -> None:
    repository_sha256 = scanner_workspace_sha256(tmp_path, tmp_path / ".mmaudit")
    baseline = _repository_suite_scanner_run(
        private_command_root="/private/original",
        scanner_duration_seconds=0.25,
        execution_duration_seconds=0.1,
        repository_sha256=repository_sha256,
    )
    volatile_replay = _repository_suite_scanner_run(
        private_command_root="/private/replay",
        scanner_duration_seconds=4.5,
        execution_duration_seconds=3.25,
        repository_sha256=repository_sha256,
    )
    assert baseline.command != volatile_replay.command
    assert baseline.raw_output_path != volatile_replay.raw_output_path
    assert baseline.raw_output_sha256 != volatile_replay.raw_output_sha256
    assert (
        baseline.repository_test_executions[0].execution_sha256
        != volatile_replay.repository_test_executions[0].execution_sha256
    )
    assert (
        baseline.repository_test_executions[0].command_sha256
        == volatile_replay.repository_test_executions[0].command_sha256
    )

    scanner = _ForkAwareScannerRunner([volatile_replay])
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)
    components = await orchestrator._replay_scanners(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[baseline],
    )

    assert scanner.allow_fork_probing == [True]
    assert components[0].status is ReplayComponentStatus.MATCHED
    assert components[0].expected_sha256 == components[0].observed_sha256

    identity_changes = {
        "toolchain": _repository_suite_scanner_run(
            compiler_sha256="b" * 64,
            repository_sha256=repository_sha256,
        ),
        "block": _repository_suite_scanner_run(
            block_hash="0x" + ("c" * 64),
            repository_sha256=repository_sha256,
        ),
        "policy": _repository_suite_scanner_run(
            policy_fuzz_runs=257,
            repository_sha256=repository_sha256,
        ),
        "evidence": _repository_suite_scanner_run(
            execution_evidence=ExecutionEvidenceKind.REAL,
            repository_sha256=repository_sha256,
        ),
    }
    statuses: dict[str, ReplayComponentStatus] = {}
    for identity, replay_run in identity_changes.items():
        scanner = _ForkAwareScannerRunner([replay_run])
        orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)
        identity_components = await orchestrator._replay_scanners(
            repository=tmp_path,
            private_dir=tmp_path / f"private-{identity}",
            projects=[],
            expected=[baseline],
        )
        statuses[identity] = identity_components[0].status

    assert statuses == {
        "toolchain": ReplayComponentStatus.DRIFTED,
        "block": ReplayComponentStatus.DRIFTED,
        "policy": ReplayComponentStatus.DRIFTED,
        "evidence": ReplayComponentStatus.DRIFTED,
    }


@pytest.mark.asyncio
async def test_repository_suite_replay_reconstructs_custom_output_exclusion(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    output = repository / "custom-audit-output"
    (repository / "src").mkdir(parents=True)
    output.mkdir()
    (repository / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
    (output / "prior-report.json").write_text('{"prior":true}', encoding="utf-8")
    repository_sha256 = scanner_workspace_sha256(repository, output)
    assert repository_sha256 != scanner_workspace_sha256(
        repository,
        repository / ".mmaudit",
    )

    baseline = _repository_suite_scanner_run(
        repository_sha256=repository_sha256,
        repository_exclusion_path="custom-audit-output",
    )
    scanner = _ForkAwareScannerRunner([baseline])
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)

    components = await orchestrator._replay_scanners(
        repository=repository,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[baseline],
    )

    assert scanner.expected_repository_sha256 == [repository_sha256]
    assert scanner.repository_exclusion_root == [output]
    assert components[0].status is ReplayComponentStatus.MATCHED


@pytest.mark.asyncio
async def test_repository_suite_replay_rejects_conflicting_exclusion_identities(
    tmp_path: Path,
) -> None:
    repository_sha256 = scanner_workspace_sha256(tmp_path, tmp_path / ".mmaudit")
    first = _repository_suite_scanner_run(repository_sha256=repository_sha256)
    second = _repository_suite_scanner_run(
        repository_sha256=repository_sha256,
        repository_exclusion_path="custom-audit-output",
    )
    scanner = _ForkAwareScannerRunner([first])
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)

    components = await orchestrator._replay_scanners(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[first, second],
    )

    assert scanner.allow_fork_probing == []
    assert len(components) == 2
    assert all(component.status is ReplayComponentStatus.BLOCKED for component in components)


@pytest.mark.asyncio
async def test_repository_suite_replay_rejects_source_identity_mismatch_before_execution(
    tmp_path: Path,
) -> None:
    baseline = _repository_suite_scanner_run(repository_sha256="f" * 64)
    scanner = _ForkAwareScannerRunner([baseline])
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)

    components = await orchestrator._replay_scanners(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[baseline],
    )

    assert scanner.allow_fork_probing == []
    assert len(components) == 1
    assert components[0].status is ReplayComponentStatus.BLOCKED


@pytest.mark.asyncio
async def test_repository_suite_replay_rejects_source_drift_during_execution(
    tmp_path: Path,
) -> None:
    source = tmp_path / "Vault.sol"
    source.write_text("contract Vault {}\n", encoding="utf-8")
    repository_sha256 = scanner_workspace_sha256(tmp_path, tmp_path / ".mmaudit")
    baseline = _repository_suite_scanner_run(repository_sha256=repository_sha256)

    def mutate_source() -> None:
        source.write_text(
            "contract Vault { uint256 changed; }\n",
            encoding="utf-8",
        )

    scanner = _ForkAwareScannerRunner(
        [baseline],
        before_return=mutate_source,
    )
    orchestrator = OfflineReplayOrchestrator(scanner_runner=scanner)

    components = await orchestrator._replay_scanners(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=[baseline],
    )

    assert scanner.allow_fork_probing == [True]
    assert len(components) == 1
    assert components[0].status is ReplayComponentStatus.BLOCKED


@pytest.mark.asyncio
async def test_repository_differential_replays_as_a_separate_offline_component(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repository_differential(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    expected = RepositorySuiteDifferentialRun.model_validate_json(
        (run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    )
    baseline = _differential_baseline(expected)
    scanner = _ForkAwareScannerRunner([baseline])
    invariant = _LocalInvariantRunner(_invariant_result())
    reproduction = _LocalReproductionRunner(_reproduction_result())
    differential = _LocalDifferentialRunner(expected)

    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline differential replay attempted network access")

    def deny_default_runner(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("explicit differential runner did not retain precedence")

    def deny_default_isolation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("fully injected replay attempted default isolation resolution")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(
        "mmaudit.models.openrouter.OpenRouterClient.__init__",
        deny_network,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        deny_default_runner,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        deny_default_isolation,
    )
    orchestrator = OfflineReplayOrchestrator(
        config,
        scanner_runner=scanner,
        invariant_runner=invariant,
        reproduction_runner=reproduction,
        differential_runner=differential,
    )
    replay = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "differential-work",
    )

    component = next(
        item
        for item in replay.components
        if item.kind is ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL
    )
    assert replay.status is OfflineReplayStatus.REPLAYED
    assert component.status is ReplayComponentStatus.MATCHED
    assert component.execution_evidence is ExecutionEvidenceKind.REAL
    assert differential.calls == 1
    assert differential.baseline_runs == [baseline]
    assert orchestrator.scanner_runner is scanner
    assert orchestrator.invariant_runner is invariant
    assert orchestrator.reproduction_runner is reproduction
    assert orchestrator.differential_runner is differential
    assert differential.repository_sha256s == [
        expected.matrix.repository_sha256 if expected.matrix is not None else ""
    ]
    scanner_artifact = json.loads((run_dir / "scanner-results.json").read_text(encoding="utf-8"))
    assert len(scanner_artifact["runs"]) == 1
    assert expected.matrix is not None
    assert len(expected.matrix.attempts) == 4
    assert ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL in replay.applicable_kinds
    assert ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL not in replay.missing_kinds
    assert replay.model_provider_contacted is False
    assert replay.remote_network_policy == "denied"
    assert replay.loopback_policy == "local_only"


@pytest.mark.asyncio
async def test_rootless_configured_replay_fails_closed_when_exact_backend_is_unavailable(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _rootless_repository_differential_config(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    resolutions: list[tuple[str, str | None, str]] = []

    def unavailable_backend(
        configured: str,
        *,
        rootless_container_image: str | None = None,
        rootless_container_runtime: str = "auto",
    ) -> None:
        resolutions.append((configured, rootless_container_image, rootless_container_runtime))
        return None

    def deny_runner_construction(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("runner construction followed failed isolation resolution")

    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        unavailable_backend,
    )
    monkeypatch.setattr("mmaudit.orchestration.replay.ScannerRunner", deny_runner_construction)
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.FoundryInvariantRunner",
        deny_runner_construction,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.ForkReproductionRunner",
        deny_runner_construction,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        deny_runner_construction,
    )

    with pytest.raises(
        ValueError,
        match="configured hardened isolation backend is unavailable",
    ):
        await OfflineReplayOrchestrator(config).replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "missing-rootless-backend-work",
        )

    assert resolutions == [
        (
            "rootless-container",
            "registry.invalid/mmaudit-replay@sha256:" + ("a" * 64),
            "podman",
        )
    ]


@pytest.mark.asyncio
async def test_stale_manifest_refuses_backend_resolution_and_default_runner_construction(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _rootless_repository_differential_config(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    scanner_binding = next(
        binding
        for binding in artifacts
        if isinstance(binding, dict) and binding.get("path") == "scanner-results.json"
    )
    scanner_binding["sha256"] = "0" * 64
    _reseal_manifest_payload(manifest_path, payload)
    calls: list[str] = []

    def deny_backend_resolution(*_args: object, **_kwargs: object) -> None:
        calls.append("backend")
        raise AssertionError("stale manifest reached isolation backend resolution")

    def deny_runner_construction(*_args: object, **_kwargs: object) -> None:
        calls.append("runner")
        raise AssertionError("stale manifest reached default runner construction")

    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        deny_backend_resolution,
    )
    monkeypatch.setattr("mmaudit.orchestration.replay.ScannerRunner", deny_runner_construction)
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.FoundryInvariantRunner",
        deny_runner_construction,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.ForkReproductionRunner",
        deny_runner_construction,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        deny_runner_construction,
    )

    with pytest.raises(ValueError, match="refused stale"):
        await OfflineReplayOrchestrator(config).replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "stale-manifest-work",
        )

    assert calls == []


@pytest.mark.asyncio
async def test_rootless_configured_replay_shares_one_exact_backend_across_default_runners(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _rootless_repository_differential_config(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    expected = RepositorySuiteDifferentialRun.model_validate_json(
        (run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    )
    backend = _LocalIsolationBackend()
    baseline = _differential_baseline(expected)
    clean_state_provider = object()
    differential_factory = _DefaultDifferentialRunnerFactory(
        expected,
        backend,
        clean_state_provider,
    )
    resolutions: list[tuple[str, str | None, str]] = []
    constructed: dict[str, object] = {}

    def resolve_backend(
        configured: str,
        *,
        rootless_container_image: str | None = None,
        rootless_container_runtime: str = "auto",
    ) -> _LocalIsolationBackend:
        resolutions.append((configured, rootless_container_image, rootless_container_runtime))
        return backend

    def scanner_factory(
        configured: AuditConfig,
        *,
        backend: object,
    ) -> _ForkAwareScannerRunner:
        assert configured.stable_hash() == config.stable_hash()
        constructed["scanner"] = backend
        return _ForkAwareScannerRunner([baseline], backend=backend)

    def invariant_factory(
        reproduction: ReproductionConfig,
        smart_contracts: SmartContractsConfig,
        *,
        backend: object,
    ) -> _LocalInvariantRunner:
        assert reproduction == config.reproduction
        assert smart_contracts == config.smart_contracts
        constructed["invariant"] = backend
        return _LocalInvariantRunner(_invariant_result(), backend=backend)

    def reproduction_factory(
        reproduction: ReproductionConfig,
        smart_contracts: SmartContractsConfig,
        *,
        backend: object,
    ) -> _LocalReproductionRunner:
        assert reproduction == config.reproduction
        assert smart_contracts == config.smart_contracts
        constructed["reproduction"] = backend
        return _LocalReproductionRunner(_reproduction_result(), backend=backend)

    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        resolve_backend,
    )
    monkeypatch.setattr("mmaudit.orchestration.replay.ScannerRunner", scanner_factory)
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.FoundryInvariantRunner",
        invariant_factory,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.ForkReproductionRunner",
        reproduction_factory,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        differential_factory,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.TrustedCleanAnvilLauncher",
        lambda: clean_state_provider,
    )

    orchestrator = OfflineReplayOrchestrator(config)
    replay = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "shared-rootless-backend-work",
    )

    assert replay.status is OfflineReplayStatus.REPLAYED
    assert resolutions == [
        (
            "rootless-container",
            "registry.invalid/mmaudit-replay@sha256:" + ("a" * 64),
            "podman",
        )
    ]
    assert constructed == {
        "scanner": backend,
        "invariant": backend,
        "reproduction": backend,
    }
    assert getattr(orchestrator.scanner_runner, "backend", None) is backend
    assert getattr(orchestrator.invariant_runner, "backend", None) is backend
    assert getattr(orchestrator.reproduction_runner, "backend", None) is backend
    assert getattr(orchestrator.differential_runner, "backend", None) is backend
    assert differential_factory.calls == 1


@pytest.mark.asyncio
async def test_profile_overridden_replay_builds_default_backend_bound_differential_runner(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_config = _config_with_repository_differential(config_factory())
    cli_overrides = audit_config_overrides({"profile": AuditProfile.DEEP.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
        with_repository_differential=True,
    )
    expected = RepositorySuiteDifferentialRun.model_validate_json(
        (run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    )
    backend = _LocalIsolationBackend()
    scanner = _ForkAwareScannerRunner(
        [_differential_baseline(expected)],
        backend=backend,
    )
    clean_state_provider = object()
    factory = _DefaultDifferentialRunnerFactory(
        expected,
        backend,
        clean_state_provider,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        factory,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.TrustedCleanAnvilLauncher",
        lambda: clean_state_provider,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        lambda *_args, **_kwargs: backend,
    )
    orchestrator = OfflineReplayOrchestrator(
        scanner_runner=scanner,
        invariant_runner=_LocalInvariantRunner(_invariant_result()),
        reproduction_runner=_LocalReproductionRunner(_reproduction_result()),
    )

    replay = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "default-differential-work",
    )

    component = next(
        item
        for item in replay.components
        if item.kind is ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL
    )
    assert replay.status is OfflineReplayStatus.REPLAYED
    assert component.status is ReplayComponentStatus.MATCHED
    assert factory.calls == 1
    assert len(factory.constructed_smart_contracts) == 1
    assert factory.constructed_smart_contracts == [effective_config.smart_contracts]
    assert factory.constructed_reproduction == [effective_config.reproduction]
    assert orchestrator.config is not None
    assert orchestrator.config.stable_hash() == effective_config.stable_hash()


@pytest.mark.asyncio
async def test_default_differential_replay_reserves_each_attempt_full_policy_timeout(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config_with_repository_differential(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    expected = RepositorySuiteDifferentialRun.model_validate_json(
        (run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    )
    backend = _LocalIsolationBackend()
    scanner = _ForkAwareScannerRunner(
        [_differential_baseline(expected)],
        backend=backend,
    )
    clean_state_provider = object()
    factory = _DefaultDifferentialRunnerFactory(
        expected,
        backend,
        clean_state_provider,
    )
    clock_value = 100.0
    wait_for_timeouts: list[float | None] = []
    original_wait_for = asyncio.wait_for

    async def capture_wait_for_timeout(
        future,
        timeout: float | None,
    ):
        wait_for_timeouts.append(timeout)
        return await original_wait_for(future, timeout)

    monkeypatch.setattr(
        "mmaudit.orchestration.replay.RepositoryForkMatrixRunner",
        factory,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.TrustedCleanAnvilLauncher",
        lambda: clean_state_provider,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.default_isolation_backend",
        lambda *_args, **_kwargs: backend,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.time.monotonic",
        lambda: clock_value,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.replay.asyncio.wait_for",
        capture_wait_for_timeout,
    )

    replay = await OfflineReplayOrchestrator(
        config,
        scanner_runner=scanner,
        invariant_runner=_LocalInvariantRunner(_invariant_result()),
        reproduction_runner=_LocalReproductionRunner(_reproduction_result()),
    ).replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "default-differential-timeout-work",
    )

    suite = config.smart_contracts.repository_suite
    matrix_timeout_budget = repository_fork_matrix_timeout_budget_seconds(suite)
    assert replay.status is OfflineReplayStatus.REPLAYED
    assert factory.calls == 1
    assert len(factory.absolute_deadlines) == 1
    assert factory.absolute_deadlines[0] == pytest.approx(clock_value + matrix_timeout_budget)
    assert wait_for_timeouts == pytest.approx(
        [matrix_timeout_budget + REPOSITORY_FORK_MATRIX_RETURN_CLEANUP_RESERVE_SECONDS]
    )
    assert wait_for_timeouts[0] is not None
    assert wait_for_timeouts[0] > factory.absolute_deadlines[0] - clock_value


@pytest.mark.asyncio
async def test_failed_repository_differential_replay_cannot_match(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = _config_with_repository_differential(config_factory())
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        config,
        candidate,
        with_repository_differential=True,
    )
    expected = RepositorySuiteDifferentialRun.model_validate_json(
        (run_dir / "repository-suite-differential.json").read_text(encoding="utf-8")
    )
    failed = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.FAILED,
        configuration_sha256=expected.configuration_sha256,
        requested_state_ids=expected.requested_state_ids,
        required_repetitions=expected.required_repetitions,
        matrix=None,
        limitations=("The local pinned state prerequisite was unavailable.",),
    )
    replay = await OfflineReplayOrchestrator(
        config,
        scanner_runner=_ForkAwareScannerRunner([_differential_baseline(expected)]),
        invariant_runner=_LocalInvariantRunner(_invariant_result()),
        reproduction_runner=_LocalReproductionRunner(_reproduction_result()),
        differential_runner=_LocalDifferentialRunner(failed),
    ).replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "failed-differential-work",
    )

    component = next(
        item
        for item in replay.components
        if item.kind is ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL
    )
    assert replay.status is OfflineReplayStatus.INCOMPLETE
    assert component.status is ReplayComponentStatus.BLOCKED
    assert component.observed_state == RepositoryDifferentialRunStatus.FAILED.value
    assert ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL in replay.missing_kinds


@pytest.mark.asyncio
async def test_missing_configured_repository_differential_is_blocked_without_execution(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    _repository, run_dir, _manifest_path = _write_replay_run(
        tmp_path,
        base_config,
        candidate,
    )
    config = _config_with_repository_differential(base_config)
    artifacts = _load_replay_artifacts(run_dir, config=config)
    assert artifacts.differential_required is True
    assert artifacts.differential is None
    assert artifacts.differential_limitation is not None
    runner = _LocalDifferentialRunner(None)
    orchestrator = OfflineReplayOrchestrator(
        config,
        differential_runner=runner,
    )

    components = await orchestrator._replay_repository_differential(
        repository=tmp_path,
        private_dir=tmp_path / "private",
        projects=[],
        expected=None,
        artifact_required=True,
        artifact_limitation="configured differential artifact is missing",
        expected_scanner_runs=[],
        observed_scanner_runs=[],
    )

    assert len(components) == 1
    assert components[0].kind is ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL
    assert components[0].status is ReplayComponentStatus.BLOCKED
    assert components[0].executed is False
    assert runner.calls == 0


def test_repository_differential_projection_excludes_volatility_and_endpoints(
    config_factory,
) -> None:
    config = _config_with_repository_differential(config_factory())
    expected = _differential_result(config, "9" * 64)
    volatile = expected.model_copy(deep=True)
    assert volatile.matrix is not None
    volatile.matrix.attempts[0].workspace_identity_sha256 = "8" * 64
    volatile.matrix.attempts[0].workspace_freshness_attestation_sha256 = "7" * 64
    volatile.matrix.attempts[0].scanner_run.started_at = datetime(
        2030,
        1,
        1,
        tzinfo=UTC,
    )
    volatile.matrix.attempts[0].scanner_run.duration_seconds = 99
    volatile.matrix.attempts[0].scanner_run.command = [
        "/private/replay-nonce/forge",
        "test",
        "http://127.0.0.1:9999",
    ]
    volatile.matrix.attempts[0].scanner_run.raw_output_path = "/private/replay-nonce/output.json"
    volatile.matrix.attempts[0].scanner_run.repository_test_executions[0].duration_seconds = 55
    volatile_clean = volatile.matrix.states[0]
    assert volatile_clean.clean_state_attestation is not None
    volatile_clean.state_source_sha256 = "6" * 64
    volatile_clean.clean_state_attestation.process_attestation_sha256 = "5" * 64
    volatile_clean.clean_state_attestation.startup_duration_seconds = 12
    volatile_clean.clean_state_attestation.termination_method = "kill"
    volatile_clean.clean_state_attestation.termination_duration_seconds = 9
    volatile_clean.clean_state_attestation.attestation_sha256 = "4" * 64
    volatile_attempt = volatile.matrix.attempts[0]
    volatile_copy = volatile_attempt.scanner_run.repository_suite_workspace_copy
    assert volatile_copy is not None
    volatile_copy.attempt_binding_sha256 = "3" * 64
    volatile_copy.source_root_device_before = 101
    volatile_copy.source_root_device_after = 101
    volatile_copy.source_root_inode_before = 102
    volatile_copy.source_root_inode_after = 102
    volatile_copy.workspace_root_device_before = 103
    volatile_copy.workspace_root_device_after = 103
    volatile_copy.workspace_root_inode_before = 104
    volatile_copy.workspace_root_inode_after = 104
    volatile_copy.workspace_parent_device = 105
    volatile_copy.workspace_parent_inode = 106
    volatile_copy.copy_evidence_sha256 = "2" * 64
    volatile_lifecycle = volatile_attempt.workspace_lifecycle
    volatile_lifecycle.attempt_binding_sha256 = "3" * 64
    volatile_lifecycle.workspace_copy_evidence_sha256 = "2" * 64
    volatile_lifecycle.scanner_execution_observation_sha256 = "1" * 64
    volatile_lifecycle.freshness_attestation_sha256 = "0" * 63 + "1"
    volatile_lifecycle.attempt_root_device = 105
    volatile_lifecycle.attempt_root_inode = 106
    volatile_lifecycle.removal_duration_seconds = 4
    volatile_lifecycle.lifecycle_evidence_sha256 = "f" * 64
    volatile_egress = volatile_attempt.scanner_run.fork_rpc_egress
    assert volatile_egress is not None
    volatile_egress.selected_test_scope_snapshot_sha256s = ("e" * 64,)
    volatile_egress.bridge_snapshot_sha256 = "d" * 64
    volatile_egress.evidence_sha256 = "c" * 64
    volatile_scope = volatile_attempt.scanner_run.repository_test_fork_rpc_scopes[0]
    volatile_scope.attempt_binding_sha256 = "b" * 64
    volatile_scope.selection_sha256 = "a" * 64
    volatile_scope.bridge_scope_snapshot_sha256 = "9" * 64
    volatile_scope.evidence_sha256 = "8" * 64
    volatile_cleanup = volatile.matrix.state_workspace_cleanups[0]
    volatile_cleanup.attempt_cleanup_sequence_lifecycle_sha256s = tuple(
        "7" * 64 for _item in volatile_cleanup.attempt_cleanup_sequence_lifecycle_sha256s
    )
    volatile_cleanup.attempt_cumulative_removal_duration_seconds = tuple(
        duration + 1 for duration in volatile_cleanup.attempt_cumulative_removal_duration_seconds
    )
    volatile_cleanup.removal_duration_seconds += 1
    volatile_cleanup.aggregate_evidence_sha256 = "6" * 64

    expected_projection = _repository_differential_projection(expected)
    observed_projection = _repository_differential_projection(volatile)
    serialized = json.dumps(observed_projection, sort_keys=True)
    matrix = expected.matrix
    assert matrix is not None

    assert observed_projection == expected_projection
    assert "/private/" not in serialized
    assert "http://" not in serialized
    assert "127.0.0.1" not in serialized
    assert "MMAUDIT_PINNED_RPC_URL" not in serialized
    assert "started_at" not in serialized
    assert "duration_seconds" not in serialized
    assert "workspace_identity_sha256" not in serialized
    assert "workspace_freshness_attestation_sha256" not in serialized
    assert "attempt_binding_sha256" not in serialized
    assert "source_root_device" not in serialized
    assert "source_root_inode" not in serialized
    assert "workspace_root_device" not in serialized
    assert "workspace_root_inode" not in serialized
    assert "workspace_parent_device" not in serialized
    assert "workspace_parent_inode" not in serialized
    assert "attempt_root_device" not in serialized
    assert "attempt_root_inode" not in serialized
    assert "copy_evidence_sha256" not in serialized
    assert "lifecycle_evidence_sha256" not in serialized
    assert "scanner_execution_observation_sha256" not in serialized
    assert "freshness_attestation_sha256" not in serialized
    assert "process_attestation_sha256" not in serialized
    assert "termination_method" not in serialized
    assert "selected_test_scope_snapshot_sha256s" not in serialized
    assert "bridge_scope_snapshot_sha256" not in serialized
    assert "attempt_cleanup_sequence_lifecycle_sha256s" not in serialized
    assert "attempt_cumulative_removal_duration_seconds" not in serialized
    assert "aggregate_evidence_sha256" not in serialized
    assert "attempt_sha256" not in serialized
    assert expected.configuration_sha256 in serialized
    assert matrix.fuzz_seed in serialized
    assert matrix.execution_configuration_sha256 in serialized
    assert matrix.fork_rpc_policy_sha256 in serialized
    assert matrix.repository_sha256 in serialized
    assert matrix.states[0].state_id in serialized
    assert matrix.states[0].state_source_sha256 in serialized
    assert str(matrix.states[0].expected_chain_id) in serialized
    observed_block_hash = matrix.states[0].observed_block_hash
    assert observed_block_hash is not None
    assert observed_block_hash in serialized
    assert matrix.descriptor_sha256s[0] in serialized
    assert "clean_pass_pinned_failure" in serialized
    assert ExecutionEvidenceKind.REAL.value in serialized
    assert "repository_test_fork_rpc_scopes" in serialized
    assert "method_log_sha256" in serialized
    assert "copy_policy_sha256" in serialized
    assert "source_inventory_sha256_before" in serialized
    assert "workspace_inventory_sha256_after_copy" in serialized
    assert "disposal_policy_sha256" in serialized
    assert "state_workspace_cleanups" in serialized
    assert '"attempt_cleanup_sequence": "reverse_attempt_order"' in serialized
    assert "removal_entry_limit" in serialized
    assert "removal_depth_limit" in serialized
    assert "removal_timeout_seconds" in serialized
    assert '"private_path_retained": false' in serialized
    assert '"rpc_endpoint_retained": false' in serialized

    descriptor_scope_drift = expected.model_copy(deep=True)
    assert descriptor_scope_drift.matrix is not None
    scoped_run = descriptor_scope_drift.matrix.attempts[0].scanner_run
    first_scope = scoped_run.repository_test_fork_rpc_scopes[0]
    second_scope = first_scope.model_copy(deep=True)
    object.__setattr__(first_scope, "descriptor_sha256", "a" * 64)
    object.__setattr__(first_scope, "method_log_sha256", "b" * 64)
    object.__setattr__(second_scope, "descriptor_sha256", "c" * 64)
    object.__setattr__(second_scope, "method_log_sha256", "d" * 64)
    scoped_run.repository_test_fork_rpc_scopes = [first_scope, second_scope]
    scoped_projection = _repository_differential_projection(descriptor_scope_drift)
    swapped_semantics = descriptor_scope_drift.model_copy(deep=True)
    assert swapped_semantics.matrix is not None
    swapped_scopes = swapped_semantics.matrix.attempts[
        0
    ].scanner_run.repository_test_fork_rpc_scopes
    object.__setattr__(swapped_scopes[0], "method_log_sha256", "d" * 64)
    object.__setattr__(swapped_scopes[1], "method_log_sha256", "b" * 64)
    assert (
        swapped_semantics.matrix.attempts[0].scanner_run.fork_rpc_egress
        == descriptor_scope_drift.matrix.attempts[0].scanner_run.fork_rpc_egress
    )
    assert _repository_differential_projection(swapped_semantics) != scoped_projection

    identity_drift = expected.model_copy(deep=True)
    assert identity_drift.matrix is not None
    identity_drift.matrix.fuzz_seed = "0x" + ("0" * 63) + "2"
    assert _repository_differential_projection(identity_drift) != expected_projection

    copy_drift = expected.model_copy(deep=True)
    assert copy_drift.matrix is not None
    copy_evidence = copy_drift.matrix.attempts[0].scanner_run.repository_suite_workspace_copy
    assert copy_evidence is not None
    copy_evidence.source_inventory_sha256_before = "0" * 63 + "1"
    assert _repository_differential_projection(copy_drift) != expected_projection

    disposal_policy_drift = expected.model_copy(deep=True)
    assert disposal_policy_drift.matrix is not None
    disposal_policy_drift.matrix.attempts[0].workspace_lifecycle.disposal_policy_sha256 = (
        "0" * 63 + "1"
    )
    assert _repository_differential_projection(disposal_policy_drift) != expected_projection

    disposal_bounds_drift = expected.model_copy(deep=True)
    assert disposal_bounds_drift.matrix is not None
    disposal_bounds_drift.matrix.attempts[0].workspace_lifecycle.removal_entry_limit -= 1
    assert _repository_differential_projection(disposal_bounds_drift) != expected_projection

    retention_drift = expected.model_copy(deep=True)
    assert retention_drift.matrix is not None
    object.__setattr__(
        retention_drift.matrix.attempts[0].workspace_lifecycle,
        "private_path_retained",
        True,
    )
    assert _repository_differential_projection(retention_drift) != expected_projection

    aggregate_cleanup_drift = expected.model_copy(deep=True)
    assert aggregate_cleanup_drift.matrix is not None
    aggregate_cleanup_drift.matrix.state_workspace_cleanups[0].owned_directory_count += 1
    assert _repository_differential_projection(aggregate_cleanup_drift) != expected_projection


def test_repository_differential_qualification_requires_copy_and_lifecycle_evidence(
    config_factory,
) -> None:
    config = _config_with_repository_differential(config_factory())
    expected = _differential_result(config, "9" * 64)

    missing_copy = expected.model_copy(deep=True)
    assert missing_copy.matrix is not None
    missing_copy.matrix.attempts[0].scanner_run.repository_suite_workspace_copy = None
    assert not _repository_differential_is_qualifying(
        missing_copy,
        config=config,
        repository_sha256="9" * 64,
    )

    uncredited_lifecycle = expected.model_copy(deep=True)
    assert uncredited_lifecycle.matrix is not None
    uncredited_lifecycle.matrix.attempts[
        0
    ].workspace_lifecycle.status = RepositorySuiteWorkspaceLifecycleStatus.DISPOSED_UNCREDITED
    assert not _repository_differential_is_qualifying(
        uncredited_lifecycle,
        config=config,
        repository_sha256="9" * 64,
    )

    parent_identity_mismatch = expected.model_copy(deep=True)
    assert parent_identity_mismatch.matrix is not None
    mismatched_copy = parent_identity_mismatch.matrix.attempts[
        0
    ].scanner_run.repository_suite_workspace_copy
    assert mismatched_copy is not None
    mismatched_copy.workspace_parent_inode += 1
    assert not _repository_differential_is_qualifying(
        parent_identity_mismatch,
        config=config,
        repository_sha256="9" * 64,
    )

    missing_state_cleanup = expected.model_copy(deep=True)
    assert missing_state_cleanup.matrix is not None
    missing_state_cleanup.matrix.state_workspace_cleanups = (
        missing_state_cleanup.matrix.state_workspace_cleanups[1:]
    )
    assert not _repository_differential_is_qualifying(
        missing_state_cleanup,
        config=config,
        repository_sha256="9" * 64,
    )

    retained_state_cleanup = expected.model_copy(deep=True)
    assert retained_state_cleanup.matrix is not None
    object.__setattr__(
        retained_state_cleanup.matrix.state_workspace_cleanups[0],
        "private_path_retained",
        True,
    )
    assert not _repository_differential_is_qualifying(
        retained_state_cleanup,
        config=config,
        repository_sha256="9" * 64,
    )


def _rewrite_manifest_as_legacy(manifest_path: Path) -> None:
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload["run_configuration"] = None
    payload["manifest_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in payload.items()
            if key not in {"manifest_sha256", "run_configuration"}
        }
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(payload),
    )


def _reseal_manifest_payload(
    manifest_path: Path,
    payload: dict[str, object],
) -> None:
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        manifest_path,
        RunEvidenceManifest.model_validate(payload),
    )


def _rebind_artifact(payload: dict[str, object], path: Path) -> None:
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    binding = next(
        item for item in artifacts if isinstance(item, dict) and item.get("path") == path.name
    )
    artifact_bytes = path.read_bytes()
    binding["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
    binding["size"] = len(artifact_bytes)


@pytest.mark.asyncio
async def test_local_fixture_replays_scanner_saved_test_and_counterexample_offline(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, scanner, invariant, reproduction = _orchestrator(config)

    def deny_network(*_args, **_kwargs):
        raise AssertionError("offline replay attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(
        "mmaudit.models.openrouter.OpenRouterClient.__init__",
        deny_network,
    )
    first = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "work-one",
    )
    second = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "work-two",
    )

    assert first == second
    assert first.status is OfflineReplayStatus.REPLAYED
    assert not first.model_provider_contacted
    assert first.remote_network_policy == "denied"
    assert not first.missing_kinds
    assert {item.kind for item in first.components} == {
        ReplayComponentKind.SCANNER,
        ReplayComponentKind.SAVED_TEST,
        ReplayComponentKind.COUNTEREXAMPLE,
    }
    assert all(item.status is ReplayComponentStatus.MATCHED for item in first.components)
    assert (scanner.calls, invariant.calls, reproduction.calls) == (2, 2, 2)
    assert OfflineReplay.model_validate_json(first.model_dump_json()) == first


@pytest.mark.asyncio
async def test_v11_replay_reconstructs_embedded_profile_override(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    cli_overrides = audit_config_overrides({"profile": AuditProfile.DEEP.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
    )
    orchestrator, scanner, invariant, reproduction = _orchestrator(None)

    replay = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "embedded-work",
    )

    assert replay.status is OfflineReplayStatus.REPLAYED
    assert orchestrator.config is not None
    assert orchestrator.config.stable_hash() == effective_config.stable_hash()
    assert orchestrator.config.profile is AuditProfile.DEEP
    assert (scanner.calls, invariant.calls, reproduction.calls) == (1, 1, 1)


def test_verify_run_cli_reconstructs_embedded_maximum_profile_without_config(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    cli_overrides = audit_config_overrides({"profile": AuditProfile.MAXIMUM_ASSURANCE.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
    )
    output = tmp_path / "maximum-profile-verification.json"

    result = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(manifest_path),
            "--run-dir",
            str(run_dir),
            "--repo",
            str(repository),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS, result.stdout
    verification = RunVerification.model_validate_json(output.read_text(encoding="utf-8"))
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    assert verification.status is RunVerificationStatus.CURRENT
    assert not verification.mismatches
    assert manifest.run_configuration is not None
    assert manifest.run_configuration.requested_profile is AuditProfile.MAXIMUM_ASSURANCE
    assert manifest.run_configuration.cli_overrides_sha256 == cli_overrides.stable_hash()


@pytest.mark.asyncio
async def test_v11_replay_reapplies_profile_override_to_explicit_base_config(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    cli_overrides = audit_config_overrides({"profile": AuditProfile.DEEP.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
    )
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result())
    reproduction = _LocalReproductionRunner(_reproduction_result())
    orchestrator = OfflineReplayOrchestrator(
        file_config=base_config,
        scanner_runner=scanner,
        invariant_runner=invariant,
        reproduction_runner=reproduction,
    )

    replay = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "explicit-base-work",
    )

    assert replay.status is OfflineReplayStatus.REPLAYED
    assert orchestrator.config is not None
    assert orchestrator.config.stable_hash() == effective_config.stable_hash()
    assert orchestrator.config.profile is AuditProfile.DEEP


@pytest.mark.asyncio
async def test_v11_replay_rejects_changed_base_masked_by_profile_override(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    cli_overrides = audit_config_overrides({"profile": AuditProfile.DEEP.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
    )
    changed_base = base_config.model_copy(update={"profile": AuditProfile.QUICK})
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result())
    reproduction = _LocalReproductionRunner(_reproduction_result())
    orchestrator = OfflineReplayOrchestrator(
        file_config=changed_base,
        scanner_runner=scanner,
        invariant_runner=invariant,
        reproduction_runner=reproduction,
    )

    with pytest.raises(ValueError, match="refused stale"):
        await orchestrator.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "changed-base-work",
        )

    assert (scanner.calls, invariant.calls, reproduction.calls) == (0, 0, 0)


@pytest.mark.asyncio
async def test_v10_replay_requires_explicit_config(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    _rewrite_manifest_as_legacy(manifest_path)
    without_config, scanner, invariant, reproduction = _orchestrator(None)

    missing_config_verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )
    assert missing_config_verification.status is RunVerificationStatus.STALE
    explicit_config_verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )
    assert explicit_config_verification.status is RunVerificationStatus.CURRENT

    with pytest.raises(ValueError, match="legacy run manifest requires"):
        await without_config.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "legacy-missing-config-work",
        )

    assert (scanner.calls, invariant.calls, reproduction.calls) == (0, 0, 0)
    with_config, _, _, _ = _orchestrator(config)
    replay = await with_config.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "legacy-explicit-config-work",
    )
    assert replay.status is OfflineReplayStatus.REPLAYED


def test_verify_run_rejects_self_consistent_run_options_manifest_tamper(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    run_configuration = payload["run_configuration"]
    assert isinstance(run_configuration, dict)
    options = AuditRunOptions.model_validate(run_configuration["run_options"]).model_copy(
        update={"scanner_only": True}
    )
    run_configuration["run_options"] = options.model_dump(mode="json")
    run_configuration["run_options_sha256"] = options.stable_hash()
    run_configuration["invocation_sha256"] = canonical_sha256(
        {
            "environment_overrides_sha256": run_configuration["environment_overrides_sha256"],
            "cli_overrides_sha256": run_configuration["cli_overrides_sha256"],
            "run_options_sha256": run_configuration["run_options_sha256"],
            "effective_config_sha256": run_configuration["effective_config_sha256"],
            "requested_profile": run_configuration["requested_profile"],
            "achieved_profile": run_configuration["achieved_profile"],
        }
    )
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert {mismatch.identifier for mismatch in verification.mismatches} >= {
        "report/configuration-provenance",
        "report/run-options",
    }


def test_verify_run_rejects_manifest_and_report_tamper_against_emitted_metadata(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    run_configuration = payload["run_configuration"]
    assert isinstance(run_configuration, dict)
    options = AuditRunOptions.model_validate(run_configuration["run_options"]).model_copy(
        update={"scanner_only": True}
    )
    run_configuration["run_options"] = options.model_dump(mode="json")
    run_configuration["run_options_sha256"] = options.stable_hash()
    run_configuration["invocation_sha256"] = canonical_sha256(
        {
            "environment_overrides_sha256": run_configuration["environment_overrides_sha256"],
            "cli_overrides_sha256": run_configuration["cli_overrides_sha256"],
            "run_options_sha256": run_configuration["run_options_sha256"],
            "effective_config_sha256": run_configuration["effective_config_sha256"],
            "requested_profile": run_configuration["requested_profile"],
            "achieved_profile": run_configuration["achieved_profile"],
        }
    )

    report_path = run_dir / "final-findings.json"
    report = AuditReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    report_metadata = dict(report.metadata)
    report_metadata["run_options"] = options.model_dump(mode="json")
    provenance = dict(report_metadata["configuration_provenance"])
    provenance["run_options_sha256"] = options.stable_hash()
    report_metadata["configuration_provenance"] = provenance
    write_json(
        report_path,
        report.model_copy(update={"metadata": report_metadata}),
    )
    report_bytes = report_path.read_bytes()
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    final_binding = next(
        binding
        for binding in artifacts
        if isinstance(binding, dict) and binding.get("path") == "final-findings.json"
    )
    final_binding["sha256"] = hashlib.sha256(report_bytes).hexdigest()
    final_binding["size"] = len(report_bytes)
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert {mismatch.identifier for mismatch in verification.mismatches} >= {
        "metadata/configuration-provenance",
        "metadata/run-options",
    }


def test_verify_run_rejects_v11_missing_metadata_when_binding_is_removed(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    (run_dir / "metadata.json").unlink()
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    payload["artifacts"] = [
        binding
        for binding in artifacts
        if not isinstance(binding, dict) or binding.get("path") != "metadata.json"
    ]
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert "metadata/missing" in {mismatch.identifier for mismatch in verification.mismatches}


def test_verify_run_rejects_type_confused_metadata_boolean(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["completed"] is True
    metadata["completed"] = 1
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    _rebind_artifact(payload, metadata_path)
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert "metadata/completed" in {mismatch.identifier for mismatch in verification.mismatches}


@pytest.mark.parametrize("nonfinite_json", ["NaN", "Infinity", "1e999"])
def test_verify_run_normalizes_nonfinite_metadata_to_stale(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    nonfinite_json: str,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    metadata_path = run_dir / "metadata.json"
    serialized_metadata = metadata_path.read_text(encoding="utf-8")
    assert '"completed": true' in serialized_metadata
    metadata_path.write_text(
        serialized_metadata.replace(
            '"completed": true',
            f'"completed": {nonfinite_json}',
        ),
        encoding="utf-8",
    )
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    _rebind_artifact(payload, metadata_path)
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert "metadata/validation" in {mismatch.identifier for mismatch in verification.mismatches}


def test_verify_run_rejects_override_layer_reclassification(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    base_config = config_factory()
    cli_overrides = audit_config_overrides({"profile": AuditProfile.DEEP.value})
    effective_config = cli_overrides.apply(base_config)
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(
        tmp_path,
        effective_config,
        candidate,
        file_config=base_config,
        cli_overrides=cli_overrides,
    )
    manifest = RunEvidenceManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    payload = manifest.model_dump(mode="json")
    run_configuration = payload["run_configuration"]
    assert isinstance(run_configuration, dict)
    empty_overrides = AuditConfigOverrides()
    run_configuration["environment_overrides"] = run_configuration["cli_overrides"]
    run_configuration["environment_overrides_sha256"] = cli_overrides.stable_hash()
    run_configuration["cli_overrides"] = empty_overrides.model_dump(mode="json")
    run_configuration["cli_overrides_sha256"] = empty_overrides.stable_hash()
    run_configuration["invocation_sha256"] = canonical_sha256(
        {
            "environment_overrides_sha256": run_configuration["environment_overrides_sha256"],
            "cli_overrides_sha256": run_configuration["cli_overrides_sha256"],
            "run_options_sha256": run_configuration["run_options_sha256"],
            "effective_config_sha256": run_configuration["effective_config_sha256"],
            "requested_profile": run_configuration["requested_profile"],
            "achieved_profile": run_configuration["achieved_profile"],
        }
    )
    _reseal_manifest_payload(manifest_path, payload)

    verification = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert "report/configuration-provenance" in {
        mismatch.identifier for mismatch in verification.mismatches
    }


@pytest.mark.asyncio
async def test_replay_detects_semantic_drift_and_verifies_before_execution(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    scanner = _LocalScannerRunner([_scanner_run()])
    invariant = _LocalInvariantRunner(_invariant_result(InvariantExecutionStatus.PASSED))
    reproduction = _LocalReproductionRunner(_reproduction_result())
    orchestrator = OfflineReplayOrchestrator(
        config,
        scanner_runner=scanner,
        invariant_runner=invariant,
        reproduction_runner=reproduction,
    )

    drifted = await orchestrator.replay(
        manifest_path=manifest_path,
        run_dir=run_dir,
        repository_root=repository,
        work_dir=tmp_path / "drift-work",
    )
    assert drifted.status is OfflineReplayStatus.DRIFTED
    assert any(
        item.kind is ReplayComponentKind.COUNTEREXAMPLE
        and item.status is ReplayComponentStatus.DRIFTED
        for item in drifted.components
    )

    (repository / "src" / "Vault.sol").write_text("contract Vault { }\n", encoding="utf-8")
    calls_before = (scanner.calls, invariant.calls, reproduction.calls)
    with pytest.raises(ValueError, match="refused stale"):
        await orchestrator.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "stale-work",
        )
    assert (scanner.calls, invariant.calls, reproduction.calls) == calls_before


def test_replay_cli_and_published_schema(
    tmp_path: Path,
    config_factory,
    candidate_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, _, _, _ = _orchestrator(None)
    monkeypatch.setattr(
        "mmaudit.cli.OfflineReplayOrchestrator",
        lambda _config=None, **_kwargs: orchestrator,
    )
    output = tmp_path / "offline-replay.json"
    result = runner.invoke(
        app,
        [
            "replay",
            "--manifest",
            str(manifest_path),
            "--run-dir",
            str(run_dir),
            "--repo",
            str(repository),
            "--output",
            str(output),
            "--work-dir",
            str(tmp_path / "cli-work"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    replay = OfflineReplay.model_validate_json(output.read_text(encoding="utf-8"))
    assert replay.status is OfflineReplayStatus.REPLAYED
    tampered = replay.model_dump(mode="json")
    tampered["run_id"] = "tampered"
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        OfflineReplay.model_validate(tampered)
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas" / "offline_replay.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["additionalProperties"] is False
    assert schema["properties"]["components"]["maxItems"] == 200_000
    assert "applicable_kinds" in schema["required"]
    assert schema["properties"]["applicable_kinds"]["minItems"] == 1
    assert schema["$defs"]["component"]["additionalProperties"] is False
    assert schema["properties"]["model_provider_contacted"] == {"const": False}


def test_verify_run_cli_uses_embedded_v11_configuration(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    output = tmp_path / "run-verification.json"

    result = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(manifest_path),
            "--run-dir",
            str(run_dir),
            "--repo",
            str(repository),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS, result.stdout
    verification = RunVerification.model_validate_json(output.read_text(encoding="utf-8"))
    assert verification.status is RunVerificationStatus.CURRENT


def test_replay_writer_rejects_links(
    tmp_path: Path,
    config_factory,
    candidate_factory,
) -> None:
    config = config_factory()
    candidate = candidate_factory(
        candidate_id="candidate-replay",
        path="src/Vault.sol",
        start_line=1,
        end_line=1,
    )
    repository, run_dir, manifest_path = _write_replay_run(tmp_path, config, candidate)
    orchestrator, _, _, _ = _orchestrator(config)
    replay = asyncio.run(
        orchestrator.replay(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository,
            work_dir=tmp_path / "writer-work",
        )
    )
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="may not be a link"):
        write_offline_replay(linked, replay)
