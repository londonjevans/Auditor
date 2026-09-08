from __future__ import annotations

import hashlib
import json
import os
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import mmaudit.benchmark.foundry_mutation_executor as mutation_executor_module
from mmaudit.benchmark.foundry_mutation_executor import (
    ExactFoundryMutationExecutor,
    FoundryMutationExecutionError,
    _build_testing_execution_path,
    _ExecuteMutation,
    canonical_foundry_mutation_test_id,
    has_host_mutation_suite_runtime_authority,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationSuiteObservation,
    MutationSuiteTestStatus,
    SourceMutationSpec,
    mutation_repository_sha256,
)
from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    ForkRpcReadOnlyEgressEvidence,
    FoundryTestExecutionSummary,
    Location,
    RepositoryCodeExecutionState,
    RepositoryForkEgressStatus,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteInventoryArtifact,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositorySuiteInventoryRecord,
    RepositorySuiteProjectInventoryEvidence,
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
)
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.runtime_evidence import (
    _build_foundry_runtime_authority,
    _ProcessLocalRevocationLease,
)

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64
_HASH_D = "d" * 64
_HASH_E = "e" * 64
_FORK_SEED = "0x" + ("0" * 63) + "1"


class _SyntheticIsolation:
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


def _workspace_pair(tmp_path: Path) -> tuple[Path, Path]:
    baseline = tmp_path / "baseline"
    mutant = tmp_path / "mutant"
    for workspace, source in (
        (baseline, "contract Vault { uint256 private value; }\n"),
        (mutant, "contract Vault { uint256 private changed; }\n"),
    ):
        (workspace / "src").mkdir(parents=True)
        (workspace / "src" / "Vault.sol").write_text(source, encoding="utf-8")
    return baseline, mutant


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


def _specification() -> SourceMutationSpec:
    return SourceMutationSpec(
        id="mut-access-guard",
        kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        path="src/Vault.sol",
        line=1,
        expected_file_sha256=_HASH_A,
        expected_line="require(msg.sender == owner);",
    )


def _compiler_inventories(
    workspace: Path,
    *,
    test_name: str,
    descriptor_source_sha256: str,
    tool_version: str,
    compiler_sha256: str,
) -> tuple[
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryRecord,
]:
    record = RepositorySuiteInventoryRecord.sealed(
        project_root=".",
        execution_path="test/Vault.t.sol",
        execution_suite_name="VaultTest",
        test_name=test_name,
        execution_signature=f"{test_name}()",
        execution_source_sha256=descriptor_source_sha256,
        execution_start_line=10,
        execution_end_line=12,
        execution_contract_ast_id=10,
        declaration_path="test/Vault.t.sol",
        declaration_suite_name="VaultTest",
        declaration_signature=f"{test_name}()",
        declaration_source_sha256=descriptor_source_sha256,
        declaration_start_line=10,
        declaration_end_line=12,
        declaration_contract_ast_id=10,
        declaration_function_ast_id=11,
        build_info_sha256=_HASH_E,
    )
    artifact = RepositorySuiteInventoryArtifact(
        name="build-info.json",
        sha256=_HASH_B,
        normalized_sha256=_HASH_E,
        bytes=2,
    )
    normalized_inventory_sha256 = _canonical_sha256([record.record_sha256])
    project = RepositorySuiteProjectInventoryEvidence.sealed(
        project_root=".",
        command_sha256=_HASH_A,
        process_exit_code=0,
        machine_output_validated=True,
        stdout_sha256=_HASH_B,
        stdout_bytes=2,
        stderr_sha256=_HASH_C,
        stderr_bytes=0,
        build_info_artifacts=(artifact,),
        build_info_bundle_sha256=_canonical_sha256([artifact.model_dump(mode="json")]),
        normalized_build_info_bundle_sha256=_canonical_sha256([_HASH_E]),
        parser_inventory_sha256=_HASH_D,
        records=(record,),
        normalized_inventory_sha256=normalized_inventory_sha256,
    )
    common: dict[str, object] = {
        "framework": RepositorySuiteFramework.FOUNDRY,
        "repository_sha256": mutation_repository_sha256(workspace),
        "configuration_sha256": _HASH_C,
        "tool_version": tool_version,
        "tool_sha256": _HASH_A,
        "compiler_version": "solc 0.8.30",
        "compiler_sha256": compiler_sha256,
        "isolation_backend": "synthetic-isolation",
        "isolation_attestation_sha256": _HASH_C,
        "execution_evidence": ExecutionEvidenceKind.REAL,
        "repository_code_execution": RepositoryCodeExecutionState.ISOLATED,
        "projects": (project,),
        "project_bundle_sha256": _canonical_sha256([project.project_inventory_sha256]),
        "normalized_inventory_sha256": normalized_inventory_sha256,
        "inventory_record_count": 1,
    }
    pre = RepositorySuiteInventoryEvidence.sealed(
        phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
        **common,
    )
    post = RepositorySuiteInventoryEvidence.sealed(
        phase=RepositorySuiteInventoryPhase.POST_EXECUTION,
        **common,
    )
    return pre, post, record


def _fork_evidence(
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
    *,
    scope_status: RepositoryTestForkRpcScopeStatus,
) -> tuple[
    RepositoryTestForkRpcScopeEvidence,
    ForkRpcReadOnlyEgressEvidence,
    RepositorySuiteWorkspaceCopyEvidence,
]:
    validated = scope_status is RepositoryTestForkRpcScopeStatus.VALIDATED
    method_counts = (ForkRpcMethodCount(method="eth_chainId", count=1),) if validated else ()
    scope_values: dict[str, object] = {
        "schema_version": "1.0",
        "attempt_binding_sha256": _HASH_B,
        "selection_sha256": selection.selection_sha256,
        "descriptor_sha256": selection.tests[0].descriptor_sha256,
        "sequence_index": 1,
        "bridge_policy_sha256": _HASH_A,
        "expected_chain_id": policy.chain_id,
        "pinned_block_number": policy.block_number,
        "pinned_block_hash": policy.block_hash,
        "status": scope_status,
        "http_request_count": 1 if validated else 0,
        "permitted_rpc_call_count": 1 if validated else 0,
        "origin_attempted_rpc_call_count": 1 if validated else 0,
        "origin_validated_rpc_call_count": 1 if validated else 0,
        "synthetic_rpc_call_count": 0,
        "denied_request_count": 0,
        "malformed_request_count": 0,
        "limit_exceeded_request_count": 0,
        "upstream_error_request_count": 0,
        "allowed_method_counts": method_counts,
        "method_log_sha256": _HASH_C,
        "boundary_drained": True,
        "transaction_capable_request_forwarded": False,
        "credentials_forwarded": False,
        "raw_payloads_retained": False,
        "rpc_endpoint_recorded": False,
    }
    scope = RepositoryTestForkRpcScopeEvidence.sealed(
        **scope_values,
        bridge_scope_snapshot_sha256=(
            RepositoryTestForkRpcScopeEvidence.calculate_bridge_scope_snapshot_sha256(scope_values)
        ),
    )
    origin_sha256 = ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
        expected_chain_id=policy.chain_id,
        pinned_block_number=policy.block_number,
        pinned_block_hash=policy.block_hash,
    )
    egress_values: dict[str, object] = {
        "schema_version": "2.0",
        "status": RepositoryForkEgressStatus.ENFORCED,
        "state_id": "pinned-fork",
        "state_source_sha256": _HASH_B,
        "expected_chain_id": policy.chain_id,
        "pinned_block_number": policy.block_number,
        "pinned_block_hash": policy.block_hash,
        "policy_sha256": _HASH_A,
        "method_log_sha256": _HASH_C,
        "selected_test_scope_snapshot_sha256s": (scope.bridge_scope_snapshot_sha256,),
        "preflight_origin_observation_sha256": origin_sha256,
        "postflight_origin_observation_sha256": origin_sha256,
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
        "allowed_method_counts": (ForkRpcMethodCount(method="eth_chainId", count=1),),
        "stopped_cleanly": True,
    }
    egress = ForkRpcReadOnlyEgressEvidence.sealed(
        **egress_values,
        bridge_snapshot_sha256=(
            ForkRpcReadOnlyEgressEvidence.calculate_bridge_snapshot_sha256(egress_values)
        ),
    )
    repository_sha256 = selection.repository_sha256
    workspace_copy = RepositorySuiteWorkspaceCopyEvidence.sealed(
        attempt_binding_sha256=_HASH_B,
        selection_sha256=selection.selection_sha256,
        repository_sha256=repository_sha256,
        source_inventory_sha256_before=repository_sha256,
        source_inventory_sha256_after=repository_sha256,
        workspace_inventory_sha256_after_copy=repository_sha256,
        workspace_inventory_sha256_after_execution=repository_sha256,
        source_root_device_before=1,
        source_root_inode_before=1,
        source_root_device_after=1,
        source_root_inode_after=1,
        workspace_root_device_before=1,
        workspace_root_inode_before=2,
        workspace_root_device_after=1,
        workspace_root_inode_after=2,
        workspace_parent_device=1,
        workspace_parent_inode=3,
    )
    return scope, egress, workspace_copy


def _repository_suite_run(
    workspace: Path,
    *,
    test_name: str = "testAccessGuard",
    test_status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
    descriptor_source_sha256: str = _HASH_A,
    tool_version: str = "1.3.2",
    compiler_sha256: str = _HASH_D,
    block_number: int = 1_234,
    fuzz_runs: int = 256,
    scanner_status: ScannerStatus = ScannerStatus.SUCCESS,
    include_egress: bool = True,
    include_scopes: bool = True,
    scope_status: RepositoryTestForkRpcScopeStatus = (RepositoryTestForkRpcScopeStatus.VALIDATED),
    compiler_bound: bool = True,
) -> ScannerRun:
    pre_inventory: RepositorySuiteInventoryEvidence | None = None
    post_inventory: RepositorySuiteInventoryEvidence | None = None
    record: RepositorySuiteInventoryRecord | None = None
    if compiler_bound:
        pre_inventory, post_inventory, record = _compiler_inventories(
            workspace,
            test_name=test_name,
            descriptor_source_sha256=descriptor_source_sha256,
            tool_version=tool_version,
            compiler_sha256=compiler_sha256,
        )
    descriptor_inventory: dict[str, Any] = {}
    if pre_inventory is not None and record is not None:
        descriptor_inventory = {
            "inventory_sha256": pre_inventory.normalized_inventory_sha256,
            "inventory_record_sha256": record.record_sha256,
            "execution_contract_ast_id": record.execution_contract_ast_id,
            "declaration_path": record.declaration_path,
            "declaration_suite_name": record.declaration_suite_name,
            "declaration_signature": record.declaration_signature,
            "declaration_source_sha256": record.declaration_source_sha256,
            "declaration_start_line": record.declaration_start_line,
            "declaration_end_line": record.declaration_end_line,
            "declaration_contract_ast_id": record.declaration_contract_ast_id,
            "declaration_function_ast_id": record.declaration_function_ast_id,
        }
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/Vault.t.sol",
        suite_name="VaultTest",
        test_name=test_name,
        source_sha256=descriptor_source_sha256,
        start_line=10,
        end_line=12,
        **descriptor_inventory,
    )
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=mutation_repository_sha256(workspace),
        repository_exclusion_path=".mmaudit",
        configuration_sha256=_HASH_C,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        inventory_kind=(
            RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
            if pre_inventory is not None
            else RepositorySuiteInventoryKind.STATIC_SOURCE
        ),
        inventory_sha256=(
            pre_inventory.normalized_inventory_sha256 if pre_inventory is not None else None
        ),
        tests=(descriptor,),
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=block_number,
        block_hash="0x" + _HASH_D,
        tool_version=tool_version,
        tool_sha256=_HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256=compiler_sha256,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=_HASH_C,
        fuzz_seed=_FORK_SEED,
        fuzz_runs=fuzz_runs,
        invariant_runs=64,
        per_test_timeout_seconds=120,
        total_timeout_seconds=900,
        max_output_bytes_per_test=1_000_000,
        max_total_output_bytes=10_000_000,
    )
    scope, egress, workspace_copy = _fork_evidence(
        selection,
        policy,
        scope_status=scope_status,
    )
    failed = test_status is not RepositoryTestExecutionStatus.PASSED
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=policy.chain_id,
        block_number=policy.block_number,
        block_hash=policy.block_hash,
        fuzz_seed=policy.fuzz_seed,
        test_kind=RepositoryTestKind.UNIT,
        status=test_status,
        terminal_detail="synthetic mutation failure" if failed else None,
        duration_seconds=0.1,
        command_sha256=_HASH_A,
        output_sha256=_HASH_B,
        output_bytes=123,
        machine_result_sha256=_HASH_C,
        process_exit_code=1 if failed else 0,
        machine_output_validated=True,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend=policy.isolation_backend,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy_sha256=policy.policy_sha256,
        inventory_sha256=(pre_inventory.inventory_sha256 if pre_inventory is not None else None),
        post_inventory_sha256=(
            post_inventory.inventory_sha256 if post_inventory is not None else None
        ),
        inventory_record_sha256=(record.record_sha256 if record is not None else None),
    )
    observed_at = datetime(2026, 1, 1, tzinfo=UTC)
    findings = (
        [
            ScannerFinding(
                scanner="foundry_fork",
                rule_id="repository-fork-test-failure",
                title="Synthetic mutation regression failed",
                severity=Severity.HIGH,
                message="Synthetic mutation failure",
                locations=[
                    Location(
                        path=descriptor.path,
                        start_line=descriptor.start_line,
                        end_line=descriptor.end_line,
                        symbol=descriptor.test_name,
                        content_hash=descriptor.source_sha256,
                    )
                ],
                metadata={"repository_test_execution_sha256": execution.execution_sha256},
                evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
                fingerprint=_HASH_D,
            )
        ]
        if failed
        else []
    )
    provisional = ScannerRun(
        scanner="foundry_fork",
        status=scanner_status,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version=policy.tool_version,
        executable_sha256=policy.tool_sha256,
        command=["forge", "test", "--offline", "--json"],
        started_at=observed_at,
        finished_at=observed_at,
        duration_seconds=0.1,
        findings=findings,
        error=(
            "synthetic scanner failure" if scanner_status is not ScannerStatus.SUCCESS else None
        ),
        raw_output_path="repository-suite/stdout.txt",
        raw_output_sha256=_HASH_B,
        raw_output_bytes=123,
        process_exit_code=1 if failed else 0,
        isolation_backend=policy.isolation_backend,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
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
        repository_suite_inventory=pre_inventory,
        repository_suite_post_inventory=post_inventory,
        repository_suite_execution_policy=policy,
        repository_suite_workspace_copy=workspace_copy,
        fork_rpc_egress=egress if include_egress else None,
        repository_test_fork_rpc_scopes=[scope] if include_scopes else [],
        repository_test_executions=[execution],
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
    )
    return ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )


def _synthetic_execution_path(
    runs: list[ScannerRun],
    *,
    run_lease_exit_hook: Callable[[ScannerRun], None] | None = None,
) -> tuple[
    _ExecuteMutation,
    Callable[[MutationSuiteObservation], bool],
    Callable[[MutationSuiteObservation], MutationSuiteObservation],
    list[tuple[object, Path, Path]],
    Callable[[ScannerRun], bool],
    Callable[[ScannerRun], AbstractContextManager[None]],
    Callable[[MutationSuiteObservation], AbstractContextManager[None]],
    _ProcessLocalRevocationLease,
]:
    queued = list(runs)
    calls: list[tuple[object, Path, Path]] = []

    def producer(
        adapter: FoundryForkScanner,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None,
        expected_version: str | None,
        expected_sha256: str | None,
        workspace_custody_guard: list[object],
    ) -> ScannerRun:
        del (
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
            workspace_custody_guard,
        )
        calls.append((adapter, root, private_dir))
        return queued.pop(0)

    revocation_lease = _ProcessLocalRevocationLease()
    invoke, run_contains, _validated_copy, _annotate, run_authority_lease = (
        _build_foundry_runtime_authority(
            adapter_type=FoundryForkScanner,
            producer_body=producer,
            execution_evidence_resolver=lambda _backend: ExecutionEvidenceKind.REAL,
            attestation_resolver=lambda _backend: _HASH_C,
            revocation_lease=revocation_lease,
        )
    )
    effective_run_authority_lease = run_authority_lease
    if run_lease_exit_hook is not None:

        @contextmanager
        def hooked_run_authority_lease(run: ScannerRun) -> Iterator[None]:
            with run_authority_lease(run):
                yield
                run_lease_exit_hook(run)

        effective_run_authority_lease = hooked_run_authority_lease
    execution_path, observation_contains, observation_copy, _observation_lease = (
        _build_testing_execution_path(
            invoke=invoke,
            run_authority_lease=effective_run_authority_lease,
            revocation_lease=revocation_lease,
        )
    )
    return (
        execution_path,
        observation_contains,
        observation_copy,
        calls,
        run_contains,
        run_authority_lease,
        _observation_lease,
        revocation_lease,
    )


class _SyntheticExecutor:
    def __init__(
        self,
        execution_path: _ExecuteMutation,
        backend: ScannerIsolationBackend,
    ) -> None:
        self._execution_path = execution_path
        self._backend = backend
        self._baseline_adapter = FoundryForkScanner(SmartContractsConfig())
        self._mutant_adapter = FoundryForkScanner(SmartContractsConfig())

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        return self._execution_path(
            baseline_adapter=self._baseline_adapter,
            mutant_adapter=self._mutant_adapter,
            backend=self._backend,
            timeout_seconds=60,
            expected_tool_version="1.3.2",
            expected_tool_sha256=_HASH_A,
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def _executor(
    execution_path: _ExecuteMutation,
    backend: ScannerIsolationBackend,
) -> _SyntheticExecutor:
    return _SyntheticExecutor(execution_path, backend)


def test_exact_executor_execution_path_is_not_caller_replaceable() -> None:
    values = {
        "baseline_adapter": FoundryForkScanner(SmartContractsConfig()),
        "mutant_adapter": FoundryForkScanner(SmartContractsConfig()),
        "backend": _SyntheticIsolation(),
        "timeout_seconds": 60,
        "expected_tool_version": "1.3.2",
        "expected_tool_sha256": _HASH_A,
    }
    executor = ExactFoundryMutationExecutor(**values)

    assert executor._execution_path.__name__ == "execute"
    with pytest.raises(TypeError, match="_execution_path"):
        ExactFoundryMutationExecutor(**values, _execution_path=executor._execution_path)


def test_exact_executor_derives_logical_population_and_runtime_authority(
    tmp_path: Path,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    baseline_run = _repository_suite_run(
        baseline,
        descriptor_source_sha256=_HASH_A,
    )
    mutant_run = _repository_suite_run(
        mutant,
        descriptor_source_sha256=_HASH_A,
        test_status=RepositoryTestExecutionStatus.FAILED,
    )
    execution_path, contains, validated_copy, calls, *_authority = _synthetic_execution_path(
        [baseline_run, mutant_run]
    )
    backend = _SyntheticIsolation()
    executor = _executor(execution_path, backend)

    observation = executor.execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )

    expected_id = canonical_foundry_mutation_test_id(
        baseline_run.repository_suite_selection.tests[0]  # type: ignore[union-attr]
    )
    assert [item.test_id for item in observation.baseline_tests] == [expected_id]
    assert observation.baseline_tests[0].status is MutationSuiteTestStatus.PASSED
    assert observation.mutant_tests[0].status is MutationSuiteTestStatus.FAILED
    assert observation.baseline_source_sha256 == mutation_repository_sha256(baseline)
    assert observation.mutant_source_sha256 == mutation_repository_sha256(mutant)
    assert observation.executor_sha256 not in {_HASH_A, _HASH_B, _HASH_E}
    policy = baseline_run.repository_suite_execution_policy
    assert policy is not None
    assert observation.isolation_policy_sha256 == _canonical_sha256(
        policy.model_dump(mode="json", exclude={"selection_sha256", "policy_sha256"})
    )
    assert [root for _adapter, root, _private in calls] == [
        baseline.resolve(),
        mutant.resolve(),
    ]
    assert all(type(adapter) is FoundryForkScanner for adapter, _root, _private in calls)
    execution_root = tmp_path / ".mmaudit-foundry-mutation-mut-access-guard"
    assert [private for _adapter, _root, private in calls] == [
        execution_root / "baseline",
        execution_root / "mutant",
    ]
    assert contains(observation)
    assert not has_host_mutation_suite_runtime_authority(observation)

    if hasattr(os, "fork"):
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the parent-side pipe
            os.close(read_fd)
            try:
                mutation_executor_module.os.getpid = lambda: os.getppid()
                os.write(write_fd, b"1" if contains(observation) else b"0")
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            fork_result = os.read(read_fd, 1)
        finally:
            os.close(read_fd)
        waited_pid, status = os.waitpid(child_pid, 0)
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(status) == 0
        assert fork_result == b"0"

    serialized = MutationSuiteObservation.model_validate(observation.model_dump(mode="json"))
    assert not contains(serialized)
    preserved = validated_copy(observation)
    assert preserved is not observation
    assert contains(preserved)


def test_observation_authority_read_cannot_outlive_concurrent_invalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, contains, _validated_copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, test_status=RepositoryTestExecutionStatus.FAILED),
        ]
    )
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    assert contains(observation)

    reader_entered = threading.Event()
    release_reader = threading.Event()
    reader_identifier: int | None = None
    reader_results: list[bool] = []
    invalidator_entered = threading.Event()
    invalidator_completed = threading.Event()
    invalidator_results: list[bool] = []
    original_model_sha256 = mutation_executor_module._model_sha256

    def blocking_model_sha256(model: MutationSuiteObservation | ScannerRun) -> str:
        if model is observation and threading.get_ident() == reader_identifier:
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                return "0" * 64
        return original_model_sha256(model)

    monkeypatch.setattr(mutation_executor_module, "_model_sha256", blocking_model_sha256)

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains(observation))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("observation authority reader did not reach its validation barrier")
    original_executor_sha256 = observation.executor_sha256
    object.__setattr__(observation, "executor_sha256", _HASH_E)

    def invalidate_authority() -> None:
        invalidator_entered.set()
        invalidator_results.append(contains(observation))
        invalidator_completed.set()

    invalidator = threading.Thread(target=invalidate_authority, daemon=True)
    invalidator.start()
    assert invalidator_entered.wait(timeout=5)
    assert not invalidator_completed.wait(timeout=0.1)
    release_reader.set()
    reader.join(timeout=5)
    invalidator.join(timeout=5)
    object.__setattr__(observation, "executor_sha256", original_executor_sha256)

    assert not reader.is_alive()
    assert not invalidator.is_alive()
    assert reader_results == [False]
    assert invalidator_results == [False]
    assert not contains(observation)


def test_observation_authority_rechecks_after_upstream_lease_exit(tmp_path: Path) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    observation_holder: list[MutationSuiteObservation] = []
    mutate_on_exit = False
    mutated = False

    def mutate_observation_after_yield(_run: ScannerRun) -> None:
        nonlocal mutated
        if mutate_on_exit and not mutated:
            mutated = True
            object.__setattr__(observation_holder[0], "executor_sha256", _HASH_E)

    execution_path, contains, _validated_copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, test_status=RepositoryTestExecutionStatus.FAILED),
        ],
        run_lease_exit_hook=mutate_observation_after_yield,
    )
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    observation_holder.append(observation)
    original_executor_sha256 = observation.executor_sha256
    mutate_on_exit = True

    assert not contains(observation)

    object.__setattr__(observation, "executor_sha256", original_executor_sha256)
    assert mutated
    assert not contains(observation)


def test_observation_copy_install_rechecks_after_upstream_lease_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    normalized_observations: list[MutationSuiteObservation] = []
    mutate_copy_on_exit = False
    mutated = False

    def mutate_copy_after_yield(_run: ScannerRun) -> None:
        nonlocal mutated
        if mutate_copy_on_exit and normalized_observations and not mutated:
            mutated = True
            object.__setattr__(normalized_observations[0], "executor_sha256", _HASH_E)

    execution_path, contains, validated_copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, test_status=RepositoryTestExecutionStatus.FAILED),
        ],
        run_lease_exit_hook=mutate_copy_after_yield,
    )
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    original_model_validate = MutationSuiteObservation.model_validate

    def capture_normalized(value: object) -> MutationSuiteObservation:
        normalized = original_model_validate(value)
        normalized_observations.append(normalized)
        return normalized

    monkeypatch.setattr(MutationSuiteObservation, "model_validate", capture_normalized)
    mutate_copy_on_exit = True
    normalized = validated_copy(observation)
    original_executor_sha256 = observation.executor_sha256

    assert normalized_observations == [normalized]
    assert mutated
    assert not contains(normalized)

    object.__setattr__(normalized, "executor_sha256", original_executor_sha256)
    mutate_copy_on_exit = False
    assert contains(observation)
    assert not contains(normalized)


def test_observation_copy_dependency_exit_interrupt_revokes_source_and_derived(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    normalized_observations: list[MutationSuiteObservation] = []
    interrupt_on_exit = False
    exit_checks = 0

    def interrupt_after_yield(_run: ScannerRun) -> None:
        nonlocal exit_checks
        if interrupt_on_exit:
            exit_checks += 1
            if exit_checks == 3:
                raise KeyboardInterrupt("synthetic observation dependency-exit interruption")

    execution_path, contains, validated_copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, test_status=RepositoryTestExecutionStatus.FAILED),
        ],
        run_lease_exit_hook=interrupt_after_yield,
    )
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    original_model_validate = MutationSuiteObservation.model_validate

    def capture_normalized(value: object) -> MutationSuiteObservation:
        normalized = original_model_validate(value)
        normalized_observations.append(normalized)
        return normalized

    monkeypatch.setattr(MutationSuiteObservation, "model_validate", capture_normalized)
    interrupt_on_exit = True

    with pytest.raises(KeyboardInterrupt, match="dependency-exit interruption"):
        validated_copy(observation)

    interrupt_on_exit = False
    assert exit_checks == 3
    assert len(normalized_observations) == 1
    assert not contains(observation)
    assert not contains(normalized_observations[0])


def test_observation_weakref_cleanup_refuses_process_mismatch_before_registry_lock(
    tmp_path: Path,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    (
        execution_path,
        contains,
        _validated_copy,
        _calls,
        _contains_run,
        _run_lease,
        _observation_lease,
        revocation_lease,
    ) = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, test_status=RepositoryTestExecutionStatus.FAILED),
        ]
    )
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    references = [
        reference
        for reference in weakref.getweakrefs(observation)
        if getattr(reference, "__callback__", None) is not None
    ]
    assert len(references) == 1
    callback = references[0].__callback__
    assert callback is not None
    original_process_id_resolver = revocation_lease._current_process_id
    revocation_lease._current_process_id = lambda: revocation_lease.authority_process_id + 1

    callback(references[0])
    revocation_lease._current_process_id = original_process_id_resolver

    assert contains(observation)


def test_observation_read_cannot_outlive_upstream_run_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    baseline_run = _repository_suite_run(baseline)
    mutant_run = _repository_suite_run(
        mutant,
        test_status=RepositoryTestExecutionStatus.FAILED,
    )
    (
        execution_path,
        contains_observation,
        _validated_copy,
        _calls,
        contains_run,
        _run_lease,
        _observation_lease,
        _revocation_lease,
    ) = _synthetic_execution_path([baseline_run, mutant_run])
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    assert contains_observation(observation)
    assert contains_run(baseline_run)

    reader_entered = threading.Event()
    release_reader = threading.Event()
    invalidator_entered = threading.Event()
    invalidator_completed = threading.Event()
    reader_identifier: int | None = None
    reader_observation_hashes = 0
    reader_results: list[bool] = []
    invalidator_results: list[bool] = []
    original_model_sha256 = mutation_executor_module._model_sha256

    def blocking_model_sha256(model: MutationSuiteObservation | ScannerRun) -> str:
        nonlocal reader_observation_hashes
        if model is observation and threading.get_ident() == reader_identifier:
            reader_observation_hashes += 1
            if reader_observation_hashes == 2:
                reader_entered.set()
                if not release_reader.wait(timeout=5):
                    return "0" * 64
        return original_model_sha256(model)

    monkeypatch.setattr(mutation_executor_module, "_model_sha256", blocking_model_sha256)

    def read_observation_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains_observation(observation))

    reader = threading.Thread(target=read_observation_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("observation reader did not acquire both upstream run leases")

    original_duration = baseline_run.duration_seconds
    baseline_run.duration_seconds += 1

    def invalidate_run_authority() -> None:
        invalidator_entered.set()
        invalidator_results.append(contains_run(baseline_run))
        invalidator_completed.set()

    invalidator = threading.Thread(target=invalidate_run_authority, daemon=True)
    invalidator.start()
    assert invalidator_entered.wait(timeout=5)
    assert not invalidator_completed.wait(timeout=0.1)
    release_reader.set()
    reader.join(timeout=5)
    invalidator.join(timeout=5)
    baseline_run.duration_seconds = original_duration

    assert not reader.is_alive()
    assert not invalidator.is_alive()
    assert reader_results == [False]
    assert invalidator_results == [False]
    assert not contains_run(baseline_run)
    assert not contains_observation(observation)


def test_observation_copy_install_cannot_cross_upstream_run_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    baseline_run = _repository_suite_run(baseline)
    mutant_run = _repository_suite_run(
        mutant,
        test_status=RepositoryTestExecutionStatus.FAILED,
    )
    (
        execution_path,
        contains_observation,
        validated_copy,
        _calls,
        contains_run,
        _run_lease,
        _observation_lease,
        _revocation_lease,
    ) = _synthetic_execution_path([baseline_run, mutant_run])
    observation = _executor(execution_path, _SyntheticIsolation()).execute(
        baseline_workspace=baseline,
        mutant_workspace=mutant,
        specification=_specification(),
    )
    copy_entered_install = threading.Event()
    release_copy = threading.Event()
    invalidator_entered = threading.Event()
    invalidator_completed = threading.Event()
    copy_identifier: int | None = None
    copies: list[MutationSuiteObservation] = []
    invalidator_results: list[bool] = []
    original_model_sha256 = mutation_executor_module._model_sha256

    def blocking_model_sha256(model: MutationSuiteObservation | ScannerRun) -> str:
        if (
            type(model) is MutationSuiteObservation
            and model is not observation
            and threading.get_ident() == copy_identifier
        ):
            copy_entered_install.set()
            if not release_copy.wait(timeout=5):
                return "0" * 64
        return original_model_sha256(model)

    monkeypatch.setattr(mutation_executor_module, "_model_sha256", blocking_model_sha256)

    def copy_observation() -> None:
        nonlocal copy_identifier
        copy_identifier = threading.get_ident()
        copies.append(validated_copy(observation))

    copier = threading.Thread(target=copy_observation, daemon=True)
    copier.start()
    if not copy_entered_install.wait(timeout=5):
        release_copy.set()
        copier.join(timeout=5)
        pytest.fail("observation copy did not reach its installation boundary")

    original_duration = baseline_run.duration_seconds
    baseline_run.duration_seconds += 1

    def invalidate_run_authority() -> None:
        invalidator_entered.set()
        invalidator_results.append(contains_run(baseline_run))
        invalidator_completed.set()

    invalidator = threading.Thread(target=invalidate_run_authority, daemon=True)
    invalidator.start()
    assert invalidator_entered.wait(timeout=5)
    assert not invalidator_completed.wait(timeout=0.1)
    release_copy.set()
    copier.join(timeout=5)
    invalidator.join(timeout=5)
    baseline_run.duration_seconds = original_duration

    assert not copier.is_alive()
    assert not invalidator.is_alive()
    assert len(copies) == 1
    assert invalidator_results == [False]
    assert copies[0] is not observation
    assert not contains_run(baseline_run)
    assert not contains_observation(copies[0])


def test_executor_rejects_live_runs_with_different_logical_population(tmp_path: Path) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, _contains, _copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline, test_name="testAccessGuard"),
            _repository_suite_run(mutant, test_name="testDifferentProperty"),
        ]
    )

    with pytest.raises(FoundryMutationExecutionError, match="logical test populations"):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )


@pytest.mark.parametrize("scanner_status", [ScannerStatus.FAILED, ScannerStatus.TIMED_OUT])
def test_executor_rejects_non_successful_scanner_run(
    tmp_path: Path,
    scanner_status: ScannerStatus,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, _contains, _copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, scanner_status=scanner_status),
        ]
    )

    with pytest.raises(FoundryMutationExecutionError, match="runtime bindings"):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )


def test_logical_test_identity_binds_source_and_declaration_but_not_compiler_ids(
    tmp_path: Path,
) -> None:
    baseline, _ = _workspace_pair(tmp_path)
    run = _repository_suite_run(baseline)
    selection = run.repository_suite_selection
    assert selection is not None
    descriptor = selection.tests[0]
    original = canonical_foundry_mutation_test_id(descriptor)

    compiler_only = descriptor.model_copy(
        update={
            "inventory_sha256": _HASH_E,
            "inventory_record_sha256": _HASH_D,
            "execution_contract_ast_id": 999,
            "declaration_contract_ast_id": 998,
            "declaration_function_ast_id": 997,
        }
    )
    assert canonical_foundry_mutation_test_id(compiler_only) == original

    for update in (
        {"source_sha256": _HASH_E},
        {"start_line": descriptor.start_line + 1},
        {"end_line": descriptor.end_line + 1},
        {"declaration_path": "test/Changed.t.sol"},
        {"declaration_suite_name": "ChangedTest"},
        {"declaration_signature": "testChanged()"},
        {"declaration_source_sha256": _HASH_E},
        {"declaration_start_line": (descriptor.declaration_start_line or 1) + 1},
        {"declaration_end_line": (descriptor.declaration_end_line or 1) + 1},
    ):
        changed = descriptor.model_copy(update=update)
        assert canonical_foundry_mutation_test_id(changed) != original


@pytest.mark.parametrize(
    ("baseline_overrides", "message"),
    [
        ({"scanner_status": ScannerStatus.FAILED}, "runtime bindings"),
        ({"scanner_status": ScannerStatus.TIMED_OUT}, "runtime bindings"),
        ({"compiler_bound": False}, "stable isolated build-info"),
        ({"include_egress": False}, "fork egress binding"),
        ({"include_scopes": False}, "fork scope custody"),
        (
            {"scope_status": RepositoryTestForkRpcScopeStatus.NOT_OBSERVED},
            "per-test fork binding",
        ),
    ],
)
def test_executor_rejects_incomplete_compilation_and_runtime_custody(
    tmp_path: Path,
    baseline_overrides: dict[str, Any],
    message: str,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, _contains, _copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline, **baseline_overrides),
            _repository_suite_run(mutant),
        ]
    )

    with pytest.raises(FoundryMutationExecutionError, match=message):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )


@pytest.mark.parametrize(
    ("mutant_overrides", "message"),
    [
        ({"include_egress": False}, "fork egress"),
        ({"include_scopes": False}, "incomplete per-test fork scope"),
        (
            {"scope_status": RepositoryTestForkRpcScopeStatus.NOT_OBSERVED},
            "per-test fork binding",
        ),
        ({"compiler_bound": False}, "stable isolated build-info inventory"),
    ],
)
def test_executor_rejects_incomplete_fork_or_compiler_custody(
    tmp_path: Path,
    mutant_overrides: dict[str, Any],
    message: str,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, _contains, _copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, **mutant_overrides),
        ]
    )

    with pytest.raises(FoundryMutationExecutionError, match=message):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )


def test_canonical_test_identity_binds_source_and_declaration_but_not_inventory_ids(
    tmp_path: Path,
) -> None:
    baseline, _mutant = _workspace_pair(tmp_path)
    run = _repository_suite_run(baseline)
    selection = run.repository_suite_selection
    assert selection is not None
    descriptor = selection.tests[0]
    base_payload = descriptor.model_dump(mode="python", exclude={"descriptor_sha256"})
    metadata_only = {
        **base_payload,
        "inventory_sha256": _HASH_B,
        "inventory_record_sha256": _HASH_C,
        "execution_contract_ast_id": 101,
        "declaration_contract_ast_id": 102,
        "declaration_function_ast_id": 103,
    }
    metadata_descriptor = RepositorySuiteTestDescriptor.sealed(**metadata_only)
    expected_id = canonical_foundry_mutation_test_id(descriptor)
    assert canonical_foundry_mutation_test_id(metadata_descriptor) == expected_id

    for field, value in (
        ("source_sha256", _HASH_E),
        ("start_line", 11),
        ("declaration_path", "test/Other.t.sol"),
        ("declaration_suite_name", "OtherTest"),
        ("declaration_signature", "testAccessGuard(uint256)"),
        ("declaration_source_sha256", _HASH_E),
        ("declaration_start_line", 11),
        ("declaration_end_line", 13),
    ):
        changed = RepositorySuiteTestDescriptor.sealed(**{**base_payload, field: value})
        assert canonical_foundry_mutation_test_id(changed) != expected_id


@pytest.mark.parametrize(
    ("mutant_overrides", "message"),
    [
        ({"tool_version": "1.3.3"}, "runtime bindings"),
        ({"compiler_sha256": _HASH_E}, "policies differ"),
        ({"block_number": 1_235}, "policies differ"),
        ({"fuzz_runs": 257}, "policies differ"),
    ],
)
def test_executor_rejects_mismatched_runtime_bindings(
    tmp_path: Path,
    mutant_overrides: dict[str, Any],
    message: str,
) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    execution_path, _contains, _copy, _calls, *_authority = _synthetic_execution_path(
        [
            _repository_suite_run(baseline),
            _repository_suite_run(mutant, **mutant_overrides),
        ]
    )

    with pytest.raises(FoundryMutationExecutionError, match=message):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )


def test_executor_rejects_self_authored_or_serialized_real_run(tmp_path: Path) -> None:
    baseline, mutant = _workspace_pair(tmp_path)
    baseline_run = _repository_suite_run(baseline)
    mutant_run = _repository_suite_run(mutant)
    _trusted_path, _contains_observation, _copy, _calls, *_authority = _synthetic_execution_path([])
    revocation_lease = _ProcessLocalRevocationLease()
    _invoke, _contains_run, _validated, _annotate, run_authority_lease = (
        _build_foundry_runtime_authority(
            adapter_type=FoundryForkScanner,
            producer_body=lambda *args, **kwargs: baseline_run,
            execution_evidence_resolver=lambda _backend: ExecutionEvidenceKind.REAL,
            attestation_resolver=lambda _backend: _HASH_C,
            revocation_lease=revocation_lease,
        )
    )
    untrusted_runs = [
        ScannerRun.model_validate(baseline_run.model_dump(mode="json")),
        ScannerRun.model_validate(mutant_run.model_dump(mode="json")),
    ]

    def direct_return(*args: object, **kwargs: object) -> ScannerRun:
        del args, kwargs
        return untrusted_runs.pop(0)

    execution_path, _observation_contains, _observation_copy, _observation_lease = (
        _build_testing_execution_path(
            invoke=direct_return,
            run_authority_lease=run_authority_lease,
            revocation_lease=revocation_lease,
        )
    )

    with pytest.raises(FoundryMutationExecutionError, match="live host runtime authority"):
        _executor(execution_path, _SyntheticIsolation()).execute(
            baseline_workspace=baseline,
            mutant_workspace=mutant,
            specification=_specification(),
        )
