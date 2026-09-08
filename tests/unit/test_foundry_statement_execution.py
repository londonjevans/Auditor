from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

import mmaudit.scanners.foundry as foundry_module
from mmaudit.models.schemas import (
    AuditedSuiteEntityCatalog,
    AuditedSuiteEntityCatalogBinding,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementCoverageProcessReceipt,
    AuditedSuiteStatementCoverageReceipt,
    AuditedSuiteStatementStatus,
    ExecutionEvidenceKind,
    Location,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteInventoryKind,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    SolidityEntityKind,
    SolidityProvenance,
)
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry import (
    _combined_private_artifact_usage,
    _display_foundry_statement_coverage_command,
    _execute_foundry_statement_coverage,
    _PrivateArtifactUsage,
    _write_repository_suite_manifest,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryInvalidError,
    FoundryInventoryOverflowError,
    FoundryInventoryTimeoutError,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
HASH_G = "0" * 63 + "1"
HASH_H = "1" * 64
HASH_I = "2" * 64
HASH_J = "3" * 64
HASH_K = "4" * 64
HASH_L = "5" * 64
SEED = "0x" + ("0" * 63) + "1"


def _descriptor() -> RepositorySuiteTestDescriptor:
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/audit/ExactSuite.t.sol",
        suite_name="ExactSuiteTest",
        test_name="testExact",
        inventory_sha256=HASH_B,
        inventory_record_sha256=HASH_C,
        execution_contract_ast_id=10,
        declaration_path="test/audit/ExactSuite.t.sol",
        declaration_suite_name="ExactSuiteTest",
        declaration_signature="testExact()",
        declaration_source_sha256=HASH_A,
        declaration_start_line=1,
        declaration_end_line=3,
        declaration_contract_ast_id=10,
        declaration_function_ast_id=11,
        source_sha256=HASH_A,
        start_line=1,
        end_line=3,
    )


def _fork() -> PinnedForkObservation:
    return PinnedForkObservation(
        chain_id=31_337,
        block_number=42,
        block_hash="0x" + HASH_B,
    )


def _debug_output(descriptor: RepositorySuiteTestDescriptor) -> bytes:
    machine_result = json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    descriptor.declaration_signature: {
                        "status": "Success",
                        "kind": {"Unit": {"gas": 1}},
                    }
                }
            }
        },
        separators=(",", ":"),
    )
    return (
        "Analysing contracts...\n"
        "Running tests...\n"
        f"{machine_result}\n"
        'Anchors for Contract "Example" (solc 0.8.24, source ID 1):\n'
        "- IC 5 -> Item 7\n"
        "- Runtime code\n"
        "  - Refers to item: Statement "
        "(location: source ID 1, lines 4..5, bytes 40..60, hits: 1)\n"
    ).encode()


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


def _v12_manifest_carriers() -> tuple[
    RepositorySuiteSelection,
    RepositorySuiteExecutionPolicy,
    RepositoryTestExecution,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementCoverageReceipt,
    AuditedSuiteEntityCatalog,
]:
    descriptor = _descriptor()
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=HASH_D,
        repository_exclusion_path=".mmaudit",
        configuration_sha256=HASH_C,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        inventory_kind=RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO,
        inventory_sha256=HASH_B,
        tests=(descriptor,),
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=42,
        block_hash="0x" + HASH_B,
        tool_version="forge 1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.24",
        compiler_sha256=HASH_C,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_H,
        fuzz_seed=SEED,
        fuzz_runs=16,
        invariant_runs=8,
        per_test_timeout_seconds=5,
        total_timeout_seconds=10,
        max_output_bytes_per_test=10_000,
        max_total_output_bytes=100_000,
    )
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        inventory_sha256=HASH_B,
        post_inventory_sha256=HASH_B,
        inventory_record_sha256=HASH_C,
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=31_337,
        block_number=42,
        block_hash="0x" + HASH_B,
        fuzz_seed=SEED,
        test_kind=RepositoryTestKind.UNIT,
        status=RepositoryTestExecutionStatus.PASSED,
        duration_seconds=0.1,
        command_sha256=HASH_E,
        output_sha256=HASH_F,
        output_bytes=1,
        machine_result_sha256=HASH_G,
        process_exit_code=0,
        machine_output_validated=True,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_H,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy_sha256=policy.policy_sha256,
    )
    location = Location(
        path="src/Example.sol",
        start_line=1,
        end_line=2,
        symbol="Example",
        content_hash=HASH_A,
    )
    entity_id = "contract:src/Example.sol:Example"
    binding = AuditedSuiteEntityCatalogBinding.sealed(
        entity_id=entity_id,
        entity_kind=SolidityEntityKind.CONTRACT,
        entity_name="Example",
        evidence_contract_name="Example",
        location=location,
        entity_start_byte_offset=0,
        entity_end_byte_offset=20,
        source_file_sha256=HASH_A,
        provenance=SolidityProvenance.COMPILER,
    )
    catalog = AuditedSuiteEntityCatalog.sealed(
        repository_sha256=selection.repository_sha256,
        classification_complete=True,
        bindings=[binding],
    )
    process = AuditedSuiteStatementCoverageProcessReceipt.sealed(
        sequence_index=1,
        descriptor_sha256=descriptor.descriptor_sha256,
        repository_test_execution_sha256=execution.execution_sha256,
        coverage_command_sha256=HASH_E,
        fork_rpc_scope_evidence_sha256=HASH_F,
        machine_result_sha256=HASH_G,
        private_artifact_path="repository-suite/coverage/00000",
        stdout_path="repository-suite/coverage/00000/stdout.txt",
        stdout_sha256=HASH_H,
        stdout_bytes=10,
        stderr_path="repository-suite/coverage/00000/stderr.txt",
        stderr_sha256=HASH_I,
        stderr_bytes=0,
        private_artifact_sha256=HASH_J,
        private_artifact_bytes=10,
        duration_seconds=0.1,
        debug_statement_population_sha256=HASH_K,
        debug_statement_result_sha256=HASH_L,
    )
    artifact_payload = [
        {
            "sequence_index": 1,
            "private_artifact_path": process.private_artifact_path,
            "stdout_path": process.stdout_path,
            "stdout_sha256": process.stdout_sha256,
            "stdout_bytes": process.stdout_bytes,
            "stderr_path": process.stderr_path,
            "stderr_sha256": process.stderr_sha256,
            "stderr_bytes": process.stderr_bytes,
            "private_artifact_sha256": process.private_artifact_sha256,
            "private_artifact_bytes": process.private_artifact_bytes,
        }
    ]
    statement_inventory_sha256 = _canonical_sha256([])
    coverage_artifact_sha256 = _canonical_sha256(artifact_payload)
    receipt = AuditedSuiteStatementCoverageReceipt.sealed(
        source_repository_sha256=selection.repository_sha256,
        repository_suite_selection_sha256=selection.selection_sha256,
        repository_suite_execution_policy_sha256=policy.policy_sha256,
        pre_inventory_sha256=HASH_B,
        post_inventory_sha256=HASH_B,
        entity_catalog_sha256=catalog.catalog_sha256,
        repository_test_execution_sha256s=[execution.execution_sha256],
        processes=[process],
        compiler_statements=[],
        entity_statement_ids={entity_id: []},
        compiler_statement_count=0,
        statement_inventory_sha256=statement_inventory_sha256,
        coverage_artifact_sha256=coverage_artifact_sha256,
        coverage_artifact_bytes=10,
        producer_version="1.0.0",
        producer_sha256=HASH_A,
        normalizer_policy_sha256=HASH_B,
        tool_version=policy.tool_version,
        tool_sha256=policy.tool_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
    )
    evidence = AuditedSuiteStatementCoverageEvidence.sealed(
        schema_version="1.2",
        entity_id=entity_id,
        entity_kind=SolidityEntityKind.CONTRACT,
        contract_name="Example",
        location=location,
        statement_status=AuditedSuiteStatementStatus.COVERED,
        statement_count=0,
        covered_statement_count=0,
        statements=[],
        repository_test_execution_sha256s=[execution.execution_sha256],
        source_repository_sha256=selection.repository_sha256,
        repository_suite_selection_sha256=selection.selection_sha256,
        repository_suite_execution_policy_sha256=policy.policy_sha256,
        coverage_command_sha256s=[process.coverage_command_sha256],
        statement_inventory_sha256=statement_inventory_sha256,
        coverage_artifact_sha256=coverage_artifact_sha256,
        coverage_artifact_bytes=10,
        producer_version="1.0.0",
        producer_sha256=HASH_A,
        normalizer_policy_sha256=HASH_B,
        tool_name="forge",
        tool_version=policy.tool_version,
        tool_sha256=policy.tool_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        machine_output_validated=True,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        coverage_receipt_sha256=receipt.receipt_sha256,
    )
    return selection, policy, execution, evidence, receipt, catalog


class _Backend:
    name = "synthetic-isolation"

    def __init__(self) -> None:
        self.wrapped_commands: list[list[str]] = []

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        assert workspace.is_dir()
        assert private_dir.is_dir()
        assert rpc_port == 8_545
        self.wrapped_commands.append(list(command))
        return command


class _CompletedProcess:
    def __init__(
        self,
        _command: list[str],
        *,
        stdout: BinaryIO,
        stderr: BinaryIO,
        return_code: int,
        stdout_bytes: bytes,
        stderr_bytes: bytes,
        **_kwargs: object,
    ) -> None:
        stdout.write(stdout_bytes)
        stdout.flush()
        stderr.write(stderr_bytes)
        stderr.flush()
        self.returncode = return_code

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode


def _install_process(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: bytes,
    stderr: bytes = b"",
    return_code: int = 0,
    starts: list[list[str]] | None = None,
) -> None:
    # Keep byte payload names separate from the subprocess stream parameters.
    output_bytes = stdout
    error_bytes = stderr

    def patched_popen(
        command: list[str],
        *,
        stdout: BinaryIO,
        stderr: BinaryIO,
        **kwargs: object,
    ) -> _CompletedProcess:
        if starts is not None:
            starts.append(list(command))
        return _CompletedProcess(
            command,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            stdout_bytes=output_bytes,
            stderr_bytes=error_bytes,
            **kwargs,
        )

    monkeypatch.setattr(foundry_module.subprocess, "Popen", patched_popen)


def _execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: bytes,
    stderr: bytes = b"",
    return_code: int = 0,
    deadline: float | None = None,
    max_output_bytes: int = 1_000_000,
    max_output_entries: int = 100,
    process_starts: list[list[str]] | None = None,
) -> tuple[object, _PrivateArtifactUsage, _Backend]:
    descriptor = _descriptor()
    private_dir = tmp_path / "private"
    workspace = private_dir / "workspace"
    workspace.mkdir(parents=True)
    executable = tmp_path / "forge"
    compiler = tmp_path / "solc"
    executable.write_bytes(b"synthetic forge identity")
    compiler.write_bytes(b"synthetic solc identity")
    backend = _Backend()
    _install_process(
        monkeypatch,
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        starts=process_starts,
    )

    observation, usage = _execute_foundry_statement_coverage(
        descriptor=descriptor,
        workspace=workspace,
        private_dir=private_dir,
        output_index=0,
        executable_path=executable,
        compiler_path=compiler,
        compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
        rpc_url="http://127.0.0.1:8545",
        rpc_port=8_545,
        fork=_fork(),
        fuzz_seed=SEED,
        fuzz_runs=16,
        invariant_runs=8,
        deadline=deadline if deadline is not None else time.monotonic() + 5,
        max_output_bytes=max_output_bytes,
        max_output_entries=max_output_entries,
        backend=backend,
        base_environment={"PATH": os.environ.get("PATH", "")},
    )
    return observation, usage, backend


def test_statement_coverage_command_is_exact_redacted_and_fully_pinned() -> None:
    descriptor = _descriptor()

    command = _display_foundry_statement_coverage_command(
        descriptor=descriptor,
        fork=_fork(),
        fuzz_seed=SEED,
        fuzz_runs=16,
        compiler_sha256=HASH_C,
    )

    assert command[:5] == ["forge", "coverage", "--report", "debug", "--exclude-tests"]
    assert command[command.index("--fork-url") + 1] == "[REDACTED_LOOPBACK_FORK_RPC]"
    assert command[command.index("--fork-block-number") + 1] == "42"
    assert command[command.index("--match-path") + 1] == descriptor.path
    assert command[command.index("--match-contract") + 1] == "^ExactSuiteTest$"
    assert command[command.index("--match-test") + 1] == "^testExact\\(\\)$"
    assert command[command.index("--fuzz-runs") + 1] == "16"
    assert command[command.index("--fuzz-seed") + 1] == SEED
    assert command[command.index("--gas-price") + 1] == "1000000000"
    assert command[command.index("--threads") + 1] == "1"
    assert command[command.index("--use") + 1] == f"[PINNED_SOLC_SHA256={HASH_C}]"
    assert command[command.index("--cache-path") + 1] == "[PRIVATE_CACHE_PATH]"
    assert command[command.index("--out") + 1] == "[PRIVATE_OUTPUT_PATH]"
    assert {"--no-storage-caching", "--force", "--no-auto-detect", "--offline", "--json"} <= set(
        command
    )
    assert not any("127.0.0.1" in argument for argument in command)

    bypassed_validation = descriptor.model_copy(update={"path": "test/audit/[ExactSuite].t.sol"})
    with pytest.raises(ValueError, match="exact literal path"):
        _display_foundry_statement_coverage_command(
            descriptor=bypassed_validation,
            fork=_fork(),
            fuzz_seed=SEED,
            fuzz_runs=16,
            compiler_sha256=HASH_C,
        )


def test_statement_coverage_execution_seals_exact_streams_and_private_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _debug_output(_descriptor())
    observation, usage, backend = _execute(
        tmp_path,
        monkeypatch,
        stdout=raw,
        stderr=b"synthetic diagnostic\n",
    )

    assert observation.sequence_index == 1
    assert observation.descriptor_sha256 == _descriptor().descriptor_sha256
    assert observation.process_exit_code == 0
    assert observation.machine_output_validated is True
    assert observation.stdout_sha256 == hashlib.sha256(raw).hexdigest()
    assert observation.stdout_bytes == len(raw)
    assert observation.stderr_sha256 == hashlib.sha256(b"synthetic diagnostic\n").hexdigest()
    assert observation.private_artifact_sha256 == usage.artifact_sha256
    assert observation.private_artifact_bytes == usage.bytes
    assert observation.private_artifact_path == "repository-suite/coverage/00000"
    assert observation.debug_coverage.statements[0].identity == (1, 40, 60, 4, 5)
    assert observation.debug_coverage.statements[0].covered
    assert usage.captured("stdout.txt") == raw
    assert usage.captured("stderr.txt") == b"synthetic diagnostic\n"

    assert len(backend.wrapped_commands) == 1
    actual = backend.wrapped_commands[0]
    assert actual[0] == str(tmp_path / "forge")
    assert actual[actual.index("--fork-url") + 1] == "http://127.0.0.1:8545"
    assert "[REDACTED_LOOPBACK_FORK_RPC]" not in actual
    assert not any("PINNED_SOLC_SHA256" in argument for argument in actual)


@pytest.mark.parametrize(
    ("stdout_factory", "return_code", "error"),
    [
        (lambda descriptor: _debug_output(descriptor), 1, "passing process status"),
        (lambda _descriptor: b"{}\nunexpected debug record\n", 0, "failed validation"),
    ],
)
def test_statement_coverage_execution_rejects_nonzero_or_invalid_debug_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout_factory: Callable[[RepositorySuiteTestDescriptor], bytes],
    return_code: int,
    error: str,
) -> None:
    with pytest.raises(FoundryInventoryInvalidError, match=error):
        _execute(
            tmp_path,
            monkeypatch,
            stdout=stdout_factory(_descriptor()),
            return_code=return_code,
        )


def test_statement_coverage_execution_rejects_artifact_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _debug_output(_descriptor())

    with pytest.raises(FoundryInventoryOverflowError, match="artifact ceiling"):
        _execute(
            tmp_path,
            monkeypatch,
            stdout=raw,
            max_output_bytes=len(raw) - 1,
        )


def test_statement_coverage_execution_rejects_expired_shared_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_starts: list[list[str]] = []
    with pytest.raises(FoundryInventoryTimeoutError, match="shared per-test deadline"):
        _execute(
            tmp_path,
            monkeypatch,
            stdout=_debug_output(_descriptor()),
            deadline=time.monotonic() - 1,
            process_starts=process_starts,
        )
    assert process_starts == []
    assert not (tmp_path / "private" / "repository-suite" / "coverage" / "00000").exists()


def test_statement_coverage_execution_rechecks_deadline_immediately_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_starts: list[list[str]] = []
    observed_times = iter((10.0, 10.0, 12.0))
    monkeypatch.setattr(foundry_module.time, "monotonic", lambda: next(observed_times))

    with pytest.raises(FoundryInventoryTimeoutError, match="shared per-test deadline"):
        _execute(
            tmp_path,
            monkeypatch,
            stdout=_debug_output(_descriptor()),
            deadline=11.0,
            process_starts=process_starts,
        )

    assert process_starts == []
    assert (tmp_path / "private" / "repository-suite" / "coverage" / "00000").is_dir()


def test_combined_private_artifact_usage_sums_and_hashes_ordered_trees() -> None:
    first = _PrivateArtifactUsage(entries=2, bytes=5, artifact_sha256=HASH_A)
    second = _PrivateArtifactUsage(entries=3, bytes=7, artifact_sha256=HASH_B)

    combined = _combined_private_artifact_usage(first, second)
    repeated = _combined_private_artifact_usage(first, second)
    reversed_usage = _combined_private_artifact_usage(second, first)
    expected_payload = {
        "schema_version": "1.0",
        "trees": [
            {
                "sequence_index": 1,
                "entries": 2,
                "bytes": 5,
                "artifact_sha256": HASH_A,
            },
            {
                "sequence_index": 2,
                "entries": 3,
                "bytes": 7,
                "artifact_sha256": HASH_B,
            },
        ],
    }
    expected_hash = hashlib.sha256(
        json.dumps(
            expected_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert combined.entries == 5
    assert combined.bytes == 12
    assert combined.artifact_sha256 == expected_hash
    assert repeated == combined
    assert reversed_usage.artifact_sha256 != combined.artifact_sha256
    with pytest.raises(ValueError, match="at least one tree"):
        _combined_private_artifact_usage()


def test_statement_coverage_command_signature_is_regex_anchored() -> None:
    descriptor = _descriptor()
    command = _display_foundry_statement_coverage_command(
        descriptor=descriptor,
        fork=_fork(),
        fuzz_seed=SEED,
        fuzz_runs=16,
        compiler_sha256=HASH_C,
    )
    pattern = command[command.index("--match-test") + 1]

    assert re.fullmatch(pattern, "testExact()")
    assert re.fullmatch(pattern, "testExact(uint256)") is None
    assert re.fullmatch(pattern, "testExact()Neighbor") is None


def test_v12_manifest_serializes_shared_receipt_without_double_charging_artifacts(
    tmp_path: Path,
) -> None:
    selection, policy, execution, evidence, receipt, catalog = _v12_manifest_carriers()
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    baseline = _write_repository_suite_manifest(
        baseline_dir,
        selection,
        None,
        None,
        policy,
        [execution],
        statement_coverage_evidence=[evidence],
        statement_coverage_receipt=receipt,
        statement_entity_catalog=catalog,
        deadline=time.monotonic() + 5,
    )
    baseline_bytes = baseline.read_bytes()
    payload = json.loads(baseline_bytes)

    assert payload["schema_version"] == "1.2"
    assert payload["repository_statement_coverage_receipt"] == receipt.model_dump(mode="json")
    assert payload["repository_statement_entity_catalog"] == catalog.model_dump(mode="json")
    assert payload["repository_statement_coverage_evidence"] == [evidence.model_dump(mode="json")]
    assert receipt.coverage_artifact_bytes > 0

    exact_dir = tmp_path / "exact-budget"
    exact_dir.mkdir()
    exact_previously_charged = policy.max_total_output_bytes - len(baseline_bytes)
    exact = _write_repository_suite_manifest(
        exact_dir,
        selection,
        None,
        None,
        policy,
        [execution],
        statement_coverage_evidence=[evidence],
        statement_coverage_receipt=receipt,
        statement_entity_catalog=catalog,
        previously_charged_artifact_bytes=exact_previously_charged,
        deadline=time.monotonic() + 5,
    )
    assert exact.read_bytes() == baseline_bytes

    overflow_dir = tmp_path / "overflow"
    overflow_dir.mkdir()
    with pytest.raises(FoundryInventoryOverflowError, match="complete artifact byte budget"):
        _write_repository_suite_manifest(
            overflow_dir,
            selection,
            None,
            None,
            policy,
            [execution],
            statement_coverage_evidence=[evidence],
            statement_coverage_receipt=receipt,
            statement_entity_catalog=catalog,
            previously_charged_artifact_bytes=exact_previously_charged + 1,
            deadline=time.monotonic() + 5,
        )
    assert not (overflow_dir / "repository-suite-execution.json").exists()
