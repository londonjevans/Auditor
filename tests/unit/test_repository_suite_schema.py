from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    Location,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
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
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
SEED = "0x" + ("0" * 63) + "1"


def _descriptor(
    *,
    framework: RepositorySuiteFramework = RepositorySuiteFramework.FOUNDRY,
    path: str = "contracts/test/Vault.t.sol",
    suite_name: str = "VaultTest",
    test_name: str = "testDeposit",
    start_line: int = 10,
) -> RepositorySuiteTestDescriptor:
    return RepositorySuiteTestDescriptor.sealed(
        framework=framework,
        project_root="contracts",
        path=path,
        suite_name=suite_name,
        test_name=test_name,
        source_sha256=HASH_A,
        start_line=start_line,
        end_line=start_line + 2,
    )


def _selection(
    tests: tuple[RepositorySuiteTestDescriptor, ...] | None = None,
) -> RepositorySuiteSelection:
    selected = (_descriptor(),) if tests is None else tests
    selected_files = {(test.framework, test.project_root, test.path) for test in selected}
    return RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=HASH_B,
        configuration_sha256=HASH_C,
        candidate_file_count=len(selected_files),
        candidate_test_count=len(selected),
        selected_file_count=len(selected_files),
        selected_test_count=len(selected),
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=selected,
    )


def _execution(
    selection: RepositorySuiteSelection,
    descriptor: RepositorySuiteTestDescriptor,
    *,
    status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
) -> RepositoryTestExecution:
    failed = status in {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
    return RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=31337,
        block_number=1_234,
        block_hash="0x" + ("d" * 64),
        fuzz_seed=SEED,
        test_kind=RepositoryTestKind.UNIT,
        status=status,
        terminal_detail="Synthetic assertion detail." if failed else None,
        duration_seconds=0.25,
        command_sha256=HASH_A,
        output_sha256=HASH_B,
        output_bytes=123,
        machine_result_sha256=HASH_C,
        process_exit_code=1 if failed else 0,
        machine_output_validated=True,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        compiler_version="solc 0.8.30",
        compiler_sha256="d" * 64,
        execution_policy_sha256=_policy(selection).policy_sha256,
    )


def _policy(selection: RepositorySuiteSelection) -> RepositorySuiteExecutionPolicy:
    return RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=1_234,
        block_hash="0x" + ("d" * 64),
        tool_version="1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256="d" * 64,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        fuzz_seed=SEED,
        fuzz_runs=256,
        invariant_runs=64,
        per_test_timeout_seconds=120,
        total_timeout_seconds=900,
        max_output_bytes_per_test=1_000_000,
        max_total_output_bytes=10_000_000,
    )


def _scanner_run(
    selection: RepositorySuiteSelection,
    executions: list[RepositoryTestExecution],
    *,
    findings: list[ScannerFinding] | None = None,
    foundry_summary: FoundryTestExecutionSummary | None = None,
) -> ScannerRun:
    now = datetime.now(UTC)
    if foundry_summary is None and all(
        execution.framework is RepositorySuiteFramework.FOUNDRY for execution in executions
    ):
        failed_statuses = {
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        }
        foundry_summary = FoundryTestExecutionSummary(
            unit_tests=len(executions),
            fuzz_tests=0,
            invariant_tests=0,
            passed_tests=sum(
                execution.status is RepositoryTestExecutionStatus.PASSED for execution in executions
            ),
            failed_tests=sum(execution.status in failed_statuses for execution in executions),
            skipped_tests=sum(
                execution.status
                not in {
                    RepositoryTestExecutionStatus.PASSED,
                    *failed_statuses,
                }
                for execution in executions
            ),
            fuzz_cases=0,
            invariant_runs=0,
            invariant_calls=0,
        )
    return ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        version="1.3.2",
        executable_sha256=HASH_A,
        command=["forge", "test"],
        started_at=now,
        finished_at=now,
        duration_seconds=0.25,
        findings=findings or [],
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        machine_output_validated=True,
        foundry_summary=foundry_summary,
        repository_suite_selection=selection,
        repository_suite_execution_policy=_policy(selection),
        repository_test_executions=executions,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
    )


def test_repository_suite_evidence_round_trips_with_hashes_and_no_safety_claim() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(selection, descriptor)
    run = _scanner_run(selection, [execution])

    restored = ScannerRun.model_validate_json(run.model_dump_json())

    assert restored == run
    assert restored.repository_suite_selection is not None
    assert restored.repository_suite_selection.safety_claim is False
    assert restored.repository_test_executions[0].safety_claim is False
    with pytest.raises(ValidationError):
        RepositoryTestExecution.model_validate(
            {**execution.model_dump(mode="json"), "safety_claim": True}
        )


def test_repository_suite_descriptor_selection_and_execution_reject_tampering() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(selection, descriptor)

    with pytest.raises(ValidationError, match="descriptor hash"):
        RepositorySuiteTestDescriptor.model_validate(
            {**descriptor.model_dump(mode="json"), "end_line": descriptor.end_line + 1}
        )
    with pytest.raises(ValidationError, match="selection hash"):
        RepositorySuiteSelection.model_validate(
            {**selection.model_dump(mode="json"), "repository_sha256": HASH_C}
        )
    with pytest.raises(ValidationError, match="execution hash"):
        RepositoryTestExecution.model_validate(
            {**execution.model_dump(mode="json"), "duration_seconds": 1.25}
        )
    policy = _policy(selection)
    with pytest.raises(ValidationError, match="execution policy hash"):
        RepositorySuiteExecutionPolicy.model_validate(
            {**policy.model_dump(mode="json"), "fuzz_runs": policy.fuzz_runs + 1}
        )


def test_repository_suite_paths_must_reside_under_their_project_root() -> None:
    with pytest.raises(ValidationError, match="reside under its project root"):
        _descriptor(path="test/Vault.t.sol")

    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution_fields = _execution(selection, descriptor).model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    execution_fields["path"] = "test/Vault.t.sol"
    with pytest.raises(ValidationError, match="reside under its project root"):
        RepositoryTestExecution.sealed(**execution_fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("path", "contracts/test/*.t.sol"),
        ("path", "contracts/test/\u202eVault.t.sol"),
        ("suite_name", "Vault\u202eTest"),
        ("test_name", "te\u0301stDeposit"),
    ],
)
def test_repository_suite_exact_evidence_rejects_globs_or_unsafe_unicode(
    field: str,
    value: str,
) -> None:
    values: dict[str, object] = {
        "framework": RepositorySuiteFramework.FOUNDRY,
        "project_root": "contracts",
        "path": "contracts/test/Vault.t.sol",
        "suite_name": "VaultTest",
        "test_name": "testDeposit",
        "source_sha256": HASH_A,
        "start_line": 10,
        "end_line": 12,
    }
    values[field] = value

    with pytest.raises(ValidationError):
        RepositorySuiteTestDescriptor.sealed(**values)


def test_repository_suite_selection_requires_canonical_unique_descriptors_and_counts() -> None:
    first = _descriptor(test_name="testAlpha", start_line=10)
    second = _descriptor(test_name="testBeta", start_line=20)

    with pytest.raises(ValidationError, match="canonically sorted"):
        _selection((second, first))
    with pytest.raises(ValidationError, match="canonically sorted"):
        _selection((first, first))
    with pytest.raises(ValidationError, match="selected counts"):
        RepositorySuiteSelection.sealed(
            profile="explicit",
            repository_sha256=HASH_A,
            configuration_sha256=HASH_B,
            candidate_file_count=2,
            candidate_test_count=2,
            selected_file_count=2,
            selected_test_count=2,
            omitted_file_count=0,
            omitted_test_count=0,
            limit_reached=False,
            tests=(first, second),
        )
    filtered = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=HASH_A,
        configuration_sha256=HASH_B,
        candidate_file_count=2,
        candidate_test_count=3,
        selected_file_count=1,
        selected_test_count=2,
        omitted_file_count=1,
        omitted_test_count=1,
        limit_reached=False,
        tests=(first, second),
    )
    assert filtered.omitted_test_count == 1
    with pytest.raises(ValidationError, match="fail instead of truncating"):
        RepositorySuiteSelection.sealed(
            profile="explicit",
            repository_sha256=HASH_A,
            configuration_sha256=HASH_B,
            candidate_file_count=2,
            candidate_test_count=3,
            selected_file_count=1,
            selected_test_count=2,
            omitted_file_count=1,
            omitted_test_count=1,
            limit_reached=True,
            tests=(first, second),
        )


def test_repository_suite_selection_rejects_casefold_identity_collisions() -> None:
    first = _descriptor(suite_name="VaultTest")
    second = _descriptor(suite_name="vaulttest")

    with pytest.raises(ValidationError, match="case-insensitive collision"):
        _selection((first, second))


def test_scanner_run_requires_exact_canonical_execution_coverage() -> None:
    first = _descriptor(test_name="testAlpha", start_line=10)
    second = _descriptor(test_name="testBeta", start_line=20)
    selection = _selection((first, second))
    first_execution = _execution(selection, first)
    second_execution = _execution(selection, second)

    with pytest.raises(ValidationError, match="exactly cover"):
        _scanner_run(selection, [first_execution])
    with pytest.raises(ValidationError, match="canonically sorted"):
        _scanner_run(selection, [second_execution, first_execution])
    wrong_selection = _selection((_descriptor(test_name="testGamma"),))
    wrong_payload = second_execution.model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    wrong_payload["selection_sha256"] = wrong_selection.selection_sha256
    wrong_execution = RepositoryTestExecution.sealed(**wrong_payload)
    with pytest.raises(ValidationError, match="bind its suite selection"):
        _scanner_run(
            selection,
            [
                first_execution,
                wrong_execution,
            ],
        )


def test_repository_suite_executions_require_one_fork_state_and_seed() -> None:
    first = _descriptor(test_name="testAlpha", start_line=10)
    second = _descriptor(test_name="testBeta", start_line=20)
    selection = _selection((first, second))
    first_execution = _execution(selection, first)
    second_fields = _execution(selection, second).model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    second_fields["fuzz_seed"] = "0x" + ("0" * 63) + "2"
    second_execution = RepositoryTestExecution.sealed(**second_fields)

    with pytest.raises(
        ValidationError,
        match=r"one pinned fork state and seed|differs from its typed execution policy",
    ):
        _scanner_run(selection, [first_execution, second_execution])


def test_successful_repository_suite_rejects_unclassified_or_wrong_framework_evidence() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    unavailable_fields = _execution(selection, descriptor).model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    unavailable_fields.update(
        {
            "status": RepositoryTestExecutionStatus.UNAVAILABLE,
            "terminal_detail": "Synthetic local prerequisite was unavailable.",
            "chain_id": None,
            "block_number": None,
            "block_hash": None,
            "test_kind": None,
            "fuzz_cases": 0,
            "invariant_runs": 0,
            "invariant_calls": 0,
            "command_sha256": None,
            "output_sha256": None,
            "output_bytes": 0,
            "machine_result_sha256": None,
            "process_exit_code": None,
            "machine_output_validated": False,
            "compiler_version": None,
            "compiler_sha256": None,
            "execution_policy_sha256": None,
        }
    )
    unavailable = RepositoryTestExecution.sealed(**unavailable_fields)
    with pytest.raises(ValidationError, match="classified machine result"):
        _scanner_run(selection, [unavailable])

    hardhat = _descriptor(
        framework=RepositorySuiteFramework.HARDHAT,
        path="contracts/test/Vault.test.ts",
    )
    hardhat_selection = _selection((hardhat,))
    with pytest.raises(ValidationError, match="framework differs"):
        _scanner_run(
            hardhat_selection,
            [_execution(hardhat_selection, hardhat)],
        )


def test_repository_execution_machine_result_hash_matches_classification_state() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    classified = _execution(selection, descriptor).model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    classified["machine_result_sha256"] = None
    with pytest.raises(ValidationError, match="normalized machine-result hash"):
        RepositoryTestExecution.sealed(**classified)

    unavailable = classified.copy()
    unavailable.update(
        {
            "status": RepositoryTestExecutionStatus.UNAVAILABLE,
            "terminal_detail": "Synthetic local prerequisite was unavailable.",
            "chain_id": None,
            "block_number": None,
            "block_hash": None,
            "test_kind": None,
            "command_sha256": None,
            "output_sha256": None,
            "output_bytes": 0,
            "machine_result_sha256": HASH_A,
            "process_exit_code": None,
            "machine_output_validated": False,
            "compiler_version": None,
            "compiler_sha256": None,
            "execution_policy_sha256": None,
        }
    )
    with pytest.raises(ValidationError, match="cannot claim a normalized"):
        RepositoryTestExecution.sealed(**unavailable)


def test_successful_foundry_repository_suite_requires_matching_summary() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(selection, descriptor)
    valid = _scanner_run(selection, [execution])
    payload = valid.model_dump(mode="json")
    payload["foundry_summary"] = None

    with pytest.raises(ValidationError, match="requires its summary"):
        ScannerRun.model_validate(payload)


def test_failing_repository_execution_requires_hash_bound_finding() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(
        selection,
        descriptor,
        status=RepositoryTestExecutionStatus.ASSERTION_FAILED,
    )

    with pytest.raises(ValidationError, match="every failing repository test"):
        _scanner_run(selection, [execution])

    finding = ScannerFinding(
        scanner="foundry_fork",
        rule_id="repository-test-assertion",
        title="Synthetic repository assertion failed",
        severity=Severity.MEDIUM,
        message="A selected synthetic test observed an incorrect state transition.",
        locations=[Location(path=descriptor.path, start_line=10, end_line=12)],
        metadata={"repository_test_execution_sha256": execution.execution_sha256},
        fingerprint=HASH_C,
    )
    restored = ScannerRun.model_validate_json(
        _scanner_run(selection, [execution], findings=[finding]).model_dump_json()
    )

    assert restored.findings[0].metadata["repository_test_execution_sha256"] == (
        execution.execution_sha256
    )

    overstated = finding.model_copy(
        update={"evidence_strength": EvidenceStrength.DETERMINISTIC_ANALYZER}
    )
    with pytest.raises(ValidationError, match="evidence strength differs"):
        _scanner_run(selection, [execution], findings=[overstated])
    wrong_scanner = finding.model_copy(update={"scanner": "other"})
    with pytest.raises(ValidationError, match="scanner differs"):
        _scanner_run(selection, [execution], findings=[wrong_scanner])
    wrong_location = finding.model_copy(
        update={
            "locations": [Location(path="contracts/test/Other.t.sol", start_line=1, end_line=1)]
        }
    )
    with pytest.raises(ValidationError, match="location differs"):
        _scanner_run(selection, [execution], findings=[wrong_location])


def test_foundry_summary_must_match_repository_execution_outcomes() -> None:
    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(selection, descriptor)
    inconsistent = FoundryTestExecutionSummary(
        unit_tests=1,
        fuzz_tests=0,
        invariant_tests=0,
        passed_tests=0,
        failed_tests=1,
        skipped_tests=0,
        fuzz_cases=0,
        invariant_runs=0,
        invariant_calls=0,
    )

    with pytest.raises(ValidationError, match="summary does not match"):
        _scanner_run(
            selection,
            [execution],
            foundry_summary=inconsistent,
        )


def test_empty_repository_suite_selection_cannot_report_success() -> None:
    selection = _selection(())

    with pytest.raises(ValidationError, match="empty repository suite selection"):
        _scanner_run(selection, [])
