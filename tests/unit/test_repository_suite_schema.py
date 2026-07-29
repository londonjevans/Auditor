from __future__ import annotations

import hashlib
import json
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
    RepositorySuiteInventoryArtifact,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositorySuiteInventoryRecord,
    RepositorySuiteProjectInventoryEvidence,
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


def _inventory_record(
    *,
    execution_source_sha256: str = HASH_A,
    declaration_source_sha256: str = HASH_B,
    declaration_start_line: int = 7,
    declaration_end_line: int = 9,
) -> RepositorySuiteInventoryRecord:
    return RepositorySuiteInventoryRecord.sealed(
        project_root="contracts",
        execution_path="contracts/test/ConcreteVault.t.sol",
        execution_suite_name="ConcreteVaultTest",
        test_name="testInheritedInvariant",
        execution_signature="testInheritedInvariant",
        execution_source_sha256=execution_source_sha256,
        execution_start_line=20,
        execution_end_line=40,
        execution_contract_ast_id=101,
        declaration_path="contracts/test/VaultBase.t.sol",
        declaration_suite_name="VaultBaseTest",
        declaration_signature="testInheritedInvariant()",
        declaration_source_sha256=declaration_source_sha256,
        declaration_start_line=declaration_start_line,
        declaration_end_line=declaration_end_line,
        declaration_contract_ast_id=202,
        declaration_function_ast_id=303,
        build_info_sha256=HASH_C,
    )


def _project_inventory(
    record: RepositorySuiteInventoryRecord,
    *,
    stdout_bytes: int = 100,
) -> RepositorySuiteProjectInventoryEvidence:
    artifact = RepositorySuiteInventoryArtifact(
        name="build-info.json",
        sha256=HASH_C,
        normalized_sha256=HASH_C,
        bytes=200,
    )
    artifact_payload = [artifact.model_dump(mode="json")]
    record_hashes = [record.record_sha256]
    return RepositorySuiteProjectInventoryEvidence.sealed(
        project_root=record.project_root,
        command_sha256=HASH_A,
        process_exit_code=0,
        machine_output_validated=True,
        stdout_sha256=HASH_B,
        stdout_bytes=stdout_bytes,
        stderr_sha256=HASH_C,
        stderr_bytes=0,
        build_info_artifacts=(artifact,),
        build_info_bundle_sha256=_canonical_sha256(artifact_payload),
        normalized_build_info_bundle_sha256=_canonical_sha256([artifact.normalized_sha256]),
        parser_inventory_sha256=HASH_A,
        records=(record,),
        normalized_inventory_sha256=_canonical_sha256(record_hashes),
    )


def _inventory(
    phase: RepositorySuiteInventoryPhase,
    *,
    record: RepositorySuiteInventoryRecord | None = None,
) -> RepositorySuiteInventoryEvidence:
    selected_record = record or _inventory_record()
    project = _project_inventory(selected_record)
    record_hashes = [selected_record.record_sha256]
    return RepositorySuiteInventoryEvidence.sealed(
        phase=phase,
        repository_sha256=HASH_B,
        configuration_sha256=HASH_C,
        tool_version="1.3.2",
        tool_sha256=HASH_A,
        compiler_version="solc 0.8.30",
        compiler_sha256="d" * 64,
        isolation_backend="synthetic-isolation",
        isolation_attestation_sha256=HASH_C,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        projects=(project,),
        project_bundle_sha256=_canonical_sha256([project.project_inventory_sha256]),
        normalized_inventory_sha256=_canonical_sha256(record_hashes),
        inventory_record_count=1,
    )


def _inventory_descriptor(
    inventory: RepositorySuiteInventoryEvidence,
    *,
    record: RepositorySuiteInventoryRecord | None = None,
    inventory_sha256: str | None = None,
    inventory_record_sha256: str | None = None,
    execution_source_sha256: str | None = None,
) -> RepositorySuiteTestDescriptor:
    selected_record = record or inventory.projects[0].records[0]
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=selected_record.project_root,
        path=selected_record.execution_path,
        suite_name=selected_record.execution_suite_name,
        test_name=selected_record.test_name,
        source_sha256=execution_source_sha256 or selected_record.execution_source_sha256,
        start_line=selected_record.execution_start_line,
        end_line=selected_record.execution_end_line,
        inventory_sha256=inventory_sha256 or inventory.normalized_inventory_sha256,
        inventory_record_sha256=(inventory_record_sha256 or selected_record.record_sha256),
        execution_contract_ast_id=selected_record.execution_contract_ast_id,
        declaration_path=selected_record.declaration_path,
        declaration_suite_name=selected_record.declaration_suite_name,
        declaration_signature=selected_record.declaration_signature,
        declaration_source_sha256=selected_record.declaration_source_sha256,
        declaration_start_line=selected_record.declaration_start_line,
        declaration_end_line=selected_record.declaration_end_line,
        declaration_contract_ast_id=selected_record.declaration_contract_ast_id,
        declaration_function_ast_id=selected_record.declaration_function_ast_id,
    )


def _inventory_selection(
    descriptor: RepositorySuiteTestDescriptor,
    *,
    inventory_sha256: str | None = None,
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
        inventory_kind=RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO,
        inventory_sha256=inventory_sha256 or descriptor.inventory_sha256,
        tests=(descriptor,),
    )


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
        repository_exclusion_path=".mmaudit",
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
    inventory: RepositorySuiteInventoryEvidence | None = None,
    post_inventory: RepositorySuiteInventoryEvidence | None = None,
) -> RepositoryTestExecution:
    failed = status in {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
    return RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        inventory_sha256=(inventory.inventory_sha256 if inventory is not None else None),
        post_inventory_sha256=(
            post_inventory.inventory_sha256 if post_inventory is not None else None
        ),
        inventory_record_sha256=(
            descriptor.inventory_record_sha256 if inventory is not None else None
        ),
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
    inventory: RepositorySuiteInventoryEvidence | None = None,
    post_inventory: RepositorySuiteInventoryEvidence | None = None,
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
        repository_suite_inventory=inventory,
        repository_suite_post_inventory=post_inventory,
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
            repository_exclusion_path=".mmaudit",
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
        repository_exclusion_path=".mmaudit",
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
            repository_exclusion_path=".mmaudit",
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


def test_repository_suite_selection_requires_hash_bound_normalized_exclusion_path() -> None:
    selection = _selection()
    missing = selection.model_dump(mode="json")
    missing.pop("repository_exclusion_path")
    with pytest.raises(ValidationError, match="repository_exclusion_path"):
        RepositorySuiteSelection.model_validate(missing)

    for invalid in ("", ".", "../output", "/tmp/output", "output/../audit", ".env-output"):
        values = selection.model_dump(
            mode="python",
            exclude={"repository_exclusion_path", "selection_sha256"},
        )
        values["inventory_kind"] = selection.inventory_kind
        values["tests"] = selection.tests
        with pytest.raises(
            ValidationError,
            match=r"repository_exclusion_path|exclusion path",
        ):
            RepositorySuiteSelection.sealed(
                **values,
                repository_exclusion_path=invalid,
            )

    tampered = selection.model_dump(mode="json")
    tampered["repository_exclusion_path"] = "custom-audit-output"
    with pytest.raises(ValidationError, match="selection hash"):
        RepositorySuiteSelection.model_validate(tampered)


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


def test_repository_suite_inventory_layers_reject_self_hash_tampering() -> None:
    record = _inventory_record()
    record_payload = record.model_dump(mode="json")
    record_payload["execution_start_line"] = record.execution_start_line + 1
    with pytest.raises(ValidationError, match="inventory record hash"):
        RepositorySuiteInventoryRecord.model_validate(record_payload)

    project = _project_inventory(record)
    project_payload = project.model_dump(mode="json")
    project_payload["stdout_bytes"] = project.stdout_bytes + 1
    with pytest.raises(ValidationError, match="project inventory hash"):
        RepositorySuiteProjectInventoryEvidence.model_validate(project_payload)

    inventory = _inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION, record=record)
    inventory_payload = inventory.model_dump(mode="json")
    inventory_payload["tool_version"] = "1.3.3"
    with pytest.raises(ValidationError, match="inventory evidence hash"):
        RepositorySuiteInventoryEvidence.model_validate(inventory_payload)


def test_project_inventory_rejects_duplicate_normalized_build_info_artifacts() -> None:
    record = _inventory_record()
    artifacts = (
        RepositorySuiteInventoryArtifact(
            name="build-info-a.json",
            sha256=HASH_A,
            normalized_sha256=HASH_C,
            bytes=200,
        ),
        RepositorySuiteInventoryArtifact(
            name="build-info-b.json",
            sha256=HASH_B,
            normalized_sha256=HASH_C,
            bytes=200,
        ),
    )

    with pytest.raises(ValidationError, match="normalized build-info artifacts must be unique"):
        RepositorySuiteProjectInventoryEvidence.sealed(
            project_root=record.project_root,
            command_sha256=HASH_A,
            process_exit_code=0,
            machine_output_validated=True,
            stdout_sha256=HASH_B,
            stdout_bytes=100,
            stderr_sha256=HASH_C,
            stderr_bytes=0,
            build_info_artifacts=artifacts,
            build_info_bundle_sha256=_canonical_sha256(
                [artifact.model_dump(mode="json") for artifact in artifacts]
            ),
            normalized_build_info_bundle_sha256=_canonical_sha256([HASH_C]),
            parser_inventory_sha256=HASH_A,
            records=(record,),
            normalized_inventory_sha256=_canonical_sha256([record.record_sha256]),
        )


def test_repository_suite_rejects_pre_post_compiler_inventory_drift() -> None:
    pre_inventory = _inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION)
    drifted_record = _inventory_record(declaration_end_line=10)
    post_inventory = _inventory(
        RepositorySuiteInventoryPhase.POST_EXECUTION,
        record=drifted_record,
    )
    descriptor = _inventory_descriptor(pre_inventory)
    selection = _inventory_selection(descriptor)
    execution = _execution(
        selection,
        descriptor,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )

    with pytest.raises(ValidationError, match="inventory evidence drifted"):
        _scanner_run(
            selection,
            [execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )


def test_repository_suite_cross_binds_selection_descriptor_inventory_and_execution() -> None:
    pre_inventory = _inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION)
    post_inventory = _inventory(RepositorySuiteInventoryPhase.POST_EXECUTION)
    descriptor = _inventory_descriptor(pre_inventory)
    selection = _inventory_selection(descriptor)
    execution = _execution(
        selection,
        descriptor,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )

    restored = ScannerRun.model_validate_json(
        _scanner_run(
            selection,
            [execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        ).model_dump_json()
    )
    assert restored.repository_suite_inventory == pre_inventory
    assert restored.repository_suite_post_inventory == post_inventory
    assert restored.repository_test_executions[0].inventory_sha256 == (
        pre_inventory.inventory_sha256
    )
    assert restored.repository_test_executions[0].post_inventory_sha256 == (
        post_inventory.inventory_sha256
    )
    assert pre_inventory.inventory_sha256 != post_inventory.inventory_sha256

    wrong_inventory_sha256 = "e" * 64
    selection_mismatch_descriptor = _inventory_descriptor(
        pre_inventory,
        inventory_sha256=wrong_inventory_sha256,
    )
    selection_mismatch = _inventory_selection(
        selection_mismatch_descriptor,
        inventory_sha256=wrong_inventory_sha256,
    )
    selection_mismatch_execution = _execution(
        selection_mismatch,
        selection_mismatch_descriptor,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )
    with pytest.raises(ValidationError, match="selection differs from its pre-execution inventory"):
        _scanner_run(
            selection_mismatch,
            [selection_mismatch_execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )

    absent_record_descriptor = _inventory_descriptor(
        pre_inventory,
        inventory_record_sha256="f" * 64,
    )
    absent_record_selection = _inventory_selection(absent_record_descriptor)
    absent_record_execution = _execution(
        absent_record_selection,
        absent_record_descriptor,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )
    with pytest.raises(ValidationError, match="descriptor is absent from compiler inventory"):
        _scanner_run(
            absent_record_selection,
            [absent_record_execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )

    divergent_descriptor = _inventory_descriptor(
        pre_inventory,
        execution_source_sha256="e" * 64,
    )
    divergent_selection = _inventory_selection(divergent_descriptor)
    divergent_execution = _execution(
        divergent_selection,
        divergent_descriptor,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )
    with pytest.raises(ValidationError, match="descriptor differs from compiler inventory record"):
        _scanner_run(
            divergent_selection,
            [divergent_execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )

    mismatched_execution_payload = execution.model_dump(
        mode="python",
        exclude={"execution_sha256"},
    )
    mismatched_execution_payload["inventory_sha256"] = wrong_inventory_sha256
    mismatched_execution = RepositoryTestExecution.sealed(
        **mismatched_execution_payload,
    )
    with pytest.raises(ValidationError, match="execution differs from compiler inventories"):
        _scanner_run(
            selection,
            [mismatched_execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )


def test_inherited_repository_failure_uses_declaration_location() -> None:
    pre_inventory = _inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION)
    post_inventory = _inventory(RepositorySuiteInventoryPhase.POST_EXECUTION)
    descriptor = _inventory_descriptor(pre_inventory)
    selection = _inventory_selection(descriptor)
    execution = _execution(
        selection,
        descriptor,
        status=RepositoryTestExecutionStatus.ASSERTION_FAILED,
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )
    finding = ScannerFinding(
        scanner="foundry_fork",
        rule_id="repository-test-assertion",
        title="Synthetic inherited repository assertion failed",
        severity=Severity.MEDIUM,
        message="A selected synthetic inherited test observed an incorrect state transition.",
        locations=[
            Location(
                path="contracts/test/VaultBase.t.sol",
                start_line=7,
                end_line=9,
            )
        ],
        metadata={"repository_test_execution_sha256": execution.execution_sha256},
        fingerprint=HASH_C,
    )

    run = _scanner_run(
        selection,
        [execution],
        findings=[finding],
        inventory=pre_inventory,
        post_inventory=post_inventory,
    )
    assert run.findings[0].locations[0].path == descriptor.declaration_path
    assert descriptor.finding_path == "contracts/test/VaultBase.t.sol"
    assert descriptor.finding_start_line == 7
    assert descriptor.finding_end_line == 9

    execution_location = finding.model_copy(
        update={
            "locations": [
                Location(
                    path=descriptor.path,
                    start_line=descriptor.start_line,
                    end_line=descriptor.end_line,
                )
            ]
        }
    )
    with pytest.raises(ValidationError, match="location differs from its test descriptor"):
        _scanner_run(
            selection,
            [execution],
            findings=[execution_location],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )


def test_static_repository_selection_rejects_compiler_inventory_claims() -> None:
    pre_inventory = _inventory(RepositorySuiteInventoryPhase.PRE_EXECUTION)
    post_inventory = _inventory(RepositorySuiteInventoryPhase.POST_EXECUTION)
    bound_descriptor = _inventory_descriptor(pre_inventory)

    with pytest.raises(ValidationError, match="static repository selection"):
        _selection((bound_descriptor,))

    descriptor = _descriptor()
    selection = _selection((descriptor,))
    execution = _execution(selection, descriptor)
    with pytest.raises(ValidationError, match="static repository selection"):
        _scanner_run(
            selection,
            [execution],
            inventory=pre_inventory,
            post_inventory=post_inventory,
        )
