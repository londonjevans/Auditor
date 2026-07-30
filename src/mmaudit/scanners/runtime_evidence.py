"""Process-local authority for host-observed Foundry repository-suite runs."""

from __future__ import annotations

import hashlib
import json
import threading
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import cast

from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    Location,
    LocationValidation,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.repository.locations import validate_location
from mmaudit.scanners.base import ScannerWorkspaceCopyCustody

_OBSERVED_TERMINAL_STATUSES = frozenset(
    {
        ScannerStatus.SUCCESS,
        ScannerStatus.FAILED,
        ScannerStatus.TIMED_OUT,
    }
)
_ATTEMPTED_TEST_STATUSES = frozenset(
    {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    }
)
_MACHINE_VALIDATED_TEST_STATUSES = frozenset(
    {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
)


def _scanner_run_sha256(run: ScannerRun) -> str:
    return hashlib.sha256(
        json.dumps(
            run.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _inventory_matches_runtime(
    inventory: RepositorySuiteInventoryEvidence,
    run: ScannerRun,
    attestation_sha256: str,
) -> bool:
    selection = run.repository_suite_selection
    return (
        selection is not None
        and inventory.execution_evidence is ExecutionEvidenceKind.REAL
        and inventory.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
        and inventory.repository_sha256 == selection.repository_sha256
        and inventory.tool_version == run.version
        and inventory.tool_sha256 == run.executable_sha256
        and inventory.isolation_backend == run.isolation_backend
        and inventory.isolation_attestation_sha256 == attestation_sha256
    )


def _execution_matches_run(
    run: ScannerRun,
    execution_policy: RepositorySuiteExecutionPolicy,
    execution: RepositoryTestExecution,
    attestation_sha256: str,
) -> bool:
    machine_validated = execution.status in _MACHINE_VALIDATED_TEST_STATUSES
    return (
        execution.status in _ATTEMPTED_TEST_STATUSES
        and execution.execution_evidence is ExecutionEvidenceKind.REAL
        and execution.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
        and execution.isolation_backend == run.isolation_backend
        and execution.isolation_attestation_sha256 == attestation_sha256
        and execution.chain_id == execution_policy.chain_id
        and execution.block_number == execution_policy.block_number
        and execution.block_hash == execution_policy.block_hash
        and execution.fuzz_seed == execution_policy.fuzz_seed
        and execution.compiler_version == execution_policy.compiler_version
        and execution.compiler_sha256 == execution_policy.compiler_sha256
        and execution.command_sha256 is not None
        and execution.output_sha256 is not None
        and execution.execution_policy_sha256 == execution_policy.policy_sha256
        and execution.machine_output_validated is machine_validated
        and (
            (execution.machine_result_sha256 is not None)
            if machine_validated
            else (execution.machine_result_sha256 is None)
        )
        and execution.execution_sha256 == execution.expected_execution_sha256()
    )


def _run_matches_runtime(
    run: ScannerRun,
    *,
    backend_name: str,
    attestation_sha256: str,
) -> bool:
    selection = run.repository_suite_selection
    execution_policy = run.repository_suite_execution_policy
    if (
        type(run) is not ScannerRun
        or run.scanner != "foundry_fork"
        or run.status not in _OBSERVED_TERMINAL_STATUSES
        or run.execution_evidence is not ExecutionEvidenceKind.REAL
        or run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
        or selection is None
        or selection.selected_test_count == 0
        or execution_policy is None
        or run.version is None
        or run.executable_sha256 is None
        or run.isolation_backend != backend_name
        or run.isolation_attestation_sha256 != attestation_sha256
        or execution_policy.tool_version != run.version
        or execution_policy.tool_sha256 != run.executable_sha256
        or execution_policy.isolation_backend != backend_name
        or execution_policy.isolation_attestation_sha256 != attestation_sha256
        or not run.command
        or run.execution_observation_sha256 != run.expected_execution_observation_sha256()
        or len(run.repository_test_executions) != selection.selected_test_count
        or any(
            not _execution_matches_run(
                run,
                execution_policy,
                execution,
                attestation_sha256,
            )
            for execution in run.repository_test_executions
        )
    ):
        return False

    inventory = run.repository_suite_inventory
    post_inventory = run.repository_suite_post_inventory
    if (
        selection.inventory_kind is RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
        and inventory is None
    ):
        return False
    if inventory is not None and not _inventory_matches_runtime(
        inventory,
        run,
        attestation_sha256,
    ):
        return False
    return post_inventory is None or _inventory_matches_runtime(
        post_inventory,
        run,
        attestation_sha256,
    )


def _build_foundry_runtime_authority(
    *,
    adapter_type: type[object] | None = None,
    producer_body: Callable[..., ScannerRun] | None = None,
    execution_evidence_resolver: Callable[
        [object | None], ExecutionEvidenceKind
    ] = isolation_execution_evidence,
    attestation_resolver: Callable[[object | None], str | None] = isolation_attestation_sha256,
    location_validator: Callable[[Path, Location], LocationValidation] = validate_location,
) -> tuple[
    Callable[..., ScannerRun],
    Callable[[ScannerRun], bool],
    Callable[[ScannerRun], ScannerRun],
    Callable[[Path, ScannerRun], ScannerRun],
]:
    """Keep issuance in one exact built-in invocation path, not a public attester."""

    from mmaudit.scanners.foundry import FoundryForkScanner

    trusted_adapter_type = adapter_type or FoundryForkScanner
    trusted_producer_body = cast(
        "Callable[..., ScannerRun]",
        producer_body or FoundryForkScanner._run_repository_suite,
    )
    trusted_execution_evidence = execution_evidence_resolver
    trusted_attestation = attestation_resolver
    trusted_location_validator = location_validator

    class _AuthoritySeal:
        __slots__ = (
            "attestation_sha256",
            "backend",
            "backend_name",
            "run",
            "run_sha256",
        )

        def __init__(
            self,
            *,
            run: ScannerRun,
            backend: object,
            backend_name: str,
            attestation_sha256: str,
        ) -> None:
            self.run = weakref.ref(run)
            self.run_sha256 = _scanner_run_sha256(run)
            self.backend = weakref.ref(backend)
            self.backend_name = backend_name
            self.attestation_sha256 = attestation_sha256

    registry: dict[int, _AuthoritySeal] = {}
    lock = threading.RLock()

    def current_seal(run: ScannerRun) -> _AuthoritySeal | None:
        with lock:
            seal = registry.get(id(run))
        if seal is None:
            return None
        backend = seal.backend()
        if (
            seal.run() is not run
            or backend is None
            or seal.run_sha256 != _scanner_run_sha256(run)
            or trusted_execution_evidence(backend) is not ExecutionEvidenceKind.REAL
            or trusted_attestation(backend) != seal.attestation_sha256
            or not _run_matches_runtime(
                run,
                backend_name=seal.backend_name,
                attestation_sha256=seal.attestation_sha256,
            )
        ):
            return None
        return seal

    def register(
        run: ScannerRun,
        *,
        backend: object,
        backend_name: str,
        attestation_sha256: str,
    ) -> bool:
        if (
            trusted_execution_evidence(backend) is not ExecutionEvidenceKind.REAL
            or trusted_attestation(backend) != attestation_sha256
            or not _run_matches_runtime(
                run,
                backend_name=backend_name,
                attestation_sha256=attestation_sha256,
            )
        ):
            return False
        key = id(run)
        seal = _AuthoritySeal(
            run=run,
            backend=backend,
            backend_name=backend_name,
            attestation_sha256=attestation_sha256,
        )

        def discard_run(reference: weakref.ReferenceType[ScannerRun]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current.run is reference:
                    registry.pop(key, None)

        def discard_backend(reference: weakref.ReferenceType[object]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current.backend is reference:
                    registry.pop(key, None)

        seal.run = weakref.ref(run, discard_run)
        seal.backend = weakref.ref(backend, discard_backend)
        with lock:
            registry[key] = seal
        return True

    def execute_trusted_producer(
        adapter: object,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: object | None,
        expected_version: str | None,
        expected_sha256: str | None,
    ) -> ScannerRun:
        """Execute the captured producer body with its original custody-finalization contract."""

        workspace_custody_guard: list[ScannerWorkspaceCopyCustody] = []
        primary_error: BaseException | None = None
        try:
            return trusted_producer_body(
                adapter,
                root,
                private_dir,
                timeout_seconds,
                backend=backend,
                expected_version=expected_version,
                expected_sha256=expected_sha256,
                workspace_custody_guard=workspace_custody_guard,
            )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            close_error: OSError | None = None
            for custody in workspace_custody_guard:
                try:
                    custody.close()
                except OSError as exc:
                    if close_error is None:
                        close_error = exc
            if close_error is not None and primary_error is None:
                raise close_error

    def invoke(
        adapter: object,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: object | None,
        expected_version: str | None,
        expected_sha256: str | None,
    ) -> ScannerRun:
        if type(adapter) is not trusted_adapter_type:
            raise TypeError("runtime authority requires the exact built-in Foundry adapter")
        before_evidence = trusted_execution_evidence(backend)
        before_attestation = trusted_attestation(backend)
        run = execute_trusted_producer(
            adapter,
            root,
            private_dir,
            timeout_seconds,
            backend=backend,
            expected_version=expected_version,
            expected_sha256=expected_sha256,
        )
        after_evidence = trusted_execution_evidence(backend)
        after_attestation = trusted_attestation(backend)
        backend_name = str(getattr(backend, "name", "")) if backend is not None else ""
        if (
            before_evidence is ExecutionEvidenceKind.REAL
            and after_evidence is ExecutionEvidenceKind.REAL
            and before_attestation is not None
            and before_attestation == after_attestation
            and backend_name
        ):
            register(
                run,
                backend=backend,
                backend_name=backend_name,
                attestation_sha256=before_attestation,
            )
        return run

    def contains(run: ScannerRun) -> bool:
        return current_seal(run) is not None

    def preserve(source: ScannerRun, derived: ScannerRun) -> None:
        seal = current_seal(source)
        backend = seal.backend() if seal is not None else None
        if seal is None or backend is None:
            return
        register(
            derived,
            backend=backend,
            backend_name=seal.backend_name,
            attestation_sha256=seal.attestation_sha256,
        )

    def validated_copy(run: ScannerRun) -> ScannerRun:
        """Schema-normalize exact content without minting caller-authored authority."""

        normalized = ScannerRun.model_validate(run.model_dump(mode="json"))
        if normalized.model_dump(mode="json") == run.model_dump(mode="json"):
            preserve(run, normalized)
        return normalized

    def validated_location_annotation(root: Path, run: ScannerRun) -> ScannerRun:
        """Apply only host-computed source validation before preserving authority."""

        findings: list[ScannerFinding] = []
        for finding in run.findings:
            locations = [
                location
                for location in finding.locations
                if location.path != ".git" and not location.path.startswith(".git/")
            ]
            if not locations:
                continue
            validations = [
                trusted_location_validator(root, location).model_dump(mode="json")
                for location in locations
            ]
            findings.append(
                finding.model_copy(
                    update={
                        "locations": locations,
                        "metadata": {
                            **finding.metadata,
                            "location_validation": validations,
                        },
                    }
                )
            )
        updated = run.model_copy(
            update={
                "findings": findings,
                "execution_observation_sha256": None,
            }
        )
        normalized = ScannerRun.model_validate(
            {
                **updated.model_dump(mode="json"),
                "execution_observation_sha256": (updated.expected_execution_observation_sha256()),
            }
        )
        preserve(run, normalized)
        return normalized

    return invoke, contains, validated_copy, validated_location_annotation


(
    _invoke_builtin_foundry_adapter,
    has_host_repository_suite_runtime_authority,
    validated_scanner_run_copy_preserving_runtime_authority,
    validated_scanner_run_location_annotation_preserving_runtime_authority,
) = _build_foundry_runtime_authority()
