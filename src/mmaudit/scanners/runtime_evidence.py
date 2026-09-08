"""Process-local authority for host-observed Foundry repository-suite runs."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, cast

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

if TYPE_CHECKING:
    from mmaudit.scanners.offline_fork_service import OfflineForkRpcLease

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


class _RevocationLeaseUnavailable(RuntimeError):
    """The exact process-local authority was unavailable during a bound lease."""


class _ProcessLocalRevocationLease:
    """Serialize exact authority reads and defer dependent revocation until release."""

    __slots__ = (
        "_authority_process_id",
        "_current_process_id",
        "_local",
        "_lock",
    )

    def __init__(self, process_id_resolver: Callable[[], int] = os.getpid) -> None:
        self._current_process_id = process_id_resolver
        self._authority_process_id = process_id_resolver()
        self._lock = threading.RLock()
        self._local = threading.local()

    @property
    def authority_process_id(self) -> int:
        """Return the PID that created this process-local lease."""

        return self._authority_process_id

    def is_current_process(self) -> bool:
        """Refuse inherited authority without acquiring the inherited lock."""

        return self._current_process_id() == self._authority_process_id

    @staticmethod
    def _notify(callbacks: tuple[Callable[[], None], ...]) -> None:
        for callback in callbacks:
            try:
                callback()
            except BaseException:
                continue

    @contextmanager
    def hold(self) -> Iterator[None]:
        """Hold the shared domain, refusing a fork before touching its inherited lock."""

        if self._current_process_id() != self._authority_process_id:
            raise _RevocationLeaseUnavailable(
                "process-local authority lease cannot cross a process boundary"
            )
        self._lock.acquire()
        entered = False
        callbacks: tuple[Callable[[], None], ...] = ()
        try:
            if self._current_process_id() != self._authority_process_id:
                raise _RevocationLeaseUnavailable(
                    "process-local authority lease cannot cross a process boundary"
                )
            depth = int(getattr(self._local, "depth", 0))
            if depth == 0:
                self._local.callbacks = []
            self._local.depth = depth + 1
            entered = True
            yield
        finally:
            if entered:
                remaining_depth = int(self._local.depth) - 1
                self._local.depth = remaining_depth
                if remaining_depth == 0:
                    callbacks = tuple(self._local.callbacks)
                    del self._local.callbacks
                    del self._local.depth
            self._lock.release()
            if callbacks:
                self._notify(callbacks)

    def defer(self, callbacks: tuple[Callable[[], None], ...]) -> None:
        """Run callbacks only after the outermost shared authority lease releases."""

        if not callbacks or self._current_process_id() != self._authority_process_id:
            return
        if int(getattr(self._local, "depth", 0)) > 0:
            pending = cast("list[Callable[[], None]]", self._local.callbacks)
            pending.extend(callbacks)
            return
        self._notify(callbacks)


_RunAuthorityLease = Callable[[ScannerRun], AbstractContextManager[None]]


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
    revocation_lease: _ProcessLocalRevocationLease | None = None,
) -> tuple[
    Callable[..., ScannerRun],
    Callable[[ScannerRun], bool],
    Callable[[ScannerRun], ScannerRun],
    Callable[[Path, ScannerRun], ScannerRun],
    _RunAuthorityLease,
]:
    """Keep issuance in one exact built-in invocation path, not a public attester."""

    from mmaudit.scanners.foundry import FoundryForkScanner

    trusted_adapter_type = adapter_type or FoundryForkScanner
    trusted_producer_body = cast(
        "Callable[..., ScannerRun]",
        producer_body or FoundryForkScanner._run_repository_suite,
    )
    builtin_primary_lifecycle = trusted_producer_body is FoundryForkScanner._run_repository_suite
    trusted_primary_verifier = FoundryForkScanner._verify_prepared_primary
    trusted_execution_evidence = execution_evidence_resolver
    trusted_attestation = attestation_resolver
    trusted_location_validator = location_validator
    trusted_revocation_lease = revocation_lease or _ProcessLocalRevocationLease()

    class _AuthoritySeal:
        __slots__ = (
            "attestation_sha256",
            "authority_process_id",
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
            self.authority_process_id = trusted_revocation_lease.authority_process_id
            self.run = weakref.ref(run)
            self.run_sha256 = _scanner_run_sha256(run)
            self.backend = weakref.ref(backend)
            self.backend_name = backend_name
            self.attestation_sha256 = attestation_sha256

    registry: dict[int, _AuthoritySeal] = {}
    lock = threading.RLock()

    def remove_registered_seal(
        key: int,
        *,
        expected_seal: _AuthoritySeal | None = None,
        expected_run_reference: weakref.ReferenceType[ScannerRun] | None = None,
        expected_backend_reference: weakref.ReferenceType[object] | None = None,
    ) -> bool:
        """Remove only the exact seal without touching inherited locks after a fork."""

        if not trusted_revocation_lease.is_current_process():
            return False
        try:
            with trusted_revocation_lease.hold(), lock:
                current = registry.get(key)
                if (
                    current is None
                    or (expected_seal is not None and current is not expected_seal)
                    or (
                        expected_run_reference is not None
                        and current.run is not expected_run_reference
                    )
                    or (
                        expected_backend_reference is not None
                        and current.backend is not expected_backend_reference
                    )
                ):
                    return False
                registry.pop(key, None)
                return True
        except _RevocationLeaseUnavailable:
            return False

    def valid_seal_locked(
        run: ScannerRun,
        *,
        expected_seal: _AuthoritySeal | None = None,
    ) -> tuple[_AuthoritySeal, object] | None:
        key = id(run)
        seal = registry.get(key)
        if seal is None or (expected_seal is not None and seal is not expected_seal):
            return None
        backend = seal.backend()
        try:
            valid = bool(
                trusted_revocation_lease.is_current_process()
                and seal.authority_process_id == trusted_revocation_lease.authority_process_id
                and seal.run() is run
                and backend is not None
                and seal.run_sha256 == _scanner_run_sha256(run)
                and trusted_execution_evidence(backend) is ExecutionEvidenceKind.REAL
                and trusted_attestation(backend) == seal.attestation_sha256
                and _run_matches_runtime(
                    run,
                    backend_name=seal.backend_name,
                    attestation_sha256=seal.attestation_sha256,
                )
            )
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            if registry.get(key) is seal:
                registry.pop(key, None)
            return None
        return seal, backend

    @contextmanager
    def authority_lease(run: ScannerRun) -> Iterator[None]:
        """Bind one run to the shared process-local revocation lease."""

        seal: _AuthoritySeal | None = None
        body_raised = False
        try:
            with trusted_revocation_lease.hold():
                with lock:
                    try:
                        seal = registry.get(id(run))
                        entry = valid_seal_locked(run, expected_seal=seal)
                    except BaseException:
                        if seal is not None and registry.get(id(run)) is seal:
                            registry.pop(id(run), None)
                        raise
                if entry is None:
                    raise _RevocationLeaseUnavailable(
                        "repository-suite run authority is unavailable"
                    )
                seal, _backend_guard = entry
                try:
                    yield
                except BaseException:
                    body_raised = True
                    try:
                        with lock:
                            valid_seal_locked(run, expected_seal=seal)
                    except BaseException:
                        with suppress(BaseException), lock:
                            if registry.get(id(run)) is seal:
                                registry.pop(id(run), None)
                    raise
                else:
                    with lock:
                        try:
                            current = valid_seal_locked(run, expected_seal=seal)
                        except BaseException:
                            if registry.get(id(run)) is seal:
                                registry.pop(id(run), None)
                            raise
                    if current is None:
                        raise _RevocationLeaseUnavailable(
                            "repository-suite run authority expired during its lease"
                        )
        except _RevocationLeaseUnavailable:
            raise
        except BaseException:
            if seal is not None and not body_raised:
                with suppress(BaseException):
                    remove_registered_seal(id(run), expected_seal=seal)
            raise

    def current_seal(run: ScannerRun) -> _AuthoritySeal | None:
        try:
            with authority_lease(run), lock:
                seal = registry.get(id(run))
        except _RevocationLeaseUnavailable:
            return None
        return seal

    def register(
        run: ScannerRun,
        *,
        backend: object,
        backend_name: str,
        attestation_sha256: str,
    ) -> _AuthoritySeal | None:
        key = id(run)
        seal = _AuthoritySeal(
            run=run,
            backend=backend,
            backend_name=backend_name,
            attestation_sha256=attestation_sha256,
        )

        def discard_run(reference: weakref.ReferenceType[ScannerRun]) -> None:
            remove_registered_seal(key, expected_run_reference=reference)

        def discard_backend(reference: weakref.ReferenceType[object]) -> None:
            remove_registered_seal(key, expected_backend_reference=reference)

        seal.run = weakref.ref(run, discard_run)
        seal.backend = weakref.ref(backend, discard_backend)
        inserted = False
        completed = False
        try:
            with trusted_revocation_lease.hold():
                if (
                    trusted_execution_evidence(backend) is not ExecutionEvidenceKind.REAL
                    or trusted_attestation(backend) != attestation_sha256
                    or not _run_matches_runtime(
                        run,
                        backend_name=backend_name,
                        attestation_sha256=attestation_sha256,
                    )
                ):
                    return None
                with lock:
                    if key in registry:
                        return None
                    registry[key] = seal
                    inserted = True
                    if valid_seal_locked(run, expected_seal=seal) is None:
                        return None
            completed = True
            return seal
        except _RevocationLeaseUnavailable:
            return None
        finally:
            if inserted and not completed:
                with suppress(BaseException):
                    remove_registered_seal(key, expected_seal=seal)

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
        offline_lease_guard: list[tuple[OfflineForkRpcLease, float]] = []
        primary_error: BaseException | None = None
        try:
            if builtin_primary_lifecycle:
                trusted_primary_verifier(cast("FoundryForkScanner", adapter), timeout_seconds)
            return trusted_producer_body(
                adapter,
                root,
                private_dir,
                timeout_seconds,
                backend=backend,
                expected_version=expected_version,
                expected_sha256=expected_sha256,
                workspace_custody_guard=workspace_custody_guard,
                **(
                    {"offline_lease_guard": offline_lease_guard}
                    if builtin_primary_lifecycle
                    else {}
                ),
            )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            close_error: BaseException | None = None
            for lease, deadline in offline_lease_guard:
                try:
                    lease.stop(deadline=deadline)
                    if not lease.stopped_cleanly:
                        raise ValueError("managed primary fork did not close cleanly")
                except BaseException as exc:
                    if close_error is None:
                        close_error = exc
            if builtin_primary_lifecycle:
                try:
                    trusted_primary_verifier(cast("FoundryForkScanner", adapter), timeout_seconds)
                except BaseException as exc:
                    if close_error is None:
                        close_error = exc
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
        derived_seal: _AuthoritySeal | None = None
        completed = False
        try:
            with authority_lease(source):
                with lock:
                    seal = registry.get(id(source))
                    backend = seal.backend() if seal is not None else None
                if seal is None or backend is None:
                    return
                derived_seal = register(
                    derived,
                    backend=backend,
                    backend_name=seal.backend_name,
                    attestation_sha256=seal.attestation_sha256,
                )
            completed = True
        except _RevocationLeaseUnavailable:
            return
        finally:
            if derived_seal is not None and not completed:
                with suppress(BaseException):
                    remove_registered_seal(id(derived), expected_seal=derived_seal)

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

    return invoke, contains, validated_copy, validated_location_annotation, authority_lease


_HOST_REPOSITORY_SUITE_REVOCATION_LEASE = _ProcessLocalRevocationLease()
(
    _invoke_builtin_foundry_adapter,
    has_host_repository_suite_runtime_authority,
    validated_scanner_run_copy_preserving_runtime_authority,
    validated_scanner_run_location_annotation_preserving_runtime_authority,
    _lease_host_repository_suite_runtime_authority,
) = _build_foundry_runtime_authority(
    revocation_lease=_HOST_REPOSITORY_SUITE_REVOCATION_LEASE,
)
