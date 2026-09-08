"""Exact built-in Foundry execution for source-local mutation comparisons."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from mmaudit.benchmark.mutations import (
    MutationSuiteObservation,
    MutationSuiteTestObservation,
    MutationSuiteTestStatus,
    SourceMutationSpec,
    mutation_repository_sha256,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositoryCodeExecutionState,
    RepositoryForkEgressStatus,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestForkRpcScopeStatus,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.runtime_evidence import (
    _HOST_REPOSITORY_SUITE_REVOCATION_LEASE,
    _invoke_builtin_foundry_adapter,
    _lease_host_repository_suite_runtime_authority,
    _ProcessLocalRevocationLease,
    _RevocationLeaseUnavailable,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_CLASSIFIED_TEST_STATUSES = frozenset(
    {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
)


class FoundryMutationExecutionError(RuntimeError):
    """The exact baseline/mutant Foundry comparison could not be proven."""


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


def _model_sha256(model: MutationSuiteObservation | ScannerRun) -> str:
    return _canonical_sha256(model.model_dump(mode="json"))


def _logical_test_projection(
    descriptor: RepositorySuiteTestDescriptor,
) -> dict[str, object]:
    return {
        "framework": descriptor.framework.value,
        "project_root": descriptor.project_root,
        "path": descriptor.path,
        "suite_name": descriptor.suite_name,
        "test_name": descriptor.test_name,
        "source_sha256": descriptor.source_sha256,
        "start_line": descriptor.start_line,
        "end_line": descriptor.end_line,
        "declaration_path": descriptor.declaration_path,
        "declaration_suite_name": descriptor.declaration_suite_name,
        "declaration_signature": descriptor.declaration_signature,
        "declaration_source_sha256": descriptor.declaration_source_sha256,
        "declaration_start_line": descriptor.declaration_start_line,
        "declaration_end_line": descriptor.declaration_end_line,
    }


def _logical_test_identity(descriptor: RepositorySuiteTestDescriptor) -> str:
    return json.dumps(
        _logical_test_projection(descriptor),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_foundry_mutation_test_id(descriptor: RepositorySuiteTestDescriptor) -> str:
    """Bind exact logical/source identity while excluding inventory and compiler AST IDs."""

    digest = _canonical_sha256(
        {
            "schema_version": "1.0",
            "test": _logical_test_projection(descriptor),
        }
    )
    return f"foundry:{digest}"


class _InvokeFoundry(Protocol):
    def __call__(
        self,
        adapter: object,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: object | None,
        expected_version: str | None,
        expected_sha256: str | None,
    ) -> ScannerRun: ...


_RunAuthorityLease = Callable[[ScannerRun], AbstractContextManager[None]]


@dataclass(frozen=True, slots=True)
class _FoundryMutationRunBinding:
    repository_sha256: str
    selection_sha256: str
    selection_configuration_sha256: str
    logical_test_ids: tuple[str, ...]
    tool_name: str
    tool_version: str
    tool_sha256: str
    compiler_version: str
    compiler_sha256: str
    chain_id: int
    block_number: int
    block_hash: str
    fuzz_seed: str
    isolation_backend: str
    isolation_attestation_sha256: str
    execution_policy_sha256: str
    execution_environment_sha256: str
    execution_observation_sha256: str
    execution_sha256s: tuple[str, ...]
    inventory_sha256: str | None
    post_inventory_sha256: str | None
    fork_rpc_egress_sha256: str | None
    fork_rpc_scope_evidence_sha256s: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _FoundryMutationRuntimeResult:
    """Live authority and exact bindings intentionally absent from the public schema."""

    observation: MutationSuiteObservation
    baseline_run: ScannerRun
    mutant_run: ScannerRun
    baseline_binding: _FoundryMutationRunBinding
    mutant_binding: _FoundryMutationRunBinding
    runtime_bindings_sha256: str
    authority_custody: object = field(repr=False, compare=False)


class _ExecuteMutation(Protocol):
    def __call__(
        self,
        *,
        baseline_adapter: FoundryForkScanner,
        mutant_adapter: FoundryForkScanner,
        backend: ScannerIsolationBackend,
        timeout_seconds: float,
        expected_tool_version: str,
        expected_tool_sha256: str,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation: ...


_ContainsObservation = Callable[[MutationSuiteObservation], bool]
_CopyObservation = Callable[[MutationSuiteObservation], MutationSuiteObservation]
_ObservationAuthorityLease = Callable[[MutationSuiteObservation], AbstractContextManager[None]]


@dataclass(slots=True)
class _MutationObservationAuthoritySeal:
    observation: weakref.ReferenceType[MutationSuiteObservation]
    observation_sha256: str
    baseline_run: ScannerRun
    mutant_run: ScannerRun
    baseline_run_sha256: str
    mutant_run_sha256: str
    baseline_binding: _FoundryMutationRunBinding
    mutant_binding: _FoundryMutationRunBinding
    runtime_bindings_sha256: str
    mutation_id: str
    suite_selection_sha256: str
    executor_sha256: str
    isolation_policy_sha256: str
    baseline_source_sha256: str
    mutant_source_sha256: str
    authority_process_id: int
    authority_custody: object


def _captured_executor_sha256(invoke: _InvokeFoundry) -> str:
    components: list[dict[str, str]] = []
    for label, implementation in (
        ("mutation_executor", _captured_executor_sha256),
        ("runtime_invoke", invoke),
        ("foundry_adapter", FoundryForkScanner),
    ):
        try:
            source_path_text = inspect.getsourcefile(implementation)
            if source_path_text is None:
                raise ValueError
            source_path = Path(source_path_text)
            if source_path.is_symlink() or not source_path.is_file():
                raise ValueError
            source = source_path.read_bytes()
        except (OSError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "Foundry mutation executor implementation identity is unavailable"
            ) from exc
        if not source or len(source) > 2_000_000:
            raise RuntimeError("Foundry mutation executor implementation identity is invalid")
        components.append(
            {
                "label": label,
                "module": str(getattr(implementation, "__module__", "")),
                "qualname": str(getattr(implementation, "__qualname__", "")),
                "module_source_sha256": hashlib.sha256(source).hexdigest(),
            }
        )
    return _canonical_sha256(
        {
            "schema_version": "1.0",
            "implementation_components": components,
        }
    )


def _build_mutation_execution_authority(
    invoke: _InvokeFoundry,
    run_authority_lease: _RunAuthorityLease,
    revocation_lease: _ProcessLocalRevocationLease,
) -> tuple[
    _ExecuteMutation,
    _ContainsObservation,
    _CopyObservation,
    _ObservationAuthorityLease,
]:
    """Capture execution and issuance inside one closed process-local authority."""

    registry: dict[int, _MutationObservationAuthoritySeal] = {}
    lock = threading.RLock()
    executor_sha256 = _captured_executor_sha256(invoke)
    current_process_id = os.getpid
    authority_process_id = current_process_id()

    def remove_registered_seal(
        key: int,
        *,
        expected_seal: _MutationObservationAuthoritySeal | None = None,
        expected_reference: weakref.ReferenceType[MutationSuiteObservation] | None = None,
    ) -> bool:
        """Remove only the exact observation seal without touching inherited fork locks."""

        if (
            current_process_id() != authority_process_id
            or not revocation_lease.is_current_process()
        ):
            return False
        try:
            with revocation_lease.hold(), lock:
                current = registry.get(key)
                if (
                    current is None
                    or (expected_seal is not None and current is not expected_seal)
                    or (
                        expected_reference is not None
                        and current.observation is not expected_reference
                    )
                ):
                    return False
                registry.pop(key, None)
                return True
        except _RevocationLeaseUnavailable:
            return False

    def valid_local_seal_locked(
        observation: MutationSuiteObservation,
        *,
        expected_seal: _MutationObservationAuthoritySeal | None = None,
    ) -> _MutationObservationAuthoritySeal | None:
        key = id(observation)
        seal = registry.get(key)
        if seal is None or (expected_seal is not None and seal is not expected_seal):
            return None
        try:
            valid = bool(
                current_process_id() == authority_process_id
                and revocation_lease.is_current_process()
                and seal.authority_process_id == authority_process_id
                and seal.observation() is observation
                and seal.observation_sha256 == _model_sha256(observation)
                and seal.baseline_run_sha256 == _model_sha256(seal.baseline_run)
                and seal.mutant_run_sha256 == _model_sha256(seal.mutant_run)
                and seal.baseline_binding == _run_binding(seal.baseline_run)
                and seal.mutant_binding == _run_binding(seal.mutant_run)
                and seal.runtime_bindings_sha256
                == _runtime_bindings_sha256(seal.baseline_binding, seal.mutant_binding)
                and observation.mutation_id == seal.mutation_id
                and observation.suite_selection_sha256 == seal.suite_selection_sha256
                and observation.executor_sha256 == seal.executor_sha256
                and observation.isolation_policy_sha256 == seal.isolation_policy_sha256
                and observation.baseline_source_sha256 == seal.baseline_source_sha256
                and observation.mutant_source_sha256 == seal.mutant_source_sha256
                and seal.baseline_source_sha256 != seal.mutant_source_sha256
            )
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            if registry.get(key) is seal:
                registry.pop(key, None)
            return None
        return seal

    @contextmanager
    def authority_lease(
        observation: MutationSuiteObservation,
    ) -> Iterator[None]:
        """Hold run and observation authority as one process-local transaction."""

        seal: _MutationObservationAuthoritySeal | None = None
        body_raised = False
        try:
            with revocation_lease.hold():
                with lock:
                    try:
                        seal = registry.get(id(observation))
                        preliminary = valid_local_seal_locked(
                            observation,
                            expected_seal=seal,
                        )
                    except BaseException:
                        if seal is not None and registry.get(id(observation)) is seal:
                            registry.pop(id(observation), None)
                        raise
                if preliminary is None:
                    raise _RevocationLeaseUnavailable(
                        "mutation observation authority is unavailable"
                    )
                seal = preliminary
                with run_authority_lease(seal.baseline_run), run_authority_lease(seal.mutant_run):
                    with lock:
                        entry = valid_local_seal_locked(
                            observation,
                            expected_seal=seal,
                        )
                    if entry is None:
                        raise _RevocationLeaseUnavailable(
                            "mutation observation authority is unavailable"
                        )
                    try:
                        yield
                    except BaseException:
                        body_raised = True
                        try:
                            with lock:
                                valid_local_seal_locked(observation, expected_seal=seal)
                        except BaseException:
                            with suppress(BaseException), lock:
                                if registry.get(id(observation)) is seal:
                                    registry.pop(id(observation), None)
                        raise
                    else:
                        with lock:
                            try:
                                current = valid_local_seal_locked(
                                    observation,
                                    expected_seal=seal,
                                )
                            except BaseException:
                                if registry.get(id(observation)) is seal:
                                    registry.pop(id(observation), None)
                                raise
                        if current is None:
                            raise _RevocationLeaseUnavailable(
                                "mutation observation authority expired during its lease"
                            )
                with lock:
                    try:
                        final = valid_local_seal_locked(
                            observation,
                            expected_seal=seal,
                        )
                    except BaseException:
                        if registry.get(id(observation)) is seal:
                            registry.pop(id(observation), None)
                        raise
                if final is None:
                    raise _RevocationLeaseUnavailable(
                        "mutation observation authority expired during dependency-lease exit"
                    )
        except _RevocationLeaseUnavailable:
            if seal is not None:
                with suppress(BaseException):
                    remove_registered_seal(id(observation), expected_seal=seal)
            raise
        except BaseException:
            if seal is not None and not body_raised:
                with suppress(BaseException):
                    remove_registered_seal(id(observation), expected_seal=seal)
            raise

    def current_seal(
        observation: MutationSuiteObservation,
    ) -> _MutationObservationAuthoritySeal | None:
        try:
            with authority_lease(observation), lock:
                seal = registry.get(id(observation))
        except _RevocationLeaseUnavailable:
            return None
        return seal

    def install(
        observation: MutationSuiteObservation,
        *,
        source: _FoundryMutationRuntimeResult | _MutationObservationAuthoritySeal,
    ) -> _MutationObservationAuthoritySeal | None:
        if (
            current_process_id() != authority_process_id
            or not revocation_lease.is_current_process()
            or type(observation) is not MutationSuiteObservation
        ):
            return None
        if isinstance(source, _FoundryMutationRuntimeResult):
            baseline_run = source.baseline_run
            mutant_run = source.mutant_run
            baseline_binding = source.baseline_binding
            mutant_binding = source.mutant_binding
            runtime_bindings_sha256 = source.runtime_bindings_sha256
            authority_custody = source.authority_custody
        else:
            baseline_run = source.baseline_run
            mutant_run = source.mutant_run
            baseline_binding = source.baseline_binding
            mutant_binding = source.mutant_binding
            runtime_bindings_sha256 = source.runtime_bindings_sha256
            authority_custody = source.authority_custody
        key = id(observation)

        def discard(reference: weakref.ReferenceType[MutationSuiteObservation]) -> None:
            remove_registered_seal(key, expected_reference=reference)

        seal = _MutationObservationAuthoritySeal(
            observation=weakref.ref(observation, discard),
            observation_sha256=_model_sha256(observation),
            baseline_run=baseline_run,
            mutant_run=mutant_run,
            baseline_run_sha256=_model_sha256(baseline_run),
            mutant_run_sha256=_model_sha256(mutant_run),
            baseline_binding=baseline_binding,
            mutant_binding=mutant_binding,
            runtime_bindings_sha256=runtime_bindings_sha256,
            mutation_id=observation.mutation_id,
            suite_selection_sha256=observation.suite_selection_sha256,
            executor_sha256=observation.executor_sha256,
            isolation_policy_sha256=observation.isolation_policy_sha256,
            baseline_source_sha256=observation.baseline_source_sha256,
            mutant_source_sha256=observation.mutant_source_sha256,
            authority_process_id=authority_process_id,
            authority_custody=authority_custody,
        )
        inserted = False
        completed = False
        try:
            with revocation_lease.hold():
                with run_authority_lease(baseline_run), run_authority_lease(mutant_run):
                    try:
                        valid = bool(
                            type(baseline_run) is ScannerRun
                            and type(mutant_run) is ScannerRun
                            and baseline_binding == _run_binding(baseline_run)
                            and mutant_binding == _run_binding(mutant_run)
                            and runtime_bindings_sha256
                            == _runtime_bindings_sha256(baseline_binding, mutant_binding)
                            and observation.executor_sha256 == executor_sha256
                            and observation.isolation_policy_sha256
                            == baseline_binding.execution_environment_sha256
                            and observation.suite_selection_sha256
                            == MutationSuiteObservation.calculate_selection_sha256(
                                list(baseline_binding.logical_test_ids)
                            )
                            and observation.baseline_source_sha256
                            != observation.mutant_source_sha256
                            and _observation_matches_runtime(
                                observation,
                                baseline_run=baseline_run,
                                mutant_run=mutant_run,
                                baseline_binding=baseline_binding,
                                mutant_binding=mutant_binding,
                            )
                        )
                    except (AttributeError, TypeError, ValueError):
                        valid = False
                    if not valid:
                        return None
                    with lock:
                        if key in registry:
                            return None
                        registry[key] = seal
                        inserted = True
                        if valid_local_seal_locked(observation, expected_seal=seal) is None:
                            return None
                with lock:
                    if valid_local_seal_locked(observation, expected_seal=seal) is None:
                        return None
            completed = inserted
            return seal if completed else None
        except _RevocationLeaseUnavailable:
            return None
        finally:
            if inserted and not completed:
                with suppress(BaseException):
                    remove_registered_seal(key, expected_seal=seal)

    def contains(observation: MutationSuiteObservation) -> bool:
        return current_seal(observation) is not None

    def validated_copy(observation: MutationSuiteObservation) -> MutationSuiteObservation:
        normalized = MutationSuiteObservation.model_validate(observation.model_dump(mode="json"))
        installed_seal: _MutationObservationAuthoritySeal | None = None
        completed = False
        try:
            with authority_lease(observation):
                with lock:
                    seal = registry.get(id(observation))
                if seal is not None and normalized.model_dump(
                    mode="json"
                ) == observation.model_dump(mode="json"):
                    installed_seal = install(normalized, source=seal)
            completed = True
        except _RevocationLeaseUnavailable:
            pass
        finally:
            if installed_seal is not None and not completed:
                with suppress(BaseException):
                    remove_registered_seal(id(normalized), expected_seal=installed_seal)
        return normalized

    def execute(
        *,
        baseline_adapter: FoundryForkScanner,
        mutant_adapter: FoundryForkScanner,
        backend: ScannerIsolationBackend,
        timeout_seconds: float,
        expected_tool_version: str,
        expected_tool_sha256: str,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        if current_process_id() != authority_process_id:
            raise FoundryMutationExecutionError(
                "Foundry mutation execution authority cannot cross a process boundary"
            )
        baseline = _exact_workspace(baseline_workspace, label="baseline")
        mutant = _exact_workspace(mutant_workspace, label="mutant")
        if baseline == mutant:
            raise FoundryMutationExecutionError("baseline and mutant workspaces are identical")
        if baseline.parent != mutant.parent:
            raise FoundryMutationExecutionError(
                "baseline and mutant must share one campaign-owned parent"
            )
        parent_stat = baseline.parent.stat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            raise FoundryMutationExecutionError(
                "mutation workspace parent lacks exclusive campaign ownership"
            )
        baseline_sha256 = mutation_repository_sha256(baseline)
        mutant_sha256 = mutation_repository_sha256(mutant)
        if baseline_sha256 == mutant_sha256:
            raise FoundryMutationExecutionError("baseline and mutant source inventories are equal")
        _require_adapter_repository_binding(baseline_adapter, baseline_sha256)
        _require_adapter_repository_binding(mutant_adapter, mutant_sha256)

        execution_root = baseline.parent / f".mmaudit-foundry-mutation-{specification.id}"
        try:
            execution_root.mkdir(mode=0o700)
        except OSError as exc:
            raise FoundryMutationExecutionError(
                "exclusive Foundry mutation artifact root could not be created"
            ) from exc

        def invoke_authorized(
            adapter: FoundryForkScanner,
            workspace: Path,
            private_dir: Path,
        ) -> ScannerRun:
            run = invoke(
                adapter,
                workspace,
                private_dir,
                timeout_seconds,
                backend=backend,
                expected_version=expected_tool_version,
                expected_sha256=expected_tool_sha256,
            )
            if type(run) is not ScannerRun:
                raise FoundryMutationExecutionError(
                    "Foundry mutation execution lacks live host runtime authority"
                )
            try:
                with run_authority_lease(run):
                    pass
            except _RevocationLeaseUnavailable as exc:
                raise FoundryMutationExecutionError(
                    "Foundry mutation execution lacks live host runtime authority"
                ) from exc
            return run

        baseline_run = invoke_authorized(
            baseline_adapter,
            baseline,
            execution_root / "baseline",
        )
        if mutation_repository_sha256(baseline) != baseline_sha256:
            raise FoundryMutationExecutionError("baseline workspace changed during execution")
        baseline_binding, baseline_tests, baseline_population = _validated_run(
            baseline_run,
            workspace_sha256=baseline_sha256,
            expected_tool_version=expected_tool_version,
            expected_tool_sha256=expected_tool_sha256,
        )

        mutant_run = invoke_authorized(
            mutant_adapter,
            mutant,
            execution_root / "mutant",
        )
        if mutation_repository_sha256(mutant) != mutant_sha256:
            raise FoundryMutationExecutionError("mutant workspace changed during execution")
        mutant_binding, mutant_tests, mutant_population = _validated_run(
            mutant_run,
            workspace_sha256=mutant_sha256,
            expected_tool_version=expected_tool_version,
            expected_tool_sha256=expected_tool_sha256,
        )

        _require_same_execution_contract(
            baseline_run,
            mutant_run,
            baseline_population=baseline_population,
            mutant_population=mutant_population,
        )
        try:
            with (
                revocation_lease.hold(),
                run_authority_lease(baseline_run),
                run_authority_lease(mutant_run),
            ):
                pass
        except _RevocationLeaseUnavailable as exc:
            raise FoundryMutationExecutionError(
                "Foundry mutation runtime authority expired before observation issuance"
            ) from exc

        test_ids = [item.test_id for item in baseline_tests]
        isolation_policy_sha256 = baseline_binding.execution_environment_sha256
        observation = MutationSuiteObservation.sealed(
            mutation_id=specification.id,
            baseline_source_sha256=baseline_sha256,
            mutant_source_sha256=mutant_sha256,
            suite_selection_sha256=MutationSuiteObservation.calculate_selection_sha256(test_ids),
            executor_sha256=executor_sha256,
            isolation_policy_sha256=isolation_policy_sha256,
            baseline_execution_evidence=ExecutionEvidenceKind.REAL,
            mutant_execution_evidence=ExecutionEvidenceKind.REAL,
            baseline_isolation_attestation_sha256=(baseline_binding.isolation_attestation_sha256),
            mutant_isolation_attestation_sha256=(mutant_binding.isolation_attestation_sha256),
            baseline_compilation_succeeded=True,
            mutant_compilation_succeeded=True,
            baseline_tests=baseline_tests,
            mutant_tests=mutant_tests,
        )
        result = _FoundryMutationRuntimeResult(
            observation=observation,
            baseline_run=baseline_run,
            mutant_run=mutant_run,
            baseline_binding=baseline_binding,
            mutant_binding=mutant_binding,
            runtime_bindings_sha256=_runtime_bindings_sha256(
                baseline_binding,
                mutant_binding,
            ),
            authority_custody=backend,
        )
        if install(observation, source=result) is None:
            raise FoundryMutationExecutionError(
                "Foundry mutation observation authority could not be issued"
            )
        return observation

    return execute, contains, validated_copy, authority_lease


(
    _execute_host_foundry_mutation,
    has_host_mutation_suite_runtime_authority,
    validated_mutation_suite_observation_copy_preserving_runtime_authority,
    _lease_host_mutation_suite_runtime_authority,
) = _build_mutation_execution_authority(
    _invoke_builtin_foundry_adapter,
    _lease_host_repository_suite_runtime_authority,
    _HOST_REPOSITORY_SUITE_REVOCATION_LEASE,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExactFoundryMutationExecutor:
    """Run baseline and mutant only through the captured built-in Foundry authority."""

    baseline_adapter: FoundryForkScanner
    mutant_adapter: FoundryForkScanner
    backend: ScannerIsolationBackend
    timeout_seconds: float
    expected_tool_version: str
    expected_tool_sha256: str
    _execution_path: _ExecuteMutation = field(
        default=_execute_host_foundry_mutation,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.baseline_adapter) is not FoundryForkScanner
            or type(self.mutant_adapter) is not FoundryForkScanner
            or self.baseline_adapter is self.mutant_adapter
        ):
            raise ValueError("mutation execution requires two exact built-in Foundry adapters")
        if isinstance(self.timeout_seconds, bool) or not 0 < self.timeout_seconds <= 7_200:
            raise ValueError("mutation execution timeout is outside its fixed bound")
        if (
            not self.expected_tool_version
            or len(self.expected_tool_version) > 1_000
            or "\n" in self.expected_tool_version
            or "\r" in self.expected_tool_version
        ):
            raise ValueError("mutation execution requires one safe expected tool version")
        if (
            _SHA256_PATTERN.fullmatch(self.expected_tool_sha256) is None
            or self.expected_tool_sha256 == "0" * 64
        ):
            raise ValueError("mutation expected tool SHA-256 must be nonzero and canonical")

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        """Execute and issue one process-authorized exact observation."""

        return self._execution_path(
            baseline_adapter=self.baseline_adapter,
            mutant_adapter=self.mutant_adapter,
            backend=self.backend,
            timeout_seconds=self.timeout_seconds,
            expected_tool_version=self.expected_tool_version,
            expected_tool_sha256=self.expected_tool_sha256,
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def _exact_workspace(workspace: Path, *, label: str) -> Path:
    try:
        if workspace.is_symlink():
            raise ValueError
        resolved = workspace.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise FoundryMutationExecutionError(f"{label} workspace identity is unavailable") from exc
    if not resolved.is_dir():
        raise FoundryMutationExecutionError(f"{label} workspace is not a directory")
    return resolved


def _require_adapter_repository_binding(
    adapter: FoundryForkScanner,
    workspace_sha256: str,
) -> None:
    expected = adapter.expected_repository_sha256
    if expected is not None and expected != workspace_sha256:
        raise FoundryMutationExecutionError(
            "Foundry adapter repository binding differs from its mutation workspace"
        )


def _selection_projection(run: ScannerRun) -> dict[str, object]:
    selection = run.repository_suite_selection
    if selection is None:
        raise FoundryMutationExecutionError("Foundry run omitted repository suite selection")
    return {
        "profile": selection.profile,
        "repository_exclusion_path": selection.repository_exclusion_path,
        "configuration_sha256": selection.configuration_sha256,
        "candidate_file_count": selection.candidate_file_count,
        "candidate_test_count": selection.candidate_test_count,
        "selected_file_count": selection.selected_file_count,
        "selected_test_count": selection.selected_test_count,
        "omitted_file_count": selection.omitted_file_count,
        "omitted_test_count": selection.omitted_test_count,
        "limit_reached": selection.limit_reached,
        "inventory_kind": selection.inventory_kind.value,
    }


def _execution_environment_projection(run: ScannerRun) -> dict[str, object]:
    policy = run.repository_suite_execution_policy
    if policy is None:
        raise FoundryMutationExecutionError("Foundry run omitted its execution policy")
    return policy.model_dump(mode="json", exclude={"selection_sha256", "policy_sha256"})


def _logical_population(
    run: ScannerRun,
) -> tuple[str, ...]:
    selection = run.repository_suite_selection
    if selection is None:
        raise FoundryMutationExecutionError("Foundry run omitted repository suite selection")
    population = tuple(sorted(_logical_test_identity(item) for item in selection.tests))
    if len(population) != len(set(population)):
        raise FoundryMutationExecutionError("Foundry logical test population is ambiguous")
    return population


def _test_observations(run: ScannerRun) -> list[MutationSuiteTestObservation]:
    selection = run.repository_suite_selection
    if selection is None:
        raise FoundryMutationExecutionError("Foundry run omitted repository suite selection")
    executions = {item.descriptor_sha256: item for item in run.repository_test_executions}
    observations: list[MutationSuiteTestObservation] = []
    for descriptor in selection.tests:
        try:
            execution = executions[descriptor.descriptor_sha256]
        except KeyError as exc:
            raise FoundryMutationExecutionError(
                "Foundry run did not execute every selected logical test"
            ) from exc
        observations.append(
            MutationSuiteTestObservation(
                test_id=canonical_foundry_mutation_test_id(descriptor),
                status=_mutation_status(execution),
            )
        )
    observations.sort(key=lambda item: item.test_id)
    if len({item.test_id for item in observations}) != len(observations):
        raise FoundryMutationExecutionError("Foundry logical test ID collision was rejected")
    return observations


def _mutation_status(execution: RepositoryTestExecution) -> MutationSuiteTestStatus:
    if execution.status is RepositoryTestExecutionStatus.PASSED:
        return MutationSuiteTestStatus.PASSED
    if execution.status in {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }:
        return MutationSuiteTestStatus.FAILED
    if execution.status is RepositoryTestExecutionStatus.TIMED_OUT:
        return MutationSuiteTestStatus.TIMED_OUT
    if execution.status is RepositoryTestExecutionStatus.INVALID_OUTPUT:
        return MutationSuiteTestStatus.INVALID_OUTPUT
    return MutationSuiteTestStatus.UNAVAILABLE


def _validated_run(
    run: ScannerRun,
    *,
    workspace_sha256: str,
    expected_tool_version: str,
    expected_tool_sha256: str,
) -> tuple[
    _FoundryMutationRunBinding,
    list[MutationSuiteTestObservation],
    tuple[str, ...],
]:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    if (
        run.status is not ScannerStatus.SUCCESS
        or run.execution_evidence is not ExecutionEvidenceKind.REAL
        or run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
        or selection is None
        or policy is None
        or selection.repository_sha256 != workspace_sha256
        or not selection.tests
        or run.version != expected_tool_version
        or run.executable_sha256 != expected_tool_sha256
        or policy.tool_version != expected_tool_version
        or policy.tool_sha256 != expected_tool_sha256
        or policy.compiler_version is None
        or policy.compiler_sha256 is None
        or run.isolation_backend != policy.isolation_backend
        or run.isolation_attestation_sha256 != policy.isolation_attestation_sha256
        or len(run.repository_test_executions) != len(selection.tests)
        or any(
            item.status not in _CLASSIFIED_TEST_STATUSES for item in run.repository_test_executions
        )
    ):
        raise FoundryMutationExecutionError(
            "Foundry mutation run is incomplete or lacks exact runtime bindings"
        )
    pre_inventory = run.repository_suite_inventory
    post_inventory = run.repository_suite_post_inventory
    if (
        selection.inventory_kind is not RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
        or pre_inventory is None
        or post_inventory is None
        or pre_inventory.normalized_inventory_sha256 != post_inventory.normalized_inventory_sha256
        or pre_inventory.inventory_record_count != post_inventory.inventory_record_count
        or _inventory_stable_projection(pre_inventory)
        != _inventory_stable_projection(post_inventory)
    ):
        raise FoundryMutationExecutionError(
            "Foundry mutation requires one stable isolated build-info inventory"
        )
    _validated_fork_bindings(run)
    observations = _test_observations(run)
    population = _logical_population(run)
    binding = _run_binding(run)
    if tuple(item.test_id for item in observations) != binding.logical_test_ids:
        raise FoundryMutationExecutionError("Foundry mutation test binding is inconsistent")
    return binding, observations, population


def _inventory_stable_projection(
    inventory: RepositorySuiteInventoryEvidence,
) -> dict[str, object]:
    payload = inventory.model_dump(
        mode="json",
        exclude={"phase", "inventory_sha256"},
    )
    if not isinstance(payload, dict):
        raise FoundryMutationExecutionError("Foundry mutation inventory is not structured")
    return payload


def _validated_fork_bindings(run: ScannerRun) -> None:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    assert selection is not None and policy is not None
    egress = run.fork_rpc_egress
    if egress is None or (
        egress.status is not RepositoryForkEgressStatus.ENFORCED
        or egress.expected_chain_id != policy.chain_id
        or egress.pinned_block_number != policy.block_number
        or egress.pinned_block_hash != policy.block_hash
    ):
        raise FoundryMutationExecutionError("Foundry mutation fork egress binding is invalid")
    scopes = run.repository_test_fork_rpc_scopes
    if len(scopes) != len(selection.tests):
        raise FoundryMutationExecutionError(
            "Foundry mutation run has incomplete per-test fork scope custody"
        )
    if any(
        scope.status is not RepositoryTestForkRpcScopeStatus.VALIDATED
        or scope.expected_chain_id != policy.chain_id
        or scope.pinned_block_number != policy.block_number
        or scope.pinned_block_hash != policy.block_hash
        for scope in scopes
    ):
        raise FoundryMutationExecutionError("Foundry mutation per-test fork binding is invalid")


def _run_binding(run: ScannerRun) -> _FoundryMutationRunBinding:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    if selection is None or policy is None or run.execution_observation_sha256 is None:
        raise ValueError("run lacks mutation binding fields")
    observations = _test_observations(run)
    return _FoundryMutationRunBinding(
        repository_sha256=selection.repository_sha256,
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        logical_test_ids=tuple(item.test_id for item in observations),
        tool_name=policy.tool_name,
        tool_version=policy.tool_version,
        tool_sha256=policy.tool_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        chain_id=policy.chain_id,
        block_number=policy.block_number,
        block_hash=policy.block_hash,
        fuzz_seed=policy.fuzz_seed,
        isolation_backend=policy.isolation_backend,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        execution_policy_sha256=policy.policy_sha256,
        execution_environment_sha256=_canonical_sha256(_execution_environment_projection(run)),
        execution_observation_sha256=run.execution_observation_sha256,
        execution_sha256s=tuple(item.execution_sha256 for item in run.repository_test_executions),
        inventory_sha256=(
            run.repository_suite_inventory.inventory_sha256
            if run.repository_suite_inventory is not None
            else None
        ),
        post_inventory_sha256=(
            run.repository_suite_post_inventory.inventory_sha256
            if run.repository_suite_post_inventory is not None
            else None
        ),
        fork_rpc_egress_sha256=(
            run.fork_rpc_egress.evidence_sha256 if run.fork_rpc_egress is not None else None
        ),
        fork_rpc_scope_evidence_sha256s=tuple(
            item.evidence_sha256 for item in run.repository_test_fork_rpc_scopes
        ),
    )


def _fork_identity_projection(run: ScannerRun) -> dict[str, object] | None:
    egress = run.fork_rpc_egress
    if egress is None:
        return None
    return {
        "status": egress.status.value,
        "state_id": egress.state_id,
        "state_source_sha256": egress.state_source_sha256,
        "expected_chain_id": egress.expected_chain_id,
        "pinned_block_number": egress.pinned_block_number,
        "pinned_block_hash": egress.pinned_block_hash,
        "boundary_kind": egress.boundary_kind,
        "network_scope": egress.network_scope,
        "policy_sha256": egress.policy_sha256,
    }


def _scope_policy_projection(run: ScannerRun) -> tuple[tuple[str, int, int, str], ...]:
    selection = run.repository_suite_selection
    if selection is None:
        raise FoundryMutationExecutionError("Foundry run omitted repository suite selection")
    descriptors = {item.descriptor_sha256: item for item in selection.tests}
    return tuple(
        sorted(
            (
                canonical_foundry_mutation_test_id(descriptors[scope.descriptor_sha256]),
                scope.expected_chain_id,
                scope.pinned_block_number,
                f"{scope.pinned_block_hash}:{scope.bridge_policy_sha256}",
            )
            for scope in run.repository_test_fork_rpc_scopes
        )
    )


def _require_same_execution_contract(
    baseline: ScannerRun,
    mutant: ScannerRun,
    *,
    baseline_population: tuple[str, ...],
    mutant_population: tuple[str, ...],
) -> None:
    if baseline_population != mutant_population:
        raise FoundryMutationExecutionError(
            "baseline and mutant selected different logical test populations"
        )
    if _selection_projection(baseline) != _selection_projection(mutant):
        raise FoundryMutationExecutionError(
            "baseline and mutant selection contracts differ outside source identity"
        )
    if _execution_environment_projection(baseline) != _execution_environment_projection(mutant):
        raise FoundryMutationExecutionError(
            "baseline and mutant tool/compiler/fork/isolation policies differ"
        )
    if _fork_identity_projection(baseline) != _fork_identity_projection(mutant):
        raise FoundryMutationExecutionError("baseline and mutant fork identities differ")
    if _scope_policy_projection(baseline) != _scope_policy_projection(mutant):
        raise FoundryMutationExecutionError("baseline and mutant per-test fork policies differ")


def _runtime_bindings_sha256(
    baseline: _FoundryMutationRunBinding,
    mutant: _FoundryMutationRunBinding,
) -> str:
    return _canonical_sha256(
        {
            "schema_version": "1.0",
            "baseline": asdict(baseline),
            "mutant": asdict(mutant),
        }
    )


def _observation_matches_runtime(
    observation: MutationSuiteObservation,
    *,
    baseline_run: ScannerRun,
    mutant_run: ScannerRun,
    baseline_binding: _FoundryMutationRunBinding,
    mutant_binding: _FoundryMutationRunBinding,
) -> bool:
    baseline_tests = _test_observations(baseline_run)
    mutant_tests = _test_observations(mutant_run)
    return (
        observation.observation_sha256
        == _canonical_sha256(observation.model_dump(mode="json", exclude={"observation_sha256"}))
        and observation.baseline_source_sha256 == baseline_binding.repository_sha256
        and observation.mutant_source_sha256 == mutant_binding.repository_sha256
        and observation.baseline_execution_evidence is ExecutionEvidenceKind.REAL
        and observation.mutant_execution_evidence is ExecutionEvidenceKind.REAL
        and observation.baseline_isolation_attestation_sha256
        == baseline_binding.isolation_attestation_sha256
        and observation.mutant_isolation_attestation_sha256
        == mutant_binding.isolation_attestation_sha256
        and observation.baseline_compilation_succeeded
        and observation.mutant_compilation_succeeded
        and observation.baseline_tests == baseline_tests
        and observation.mutant_tests == mutant_tests
    )


def _build_testing_execution_path(
    *,
    invoke: _InvokeFoundry,
    run_authority_lease: _RunAuthorityLease,
    revocation_lease: _ProcessLocalRevocationLease,
) -> tuple[
    _ExecuteMutation,
    _ContainsObservation,
    _CopyObservation,
    _ObservationAuthorityLease,
]:
    """Create isolated synthetic authority for unit tests without altering production trust."""

    return _build_mutation_execution_authority(
        invoke,
        run_authority_lease,
        revocation_lease,
    )
