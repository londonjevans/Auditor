"""Foundry fork-test adapter for defensive smart-contract probing."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.isolation.container import (
    cleanup_isolation_backend,
    isolation_host_environment,
)
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
    EvidenceStrength,
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    FoundryTestExecutionSummary,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryPhase,
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
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    ScannerWorkspaceCopyCustody,
    ScannerWorkspaceCopyObservation,
    _file_sha256,
    copy_scanner_workspace_with_custody,
    isolated_executable_version,
    make_finding,
    sanitized_scanner_environment,
    scanner_trust_pin_error,
    scanner_workspace_exclusion_path,
    scanner_workspace_sha256,
)
from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    PinnedForkObservation,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryInvalidError,
    FoundryInventoryOverflowError,
    FoundryInventoryRunLimits,
    FoundryInventoryTimeoutError,
    FoundryInventoryUnavailableError,
    run_foundry_test_inventory,
)
from mmaudit.scanners.read_only_rpc import (
    DETERMINISTIC_FORK_GAS_PRICE_WEI,
    ReadOnlyRpcTestScopeSnapshot,
)
from mmaudit.scanners.repository_suite import (
    RepositorySuiteSelectionError,
    select_foundry_repository_suite,
    select_foundry_repository_suite_from_inventory,
)

_MAX_PRIVATE_ARTIFACT_ENTRIES_PER_TEST = 20_000
_MAX_PRIVATE_ARTIFACT_ENTRIES_TOTAL = 100_000
_MAX_PRIVATE_ARTIFACT_BYTES = 100_000_000
_MAX_PRIVATE_ARTIFACT_DIRECTORY_DEPTH = 128
_FOUNDRY_PATH_GLOB_MAGIC = frozenset("*?[]{}!")
_FOUNDRY_HOST_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "CI",
        "CONTAINER_HOST",
        "DOCKER_HOST",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    }
)


class _PrivateArtifactTraversalPurpose(StrEnum):
    """Separate live ceiling monitoring from stable post-exit evidence capture."""

    STRICT_SNAPSHOT = "strict_snapshot"
    LIVE_LIMIT_MONITOR = "live_limit_monitor"


@dataclass(frozen=True)
class _FoundryTestObservation:
    descriptor: RepositorySuiteTestDescriptor
    status: RepositoryTestExecutionStatus
    terminal_detail: str | None
    duration_seconds: float
    command_sha256: str | None
    output_sha256: str | None
    output_bytes: int
    process_exit_code: int | None
    machine_output_validated: bool
    machine_result_sha256: str | None = None
    summary: FoundryTestExecutionSummary | None = None


@dataclass(frozen=True)
class _CapturedPrivateArtifact:
    """Bytes retained from the same descriptor snapshot used by the artifact hash."""

    relative_path: str
    sha256: str
    content: bytes


@dataclass(frozen=True)
class _PrivateArtifactUsage:
    """Bounded identity and resource usage for one private execution tree."""

    entries: int
    bytes: int
    artifact_sha256: str
    captured_files: tuple[_CapturedPrivateArtifact, ...] = ()

    def captured(self, relative_path: str) -> builtins.bytes:
        matches = [
            artifact.content
            for artifact in self.captured_files
            if artifact.relative_path == relative_path
        ]
        if len(matches) != 1:
            raise FoundryInventoryInvalidError(
                "Foundry private artifact snapshot is missing its bound file"
            )
        return matches[0]


class _FoundryForkRpcScopeRecorder(Protocol):
    """Trusted bridge boundary used to account one selected test at a time."""

    def begin_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> None: ...

    def end_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> ReadOnlyRpcTestScopeSnapshot: ...


class _FoundryScopeBoundaryError(RuntimeError):
    """A trusted per-test RPC accounting boundary could not be sealed."""


@dataclass(frozen=True)
class _ScopedFoundryTestOutcome:
    """Keep a test result, its drained RPC scope, and any execution error distinct."""

    result: tuple[_FoundryTestObservation, _PrivateArtifactUsage] | None
    scope: RepositoryTestForkRpcScopeEvidence | None
    error: BaseException | None


@dataclass
class _SuiteArtifactBudget:
    """Charge every generated execution artifact against one suite-wide budget."""

    max_bytes_per_test: int
    max_total_bytes: int
    max_entries_per_test: int = _MAX_PRIVATE_ARTIFACT_ENTRIES_PER_TEST
    max_total_entries: int = _MAX_PRIVATE_ARTIFACT_ENTRIES_TOTAL
    bytes: int = 0
    entries: int = 0

    @property
    def remaining_bytes(self) -> int:
        return self.max_total_bytes - self.bytes

    def charge(
        self,
        usage: _PrivateArtifactUsage,
        *,
        label: str,
        per_test: bool,
    ) -> None:
        if per_test and (
            usage.bytes > self.max_bytes_per_test or usage.entries > self.max_entries_per_test
        ):
            raise FoundryInventoryOverflowError(f"{label} exceeded the per-test artifact ceiling")
        next_bytes = self.bytes + usage.bytes
        next_entries = self.entries + usage.entries
        if next_bytes > self.max_total_bytes or next_entries > self.max_total_entries:
            raise FoundryInventoryOverflowError(
                f"{label} exceeded the suite total artifact ceiling"
            )
        self.bytes = next_bytes
        self.entries = next_entries


class _FoundrySuiteDeadlineExpired(RuntimeError):
    """The single repository-suite wall-clock deadline has expired."""


class _PinnedCompilerUnavailableError(RuntimeError):
    """A required operator-pinned external Solidity compiler is absent."""


def _repository_test_fork_rpc_scope(
    snapshot: ReadOnlyRpcTestScopeSnapshot,
) -> RepositoryTestForkRpcScopeEvidence:
    """Convert one verified bridge snapshot into public endpoint-free evidence."""

    if not isinstance(snapshot, ReadOnlyRpcTestScopeSnapshot) or not snapshot.verify():
        raise ValueError("Foundry fork RPC scope snapshot is not verified bridge evidence")
    return RepositoryTestForkRpcScopeEvidence.sealed(
        schema_version=snapshot.schema_version,
        attempt_binding_sha256=snapshot.attempt_binding_sha256,
        selection_sha256=snapshot.selection_sha256,
        descriptor_sha256=snapshot.descriptor_sha256,
        sequence_index=snapshot.sequence_index,
        bridge_policy_sha256=snapshot.policy_sha256,
        expected_chain_id=snapshot.expected_chain_id,
        pinned_block_number=snapshot.pinned_block_number,
        pinned_block_hash=snapshot.pinned_block_hash,
        status=RepositoryTestForkRpcScopeStatus(snapshot.status),
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
        method_log_sha256=snapshot.method_log_sha256,
        boundary_drained=snapshot.boundary_drained,
        transaction_capable_request_forwarded=False,
        credentials_forwarded=False,
        raw_payloads_retained=False,
        rpc_endpoint_recorded=False,
        bridge_scope_snapshot_sha256=snapshot.snapshot_sha256,
    )


def _execute_foundry_test_with_scope(
    *,
    recorder: _FoundryForkRpcScopeRecorder | None,
    attempt_binding_sha256: str | None,
    selection: RepositorySuiteSelection,
    descriptor: RepositorySuiteTestDescriptor,
    sequence_index: int,
    execute: Callable[[], tuple[_FoundryTestObservation, _PrivateArtifactUsage]],
) -> _ScopedFoundryTestOutcome:
    """Execute exactly one descriptor inside an unconditional drained scope boundary."""

    if (recorder is None) != (attempt_binding_sha256 is None):
        return _ScopedFoundryTestOutcome(
            result=None,
            scope=None,
            error=_FoundryScopeBoundaryError(
                "Foundry fork RPC scope boundary context is incomplete"
            ),
        )
    if recorder is None:
        try:
            return _ScopedFoundryTestOutcome(result=execute(), scope=None, error=None)
        except BaseException as exc:
            return _ScopedFoundryTestOutcome(result=None, scope=None, error=exc)

    assert attempt_binding_sha256 is not None
    try:
        recorder.begin_selected_test_scope(
            attempt_binding_sha256=attempt_binding_sha256,
            selection_sha256=selection.selection_sha256,
            descriptor_sha256=descriptor.descriptor_sha256,
            sequence_index=sequence_index,
        )
    except Exception as exc:
        return _ScopedFoundryTestOutcome(
            result=None,
            scope=None,
            error=_FoundryScopeBoundaryError(
                f"Foundry fork RPC scope boundary begin failed: {type(exc).__name__}"
            ),
        )

    result: tuple[_FoundryTestObservation, _PrivateArtifactUsage] | None = None
    execution_error: BaseException | None = None
    snapshot: ReadOnlyRpcTestScopeSnapshot | None = None
    boundary_error: Exception | None = None
    try:
        result = execute()
    except BaseException as exc:
        execution_error = exc
    finally:
        try:
            snapshot = recorder.end_selected_test_scope(
                attempt_binding_sha256=attempt_binding_sha256,
                selection_sha256=selection.selection_sha256,
                descriptor_sha256=descriptor.descriptor_sha256,
                sequence_index=sequence_index,
            )
        except Exception as exc:
            boundary_error = exc

    if boundary_error is not None:
        return _ScopedFoundryTestOutcome(
            result=None,
            scope=None,
            error=_FoundryScopeBoundaryError(
                f"Foundry fork RPC scope boundary end failed: {type(boundary_error).__name__}"
            ),
        )
    assert snapshot is not None
    try:
        scope = _repository_test_fork_rpc_scope(snapshot)
    except (TypeError, ValueError) as exc:
        return _ScopedFoundryTestOutcome(
            result=None,
            scope=None,
            error=_FoundryScopeBoundaryError(
                f"Foundry fork RPC scope boundary evidence failed: {type(exc).__name__}"
            ),
        )
    return _ScopedFoundryTestOutcome(result=result, scope=scope, error=execution_error)


class FoundryForkScanner(ScannerAdapter):
    """Run existing Foundry audit tests against an explicitly configured fork RPC."""

    name = "foundry_fork"
    executable = "forge"
    finding_exit_codes = frozenset({0, 1})
    max_stdout_bytes = 50_000_000
    max_stderr_bytes = 10_000_000

    def __init__(
        self,
        config: SmartContractsConfig,
        *,
        reproduction: ReproductionConfig | None = None,
        projects: Sequence[SolidityProjectMetadata] = (),
        allow_fork_probing: bool = False,
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
        fork_rpc_url_override: str | None = None,
        fork_rpc_scope_recorder: _FoundryForkRpcScopeRecorder | None = None,
        attempt_binding_sha256: str | None = None,
    ) -> None:
        if (fork_rpc_scope_recorder is None) != (attempt_binding_sha256 is None):
            raise ValueError("Foundry fork RPC scope recorder and attempt binding are all-or-none")
        if attempt_binding_sha256 is not None and (
            re.fullmatch(r"[0-9a-f]{64}", attempt_binding_sha256) is None
            or attempt_binding_sha256 == "0" * 64
        ):
            raise ValueError("Foundry fork RPC attempt binding must be a nonzero SHA-256")
        self.config = config
        self.reproduction = reproduction or ReproductionConfig()
        self.projects = tuple(projects)
        self.allow_fork_probing = allow_fork_probing
        self.expected_repository_sha256 = expected_repository_sha256
        self.repository_exclusion_root = repository_exclusion_root
        self.fork_rpc_url_override = fork_rpc_url_override
        self.fork_rpc_scope_recorder = fork_rpc_scope_recorder
        self.attempt_binding_sha256 = attempt_binding_sha256

    def with_runtime_context(
        self,
        *,
        allow_fork_probing: bool,
        projects: Sequence[SolidityProjectMetadata],
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
        fork_rpc_scope_recorder: _FoundryForkRpcScopeRecorder | None = None,
        attempt_binding_sha256: str | None = None,
    ) -> FoundryForkScanner:
        if fork_rpc_scope_recorder is None and attempt_binding_sha256 is None:
            fork_rpc_scope_recorder = self.fork_rpc_scope_recorder
            attempt_binding_sha256 = self.attempt_binding_sha256
        return FoundryForkScanner(
            self.config,
            reproduction=self.reproduction,
            projects=projects,
            allow_fork_probing=allow_fork_probing,
            expected_repository_sha256=expected_repository_sha256,
            repository_exclusion_root=repository_exclusion_root,
            fork_rpc_url_override=self.fork_rpc_url_override,
            fork_rpc_scope_recorder=fork_rpc_scope_recorder,
            attempt_binding_sha256=attempt_binding_sha256,
        )

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        command = [
            self.executable,
            "test",
            "--fork-url",
            self._fork_rpc_url(),
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--json",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def display_command(self) -> list[str]:
        command = [
            self.executable,
            "test",
            "--fork-url",
            "[REDACTED_FORK_RPC_URL]",
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--json",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        findings: list[ScannerFinding] = []
        for suite_name, suite in _foundry_suites(stdout).items():
            current_path = suite_name.rsplit(":", maxsplit=1)[0]
            test_results = suite["test_results"]
            assert isinstance(test_results, dict)
            for test_signature, result in test_results.items():
                assert isinstance(test_signature, str)
                assert isinstance(result, dict)
                if _foundry_status(result) != "FAIL":
                    continue
                test_name = test_signature.partition("(")[0]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name) is None:
                    raise ValueError("Forge JSON contains an invalid test name")
                location = _find_test_location(root, current_path, test_name)
                raw_reason = result.get("reason")
                reason = _clean_reason(
                    raw_reason
                    if isinstance(raw_reason, str) and raw_reason
                    else "Foundry fork test failed"
                )
                finding = make_finding(
                    root=root,
                    scanner=self.name,
                    rule_id="foundry-fork-test-failure",
                    title=f"Fork reproduction test failed: {test_name}",
                    severity=Severity.HIGH,
                    message=reason,
                    path=current_path,
                    start_line=location[0],
                    end_line=location[1],
                    metadata={
                        "class": "fork_reproduction",
                        "fork_only": True,
                        "test_name": test_name,
                        "fork_rpc_url_env": self.config.fork_rpc_url_env,
                    },
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun:
        workspace_custody_guard: list[ScannerWorkspaceCopyCustody] = []
        primary_error: BaseException | None = None
        try:
            return self._run_repository_suite(
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

    def _run_repository_suite(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None,
        expected_version: str | None,
        expected_sha256: str | None,
        workspace_custody_guard: list[ScannerWorkspaceCopyCustody],
    ) -> ScannerRun:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()
        selection: RepositorySuiteSelection | None = None
        observations: list[_FoundryTestObservation] = []
        test_fork_rpc_scopes: list[RepositoryTestForkRpcScopeEvidence] = []
        fork: PinnedForkObservation | None = None
        executable_sha256: str | None = None
        version: str | None = None
        compiler_version: str | None = None
        compiler_sha256: str | None = None
        execution_policy: RepositorySuiteExecutionPolicy | None = None
        inventory: RepositorySuiteInventoryEvidence | None = None
        post_inventory: RepositorySuiteInventoryEvidence | None = None
        workspace_copy_custody: ScannerWorkspaceCopyCustody | None = None
        compiler_path: Path | None = None
        repository_sha256: str | None = None
        repository_exclusion_root = self.repository_exclusion_root or private_dir
        repository_exclusion_path: str
        total_timeout = min(
            timeout_seconds,
            self.config.max_fork_probe_seconds,
            self.config.repository_suite.total_timeout_seconds,
        )
        per_test_timeout = min(
            total_timeout,
            self.config.repository_suite.per_test_timeout_seconds,
        )
        deadline = monotonic_start + total_timeout
        artifact_budget = _SuiteArtifactBudget(
            max_bytes_per_test=self.config.repository_suite.max_output_bytes_per_test,
            max_total_bytes=self.config.repository_suite.max_total_output_bytes,
        )

        def finish(status: ScannerStatus, error: str | None) -> ScannerRun:
            nonlocal workspace_copy_custody
            custody = workspace_copy_custody
            workspace_copy_custody = None
            return _finalize_foundry_repository_suite(
                root=root,
                private_dir=private_dir,
                backend=backend,
                start=start,
                monotonic_start=monotonic_start,
                deadline=deadline,
                total_timeout_seconds=total_timeout,
                status=status,
                error=error,
                selection=selection,
                observations=observations,
                fork=fork,
                executable_sha256=executable_sha256,
                version=version,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                execution_policy=execution_policy,
                inventory=inventory,
                post_inventory=post_inventory,
                fuzz_seed=self.config.repository_suite.fuzz_seed,
                repository_test_fork_rpc_scopes=test_fork_rpc_scopes,
                repository_suite_workspace_custody=custody,
            )

        if not self.config.enabled:
            return finish(ScannerStatus.SKIPPED, "smart-contract probing disabled by configuration")
        if not (self.allow_fork_probing or self.config.allow_fork_probing):
            return finish(
                ScannerStatus.SKIPPED,
                "fork probing not acknowledged; pass --allow-fork or configure acknowledgement",
            )
        if (
            not self.config.repository_suite.foundry_include_paths
            or not self.config.repository_suite.foundry_include_tests
        ):
            return finish(ScannerStatus.SKIPPED, "Foundry repository-suite selection is disabled")
        if self.repository_exclusion_root is not None and self.expected_repository_sha256 is None:
            return finish(
                ScannerStatus.FAILED,
                "pipeline-frozen repository execution identity is unavailable",
            )
        try:
            repository_exclusion_path = scanner_workspace_exclusion_path(
                root,
                repository_exclusion_root,
            )
            repository_sha256 = scanner_workspace_sha256(
                root,
                repository_exclusion_root,
            )
        except (OSError, ValueError):
            return finish(
                ScannerStatus.FAILED,
                "repository suite could not bind the complete scanner workspace",
            )
        if (
            self.expected_repository_sha256 is not None
            and repository_sha256 != self.expected_repository_sha256
        ):
            return finish(
                ScannerStatus.FAILED,
                "repository execution source differs from the pipeline-frozen identity",
            )
        projects = self.projects or _default_foundry_projects(
            root,
            excluded_root=repository_exclusion_root,
        )
        if not projects:
            return finish(ScannerStatus.SKIPPED, "no Foundry smart-contract project detected")
        try:
            selection = select_foundry_repository_suite(
                root,
                projects,
                self.config,
                private_dir=repository_exclusion_root,
            )
        except RepositorySuiteSelectionError as exc:
            if str(exc) == ("Foundry test inheritance requires isolated inventory reconciliation"):
                pass
            else:
                status = (
                    ScannerStatus.SKIPPED
                    if (
                        self.config.repository_suite.profile == "legacy_audit"
                        and "matched zero tests" in str(exc)
                    )
                    else ScannerStatus.FAILED
                )
                return finish(status, str(exc))
        else:
            if selection.repository_sha256 != repository_sha256:
                return finish(
                    ScannerStatus.FAILED,
                    "repository execution source changed during suite selection",
                )

        if backend is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                "hardened fork-test isolation is unavailable; tests were not executed",
            )
        if getattr(backend, "supports_local_fork_rpc", None) is not True:
            return finish(
                ScannerStatus.UNAVAILABLE,
                f"{backend.name} lacks an explicit configured loopback fork RPC capability; "
                "tests were not executed",
            )
        if (
            isolation_execution_evidence(backend) is not ExecutionEvidenceKind.REAL
            or isolation_attestation_sha256(backend) is None
        ):
            return finish(
                ScannerStatus.UNAVAILABLE,
                "fork-test isolation lacks current process-attested REAL evidence",
            )
        if (
            self.reproduction.expected_chain_id is None
            or self.reproduction.pinned_block_number is None
        ):
            return finish(
                ScannerStatus.FAILED,
                "repository fork-suite execution requires pinned chain ID and block number",
            )

        try:
            rpc_url = self._fork_rpc_url()
            rpc_port = local_fork_rpc_port(rpc_url)
        except ValueError as exc:
            status = (
                ScannerStatus.UNAVAILABLE
                if str(exc) == f"{self.config.fork_rpc_url_env} is not set"
                else ScannerStatus.FAILED
            )
            return finish(status, str(exc))

        try:
            _reject_unsafe_foundry_configuration(
                root,
                excluded_root=repository_exclusion_root,
            )
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            return finish(
                ScannerStatus.FAILED,
                f"unsafe or invalid Foundry configuration: {type(exc).__name__}",
            )

        executable = shutil.which(self.executable)
        if executable is None:
            return finish(ScannerStatus.UNAVAILABLE, "forge is not installed")
        try:
            executable_path = Path(executable).resolve(strict=True)
        except OSError:
            return finish(ScannerStatus.FAILED, "forge executable could not be resolved")
        try:
            executable_path.relative_to(root.resolve(strict=True))
        except ValueError:
            pass
        else:
            return finish(
                ScannerStatus.FAILED,
                "refusing forge executable resolved from inside audited repository",
            )
        try:
            executable_sha256 = _file_sha256(executable_path)
        except OSError:
            return finish(
                ScannerStatus.FAILED,
                "could not hash forge executable",
            )
        try:
            compiler_path, compiler_sha256 = _resolve_pinned_solidity_compiler(
                root,
                self.config,
            )
        except _PinnedCompilerUnavailableError as exc:
            return finish(ScannerStatus.UNAVAILABLE, str(exc))
        except (OSError, ValueError) as exc:
            return finish(
                ScannerStatus.FAILED,
                f"pinned Solidity compiler validation failed: {type(exc).__name__}",
            )

        try:
            fork_timeout = _remaining_deadline_seconds(
                deadline,
                maximum=min(
                    5.0,
                    self.config.repository_suite.per_test_timeout_seconds,
                ),
            )
            fork = observe_pinned_fork_rpc(
                rpc_url,
                expected_chain_id=self.reproduction.expected_chain_id,
                pinned_block_number=self.reproduction.pinned_block_number,
                timeout_seconds=fork_timeout,
            )
            _remaining_deadline_seconds(deadline)
        except _FoundrySuiteDeadlineExpired:
            return finish(
                ScannerStatus.TIMED_OUT,
                f"repository fork suite exceeded {total_timeout:.0f}s total timeout",
            )
        except ForkRpcUnavailableError as exc:
            return finish(ScannerStatus.UNAVAILABLE, str(exc))
        except ForkRpcBindingError as exc:
            return finish(ScannerStatus.FAILED, str(exc))

        workspace = private_dir / "workspace"
        environment = sanitized_scanner_environment(private_dir)
        copied_compiler = private_dir / "toolchain" / "solc"
        try:
            workspace_copy_custody = copy_scanner_workspace_with_custody(
                root,
                workspace,
                repository_exclusion_root,
            )
            workspace_custody_guard.append(workspace_copy_custody)
            if repository_sha256 is None:
                raise ValueError("repository suite workspace identity is absent")
            if (
                workspace_copy_custody.source_inventory_sha256_before != repository_sha256
                or workspace_copy_custody.workspace_inventory_sha256_after_copy != repository_sha256
            ):
                raise ValueError("disposable scanner workspace differs from the selected source")
            version = isolated_executable_version(
                executable_path,
                environment,
                backend,
                workspace,
                private_dir,
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    maximum=15.0,
                ),
            )
            _remaining_deadline_seconds(deadline)
            trust_error = scanner_trust_pin_error(
                version=version,
                executable_sha256=executable_sha256,
                expected_version=expected_version,
                expected_sha256=expected_sha256,
            )
            if trust_error is not None:
                return finish(ScannerStatus.FAILED, trust_error)
            if version is None:
                return finish(
                    ScannerStatus.UNAVAILABLE,
                    "forge version could not be attested before repository execution",
                )
            version = " ".join(version.split())
            if not version or len(version) > 1_000:
                return finish(
                    ScannerStatus.FAILED,
                    "forge version attestation is not bounded printable text",
                )
            assert compiler_path is not None
            observed_compiler_version = isolated_executable_version(
                compiler_path,
                environment,
                backend,
                workspace,
                private_dir,
                timeout_seconds=_remaining_deadline_seconds(
                    deadline,
                    maximum=15.0,
                ),
            )
            _remaining_deadline_seconds(deadline)
            if (
                observed_compiler_version is None
                or self.config.solc_version is None
                or re.search(
                    rf"(?<![0-9.]){re.escape(self.config.solc_version)}(?![0-9.])",
                    observed_compiler_version,
                )
                is None
            ):
                return finish(
                    ScannerStatus.FAILED,
                    "Solidity compiler version does not match the configured trust pin",
                )
            compiler_version = self.config.solc_version
            copied_compiler.parent.mkdir(mode=0o700)
            shutil.copyfile(compiler_path, copied_compiler)
            copied_compiler.chmod(0o500)
            if _file_sha256(copied_compiler) != compiler_sha256:
                raise ValueError("copied Solidity compiler differs from its trust pin")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FoundryInventoryTimeoutError(
                    "repository suite deadline expired before compiler inventory"
                )
            assert repository_sha256 is not None
            assert version is not None
            assert compiler_version is not None
            pre_inventory_result = run_foundry_test_inventory(
                workspace=workspace,
                private_dir=private_dir,
                projects=projects,
                phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
                forge_executable=executable_path,
                copied_solc=copied_compiler,
                repository_sha256=repository_sha256,
                configuration_sha256=self.config.repository_suite.stable_hash(),
                tool_version=version,
                tool_sha256=executable_sha256,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                backend=backend,
                timeout_seconds=min(remaining, per_test_timeout),
                limits=_foundry_inventory_limits(
                    self.config,
                    remaining_total_bytes=artifact_budget.remaining_bytes,
                ),
            )
            inventory = pre_inventory_result.evidence
            pre_inventory_usage = _foundry_inventory_artifact_usage(
                backend=backend,
                private_dir=private_dir,
                phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
                deadline=deadline,
            )
            _validate_inventory_artifact_accounting(
                pre_inventory_result.accounted_output_bytes,
                pre_inventory_result.generated_artifact_bytes,
                pre_inventory_usage,
            )
            artifact_budget.charge(
                pre_inventory_usage,
                label="pre-execution Foundry inventory",
                per_test=False,
            )
            _remaining_deadline_seconds(deadline)
            inventory_records = tuple(
                record
                for project_inventory in inventory.projects
                for record in project_inventory.records
            )
            selection = select_foundry_repository_suite_from_inventory(
                inventory_records,
                self.config,
                repository_sha256=repository_sha256,
                repository_exclusion_path=repository_exclusion_path,
                inventory_sha256=inventory.normalized_inventory_sha256,
            )
            execution_policy = _foundry_execution_policy(
                selection=selection,
                fork=fork,
                forge_version=version,
                forge_sha256=executable_sha256,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                isolation_backend=str(getattr(backend, "name", "")),
                isolation_attestation_sha256=isolation_attestation_sha256(backend),
                fuzz_seed=self.config.repository_suite.fuzz_seed,
                fuzz_runs=self.config.foundry_fuzz_runs,
                invariant_runs=self.config.foundry_invariant_runs,
                per_test_timeout_seconds=per_test_timeout,
                total_timeout_seconds=total_timeout,
                max_output_bytes_per_test=(self.config.repository_suite.max_output_bytes_per_test),
                max_total_output_bytes=self.config.repository_suite.max_total_output_bytes,
            )
        except _FoundrySuiteDeadlineExpired:
            return finish(
                ScannerStatus.TIMED_OUT,
                f"repository fork suite exceeded {total_timeout:.0f}s total timeout",
            )
        except FoundryInventoryUnavailableError as exc:
            return finish(ScannerStatus.UNAVAILABLE, str(exc))
        except FoundryInventoryTimeoutError as exc:
            return finish(ScannerStatus.TIMED_OUT, str(exc))
        except (FoundryInventoryInvalidError, FoundryInventoryOverflowError) as exc:
            return finish(ScannerStatus.FAILED, str(exc))
        except RepositorySuiteSelectionError as exc:
            status = (
                ScannerStatus.SKIPPED
                if (
                    self.config.repository_suite.profile == "legacy_audit"
                    and "matched zero tests" in str(exc)
                )
                else ScannerStatus.FAILED
            )
            return finish(status, str(exc))
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
            return finish(
                ScannerStatus.FAILED,
                f"fork-suite workspace preflight failed: {type(exc).__name__}",
            )

        assert selection is not None
        assert inventory is not None
        assert repository_sha256 is not None
        assert executable_sha256 is not None
        assert version is not None
        assert compiler_version is not None
        assert compiler_sha256 is not None
        terminal_status = ScannerStatus.SUCCESS
        terminal_error: str | None = None
        for index, descriptor in enumerate(selection.tests):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = (
                    f"repository fork suite exceeded {total_timeout:.0f}s total timeout"
                )
                break

            def execute_selected_test(
                descriptor: RepositorySuiteTestDescriptor = descriptor,
                index: int = index,
            ) -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
                return _execute_foundry_test(
                    descriptor=descriptor,
                    selection=selection,
                    workspace=workspace,
                    private_dir=private_dir,
                    output_index=index,
                    executable_path=executable_path,
                    compiler_path=copied_compiler,
                    compiler_sha256=compiler_sha256,
                    rpc_url=rpc_url,
                    rpc_port=rpc_port,
                    fork=fork,
                    fuzz_seed=self.config.repository_suite.fuzz_seed,
                    fuzz_runs=self.config.foundry_fuzz_runs,
                    invariant_runs=self.config.foundry_invariant_runs,
                    deadline=min(deadline, time.monotonic() + per_test_timeout),
                    max_output_bytes=self.config.repository_suite.max_output_bytes_per_test,
                    backend=backend,
                    base_environment=environment,
                )

            outcome = _execute_foundry_test_with_scope(
                recorder=self.fork_rpc_scope_recorder,
                attempt_binding_sha256=self.attempt_binding_sha256,
                selection=selection,
                descriptor=descriptor,
                sequence_index=index + 1,
                execute=execute_selected_test,
            )
            if outcome.scope is not None:
                test_fork_rpc_scopes.append(outcome.scope)
            if isinstance(outcome.error, _FoundryScopeBoundaryError):
                terminal_status = ScannerStatus.FAILED
                terminal_error = str(outcome.error)
                break
            if isinstance(outcome.error, FoundryInventoryUnavailableError):
                terminal_status = ScannerStatus.UNAVAILABLE
                terminal_error = str(outcome.error)
                break
            if isinstance(
                outcome.error,
                (
                    _FoundrySuiteDeadlineExpired,
                    FoundryInventoryTimeoutError,
                    subprocess.TimeoutExpired,
                    TimeoutError,
                ),
            ):
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = "Foundry repository test execution exceeded its deadline"
                break
            if isinstance(
                outcome.error,
                (FoundryInventoryInvalidError, FoundryInventoryOverflowError),
            ):
                terminal_status = ScannerStatus.FAILED
                terminal_error = str(outcome.error)
                break
            if outcome.error is not None:
                if not isinstance(outcome.error, Exception):
                    raise outcome.error
                terminal_status = ScannerStatus.FAILED
                terminal_error = (
                    f"Foundry repository test execution failed: {type(outcome.error).__name__}"
                )
                break
            if outcome.result is None:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "Foundry repository test returned no execution result"
                break
            observation, private_artifacts = outcome.result
            observations.append(observation)
            try:
                artifact_budget.charge(
                    private_artifacts,
                    label=f"Foundry repository test {descriptor.test_name}",
                    per_test=True,
                )
            except FoundryInventoryOverflowError as exc:
                terminal_status = ScannerStatus.FAILED
                terminal_error = str(exc)
                break
            try:
                compiler_unchanged = _file_sha256(copied_compiler) == compiler_sha256
            except OSError:
                compiler_unchanged = False
            if not compiler_unchanged:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "pinned Solidity compiler changed during repository execution"
                break
            if outcome.scope is not None and outcome.scope.status.value != "validated":
                terminal_status = ScannerStatus.FAILED
                terminal_error = (
                    "Foundry repository test lacks validated pinned-origin RPC evidence"
                )
                break
            if observation.status is RepositoryTestExecutionStatus.TIMED_OUT:
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = "one repository fork test exceeded its timeout"
                break
            if observation.status is RepositoryTestExecutionStatus.INVALID_OUTPUT:
                terminal_status = ScannerStatus.FAILED
                terminal_error = observation.terminal_detail
                break
            if observation.status is RepositoryTestExecutionStatus.UNAVAILABLE:
                terminal_status = ScannerStatus.FAILED
                terminal_error = observation.terminal_detail
                break

        if len(observations) != len(selection.tests) and terminal_status is ScannerStatus.SUCCESS:
            terminal_status = ScannerStatus.FAILED
            terminal_error = "repository fork suite did not execute every selected test"
        if (
            self.fork_rpc_scope_recorder is not None
            and terminal_status is ScannerStatus.SUCCESS
            and len(test_fork_rpc_scopes) != len(selection.tests)
        ):
            terminal_status = ScannerStatus.FAILED
            terminal_error = (
                "repository fork suite lacks per-test RPC scope coverage for every selected test"
            )

        remaining = deadline - time.monotonic()
        if terminal_status is not ScannerStatus.TIMED_OUT and remaining > 0:
            try:
                post_inventory_result = run_foundry_test_inventory(
                    workspace=workspace,
                    private_dir=private_dir,
                    projects=projects,
                    phase=RepositorySuiteInventoryPhase.POST_EXECUTION,
                    forge_executable=executable_path,
                    copied_solc=copied_compiler,
                    repository_sha256=repository_sha256,
                    configuration_sha256=self.config.repository_suite.stable_hash(),
                    tool_version=version,
                    tool_sha256=executable_sha256,
                    compiler_version=compiler_version,
                    compiler_sha256=compiler_sha256,
                    backend=backend,
                    timeout_seconds=min(remaining, per_test_timeout),
                    limits=_foundry_inventory_limits(
                        self.config,
                        remaining_total_bytes=artifact_budget.remaining_bytes,
                    ),
                )
                post_inventory = post_inventory_result.evidence
                post_inventory_usage = _foundry_inventory_artifact_usage(
                    backend=backend,
                    private_dir=private_dir,
                    phase=RepositorySuiteInventoryPhase.POST_EXECUTION,
                    deadline=deadline,
                )
                _validate_inventory_artifact_accounting(
                    post_inventory_result.accounted_output_bytes,
                    post_inventory_result.generated_artifact_bytes,
                    post_inventory_usage,
                )
                artifact_budget.charge(
                    post_inventory_usage,
                    label="post-execution Foundry inventory",
                    per_test=False,
                )
                _remaining_deadline_seconds(deadline)
                post_records = tuple(
                    record
                    for project_inventory in post_inventory.projects
                    for record in project_inventory.records
                )
                final_selection = select_foundry_repository_suite_from_inventory(
                    post_records,
                    self.config,
                    repository_sha256=repository_sha256,
                    repository_exclusion_path=repository_exclusion_path,
                    inventory_sha256=post_inventory.normalized_inventory_sha256,
                )
                if final_selection.selection_sha256 != selection.selection_sha256:
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = "repository fork-suite inventory changed during execution"
                if not _foundry_inventory_semantics_match(inventory, post_inventory):
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = (
                        "repository fork-suite compiler evidence changed during execution"
                    )
            except _FoundrySuiteDeadlineExpired:
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = (
                    f"repository fork suite exceeded {total_timeout:.0f}s total timeout"
                )
            except FoundryInventoryUnavailableError as exc:
                terminal_status = ScannerStatus.UNAVAILABLE
                terminal_error = str(exc)
            except FoundryInventoryTimeoutError as exc:
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = str(exc)
            except (
                FoundryInventoryInvalidError,
                FoundryInventoryOverflowError,
                RepositorySuiteSelectionError,
            ) as exc:
                terminal_status = ScannerStatus.FAILED
                terminal_error = str(exc)
        elif post_inventory is None:
            terminal_status = ScannerStatus.TIMED_OUT
            terminal_error = "repository suite deadline expired before post-execution inventory"

        if terminal_status is not ScannerStatus.TIMED_OUT:
            try:
                if not _selection_sources_unchanged(root, selection, deadline=deadline):
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = "repository fork-suite source changed after selection"
                final_fork = observe_pinned_fork_rpc(
                    rpc_url,
                    expected_chain_id=self.reproduction.expected_chain_id,
                    pinned_block_number=self.reproduction.pinned_block_number,
                    timeout_seconds=_remaining_deadline_seconds(
                        deadline,
                        maximum=min(
                            5.0,
                            self.config.repository_suite.per_test_timeout_seconds,
                        ),
                    ),
                )
                _remaining_deadline_seconds(deadline)
                if final_fork != fork:
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = "configured loopback fork state changed during execution"
                workspace_unchanged = (
                    scanner_workspace_sha256(workspace) == selection.repository_sha256
                )
                _remaining_deadline_seconds(deadline)
                if not workspace_unchanged:
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = (
                        "disposable scanner workspace changed during repository execution"
                    )
                repository_unchanged = (
                    scanner_workspace_sha256(root, repository_exclusion_root)
                    == selection.repository_sha256
                )
                _remaining_deadline_seconds(deadline)
                if not repository_unchanged:
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = (
                        "repository execution source changed during repository execution"
                    )
            except _FoundrySuiteDeadlineExpired:
                terminal_status = ScannerStatus.TIMED_OUT
                terminal_error = (
                    f"repository fork suite exceeded {total_timeout:.0f}s total timeout"
                )
            except ForkRpcUnavailableError:
                terminal_status = ScannerStatus.UNAVAILABLE
                terminal_error = "configured loopback fork RPC became unavailable after execution"
            except ForkRpcBindingError:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "configured loopback fork identity changed after execution"
            except (OSError, ValueError):
                terminal_status = ScannerStatus.FAILED
                terminal_error = (
                    "repository or disposable scanner workspace could not be revalidated"
                )
        return finish(terminal_status, terminal_error)

    def _fork_rpc_url(self) -> str:
        """Retain the legacy command-builder interface with strict loopback validation."""

        value = self.fork_rpc_url_override
        if value is None:
            value = os.environ.get(self.config.fork_rpc_url_env, "")
        if not value:
            raise ValueError(f"{self.config.fork_rpc_url_env} is not set")
        try:
            local_fork_rpc_port(value)
        except ForkRpcBindingError as exc:
            raise ValueError(str(exc)) from exc
        return value


def _resolve_pinned_solidity_compiler(
    root: Path,
    config: SmartContractsConfig,
) -> tuple[Path, str]:
    if config.solc_version is None or config.solc_sha256 is None:
        raise _PinnedCompilerUnavailableError(
            "repository fork-suite execution requires pinned Solidity compiler metadata"
        )
    raw_path = os.environ.get(config.solc_executable_env, "")
    if not raw_path:
        raise _PinnedCompilerUnavailableError(f"{config.solc_executable_env} is not set")
    candidate = Path(raw_path)
    if (
        not candidate.is_absolute()
        or candidate.is_symlink()
        or candidate.is_junction()
        or not candidate.is_file()
    ):
        raise ValueError("pinned Solidity compiler must be an absolute regular non-link file")
    metadata = candidate.stat()
    if (
        metadata.st_nlink != 1
        or metadata.st_size > 500_000_000
        or not os.access(candidate, os.X_OK)
    ):
        raise ValueError("pinned Solidity compiler file is unsafe or not executable")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate:
        raise ValueError("pinned Solidity compiler path must already be canonical")
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ValueError("pinned Solidity compiler cannot reside in the audited repository")
    compiler_sha256 = _file_sha256(resolved)
    if compiler_sha256 != config.solc_sha256:
        raise ValueError("Solidity compiler SHA-256 does not match the configured trust pin")
    return resolved, compiler_sha256


def _foundry_execution_policy(
    *,
    selection: RepositorySuiteSelection,
    fork: PinnedForkObservation,
    forge_version: str,
    forge_sha256: str,
    compiler_version: str,
    compiler_sha256: str,
    isolation_backend: str,
    isolation_attestation_sha256: str | None,
    fuzz_seed: str,
    fuzz_runs: int,
    invariant_runs: int,
    per_test_timeout_seconds: float,
    total_timeout_seconds: float,
    max_output_bytes_per_test: int,
    max_total_output_bytes: int,
) -> RepositorySuiteExecutionPolicy:
    if not isolation_backend or isolation_attestation_sha256 is None:
        raise ValueError("Foundry execution policy requires attested isolation")
    return RepositorySuiteExecutionPolicy.sealed(
        selection_configuration_sha256=selection.configuration_sha256,
        selection_sha256=selection.selection_sha256,
        chain_id=fork.chain_id,
        block_number=fork.block_number,
        block_hash=fork.block_hash,
        tool_version=forge_version,
        tool_sha256=forge_sha256,
        compiler_version=compiler_version,
        compiler_sha256=compiler_sha256,
        isolation_backend=isolation_backend,
        isolation_attestation_sha256=isolation_attestation_sha256,
        fuzz_seed=fuzz_seed,
        fuzz_runs=fuzz_runs,
        invariant_runs=invariant_runs,
        per_test_timeout_seconds=per_test_timeout_seconds,
        total_timeout_seconds=total_timeout_seconds,
        max_output_bytes_per_test=max_output_bytes_per_test,
        max_total_output_bytes=max_total_output_bytes,
    )


def _foundry_inventory_semantics_match(
    pre_inventory: RepositorySuiteInventoryEvidence,
    post_inventory: RepositorySuiteInventoryEvidence,
) -> bool:
    stable_fields = (
        "framework",
        "repository_sha256",
        "configuration_sha256",
        "tool_version",
        "tool_sha256",
        "compiler_version",
        "compiler_sha256",
        "isolation_backend",
        "isolation_attestation_sha256",
        "execution_evidence",
        "repository_code_execution",
        "normalized_inventory_sha256",
        "inventory_record_count",
        "safety_claim",
    )
    if any(
        getattr(pre_inventory, field) != getattr(post_inventory, field) for field in stable_fields
    ):
        return False
    pre_projects = tuple(
        (
            project.project_root,
            project.build_info_bundle_sha256,
            project.normalized_build_info_bundle_sha256,
            project.parser_inventory_sha256,
            project.normalized_inventory_sha256,
            tuple(record.record_sha256 for record in project.records),
        )
        for project in pre_inventory.projects
    )
    post_projects = tuple(
        (
            project.project_root,
            project.build_info_bundle_sha256,
            project.normalized_build_info_bundle_sha256,
            project.parser_inventory_sha256,
            project.normalized_inventory_sha256,
            tuple(record.record_sha256 for record in project.records),
        )
        for project in post_inventory.projects
    )
    return pre_projects == post_projects


def _foundry_inventory_limits(
    config: SmartContractsConfig,
    *,
    remaining_total_bytes: int,
) -> FoundryInventoryRunLimits:
    if remaining_total_bytes < 1_024:
        raise FoundryInventoryOverflowError(
            "repository suite has insufficient output budget for compiler inventory"
        )
    stream_ceiling = min(
        config.repository_suite.max_output_bytes_per_test,
        remaining_total_bytes,
    )
    return FoundryInventoryRunLimits(
        max_stdout_bytes_per_project=stream_ceiling,
        max_stderr_bytes_per_project=stream_ceiling,
        max_total_stream_bytes=remaining_total_bytes,
        max_generated_file_bytes=remaining_total_bytes,
        max_generated_bytes_per_project=remaining_total_bytes,
        max_total_generated_bytes=remaining_total_bytes,
        max_combined_output_bytes=remaining_total_bytes,
    )


def _remaining_deadline_seconds(
    deadline: float,
    *,
    maximum: float | None = None,
) -> float:
    """Return only time remaining on the suite deadline, never a fresh allowance."""

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _FoundrySuiteDeadlineExpired
    return min(remaining, maximum) if maximum is not None else remaining


def _foundry_private_generated_root(
    backend: ScannerIsolationBackend,
    private_dir: Path,
) -> Path:
    provider = getattr(backend, "writable_path", None)
    try:
        candidate = Path(provider(private_dir) if callable(provider) else private_dir)
        resolved_private = private_dir.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_private)
    except (OSError, TypeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            "Foundry isolation returned an invalid private artifact root"
        ) from exc
    if resolved.is_symlink() or resolved.is_junction() or not resolved.is_dir():
        raise FoundryInventoryInvalidError(
            "Foundry private artifact root is not a regular directory"
        )
    return resolved


def _foundry_inventory_artifact_usage(
    *,
    backend: ScannerIsolationBackend,
    private_dir: Path,
    phase: RepositorySuiteInventoryPhase,
    deadline: float,
) -> _PrivateArtifactUsage:
    generated_root = _foundry_private_generated_root(backend, private_dir)
    phase_root = generated_root / "repository-suite" / "inventory" / phase.value
    return _private_artifact_usage(
        phase_root,
        deadline=deadline,
        trusted_root=generated_root,
    )


def _validate_inventory_artifact_accounting(
    stream_bytes: int,
    generated_bytes: int,
    observed: _PrivateArtifactUsage,
) -> None:
    if observed.bytes != stream_bytes + generated_bytes:
        raise FoundryInventoryInvalidError(
            "Foundry inventory artifact accounting differs from private outputs"
        )


def _default_foundry_projects(
    root: Path,
    *,
    excluded_root: Path | None = None,
) -> tuple[SolidityProjectMetadata, ...]:
    if not _looks_like_foundry_project(root, excluded_root=excluded_root):
        return ()
    test_directories = [
        name
        for name in ("test", "tests")
        if (
            (root / name).is_dir()
            and not (root / name).is_symlink()
            and not _path_is_within_excluded_root(root / name, excluded_root)
        )
    ]
    if not test_directories:
        return ()
    return (
        SolidityProjectMetadata(
            project_type=SolidityProjectType.FOUNDRY,
            project_root=".",
            test_directories=test_directories,
        ),
    )


def _project_relative_test_path(descriptor: RepositorySuiteTestDescriptor) -> str:
    if descriptor.project_root == ".":
        return descriptor.path
    prefix = f"{descriptor.project_root}/"
    if not descriptor.path.startswith(prefix):
        raise ValueError("selected Foundry test is outside its project root")
    relative = descriptor.path[len(prefix) :]
    if not relative:
        raise ValueError("selected Foundry test path is empty")
    return relative


def _display_foundry_test_command(
    *,
    descriptor: RepositorySuiteTestDescriptor,
    fork: PinnedForkObservation,
    fuzz_seed: str,
    fuzz_runs: int,
    compiler_sha256: str,
) -> list[str]:
    project_relative_path = _project_relative_test_path(descriptor)
    if any(character in _FOUNDRY_PATH_GLOB_MAGIC for character in project_relative_path):
        raise ValueError("selected Foundry test path is not an exact literal path")
    test_pattern = (
        f"^{re.escape(descriptor.declaration_signature)}$"
        if descriptor.declaration_signature is not None
        else rf"^{re.escape(descriptor.test_name)}\([^)]*\)$"
    )
    return [
        "forge",
        "test",
        "--fork-url",
        "[REDACTED_LOOPBACK_FORK_RPC]",
        "--fork-block-number",
        str(fork.block_number),
        "--match-path",
        project_relative_path,
        "--match-contract",
        f"^{re.escape(descriptor.suite_name)}$",
        "--match-test",
        test_pattern,
        "--fuzz-runs",
        str(fuzz_runs),
        "--fuzz-seed",
        fuzz_seed,
        "--gas-price",
        str(DETERMINISTIC_FORK_GAS_PRICE_WEI),
        "--threads",
        "1",
        "--no-storage-caching",
        "--offline",
        "--use",
        f"[PINNED_SOLC_SHA256={compiler_sha256}]",
        "--cache-path",
        "[PRIVATE_CACHE_PATH]",
        "--out",
        "[PRIVATE_OUTPUT_PATH]",
        "--json",
        "-vv",
    ]


def _actual_foundry_test_command(
    display_command: list[str],
    *,
    executable_path: Path,
    rpc_url: str,
    compiler_path: Path,
    compiler_sha256: str,
    cache_path: Path,
    output_path: Path,
) -> list[str]:
    command = list(display_command)
    command[0] = str(executable_path)
    command[command.index("[REDACTED_LOOPBACK_FORK_RPC]")] = rpc_url
    command[command.index(f"[PINNED_SOLC_SHA256={compiler_sha256}]")] = str(compiler_path)
    command[command.index("[PRIVATE_CACHE_PATH]")] = str(cache_path)
    command[command.index("[PRIVATE_OUTPUT_PATH]")] = str(output_path)
    return command


def _canonical_command_sha256(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(
            command,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _private_artifact_open_flags(*, directory: bool = False) -> int:
    """Return fail-closed flags for descriptor-bound private artifact reads."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0:
        raise FoundryInventoryUnavailableError(
            "Foundry private artifacts cannot be hashed safely because no no-follow "
            "open flag is available"
        )
    flags = os.O_RDONLY | no_follow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if not isinstance(directory_flag, int) or directory_flag == 0:
            raise FoundryInventoryUnavailableError(
                "Foundry private artifacts cannot be traversed safely because no directory "
                "open flag is available"
            )
        flags |= directory_flag
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_BINARY", 0))
    return flags


def _private_file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _private_file_snapshot(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _ensure_private_descriptor_noninheritable(descriptor: int, *, label: str) -> None:
    if os.get_inheritable(descriptor):
        os.set_inheritable(descriptor, False)
    if os.get_inheritable(descriptor):
        raise FoundryInventoryInvalidError(f"{label} descriptor is inheritable")


@dataclass
class _PrivateArtifactDirectoryChain:
    """Retained descriptor chain from one trusted private root to an artifact tree."""

    trusted_path: Path
    descriptors: list[int]
    opened: list[os.stat_result]
    names: list[str]

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    @property
    def root_opened(self) -> os.stat_result:
        return self.opened[-1]


def _open_private_artifact_directory(
    path: Path | str,
    *,
    named_before: os.stat_result,
    open_flags: int,
    parent_descriptor: int | None,
    require_stable_snapshot: bool,
) -> tuple[int, os.stat_result]:
    """Open one directory without following its name and bind it to its prior stat."""

    if not stat.S_ISDIR(named_before.st_mode) or stat.S_ISLNK(named_before.st_mode):
        raise FoundryInventoryInvalidError(
            "Foundry private artifact directory is not a non-link directory"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, open_flags, dir_fd=parent_descriptor)
        _ensure_private_descriptor_noninheritable(
            descriptor,
            label="Foundry private artifact directory",
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or _private_file_identity(named_before) != _private_file_identity(opened)
            or (
                require_stable_snapshot
                and _private_file_snapshot(named_before) != _private_file_snapshot(opened)
            )
        ):
            raise FoundryInventoryInvalidError(
                "Foundry private artifact directory changed before it was traversed"
            )
        return descriptor, opened
    except FoundryInventoryInvalidError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise FoundryInventoryInvalidError(
            "Foundry private artifact directory could not be opened safely"
        ) from exc


def _open_private_artifact_tree(
    root: Path,
    *,
    trusted_root: Path,
    open_flags: int,
    require_stable_snapshot: bool,
) -> _PrivateArtifactDirectoryChain:
    """Open every target component relative to one retained trusted-root descriptor."""

    trusted_path = Path(os.path.abspath(trusted_root))
    target_path = Path(os.path.abspath(root))
    try:
        relative = target_path.relative_to(trusted_path)
    except ValueError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact tree lies outside its trusted root"
        ) from exc
    parts = relative.parts
    if any(part in {"", ".", ".."} or "/" in part or "\x00" in part for part in parts):
        raise FoundryInventoryInvalidError(
            "Foundry private artifact tree has an invalid relative path"
        )

    try:
        trusted_metadata = trusted_path.lstat()
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact trusted root is unavailable"
        ) from exc
    trusted_descriptor, trusted_opened = _open_private_artifact_directory(
        trusted_path,
        named_before=trusted_metadata,
        open_flags=open_flags,
        parent_descriptor=None,
        require_stable_snapshot=require_stable_snapshot,
    )
    chain = _PrivateArtifactDirectoryChain(
        trusted_path=trusted_path,
        descriptors=[trusted_descriptor],
        opened=[trusted_opened],
        names=[],
    )
    try:
        for part in parts:
            parent_descriptor = chain.descriptors[-1]
            metadata = os.stat(
                part,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            descriptor, opened = _open_private_artifact_directory(
                part,
                named_before=metadata,
                open_flags=open_flags,
                parent_descriptor=parent_descriptor,
                require_stable_snapshot=require_stable_snapshot,
            )
            chain.names.append(part)
            chain.descriptors.append(descriptor)
            chain.opened.append(opened)
        return chain
    except BaseException:
        _close_private_artifact_chain(chain, validate=False)
        raise


def _validate_private_artifact_chain(
    chain: _PrivateArtifactDirectoryChain,
    *,
    require_stable_snapshot: bool,
) -> None:
    _validate_private_artifact_directory(
        chain.descriptors[0],
        chain.opened[0],
        path=chain.trusted_path,
        parent_descriptor=None,
        require_stable_snapshot=require_stable_snapshot,
    )
    for index, name in enumerate(chain.names, start=1):
        _validate_private_artifact_directory(
            chain.descriptors[index],
            chain.opened[index],
            path=name,
            parent_descriptor=chain.descriptors[index - 1],
            require_stable_snapshot=require_stable_snapshot,
        )


def _close_private_artifact_chain(
    chain: _PrivateArtifactDirectoryChain,
    *,
    validate: bool,
    require_stable_snapshot: bool = True,
) -> None:
    pending_error: BaseException | None = None
    if validate:
        try:
            _validate_private_artifact_chain(
                chain,
                require_stable_snapshot=require_stable_snapshot,
            )
        except BaseException as exc:
            pending_error = exc
    for descriptor in reversed(chain.descriptors):
        try:
            _close_private_artifact_descriptor(
                descriptor,
                label="Foundry private artifact directory chain",
            )
        except BaseException as exc:
            if pending_error is None:
                pending_error = exc
    if pending_error is not None:
        raise pending_error


def _validate_private_artifact_directory(
    descriptor: int,
    opened_before: os.stat_result,
    *,
    path: Path | str,
    parent_descriptor: int | None,
    require_stable_snapshot: bool,
) -> None:
    """Verify the opened directory and its final name still identify one snapshot."""

    try:
        opened_after = os.fstat(descriptor)
        named_after = (
            Path(path).lstat()
            if parent_descriptor is None
            else os.stat(path, dir_fd=parent_descriptor, follow_symlinks=False)
        )
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact directory changed while it was traversed"
        ) from exc
    if (
        not stat.S_ISDIR(opened_after.st_mode)
        or not stat.S_ISDIR(named_after.st_mode)
        or stat.S_ISLNK(named_after.st_mode)
        or _private_file_identity(opened_before) != _private_file_identity(opened_after)
        or _private_file_identity(opened_after) != _private_file_identity(named_after)
        or (
            require_stable_snapshot
            and (
                _private_file_snapshot(opened_before) != _private_file_snapshot(opened_after)
                or _private_file_snapshot(opened_after) != _private_file_snapshot(named_after)
            )
        )
    ):
        raise FoundryInventoryInvalidError(
            "Foundry private artifact directory changed while it was traversed"
        )


def _close_private_artifact_descriptor(descriptor: int, *, label: str) -> None:
    try:
        os.close(descriptor)
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} descriptor could not be closed") from exc


def _private_artifact_file_sha256(
    name: str,
    *,
    directory_descriptor: int,
    named_before: os.stat_result,
    open_flags: int,
    maximum_bytes: int,
    deadline: float | None = None,
    capture_content: bool = False,
) -> tuple[str, bytes | None]:
    """Hash one bounded regular file through a single no-follow descriptor."""

    if deadline is not None:
        _remaining_deadline_seconds(deadline)
    if (
        not stat.S_ISREG(named_before.st_mode)
        or stat.S_ISLNK(named_before.st_mode)
        or named_before.st_nlink != 1
    ):
        raise FoundryInventoryInvalidError("Foundry private artifact is not a unique regular file")
    if named_before.st_size > maximum_bytes:
        raise FoundryInventoryOverflowError(
            "Foundry private artifact exceeded the absolute file ceiling"
        )

    descriptor: int | None = None
    try:
        descriptor = os.open(name, open_flags, dir_fd=directory_descriptor)
        _ensure_private_descriptor_noninheritable(
            descriptor,
            label="Foundry private artifact",
        )
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _private_file_identity(named_before) != _private_file_identity(opened_before)
            or _private_file_snapshot(named_before) != _private_file_snapshot(opened_before)
        ):
            raise FoundryInventoryInvalidError(
                "Foundry private artifact changed before it was hashed"
            )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)

        digest = hashlib.sha256()
        consumed = 0
        captured: list[bytes] | None = [] if capture_content else None
        while True:
            if deadline is not None:
                _remaining_deadline_seconds(deadline)
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes - consumed + 1),
            )
            if not chunk:
                break
            digest.update(chunk)
            if captured is not None:
                captured.append(chunk)
            consumed += len(chunk)
            if deadline is not None:
                _remaining_deadline_seconds(deadline)
            if consumed > maximum_bytes:
                raise FoundryInventoryOverflowError(
                    "Foundry private artifact exceeded the absolute file ceiling"
                )

        opened_after = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _private_file_snapshot(opened_before) != _private_file_snapshot(opened_after)
            or _private_file_identity(opened_after) != _private_file_identity(named_after)
            or _private_file_snapshot(opened_after) != _private_file_snapshot(named_after)
            or not stat.S_ISREG(named_after.st_mode)
            or stat.S_ISLNK(named_after.st_mode)
            or named_after.st_nlink != 1
            or consumed != opened_before.st_size
        ):
            raise FoundryInventoryInvalidError(
                "Foundry private artifact changed while it was hashed"
            )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        return digest.hexdigest(), (b"".join(captured) if captured is not None else None)
    except (
        FoundryInventoryInvalidError,
        FoundryInventoryOverflowError,
        FoundryInventoryUnavailableError,
    ):
        raise
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact could not be hashed safely"
        ) from exc
    finally:
        if descriptor is not None:
            _close_private_artifact_descriptor(
                descriptor,
                label="Foundry private artifact",
            )


def _private_artifact_live_file_size(
    name: str,
    *,
    directory_descriptor: int,
    named_before: os.stat_result,
    open_flags: int,
) -> int:
    """Observe one live file without following names or requiring stable size/timestamps."""

    if (
        not stat.S_ISREG(named_before.st_mode)
        or stat.S_ISLNK(named_before.st_mode)
        or named_before.st_nlink != 1
    ):
        raise FoundryInventoryInvalidError("Foundry private artifact is not a unique regular file")
    descriptor: int | None = None
    try:
        descriptor = os.open(name, open_flags, dir_fd=directory_descriptor)
        _ensure_private_descriptor_noninheritable(
            descriptor,
            label="Foundry private artifact",
        )
        opened_before = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        opened_after = os.fstat(descriptor)
        observed = (named_before, opened_before, opened_after, named_after)
        if (
            any(
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                for metadata in observed
            )
            or len({_private_file_identity(metadata) for metadata in observed}) != 1
        ):
            raise FoundryInventoryInvalidError(
                "Foundry private artifact changed while it was monitored"
            )
        return max(metadata.st_size for metadata in observed)
    except (
        FoundryInventoryInvalidError,
        FoundryInventoryOverflowError,
        FoundryInventoryUnavailableError,
    ):
        raise
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact could not be monitored safely"
        ) from exc
    finally:
        if descriptor is not None:
            _close_private_artifact_descriptor(
                descriptor,
                label="Foundry private artifact",
            )


def _private_artifact_usage(
    root: Path,
    *,
    hash_contents: bool = True,
    deadline: float | None = None,
    trusted_root: Path | None = None,
    capture_relative_paths: frozenset[str] = frozenset(),
    purpose: _PrivateArtifactTraversalPurpose = (_PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT),
) -> _PrivateArtifactUsage:
    """Enumerate one generated tree without following links or ignoring cache artifacts."""

    if deadline is not None:
        _remaining_deadline_seconds(deadline)
    if not isinstance(purpose, _PrivateArtifactTraversalPurpose):
        raise FoundryInventoryInvalidError("Foundry private artifact traversal purpose is invalid")
    require_stable_snapshot = purpose is _PrivateArtifactTraversalPurpose.STRICT_SNAPSHOT
    if not require_stable_snapshot and (hash_contents or capture_relative_paths):
        raise FoundryInventoryInvalidError(
            "live Foundry artifact monitoring cannot produce content evidence"
        )
    directory_open_flags = _private_artifact_open_flags(directory=True)
    file_open_flags = _private_artifact_open_flags()
    if capture_relative_paths and not hash_contents:
        raise FoundryInventoryInvalidError(
            "Foundry private artifact capture requires content hashing"
        )
    if any(
        not relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
        for relative in capture_relative_paths
    ):
        raise FoundryInventoryInvalidError("Foundry private artifact capture path is invalid")

    entries = 0
    total_bytes = 0
    bindings: list[dict[str, str | int | None]] = []
    captured_files: list[_CapturedPrivateArtifact] = []
    chain = _open_private_artifact_tree(
        root,
        trusted_root=trusted_root or root,
        open_flags=directory_open_flags,
        require_stable_snapshot=require_stable_snapshot,
    )
    root_descriptor = chain.descriptor
    root_opened = chain.root_opened

    def walk_directory(
        directory_descriptor: int,
        opened_before: os.stat_result,
        *,
        relative_prefix: str,
        depth: int,
    ) -> None:
        nonlocal entries, total_bytes
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        if depth > _MAX_PRIVATE_ARTIFACT_DIRECTORY_DEPTH:
            raise FoundryInventoryOverflowError(
                "Foundry private artifacts exceeded the directory-depth ceiling"
            )
        try:
            current = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or _private_file_identity(opened_before) != _private_file_identity(current)
                or (
                    require_stable_snapshot
                    and _private_file_snapshot(opened_before) != _private_file_snapshot(current)
                )
            ):
                raise FoundryInventoryInvalidError(
                    "Foundry private artifact directory changed before it was traversed"
                )
            with os.scandir(directory_descriptor) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
                for child in children:
                    if deadline is not None:
                        _remaining_deadline_seconds(deadline)
                    entries += 1
                    if entries > _MAX_PRIVATE_ARTIFACT_ENTRIES_TOTAL:
                        raise FoundryInventoryOverflowError(
                            "Foundry private artifacts exceeded the absolute entry ceiling"
                        )
                    name = child.name
                    relative = name if not relative_prefix else f"{relative_prefix}/{name}"
                    if (
                        not relative
                        or len(relative) > 4_000
                        or any(
                            ord(character) < 32 or ord(character) == 127 for character in relative
                        )
                    ):
                        raise FoundryInventoryInvalidError(
                            "Foundry private artifact path is not bounded printable text"
                        )
                    metadata = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISDIR(metadata.st_mode):
                        bindings.append({"kind": "directory", "path": relative})
                        child_descriptor, child_opened = _open_private_artifact_directory(
                            name,
                            named_before=metadata,
                            open_flags=directory_open_flags,
                            parent_descriptor=directory_descriptor,
                            require_stable_snapshot=require_stable_snapshot,
                        )
                        try:
                            walk_directory(
                                child_descriptor,
                                child_opened,
                                relative_prefix=relative,
                                depth=depth + 1,
                            )
                            _validate_private_artifact_directory(
                                child_descriptor,
                                child_opened,
                                path=name,
                                parent_descriptor=directory_descriptor,
                                require_stable_snapshot=require_stable_snapshot,
                            )
                            if deadline is not None:
                                _remaining_deadline_seconds(deadline)
                        finally:
                            _close_private_artifact_descriptor(
                                child_descriptor,
                                label="Foundry private artifact directory",
                            )
                        continue
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or stat.S_ISLNK(metadata.st_mode)
                    ):
                        raise FoundryInventoryInvalidError(
                            "Foundry private artifact is not a unique regular file"
                        )
                    observed_size = metadata.st_size
                    if not hash_contents:
                        observed_size = _private_artifact_live_file_size(
                            name,
                            directory_descriptor=directory_descriptor,
                            named_before=metadata,
                            open_flags=file_open_flags,
                        )
                    if observed_size > _MAX_PRIVATE_ARTIFACT_BYTES:
                        raise FoundryInventoryOverflowError(
                            "Foundry private artifact exceeded the absolute file ceiling"
                        )
                    total_bytes += observed_size
                    if total_bytes > _MAX_PRIVATE_ARTIFACT_BYTES:
                        raise FoundryInventoryOverflowError(
                            "Foundry private artifacts exceeded the absolute byte ceiling"
                        )
                    digest: str | None = None
                    if hash_contents:
                        digest, captured = _private_artifact_file_sha256(
                            name,
                            directory_descriptor=directory_descriptor,
                            named_before=metadata,
                            open_flags=file_open_flags,
                            maximum_bytes=_MAX_PRIVATE_ARTIFACT_BYTES,
                            deadline=deadline,
                            capture_content=relative in capture_relative_paths,
                        )
                        if captured is not None:
                            captured_files.append(
                                _CapturedPrivateArtifact(
                                    relative_path=relative,
                                    sha256=digest,
                                    content=captured,
                                )
                            )
                    bindings.append(
                        {
                            "kind": "file",
                            "path": relative,
                            "bytes": observed_size,
                            "sha256": digest,
                        }
                    )
        except (
            FoundryInventoryInvalidError,
            FoundryInventoryOverflowError,
            FoundryInventoryUnavailableError,
        ):
            raise
        except (OSError, TypeError) as exc:
            raise FoundryInventoryInvalidError(
                "Foundry private artifact tree could not be enumerated"
            ) from exc

    try:
        walk_directory(
            root_descriptor,
            root_opened,
            relative_prefix="",
            depth=0,
        )
        _validate_private_artifact_chain(
            chain,
            require_stable_snapshot=require_stable_snapshot,
        )
        if {artifact.relative_path for artifact in captured_files} != set(capture_relative_paths):
            raise FoundryInventoryInvalidError("Foundry private artifact capture is incomplete")
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
    finally:
        _close_private_artifact_chain(chain, validate=False)

    bindings.sort(key=lambda item: str(item["path"]))
    payload = {
        "schema_version": "1.0",
        "entries": entries,
        "bytes": total_bytes,
        "artifacts": bindings,
    }
    artifact_sha256 = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return _PrivateArtifactUsage(
        entries=entries,
        bytes=total_bytes,
        artifact_sha256=artifact_sha256,
        captured_files=tuple(sorted(captured_files, key=lambda artifact: artifact.relative_path)),
    )


def _invalid_private_artifact_usage() -> _PrivateArtifactUsage:
    payload = {
        "schema_version": "1.0",
        "entries": 1,
        "bytes": 0,
        "artifacts": [
            {
                "kind": "invalid_artifact_tree",
                "path": "[UNAVAILABLE]",
                "bytes": 0,
                "sha256": None,
            }
        ],
    }
    return _PrivateArtifactUsage(
        entries=1,
        bytes=0,
        artifact_sha256=hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
    )


def _bounded_stream_artifact_usage(
    stdout_path: Path,
    stderr_path: Path,
    *,
    deadline: float | None = None,
    trusted_root: Path | None = None,
) -> _PrivateArtifactUsage:
    """Retain bounded stream evidence when the wider artifact tree is invalid."""

    bindings: list[dict[str, str | int | None]] = []
    captured_files: list[_CapturedPrivateArtifact] = []
    total_bytes = 0
    chain: _PrivateArtifactDirectoryChain | None = None
    invalid = False
    try:
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        if stdout_path.parent != stderr_path.parent:
            raise FoundryInventoryInvalidError(
                "Foundry stream evidence does not share one private directory"
            )
        directory_open_flags = _private_artifact_open_flags(directory=True)
        file_open_flags = _private_artifact_open_flags()
        chain = _open_private_artifact_tree(
            stdout_path.parent,
            trusted_root=trusted_root or stdout_path.parent,
            open_flags=directory_open_flags,
            require_stable_snapshot=True,
        )
        directory_descriptor = chain.descriptor
        for label, path in (("stdout.json", stdout_path), ("stderr.txt", stderr_path)):
            metadata = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_PRIVATE_ARTIFACT_BYTES
            ):
                raise OSError("unsafe stream evidence")
            total_bytes += metadata.st_size
            if total_bytes > _MAX_PRIVATE_ARTIFACT_BYTES:
                raise OSError("oversized stream evidence")
            digest, captured = _private_artifact_file_sha256(
                path.name,
                directory_descriptor=directory_descriptor,
                named_before=metadata,
                open_flags=file_open_flags,
                maximum_bytes=_MAX_PRIVATE_ARTIFACT_BYTES,
                deadline=deadline,
                capture_content=label == "stdout.json",
            )
            bindings.append(
                {
                    "kind": "file",
                    "path": label,
                    "bytes": metadata.st_size,
                    "sha256": digest,
                }
            )
            if captured is not None:
                captured_files.append(
                    _CapturedPrivateArtifact(
                        relative_path=label,
                        sha256=digest,
                        content=captured,
                    )
                )
        _validate_private_artifact_chain(
            chain,
            require_stable_snapshot=True,
        )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
    except (
        OSError,
        FoundryInventoryInvalidError,
        FoundryInventoryOverflowError,
        FoundryInventoryUnavailableError,
    ):
        invalid = True
    finally:
        if chain is not None:
            try:
                _close_private_artifact_chain(chain, validate=False)
            except FoundryInventoryInvalidError:
                invalid = True
    if invalid:
        return _invalid_private_artifact_usage()
    payload = {
        "schema_version": "1.0",
        "entries": len(bindings),
        "bytes": total_bytes,
        "artifacts": bindings,
    }
    return _PrivateArtifactUsage(
        entries=len(bindings),
        bytes=total_bytes,
        artifact_sha256=hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
        captured_files=tuple(captured_files),
    )


def _execute_foundry_test(
    *,
    descriptor: RepositorySuiteTestDescriptor,
    selection: RepositorySuiteSelection,
    workspace: Path,
    private_dir: Path,
    output_index: int,
    executable_path: Path,
    compiler_path: Path,
    compiler_sha256: str,
    rpc_url: str,
    rpc_port: int,
    fork: PinnedForkObservation,
    fuzz_seed: str,
    fuzz_runs: int,
    invariant_runs: int,
    deadline: float,
    max_output_bytes: int,
    backend: ScannerIsolationBackend,
    base_environment: dict[str, str],
) -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
    del selection
    started = time.monotonic()
    generated_root = _foundry_private_generated_root(backend, private_dir)
    execution_dir = generated_root / "repository-suite" / "tests" / f"{output_index:05d}"
    execution_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    raw_path = execution_dir / "stdout.json"
    error_path = execution_dir / "stderr.txt"
    cache_path = execution_dir / "cache"
    output_path = execution_dir / "out"
    project_path = (
        workspace
        if descriptor.project_root == "."
        else workspace.joinpath(*PurePosixPath(descriptor.project_root).parts)
    )
    try:
        project_path.resolve(strict=True).relative_to(workspace.resolve(strict=True))
    except (OSError, ValueError):
        return (
            _invalid_foundry_observation(
                descriptor,
                started,
                "selected Foundry project root is unavailable in the disposable workspace",
            ),
            _private_artifact_usage(
                execution_dir,
                deadline=deadline,
                trusted_root=generated_root,
            ),
        )
    display_command = _display_foundry_test_command(
        descriptor=descriptor,
        fork=fork,
        fuzz_seed=fuzz_seed,
        fuzz_runs=fuzz_runs,
        compiler_sha256=compiler_sha256,
    )
    command_sha256 = _canonical_command_sha256(display_command)
    command = _actual_foundry_test_command(
        display_command,
        executable_path=executable_path,
        rpc_url=rpc_url,
        compiler_path=compiler_path,
        compiler_sha256=compiler_sha256,
        cache_path=cache_path,
        output_path=output_path,
    )
    try:
        wrapped_command = backend.wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )
        environment = isolation_host_environment(
            backend,
            private_dir,
            base_environment,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return (
            _invalid_foundry_observation(
                descriptor,
                started,
                f"fork-test isolation setup failed: {type(exc).__name__}",
                command_sha256=command_sha256,
            ),
            _private_artifact_usage(
                execution_dir,
                deadline=deadline,
                trusted_root=generated_root,
            ),
        )
    environment = {
        name: value
        for name, value in environment.items()
        if name in _FOUNDRY_HOST_ENVIRONMENT_ALLOWLIST
    }
    environment.update(
        {
            "ETH_RPC_URL": rpc_url,
            "FOUNDRY_FFI": "false",
            "FOUNDRY_FS_PERMISSIONS": "[]",
            "FOUNDRY_INVARIANT_RUNS": str(invariant_runs),
            "FOUNDRY_NO_STORAGE_CACHING": "true",
            "FOUNDRY_PROFILE": "default",
        }
    )
    timed_out = False
    output_exceeded = False
    return_code: int | None = None
    process: subprocess.Popen[bytes] | None = None
    process_error: str | None = None
    artifact_error: str | None = None
    try:
        with raw_path.open("wb") as stdout_handle, error_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                wrapped_command,
                cwd=project_path,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=environment,
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=(
                    int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                    if os.name == "nt"
                    else 0
                ),
                preexec_fn=_limit_process if os.name != "nt" else None,
            )
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    _stop_process(process, deadline=deadline)
                    break
                try:
                    current_usage = _private_artifact_usage(
                        execution_dir,
                        hash_contents=False,
                        deadline=deadline,
                        trusted_root=generated_root,
                        purpose=(_PrivateArtifactTraversalPurpose.LIVE_LIMIT_MONITOR),
                    )
                except _FoundrySuiteDeadlineExpired:
                    timed_out = True
                    _stop_process(process, deadline=deadline)
                    break
                except (
                    FoundryInventoryInvalidError,
                    FoundryInventoryOverflowError,
                    FoundryInventoryUnavailableError,
                ) as exc:
                    artifact_error = str(exc)
                    _stop_process(process, deadline=deadline)
                    break
                if (
                    current_usage.bytes > max_output_bytes
                    or current_usage.entries > _MAX_PRIVATE_ARTIFACT_ENTRIES_PER_TEST
                ):
                    output_exceeded = True
                    _stop_process(process, deadline=deadline)
                    break
                time.sleep(0.05)
            return_code = process.wait(timeout=max(0.0, min(0.1, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            _stop_process(process, deadline=deadline)
            return_code = process.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        process_error = f"fork-test process failed: {type(exc).__name__}"

    def timed_out_result(
        artifact_usage: _PrivateArtifactUsage | None = None,
    ) -> tuple[_FoundryTestObservation, _PrivateArtifactUsage]:
        usage = artifact_usage or _invalid_private_artifact_usage()
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.TIMED_OUT,
                terminal_detail="Foundry repository test exceeded its fixed timeout",
                duration_seconds=time.monotonic() - started,
                command_sha256=command_sha256,
                output_sha256=usage.artifact_sha256,
                output_bytes=usage.bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            usage,
        )

    cleanup_error = _cleanup_error(backend, private_dir)
    if timed_out or time.monotonic() >= deadline:
        return timed_out_result()
    try:
        try:
            artifact_usage = _private_artifact_usage(
                execution_dir,
                deadline=deadline,
                trusted_root=generated_root,
                capture_relative_paths=frozenset({"stdout.json"}),
            )
        except (
            FoundryInventoryInvalidError,
            FoundryInventoryOverflowError,
            FoundryInventoryUnavailableError,
        ) as exc:
            artifact_error = artifact_error or str(exc)
            artifact_usage = _bounded_stream_artifact_usage(
                raw_path,
                error_path,
                deadline=deadline,
                trusted_root=generated_root,
            )
        _remaining_deadline_seconds(deadline)
    except _FoundrySuiteDeadlineExpired:
        return timed_out_result()
    output_bytes = artifact_usage.bytes
    output_sha256 = artifact_usage.artifact_sha256
    if cleanup_error or process_error or artifact_error:
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail=cleanup_error or process_error or artifact_error,
                duration_seconds=time.monotonic() - started,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            artifact_usage,
        )
    if (
        output_exceeded
        or output_bytes > max_output_bytes
        or artifact_usage.entries > _MAX_PRIVATE_ARTIFACT_ENTRIES_PER_TEST
    ):
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail="Foundry repository test exceeded its artifact ceiling",
                duration_seconds=time.monotonic() - started,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            artifact_usage,
        )
    try:
        _remaining_deadline_seconds(deadline)
        stdout = artifact_usage.captured("stdout.json").decode("utf-8")
        _remaining_deadline_seconds(deadline)
        precondition_error = _foundry_machine_result_precondition(
            return_code=return_code,
            stdout=stdout,
        )
        _remaining_deadline_seconds(deadline)
        if precondition_error is not None:
            return (
                _FoundryTestObservation(
                    descriptor=descriptor,
                    status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                    terminal_detail=precondition_error,
                    duration_seconds=time.monotonic() - started,
                    command_sha256=command_sha256,
                    output_sha256=output_sha256,
                    output_bytes=output_bytes,
                    process_exit_code=return_code,
                    machine_output_validated=False,
                ),
                artifact_usage,
            )
        status, detail, summary, machine_result_sha256 = _parse_exact_foundry_test_with_deadline(
            stdout,
            descriptor=descriptor,
            return_code=return_code,
            deadline=deadline,
        )
    except _FoundrySuiteDeadlineExpired:
        return timed_out_result(artifact_usage)
    except (OSError, UnicodeError, ValueError) as exc:
        if time.monotonic() >= deadline:
            return timed_out_result(artifact_usage)
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail=f"invalid exact Forge JSON result: {type(exc).__name__}",
                duration_seconds=time.monotonic() - started,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            artifact_usage,
        )
    return (
        _FoundryTestObservation(
            descriptor=descriptor,
            status=status,
            terminal_detail=detail,
            duration_seconds=time.monotonic() - started,
            command_sha256=command_sha256,
            output_sha256=output_sha256,
            output_bytes=output_bytes,
            process_exit_code=return_code,
            machine_output_validated=(
                status
                in {
                    RepositoryTestExecutionStatus.PASSED,
                    RepositoryTestExecutionStatus.FAILED,
                    RepositoryTestExecutionStatus.REVERTED,
                    RepositoryTestExecutionStatus.ASSERTION_FAILED,
                }
            ),
            machine_result_sha256=machine_result_sha256,
            summary=summary,
        ),
        artifact_usage,
    )


def _invalid_foundry_observation(
    descriptor: RepositorySuiteTestDescriptor,
    started: float,
    detail: str,
    *,
    command_sha256: str | None = None,
) -> _FoundryTestObservation:
    return _FoundryTestObservation(
        descriptor=descriptor,
        status=RepositoryTestExecutionStatus.UNAVAILABLE,
        terminal_detail=detail,
        duration_seconds=time.monotonic() - started,
        command_sha256=command_sha256,
        output_sha256=None,
        output_bytes=0,
        process_exit_code=None,
        machine_output_validated=False,
    )


def _foundry_machine_result_precondition(
    *,
    return_code: int | None,
    stdout: str,
) -> str | None:
    """Reject process failures and missing machine output before JSON parsing."""

    if return_code not in {0, 1}:
        return "Forge terminated before emitting a classifiable machine result"
    if not stdout.strip():
        return "Forge emitted no machine JSON"
    return None


def _parse_exact_foundry_test_with_deadline(
    stdout: str,
    *,
    descriptor: RepositorySuiteTestDescriptor,
    return_code: int | None,
    deadline: float,
) -> tuple[
    RepositoryTestExecutionStatus,
    str | None,
    FoundryTestExecutionSummary,
    str,
]:
    """Parse one bounded machine result without granting post-process time."""

    _remaining_deadline_seconds(deadline)
    result = _parse_exact_foundry_test(
        stdout,
        descriptor=descriptor,
        return_code=return_code,
    )
    _remaining_deadline_seconds(deadline)
    return result


def _parse_exact_foundry_test(
    stdout: str,
    *,
    descriptor: RepositorySuiteTestDescriptor,
    return_code: int | None,
) -> tuple[
    RepositoryTestExecutionStatus,
    str | None,
    FoundryTestExecutionSummary,
    str,
]:
    suites = _foundry_suites(stdout)
    if len(suites) != 1:
        raise ValueError("Forge JSON must contain exactly one selected suite")
    suite_identifier, suite = next(iter(suites.items()))
    raw_path, suite_name = suite_identifier.rsplit(":", maxsplit=1)
    if raw_path != _project_relative_test_path(descriptor):
        raise ValueError("Forge JSON suite path differs from the selected test")
    if suite_name != descriptor.suite_name:
        raise ValueError("Forge JSON contract differs from the selected suite")
    test_results = suite["test_results"]
    if not isinstance(test_results, dict) or len(test_results) != 1:
        raise ValueError("Forge JSON must contain exactly one selected test result")
    test_signature, result = next(iter(test_results.items()))
    if (
        not isinstance(test_signature, str)
        or test_signature.partition("(")[0] != descriptor.test_name
        or not isinstance(result, dict)
    ):
        raise ValueError("Forge JSON test identity differs from the selection")
    if (
        descriptor.declaration_signature is not None
        and test_signature != descriptor.declaration_signature
    ):
        raise ValueError("Forge JSON test signature differs from compiler inventory")
    summary = _foundry_execution_summary(stdout)
    if summary is None:
        raise ValueError("Forge JSON contains no classified test result")
    foundry_status = _foundry_status(result)
    if foundry_status == "PASS":
        if return_code != 0:
            raise ValueError("passing Forge result has a nonzero process exit")
        status = RepositoryTestExecutionStatus.PASSED
        detail = None
        return (
            status,
            detail,
            summary,
            _foundry_machine_result_sha256(
                suite_identifier=suite_identifier,
                test_signature=test_signature,
                result=result,
                status=status,
                detail=detail,
                summary=summary,
            ),
        )
    if foundry_status == "SKIP":
        if return_code != 0:
            raise ValueError("skipped Forge result has a nonzero process exit")
        status = RepositoryTestExecutionStatus.SKIPPED
        detail = "Foundry repository test was skipped"
        return (
            status,
            detail,
            summary,
            _foundry_machine_result_sha256(
                suite_identifier=suite_identifier,
                test_signature=test_signature,
                result=result,
                status=status,
                detail=detail,
                summary=summary,
            ),
        )
    if return_code != 1:
        raise ValueError("failing Forge result must use the bounded finding exit code")
    raw_reason = result.get("reason")
    detail = _clean_reason(
        raw_reason
        if isinstance(raw_reason, str) and raw_reason
        else "Foundry repository test failed"
    )
    if re.search(r"\b(?:assert|assertion)\b", detail, re.IGNORECASE):
        status = RepositoryTestExecutionStatus.ASSERTION_FAILED
    elif re.search(r"\b(?:revert|panic|evmerror)\b", detail, re.IGNORECASE):
        status = RepositoryTestExecutionStatus.REVERTED
    else:
        status = RepositoryTestExecutionStatus.FAILED
    return (
        status,
        detail,
        summary,
        _foundry_machine_result_sha256(
            suite_identifier=suite_identifier,
            test_signature=test_signature,
            result=result,
            status=status,
            detail=detail,
            summary=summary,
        ),
    )


def _foundry_machine_result_sha256(
    *,
    suite_identifier: str,
    test_signature: str,
    result: dict[str, Any],
    status: RepositoryTestExecutionStatus,
    detail: str | None,
    summary: FoundryTestExecutionSummary,
) -> str:
    """Hash stable semantic machine evidence while excluding Forge timing/traces."""

    payload = {
        "schema_version": "1.0",
        "suite_identifier": suite_identifier,
        "test_signature": test_signature,
        "status": status.value,
        "terminal_detail": detail,
        "counterexample": result.get("counterexample"),
        "summary": summary.model_dump(mode="json"),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _aggregate_foundry_summaries(
    observations: list[_FoundryTestObservation],
) -> FoundryTestExecutionSummary | None:
    if not observations or any(observation.summary is None for observation in observations):
        return None
    summaries = [observation.summary for observation in observations]
    assert all(summary is not None for summary in summaries)
    typed = [summary for summary in summaries if summary is not None]
    return FoundryTestExecutionSummary(
        unit_tests=sum(summary.unit_tests for summary in typed),
        fuzz_tests=sum(summary.fuzz_tests for summary in typed),
        invariant_tests=sum(summary.invariant_tests for summary in typed),
        passed_tests=sum(summary.passed_tests for summary in typed),
        failed_tests=sum(summary.failed_tests for summary in typed),
        skipped_tests=sum(summary.skipped_tests for summary in typed),
        fuzz_cases=sum(summary.fuzz_cases for summary in typed),
        invariant_runs=sum(summary.invariant_runs for summary in typed),
        invariant_calls=sum(summary.invariant_calls for summary in typed),
    )


def _selection_sources_unchanged(
    root: Path,
    selection: RepositorySuiteSelection,
    *,
    deadline: float | None = None,
) -> bool:
    try:
        resolved_root = root.resolve(strict=True)
        for descriptor in selection.tests:
            sources = {
                descriptor.path: descriptor.source_sha256,
                descriptor.finding_path: descriptor.finding_source_sha256,
            }
            for relative_path, source_sha256 in sources.items():
                if deadline is not None:
                    _remaining_deadline_seconds(deadline)
                path = resolved_root.joinpath(*PurePosixPath(relative_path).parts)
                if path.is_symlink() or path.is_junction() or not path.is_file():
                    return False
                if path.resolve(strict=True).relative_to(resolved_root).as_posix() != relative_path:
                    return False
                if _file_sha256(path) != source_sha256:
                    return False
                if deadline is not None:
                    _remaining_deadline_seconds(deadline)
    except _FoundrySuiteDeadlineExpired:
        raise
    except (OSError, ValueError):
        return False
    return True


def _cleanup_error(
    backend: ScannerIsolationBackend | None,
    private_dir: Path,
) -> str | None:
    if backend is None:
        return None
    try:
        cleanup_isolation_backend(backend, private_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return f"isolation cleanup verification failed: {type(exc).__name__}"
    return None


def _unavailable_observation(
    descriptor: RepositorySuiteTestDescriptor,
    detail: str,
) -> _FoundryTestObservation:
    return _FoundryTestObservation(
        descriptor=descriptor,
        status=RepositoryTestExecutionStatus.UNAVAILABLE,
        terminal_detail=detail,
        duration_seconds=0,
        command_sha256=None,
        output_sha256=None,
        output_bytes=0,
        process_exit_code=None,
        machine_output_validated=False,
    )


def _repository_test_executions(
    *,
    selection: RepositorySuiteSelection,
    observations: list[_FoundryTestObservation],
    fallback_detail: str,
    fork: PinnedForkObservation | None,
    fuzz_seed: str,
    execution_evidence: ExecutionEvidenceKind,
    repository_code_execution: RepositoryCodeExecutionState,
    isolation_backend: str | None,
    isolation_attestation: str | None,
    compiler_version: str | None,
    compiler_sha256: str | None,
    execution_policy: RepositorySuiteExecutionPolicy | None,
    inventory: RepositorySuiteInventoryEvidence | None,
    post_inventory: RepositorySuiteInventoryEvidence | None,
    deadline: float | None = None,
) -> list[RepositoryTestExecution]:
    by_descriptor = {
        observation.descriptor.descriptor_sha256: observation for observation in observations
    }
    if len(by_descriptor) != len(observations):
        raise ValueError("repository fork suite emitted duplicate execution observations")
    executions: list[RepositoryTestExecution] = []
    stable_inventories = (
        inventory is not None
        and post_inventory is not None
        and _foundry_inventory_semantics_match(inventory, post_inventory)
    )
    inventory_sha256 = inventory.inventory_sha256 if stable_inventories and inventory else None
    post_inventory_sha256 = (
        post_inventory.inventory_sha256 if stable_inventories and post_inventory else None
    )
    for descriptor in selection.tests:
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        observation = by_descriptor.get(descriptor.descriptor_sha256) or _unavailable_observation(
            descriptor,
            fallback_detail,
        )
        test_kind: RepositoryTestKind | None = None
        fuzz_cases = 0
        invariant_runs = 0
        invariant_calls = 0
        if observation.machine_output_validated and observation.summary is not None:
            if observation.summary.unit_tests == 1:
                test_kind = RepositoryTestKind.UNIT
            elif observation.summary.fuzz_tests == 1:
                test_kind = RepositoryTestKind.FUZZ
                fuzz_cases = observation.summary.fuzz_cases
            elif observation.summary.invariant_tests == 1:
                test_kind = RepositoryTestKind.INVARIANT
                invariant_runs = observation.summary.invariant_runs
                invariant_calls = observation.summary.invariant_calls
            else:
                raise ValueError("exact Foundry test observation has an ambiguous campaign kind")
        executions.append(
            RepositoryTestExecution.sealed(
                selection_sha256=selection.selection_sha256,
                descriptor_sha256=descriptor.descriptor_sha256,
                inventory_sha256=inventory_sha256,
                post_inventory_sha256=post_inventory_sha256,
                inventory_record_sha256=(
                    descriptor.inventory_record_sha256 if stable_inventories else None
                ),
                framework=descriptor.framework,
                project_root=descriptor.project_root,
                path=descriptor.path,
                suite_name=descriptor.suite_name,
                test_name=descriptor.test_name,
                chain_id=fork.chain_id if fork is not None else None,
                block_number=fork.block_number if fork is not None else None,
                block_hash=fork.block_hash if fork is not None else None,
                fuzz_seed=fuzz_seed,
                test_kind=test_kind,
                fuzz_cases=fuzz_cases,
                invariant_runs=invariant_runs,
                invariant_calls=invariant_calls,
                status=observation.status,
                terminal_detail=observation.terminal_detail,
                duration_seconds=observation.duration_seconds,
                command_sha256=observation.command_sha256,
                output_sha256=observation.output_sha256,
                output_bytes=observation.output_bytes,
                machine_result_sha256=observation.machine_result_sha256,
                process_exit_code=observation.process_exit_code,
                machine_output_validated=observation.machine_output_validated,
                execution_evidence=execution_evidence,
                repository_code_execution=repository_code_execution,
                isolation_backend=isolation_backend,
                isolation_attestation_sha256=isolation_attestation,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                execution_policy_sha256=(
                    execution_policy.policy_sha256 if execution_policy is not None else None
                ),
                safety_claim=False,
            )
        )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
    return executions


def _repository_test_findings(
    root: Path,
    executions: list[RepositoryTestExecution],
    selection: RepositorySuiteSelection,
    *,
    deadline: float | None = None,
) -> list[ScannerFinding]:
    descriptors = {descriptor.descriptor_sha256: descriptor for descriptor in selection.tests}
    failure_statuses = {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
    findings: list[ScannerFinding] = []
    for execution in executions:
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        if execution.status not in failure_statuses:
            continue
        descriptor = descriptors[execution.descriptor_sha256]
        detail = execution.terminal_detail or "Foundry repository test failed"
        finding = make_finding(
            root=root,
            scanner="foundry_fork",
            rule_id="repository-fork-test-failure",
            title=f"Pinned-fork repository test failed: {execution.test_name}",
            severity=Severity.HIGH,
            message=detail,
            path=descriptor.finding_path,
            start_line=descriptor.finding_start_line,
            end_line=descriptor.finding_end_line,
            metadata={
                "class": "repository_fork_suite",
                "fork_only": True,
                "test_name": execution.test_name,
                "suite_name": execution.suite_name,
                "chain_id": execution.chain_id,
                "block_number": execution.block_number,
                "repository_test_execution_sha256": execution.execution_sha256,
            },
            evidence_strength=(
                EvidenceStrength.DETERMINISTIC_ANALYZER
                if execution.execution_evidence is ExecutionEvidenceKind.REAL
                else EvidenceStrength.NONE
            ),
        )
        if finding is None:
            raise ValueError("repository fork-test finding location could not be normalized")
        findings.append(finding)
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
    return findings


def _write_repository_suite_manifest(
    private_dir: Path,
    selection: RepositorySuiteSelection,
    inventory: RepositorySuiteInventoryEvidence | None,
    post_inventory: RepositorySuiteInventoryEvidence | None,
    execution_policy: RepositorySuiteExecutionPolicy | None,
    executions: list[RepositoryTestExecution],
    repository_test_fork_rpc_scopes: Sequence[RepositoryTestForkRpcScopeEvidence] = (),
    *,
    deadline: float,
) -> Path:
    _remaining_deadline_seconds(deadline)
    path = private_dir / "repository-suite-execution.json"
    selection_payload = selection.model_dump(mode="json")
    _remaining_deadline_seconds(deadline)
    inventory_payload = inventory.model_dump(mode="json") if inventory is not None else None
    _remaining_deadline_seconds(deadline)
    post_inventory_payload = (
        post_inventory.model_dump(mode="json") if post_inventory is not None else None
    )
    _remaining_deadline_seconds(deadline)
    policy_payload = (
        execution_policy.model_dump(mode="json") if execution_policy is not None else None
    )
    _remaining_deadline_seconds(deadline)
    execution_payloads: list[dict[str, Any]] = []
    for execution in executions:
        execution_payloads.append(execution.model_dump(mode="json"))
        _remaining_deadline_seconds(deadline)
    scope_payloads: list[dict[str, Any]] = []
    for scope in repository_test_fork_rpc_scopes:
        scope_payloads.append(scope.model_dump(mode="json"))
        _remaining_deadline_seconds(deadline)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "selection": selection_payload,
        "pre_execution_inventory": inventory_payload,
        "post_execution_inventory": post_inventory_payload,
        "execution_policy": policy_payload,
        "executions": execution_payloads,
        "safety_claim": False,
    }
    if scope_payloads:
        payload["repository_test_fork_rpc_scopes"] = scope_payloads
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    _remaining_deadline_seconds(deadline)
    path.write_text(
        serialized + "\n",
        encoding="utf-8",
    )
    _remaining_deadline_seconds(deadline)
    return path


def _sealed_workspace_copy_evidence(
    observation: ScannerWorkspaceCopyObservation,
    *,
    attempt_binding_sha256: str,
    selection: RepositorySuiteSelection,
) -> RepositorySuiteWorkspaceCopyEvidence:
    return RepositorySuiteWorkspaceCopyEvidence.sealed(
        attempt_binding_sha256=attempt_binding_sha256,
        selection_sha256=selection.selection_sha256,
        repository_sha256=selection.repository_sha256,
        copy_policy_sha256=REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
        source_inventory_sha256_before=observation.source_inventory_sha256_before,
        source_inventory_sha256_after=observation.source_inventory_sha256_after,
        workspace_inventory_sha256_after_copy=(observation.workspace_inventory_sha256_after_copy),
        workspace_inventory_sha256_after_execution=(
            observation.workspace_inventory_sha256_after_execution
        ),
        source_root_device_before=observation.source_root_device_before,
        source_root_inode_before=observation.source_root_inode_before,
        source_root_device_after=observation.source_root_device_after,
        source_root_inode_after=observation.source_root_inode_after,
        workspace_root_device_before=observation.workspace_root_device_before,
        workspace_root_inode_before=observation.workspace_root_inode_before,
        workspace_root_device_after=observation.workspace_root_device_after,
        workspace_root_inode_after=observation.workspace_root_inode_after,
        workspace_parent_device=observation.workspace_parent_device,
        workspace_parent_inode=observation.workspace_parent_inode,
        workspace_created_exclusively=observation.workspace_created_exclusively,
        workspace_direct_child=observation.workspace_direct_child,
        audited_inventory_symlink_free=observation.audited_inventory_symlink_free,
        source_descriptor_custody_validated=(observation.source_descriptor_custody_validated),
        workspace_descriptor_custody_validated=(observation.workspace_descriptor_custody_validated),
        workspace_parent_descriptor_custody_validated=(
            observation.workspace_parent_descriptor_custody_validated
        ),
        copy_matches_source=observation.copy_matches_source,
        source_identity_stable=observation.source_identity_stable,
        workspace_identity_stable=observation.workspace_identity_stable,
        workspace_removed=observation.workspace_removed,
    )


def _finalize_foundry_repository_suite(
    *,
    root: Path,
    private_dir: Path,
    backend: ScannerIsolationBackend | None,
    start: datetime,
    monotonic_start: float,
    deadline: float,
    total_timeout_seconds: float,
    status: ScannerStatus,
    error: str | None,
    selection: RepositorySuiteSelection | None,
    observations: list[_FoundryTestObservation],
    fork: PinnedForkObservation | None,
    executable_sha256: str | None,
    version: str | None,
    compiler_version: str | None,
    compiler_sha256: str | None,
    execution_policy: RepositorySuiteExecutionPolicy | None,
    inventory: RepositorySuiteInventoryEvidence | None,
    post_inventory: RepositorySuiteInventoryEvidence | None,
    fuzz_seed: str,
    repository_test_fork_rpc_scopes: Sequence[RepositoryTestForkRpcScopeEvidence] = (),
    repository_suite_workspace_copy: RepositorySuiteWorkspaceCopyEvidence | None = None,
    repository_suite_workspace_custody: ScannerWorkspaceCopyCustody | None = None,
) -> ScannerRun:
    timeout_error = f"repository fork suite exceeded {total_timeout_seconds:.0f}s total timeout"
    cleanup_error = _cleanup_error(backend, private_dir)
    deadline_crossed = time.monotonic() >= deadline
    if deadline_crossed:
        status = ScannerStatus.TIMED_OUT
        error = timeout_error
    elif cleanup_error is not None:
        status = ScannerStatus.FAILED
        error = cleanup_error
    matrix_scoped = bool(repository_test_fork_rpc_scopes)
    if repository_suite_workspace_custody is not None:
        try:
            observation = repository_suite_workspace_custody.finalize()
            if repository_suite_workspace_copy is not None:
                raise ValueError("workspace copy evidence and live custody are mutually exclusive")
            if status is ScannerStatus.SUCCESS and matrix_scoped:
                if selection is None:
                    raise ValueError("matrix-scoped workspace evidence lacks its selection")
                attempt_bindings = {
                    scope.attempt_binding_sha256 for scope in repository_test_fork_rpc_scopes
                }
                if len(attempt_bindings) != 1 or "0" * 64 in attempt_bindings:
                    raise ValueError("matrix-scoped workspace evidence lacks one attempt binding")
                repository_suite_workspace_copy = _sealed_workspace_copy_evidence(
                    observation,
                    attempt_binding_sha256=next(iter(attempt_bindings)),
                    selection=selection,
                )
        except (OSError, ValueError) as exc:
            if status is not ScannerStatus.TIMED_OUT:
                status = ScannerStatus.FAILED
                error = (
                    f"repository suite workspace custody validation failed: {type(exc).__name__}"
                )
    attestation = isolation_attestation_sha256(backend)
    if time.monotonic() >= deadline:
        deadline_crossed = True
        status = ScannerStatus.TIMED_OUT
        error = timeout_error
    isolation_backend = str(getattr(backend, "name", "")) or None if backend is not None else None
    attempted_statuses = {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    }
    attempted = inventory is not None or any(
        observation.status in attempted_statuses for observation in observations
    )
    if execution_policy is not None and any(
        observation.duration_seconds > execution_policy.per_test_timeout_seconds
        for observation in observations
    ):
        status = ScannerStatus.TIMED_OUT
        error = "one repository fork test exceeded its complete per-test deadline"
    if not matrix_scoped or status is not ScannerStatus.SUCCESS:
        repository_suite_workspace_copy = None
    elif repository_suite_workspace_copy is None:
        status = ScannerStatus.FAILED
        error = "successful matrix-scoped repository suite lacks workspace copy evidence"
    repository_code_execution = (
        RepositoryCodeExecutionState.ISOLATED
        if attempted
        else (
            RepositoryCodeExecutionState.BLOCKED
            if selection is not None
            else RepositoryCodeExecutionState.NOT_APPLICABLE
        )
    )
    execution_evidence = (
        isolation_execution_evidence(backend)
        if (
            status is ScannerStatus.SUCCESS
            and attempted
            and executable_sha256 is not None
            and version is not None
            and attestation is not None
            and inventory is not None
            and post_inventory is not None
            and _foundry_inventory_semantics_match(inventory, post_inventory)
            and not deadline_crossed
        )
        else ExecutionEvidenceKind.UNVERIFIED
    )
    executions: list[RepositoryTestExecution] = []
    findings: list[ScannerFinding] = []
    foundry_summary: FoundryTestExecutionSummary | None = None
    manifest_path: Path | None = None

    def build_evidence(
        evidence: ExecutionEvidenceKind,
        fallback_detail: str,
    ) -> tuple[list[RepositoryTestExecution], list[ScannerFinding]]:
        if selection is None:
            return [], []
        evidence_deadline = None if deadline_crossed else deadline
        sealed_executions = _repository_test_executions(
            selection=selection,
            observations=observations,
            fallback_detail=fallback_detail,
            fork=fork,
            fuzz_seed=fuzz_seed,
            execution_evidence=evidence,
            repository_code_execution=repository_code_execution,
            isolation_backend=isolation_backend,
            isolation_attestation=attestation,
            compiler_version=compiler_version,
            compiler_sha256=compiler_sha256,
            execution_policy=execution_policy,
            inventory=inventory,
            post_inventory=post_inventory,
            deadline=evidence_deadline,
        )
        return (
            sealed_executions,
            _repository_test_findings(
                root,
                sealed_executions,
                selection,
                deadline=evidence_deadline,
            ),
        )

    def discard_manifest() -> None:
        nonlocal manifest_path
        candidate = manifest_path or (private_dir / "repository-suite-execution.json")
        with suppress(OSError):
            candidate.unlink(missing_ok=True)
        manifest_path = None

    def downgrade_for_expired_deadline() -> None:
        nonlocal status, error, execution_evidence, executions, findings, foundry_summary
        nonlocal deadline_crossed
        deadline_crossed = True
        status = ScannerStatus.TIMED_OUT
        error = timeout_error
        foundry_summary = None
        discard_manifest()
        if execution_evidence is not ExecutionEvidenceKind.UNVERIFIED:
            execution_evidence = ExecutionEvidenceKind.UNVERIFIED
            executions, findings = build_evidence(execution_evidence, error)

    def check_final_deadline() -> None:
        if time.monotonic() >= deadline:
            downgrade_for_expired_deadline()
            raise _FoundrySuiteDeadlineExpired

    if selection is not None:
        fallback_detail = error or "repository fork test was not executed"
        try:
            check_final_deadline()
            executions, findings = build_evidence(execution_evidence, fallback_detail)
            check_final_deadline()
            if status is ScannerStatus.SUCCESS:
                foundry_summary = _aggregate_foundry_summaries(observations)
                if foundry_summary is None:
                    raise ValueError("successful repository suite lacks complete typed outcomes")
                check_final_deadline()
            if not deadline_crossed:
                manifest_path = _write_repository_suite_manifest(
                    private_dir,
                    selection,
                    inventory,
                    post_inventory,
                    execution_policy,
                    executions,
                    repository_test_fork_rpc_scopes,
                    deadline=deadline,
                )
                check_final_deadline()
        except _FoundrySuiteDeadlineExpired:
            if execution_evidence is not ExecutionEvidenceKind.UNVERIFIED:
                downgrade_for_expired_deadline()
            if not executions:
                executions, findings = build_evidence(
                    ExecutionEvidenceKind.UNVERIFIED,
                    timeout_error,
                )
        except (OSError, ValueError) as exc:
            if time.monotonic() >= deadline:
                downgrade_for_expired_deadline()
            else:
                status = ScannerStatus.FAILED
                error = f"repository fork-suite evidence finalization failed: {type(exc).__name__}"
            execution_evidence = ExecutionEvidenceKind.UNVERIFIED
            executions, findings = build_evidence(
                execution_evidence,
                error or "repository fork-suite evidence finalization failed",
            )
            foundry_summary = None
            discard_manifest()
    if time.monotonic() >= deadline and not deadline_crossed:
        downgrade_for_expired_deadline()
    process_exit_code = (
        1
        if any(
            observation.status
            in {
                RepositoryTestExecutionStatus.FAILED,
                RepositoryTestExecutionStatus.REVERTED,
                RepositoryTestExecutionStatus.ASSERTION_FAILED,
            }
            for observation in observations
        )
        else (
            observations[-1].process_exit_code
            if observations and observations[-1].process_exit_code is not None
            else (0 if status is ScannerStatus.SUCCESS else None)
        )
    )
    raw_output_path: str | None = None
    raw_output_sha256: str | None = None
    raw_output_bytes = 0
    if manifest_path is not None and not deadline_crossed:
        try:
            check_final_deadline()
            raw_output_path = str(manifest_path.relative_to(private_dir.parent))
            raw_output_sha256 = _file_sha256(manifest_path)
            check_final_deadline()
            raw_output_bytes = manifest_path.stat().st_size
            check_final_deadline()
        except _FoundrySuiteDeadlineExpired:
            raw_output_path = None
            raw_output_sha256 = None
            raw_output_bytes = 0
        except (OSError, ValueError) as exc:
            if time.monotonic() >= deadline:
                downgrade_for_expired_deadline()
            else:
                status = ScannerStatus.FAILED
                error = f"repository fork-suite evidence finalization failed: {type(exc).__name__}"
                execution_evidence = ExecutionEvidenceKind.UNVERIFIED
                executions, findings = build_evidence(execution_evidence, error)
                foundry_summary = None
                discard_manifest()
            raw_output_path = None
            raw_output_sha256 = None
            raw_output_bytes = 0

    def build_run() -> ScannerRun:
        return ScannerRun(
            scanner="foundry_fork",
            status=status,
            execution_evidence=execution_evidence,
            version=version,
            executable_sha256=executable_sha256,
            command=(
                [
                    "forge",
                    "test",
                    "[BOUNDED_PER_TEST_REPOSITORY_SUITE]",
                    selection.selection_sha256,
                ]
                if selection is not None and observations
                else []
            ),
            started_at=start,
            finished_at=datetime.now(UTC),
            duration_seconds=time.monotonic() - monotonic_start,
            findings=findings,
            error=error,
            raw_output_path=raw_output_path,
            raw_output_sha256=raw_output_sha256,
            raw_output_bytes=raw_output_bytes,
            process_exit_code=process_exit_code,
            isolation_backend=isolation_backend,
            isolation_attestation_sha256=attestation,
            machine_output_validated=(
                status is ScannerStatus.SUCCESS and foundry_summary is not None
            ),
            foundry_summary=foundry_summary,
            repository_suite_selection=selection,
            repository_suite_inventory=inventory,
            repository_suite_post_inventory=post_inventory,
            repository_suite_execution_policy=execution_policy,
            repository_suite_workspace_copy=(
                repository_suite_workspace_copy
                if status is ScannerStatus.SUCCESS and matrix_scoped
                else None
            ),
            repository_test_fork_rpc_scopes=list(repository_test_fork_rpc_scopes),
            repository_test_executions=executions,
            repository_code_execution=repository_code_execution,
        )

    def seal_run(run: ScannerRun) -> ScannerRun:
        payload = run.model_dump(mode="json")
        check_final_deadline()
        payload["execution_observation_sha256"] = run.expected_execution_observation_sha256()
        check_final_deadline()
        sealed = ScannerRun.model_validate(payload)
        check_final_deadline()
        return sealed

    try:
        run = build_run()
        check_final_deadline()
        return seal_run(run)
    except _FoundrySuiteDeadlineExpired:
        downgrade_for_expired_deadline()
        raw_output_path = None
        raw_output_sha256 = None
        raw_output_bytes = 0
        timed_out_run = build_run()
        payload = timed_out_run.model_dump(mode="json")
        payload["execution_observation_sha256"] = (
            timed_out_run.expected_execution_observation_sha256()
        )
        return ScannerRun.model_validate(payload)


def _looks_like_foundry_project(
    root: Path,
    *,
    excluded_root: Path | None = None,
) -> bool:
    return (
        (root / "foundry.toml").is_file()
        and not _path_is_within_excluded_root(root / "foundry.toml", excluded_root)
    ) or any(
        path.suffix == ".sol" and not _path_is_within_excluded_root(path, excluded_root)
        for path in [*root.glob("src/**/*.sol"), *root.glob("contracts/**/*.sol")]
    )


def _reject_unsafe_foundry_configuration(
    root: Path,
    *,
    excluded_root: Path | None = None,
) -> None:
    foundry_configs = [
        path
        for path in root.glob("**/foundry.toml")
        if (
            not {".git", ".mmaudit", "node_modules"}.intersection(path.relative_to(root).parts)
            and not _path_is_within_excluded_root(path, excluded_root)
        )
    ]
    if len(foundry_configs) > 1_000:
        raise ValueError("Foundry configuration count exceeds the fixed bound")
    for foundry_config in foundry_configs:
        if (
            foundry_config.is_symlink()
            or foundry_config.is_junction()
            or not foundry_config.is_file()
            or foundry_config.stat().st_nlink != 1
            or foundry_config.stat().st_size > 1_000_000
        ):
            raise ValueError("Foundry configuration must be a bounded regular non-link file")
        payload = tomllib.loads(foundry_config.read_text(encoding="utf-8"))
        if _toml_contains_true(payload, "ffi"):
            raise ValueError("Foundry FFI is enabled; refusing to execute fork tests")
        if _toml_contains_nonempty(payload, "fs_permissions"):
            raise ValueError(
                "Foundry fs_permissions are configured; refusing to execute fork tests"
            )
        for compiler_value in (
            *_toml_named_values(payload, "solc"),
            *_toml_named_values(payload, "solc_version"),
        ):
            if (
                not isinstance(compiler_value, str)
                or re.fullmatch(
                    r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?",
                    compiler_value,
                )
                is None
            ):
                raise ValueError(
                    "Foundry repository configuration selects an executable compiler path"
                )
    source_count = 0
    for path in root.glob("**/*.sol"):
        try:
            relative = PurePosixPath(path.relative_to(root).as_posix())
        except ValueError:
            continue
        if (
            ".git" in relative.parts
            or ".mmaudit" in relative.parts
            or "node_modules" in relative.parts
            or _path_is_within_excluded_root(path, excluded_root)
        ):
            continue
        source_count += 1
        if source_count > 100_000:
            raise ValueError("Solidity source count exceeds the fixed safety bound")
        if (
            path.is_symlink()
            or path.is_junction()
            or not path.is_file()
            or path.stat().st_nlink != 1
            or path.stat().st_size > 10_000_000
        ):
            raise ValueError("Solidity source must be a bounded regular non-link file")
        content = path.read_text(encoding="utf-8")
        if "vm.ffi" in content:
            raise ValueError("Foundry test uses vm.ffi; refusing to execute fork tests")


def _path_is_within_excluded_root(path: Path, excluded_root: Path | None) -> bool:
    if excluded_root is None:
        return False
    try:
        path.resolve(strict=False).relative_to(excluded_root.resolve(strict=False))
    except OSError:
        return True
    except ValueError:
        return False
    return True


def _toml_contains_true(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return any(
            (name == key and item is True) or _toml_contains_true(item, key)
            for name, item in value.items()
        )
    if isinstance(value, list):
        return any(_toml_contains_true(item, key) for item in value)
    return False


def _toml_contains_nonempty(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return any(
            (name == key and item not in (None, [], {})) or _toml_contains_nonempty(item, key)
            for name, item in value.items()
        )
    if isinstance(value, list):
        return any(_toml_contains_nonempty(item, key) for item in value)
    return False


def _toml_named_values(value: Any, key: str) -> tuple[Any, ...]:
    if isinstance(value, dict):
        return tuple(
            item
            for name, child in value.items()
            for item in ((child,) if name == key else _toml_named_values(child, key))
        )
    if isinstance(value, list):
        return tuple(item for child in value for item in _toml_named_values(child, key))
    return ()


def _find_test_location(root: Path, raw_path: str, test_name: str) -> tuple[int, int]:
    path = root / raw_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return (1, 1)
    pattern = re.compile(rf"\bfunction\s+{re.escape(test_name)}\b")
    for index, line in enumerate(lines, start=1):
        if pattern.search(line):
            return (index, _find_block_end(lines, index))
    return (1, min(1, len(lines)))


def _find_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return index
    return start_line


def _clean_reason(value: str) -> str:
    sanitized = "".join(character if ord(character) >= 32 else " " for character in value)
    return " ".join(sanitized.split())[:500]


def _foundry_execution_summary(stdout: str) -> FoundryTestExecutionSummary | None:
    """Count only typed Forge JSON results; repository log text is never classified."""

    classified = {"unit": 0, "fuzz": 0, "invariant": 0}
    outcomes = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    fuzz_cases = 0
    invariant_runs = 0
    invariant_calls = 0

    for suite in _foundry_suites(stdout).values():
        test_results = suite["test_results"]
        assert isinstance(test_results, dict)
        for result in test_results.values():
            assert isinstance(result, dict)
            status = _foundry_status(result)
            kind, metadata = _foundry_kind(result)
            outcomes[status] += 1
            classified[kind] += 1
            if kind == "fuzz":
                fuzz_cases += _foundry_nonnegative_integer(metadata, "runs")
            elif kind == "invariant":
                invariant_runs += _foundry_nonnegative_integer(metadata, "runs")
                invariant_calls += _foundry_nonnegative_integer(metadata, "calls")

    if not any(classified.values()):
        return None
    return FoundryTestExecutionSummary(
        unit_tests=classified["unit"],
        fuzz_tests=classified["fuzz"],
        invariant_tests=classified["invariant"],
        passed_tests=outcomes["PASS"],
        failed_tests=outcomes["FAIL"],
        skipped_tests=outcomes["SKIP"],
        fuzz_cases=fuzz_cases,
        invariant_runs=invariant_runs,
        invariant_calls=invariant_calls,
    )


def _foundry_suites(stdout: str) -> dict[str, dict[str, Any]]:
    """Load the bounded Forge JSON suite map and reject ambiguous structures."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Forge JSON contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Forge JSON contains a non-finite number: {value}")

    try:
        payload = json.loads(
            stdout,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Forge output is not one JSON document") from exc
    if not isinstance(payload, dict):
        raise ValueError("Forge JSON root must be a suite object")
    if len(payload) > 10_000:
        raise ValueError("Forge JSON suite count exceeds the execution bound")

    suites: dict[str, dict[str, Any]] = {}
    total_tests = 0
    for suite_name, raw_suite in sorted(payload.items()):
        if (
            not isinstance(suite_name, str)
            or not suite_name
            or len(suite_name) > 2_000
            or any(ord(character) < 32 or ord(character) == 127 for character in suite_name)
            or ":" not in suite_name
        ):
            raise ValueError("Forge JSON contains an invalid suite identifier")
        raw_path, contract_name = suite_name.rsplit(":", maxsplit=1)
        path = PurePosixPath(raw_path)
        if (
            not raw_path
            or not contract_name
            or path.is_absolute()
            or path.as_posix() != raw_path
            or "\\" in raw_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Forge JSON suite identifier is not repository-relative")
        if not isinstance(raw_suite, dict):
            raise ValueError("Forge JSON suite must be an object")
        test_results = raw_suite.get("test_results")
        if not isinstance(test_results, dict):
            raise ValueError("Forge JSON suite is missing test_results")
        total_tests += len(test_results)
        if total_tests > 200_000:
            raise ValueError("Forge JSON test count exceeds the execution bound")
        for test_name, result in test_results.items():
            if (
                not isinstance(test_name, str)
                or not test_name
                or len(test_name) > 1_000
                or any(ord(character) < 32 or ord(character) == 127 for character in test_name)
                or not isinstance(result, dict)
            ):
                raise ValueError("Forge JSON contains an invalid test result")
            _foundry_status(result)
            _foundry_kind(result)
        suites[suite_name] = raw_suite
    return suites


def _foundry_status(result: dict[str, Any]) -> str:
    raw_status = result.get("status")
    statuses = {
        "Success": "PASS",
        "Failure": "FAIL",
        "Skipped": "SKIP",
    }
    if not isinstance(raw_status, str) or raw_status not in statuses:
        raise ValueError("Forge JSON contains an unknown test status")
    return statuses[raw_status]


def _foundry_kind(result: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    raw_kind = result.get("kind")
    if not isinstance(raw_kind, dict) or len(raw_kind) != 1:
        raise ValueError("Forge JSON test kind must contain one typed variant")
    kind_name, metadata = next(iter(raw_kind.items()))
    normalized = {
        "Unit": "unit",
        "Fuzz": "fuzz",
        "Invariant": "invariant",
    }.get(kind_name)
    if normalized is None or not isinstance(metadata, dict):
        raise ValueError("Forge JSON contains an unsupported test kind")
    if normalized == "fuzz":
        _foundry_nonnegative_integer(metadata, "runs")
    elif normalized == "invariant":
        _foundry_nonnegative_integer(metadata, "runs")
        _foundry_nonnegative_integer(metadata, "calls")
    return normalized, metadata


def _foundry_nonnegative_integer(metadata: dict[str, Any], field: str) -> int:
    value = metadata.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2**63 - 1:
        raise ValueError(f"Forge JSON {field} must be a bounded non-negative integer")
    return value


def _limit_process() -> None:
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("Foundry resource limit setup failed") from exc

    limits = [
        (resource.RLIMIT_CPU, (900, 900)),
        (resource.RLIMIT_FSIZE, (50_000_000, 50_000_000)),
        (resource.RLIMIT_NOFILE, (256, 256)),
    ]
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_NPROC"):
        limits.append((resource.RLIMIT_NPROC, (64, 64)))
    # Darwin exposes RLIMIT_AS but rejects setrlimit for it.
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_AS"):
        limits.append((resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3)))

    failures = 0
    for resource_kind, value in limits:
        try:
            resource.setrlimit(resource_kind, value)
        except (OSError, ValueError):
            failures += 1
    if failures:
        raise RuntimeError(f"Foundry resource limit setup failed for {failures} limit(s)")


def _stop_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float | None = None,
) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        wait_seconds = 5.0 if deadline is None else max(0.0, deadline - time.monotonic())
        process.wait(timeout=wait_seconds)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
