"""Foundry fork-test adapter for defensive smart-contract probing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

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
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
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
    _file_sha256,
    copy_scanner_workspace,
    isolated_executable_version,
    make_finding,
    sanitized_scanner_environment,
    scanner_trust_pin_error,
    scanner_workspace_sha256,
)
from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    PinnedForkObservation,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)
from mmaudit.scanners.repository_suite import (
    RepositorySuiteSelectionError,
    select_foundry_repository_suite,
)


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


class _PinnedCompilerUnavailableError(RuntimeError):
    """A required operator-pinned external Solidity compiler is absent."""


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
    ) -> None:
        self.config = config
        self.reproduction = reproduction or ReproductionConfig()
        self.projects = tuple(projects)
        self.allow_fork_probing = allow_fork_probing

    def with_runtime_context(
        self,
        *,
        allow_fork_probing: bool,
        projects: Sequence[SolidityProjectMetadata],
    ) -> FoundryForkScanner:
        return FoundryForkScanner(
            self.config,
            reproduction=self.reproduction,
            projects=projects,
            allow_fork_probing=allow_fork_probing,
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
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()
        selection: RepositorySuiteSelection | None = None
        observations: list[_FoundryTestObservation] = []
        fork: PinnedForkObservation | None = None
        executable_sha256: str | None = None
        version: str | None = None
        compiler_version: str | None = None
        compiler_sha256: str | None = None
        execution_policy: RepositorySuiteExecutionPolicy | None = None
        compiler_path: Path | None = None
        total_timeout = min(
            timeout_seconds,
            self.config.max_fork_probe_seconds,
            self.config.repository_suite.total_timeout_seconds,
        )
        per_test_timeout = min(
            total_timeout,
            self.config.repository_suite.per_test_timeout_seconds,
        )

        def finish(status: ScannerStatus, error: str | None) -> ScannerRun:
            return _finalize_foundry_repository_suite(
                root=root,
                private_dir=private_dir,
                backend=backend,
                start=start,
                monotonic_start=monotonic_start,
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
                fuzz_seed=self.config.repository_suite.fuzz_seed,
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
        projects = self.projects or _default_foundry_projects(root)
        if not projects:
            return finish(ScannerStatus.SKIPPED, "no Foundry smart-contract project detected")
        try:
            selection = select_foundry_repository_suite(
                root,
                projects,
                self.config,
                private_dir=private_dir,
            )
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

        if backend is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                "hardened fork-test isolation is unavailable; tests were not executed",
            )
        if not bool(getattr(backend, "supports_local_fork_rpc", True)):
            return finish(
                ScannerStatus.UNAVAILABLE,
                f"{backend.name} cannot reach the configured loopback fork RPC; "
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

        rpc_url = os.environ.get(self.config.fork_rpc_url_env, "")
        if not rpc_url:
            return finish(
                ScannerStatus.UNAVAILABLE,
                f"{self.config.fork_rpc_url_env} is not set",
            )
        try:
            rpc_port = local_fork_rpc_port(rpc_url)
        except ForkRpcBindingError as exc:
            return finish(ScannerStatus.FAILED, str(exc))

        try:
            _reject_unsafe_foundry_configuration(root)
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
            fork = observe_pinned_fork_rpc(
                rpc_url,
                expected_chain_id=self.reproduction.expected_chain_id,
                pinned_block_number=self.reproduction.pinned_block_number,
                timeout_seconds=min(5.0, self.config.repository_suite.per_test_timeout_seconds),
            )
        except ForkRpcUnavailableError as exc:
            return finish(ScannerStatus.UNAVAILABLE, str(exc))
        except ForkRpcBindingError as exc:
            return finish(ScannerStatus.FAILED, str(exc))

        workspace = private_dir / "workspace"
        environment = sanitized_scanner_environment(private_dir)
        copied_compiler = private_dir / "toolchain" / "solc"
        try:
            copy_scanner_workspace(root, workspace, private_dir)
            if scanner_workspace_sha256(workspace) != selection.repository_sha256:
                raise ValueError("disposable scanner workspace differs from the selected source")
            version = isolated_executable_version(
                executable_path,
                environment,
                backend,
                workspace,
                private_dir,
            )
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
            assert compiler_path is not None
            compiler_version = isolated_executable_version(
                compiler_path,
                environment,
                backend,
                workspace,
                private_dir,
            )
            if (
                compiler_version is None
                or self.config.solc_version is None
                or re.search(
                    rf"(?<![0-9.]){re.escape(self.config.solc_version)}(?![0-9.])",
                    compiler_version,
                )
                is None
            ):
                return finish(
                    ScannerStatus.FAILED,
                    "Solidity compiler version does not match the configured trust pin",
                )
            copied_compiler.parent.mkdir(mode=0o700)
            shutil.copyfile(compiler_path, copied_compiler)
            copied_compiler.chmod(0o500)
            if _file_sha256(copied_compiler) != compiler_sha256:
                raise ValueError("copied Solidity compiler differs from its trust pin")
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
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
            return finish(
                ScannerStatus.FAILED,
                f"fork-suite workspace preflight failed: {type(exc).__name__}",
            )

        deadline = time.monotonic() + total_timeout
        total_output_bytes = 0
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
            observation, private_output_bytes = _execute_foundry_test(
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
                timeout_seconds=min(remaining, per_test_timeout),
                max_output_bytes=self.config.repository_suite.max_output_bytes_per_test,
                backend=backend,
                base_environment=environment,
            )
            observations.append(observation)
            try:
                compiler_unchanged = _file_sha256(copied_compiler) == compiler_sha256
            except OSError:
                compiler_unchanged = False
            if not compiler_unchanged:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "pinned Solidity compiler changed during repository execution"
                break
            total_output_bytes += private_output_bytes
            if total_output_bytes > self.config.repository_suite.max_total_output_bytes:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "repository fork-suite output exceeded the total byte ceiling"
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
        if not _selection_sources_unchanged(root, selection):
            terminal_status = ScannerStatus.FAILED
            terminal_error = "repository fork-suite source changed after selection"
        else:
            try:
                final_selection = select_foundry_repository_suite(
                    root,
                    projects,
                    self.config,
                    private_dir=private_dir,
                )
            except RepositorySuiteSelectionError:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "repository fork-suite selection changed during execution"
            else:
                if final_selection.selection_sha256 != selection.selection_sha256:
                    terminal_status = ScannerStatus.FAILED
                    terminal_error = "repository fork-suite selection changed during execution"
        try:
            final_fork = observe_pinned_fork_rpc(
                rpc_url,
                expected_chain_id=self.reproduction.expected_chain_id,
                pinned_block_number=self.reproduction.pinned_block_number,
                timeout_seconds=min(5.0, self.config.repository_suite.per_test_timeout_seconds),
            )
        except ForkRpcUnavailableError:
            terminal_status = ScannerStatus.UNAVAILABLE
            terminal_error = "configured loopback fork RPC became unavailable after execution"
        except ForkRpcBindingError:
            terminal_status = ScannerStatus.FAILED
            terminal_error = "configured loopback fork identity changed after execution"
        else:
            if final_fork != fork:
                terminal_status = ScannerStatus.FAILED
                terminal_error = "configured loopback fork state changed during execution"
        try:
            workspace_unchanged = scanner_workspace_sha256(workspace) == selection.repository_sha256
        except (OSError, ValueError):
            workspace_unchanged = False
        if not workspace_unchanged:
            terminal_status = ScannerStatus.FAILED
            terminal_error = "disposable scanner workspace changed during repository execution"
        return finish(terminal_status, terminal_error)

    def _fork_rpc_url(self) -> str:
        """Retain the legacy command-builder interface with strict loopback validation."""

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


def _default_foundry_projects(root: Path) -> tuple[SolidityProjectMetadata, ...]:
    if not _looks_like_foundry_project(root):
        return ()
    test_directories = [
        name
        for name in ("test", "tests")
        if (root / name).is_dir() and not (root / name).is_symlink()
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
        descriptor.test_name,
        "--fuzz-runs",
        str(fuzz_runs),
        "--fuzz-seed",
        fuzz_seed,
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


def _process_output_sha256(stdout_path: Path, stderr_path: Path) -> str:
    """Bind both bounded process streams without exposing their contents."""

    payload = {
        "stderr_bytes": stderr_path.stat().st_size,
        "stderr_sha256": _file_sha256(stderr_path),
        "stdout_bytes": stdout_path.stat().st_size,
        "stdout_sha256": _file_sha256(stdout_path),
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
    timeout_seconds: float,
    max_output_bytes: int,
    backend: ScannerIsolationBackend,
    base_environment: dict[str, str],
) -> tuple[_FoundryTestObservation, int]:
    del selection
    started = time.monotonic()
    execution_dir = private_dir / "repository-suite" / f"{output_index:05d}"
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
            0,
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
            0,
        )
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
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    _stop_process(process)
                    break
                if raw_path.stat().st_size + error_path.stat().st_size > max_output_bytes:
                    output_exceeded = True
                    _stop_process(process)
                    break
                time.sleep(0.05)
            return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            _stop_process(process)
            return_code = process.returncode
    except OSError as exc:
        process_error = f"fork-test process failed: {type(exc).__name__}"
    cleanup_error = _cleanup_error(backend, private_dir)
    output_bytes = sum(path.stat().st_size for path in (raw_path, error_path) if path.is_file())
    output_sha256 = (
        _process_output_sha256(raw_path, error_path)
        if raw_path.is_file() and error_path.is_file()
        else None
    )
    duration_seconds = time.monotonic() - started
    if cleanup_error or process_error:
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail=cleanup_error or process_error,
                duration_seconds=duration_seconds,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            output_bytes,
        )
    if timed_out:
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.TIMED_OUT,
                terminal_detail="Foundry repository test exceeded its fixed timeout",
                duration_seconds=duration_seconds,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            output_bytes,
        )
    if output_exceeded or output_bytes > max_output_bytes:
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail="Foundry repository test exceeded its output byte ceiling",
                duration_seconds=duration_seconds,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            output_bytes,
        )
    try:
        stdout = raw_path.read_text(encoding="utf-8")
        precondition_error = _foundry_machine_result_precondition(
            return_code=return_code,
            stdout=stdout,
        )
        if precondition_error is not None:
            return (
                _FoundryTestObservation(
                    descriptor=descriptor,
                    status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                    terminal_detail=precondition_error,
                    duration_seconds=duration_seconds,
                    command_sha256=command_sha256,
                    output_sha256=output_sha256,
                    output_bytes=output_bytes,
                    process_exit_code=return_code,
                    machine_output_validated=False,
                ),
                output_bytes,
            )
        status, detail, summary, machine_result_sha256 = _parse_exact_foundry_test(
            stdout,
            descriptor=descriptor,
            return_code=return_code,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return (
            _FoundryTestObservation(
                descriptor=descriptor,
                status=RepositoryTestExecutionStatus.INVALID_OUTPUT,
                terminal_detail=f"invalid exact Forge JSON result: {type(exc).__name__}",
                duration_seconds=duration_seconds,
                command_sha256=command_sha256,
                output_sha256=output_sha256,
                output_bytes=output_bytes,
                process_exit_code=return_code,
                machine_output_validated=False,
            ),
            output_bytes,
        )
    return (
        _FoundryTestObservation(
            descriptor=descriptor,
            status=status,
            terminal_detail=detail,
            duration_seconds=duration_seconds,
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
        output_bytes,
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


def _selection_sources_unchanged(root: Path, selection: RepositorySuiteSelection) -> bool:
    try:
        resolved_root = root.resolve(strict=True)
        for descriptor in selection.tests:
            path = resolved_root.joinpath(*PurePosixPath(descriptor.path).parts)
            if path.is_symlink() or path.is_junction() or not path.is_file():
                return False
            if path.resolve(strict=True).relative_to(resolved_root).as_posix() != descriptor.path:
                return False
            if _file_sha256(path) != descriptor.source_sha256:
                return False
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
) -> list[RepositoryTestExecution]:
    by_descriptor = {
        observation.descriptor.descriptor_sha256: observation for observation in observations
    }
    if len(by_descriptor) != len(observations):
        raise ValueError("repository fork suite emitted duplicate execution observations")
    executions: list[RepositoryTestExecution] = []
    for descriptor in selection.tests:
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
    return executions


def _repository_test_findings(
    root: Path,
    executions: list[RepositoryTestExecution],
    selection: RepositorySuiteSelection,
) -> list[ScannerFinding]:
    descriptors = {descriptor.descriptor_sha256: descriptor for descriptor in selection.tests}
    failure_statuses = {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
    findings: list[ScannerFinding] = []
    for execution in executions:
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
            path=descriptor.path,
            start_line=descriptor.start_line,
            end_line=descriptor.end_line,
            metadata={
                "class": "repository_fork_suite",
                "fork_only": True,
                "test_name": execution.test_name,
                "suite_name": execution.suite_name,
                "chain_id": execution.chain_id,
                "block_number": execution.block_number,
                "repository_test_execution_sha256": execution.execution_sha256,
            },
        )
        if finding is None:
            raise ValueError("repository fork-test finding location could not be normalized")
        findings.append(finding)
    return findings


def _write_repository_suite_manifest(
    private_dir: Path,
    selection: RepositorySuiteSelection,
    execution_policy: RepositorySuiteExecutionPolicy | None,
    executions: list[RepositoryTestExecution],
) -> Path:
    path = private_dir / "repository-suite-execution.json"
    payload = {
        "schema_version": "1.0",
        "selection": selection.model_dump(mode="json"),
        "execution_policy": (
            execution_policy.model_dump(mode="json") if execution_policy is not None else None
        ),
        "executions": [execution.model_dump(mode="json") for execution in executions],
        "safety_claim": False,
    }
    path.write_text(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _finalize_foundry_repository_suite(
    *,
    root: Path,
    private_dir: Path,
    backend: ScannerIsolationBackend | None,
    start: datetime,
    monotonic_start: float,
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
    fuzz_seed: str,
) -> ScannerRun:
    cleanup_error = _cleanup_error(backend, private_dir)
    if cleanup_error is not None:
        status = ScannerStatus.FAILED
        error = cleanup_error
    attestation = isolation_attestation_sha256(backend)
    isolation_backend = str(getattr(backend, "name", "")) or None if backend is not None else None
    attempted_statuses = {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    }
    attempted = any(observation.status in attempted_statuses for observation in observations)
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
        )
        else ExecutionEvidenceKind.UNVERIFIED
    )
    executions: list[RepositoryTestExecution] = []
    findings: list[ScannerFinding] = []
    foundry_summary: FoundryTestExecutionSummary | None = None
    manifest_path: Path | None = None
    if selection is not None:
        fallback_detail = error or "repository fork test was not executed"
        try:
            executions = _repository_test_executions(
                selection=selection,
                observations=observations,
                fallback_detail=fallback_detail,
                fork=fork,
                fuzz_seed=fuzz_seed,
                execution_evidence=execution_evidence,
                repository_code_execution=repository_code_execution,
                isolation_backend=isolation_backend,
                isolation_attestation=attestation,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                execution_policy=execution_policy,
            )
            findings = _repository_test_findings(root, executions, selection)
            if status is ScannerStatus.SUCCESS:
                foundry_summary = _aggregate_foundry_summaries(observations)
                if foundry_summary is None:
                    raise ValueError("successful repository suite lacks complete typed outcomes")
            manifest_path = _write_repository_suite_manifest(
                private_dir,
                selection,
                execution_policy,
                executions,
            )
        except (OSError, ValueError) as exc:
            status = ScannerStatus.FAILED
            error = f"repository fork-suite evidence finalization failed: {type(exc).__name__}"
            execution_evidence = ExecutionEvidenceKind.UNVERIFIED
            executions = _repository_test_executions(
                selection=selection,
                observations=observations,
                fallback_detail=error,
                fork=fork,
                fuzz_seed=fuzz_seed,
                execution_evidence=execution_evidence,
                repository_code_execution=repository_code_execution,
                isolation_backend=isolation_backend,
                isolation_attestation=attestation,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                execution_policy=execution_policy,
            )
            findings = _repository_test_findings(root, executions, selection)
            foundry_summary = None
            manifest_path = None
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
    raw_output_path = (
        str(manifest_path.relative_to(private_dir.parent)) if manifest_path is not None else None
    )
    run = ScannerRun(
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
        raw_output_sha256=(_file_sha256(manifest_path) if manifest_path is not None else None),
        raw_output_bytes=manifest_path.stat().st_size if manifest_path is not None else 0,
        process_exit_code=process_exit_code,
        isolation_backend=isolation_backend,
        isolation_attestation_sha256=attestation,
        machine_output_validated=(status is ScannerStatus.SUCCESS and foundry_summary is not None),
        foundry_summary=foundry_summary,
        repository_suite_selection=selection,
        repository_suite_execution_policy=execution_policy,
        repository_test_executions=executions,
        repository_code_execution=repository_code_execution,
    )
    return ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )


def _looks_like_foundry_project(root: Path) -> bool:
    return (root / "foundry.toml").is_file() or any(
        path.suffix == ".sol"
        for path in [*root.glob("src/**/*.sol"), *root.glob("contracts/**/*.sol")]
    )


def _reject_unsafe_foundry_configuration(root: Path) -> None:
    foundry_configs = [
        path
        for path in root.glob("**/foundry.toml")
        if not {".git", ".mmaudit", "node_modules"}.intersection(path.relative_to(root).parts)
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

        resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if sys.platform != "darwin" and hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
