"""Fail-closed boundary for repository-supplied Hardhat fork suites."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.isolation.container import RootlessContainerBackend
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    HardhatReporterExecution,
    HardhatReporterInventory,
    RepositoryCodeExecutionState,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.base import ScannerAdapter, ScannerIsolationBackend

_HARDHAT_CONFIG_NAMES = (
    "hardhat.config.cjs",
    "hardhat.config.js",
    "hardhat.config.mjs",
    "hardhat.config.ts",
)
_DIGEST_PINNED_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CONFIGURATION_BYTES = 1_000_000
_CONFIGURATION_READ_CHUNK_BYTES = 64 * 1024
_MAX_REPORT_BYTES = 100_000_000
_DESCRIPTOR_RELATIVE_OPEN_SUPPORTED = os.open in os.supports_dir_fd
_DESCRIPTOR_RELATIVE_STAT_SUPPORTED = os.stat in os.supports_dir_fd
_NOFOLLOW_STAT_SUPPORTED = os.stat in os.supports_follow_symlinks
_UNSAFE_CONFIGURATION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bnetworks?\s*[:=]", re.IGNORECASE), "repository-defined network settings"),
    (
        re.compile(
            r"\b(?:child_process|node:child_process|execSync|spawnSync|"
            r"execFile|spawn|shelljs|execa)\b",
            re.IGNORECASE,
        ),
        "process or shell execution",
    ),
    (
        re.compile(r"\b(?:task|subtask)\s*\(", re.IGNORECASE),
        "repository-defined task hooks",
    ),
    (
        re.compile(
            r"\b(?:process\.env|dotenv|mnemonic|private[_-]?key|wallet)\b",
            re.IGNORECASE,
        ),
        "wallet, private-key, or environment credential material",
    ),
    (
        re.compile(r"(?:https?|wss?)://", re.IGNORECASE),
        "repository-defined network endpoint",
    ),
)
_LIFECYCLE_SCRIPTS = frozenset(
    {
        "install",
        "postinstall",
        "postpack",
        "preinstall",
        "prepack",
        "prepare",
        "prepublish",
        "prepublishonly",
    }
)
_UNSAFE_PACKAGE_SCRIPT = re.compile(
    r"(?:[;&|`$<>]|\r|\n|\b(?:bash|curl|wget|ssh|nc|netcat|powershell)\b|"
    r"\bnode\s+-e\b|\bhardhat\s+(?:node|run)\b|--network\b|--config\b)",
    re.IGNORECASE,
)
_SENSITIVE_PACKAGE_KEY = re.compile(
    r"(?:mnemonic|private[_-]?key|wallet)",
    re.IGNORECASE,
)
_UNSAFE_DEPENDENCY = re.compile(
    r"(?:^|/)(?:ffi-napi|node-ffi|shelljs|execa|zx)$",
    re.IGNORECASE,
)


class HardhatReporterError(ValueError):
    """Trusted Hardhat reporter output or selection failed strict validation."""


@runtime_checkable
class HardhatSingleLoopbackIsolationBackend(Protocol):
    """Dedicated boundary required before any repository JavaScript may execute."""

    name: str
    image: str
    rootless_verified: bool
    approved_loopback_rpc_port: int
    hardhat_network_policy: str
    broad_network_enabled: bool
    hardhat_loopback_capability_sha256: str

    def wrap_hardhat_fork_suite(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]: ...

    def writable_path(self, private_dir: Path) -> Path: ...

    def cleanup(self, private_dir: Path) -> None: ...

    def host_environment(self, private_dir: Path) -> dict[str, str]: ...


class HardhatForkScanner(ScannerAdapter):
    """Refuse Hardhat execution until its exact rootless fork boundary is attested."""

    name = "hardhat_fork"
    executable = "hardhat"
    may_execute_repository_code = True
    strict_machine_output = True

    def __init__(
        self,
        smart_contracts: SmartContractsConfig,
        scanner_config: ScannerConfig,
    ) -> None:
        self.smart_contracts = smart_contracts
        self.scanner_config = scanner_config

    def with_runtime_allowance(self, allow_fork_probing: bool) -> HardhatForkScanner:
        """Return an immutable runtime view of the explicit CLI/config acknowledgement."""

        return HardhatForkScanner(
            self.smart_contracts.model_copy(
                update={
                    "allow_fork_probing": (
                        self.smart_contracts.allow_fork_probing or allow_fork_probing
                    )
                }
            ),
            self.scanner_config,
        )

    def available(self) -> bool:
        """Host PATH discovery cannot prove an in-container Hardhat toolchain."""

        return False

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        """Reject an unbound command that could silently execute the full target suite."""

        del root, private_dir
        raise ValueError(
            "Hardhat execution requires an exact reporter inventory and selection hash"
        )

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        """Reject unbound output; callers must supply explicit selection and trust pins."""

        del root, stdout, private_dir
        raise ValueError(
            "Hardhat reporter output requires explicit selection, fork, and reporter bindings"
        )

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
        """Perform only fail-closed preflight; never execute target JavaScript here."""

        del timeout_seconds
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()

        def finish(status: ScannerStatus, error: str) -> ScannerRun:
            run = ScannerRun(
                scanner=self.name,
                status=status,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=error,
                isolation_backend=(
                    str(getattr(backend, "name", "")) or None if backend is not None else None
                ),
                isolation_attestation_sha256=isolation_attestation_sha256(backend),
                repository_code_execution=RepositoryCodeExecutionState.BLOCKED,
            )
            return ScannerRun.model_validate(
                {
                    **run.model_dump(mode="json"),
                    "execution_observation_sha256": (run.expected_execution_observation_sha256()),
                }
            )

        if not self.scanner_config.enabled:
            return finish(ScannerStatus.SKIPPED, "Hardhat fork-suite scanner is disabled")
        if not self.smart_contracts.enabled:
            return finish(ScannerStatus.SKIPPED, "smart-contract analysis is disabled")
        if not self.smart_contracts.allow_fork_probing:
            return finish(
                ScannerStatus.SKIPPED,
                "Hardhat fork probing requires explicit operator acknowledgement",
            )
        suite_config = self.smart_contracts.repository_suite
        if not suite_config.hardhat_include_paths or not suite_config.hardhat_include_tests:
            return finish(
                ScannerStatus.SKIPPED,
                "Hardhat repository-suite selection is disabled",
            )

        backend_error = _rootless_backend_error(backend)
        if backend_error is not None:
            return finish(ScannerStatus.UNAVAILABLE, backend_error)

        if expected_version is None:
            expected_version = self.scanner_config.version
        if expected_sha256 is None:
            expected_sha256 = self.scanner_config.sha256
        if expected_version is None or expected_sha256 is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                "Hardhat fork execution requires paired in-container toolchain trust pins",
            )

        rpc_value = _fork_rpc_value(self.smart_contracts)
        if rpc_value is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                f"{self.smart_contracts.fork_rpc_url_env} is not set",
            )
        try:
            rpc_port = _loopback_rpc_port(rpc_value)
        except ValueError:
            return finish(
                ScannerStatus.FAILED,
                "Hardhat fork RPC must be one credential-free plain HTTP loopback endpoint",
            )

        assert isinstance(backend, HardhatSingleLoopbackIsolationBackend)
        approved_port = getattr(backend, "approved_loopback_rpc_port", None)
        if (
            not isinstance(approved_port, int)
            or isinstance(approved_port, bool)
            or approved_port != rpc_port
        ):
            return finish(
                ScannerStatus.UNAVAILABLE,
                "rootless isolation has no attested single-port loopback RPC capability",
            )

        try:
            configuration_error = _target_configuration_error(root)
        except (OSError, UnicodeError, ValueError):
            return finish(
                ScannerStatus.FAILED,
                "Hardhat repository configuration could not be validated safely",
            )
        if configuration_error is not None:
            return finish(ScannerStatus.FAILED, configuration_error)

        return finish(
            ScannerStatus.UNAVAILABLE,
            "trusted Hardhat reporter parsing and selection are implemented, but no "
            "production single-loopback backend executes the two-phase inventory/test protocol",
        )


def _rootless_backend_error(backend: object | None) -> str | None:
    if type(backend) is RootlessContainerBackend:
        return (
            "the current no-network RootlessContainerBackend is not a dedicated "
            "single-loopback Hardhat capability"
        )
    if not isinstance(backend, HardhatSingleLoopbackIsolationBackend):
        return (
            "Hardhat fork suites require a dedicated digest-pinned rootless "
            "single-loopback-RPC capability"
        )
    if (
        backend.rootless_verified is not True
        or _DIGEST_PINNED_IMAGE.fullmatch(backend.image) is None
    ):
        return "Hardhat fork suites require a verified digest-pinned rootless container"
    if (
        backend.hardhat_network_policy != "single-loopback-rpc"
        or backend.broad_network_enabled is not False
    ):
        return "Hardhat isolation must deny broad networking and allow one loopback RPC only"
    if isolation_execution_evidence(backend) is not ExecutionEvidenceKind.REAL:
        return "rootless Hardhat isolation lacks process-attested REAL provenance"
    process_attestation = isolation_attestation_sha256(backend)
    if process_attestation is None:
        return "rootless Hardhat isolation lacks a current process attestation"
    capability_sha256 = backend.hardhat_loopback_capability_sha256
    if _SHA256.fullmatch(capability_sha256) is None:
        return "Hardhat isolation has an invalid single-loopback capability identity"
    if _hardhat_loopback_capability_attestation_sha256(backend) != capability_sha256:
        return "Hardhat single-loopback capability lacks a current process-bound attestation"
    return None


def _hardhat_loopback_capability_attestation_sha256(
    backend: HardhatSingleLoopbackIsolationBackend,
) -> str | None:
    """Return no credit until a production process probe seals this exact capability."""

    del backend
    return None


def _fork_rpc_value(config: SmartContractsConfig) -> str | None:
    """Read only the operator-selected fork variable, never target dotenv files."""

    value = os.environ.get(config.fork_rpc_url_env)
    return value if value else None


def _loopback_rpc_port(value: str) -> int:
    parsed = urlparse(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.port is None
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid loopback RPC")
    return parsed.port


def _strict_report_object(content: str, *, maximum_bytes: int) -> dict[str, Any]:
    if not 1_024 <= maximum_bytes <= _MAX_REPORT_BYTES:
        raise HardhatReporterError("Hardhat reporter byte ceiling is out of bounds")
    try:
        encoded = content.encode("utf-8")
    except UnicodeError as exc:
        raise HardhatReporterError("Hardhat reporter output is not valid UTF-8") from exc
    if not encoded or len(encoded) > maximum_bytes:
        raise HardhatReporterError("Hardhat reporter output is empty or exceeds its byte ceiling")
    try:
        return _strict_json_object(content)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HardhatReporterError("Hardhat reporter output is not one strict JSON object") from exc


def parse_hardhat_inventory_report(
    content: str,
    *,
    expected_reporter_version: str,
    expected_reporter_sha256: str,
    expected_repository_sha256: str,
    maximum_bytes: int,
) -> HardhatReporterInventory:
    """Parse one complete inventory without retaining unvalidated reporter output."""

    payload = _strict_report_object(content, maximum_bytes=maximum_bytes)
    try:
        inventory = HardhatReporterInventory.model_validate(payload)
    except ValueError as exc:
        raise HardhatReporterError("Hardhat reporter inventory failed strict validation") from exc
    if (
        inventory.reporter_version != expected_reporter_version
        or inventory.reporter_sha256 != expected_reporter_sha256
    ):
        raise HardhatReporterError("Hardhat reporter inventory differs from its trust pins")
    if inventory.repository_sha256 != expected_repository_sha256:
        raise HardhatReporterError("Hardhat reporter inventory differs from the frozen repository")
    return inventory


def select_hardhat_repository_suite(
    inventory: HardhatReporterInventory,
    smart_contracts: SmartContractsConfig,
    *,
    repository_exclusion_path: str,
) -> RepositorySuiteSelection:
    """Select an exact bounded Hardhat suite from trusted isolated inventory."""

    config = smart_contracts.repository_suite
    if not config.hardhat_include_paths or not config.hardhat_include_tests:
        raise HardhatReporterError("Hardhat repository-suite selection is disabled")
    descriptors: list[RepositorySuiteTestDescriptor] = []
    exact_bare_matches: dict[str, set[tuple[str, str, str]]] = {
        pattern: set()
        for pattern in config.hardhat_include_tests
        if not any(character in pattern for character in "*?[")
    }
    per_file_counts: dict[tuple[str, str], int] = {}
    candidate_files = {(descriptor.project_root, descriptor.path) for descriptor in inventory.tests}

    for descriptor in inventory.tests:
        if not _matches_any(descriptor.path, config.hardhat_include_paths):
            continue
        if _matches_any(descriptor.path, config.hardhat_exclude_paths):
            continue
        stable_id = f"{descriptor.path}:{descriptor.suite_name}:{descriptor.test_name}"
        if not _matches_hardhat_test(
            descriptor.test_name,
            stable_id,
            config.hardhat_include_tests,
        ):
            continue
        if _matches_hardhat_test(
            descriptor.test_name,
            stable_id,
            config.hardhat_exclude_tests,
        ):
            continue
        file_key = (descriptor.project_root, descriptor.path)
        per_file_counts[file_key] = per_file_counts.get(file_key, 0) + 1
        if per_file_counts[file_key] > config.max_tests_per_file:
            raise HardhatReporterError(
                f"selected Hardhat tests exceed per-file ceiling for {descriptor.path}"
            )
        for exact_name in exact_bare_matches:
            if descriptor.test_name == exact_name:
                exact_bare_matches[exact_name].add(
                    (descriptor.path, descriptor.suite_name, descriptor.test_name)
                )
        descriptors.append(descriptor)

    for exact_name, matches in exact_bare_matches.items():
        if len(matches) > 1:
            raise HardhatReporterError(
                f"exact bare Hardhat test selector is ambiguous: {exact_name}"
            )
    descriptors.sort(key=lambda item: item.canonical_key)
    if not descriptors:
        raise HardhatReporterError("Hardhat repository-suite selection matched zero tests")
    selected_files = {(descriptor.project_root, descriptor.path) for descriptor in descriptors}
    if len(selected_files) > config.max_selected_files:
        raise HardhatReporterError("selected Hardhat files exceed configured ceiling")
    if len(descriptors) > config.max_total_tests:
        raise HardhatReporterError("selected Hardhat tests exceed configured total ceiling")

    return RepositorySuiteSelection.sealed(
        profile=config.profile,
        repository_sha256=inventory.repository_sha256,
        repository_exclusion_path=repository_exclusion_path,
        configuration_sha256=config.stable_hash(),
        candidate_file_count=len(candidate_files),
        candidate_test_count=len(inventory.tests),
        selected_file_count=len(selected_files),
        selected_test_count=len(descriptors),
        omitted_file_count=len(candidate_files - selected_files),
        omitted_test_count=len(inventory.tests) - len(descriptors),
        limit_reached=False,
        tests=tuple(descriptors),
        safety_claim=False,
    )


def parse_hardhat_execution_report(
    content: str,
    *,
    selection: RepositorySuiteSelection,
    expected_reporter_version: str,
    expected_reporter_sha256: str,
    expected_chain_id: int,
    expected_block_number: int,
    expected_block_hash: str,
    expected_fuzz_seed: str,
    per_test_timeout_seconds: float,
    maximum_bytes: int,
) -> HardhatReporterExecution:
    """Parse and exactly bind one complete report to its pre-execution selection."""

    payload = _strict_report_object(content, maximum_bytes=maximum_bytes)
    try:
        report = HardhatReporterExecution.model_validate(payload)
    except ValueError as exc:
        raise HardhatReporterError("Hardhat execution report failed strict validation") from exc
    if any(
        descriptor.framework is not RepositorySuiteFramework.HARDHAT
        for descriptor in selection.tests
    ):
        raise HardhatReporterError("Hardhat execution selection contains another framework")
    if (
        report.reporter_version != expected_reporter_version
        or report.reporter_sha256 != expected_reporter_sha256
    ):
        raise HardhatReporterError("Hardhat execution reporter differs from its trust pins")
    if (
        report.repository_sha256 != selection.repository_sha256
        or report.selection_sha256 != selection.selection_sha256
    ):
        raise HardhatReporterError("Hardhat execution report differs from its suite selection")
    if (
        report.chain_id != expected_chain_id
        or report.block_number != expected_block_number
        or report.block_hash != expected_block_hash
        or report.fuzz_seed != expected_fuzz_seed
    ):
        raise HardhatReporterError("Hardhat execution report differs from pinned fork state")
    expected_by_hash = {descriptor.descriptor_sha256: descriptor for descriptor in selection.tests}
    results_by_hash = {result.descriptor_sha256: result for result in report.results}
    if set(results_by_hash) != set(expected_by_hash):
        raise HardhatReporterError(
            "Hardhat execution report does not cover the exact selected test set"
        )
    if not 0 < per_test_timeout_seconds <= 1_800:
        raise HardhatReporterError("Hardhat per-test timeout is out of bounds")
    for descriptor_sha256, descriptor in expected_by_hash.items():
        result = results_by_hash[descriptor_sha256]
        if (
            result.path != descriptor.path
            or result.suite_name != descriptor.suite_name
            or result.test_name != descriptor.test_name
        ):
            raise HardhatReporterError(
                "Hardhat reporter test identity differs from its selected descriptor"
            )
        if result.duration_seconds > per_test_timeout_seconds:
            raise HardhatReporterError(
                "Hardhat reporter test exceeded the configured per-test deadline"
            )
    return report


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _matches_hardhat_test(
    test_name: str,
    stable_id: str,
    patterns: tuple[str, ...],
) -> bool:
    return any(
        fnmatch.fnmatchcase(test_name, pattern) or fnmatch.fnmatchcase(stable_id, pattern)
        for pattern in patterns
    )


def _target_configuration_error(root: Path) -> str | None:
    repository_path, repository_descriptor, root_snapshot = _open_repository_root(root)
    entry_names = (*_HARDHAT_CONFIG_NAMES, "package.json")
    observations: dict[str, os.stat_result | None] = {}
    try:
        for name in entry_names:
            observations[name] = _repository_entry_metadata(repository_descriptor, name)

        present_configs = [name for name in _HARDHAT_CONFIG_NAMES if observations[name] is not None]
        if not present_configs:
            return "no repository-root Hardhat configuration was found"
        for name in present_configs:
            expected = observations[name]
            assert expected is not None
            content = _bounded_regular_text(
                repository_descriptor,
                name,
                expected=expected,
            )
            for pattern, label in _UNSAFE_CONFIGURATION_PATTERNS:
                if pattern.search(content):
                    return f"Hardhat configuration contains prohibited {label}"

        package_metadata = observations["package.json"]
        if package_metadata is not None:
            payload = _strict_json_object(
                _bounded_regular_text(
                    repository_descriptor,
                    "package.json",
                    expected=package_metadata,
                )
            )
            package_error = _package_configuration_error(payload)
            if package_error is not None:
                return package_error
        return None
    finally:
        try:
            for name, expected in observations.items():
                observed = _repository_entry_metadata(repository_descriptor, name)
                if (expected is None) != (observed is None) or (
                    expected is not None
                    and observed is not None
                    and _configuration_snapshot(expected) != _configuration_snapshot(observed)
                ):
                    raise ValueError("Hardhat repository configuration changed during inspection")
            _validate_repository_root(
                repository_path,
                repository_descriptor,
                expected=root_snapshot,
            )
        finally:
            os.close(repository_descriptor)


def _open_repository_root(root: Path) -> tuple[Path, int, os.stat_result]:
    """Open and retain the exact non-link repository root used for all config reads."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow == 0
        or directory == 0
        or not _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED
        or not _DESCRIPTOR_RELATIVE_STAT_SUPPORTED
        or not _NOFOLLOW_STAT_SUPPORTED
    ):
        raise OSError("descriptor-relative no-follow repository access is unavailable")
    repository_path = root.absolute()
    named_before = repository_path.lstat()
    if (
        not stat.S_ISDIR(named_before.st_mode)
        or stat.S_ISLNK(named_before.st_mode)
        or repository_path.is_junction()
    ):
        raise ValueError("repository root must be a non-link directory")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            repository_path,
            os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0),
        )
        os.set_inheritable(descriptor, False)
        opened = os.fstat(descriptor)
        named_after = repository_path.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _configuration_snapshot(named_before) != _configuration_snapshot(opened)
            or _configuration_snapshot(opened) != _configuration_snapshot(named_after)
        ):
            raise ValueError("repository root changed while it was opened")
        return repository_path, descriptor, opened
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _validate_repository_root(
    path: Path,
    descriptor: int,
    *,
    expected: os.stat_result,
) -> None:
    opened_after = os.fstat(descriptor)
    named_after = path.lstat()
    if (
        not stat.S_ISDIR(opened_after.st_mode)
        or not stat.S_ISDIR(named_after.st_mode)
        or _configuration_snapshot(expected) != _configuration_snapshot(opened_after)
        or _configuration_snapshot(opened_after) != _configuration_snapshot(named_after)
    ):
        raise ValueError("repository root changed during configuration inspection")


def _repository_entry_metadata(
    repository_descriptor: int,
    name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            name,
            dir_fd=repository_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


def _bounded_regular_text(
    repository_descriptor: int,
    name: str,
    *,
    expected: os.stat_result,
) -> str:
    """Read one stable root-relative file without following a raced path."""

    if (
        not stat.S_ISREG(expected.st_mode)
        or expected.st_nlink != 1
        or expected.st_size > _MAX_CONFIGURATION_BYTES
    ):
        raise ValueError("Hardhat configuration must be a bounded unique regular file")
    named_before = os.stat(
        name,
        dir_fd=repository_descriptor,
        follow_symlinks=False,
    )
    if _configuration_snapshot(named_before) != _configuration_snapshot(expected):
        raise ValueError("Hardhat configuration changed before it was read")

    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | _required_configuration_nofollow()
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor = os.open(name, flags, dir_fd=repository_descriptor)
        os.set_inheritable(descriptor, False)
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _configuration_snapshot(opened_before) != _configuration_snapshot(named_before)
        ):
            raise ValueError("Hardhat configuration changed before it was read")

        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(
                    _CONFIGURATION_READ_CHUNK_BYTES,
                    _MAX_CONFIGURATION_BYTES - consumed + 1,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > _MAX_CONFIGURATION_BYTES:
                raise ValueError("Hardhat configuration file exceeds its byte ceiling")
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=repository_descriptor,
            follow_symlinks=False,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)

    snapshots = {
        _configuration_snapshot(expected),
        _configuration_snapshot(named_before),
        _configuration_snapshot(opened_before),
        _configuration_snapshot(opened_after),
        _configuration_snapshot(named_after),
    }
    if (
        len(snapshots) != 1
        or not stat.S_ISREG(named_after.st_mode)
        or named_after.st_nlink != 1
        or len(raw) != opened_before.st_size
    ):
        raise ValueError("Hardhat configuration changed while it was read")
    return raw.decode("utf-8")


def _required_configuration_nofollow() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0 or not _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED:
        raise OSError("descriptor-relative no-follow configuration access is unavailable")
    return no_follow


def _configuration_snapshot(
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


def _strict_json_object(content: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("package.json contains duplicate keys")
            result[key] = value
        return result

    payload = json.loads(content, object_pairs_hook=unique_object)
    if not isinstance(payload, dict):
        raise ValueError("package.json must be an object")
    return payload


def _package_configuration_error(payload: dict[str, Any]) -> str | None:
    if _contains_sensitive_package_key(payload):
        return "Hardhat package configuration contains wallet or private-key material"

    scripts = payload.get("scripts", {})
    if not isinstance(scripts, dict):
        return "Hardhat package scripts must be an object"
    for raw_name, raw_command in scripts.items():
        if not isinstance(raw_name, str) or not isinstance(raw_command, str):
            return "Hardhat package scripts must contain string commands"
        name = raw_name.casefold()
        if name in _LIFECYCLE_SCRIPTS or name.startswith(("pre", "post")):
            return "Hardhat package configuration contains prohibited lifecycle hooks"
        if _UNSAFE_PACKAGE_SCRIPT.search(raw_command):
            return "Hardhat package configuration contains prohibited shell or network hooks"

    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = payload.get(field, {})
        if not isinstance(dependencies, dict):
            return f"Hardhat {field} must be an object"
        if any(isinstance(name, str) and _UNSAFE_DEPENDENCY.search(name) for name in dependencies):
            return "Hardhat package configuration contains a prohibited execution dependency"
    return None


def _contains_sensitive_package_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            _SENSITIVE_PACKAGE_KEY.search(str(key)) is not None
            or _contains_sensitive_package_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_package_key(item) for item in value)
    return False
