"""Common read-only scanner process and normalization interface."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from mmaudit.isolation.container import (
    RepositoryJavaScriptIsolationBackend,
    cleanup_isolation_backend,
    isolation_host_environment,
)
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.isolation.repository_code import contains_hardhat_repository_code
from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
    Location,
    RepositoryCodeExecutionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.workspace import (
    audited_workspace_bindings_sha256,
    audited_workspace_exclusion_root,
    audited_workspace_relative_excluded,
    require_audited_workspace_paths_included,
)
from mmaudit.scanners.diagnostics import (
    ExecutableVersionProbe,
    ExecutableVersionProbeStatus,
    ScannerExecutablePreflight,
    ScannerExecutableState,
    select_public_tool_version_line,
)
from mmaudit.solidity.reproduction import MacOSToolchainResolutionError

_MAX_WORKSPACE_ENTRIES = 100_000
_MAX_WORKSPACE_FILES = 100_000
_MAX_WORKSPACE_FILE_BYTES = 100_000_000
_MAX_WORKSPACE_BYTES = 2 * 1024**3
_MAX_WORKSPACE_DEPTH = 128
_WORKSPACE_READ_BYTES = 1024 * 1024
_VERSION_PROBE_OUTPUT_BYTES = 64 * 1024
_SCANNER_OUTPUT_CAPTURE_BYTES = 50_000_000
_VERSION_PROBE_MEMORY_BYTES = 1024**3
_SCANNER_MEMORY_BYTES = 4 * 1024**3
_DARWIN_PROCESS_TREE_MAXIMUM = 128
_VERSION_PROBE_POLL_SECONDS = 0.02
_INTERPRETER_OR_LOADER_FAILURE_MARKERS = (
    "bad interpreter",
    "cannot open shared object file",
    "could not find platform independent libraries",
    "dyld: library not loaded",
    "error while loading shared libraries",
    "fatal python error: init_fs_encoding",
    "library not loaded",
    "pythonhome =",
)

_INTERPRETER_OR_LOADER_DIAGNOSTIC = (
    "tool interpreter or dynamic loader could not initialize under the scrubbed isolated "
    "environment; install a self-contained tool distribution, for example with pipx or "
    "Homebrew"
)
_ISOLATION_FAILURE_DIAGNOSTIC = (
    "tool is present but its version command could not execute successfully under hardened "
    "isolation"
)
_INVALID_VERSION_DIAGNOSTIC = (
    "tool version is unavailable because its output was not bounded path-free single-line text"
)
_VERSION_TIMEOUT_DIAGNOSTIC = "tool version command timed out under hardened isolation"
_VERSION_MEMORY_DIAGNOSTIC = "tool version command exceeded the private memory limit"
_VERSION_MEMORY_MONITOR_DIAGNOSTIC = (
    "tool version command was stopped because private memory monitoring failed closed"
)
_SCANNER_MEMORY_DIAGNOSTIC = "scanner exceeded the private memory limit"
_SCANNER_MEMORY_MONITOR_DIAGNOSTIC = (
    "scanner stopped because private memory monitoring failed closed"
)
_VERSION_DESCENDANT_DIAGNOSTIC = (
    "tool version command left a descendant process after its leader exited"
)
_SCANNER_DESCENDANT_DIAGNOSTIC = "scanner left a descendant process after its leader exited"


@dataclass(frozen=True, slots=True)
class _WorkspaceIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _WorkspaceIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            links=metadata.st_nlink,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class _PrivateProbeStreamIdentity:
    device: int
    inode: int
    mode: int
    owner: int


@dataclass(frozen=True, slots=True)
class _WorkspaceDirectory:
    relative_path: str
    identity: _WorkspaceIdentity


@dataclass(frozen=True, slots=True)
class _WorkspaceFile:
    relative_path: str
    identity: _WorkspaceIdentity
    sha256: str


@dataclass(frozen=True, slots=True)
class _ScannerWorkspaceInventory:
    repository_root: Path
    root_identity: _WorkspaceIdentity
    directories: tuple[_WorkspaceDirectory, ...]
    files: tuple[_WorkspaceFile, ...]

    def bindings(self) -> list[dict[str, str | int]]:
        return [
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "size": item.identity.size,
            }
            for item in self.files
        ]

    def sha256(self) -> str:
        return audited_workspace_bindings_sha256(self.bindings())


@dataclass(frozen=True, slots=True)
class ScannerWorkspaceFileRecord:
    """Path-safe public projection of one file in the scanner source inventory."""

    relative_path: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ScannerWorkspaceTextRecord:
    """Descriptor-observed UTF-8 text bound to the full scanner source inventory."""

    relative_path: str
    raw_sha256: str
    size: int
    content: str
    lines: int


@dataclass(frozen=True, slots=True)
class ScannerWorkspaceCopyObservation:
    """Path-free facts observed while retaining both source-root descriptors."""

    source_inventory_sha256_before: str
    source_inventory_sha256_after: str
    workspace_inventory_sha256_after_copy: str
    workspace_inventory_sha256_after_execution: str
    source_root_device_before: int
    source_root_inode_before: int
    source_root_device_after: int
    source_root_inode_after: int
    workspace_root_device_before: int
    workspace_root_inode_before: int
    workspace_root_device_after: int
    workspace_root_inode_after: int
    workspace_parent_device: int
    workspace_parent_inode: int
    workspace_created_exclusively: bool = True
    workspace_direct_child: bool = True
    audited_inventory_symlink_free: bool = True
    source_descriptor_custody_validated: bool = True
    workspace_descriptor_custody_validated: bool = True
    workspace_parent_descriptor_custody_validated: bool = True
    copy_matches_source: bool = True
    source_identity_stable: bool = True
    workspace_identity_stable: bool = True
    workspace_removed: bool = False


@dataclass(slots=True)
class ScannerWorkspaceSourceCustody:
    """Retain and later revalidate one exact no-follow source inventory."""

    _source_root: Path
    _source_private_dir: Path
    _allow_custom_source_private_exclusion: bool
    _source_fd: int
    _source_before: _ScannerWorkspaceInventory
    _closed: bool = False

    @property
    def closed(self) -> bool:
        """Report whether the retained source descriptor has been released."""

        return self._closed

    @property
    def source_inventory_sha256_before(self) -> str:
        """Return the canonical audited source digest captured at acquisition."""

        return self._source_before.sha256()

    def finalize(self) -> str:
        """Revalidate exact source identity and bytes, then close custody."""

        if self._closed:
            raise ValueError("scanner workspace source custody is already closed")
        primary_error: BaseException | None = None
        try:
            _require_retained_workspace_root(
                self._source_root,
                self._source_fd,
                self._source_before.root_identity,
                label="source",
            )
            source_after = _build_scanner_workspace_inventory_from_descriptor(
                self._source_root,
                self._source_fd,
                self._source_private_dir,
                allow_custom_private_exclusion=(self._allow_custom_source_private_exclusion),
            )
            _require_retained_workspace_root(
                self._source_root,
                self._source_fd,
                self._source_before.root_identity,
                label="source",
            )
            if not _workspace_inventory_identity_stable(self._source_before, source_after):
                raise ValueError("scanner workspace source inventory changed during custody")
            return source_after.sha256()
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                self.close()
            except OSError:
                if primary_error is None:
                    raise

    def close(self) -> None:
        """Idempotently release the retained source descriptor."""

        if self._closed:
            return
        self._closed = True
        source_fd = self._source_fd
        self._source_fd = -1
        os.close(source_fd)


@dataclass(slots=True)
class ScannerWorkspaceCopyCustody:
    """Retain no-follow source/workspace root custody until final validation."""

    _source_root: Path
    _workspace_root: Path
    _workspace_parent_root: Path
    _source_private_dir: Path
    _allow_custom_source_private_exclusion: bool
    _source_fd: int
    _workspace_fd: int
    _workspace_parent_fd: int
    _workspace_parent_identity: _WorkspaceIdentity
    _source_before: _ScannerWorkspaceInventory
    _workspace_after_copy: _ScannerWorkspaceInventory
    _closed: bool = False

    @property
    def closed(self) -> bool:
        """Report whether both retained descriptors have been released."""

        return self._closed

    @property
    def source_inventory_sha256_before(self) -> str:
        """Return the audited source identity captured before copying."""

        return self._source_before.sha256()

    @property
    def workspace_inventory_sha256_after_copy(self) -> str:
        """Return the copied audited inventory identity before execution."""

        return self._workspace_after_copy.sha256()

    def finalize(self) -> ScannerWorkspaceCopyObservation:
        """Validate pre/post identity and audited inventory, then close custody."""

        if self._closed:
            raise ValueError("scanner workspace copy custody is already closed")
        primary_error: BaseException | None = None
        try:
            _require_retained_workspace_root(
                self._source_root,
                self._source_fd,
                self._source_before.root_identity,
                label="source",
            )
            _require_retained_workspace_root(
                self._workspace_root,
                self._workspace_fd,
                self._workspace_after_copy.root_identity,
                label="workspace",
            )
            _require_retained_workspace_root(
                self._workspace_parent_root,
                self._workspace_parent_fd,
                self._workspace_parent_identity,
                label="workspace parent",
            )
            _require_retained_workspace_child(
                self._workspace_parent_fd,
                self._workspace_root.name,
                self._workspace_after_copy.root_identity,
            )
            source_after = _build_scanner_workspace_inventory_from_descriptor(
                self._source_root,
                self._source_fd,
                self._source_private_dir,
                allow_custom_private_exclusion=(self._allow_custom_source_private_exclusion),
            )
            workspace_after = _build_scanner_workspace_inventory_from_descriptor(
                self._workspace_root,
                self._workspace_fd,
                self._workspace_root / ".mmaudit",
            )
            _require_retained_workspace_root(
                self._source_root,
                self._source_fd,
                self._source_before.root_identity,
                label="source",
            )
            _require_retained_workspace_root(
                self._workspace_root,
                self._workspace_fd,
                self._workspace_after_copy.root_identity,
                label="workspace",
            )
            _require_retained_workspace_root(
                self._workspace_parent_root,
                self._workspace_parent_fd,
                self._workspace_parent_identity,
                label="workspace parent",
            )
            _require_retained_workspace_child(
                self._workspace_parent_fd,
                self._workspace_root.name,
                self._workspace_after_copy.root_identity,
            )
            if not _workspace_inventory_identity_stable(self._source_before, source_after):
                raise ValueError("scanner workspace source inventory changed during execution")
            if not _workspace_inventory_identity_stable(
                self._workspace_after_copy,
                workspace_after,
            ):
                raise ValueError("scanner workspace inventory changed during execution")
            return ScannerWorkspaceCopyObservation(
                source_inventory_sha256_before=self._source_before.sha256(),
                source_inventory_sha256_after=source_after.sha256(),
                workspace_inventory_sha256_after_copy=self._workspace_after_copy.sha256(),
                workspace_inventory_sha256_after_execution=workspace_after.sha256(),
                source_root_device_before=self._source_before.root_identity.device,
                source_root_inode_before=self._source_before.root_identity.inode,
                source_root_device_after=source_after.root_identity.device,
                source_root_inode_after=source_after.root_identity.inode,
                workspace_root_device_before=self._workspace_after_copy.root_identity.device,
                workspace_root_inode_before=self._workspace_after_copy.root_identity.inode,
                workspace_root_device_after=workspace_after.root_identity.device,
                workspace_root_inode_after=workspace_after.root_identity.inode,
                workspace_parent_device=self._workspace_parent_identity.device,
                workspace_parent_inode=self._workspace_parent_identity.inode,
            )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                self.close()
            except OSError:
                if primary_error is None:
                    raise

    def close(self) -> None:
        """Idempotently release retained descriptors without removing the workspace."""

        if self._closed:
            return
        self._closed = True
        workspace_fd = self._workspace_fd
        source_fd = self._source_fd
        workspace_parent_fd = self._workspace_parent_fd
        self._workspace_fd = -1
        self._source_fd = -1
        self._workspace_parent_fd = -1
        _close_workspace_descriptors(workspace_fd, source_fd, workspace_parent_fd)


class ScannerIsolationBackend(Protocol):
    """Structural isolation interface shared with the execution subsystem."""

    @property
    def name(self) -> str: ...

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]: ...


def wrap_scanner_without_network(
    backend: ScannerIsolationBackend,
    command: list[str],
    *,
    workspace: Path,
    private_dir: Path,
) -> list[str]:
    """Wrap a static scanner command without granting a loopback entitlement."""

    no_network_wrapper = getattr(backend, "wrap_without_network", None)
    if callable(no_network_wrapper):
        wrapped = no_network_wrapper(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=0,
        )
        if not isinstance(wrapped, list) or not all(isinstance(item, str) for item in wrapped):
            raise ValueError("scanner isolation returned an invalid command")
        return wrapped
    return backend.wrap(
        command,
        workspace=workspace,
        private_dir=private_dir,
        rpc_port=0,
    )


class ScannerSourceIntegrityError(RuntimeError):
    """Scanner execution could not preserve the frozen audited source identity."""


def scanner_fingerprint(
    scanner: str,
    rule_id: str,
    path: str,
    line: int,
    message: str,
) -> str:
    stable = "\0".join((scanner, rule_id, path, str(line), message.strip().lower()))
    return hashlib.sha256(stable.encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_scanner_path(root: Path, raw_path: str) -> str | None:
    """Return a contained repository-relative path, never an external path."""

    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
        relative = resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    pure = PurePosixPath(relative.as_posix())
    if ".." in pure.parts:
        return None
    return pure.as_posix()


def severity_from_text(value: str | None) -> Severity:
    normalized = (value or "").lower()
    if normalized in {"critical", "error"}:
        return Severity.CRITICAL if normalized == "critical" else Severity.HIGH
    if normalized in {"high", "warning", "warn"}:
        return Severity.HIGH if normalized == "high" else Severity.MEDIUM
    if normalized in {"medium", "moderate"}:
        return Severity.MEDIUM
    if normalized in {"low", "note"}:
        return Severity.LOW
    return Severity.INFORMATIONAL


def safe_json(value: str) -> Any:
    if not value.strip():
        return {}
    return json.loads(value)


def positive_line(value: Any, default: int = 1) -> int:
    """Coerce scanner line metadata without accepting invalid or missing values."""

    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, parsed)


@dataclass(frozen=True, slots=True)
class ScannerExitClassification:
    """Bounded public diagnosis for one observed non-success scanner exit."""

    status: ScannerStatus
    diagnostic: str
    operator_preparation_step: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {
            ScannerStatus.NOT_APPLICABLE,
            ScannerStatus.UNMET_PREREQUISITE,
            ScannerStatus.SILENT_FAILURE,
        }:
            raise ValueError("scanner exit classification requires a typed non-success status")
        if (
            not self.diagnostic
            or self.diagnostic != self.diagnostic.strip()
            or len(self.diagnostic) > 1_000
            or any(ord(character) < 32 or ord(character) == 127 for character in self.diagnostic)
        ):
            raise ValueError("scanner exit classification requires a bounded diagnostic")
        if (self.status is ScannerStatus.UNMET_PREREQUISITE) != (
            self.operator_preparation_step is not None
        ):
            raise ValueError(
                "only an unmet scanner prerequisite may name an operator preparation step"
            )


class ScannerAdapter(ABC):
    """A fixed-command adapter; model output can never influence arguments."""

    name: str
    executable: str
    finding_exit_codes: frozenset[int] = frozenset({0, 1})
    max_stdout_bytes: int = 50_000_000
    max_stderr_bytes: int = 5_000_000
    may_execute_repository_code: bool = False
    strict_machine_output: bool = False

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    @abstractmethod
    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        """Return a trusted argument array."""

    @abstractmethod
    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        """Normalize scanner-specific machine-readable output."""

    def execution_working_directory(self, workspace: Path, private_dir: Path) -> Path:
        """Return the private execution directory for this fixed adapter command."""

        del private_dir
        return workspace

    def validate_pre_execution_inputs(self, workspace: Path, private_dir: Path) -> None:
        """Revalidate adapter-owned trusted inputs immediately before process launch."""

        del workspace, private_dir

    def classify_non_success_exit(
        self,
        *,
        return_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> ScannerExitClassification | None:
        """Recognize typed bounded outcomes without publishing untrusted tool output."""

        if return_code != 0 and not stdout and not stderr:
            return ScannerExitClassification(
                status=ScannerStatus.SILENT_FAILURE,
                diagnostic=(
                    "scanner exited nonzero without machine output or diagnostics; "
                    "inspect the named private stderr artifact"
                ),
            )
        return None

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
        """Run with the compatibility boundary used by direct adapter callers."""

        return self._run(
            root,
            private_dir,
            timeout_seconds,
            backend=backend,
            expected_version=expected_version,
            expected_sha256=expected_sha256,
        )

    def run_source_bound(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        expected_repository_sha256: str,
        audited_relative_paths: Sequence[str],
        repository_exclusion_root: Path | None = None,
        allow_custom_repository_exclusion: bool = False,
    ) -> ScannerRun:
        """Run against a copy proven equal to one frozen audited inventory."""

        return self._run(
            root,
            private_dir,
            timeout_seconds,
            backend=backend,
            expected_version=expected_version,
            expected_sha256=expected_sha256,
            expected_repository_sha256=expected_repository_sha256,
            audited_relative_paths=audited_relative_paths,
            repository_exclusion_root=repository_exclusion_root,
            allow_custom_repository_exclusion=allow_custom_repository_exclusion,
        )

    def _run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        expected_repository_sha256: str | None = None,
        audited_relative_paths: Sequence[str] = (),
        repository_exclusion_root: Path | None = None,
        allow_custom_repository_exclusion: bool = False,
    ) -> ScannerRun:
        """Run in a copied workspace and fail closed without hardened isolation."""

        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = sanitized_scanner_environment(private_dir)
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()
        loads_repository_code = (
            self.may_execute_repository_code and contains_hardhat_repository_code(root)
        )
        isolation_backend = (
            (str(getattr(backend, "name", "")) or None) if backend is not None else None
        )
        repository_code_execution = (
            RepositoryCodeExecutionState.BLOCKED
            if loads_repository_code
            else RepositoryCodeExecutionState.NOT_APPLICABLE
        )
        executable_sha256: str | None = None

        def finish(
            status: ScannerStatus,
            *,
            version: str | None = None,
            command: list[str] | None = None,
            findings: list[ScannerFinding] | None = None,
            error: str | None = None,
            raw_output_path: str | None = None,
            attested_output_sha256: str | None = None,
            attested_output_bytes: int = 0,
            private_stderr_path: str | None = None,
            private_stderr_sha256: str | None = None,
            private_stderr_bytes: int = 0,
            operator_preparation_step: str | None = None,
            process_exit_code: int | None = None,
            machine_output_validated: bool = False,
        ) -> ScannerRun:
            if raw_output_path is None and (
                attested_output_sha256 is not None or attested_output_bytes != 0
            ):
                raise ValueError("scanner output evidence requires a private relative path")
            if raw_output_path is not None and attested_output_sha256 is None:
                raise ValueError("scanner output path requires descriptor-attested evidence")
            if private_stderr_path is None and (
                private_stderr_sha256 is not None or private_stderr_bytes != 0
            ):
                raise ValueError("scanner stderr evidence requires a private relative path")
            if private_stderr_path is not None and private_stderr_sha256 is None:
                raise ValueError("scanner stderr path requires descriptor-attested evidence")
            run = ScannerRun(
                scanner=self.name,
                status=status,
                execution_evidence=(
                    isolation_execution_evidence(backend)
                    if (
                        status
                        in {
                            ScannerStatus.SUCCESS,
                            ScannerStatus.NOT_APPLICABLE,
                            ScannerStatus.UNMET_PREREQUISITE,
                            ScannerStatus.SILENT_FAILURE,
                        }
                        and executable_sha256 is not None
                        and bool(command)
                        and raw_output_path is not None
                        and isolation_backend is not None
                    )
                    else ExecutionEvidenceKind.UNVERIFIED
                ),
                version=version,
                executable_sha256=executable_sha256,
                command=command or [],
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                findings=findings or [],
                error=error,
                raw_output_path=raw_output_path,
                raw_output_sha256=attested_output_sha256,
                raw_output_bytes=attested_output_bytes,
                private_stderr_path=private_stderr_path,
                private_stderr_sha256=private_stderr_sha256,
                private_stderr_bytes=private_stderr_bytes,
                operator_preparation_step=operator_preparation_step,
                process_exit_code=process_exit_code,
                isolation_backend=isolation_backend,
                isolation_attestation_sha256=isolation_attestation_sha256(backend),
                machine_output_validated=machine_output_validated,
                repository_code_execution=repository_code_execution,
            )
            return ScannerRun.model_validate(
                {
                    **run.model_dump(mode="json"),
                    "execution_observation_sha256": (run.expected_execution_observation_sha256()),
                }
            )

        if loads_repository_code and not isinstance(
            backend,
            RepositoryJavaScriptIsolationBackend,
        ):
            return finish(
                ScannerStatus.UNAVAILABLE,
                error=(
                    "off-host repository-JavaScript isolation is unavailable; "
                    "Hardhat configuration and plugins were not executed"
                ),
            )
        if not loads_repository_code and not self.available():
            return finish(
                ScannerStatus.UNAVAILABLE,
                error=f"{self.executable} is not installed",
            )
        if backend is None:
            return finish(
                ScannerStatus.UNAVAILABLE,
                error="hardened scanner isolation is unavailable; scanner was not executed",
            )
        executable_path: Path | None = None
        if not loads_repository_code:
            executable_path = Path(shutil.which(self.executable) or "").resolve(strict=True)
            try:
                executable_path.relative_to(root.resolve(strict=True))
            except ValueError:
                pass
            else:
                return finish(
                    ScannerStatus.FAILED,
                    error="refusing scanner executable resolved from inside audited repository",
                )
            try:
                executable_sha256 = _file_sha256(executable_path)
            except OSError as exc:
                return finish(
                    ScannerStatus.FAILED,
                    error=f"could not hash scanner executable: {type(exc).__name__}",
                )
        workspace = private_dir / "workspace"
        try:
            copy_custody = copy_scanner_workspace_with_custody(
                root,
                workspace,
                repository_exclusion_root or private_dir,
                audited_relative_paths=audited_relative_paths,
                allow_custom_private_exclusion=allow_custom_repository_exclusion,
            )
            copy_observation = copy_custody.finalize()
        except (OSError, ValueError) as exc:
            if expected_repository_sha256 is not None:
                raise ScannerSourceIntegrityError(
                    "scanner source copy failed its frozen inventory validation"
                ) from exc
            return finish(
                ScannerStatus.FAILED,
                error=f"could not create isolated scanner workspace: {type(exc).__name__}",
            )
        if expected_repository_sha256 is not None and any(
            observed != expected_repository_sha256
            for observed in (
                copy_observation.source_inventory_sha256_before,
                copy_observation.source_inventory_sha256_after,
                copy_observation.workspace_inventory_sha256_after_copy,
                copy_observation.workspace_inventory_sha256_after_execution,
            )
        ):
            raise ScannerSourceIntegrityError(
                "isolated scanner workspace differs from the frozen audited source"
            )
        raw_path = private_dir / f"{self.name}.json"
        error_path = private_dir / f"{self.name}.stderr.txt"
        version: str | None = None
        try:
            command = self.build_command(workspace, private_dir)
            if not command:
                raise ValueError("scanner command must not be empty")
            command[0] = str(executable_path) if executable_path is not None else self.executable
            if loads_repository_code:
                assert isinstance(backend, RepositoryJavaScriptIsolationBackend)
                command = backend.wrap_repository_javascript(
                    command,
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=1,
                )
                repository_code_execution = RepositoryCodeExecutionState.ISOLATED
            else:
                command = wrap_scanner_without_network(
                    backend,
                    command,
                    workspace=workspace,
                    private_dir=private_dir,
                )
            version_probe = isolated_executable_version_probe(
                str(executable_path) if executable_path is not None else self.executable,
                environment,
                backend,
                workspace,
                private_dir,
                repository_javascript=loads_repository_code,
            )
            if version_probe.status is not ExecutableVersionProbeStatus.SUCCESS:
                status = (
                    ScannerStatus.INTERPRETER_OR_LOADER_FAILURE
                    if version_probe.status
                    is ExecutableVersionProbeStatus.INTERPRETER_OR_LOADER_FAILURE
                    else (
                        ScannerStatus.TIMED_OUT
                        if version_probe.status is ExecutableVersionProbeStatus.TIMED_OUT
                        else ScannerStatus.UNAVAILABLE
                    )
                )
                return finish(
                    status,
                    version=None,
                    error=version_probe.diagnostic,
                )
            version = version_probe.version
            if version is None:
                raise ValueError("successful scanner version probe omitted its version")
            trust_error = scanner_trust_pin_error(
                version=version,
                executable_sha256=executable_sha256,
                expected_version=expected_version,
                expected_sha256=expected_sha256,
            )
            if trust_error is not None:
                return finish(
                    ScannerStatus.FAILED,
                    version=version,
                    command=command,
                    error=trust_error,
                )
            process_environment = isolation_host_environment(
                backend,
                private_dir,
                environment,
            )
            self.validate_pre_execution_inputs(workspace, private_dir)
            execution_cwd = self.execution_working_directory(workspace, private_dir)
            resolved_execution_cwd = execution_cwd.resolve(strict=True)
            resolved_execution_cwd.relative_to(private_dir.resolve(strict=True))
            if execution_cwd.is_symlink() or execution_cwd.is_junction():
                raise ValueError("scanner execution directory may not be a link")
        except MacOSToolchainResolutionError:
            cleanup_error = _scanner_cleanup_error(backend, private_dir)
            return finish(
                ScannerStatus.INTERPRETER_OR_LOADER_FAILURE,
                version=version,
                error=cleanup_error or _INTERPRETER_OR_LOADER_DIAGNOSTIC,
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
            cleanup_error = _scanner_cleanup_error(backend, private_dir)
            return finish(
                ScannerStatus.FAILED,
                version=version,
                error=(
                    cleanup_error
                    or f"unsafe or invalid scanner configuration: {type(exc).__name__}"
                ),
            )
        timed_out = False
        output_exceeded = False
        memory_exceeded = False
        memory_monitor_failed = False
        process: subprocess.Popen[bytes] | None = None
        process_error: str | None = None
        descendant_error: str | None = None
        raw_identity: _PrivateProbeStreamIdentity | None = None
        error_identity: _PrivateProbeStreamIdentity | None = None
        try:
            nproc_ceiling = _darwin_uid_process_ceiling(64)
            with (
                _open_private_probe_stream(raw_path) as stdout_handle,
                _open_private_probe_stream(error_path) as stderr_handle,
            ):
                raw_identity = _private_probe_stream_identity(stdout_handle)
                error_identity = _private_probe_stream_identity(stderr_handle)
                process = subprocess.Popen(
                    command,
                    cwd=resolved_execution_cwd,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    env=process_environment,
                    shell=False,
                    start_new_session=os.name != "nt",
                    creationflags=(
                        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                        if os.name == "nt"
                        else 0
                    ),
                    preexec_fn=(
                        partial(
                            _limit_scanner_process,
                            nproc_ceiling=nproc_ceiling,
                        )
                        if os.name != "nt"
                        else None
                    ),
                )
                deadline = time.monotonic() + timeout_seconds
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        os.fstat(stdout_handle.fileno()).st_size > self.max_stdout_bytes
                        or os.fstat(stderr_handle.fileno()).st_size > self.max_stderr_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    try:
                        resident_bytes = _darwin_process_group_rss_bytes(process.pid)
                    except OSError:
                        try:
                            process.wait(timeout=0.05)
                        except subprocess.TimeoutExpired:
                            pass
                        else:
                            break
                        memory_monitor_failed = True
                        _stop_process(process)
                        break
                    if resident_bytes > _SCANNER_MEMORY_BYTES:
                        memory_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
                descendant_error = _cleanup_lingering_process_group(
                    process,
                    diagnostic=_SCANNER_DESCENDANT_DIAGNOSTIC,
                )
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                _stop_process(process)
                descendant_error = _cleanup_lingering_process_group(
                    process,
                    diagnostic=_SCANNER_DESCENDANT_DIAGNOSTIC,
                )
            return_code = (
                process.returncode if process is not None and process.returncode is not None else -1
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if process is not None:
                _stop_process(process)
                descendant_error = _cleanup_lingering_process_group(
                    process,
                    diagnostic=_SCANNER_DESCENDANT_DIAGNOSTIC,
                )
            process_error = f"scanner process failed: {type(exc).__name__}"
            return_code = process.returncode if process is not None else -1
        cleanup_error = _scanner_cleanup_error(backend, private_dir)
        if raw_identity is None or error_identity is None:
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error="private scanner output identity was not established",
            )
        try:
            raw_bytes = _read_attested_private_stream(
                raw_path,
                raw_identity,
                maximum_bytes=_SCANNER_OUTPUT_CAPTURE_BYTES,
            )
            error_bytes = _read_attested_private_stream(
                error_path,
                error_identity,
                maximum_bytes=_SCANNER_OUTPUT_CAPTURE_BYTES,
            )
        except (OSError, ValueError):
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error="private scanner output identity changed and was rejected",
                process_exit_code=return_code,
            )
        raw_output_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        raw_output_bytes = len(raw_bytes)
        private_stderr_sha256 = hashlib.sha256(error_bytes).hexdigest()
        raw_public_path = str(raw_path.relative_to(private_dir.parent))
        stderr_public_path = str(error_path.relative_to(private_dir.parent))

        def finish_observed(
            status: ScannerStatus,
            *,
            findings: list[ScannerFinding] | None = None,
            error: str | None = None,
            operator_preparation_step: str | None = None,
            machine_output_validated: bool = False,
        ) -> ScannerRun:
            return finish(
                status,
                version=version,
                command=command,
                findings=findings,
                error=error,
                raw_output_path=raw_public_path,
                attested_output_sha256=raw_output_sha256,
                attested_output_bytes=raw_output_bytes,
                private_stderr_path=stderr_public_path,
                private_stderr_sha256=private_stderr_sha256,
                private_stderr_bytes=len(error_bytes),
                operator_preparation_step=operator_preparation_step,
                process_exit_code=return_code if process is not None else None,
                machine_output_validated=machine_output_validated,
            )

        if process_error or cleanup_error or descendant_error:
            return finish_observed(
                ScannerStatus.FAILED,
                error=cleanup_error or descendant_error or process_error,
            )
        if memory_monitor_failed or memory_exceeded:
            return finish_observed(
                ScannerStatus.FAILED,
                error=(
                    _SCANNER_MEMORY_MONITOR_DIAGNOSTIC
                    if memory_monitor_failed
                    else _SCANNER_MEMORY_DIAGNOSTIC
                ),
            )
        if timed_out:
            return finish_observed(
                ScannerStatus.TIMED_OUT,
                error=f"scanner exceeded {timeout_seconds:.0f}s timeout",
            )
        if (
            output_exceeded
            or raw_output_bytes > self.max_stdout_bytes
            or len(error_bytes) > self.max_stderr_bytes
        ):
            return finish_observed(
                ScannerStatus.FAILED,
                error="scanner output exceeded the private output limit",
            )

        stdout = raw_bytes.decode("utf-8", errors="replace")
        if return_code not in self.finding_exit_codes:
            classification = self.classify_non_success_exit(
                return_code=return_code,
                stdout=raw_bytes,
                stderr=error_bytes,
            )
            if classification is not None:
                return finish_observed(
                    classification.status,
                    error=classification.diagnostic,
                    operator_preparation_step=classification.operator_preparation_step,
                )
            return finish_observed(
                ScannerStatus.FAILED,
                error=f"scanner exited with code {return_code}",
            )
        try:
            findings = self.parse(workspace, stdout, private_dir)
        except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as exc:
            return finish_observed(
                ScannerStatus.FAILED,
                error=f"invalid scanner output: {type(exc).__name__}",
            )
        return finish_observed(
            ScannerStatus.SUCCESS,
            findings=findings,
            machine_output_validated=self.strict_machine_output,
        )


def scanner_trust_pin_error(
    *,
    version: str | None,
    executable_sha256: str | None,
    expected_version: str | None,
    expected_sha256: str | None,
) -> str | None:
    """Validate an optional paired scanner pin before target execution."""

    if expected_version is None and expected_sha256 is None:
        return None
    if expected_version is None or expected_sha256 is None:
        return "scanner trust policy requires paired version and SHA-256 pins"
    if executable_sha256 != expected_sha256:
        return "scanner executable SHA-256 does not match the configured trust pin"
    normalized_expected_version = select_public_tool_version_line(expected_version)
    normalized_version = select_public_tool_version_line(version) if version is not None else None
    if (
        normalized_version is None
        or normalized_expected_version is None
        or re.search(
            rf"(?<![0-9.]){re.escape(normalized_expected_version)}(?![0-9.])",
            normalized_version,
        )
        is None
    ):
        return "scanner version does not match the configured trust pin"
    return None


def copy_scanner_workspace(
    root: Path,
    workspace: Path,
    private_dir: Path,
    *,
    audited_relative_paths: Sequence[str | Path | PurePosixPath] = (),
    allow_custom_private_exclusion: bool = False,
) -> None:
    """Copy exactly one bounded, pruned, no-follow source inventory."""

    custody = copy_scanner_workspace_with_custody(
        root,
        workspace,
        private_dir,
        audited_relative_paths=audited_relative_paths,
        allow_custom_private_exclusion=allow_custom_private_exclusion,
    )
    custody.finalize()


def copy_scanner_workspace_with_custody(
    root: Path,
    workspace: Path,
    private_dir: Path,
    *,
    audited_relative_paths: Sequence[str | Path | PurePosixPath] = (),
    allow_custom_private_exclusion: bool = False,
) -> ScannerWorkspaceCopyCustody:
    """Exclusively copy one audited inventory and retain both root descriptors."""

    require_audited_workspace_paths_included(audited_relative_paths)
    required_paths = _normalized_audited_workspace_paths(audited_relative_paths)
    source_root, source_identity = _openable_workspace_root(root)
    source_fd = _open_workspace_directory(source_root)
    workspace_fd = -1
    workspace_parent_fd = -1
    primary_error: BaseException | None = None
    try:
        _require_workspace_identity(os.fstat(source_fd), source_identity)
        source_inventory = _build_scanner_workspace_inventory_from_descriptor(
            source_root,
            source_fd,
            private_dir,
            allow_custom_private_exclusion=allow_custom_private_exclusion,
        )
        _require_audited_paths_in_inventory(source_inventory, required_paths)
        (
            workspace_root,
            workspace_fd,
            workspace_parent_root,
            workspace_parent_fd,
            workspace_parent_identity,
        ) = _create_exclusive_workspace_root(workspace)
        _copy_scanner_workspace_inventory_with_descriptors(
            source_inventory,
            source_fd,
            workspace_fd,
        )
        workspace_inventory = _build_scanner_workspace_inventory_from_descriptor(
            workspace_root,
            workspace_fd,
            workspace_root / ".mmaudit",
        )
        _require_retained_workspace_root(
            source_root,
            source_fd,
            source_inventory.root_identity,
            label="source",
        )
        _require_retained_workspace_root(
            workspace_root,
            workspace_fd,
            workspace_inventory.root_identity,
            label="workspace",
        )
        if not _workspace_copy_matches(source_inventory, workspace_inventory):
            raise ValueError("scanner workspace copy does not match its hashed source inventory")
        custody = ScannerWorkspaceCopyCustody(
            _source_root=source_root,
            _workspace_root=workspace_root,
            _workspace_parent_root=workspace_parent_root,
            _source_private_dir=private_dir,
            _allow_custom_source_private_exclusion=allow_custom_private_exclusion,
            _source_fd=source_fd,
            _workspace_fd=workspace_fd,
            _workspace_parent_fd=workspace_parent_fd,
            _workspace_parent_identity=workspace_parent_identity,
            _source_before=source_inventory,
            _workspace_after_copy=workspace_inventory,
        )
        source_fd = -1
        workspace_fd = -1
        workspace_parent_fd = -1
        return custody
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            _close_workspace_descriptors(workspace_fd, source_fd, workspace_parent_fd)
        except OSError:
            if primary_error is None:
                raise


def retain_scanner_workspace_source_custody(
    root: Path,
    private_dir: Path | None = None,
    *,
    audited_relative_paths: Sequence[str | Path | PurePosixPath] = (),
    allow_custom_private_exclusion: bool = False,
) -> ScannerWorkspaceSourceCustody:
    """Capture an exact source inventory and retain its no-follow root descriptor."""

    require_audited_workspace_paths_included(audited_relative_paths)
    required_paths = _normalized_audited_workspace_paths(audited_relative_paths)
    source_root, source_identity = _openable_workspace_root(root)
    source_fd = _open_workspace_directory(source_root)
    try:
        _require_workspace_identity(os.fstat(source_fd), source_identity)
        exclusion_root = private_dir if private_dir is not None else source_root / ".mmaudit"
        source_inventory = _build_scanner_workspace_inventory_from_descriptor(
            source_root,
            source_fd,
            exclusion_root,
            allow_custom_private_exclusion=allow_custom_private_exclusion,
        )
        _require_audited_paths_in_inventory(source_inventory, required_paths)
        return ScannerWorkspaceSourceCustody(
            _source_root=source_root,
            _source_private_dir=exclusion_root,
            _allow_custom_source_private_exclusion=allow_custom_private_exclusion,
            _source_fd=source_fd,
            _source_before=source_inventory,
        )
    except BaseException:
        os.close(source_fd)
        raise


def scanner_workspace_sha256(
    root: Path,
    private_dir: Path | None = None,
    *,
    audited_relative_paths: Sequence[str | Path | PurePosixPath] = (),
    allow_custom_private_exclusion: bool = False,
) -> str:
    """Hash the exact bounded, non-secret tree copied into scanner workspaces."""

    require_audited_workspace_paths_included(audited_relative_paths)
    required_paths = _normalized_audited_workspace_paths(audited_relative_paths)
    exclusion_root = private_dir if private_dir is not None else root / ".mmaudit"
    inventory = _build_scanner_workspace_inventory(
        root,
        exclusion_root,
        allow_custom_private_exclusion=allow_custom_private_exclusion,
    )
    _require_audited_paths_in_inventory(inventory, required_paths)
    return inventory.sha256()


def scanner_workspace_file_records(
    root: Path,
    private_dir: Path | None = None,
) -> tuple[ScannerWorkspaceFileRecord, ...]:
    """Return the exact bounded, no-follow file inventory used by scanner custody."""

    exclusion_root = private_dir if private_dir is not None else root / ".mmaudit"
    inventory = _build_scanner_workspace_inventory(root, exclusion_root)
    return tuple(
        ScannerWorkspaceFileRecord(
            relative_path=item.relative_path,
            sha256=item.sha256,
            size=item.identity.size,
        )
        for item in inventory.files
    )


def scanner_workspace_file_sha256(
    root: Path,
    relative_path: str | Path | PurePosixPath,
    private_dir: Path | None = None,
) -> str:
    """Hash one included regular file through the scanner's no-follow inventory."""

    normalized = normalize_relative_path(str(relative_path))
    if normalized in {"", "."}:
        raise ValueError("scanner workspace file path must identify a file")
    require_audited_workspace_paths_included((normalized,))
    exclusion_root = private_dir if private_dir is not None else root / ".mmaudit"
    inventory = _build_scanner_workspace_inventory(root, exclusion_root)
    for item in inventory.files:
        if item.relative_path == normalized:
            return item.sha256
    raise ValueError("scanner workspace file is absent from the audited inventory")


def observe_scanner_workspace_texts(
    root: Path,
    relative_paths: Sequence[str | Path | PurePosixPath],
    *,
    expected_inventory_sha256: str,
    private_dir: Path | None = None,
    allow_custom_private_exclusion: bool = False,
    maximum_file_bytes: int = _MAX_WORKSPACE_FILE_BYTES,
    maximum_total_bytes: int = _MAX_WORKSPACE_BYTES,
) -> tuple[ScannerWorkspaceTextRecord, ...]:
    """Read exact source texts while retaining and revalidating scanner-tree custody."""

    if re.fullmatch(r"[0-9a-f]{64}", expected_inventory_sha256) is None:
        raise ValueError("expected scanner workspace inventory hash must be lowercase SHA-256")
    if not 1 <= maximum_file_bytes <= _MAX_WORKSPACE_FILE_BYTES:
        raise ValueError("scanner workspace text per-file byte bound is invalid")
    if not 1 <= maximum_total_bytes <= _MAX_WORKSPACE_BYTES:
        raise ValueError("scanner workspace text total byte bound is invalid")

    require_audited_workspace_paths_included(relative_paths)
    requested_paths = _normalized_audited_workspace_paths(relative_paths)
    if not requested_paths:
        raise ValueError("scanner workspace text observation requires at least one source path")

    source_root, source_identity = _openable_workspace_root(root)
    source_fd = _open_workspace_directory(source_root)
    try:
        _require_workspace_identity(os.fstat(source_fd), source_identity)
        exclusion_root = private_dir if private_dir is not None else source_root / ".mmaudit"
        source_before = _build_scanner_workspace_inventory_from_descriptor(
            source_root,
            source_fd,
            exclusion_root,
            allow_custom_private_exclusion=allow_custom_private_exclusion,
        )
        if source_before.sha256() != expected_inventory_sha256:
            raise ValueError("scanner workspace source inventory differs from the expected hash")
        _require_audited_paths_in_inventory(source_before, requested_paths)

        files_by_path = {item.relative_path: item for item in source_before.files}
        directory_identities = {
            item.relative_path: item.identity for item in source_before.directories
        }
        observed: list[ScannerWorkspaceTextRecord] = []
        total_bytes = 0
        for relative_path in requested_paths:
            item = files_by_path[relative_path]
            if item.identity.size > maximum_file_bytes:
                raise ValueError(
                    "scanner workspace observed source exceeds the per-file byte bound"
                )
            total_bytes += item.identity.size
            if total_bytes > maximum_total_bytes:
                raise ValueError("scanner workspace observed sources exceed the total byte bound")
            raw = _read_scanner_workspace_file_bytes(
                source_fd,
                item,
                directory_identities,
            )
            if _scanner_workspace_text_is_binary(raw):
                raise ValueError("scanner workspace observed source is binary")
            try:
                content = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ValueError("scanner workspace observed source is not strict UTF-8") from exc
            observed.append(
                ScannerWorkspaceTextRecord(
                    relative_path=relative_path,
                    raw_sha256=item.sha256,
                    size=item.identity.size,
                    content=content,
                    lines=len(content.splitlines()),
                )
            )

        _require_retained_workspace_root(
            source_root,
            source_fd,
            source_before.root_identity,
            label="source",
        )
        source_after = _build_scanner_workspace_inventory_from_descriptor(
            source_root,
            source_fd,
            exclusion_root,
            allow_custom_private_exclusion=allow_custom_private_exclusion,
        )
        _require_retained_workspace_root(
            source_root,
            source_fd,
            source_before.root_identity,
            label="source",
        )
        if (
            source_after.sha256() != expected_inventory_sha256
            or not _workspace_inventory_identity_stable(source_before, source_after)
        ):
            raise ValueError("scanner workspace source inventory changed during text observation")
        return tuple(observed)
    finally:
        os.close(source_fd)


def _normalized_audited_workspace_paths(
    relative_paths: Sequence[str | Path | PurePosixPath],
) -> tuple[str, ...]:
    return tuple(sorted({normalize_relative_path(str(relative)) for relative in relative_paths}))


def _require_audited_paths_in_inventory(
    inventory: _ScannerWorkspaceInventory,
    required_paths: tuple[str, ...],
) -> None:
    available = {item.relative_path for item in inventory.files}
    missing = sorted(set(required_paths) - available)
    if missing:
        raise ValueError(
            "explicit audited source path is absent from the execution inventory: "
            + ", ".join(missing[:20])
        )


def scanner_workspace_exclusion_path(
    root: Path,
    private_dir: Path | None = None,
) -> str:
    """Return the exact normalized repository-relative scanner-output exclusion."""

    repository_root, _ = _openable_workspace_root(root)
    exclusion_root = private_dir if private_dir is not None else repository_root / ".mmaudit"
    relative = _workspace_private_relative(repository_root, exclusion_root)
    if relative is None:
        return ".mmaudit"
    return PurePosixPath(*relative).as_posix()


def _build_scanner_workspace_inventory(
    root: Path,
    private_dir: Path,
    *,
    allow_custom_private_exclusion: bool = False,
) -> _ScannerWorkspaceInventory:
    """Inventory a pruned tree through retained no-follow directory descriptors."""

    repository_root, root_identity = _openable_workspace_root(root)
    root_fd = _open_workspace_directory(repository_root)
    try:
        _require_workspace_identity(os.fstat(root_fd), root_identity)
        return _build_scanner_workspace_inventory_from_descriptor(
            repository_root,
            root_fd,
            private_dir,
            allow_custom_private_exclusion=allow_custom_private_exclusion,
        )
    finally:
        os.close(root_fd)


def _build_scanner_workspace_inventory_from_descriptor(
    repository_root: Path,
    root_fd: int,
    private_dir: Path,
    *,
    allow_custom_private_exclusion: bool = False,
) -> _ScannerWorkspaceInventory:
    """Inventory through an already-custodied no-follow root descriptor."""

    root_identity = _WorkspaceIdentity.from_stat(os.fstat(root_fd))
    private_relative = _workspace_private_relative(
        repository_root,
        private_dir,
        allow_custom_private_exclusion=allow_custom_private_exclusion,
    )
    directories: list[_WorkspaceDirectory] = []
    files: list[_WorkspaceFile] = []
    entries_seen = 0
    total_bytes = 0

    try:
        _require_workspace_identity(os.fstat(root_fd), root_identity)

        def walk(directory_fd: int, parts: tuple[str, ...], depth: int) -> None:
            nonlocal entries_seen, total_bytes
            if depth > _MAX_WORKSPACE_DEPTH:
                raise ValueError("scanner workspace directory depth limit exceeded")
            names: list[str] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > _MAX_WORKSPACE_ENTRIES:
                        raise ValueError("scanner workspace source entry limit exceeded")
                    names.append(entry.name)

            for name in sorted(names):
                try:
                    relative = normalize_relative_path(PurePosixPath(*parts, name).as_posix())
                except (UnicodeError, ValueError) as exc:
                    raise ValueError(
                        "scanner workspace source contains an unsupported repository path"
                    ) from exc
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                is_directory = stat.S_ISDIR(metadata.st_mode)
                if _workspace_relative_excluded(
                    relative,
                    is_dir=is_directory,
                    private_relative=private_relative,
                ):
                    continue
                identity = _WorkspaceIdentity.from_stat(metadata)
                if is_directory:
                    child_fd = os.open(
                        name,
                        _workspace_directory_flags(),
                        dir_fd=directory_fd,
                    )
                    try:
                        _require_workspace_identity(os.fstat(child_fd), identity)
                        directories.append(
                            _WorkspaceDirectory(
                                relative_path=relative,
                                identity=identity,
                            )
                        )
                        walk(child_fd, (*parts, name), depth + 1)
                        _require_workspace_identity(os.fstat(child_fd), identity)
                        _require_workspace_identity(
                            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                            identity,
                        )
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError(
                        "scanner workspace source must contain unique regular files only"
                    )
                if metadata.st_size > _MAX_WORKSPACE_FILE_BYTES:
                    raise ValueError("scanner workspace source file exceeds the byte limit")
                if len(files) + 1 > _MAX_WORKSPACE_FILES:
                    raise ValueError("scanner workspace source file-count limit exceeded")
                total_bytes += metadata.st_size
                if total_bytes > _MAX_WORKSPACE_BYTES:
                    raise ValueError("scanner workspace source total byte limit exceeded")
                files.append(
                    _WorkspaceFile(
                        relative_path=relative,
                        identity=identity,
                        sha256=_hash_workspace_file(directory_fd, name, identity),
                    )
                )

        walk(root_fd, (), 0)
        _require_workspace_identity(os.fstat(root_fd), root_identity)
        _require_workspace_identity(
            os.stat(repository_root, follow_symlinks=False),
            root_identity,
        )
    except (TypeError, UnicodeError) as exc:
        raise ValueError("scanner workspace source could not be safely inventoried") from exc

    return _ScannerWorkspaceInventory(
        repository_root=repository_root,
        root_identity=root_identity,
        directories=tuple(sorted(directories, key=lambda item: item.relative_path)),
        files=tuple(sorted(files, key=lambda item: item.relative_path)),
    )


def _copy_scanner_workspace_inventory_with_descriptors(
    inventory: _ScannerWorkspaceInventory,
    source_root_fd: int,
    workspace_root_fd: int,
) -> None:
    """Populate an exclusive workspace solely through retained root descriptors."""

    _require_workspace_identity(os.fstat(source_root_fd), inventory.root_identity)
    source_directories = {item.relative_path: item.identity for item in inventory.directories}
    destination_directories: dict[str, _WorkspaceIdentity] = {}
    for directory in sorted(
        inventory.directories,
        key=lambda item: (
            len(PurePosixPath(item.relative_path).parts),
            item.relative_path,
        ),
    ):
        parts = PurePosixPath(directory.relative_path).parts
        parent_fd = _open_workspace_relative_directory_by_identity(
            workspace_root_fd,
            parts[:-1],
            destination_directories,
        )
        child_fd = -1
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("scanner workspace destination directory is invalid")
            destination_identity = _WorkspaceIdentity.from_stat(metadata)
            child_fd = os.open(
                parts[-1],
                _workspace_directory_flags(),
                dir_fd=parent_fd,
            )
            _require_workspace_node_identity(os.fstat(child_fd), destination_identity)
            destination_directories[directory.relative_path] = destination_identity
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(parent_fd)

    for item in inventory.files:
        _copy_workspace_file_with_descriptors(
            source_root_fd,
            workspace_root_fd,
            item,
            source_directories,
            destination_directories,
        )

    _verify_workspace_source(inventory, source_root_fd, source_directories)
    for directory in sorted(
        inventory.directories,
        key=lambda item: len(PurePosixPath(item.relative_path).parts),
        reverse=True,
    ):
        parts = PurePosixPath(directory.relative_path).parts
        directory_fd = _open_workspace_relative_directory_by_identity(
            workspace_root_fd,
            parts,
            destination_directories,
        )
        try:
            os.fchmod(directory_fd, stat.S_IMODE(directory.identity.mode))
        finally:
            os.close(directory_fd)


def _copy_workspace_file_with_descriptors(
    source_root_fd: int,
    workspace_root_fd: int,
    item: _WorkspaceFile,
    source_directory_identities: dict[str, _WorkspaceIdentity],
    destination_directory_identities: dict[str, _WorkspaceIdentity],
) -> None:
    parts = PurePosixPath(item.relative_path).parts
    source_parent_fd = _open_workspace_relative_directory(
        source_root_fd,
        parts[:-1],
        source_directory_identities,
    )
    destination_parent_fd = _open_workspace_relative_directory_by_identity(
        workspace_root_fd,
        parts[:-1],
        destination_directory_identities,
    )
    source_fd = -1
    destination_fd = -1
    try:
        _require_workspace_identity(
            os.stat(parts[-1], dir_fd=source_parent_fd, follow_symlinks=False),
            item.identity,
        )
        source_fd = os.open(
            parts[-1],
            _workspace_file_flags(),
            dir_fd=source_parent_fd,
        )
        _require_workspace_identity(os.fstat(source_fd), item.identity)
        destination_fd = os.open(
            parts[-1],
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | _required_no_follow_flag()
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_parent_fd,
        )
        digest = hashlib.sha256()
        remaining = item.identity.size
        while remaining:
            chunk = os.read(source_fd, min(_WORKSPACE_READ_BYTES, remaining))
            if not chunk:
                raise ValueError("scanner workspace source changed while it was copied")
            digest.update(chunk)
            _write_all(destination_fd, chunk)
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise ValueError("scanner workspace source changed while it was copied")
        if digest.hexdigest() != item.sha256:
            raise ValueError("scanner workspace source bytes changed after inventory")
        _require_workspace_identity(os.fstat(source_fd), item.identity)
        _require_workspace_identity(
            os.stat(parts[-1], dir_fd=source_parent_fd, follow_symlinks=False),
            item.identity,
        )
        os.fchmod(destination_fd, stat.S_IMODE(item.identity.mode))
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
        os.close(destination_parent_fd)
        os.close(source_parent_fd)


def _verify_workspace_source(
    inventory: _ScannerWorkspaceInventory,
    source_root_fd: int,
    directory_identities: dict[str, _WorkspaceIdentity],
) -> None:
    for directory in inventory.directories:
        parts = PurePosixPath(directory.relative_path).parts
        descriptor = _open_workspace_relative_directory(
            source_root_fd,
            parts,
            directory_identities,
        )
        os.close(descriptor)
    for item in inventory.files:
        parts = PurePosixPath(item.relative_path).parts
        parent_fd = _open_workspace_relative_directory(
            source_root_fd,
            parts[:-1],
            directory_identities,
        )
        try:
            _require_workspace_identity(
                os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False),
                item.identity,
            )
        finally:
            os.close(parent_fd)
    _require_workspace_identity(os.fstat(source_root_fd), inventory.root_identity)
    _require_workspace_identity(
        os.stat(inventory.repository_root, follow_symlinks=False),
        inventory.root_identity,
    )


def _openable_workspace_root(root: Path) -> tuple[Path, _WorkspaceIdentity]:
    _required_no_follow_flag()
    _workspace_directory_flags()
    source_path = root.absolute()
    initial = source_path.lstat()
    if not stat.S_ISDIR(initial.st_mode) or source_path.is_symlink() or source_path.is_junction():
        raise ValueError("scanner workspace source must be a regular directory")
    repository_root = source_path.resolve(strict=True)
    identity = _WorkspaceIdentity.from_stat(initial)
    _require_workspace_identity(
        os.stat(source_path, follow_symlinks=False),
        identity,
    )
    _require_workspace_identity(
        os.stat(repository_root, follow_symlinks=False),
        identity,
    )
    return repository_root, identity


def _workspace_private_relative(
    repository_root: Path,
    private_dir: Path,
    *,
    allow_custom_private_exclusion: bool = False,
) -> tuple[str, ...] | None:
    private_root = private_dir.parent.resolve(strict=False) / private_dir.name
    try:
        relative = private_root.relative_to(repository_root)
    except ValueError:
        return None
    normalized = normalize_relative_path(relative)
    parts = PurePosixPath(normalized).parts
    if not parts:
        raise ValueError("scanner private directory may not be the repository root")
    exclusion_root = audited_workspace_exclusion_root(normalized)
    if exclusion_root is None:
        if allow_custom_private_exclusion:
            return parts
        raise ValueError(
            "scanner private directory inside the repository must remain within "
            "the shared audited-tree exclusion domain"
        )
    return PurePosixPath(exclusion_root).parts


def _workspace_relative_excluded(
    relative: str,
    *,
    is_dir: bool,
    private_relative: tuple[str, ...] | None,
) -> bool:
    parts = PurePosixPath(relative).parts
    if private_relative is not None and parts[: len(private_relative)] == private_relative:
        return True
    return audited_workspace_relative_excluded(relative, is_dir=is_dir)


def _hash_workspace_file(
    directory_fd: int,
    name: str,
    identity: _WorkspaceIdentity,
) -> str:
    _require_workspace_identity(
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
        identity,
    )
    file_fd = os.open(name, _workspace_file_flags(), dir_fd=directory_fd)
    try:
        _require_workspace_identity(os.fstat(file_fd), identity)
        digest = hashlib.sha256()
        remaining = identity.size
        while remaining:
            chunk = os.read(file_fd, min(_WORKSPACE_READ_BYTES, remaining))
            if not chunk:
                raise ValueError("scanner workspace source changed while it was hashed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ValueError("scanner workspace source changed while it was hashed")
        _require_workspace_identity(os.fstat(file_fd), identity)
        _require_workspace_identity(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
            identity,
        )
        return digest.hexdigest()
    finally:
        os.close(file_fd)


def _read_scanner_workspace_file_bytes(
    root_fd: int,
    item: _WorkspaceFile,
    directory_identities: dict[str, _WorkspaceIdentity],
) -> bytes:
    """Read one inventoried file exactly through descriptor-relative no-follow access."""

    parts = PurePosixPath(item.relative_path).parts
    parent_fd = _open_workspace_relative_directory(
        root_fd,
        parts[:-1],
        directory_identities,
    )
    file_fd = -1
    try:
        _require_workspace_identity(
            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False),
            item.identity,
        )
        file_fd = os.open(parts[-1], _workspace_file_flags(), dir_fd=parent_fd)
        _require_workspace_identity(os.fstat(file_fd), item.identity)
        raw = bytearray()
        remaining = item.identity.size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(file_fd, min(_WORKSPACE_READ_BYTES, remaining))
            if not chunk:
                raise ValueError("scanner workspace observed source changed while it was read")
            raw.extend(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ValueError("scanner workspace observed source changed while it was read")
        if len(raw) != item.identity.size or digest.hexdigest() != item.sha256:
            raise ValueError("scanner workspace observed source bytes differ from its inventory")
        _require_workspace_identity(os.fstat(file_fd), item.identity)
        _require_workspace_identity(
            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False),
            item.identity,
        )
        return bytes(raw)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def _scanner_workspace_text_is_binary(raw: bytes) -> bool:
    if b"\x00" in raw:
        return True
    sample = raw[:8_192]
    if not sample:
        return False
    control_bytes = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control_bytes / len(sample) > 0.15


def _open_workspace_relative_directory(
    root_fd: int,
    parts: tuple[str, ...],
    directory_identities: dict[str, _WorkspaceIdentity],
) -> int:
    current_fd = os.dup(root_fd)
    traversed: list[str] = []
    try:
        for part in parts:
            traversed.append(part)
            relative = PurePosixPath(*traversed).as_posix()
            identity = directory_identities[relative]
            _require_workspace_identity(
                os.stat(part, dir_fd=current_fd, follow_symlinks=False),
                identity,
            )
            child_fd = os.open(
                part,
                _workspace_directory_flags(),
                dir_fd=current_fd,
            )
            try:
                _require_workspace_identity(os.fstat(child_fd), identity)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_workspace_relative_directory_by_identity(
    root_fd: int,
    parts: tuple[str, ...],
    directory_identities: dict[str, _WorkspaceIdentity],
) -> int:
    """Traverse a destination while allowing expected parent metadata changes."""

    current_fd = os.dup(root_fd)
    traversed: list[str] = []
    try:
        for part in parts:
            traversed.append(part)
            relative = PurePosixPath(*traversed).as_posix()
            identity = directory_identities[relative]
            _require_workspace_node_identity(
                os.stat(part, dir_fd=current_fd, follow_symlinks=False),
                identity,
            )
            child_fd = os.open(
                part,
                _workspace_directory_flags(),
                dir_fd=current_fd,
            )
            try:
                _require_workspace_node_identity(os.fstat(child_fd), identity)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _create_exclusive_workspace_root(
    workspace: Path,
) -> tuple[Path, int, Path, int, _WorkspaceIdentity]:
    requested_parent = workspace.parent.absolute()
    parent_root, parent_identity = _openable_workspace_root(requested_parent)
    if requested_parent != parent_root or workspace.name in {"", ".", ".."}:
        raise ValueError("scanner workspace must be a canonical direct child")
    parent_fd = _open_workspace_directory(parent_root)
    workspace_fd = -1
    created_identity: _WorkspaceIdentity | None = None
    retain_parent_descriptor = False
    try:
        _require_workspace_identity(os.fstat(parent_fd), parent_identity)
        try:
            os.mkdir(workspace.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise OSError("scanner workspace already exists") from exc
        metadata = os.stat(workspace.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("scanner workspace destination root is not a directory")
        identity = _WorkspaceIdentity.from_stat(metadata)
        created_identity = identity
        workspace_fd = os.open(
            workspace.name,
            _workspace_directory_flags(),
            dir_fd=parent_fd,
        )
        _require_workspace_identity(os.fstat(workspace_fd), identity)
        _require_workspace_identity(
            os.stat(workspace.name, dir_fd=parent_fd, follow_symlinks=False),
            identity,
        )
        parent_identity_after_creation = _WorkspaceIdentity.from_stat(os.fstat(parent_fd))
        retain_parent_descriptor = True
        return (
            parent_root / workspace.name,
            workspace_fd,
            parent_root,
            parent_fd,
            parent_identity_after_creation,
        )
    except BaseException:
        if workspace_fd >= 0:
            os.close(workspace_fd)
        if created_identity is not None:
            try:
                current = os.stat(
                    workspace.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                _require_workspace_identity(current, created_identity)
                os.rmdir(workspace.name, dir_fd=parent_fd)
            except (OSError, ValueError):
                pass
        raise
    finally:
        if not retain_parent_descriptor:
            os.close(parent_fd)


def _require_retained_workspace_root(
    path: Path,
    descriptor: int,
    expected: _WorkspaceIdentity,
    *,
    label: str,
) -> None:
    descriptor_metadata = os.fstat(descriptor)
    try:
        named_metadata = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"scanner workspace {label} root identity changed") from exc
    if not (
        stat.S_ISDIR(descriptor_metadata.st_mode)
        and stat.S_ISDIR(named_metadata.st_mode)
        and descriptor_metadata.st_dev == expected.device == named_metadata.st_dev
        and descriptor_metadata.st_ino == expected.inode == named_metadata.st_ino
        and stat.S_IMODE(descriptor_metadata.st_mode) == stat.S_IMODE(expected.mode)
        and stat.S_IMODE(named_metadata.st_mode) == stat.S_IMODE(expected.mode)
    ):
        raise ValueError(f"scanner workspace {label} root identity changed")


def _require_retained_workspace_child(
    parent_descriptor: int,
    child_name: str,
    expected: _WorkspaceIdentity,
) -> None:
    try:
        metadata = os.stat(
            child_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise ValueError("scanner workspace is no longer its custodied parent's child") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != expected.device
        or metadata.st_ino != expected.inode
        or stat.S_IMODE(metadata.st_mode) != stat.S_IMODE(expected.mode)
    ):
        raise ValueError("scanner workspace is no longer its custodied parent's child")


def _workspace_copy_matches(
    source: _ScannerWorkspaceInventory,
    workspace: _ScannerWorkspaceInventory,
) -> bool:
    source_directories = tuple(
        (item.relative_path, stat.S_IMODE(item.identity.mode)) for item in source.directories
    )
    workspace_directories = tuple(
        (item.relative_path, stat.S_IMODE(item.identity.mode)) for item in workspace.directories
    )
    source_files = tuple(
        (
            item.relative_path,
            item.sha256,
            item.identity.size,
            stat.S_IMODE(item.identity.mode),
        )
        for item in source.files
    )
    workspace_files = tuple(
        (
            item.relative_path,
            item.sha256,
            item.identity.size,
            stat.S_IMODE(item.identity.mode),
        )
        for item in workspace.files
    )
    return (
        source.sha256() == workspace.sha256()
        and source_directories == workspace_directories
        and source_files == workspace_files
    )


def _workspace_inventory_identity_stable(
    before: _ScannerWorkspaceInventory,
    after: _ScannerWorkspaceInventory,
) -> bool:
    before_directories = tuple(
        (
            item.relative_path,
            item.identity.device,
            item.identity.inode,
            stat.S_IMODE(item.identity.mode),
        )
        for item in before.directories
    )
    after_directories = tuple(
        (
            item.relative_path,
            item.identity.device,
            item.identity.inode,
            stat.S_IMODE(item.identity.mode),
        )
        for item in after.directories
    )
    before_files = tuple(
        (
            item.relative_path,
            item.identity,
            item.sha256,
        )
        for item in before.files
    )
    after_files = tuple(
        (
            item.relative_path,
            item.identity,
            item.sha256,
        )
        for item in after.files
    )
    return (
        before.sha256() == after.sha256()
        and before_directories == after_directories
        and before_files == after_files
    )


def _open_workspace_directory(path: Path) -> int:
    return os.open(path, _workspace_directory_flags())


def _workspace_directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise OSError("descriptor-relative directory traversal is unavailable")
    return os.O_RDONLY | directory | _required_no_follow_flag() | getattr(os, "O_CLOEXEC", 0)


def _workspace_file_flags() -> int:
    return os.O_RDONLY | _required_no_follow_flag() | getattr(os, "O_CLOEXEC", 0)


def _required_no_follow_flag() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise OSError("no-follow workspace access is unavailable")
    return no_follow


def _require_workspace_identity(
    metadata: os.stat_result,
    expected: _WorkspaceIdentity,
) -> None:
    if _WorkspaceIdentity.from_stat(metadata) != expected:
        raise ValueError("scanner workspace source identity changed during access")


def _require_workspace_node_identity(
    metadata: os.stat_result,
    expected: _WorkspaceIdentity,
) -> None:
    actual = _WorkspaceIdentity.from_stat(metadata)
    if (
        actual.device != expected.device
        or actual.inode != expected.inode
        or stat.S_IFMT(actual.mode) != stat.S_IFMT(expected.mode)
    ):
        raise ValueError("scanner workspace destination identity changed during access")


def _close_workspace_descriptors(*descriptors: int) -> None:
    first_error: OSError | None = None
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError("scanner workspace destination write did not progress")
        offset += written


def _version_probe_directory(private_dir: Path, executable: str | Path) -> Path:
    """Create a private, collision-safe directory for raw version-probe streams."""

    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = private_dir.lstat()
    absolute = Path(os.path.abspath(private_dir))
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or private_dir.is_symlink()
        or private_dir.resolve(strict=True) != absolute
        or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077)
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise ValueError("private version-probe root is not a private owned directory")
    identity = hashlib.sha256(os.fsencode(str(executable))).hexdigest()[:16]
    for sequence in range(100):
        candidate = private_dir / f"version-probe-{identity}-{sequence:02d}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        if stat.S_IMODE(candidate.lstat().st_mode) != 0o700 or candidate.is_symlink():
            raise ValueError("private version-probe artifact directory is invalid")
        return candidate
    raise OSError("private version-probe artifact slots are exhausted")


def _open_private_probe_stream(path: Path) -> Any:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


def _private_probe_stream_identity(handle: Any) -> _PrivateProbeStreamIdentity:
    metadata = os.fstat(handle.fileno())
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise ValueError("private version-probe stream identity is invalid")
    return _PrivateProbeStreamIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        owner=metadata.st_uid,
    )


def _read_attested_private_stream(
    path: Path,
    expected: _PrivateProbeStreamIdentity,
    *,
    maximum_bytes: int,
) -> bytes:
    """Read one original bounded private stream without following path replacement."""

    if not 1 <= maximum_bytes <= 100_000_000:
        raise ValueError("private stream read bound is invalid")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise OSError("no-follow private probe access is unavailable")
    path_before = path.lstat()
    descriptor = os.open(path, flags | no_follow)
    try:
        descriptor_before = os.fstat(descriptor)

        def identity_tuple(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_nlink,
            )

        expected_tuple = (
            expected.device,
            expected.inode,
            expected.mode,
            expected.owner,
            1,
        )
        if (
            identity_tuple(path_before) != expected_tuple
            or identity_tuple(descriptor_before) != expected_tuple
            or not stat.S_ISREG(descriptor_before.st_mode)
            or descriptor_before.st_size > maximum_bytes
        ):
            raise OSError("private version-probe stream identity changed")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(4096, maximum_bytes + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        descriptor_after = os.fstat(descriptor)
        path_after = path.lstat()
        stable_fields_before = (
            identity_tuple(descriptor_before),
            descriptor_before.st_size,
            descriptor_before.st_mtime_ns,
            descriptor_before.st_ctime_ns,
        )
        stable_fields_after = (
            identity_tuple(descriptor_after),
            descriptor_after.st_size,
            descriptor_after.st_mtime_ns,
            descriptor_after.st_ctime_ns,
        )
        if (
            len(raw) > maximum_bytes
            or len(raw) != descriptor_before.st_size
            or stable_fields_after != stable_fields_before
            or identity_tuple(path_after) != expected_tuple
        ):
            raise OSError("private version-probe stream changed during read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _darwin_nproc_ceiling_from_uid_listing(
    listing: str,
    *,
    current_uid: int,
    allowance: int,
    inherited_hard_limit: int,
) -> int:
    """Derive a per-login-UID Darwin process ceiling from one trusted snapshot."""

    if not 1 <= allowance <= 256 or len(listing.encode("utf-8")) > 1_000_000:
        raise OSError("Darwin process-count evidence is outside its fixed bound")
    try:
        observed_uids = tuple(int(line.strip()) for line in listing.splitlines() if line.strip())
    except ValueError as exc:
        raise OSError("Darwin process-count evidence is malformed") from exc
    observed_count = sum(uid == current_uid for uid in observed_uids)
    if observed_count < 1:
        raise OSError("Darwin process-count evidence omitted the current UID")
    requested = observed_count + allowance
    ceiling = requested if inherited_hard_limit < 0 else min(requested, inherited_hard_limit)
    if ceiling <= observed_count:
        raise OSError("Darwin inherited process limit has no safe child allowance")
    return ceiling


def _darwin_current_uid_process_count() -> int:
    """Count the real UID's processes through the fixed macOS libproc ABI."""

    maximum_bytes = 1_000_000
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_pids = libproc.proc_listpids
        list_pids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        list_pids.restype = ctypes.c_int
        current_uid = os.getuid()
        required = int(list_pids(5, current_uid, None, 0))  # PROC_RUID_ONLY
        capacity = required + 64 * 1024
        if required <= 0 or capacity > maximum_bytes:
            raise OSError("Darwin process inventory size is invalid")
        buffer = ctypes.create_string_buffer(capacity)
        captured = int(list_pids(5, current_uid, buffer, capacity))
        if captured <= 0 or captured >= capacity or captured % 4:
            raise OSError("Darwin process inventory capture is incomplete")
        pids = {pid for pid in struct.unpack_from(f"={captured // 4}i", buffer.raw) if pid > 0}
        if os.getpid() not in pids:
            raise OSError("Darwin process inventory omitted the current process")
        return len(pids)
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise OSError("Darwin process inventory could not be established") from exc


def _darwin_process_group_rss_bytes(root_pid: int) -> int:
    """Measure resident memory for one bounded Darwin process group via libproc."""

    if sys.platform != "darwin":
        return 0
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_pids = libproc.proc_listpids
        list_pids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        list_pids.restype = ctypes.c_int
        pid_info = libproc.proc_pidinfo
        pid_info.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        pid_info.restype = ctypes.c_int

        def capture_group() -> set[int]:
            required = int(list_pids(2, root_pid, None, 0))  # PROC_PGRP_ONLY
            capacity = required + 64 * 1024
            if required <= 0 or capacity > 1_000_000:
                raise OSError("Darwin process-group inventory size is invalid")
            buffer = ctypes.create_string_buffer(capacity)
            captured = int(list_pids(2, root_pid, buffer, capacity))
            if captured <= 0 or captured >= capacity or captured % 4:
                raise OSError("Darwin process-group inventory capture is incomplete")
            pids = {pid for pid in struct.unpack_from(f"={captured // 4}i", buffer.raw) if pid > 0}
            if not pids or len(pids) > _DARWIN_PROCESS_TREE_MAXIMUM:
                raise OSError("Darwin process group exceeded its fixed monitor bound")
            return pids

        pids = capture_group()
        if root_pid not in pids:
            raise OSError("Darwin process-group inventory omitted its leader")
        resident_bytes = 0
        observed_pids = 0
        for pid in pids:
            task_info = ctypes.create_string_buffer(256)
            ctypes.set_errno(0)
            size = int(pid_info(pid, 4, 0, task_info, len(task_info)))  # PROC_PIDTASKINFO
            if size < 16:
                # PROC_PGRP_ONLY may briefly retain an exited PID while the
                # task-info query already reports ESRCH. That exact kernel race
                # has no resident task to charge; every other short read remains
                # a fail-closed monitor error.
                if ctypes.get_errno() == errno.ESRCH:
                    continue
                raise OSError("Darwin process-group memory could not be observed")
            resident = int(struct.unpack_from("=Q", task_info.raw, 8)[0])
            if resident < 0 or resident > 1 << 60:
                raise OSError("Darwin process-group memory evidence is invalid")
            resident_bytes += resident
            observed_pids += 1
        if observed_pids < 1:
            return 0
        return resident_bytes
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise OSError("Darwin process-group memory could not be established") from exc


def _darwin_uid_process_ceiling(allowance: int) -> int | None:
    """Observe and bound Darwin's per-login-UID RLIMIT_NPROC semantics."""

    if sys.platform != "darwin":
        return None
    try:
        import resource

        observed_count = _darwin_current_uid_process_count()
        inherited_hard_limit = int(resource.getrlimit(resource.RLIMIT_NPROC)[1])
        return _darwin_nproc_ceiling_from_uid_listing(
            f"{os.getuid()}\n" * observed_count,
            current_uid=os.getuid(),
            allowance=allowance,
            inherited_hard_limit=inherited_hard_limit,
        )
    except (OSError, ValueError) as exc:
        raise OSError("Darwin process-count ceiling could not be established") from exc


def _limit_version_probe_process(*, nproc_ceiling: int | None) -> None:
    """Apply stricter resource bounds than a full scanner process."""

    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("version-probe resource bounds are unavailable") from exc
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (_VERSION_PROBE_OUTPUT_BYTES, _VERSION_PROBE_OUTPUT_BYTES),
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if hasattr(resource, "RLIMIT_NPROC"):
            limit = 16 if nproc_ceiling is None else nproc_ceiling
            resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
        if hasattr(resource, "RLIMIT_AS"):
            try:
                resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
            except (OSError, ValueError):
                # Darwin maps the system shared-cache reservation into every
                # process, so a 1 GiB virtual-address ceiling is below the
                # already-inherited footprint and cannot be installed. The
                # CPU/file/FD/NPROC remain enforced here; the parent process
                # independently enforces a resident-memory ceiling for the whole
                # isolated process group through the fixed libproc ABI.
                if sys.platform != "darwin":
                    raise
    except (OSError, ValueError) as exc:
        raise RuntimeError("version-probe resource bounds could not be applied") from exc


def _probe_has_interpreter_or_loader_failure(stdout: str, stderr: str) -> bool:
    normalized = f"{stdout}\n{stderr}".casefold()
    return any(marker in normalized for marker in _INTERPRETER_OR_LOADER_FAILURE_MARKERS)


def _public_version_line(
    stdout: str,
    stderr: str,
    environment: dict[str, str],
) -> str | None:
    for output in (stdout, stderr):
        selected = select_public_tool_version_line(
            output,
            forbidden_values=environment.values(),
        )
        if selected is not None:
            return selected
    return None


def isolated_executable_version_probe(
    executable: str | Path,
    environment: dict[str, str],
    backend: ScannerIsolationBackend,
    workspace: Path,
    private_dir: Path,
    *,
    repository_javascript: bool = False,
    timeout_seconds: float = 15.0,
) -> ExecutableVersionProbe:
    """Probe one exact executable without exposing raw output outside ``private_dir``."""

    if not 0 < timeout_seconds <= 15.0:
        raise ValueError("isolated executable version timeout is outside its fixed bound")
    probe_dir = _version_probe_directory(private_dir, executable)
    stdout_path = probe_dir / "stdout.txt"
    stderr_path = probe_dir / "stderr.txt"
    process: subprocess.Popen[bytes] | None = None
    return_code: int | None = None
    timed_out = False
    output_exceeded = False
    memory_exceeded = False
    memory_monitor_failed = False
    launch_failed = False
    toolchain_resolution_failed = False
    descendant_error: str | None = None
    stdout_identity: _PrivateProbeStreamIdentity | None = None
    stderr_identity: _PrivateProbeStreamIdentity | None = None
    try:
        if repository_javascript:
            if not isinstance(backend, RepositoryJavaScriptIsolationBackend):
                raise ValueError("off-host repository-JavaScript isolation is unavailable")
            command = backend.wrap_repository_javascript(
                [str(executable), "--version"],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=1,
            )
        else:
            command = wrap_scanner_without_network(
                backend,
                [str(executable), "--version"],
                workspace=workspace,
                private_dir=private_dir,
            )
        process_environment = isolation_host_environment(
            backend,
            private_dir,
            environment,
        )
        nproc_ceiling = _darwin_uid_process_ceiling(16)
        with (
            _open_private_probe_stream(stdout_path) as stdout_handle,
            _open_private_probe_stream(stderr_path) as stderr_handle,
        ):
            stdout_identity = _private_probe_stream_identity(stdout_handle)
            stderr_identity = _private_probe_stream_identity(stderr_handle)
            process = subprocess.Popen(
                command,
                cwd=workspace,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=process_environment,
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=(
                    int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                    if os.name == "nt"
                    else 0
                ),
                preexec_fn=(
                    partial(
                        _limit_version_probe_process,
                        nproc_ceiling=nproc_ceiling,
                    )
                    if os.name != "nt"
                    else None
                ),
            )
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    _stop_process(process)
                    break
                if (
                    os.fstat(stdout_handle.fileno()).st_size >= _VERSION_PROBE_OUTPUT_BYTES
                    or os.fstat(stderr_handle.fileno()).st_size >= _VERSION_PROBE_OUTPUT_BYTES
                ):
                    output_exceeded = True
                    _stop_process(process)
                    break
                try:
                    resident_bytes = _darwin_process_group_rss_bytes(process.pid)
                except OSError:
                    try:
                        process.wait(timeout=_VERSION_PROBE_POLL_SECONDS)
                    except subprocess.TimeoutExpired:
                        pass
                    else:
                        break
                    memory_monitor_failed = True
                    _stop_process(process)
                    break
                if resident_bytes > _VERSION_PROBE_MEMORY_BYTES:
                    memory_exceeded = True
                    _stop_process(process)
                    break
                time.sleep(_VERSION_PROBE_POLL_SECONDS)
            return_code = process.wait(timeout=5)
            descendant_error = _cleanup_lingering_process_group(
                process,
                diagnostic=_VERSION_DESCENDANT_DIAGNOSTIC,
            )
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            _stop_process(process)
            return_code = process.returncode
            descendant_error = _cleanup_lingering_process_group(
                process,
                diagnostic=_VERSION_DESCENDANT_DIAGNOSTIC,
            )
    except MacOSToolchainResolutionError:
        toolchain_resolution_failed = True
    except (OSError, subprocess.SubprocessError):
        if process is not None:
            _stop_process(process)
            return_code = process.returncode
            descendant_error = _cleanup_lingering_process_group(
                process,
                diagnostic=_VERSION_DESCENDANT_DIAGNOSTIC,
            )
        launch_failed = True
    finally:
        cleanup_error = _scanner_cleanup_error(backend, private_dir)

    if toolchain_resolution_failed:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.INTERPRETER_OR_LOADER_FAILURE,
            version=None,
            diagnostic=_INTERPRETER_OR_LOADER_DIAGNOSTIC,
            return_code=return_code,
        )
    if cleanup_error is not None or launch_failed or descendant_error is not None:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            version=None,
            diagnostic=descendant_error or _ISOLATION_FAILURE_DIAGNOSTIC,
            return_code=return_code,
        )
    if stdout_identity is None or stderr_identity is None:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            version=None,
            diagnostic=_ISOLATION_FAILURE_DIAGNOSTIC,
            return_code=return_code,
        )
    try:
        stdout_bytes = _read_attested_private_stream(
            stdout_path,
            stdout_identity,
            maximum_bytes=_VERSION_PROBE_OUTPUT_BYTES,
        )
        stderr_bytes = _read_attested_private_stream(
            stderr_path,
            stderr_identity,
            maximum_bytes=_VERSION_PROBE_OUTPUT_BYTES,
        )
    except (OSError, ValueError):
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            version=None,
            diagnostic="private tool-version evidence identity changed and was rejected",
            return_code=return_code,
        )
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    stdout_size = len(stdout_bytes)
    stderr_size = len(stderr_bytes)
    if timed_out:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.TIMED_OUT,
            version=None,
            diagnostic=_VERSION_TIMEOUT_DIAGNOSTIC,
            return_code=return_code,
        )
    if memory_monitor_failed or memory_exceeded:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            version=None,
            diagnostic=(
                _VERSION_MEMORY_MONITOR_DIAGNOSTIC
                if memory_monitor_failed
                else _VERSION_MEMORY_DIAGNOSTIC
            ),
            return_code=return_code,
        )
    if _probe_has_interpreter_or_loader_failure(stdout, stderr):
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.INTERPRETER_OR_LOADER_FAILURE,
            version=None,
            diagnostic=_INTERPRETER_OR_LOADER_DIAGNOSTIC,
            return_code=return_code,
        )
    if (
        output_exceeded
        or stdout_size >= _VERSION_PROBE_OUTPUT_BYTES
        or stderr_size >= _VERSION_PROBE_OUTPUT_BYTES
    ):
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.INVALID_VERSION,
            version=None,
            diagnostic=_INVALID_VERSION_DIAGNOSTIC,
            return_code=return_code,
        )
    if return_code != 0:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            version=None,
            diagnostic=_ISOLATION_FAILURE_DIAGNOSTIC,
            return_code=return_code,
        )
    version = _public_version_line(stdout, stderr, process_environment)
    if version is None:
        return ExecutableVersionProbe(
            status=ExecutableVersionProbeStatus.INVALID_VERSION,
            version=None,
            diagnostic=_INVALID_VERSION_DIAGNOSTIC,
            return_code=return_code,
        )
    return ExecutableVersionProbe(
        status=ExecutableVersionProbeStatus.SUCCESS,
        version=version,
        diagnostic=None,
        return_code=return_code,
    )


def isolated_executable_version(
    executable: str | Path,
    environment: dict[str, str],
    backend: ScannerIsolationBackend,
    workspace: Path,
    private_dir: Path,
    *,
    repository_javascript: bool = False,
    timeout_seconds: float = 15.0,
) -> str | None:
    """Compatibility projection returning only a validated public version."""

    return isolated_executable_version_probe(
        executable,
        environment,
        backend,
        workspace,
        private_dir,
        repository_javascript=repository_javascript,
        timeout_seconds=timeout_seconds,
    ).version


def preflight_scanner_executable(
    executable: str | Path,
    environment: dict[str, str],
    backend: ScannerIsolationBackend,
    workspace: Path,
    private_dir: Path,
    *,
    repository_javascript: bool = False,
    timeout_seconds: float = 15.0,
) -> ScannerExecutablePreflight:
    """Resolve and probe a tool into the exact three operator-facing states."""

    requested = Path(executable)
    candidate: str | None
    if requested.is_absolute():
        candidate = str(requested)
    elif requested.parent == Path("."):
        candidate = shutil.which(str(executable))
    else:
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            resolved_path=None,
            version=None,
            failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
            diagnostic="relative executable paths are refused by scanner preflight",
        )
    if candidate is None:
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.ABSENT,
            resolved_path=None,
            version=None,
            failure_kind=None,
            diagnostic="tool was not found on PATH",
        )
    try:
        resolved = Path(candidate).resolve(strict=True)
    except (OSError, RuntimeError):
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            resolved_path=None,
            version=None,
            failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
            diagnostic="resolved tool identity could not be validated safely",
        )
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            resolved_path=resolved,
            version=None,
            failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
            diagnostic="resolved tool is not an executable regular file",
        )
    try:
        probe = isolated_executable_version_probe(
            resolved,
            environment,
            backend,
            workspace,
            private_dir,
            repository_javascript=repository_javascript,
            timeout_seconds=timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError):
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            resolved_path=resolved,
            version=None,
            failure_kind=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
            diagnostic="private tool-probe evidence could not be retained safely",
        )
    if probe.status is ExecutableVersionProbeStatus.SUCCESS:
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_EXECUTABLE,
            resolved_path=resolved,
            version=probe.version,
            failure_kind=None,
            diagnostic=None,
        )
    if probe.status is ExecutableVersionProbeStatus.INVALID_VERSION:
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_EXECUTABLE,
            resolved_path=resolved,
            version=None,
            failure_kind=probe.status,
            diagnostic=probe.diagnostic,
        )
    return ScannerExecutablePreflight(
        state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
        resolved_path=resolved,
        version=None,
        failure_kind=probe.status,
        diagnostic=probe.diagnostic,
    )


def _scanner_cleanup_error(backend: object, private_dir: Path) -> str | None:
    try:
        cleanup_isolation_backend(backend, private_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return f"isolation cleanup verification failed: {type(exc).__name__}"
    return None


def _fixed_darwin_scanner_ca_bundle() -> Path | None:
    """Return the public system CA alias, never an inherited environment value."""

    candidate = Path("/etc/ssl/cert.pem")
    return candidate if sys.platform == "darwin" and candidate.is_file() else None


def sanitized_scanner_environment(private_dir: Path) -> dict[str, str]:
    """Create a minimal environment without inherited application credentials."""

    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    home = private_dir / "home"
    cache = private_dir / "cache"
    temporary = private_dir / "tmp"
    for path in (home, cache, temporary):
        path.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "HOME": str(home),
        "XDG_CACHE_HOME": str(cache),
        "TMPDIR": str(temporary),
        "NO_COLOR": "1",
        "CI": "true",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }
    if (ca_bundle := _fixed_darwin_scanner_ca_bundle()) is not None:
        environment["SSL_CERT_FILE"] = str(ca_bundle)
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def _limit_scanner_process(*, nproc_ceiling: int | None) -> None:
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("scanner resource bounds are unavailable") from exc
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if hasattr(resource, "RLIMIT_NPROC"):
            limit = 64 if nproc_ceiling is None else nproc_ceiling
            resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
        if hasattr(resource, "RLIMIT_AS"):
            try:
                resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
            except (OSError, ValueError):
                # See the version-probe note above. The parent-side process-group
                # monitor supplies the memory bound, and NPROC failure remains
                # fail-closed.
                if sys.platform != "darwin":
                    raise
    except (OSError, ValueError) as exc:
        raise RuntimeError("scanner resource bounds could not be applied") from exc


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate a scanner and its process group after a bound is crossed."""

    try:
        if os.name == "nt":
            if process.poll() is not None:
                return
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        if process.poll() is None:
            process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()


def _cleanup_lingering_process_group(
    process: subprocess.Popen[bytes],
    *,
    diagnostic: str,
) -> str | None:
    """Kill and reject descendants that outlive a completed process-group leader."""

    if os.name == "nt":
        return None

    def group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except OSError as exc:
            raise OSError("process-group absence could not be attested") from exc
        return True

    try:
        if not group_exists():
            return None
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return diagnostic
        deadline = time.monotonic() + 5
        while group_exists():
            if time.monotonic() >= deadline:
                return "scanner process-group descendants could not be terminated"
            time.sleep(0.01)
    except OSError:
        return "scanner process-group absence could not be attested"
    return diagnostic


def make_finding(
    *,
    root: Path,
    scanner: str,
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    path: str,
    start_line: int,
    end_line: int | None = None,
    cwe: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    evidence_strength: EvidenceStrength = EvidenceStrength.NONE,
) -> ScannerFinding | None:
    normalized = normalize_scanner_path(root, path)
    if normalized is None:
        return None
    line = max(1, int(start_line))
    final_line = max(line, int(end_line or line))
    return ScannerFinding(
        scanner=scanner,
        rule_id=rule_id or "unknown",
        title=title or rule_id or "Scanner finding",
        severity=severity,
        message=message or title or rule_id,
        locations=[Location(path=normalized, start_line=line, end_line=final_line)],
        cwe=cwe or [],
        metadata=metadata or {},
        evidence_strength=evidence_strength,
        fingerprint=scanner_fingerprint(scanner, rule_id, normalized, line, message),
    )
