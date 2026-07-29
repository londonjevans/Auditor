"""Common read-only scanner process and normalization interface."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
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
from mmaudit.repository.secrets import is_sensitive_workspace_path

_MAX_WORKSPACE_ENTRIES = 100_000
_MAX_WORKSPACE_FILES = 100_000
_MAX_WORKSPACE_FILE_BYTES = 100_000_000
_MAX_WORKSPACE_BYTES = 2 * 1024**3
_MAX_WORKSPACE_DEPTH = 128
_WORKSPACE_READ_BYTES = 1024 * 1024
_EXCLUDED_WORKSPACE_DIRECTORIES = frozenset(
    {
        ".git",
        ".mmaudit",
        ".next",
        ".venv",
        "__pycache__",
        "artifacts",
        "broadcast",
        "build",
        "cache",
        "coverage",
        "dist",
        "node_modules",
        "out",
        "target",
        "vendor",
        "venv",
    }
)


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
        return hashlib.sha256(
            json.dumps(
                self.bindings(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()


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
    workspace_created_exclusively: bool = True
    workspace_direct_child: bool = True
    audited_inventory_symlink_free: bool = True
    source_descriptor_custody_validated: bool = True
    workspace_descriptor_custody_validated: bool = True
    copy_matches_source: bool = True
    source_identity_stable: bool = True
    workspace_identity_stable: bool = True
    workspace_removed: bool = False


@dataclass(slots=True)
class ScannerWorkspaceCopyCustody:
    """Retain no-follow source/workspace root custody until final validation."""

    _source_root: Path
    _workspace_root: Path
    _source_private_dir: Path
    _source_fd: int
    _workspace_fd: int
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
            source_after = _build_scanner_workspace_inventory_from_descriptor(
                self._source_root,
                self._source_fd,
                self._source_private_dir,
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
        self._workspace_fd = -1
        self._source_fd = -1
        _close_workspace_descriptors(workspace_fd, source_fd)


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
            process_exit_code: int | None = None,
            machine_output_validated: bool = False,
        ) -> ScannerRun:
            output_sha256 = (
                _file_sha256(raw_path)
                if raw_output_path is not None and raw_path.is_file()
                else None
            )
            output_bytes = (
                raw_path.stat().st_size if raw_output_path is not None and raw_path.is_file() else 0
            )
            run = ScannerRun(
                scanner=self.name,
                status=status,
                execution_evidence=(
                    isolation_execution_evidence(backend)
                    if (
                        status is ScannerStatus.SUCCESS
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
                raw_output_sha256=output_sha256,
                raw_output_bytes=output_bytes,
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
            copy_scanner_workspace(root, workspace, private_dir)
        except (OSError, ValueError) as exc:
            return finish(
                ScannerStatus.FAILED,
                error=f"could not create isolated scanner workspace: {type(exc).__name__}",
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
                command = backend.wrap(
                    command,
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=1,
                )
            version = isolated_executable_version(
                str(executable_path) if executable_path is not None else self.executable,
                environment,
                backend,
                workspace,
                private_dir,
                repository_javascript=loads_repository_code,
            )
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
        process: subprocess.Popen[bytes] | None = None
        process_error: str | None = None
        try:
            with raw_path.open("wb") as stdout_handle, error_path.open("wb") as stderr_handle:
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
                    preexec_fn=_limit_scanner_process if os.name != "nt" else None,
                )
                deadline = time.monotonic() + timeout_seconds
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        raw_path.stat().st_size > self.max_stdout_bytes
                        or error_path.stat().st_size > self.max_stderr_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                _stop_process(process)
            return_code = (
                process.returncode if process is not None and process.returncode is not None else -1
            )
        except OSError as exc:
            process_error = f"scanner process failed: {type(exc).__name__}"
            return_code = -1
        cleanup_error = _scanner_cleanup_error(backend, private_dir)
        if process_error or cleanup_error:
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error=cleanup_error or process_error,
            )
        if timed_out:
            return finish(
                ScannerStatus.TIMED_OUT,
                version=version,
                command=command,
                error=f"scanner exceeded {timeout_seconds:.0f}s timeout",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
                process_exit_code=return_code,
            )
        if (
            output_exceeded
            or raw_path.stat().st_size > self.max_stdout_bytes
            or error_path.stat().st_size > self.max_stderr_bytes
        ):
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error="scanner output exceeded the private output limit",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
                process_exit_code=return_code,
            )

        stdout = raw_path.read_text(encoding="utf-8", errors="replace")
        if return_code not in self.finding_exit_codes:
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error=f"scanner exited with code {return_code}",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
                process_exit_code=return_code,
            )
        try:
            findings = self.parse(workspace, stdout, private_dir)
        except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as exc:
            return finish(
                ScannerStatus.FAILED,
                version=version,
                command=command,
                error=f"invalid scanner output: {type(exc).__name__}",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
                process_exit_code=return_code,
            )
        return finish(
            ScannerStatus.SUCCESS,
            version=version,
            command=command,
            findings=findings,
            raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            process_exit_code=return_code,
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
    if (
        version is None
        or re.search(
            rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])",
            version,
        )
        is None
    ):
        return "scanner version does not match the configured trust pin"
    return None


def copy_scanner_workspace(root: Path, workspace: Path, private_dir: Path) -> None:
    """Copy exactly one bounded, pruned, no-follow source inventory."""

    custody = copy_scanner_workspace_with_custody(root, workspace, private_dir)
    custody.finalize()


def copy_scanner_workspace_with_custody(
    root: Path,
    workspace: Path,
    private_dir: Path,
) -> ScannerWorkspaceCopyCustody:
    """Exclusively copy one audited inventory and retain both root descriptors."""

    source_root, source_identity = _openable_workspace_root(root)
    source_fd = _open_workspace_directory(source_root)
    workspace_fd = -1
    primary_error: BaseException | None = None
    try:
        _require_workspace_identity(os.fstat(source_fd), source_identity)
        source_inventory = _build_scanner_workspace_inventory_from_descriptor(
            source_root,
            source_fd,
            private_dir,
        )
        workspace_root, workspace_fd = _create_exclusive_workspace_root(workspace)
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
            _source_private_dir=private_dir,
            _source_fd=source_fd,
            _workspace_fd=workspace_fd,
            _source_before=source_inventory,
            _workspace_after_copy=workspace_inventory,
        )
        source_fd = -1
        workspace_fd = -1
        return custody
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            _close_workspace_descriptors(workspace_fd, source_fd)
        except OSError:
            if primary_error is None:
                raise


def scanner_workspace_sha256(root: Path, private_dir: Path | None = None) -> str:
    """Hash the exact bounded, non-secret tree copied into scanner workspaces."""

    exclusion_root = private_dir if private_dir is not None else root / ".mmaudit"
    return _build_scanner_workspace_inventory(root, exclusion_root).sha256()


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
        )
    finally:
        os.close(root_fd)


def _build_scanner_workspace_inventory_from_descriptor(
    repository_root: Path,
    root_fd: int,
    private_dir: Path,
) -> _ScannerWorkspaceInventory:
    """Inventory through an already-custodied no-follow root descriptor."""

    root_identity = _WorkspaceIdentity.from_stat(os.fstat(root_fd))
    private_relative = _workspace_private_relative(repository_root, private_dir)
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
    return parts


def _workspace_relative_excluded(
    relative: str,
    *,
    is_dir: bool,
    private_relative: tuple[str, ...] | None,
) -> bool:
    parts = PurePosixPath(relative).parts
    if private_relative is not None and parts[: len(private_relative)] == private_relative:
        return True
    if any(part.lower() in _EXCLUDED_WORKSPACE_DIRECTORIES for part in parts):
        return True
    return is_sensitive_workspace_path(relative, is_dir=is_dir)


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


def _create_exclusive_workspace_root(workspace: Path) -> tuple[Path, int]:
    requested_parent = workspace.parent.absolute()
    parent_root, parent_identity = _openable_workspace_root(requested_parent)
    if requested_parent != parent_root or workspace.name in {"", ".", ".."}:
        raise ValueError("scanner workspace must be a canonical direct child")
    parent_fd = _open_workspace_directory(parent_root)
    workspace_fd = -1
    created_identity: _WorkspaceIdentity | None = None
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
        return parent_root / workspace.name, workspace_fd
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
    if not 0 < timeout_seconds <= 15.0:
        raise ValueError("isolated executable version timeout is outside its fixed bound")
    result: subprocess.CompletedProcess[str] | None = None
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
            command = backend.wrap(
                [str(executable), "--version"],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=1,
            )
        process_environment = isolation_host_environment(
            backend,
            private_dir,
            environment,
        )
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=process_environment,
            shell=False,
            cwd=workspace,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    finally:
        cleanup_isolation_backend(backend, private_dir)
    if result is None:
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return "\n".join(output)[:1_000] if output else None


def _scanner_cleanup_error(backend: object, private_dir: Path) -> str | None:
    try:
        cleanup_isolation_backend(backend, private_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return f"isolation cleanup verification failed: {type(exc).__name__}"
    return None


def sanitized_scanner_environment(private_dir: Path) -> dict[str, str]:
    """Create a minimal environment without inherited application credentials."""

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
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def _limit_scanner_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate a scanner and its process group after a bound is crossed."""

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
