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
    ExecutionEvidenceKind,
    Location,
    RepositoryCodeExecutionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.repository.workspace import validate_copyable_workspace

_MAX_WORKSPACE_FILES = 100_000
_MAX_WORKSPACE_BYTES = 2 * 1024**3
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
    """Copy bounded, non-secret regular files without following repository links."""

    repository_root = root.resolve(strict=True)
    private_root = private_dir.resolve(strict=False)
    if workspace.exists():
        raise OSError("scanner workspace already exists")
    validate_copyable_workspace(
        repository_root,
        excluded=lambda path: _workspace_path_excluded(
            path,
            repository_root,
            private_root,
        ),
        max_files=_MAX_WORKSPACE_FILES,
        max_total_bytes=_MAX_WORKSPACE_BYTES,
    )

    def ignore(directory: str, names: list[str]) -> set[str]:
        parent = Path(directory)
        return {
            name
            for name in names
            if _workspace_path_excluded(parent / name, repository_root, private_root)
        }

    shutil.copytree(repository_root, workspace, symlinks=False, ignore=ignore)


def scanner_workspace_sha256(root: Path, private_dir: Path | None = None) -> str:
    """Hash the exact bounded, non-secret tree copied into scanner workspaces."""

    repository_root = root.resolve(strict=True)
    private_root = (
        private_dir.resolve(strict=False)
        if private_dir is not None
        else (repository_root / ".mmaudit").resolve(strict=False)
    )

    def excluded(path: Path) -> bool:
        return _workspace_path_excluded(path, repository_root, private_root)

    validate_copyable_workspace(
        repository_root,
        excluded=excluded,
        max_files=_MAX_WORKSPACE_FILES,
        max_total_bytes=_MAX_WORKSPACE_BYTES,
    )
    bindings: list[dict[str, str | int]] = []
    total_bytes = 0
    for candidate in sorted(repository_root.rglob("*"), key=lambda item: item.as_posix()):
        if excluded(candidate) or candidate.is_dir():
            continue
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("scanner workspace hash requires unique regular files")
        total_bytes += metadata.st_size
        if len(bindings) + 1 > _MAX_WORKSPACE_FILES or total_bytes > _MAX_WORKSPACE_BYTES:
            raise ValueError("scanner workspace hash bounds were exceeded")
        bindings.append(
            {
                "path": candidate.relative_to(repository_root).as_posix(),
                "sha256": _file_sha256(candidate),
                "size": metadata.st_size,
            }
        )
    return hashlib.sha256(
        json.dumps(
            bindings,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _workspace_path_excluded(path: Path, root: Path, private_dir: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    try:
        path.resolve(strict=False).relative_to(private_dir)
    except ValueError:
        pass
    else:
        return True
    if any(part.lower() in _EXCLUDED_WORKSPACE_DIRECTORIES for part in relative.parts):
        return True
    return is_sensitive_workspace_path(relative, is_dir=path.is_dir())


def isolated_executable_version(
    executable: str | Path,
    environment: dict[str, str],
    backend: ScannerIsolationBackend,
    workspace: Path,
    private_dir: Path,
    *,
    repository_javascript: bool = False,
) -> str | None:
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
            timeout=15,
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
        fingerprint=scanner_fingerprint(scanner, rule_id, normalized, line, message),
    )
