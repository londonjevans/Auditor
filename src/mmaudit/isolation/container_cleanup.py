"""Bounded exact-ID cleanup observations, never image admission or execution authority.

The trusted caller must own the private CID and runtime selection from launch through cleanup.
Local identity rechecks do not attest a daemon, its state, an image or through-exec custody.
"""

from __future__ import annotations

import math
import os
import re
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal

from mmaudit.isolation.container import (
    RootlessContainerBackend,
    SingleLoopbackHardhatBackend,
    rootless_runtime_environment,
)
from mmaudit.release_io import read_file_evidence
from mmaudit.scanners.base import _observe_scanner_executable, _ScannerExecutableObservation
from mmaudit.scanners.hardhat_supervision import (
    HardhatCaptureOutcome,
    _capture_pipes,
    _cleanup_child,
    _command_and_environment,
    _root_identity,
)

_MAX_CONTROL_BYTES = 4096
_MAX_CLEANUP_SECONDS = 30.0
_CID_NAME = "container.cid"


class ContainerCleanupError(RuntimeError):
    """The owned container's absence could not be established safely."""


class ContainerCleanupStatus(StrEnum):
    NO_IDENTIFIER = "NO_IDENTIFIER"
    ALREADY_ABSENT = "ALREADY_ABSENT"
    REMOVED = "REMOVED"


@dataclass(frozen=True, slots=True)
class ContainerCleanupObservation:
    """A boundary-local runtime response, not independently authenticated container proof."""

    status: ContainerCleanupStatus
    container_id: str | None = field(repr=False)

    @property
    def absence_verified(self) -> bool:
        return self.status in {
            ContainerCleanupStatus.ALREADY_ABSENT,
            ContainerCleanupStatus.REMOVED,
        }

    @property
    def execution_credit(self) -> Literal[False]:
        return False

    @property
    def runtime_authority(self) -> Literal[False]:
        return False


def _directory_identity(path: Path, *, private: bool) -> tuple[int, ...]:
    identity = _root_identity(path, private=private)
    if identity[3] != os.getuid() or stat.S_IMODE(identity[2]) & 0o022:
        raise ContainerCleanupError("container cleanup directory ownership is unsafe")
    return identity


def _cid_identity(path: Path) -> tuple[int, ...]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 64 <= metadata.st_size <= 65
    ):
        raise ContainerCleanupError("container cleanup identifier is not a bounded owned file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _runtime_identity(executable: Path, private_dir: Path) -> _ScannerExecutableObservation:
    if executable.is_relative_to(private_dir) or executable.is_relative_to(Path.cwd().resolve()):
        raise ContainerCleanupError("container cleanup refuses a repository/private executable")
    return _observe_scanner_executable(executable)


def _control_environment(
    executable: Path, private_dir: Path, environment: dict[str, str] | None
) -> dict[str, str]:
    """Retain explicit launch routing; never silently rebuild a supplied client selection."""

    fixed_path = str(executable.parent) + os.pathsep + "/usr/bin:/bin"
    if environment is None:
        selected = rootless_runtime_environment(private_dir / "container-runtime")
        selected["PATH"] = fixed_path
        client_home = private_dir / "container-runtime/runtime-home"
    else:
        if type(environment) is not dict:
            raise ContainerCleanupError(
                "container cleanup requires an explicit environment mapping"
            )
        selected = environment.copy()
        client_home = private_dir / "runtime-client/runtime-home"
    if any(type(key) is not str or type(value) is not str for key, value in selected.items()):
        raise ContainerCleanupError("container cleanup environment keys and values must be strings")
    if (
        set(selected)
        - {"PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DOCKER_HOST", "CONTAINER_HOST"}
        or selected.get("PATH") != fixed_path
        or selected.get("HOME") != str(client_home)
        or any(
            re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", selected[name]) is None
            for name in ("DOCKER_HOST", "CONTAINER_HOST")
            if name in selected
        )
        or ("XDG_RUNTIME_DIR" in selected and not Path(selected["XDG_RUNTIME_DIR"]).is_absolute())
    ):
        raise ContainerCleanupError("container cleanup runtime environment is unsafe or changed")
    _directory_identity(client_home, private=True)
    _, checked, _ = _command_and_environment(
        (str(executable),), selected, Path.cwd().resolve(), private_dir
    )
    return checked


def _run_control_command(
    command: tuple[str, ...], *, runtime_dir: Path, environment: dict[str, str], deadline: float
) -> bytes:
    """Capture one fixed runtime control command and always reap its owned POSIX group."""

    argv, child_environment, _ = _command_and_environment(
        command, environment, Path.cwd().resolve(), runtime_dir
    )
    if time.monotonic() >= deadline:
        raise ContainerCleanupError("container cleanup deadline expired before control launch")
    process: subprocess.Popen[bytes] | None = None
    primary_error: BaseException | None = None
    outcome = HardhatCaptureOutcome.SPAWN_FAILED
    stdout, stderr = b"", b""
    try:
        process = subprocess.Popen(
            argv,
            cwd=runtime_dir,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
        outcome, stdout, stderr = _capture_pipes(
            process, deadline=deadline, maximum_bytes=_MAX_CONTROL_BYTES, report_path=None
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        if process is not None:
            try:
                if not _cleanup_child(process):
                    raise ContainerCleanupError("container cleanup control group was not clean")
            except BaseException as exc:
                cleanup_error = exc
            finally:
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except BaseException as exc:
                            if cleanup_error is None:
                                cleanup_error = exc
        if cleanup_error is not None and primary_error is None:
            raise cleanup_error
    if (
        outcome is not HardhatCaptureOutcome.EXITED
        or process is None
        or process.returncode != 0
        or stderr
        or time.monotonic() >= deadline
    ):
        raise ContainerCleanupError("container cleanup control failed, expired or was ambiguous")
    return stdout


def cleanup_rootless_container(
    backend: RootlessContainerBackend,
    private_dir: Path,
    *,
    timeout_seconds: float = 30.0,
    environment: dict[str, str] | None = None,
    expected_runtime_identity: _ScannerExecutableObservation | None = None,
    expected_container_id: str | None = None,
) -> ContainerCleanupObservation:
    """Remove only a selected full CID, requiring a successful scoped query to establish absence.

    No CID returns NO_IDENTIFIER without a process; a started launch must not treat it as absence.
    The separate finite emergency-cleanup budget cannot be skipped because an audit expired.
    Expiry rejects the result, but trusted Python/file work is not preempted; child reaping remains
    bounded and mandatory after expiry. The private control-plane directory must not be child-writable.
    A trusted phase finalizer supplies its retained launch environment and executable/CID
    observations. These are narrowing custody checks, never serialized launch or image authority.
    """

    if (
        os.name != "posix"
        or type(backend) not in {RootlessContainerBackend, SingleLoopbackHardhatBackend}
        or type(timeout_seconds) not in {int, float}
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= _MAX_CLEANUP_SECONDS
        or (environment is not None and type(environment) is not dict)
        or (
            expected_runtime_identity is not None
            and type(expected_runtime_identity) is not _ScannerExecutableObservation
        )
        or (
            expected_container_id is not None
            and (
                type(expected_container_id) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is None
            )
        )
    ):
        raise ContainerCleanupError("container cleanup inputs or POSIX controls are unavailable")
    deadline = time.monotonic() + timeout_seconds
    try:
        return _cleanup_selected_container(
            backend,
            private_dir,
            deadline=deadline,
            environment=None if environment is None else environment.copy(),
            expected_runtime_identity=expected_runtime_identity,
            expected_container_id=expected_container_id,
        )
    except (OSError, ValueError) as exc:
        raise ContainerCleanupError("container cleanup custody or control is unavailable") from exc


def _cleanup_selected_container(
    backend: RootlessContainerBackend,
    private_dir: Path,
    *,
    deadline: float,
    environment: dict[str, str] | None,
    expected_runtime_identity: _ScannerExecutableObservation | None,
    expected_container_id: str | None,
) -> ContainerCleanupObservation:
    private_identity = _directory_identity(private_dir, private=False)
    runtime_dir = private_dir / "container-runtime"
    try:
        runtime_dir.lstat()
    except FileNotFoundError:
        return ContainerCleanupObservation(ContainerCleanupStatus.NO_IDENTIFIER, None)
    runtime_identity = _directory_identity(runtime_dir, private=True)
    cidfile = runtime_dir / _CID_NAME
    try:
        cid_identity = _cid_identity(cidfile)
    except FileNotFoundError:
        return ContainerCleanupObservation(ContainerCleanupStatus.NO_IDENTIFIER, None)
    cid = read_file_evidence(evidence_root=runtime_dir, relative_path=_CID_NAME, max_bytes=65)
    if re.fullmatch(rb"[0-9a-f]{64}\n?", cid.content) is None:
        raise ContainerCleanupError("container cleanup requires one exact full runtime identifier")
    container_id = cid.content[:64].decode("ascii")
    if expected_container_id is not None and container_id != expected_container_id:
        raise ContainerCleanupError("container cleanup identifier differs from the retained phase")
    backend_snapshot = asdict(backend)
    executable = Path(backend.executable)
    executable_identity = _runtime_identity(executable, private_dir)
    if expected_runtime_identity is not None and executable_identity != expected_runtime_identity:
        raise ContainerCleanupError("container cleanup executable differs from the retained launch")
    environment = _control_environment(executable, private_dir, environment)
    client_home = Path(environment["HOME"])
    home_identity = _directory_identity(client_home, private=True)

    def verify_custody() -> None:
        if (
            asdict(backend) != backend_snapshot
            or _directory_identity(private_dir, private=False) != private_identity
            or _directory_identity(runtime_dir, private=True) != runtime_identity
            or _directory_identity(client_home, private=True) != home_identity
            or _cid_identity(cidfile) != cid_identity
            or read_file_evidence(evidence_root=runtime_dir, relative_path=_CID_NAME, max_bytes=65)
            != cid
            or _runtime_identity(executable, private_dir) != executable_identity
        ):
            raise ContainerCleanupError("container cleanup selection changed")
        if time.monotonic() >= deadline:
            raise ContainerCleanupError("container cleanup shared deadline expired")

    def control(*arguments: str) -> bytes:
        verify_custody()
        output = _run_control_command(
            (backend.executable, *arguments),
            runtime_dir=runtime_dir,
            environment=environment.copy(),
            deadline=min(deadline, time.monotonic() + 10.0),
        )
        verify_custody()
        return output

    def present() -> bool:
        output = control(
            "container", "ls", "--all", "--no-trunc", "--quiet", "--filter", "id=" + container_id
        )
        if output == b"":
            return False
        if output not in {container_id.encode("ascii"), container_id.encode("ascii") + b"\n"}:
            raise ContainerCleanupError("container cleanup query returned ambiguous identifiers")
        return True

    status = ContainerCleanupStatus.ALREADY_ABSENT
    if present():
        control("rm", "--force", container_id)
        if present():
            raise ContainerCleanupError("container cleanup could not verify removal")
        status = ContainerCleanupStatus.REMOVED
    verify_custody()
    # Hold the exact parent while removing only its rechecked CID, never an aliased path.
    descriptor = os.open(runtime_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != runtime_identity[:2]:
            raise ContainerCleanupError("container cleanup parent changed before evidence removal")
        verify_custody()
        os.unlink(_CID_NAME, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    if time.monotonic() >= deadline:
        raise ContainerCleanupError("container cleanup evidence finalization exceeded its deadline")
    return ContainerCleanupObservation(status, container_id)
