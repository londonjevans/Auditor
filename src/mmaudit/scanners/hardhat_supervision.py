"""Independent bounded phase capture, not Hardhat launch admission or execution authority.

Only a trusted executor may supply the command and explicit scrubbed environment. This layer
does not attest an image, contain repository code, authenticate reporter claims or stop containers.
Production Hardhat must still refuse until those separate boundaries are satisfied.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import selectors
import stat
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal

from mmaudit.models.schemas import HardhatInventoryPhaseRequest, HardhatTestPhaseRequest
from mmaudit.release_io import read_file_evidence
from mmaudit.scanners.base import (
    _cleanup_lingering_process_group,
    _observe_scanner_executable,
    _stop_process,
)

HARDHAT_PHASE_REPORT_NAME = "hardhat-report.json"
_READ_BYTES = 64 * 1024
_POLL_SECONDS = 0.05
_MAX_COMMAND_BYTES = 128 * 1024
_MAX_ENVIRONMENT_BYTES = 64 * 1024
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")

type HardhatPhaseRequest = HardhatInventoryPhaseRequest | HardhatTestPhaseRequest


class HardhatSupervisionError(ValueError):
    """The selected capture boundary changed or could not safely retain its observations."""


class HardhatCaptureOutcome(StrEnum):
    EXITED = "EXITED"
    SPAWN_FAILED = "SPAWN_FAILED"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    REPORT_UNAVAILABLE = "REPORT_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class HardhatPhaseCapture:
    """Detached parent observations; even complete capture grants no execution credit."""

    request_sha256: str
    phase: Literal["inventory", "test"]
    outcome: HardhatCaptureOutcome
    process_exit_code: int | None
    duration_seconds: float
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    report: bytes | None = field(repr=False)

    @property
    def complete(self) -> bool:
        return (
            self.outcome is HardhatCaptureOutcome.EXITED
            and self.process_exit_code == 0
            and self.report is not None
        )

    @property
    def execution_credit(self) -> Literal[False]:
        return False

    @property
    def runtime_authority(self) -> Literal[False]:
        return False

    @property
    def stdout_sha256(self) -> str:
        return hashlib.sha256(self.stdout).hexdigest()

    @property
    def stderr_sha256(self) -> str:
        return hashlib.sha256(self.stderr).hexdigest()

    @property
    def report_sha256(self) -> str | None:
        return hashlib.sha256(self.report).hexdigest() if self.report is not None else None


def _detached_request(request: HardhatPhaseRequest) -> tuple[HardhatPhaseRequest, str]:
    if type(request) not in {HardhatInventoryPhaseRequest, HardhatTestPhaseRequest}:
        raise HardhatSupervisionError("Hardhat supervision requires an exact phase request")
    serialized = request.model_dump_json()
    try:
        detached = type(request).model_validate_json(serialized, strict=True)
    except (TypeError, ValueError):
        raise HardhatSupervisionError("Hardhat phase request is invalid") from None
    return detached, serialized


def _root_identity(path: Path, *, private: bool) -> tuple[int, int, int, int, int]:
    try:
        if not path.is_absolute() or ".." in path.parts or path.resolve(strict=True) != path:
            raise ValueError("root alias")
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("root type")
        if private and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError("private root ownership")
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )
    except (OSError, RuntimeError, ValueError):
        raise HardhatSupervisionError("Hardhat supervision root is unavailable or unsafe") from None


def _command_and_environment(
    command: tuple[str, ...], environment: dict[str, str], workspace: Path, output_root: Path
) -> tuple[tuple[str, ...], dict[str, str], Path]:
    try:
        if (
            type(command) is not tuple
            or not 1 <= len(command) <= 256
            or any(type(item) is not str or "\x00" in item for item in command)
            or sum(len(item.encode("utf-8")) for item in command) > _MAX_COMMAND_BYTES
            or type(environment) is not dict
            or len(environment) > 64
            or any(
                type(key) is not str
                or type(value) is not str
                or _ENVIRONMENT_NAME.fullmatch(key) is None
                or "\x00" in value
                for key, value in environment.items()
            )
            or sum(len((key + value).encode("utf-8")) for key, value in environment.items())
            > _MAX_ENVIRONMENT_BYTES
        ):
            raise ValueError("command or environment bounds")
        executable = Path(command[0])
        if (
            not executable.is_absolute()
            or executable.resolve(strict=True) != executable
            or executable.is_relative_to(workspace)
            or executable.is_relative_to(output_root)
        ):
            raise ValueError("runtime executable path")
        return command, environment.copy(), executable
    except (OSError, RuntimeError, TypeError, ValueError):
        raise HardhatSupervisionError("Hardhat supervisor launch inputs are invalid") from None


def _capture_pipes(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    maximum_bytes: int,
    report_path: Path | None,
) -> tuple[HardhatCaptureOutcome, bytes, bytes]:
    """Drain both anonymous pipes fairly without blocking on EOF or allocating unbounded output."""

    if process.stdout is None or process.stderr is None:
        raise HardhatSupervisionError("Hardhat capture requires both owned output pipes")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    outcome = HardhatCaptureOutcome.EXITED
    with selectors.DefaultSelector() as selector:
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                outcome = HardhatCaptureOutcome.TIMED_OUT
                break
            try:
                report_size = report_path.lstat().st_size if report_path is not None else 0
            except FileNotFoundError:
                report_size = 0
            if total + report_size > maximum_bytes:
                outcome = HardhatCaptureOutcome.OUTPUT_LIMIT
                break
            for key, _ in selector.select(min(_POLL_SECONDS, remaining_time)):
                try:
                    chunk = os.read(key.fd, min(_READ_BYTES, maximum_bytes - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                available = maximum_bytes - total
                output[key.data].extend(chunk[:available])
                total += min(len(chunk), available)
                if len(chunk) > available or total + report_size > maximum_bytes:
                    return (
                        HardhatCaptureOutcome.OUTPUT_LIMIT,
                        bytes(output["stdout"]),
                        bytes(output["stderr"]),
                    )
    return outcome, bytes(output["stdout"]), bytes(output["stderr"])


def _claim_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


@contextmanager
def _claim_output(output_root: Path) -> Iterator[None]:
    """Irreversibly claim a phase directory using a marker outside its child-writable mount."""

    parent_identity = _root_identity(output_root.parent, private=True)
    key = hashlib.sha256(str(output_root).encode("utf-8")).hexdigest()
    claim_path = output_root.parent / (".mmaudit-hardhat-" + key + ".claim")
    try:
        descriptor = os.open(
            claim_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        raise HardhatSupervisionError("Hardhat output directory claim is unavailable") from None
    primary_error: BaseException | None = None
    identity: tuple[int, ...] | None = None
    try:
        os.fchmod(descriptor, 0o600)
        identity = _claim_identity(os.fstat(descriptor))
        yield
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        error: BaseException | None = None
        try:
            if (
                identity is None
                or _root_identity(output_root.parent, private=True) != parent_identity
                or _claim_identity(os.fstat(descriptor)) != identity
                or _claim_identity(claim_path.lstat()) != identity
            ):
                raise HardhatSupervisionError("Hardhat output directory claim changed")
        except BaseException as exc:
            error = exc
        finally:
            try:
                os.close(descriptor)
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None and primary_error is None:
            raise error


def _cleanup_child(process: subprocess.Popen[bytes]) -> bool:
    """Reap the owned leader and reject descendants even when the leader reports success."""

    if process.poll() is None:
        _stop_process(process)
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return (
        _cleanup_lingering_process_group(
            process, diagnostic="Hardhat phase left an owned descendant"
        )
        is None
    )


def supervise_hardhat_phase_process(
    request: HardhatPhaseRequest,
    *,
    command: tuple[str, ...],
    workspace: Path,
    output_root: Path,
    environment: dict[str, str],
    absolute_deadline: float | None = None,
    maximum_output_bytes: int | None = None,
) -> HardhatPhaseCapture:
    """Capture a trusted executor's already-admitted command; this is not launch authorization.

    Only the owned POSIX child group is supervised. Image identity, container teardown, repository
    isolation and semantic report validation remain separate mandatory executor responsibilities.
    Shared allowances can only narrow the sealed request. Expiry cannot skip bounded emergency
    cleanup; cleanup overruns cannot produce a successful capture.
    """

    if os.name != "posix":
        raise HardhatSupervisionError("Hardhat supervision requires POSIX process groups")
    detached, request_json = _detached_request(request)
    if absolute_deadline is not None and (
        type(absolute_deadline) not in {int, float}
        or not math.isfinite(absolute_deadline)
        or absolute_deadline <= time.monotonic()
    ):
        raise HardhatSupervisionError("Hardhat shared deadline is invalid or exhausted")
    if maximum_output_bytes is not None and (
        type(maximum_output_bytes) is not int
        or not 0 < maximum_output_bytes <= detached.maximum_output_bytes
    ):
        raise HardhatSupervisionError("Hardhat shared output allowance must narrow the request")
    output_limit = (
        detached.maximum_output_bytes if maximum_output_bytes is None else maximum_output_bytes
    )
    workspace_identity = _root_identity(workspace, private=False)
    output_identity = _root_identity(output_root, private=True)
    if workspace.is_relative_to(output_root) or output_root.is_relative_to(workspace):
        raise HardhatSupervisionError("Hardhat workspace and capture output overlap")
    report_path = output_root / HARDHAT_PHASE_REPORT_NAME
    try:
        report_path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise HardhatSupervisionError("Hardhat phase output already exists")
    argv, child_environment, executable = _command_and_environment(
        command, environment, workspace, output_root
    )
    executable_identity = _observe_scanner_executable(executable)

    def verify_selection() -> None:
        if (
            _root_identity(workspace, private=False) != workspace_identity
            or _root_identity(output_root, private=True) != output_identity
            or _observe_scanner_executable(executable) != executable_identity
            or request.model_dump_json() != request_json
        ):
            raise HardhatSupervisionError("Hardhat supervision selection changed")

    with _claim_output(output_root):
        verify_selection()
        start = time.monotonic()
        deadline = start + detached.timeout_seconds
        if absolute_deadline is not None:
            deadline = min(deadline, absolute_deadline)
        if start >= deadline:
            raise HardhatSupervisionError("Hardhat shared deadline expired before launch")
        process: subprocess.Popen[bytes] | None = None
        stdout, stderr = b"", b""
        report: bytes | None = None
        outcome = HardhatCaptureOutcome.SPAWN_FAILED
        primary_error: BaseException | None = None
        try:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=workspace,
                    env=child_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                )
            except OSError:
                pass
            else:
                outcome, stdout, stderr = _capture_pipes(
                    process,
                    deadline=deadline,
                    maximum_bytes=output_limit,
                    report_path=report_path,
                )
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            cleanup_error: BaseException | None = None
            if process is not None:
                try:
                    if not _cleanup_child(process):
                        outcome = HardhatCaptureOutcome.CLEANUP_FAILED
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
            try:
                verify_selection()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
            if cleanup_error is not None and primary_error is None:
                raise cleanup_error
        if outcome is HardhatCaptureOutcome.EXITED and time.monotonic() >= deadline:
            outcome = HardhatCaptureOutcome.TIMED_OUT
        if outcome is HardhatCaptureOutcome.EXITED:
            remaining = output_limit - len(stdout) - len(stderr)
            try:
                if remaining <= 0 or report_path.lstat().st_size > remaining:
                    outcome = HardhatCaptureOutcome.OUTPUT_LIMIT
                else:
                    report = read_file_evidence(
                        evidence_root=output_root,
                        relative_path=HARDHAT_PHASE_REPORT_NAME,
                        max_bytes=remaining,
                    ).content
            except (OSError, ValueError):
                outcome = HardhatCaptureOutcome.REPORT_UNAVAILABLE
        verify_selection()
        if outcome is HardhatCaptureOutcome.EXITED and time.monotonic() >= deadline:
            outcome = HardhatCaptureOutcome.TIMED_OUT
            report = None
        return HardhatPhaseCapture(
            request_sha256=detached.request_sha256,
            phase=detached.phase,
            outcome=outcome,
            process_exit_code=process.returncode if process is not None else None,
            duration_seconds=time.monotonic() - start,
            stdout=stdout,
            stderr=stderr,
            report=report,
        )
