"""Trusted, hash-pinned clean Anvil lifecycle for repository-suite comparisons."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Literal, Protocol

import httpx

from mmaudit.config import RepositoryCleanForkMatrixStateConfig
from mmaudit.models.schemas import (
    RepositoryCleanExecPathBindingKind,
    RepositoryCleanListenerOwnershipKind,
    RepositoryCleanRuntimeExecutableIdentityKind,
    RepositoryCleanStateAttestationEvidence,
)
from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    PinnedForkObservation,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)

_LAUNCHER_POLICY_VERSION = "2.0"
_LOOPBACK_HOST = "127.0.0.1"
_GENESIS_BLOCK_NUMBER = 0
_BLOCK_GAS_LIMIT = 30_000_000
_BLOCK_BASE_FEE_WEI = 1_000_000_000
_GAS_PRICE_WEI = 1_000_000_000
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_PORT_ATTEMPTS = 3
_OBSERVATION_TIMEOUT_SECONDS = 1.0
CLEAN_ANVIL_VERSION_ATTESTATION_TIMEOUT_SECONDS = 3.0
_PORT_BIND_STABILITY_SECONDS = 0.05
_STARTUP_POLL_SECONDS = 0.02
_TERMINATION_POLL_SECONDS = 0.01
_MIN_DEADLINE_SLACK_SECONDS = 0.01
_MAX_CLEANUP_RESERVE_SECONDS = 0.25
_MAX_ANCESTOR_DEPTH = 64
_MAX_ANCESTOR_ENTRIES = 10_000
_MAX_RPC_RESPONSE_BYTES = 65_536
_MACOS_LSOF = Path("/usr/sbin/lsof")


class CleanAnvilError(RuntimeError):
    """Base failure for the trusted clean-chain lifecycle."""


class CleanAnvilConfigurationError(CleanAnvilError, ValueError):
    """A configured executable or private workspace was not trustworthy."""


class CleanAnvilUnavailableError(CleanAnvilError):
    """A trusted clean chain could not be started or stopped within its bounds."""


class CleanAnvilIdentityError(CleanAnvilError):
    """The running chain did not retain its exact configured genesis identity."""


class _ProcessFactory(Protocol):
    def __call__(self, args: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]: ...


class _Observer(Protocol):
    def __call__(
        self,
        endpoint: str,
        *,
        expected_chain_id: int | None,
        pinned_block_number: int | None,
        timeout_seconds: float,
    ) -> PinnedForkObservation: ...


@dataclass(frozen=True, slots=True)
class _HeadObservation:
    block_number: int
    block_hash: str
    state_root: str


@dataclass(frozen=True, slots=True)
class _PristineObservation:
    genesis: PinnedForkObservation
    head: _HeadObservation


@dataclass(frozen=True, slots=True)
class _ExecutableIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> _ExecutableIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=metadata.st_mode,
            links=metadata.st_nlink,
            size=metadata.st_size,
            modified_ns=metadata.st_mtime_ns,
            changed_ns=metadata.st_ctime_ns,
        )

    def matches(self, metadata: os.stat_result) -> bool:
        return self == self.from_stat(metadata)


class _HeadObserver(Protocol):
    def __call__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float,
    ) -> _HeadObservation: ...


class _ListenerOwnerVerifier(Protocol):
    def __call__(
        self,
        process: subprocess.Popen[bytes],
        *,
        host: str,
        port: int,
        deadline: float,
    ) -> bool: ...


class _RuntimeExecutableVerifier(Protocol):
    def __call__(
        self,
        process: subprocess.Popen[bytes],
        expected_identity: _ExecutableIdentity,
    ) -> bool: ...


class _BoundedOutput:
    """Drain one child pipe without retaining more than a fixed byte limit."""

    def __init__(self, stream: IO[bytes], *, maximum_bytes: int) -> None:
        self._stream = stream
        self._maximum_bytes = maximum_bytes
        self._content = bytearray()
        self._overflowed = False
        self._read_failed = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._stream.read(min(8192, self._maximum_bytes + 1))
                if not chunk:
                    return
                with self._lock:
                    remaining = self._maximum_bytes - len(self._content)
                    if remaining > 0:
                        self._content.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self._overflowed = True
                        return
        except (OSError, ValueError):
            with self._lock:
                self._read_failed = True
        finally:
            with suppress(OSError):
                self._stream.close()

    def snapshot(self) -> tuple[bytes, bool, bool]:
        with self._lock:
            return bytes(self._content), self._overflowed, self._read_failed

    def finish(self, *, deadline: float, clock: Callable[[], float]) -> bool:
        self._thread.join(timeout=max(0.0, deadline - clock()))
        return not self._thread.is_alive()

    def force_close(self) -> None:
        """Interrupt a stuck pipe reader without retaining its buffered bytes."""

        with suppress(OSError, ValueError):
            self._stream.close()

    def clear(self) -> None:
        with self._lock:
            self._content.clear()


class _ProcessCapture:
    """A process plus bounded stdout/stderr collectors."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdout is None or process.stderr is None:
            raise CleanAnvilUnavailableError("clean Anvil process pipes were not created")
        self.process = process
        self.stdout = _BoundedOutput(
            process.stdout,
            maximum_bytes=_MAX_PROCESS_OUTPUT_BYTES,
        )
        self.stderr = _BoundedOutput(
            process.stderr,
            maximum_bytes=_MAX_PROCESS_OUTPUT_BYTES,
        )

    def output_is_valid(self) -> bool:
        _, stdout_overflow, stdout_failed = self.stdout.snapshot()
        _, stderr_overflow, stderr_failed = self.stderr.snapshot()
        return not (stdout_overflow or stdout_failed or stderr_overflow or stderr_failed)

    def finish_collectors(self, *, deadline: float, clock: Callable[[], float]) -> bool:
        now = clock()
        graceful_deadline = now + max(0.0, deadline - now) / 2
        stdout_finished = self.stdout.finish(deadline=graceful_deadline, clock=clock)
        stderr_finished = self.stderr.finish(deadline=graceful_deadline, clock=clock)
        if not stdout_finished:
            self.stdout.force_close()
        if not stderr_finished:
            self.stderr.force_close()
        if not stdout_finished:
            stdout_finished = self.stdout.finish(deadline=deadline, clock=clock)
        if not stderr_finished:
            stderr_finished = self.stderr.finish(deadline=deadline, clock=clock)
        return stdout_finished and stderr_finished

    def clear(self) -> None:
        self.stdout.clear()
        self.stderr.clear()


class _TrustedExecutable:
    """Retained descriptor and immutable-path policy for the copied Anvil binary."""

    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        identity: _ExecutableIdentity,
        sha256: str,
        workspace: _PrivateWorkspace,
    ) -> None:
        self.path = path
        self.descriptor: int | None = descriptor
        self.identity = identity
        self.sha256 = sha256
        self.workspace = workspace

    @property
    def command_path(self) -> str:
        descriptor = self._required_descriptor()
        if platform.system() == "Linux":
            return f"/proc/self/fd/{descriptor}"
        if platform.system() == "Darwin":
            return str(self.path)
        raise CleanAnvilUnavailableError(
            "trusted executable identity binding is unavailable on this host"
        )

    @property
    def pass_fds(self) -> tuple[int, ...]:
        if platform.system() == "Linux":
            return (self._required_descriptor(),)
        return ()

    @property
    def binding_kind(self) -> RepositoryCleanExecPathBindingKind:
        if platform.system() == "Linux":
            return RepositoryCleanExecPathBindingKind.LINUX_INHERITED_FD
        if platform.system() == "Darwin":
            return RepositoryCleanExecPathBindingKind.DARWIN_PRIVATE_PATH_POST_SPAWN_HASH
        raise CleanAnvilUnavailableError(
            "clean Anvil executable-path binding is unavailable on this platform"
        )

    def validate(self) -> None:
        descriptor = self._required_descriptor()
        self.workspace.validate()
        opened = os.fstat(descriptor)
        named = os.stat(
            "anvil",
            dir_fd=self.workspace.toolchain_descriptor,
            follow_symlinks=False,
        )
        if (
            not self.identity.matches(opened)
            or not self.identity.matches(named)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o500
        ):
            raise CleanAnvilConfigurationError("private clean Anvil executable identity changed")
        if platform.system() == "Darwin":
            immutable = getattr(stat, "UF_IMMUTABLE", 0)
            if immutable == 0 or not opened.st_flags & immutable:
                raise CleanAnvilConfigurationError(
                    "private clean Anvil executable lost its immutable guard"
                )

    def close(self) -> None:
        if self.descriptor is not None:
            with suppress(OSError):
                os.close(self.descriptor)
            self.descriptor = None

    def _required_descriptor(self) -> int:
        if self.descriptor is None:
            raise CleanAnvilConfigurationError(
                "private clean Anvil executable descriptor is unavailable"
            )
        return self.descriptor


class TrustedCleanAnvilLauncher:
    """Launch only an exact, externally pinned Anvil binary into a private workspace."""

    def __init__(
        self,
        *,
        environment: Mapping[str, str] | None = None,
        process_factory: _ProcessFactory | None = None,
        observer: _Observer | None = None,
        head_observer: _HeadObserver | None = None,
        listener_owner_verifier: _ListenerOwnerVerifier | None = None,
        runtime_executable_verifier: _RuntimeExecutableVerifier | None = None,
        port_supplier: Callable[[], int] | None = None,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._environment = os.environ if environment is None else environment
        self._process_factory = process_factory or subprocess.Popen
        self._observer = observer or observe_pinned_fork_rpc
        self._head_observer = head_observer or _observe_pristine_head
        self._listener_owner_verifier = listener_owner_verifier or _process_owns_loopback_listener
        self._runtime_executable_verifier = (
            runtime_executable_verifier or _runtime_executable_matches
        )
        self._port_supplier = port_supplier or _ephemeral_loopback_port
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep

    def start(
        self,
        config: RepositoryCleanForkMatrixStateConfig,
        repository_root: Path,
        private_root: Path,
        absolute_deadline: float,
    ) -> RunningCleanAnvil:
        """Start a clean chain and return only after two exact genesis observations."""

        _require_future_deadline(absolute_deadline, clock=self._clock)
        repository = _trusted_repository_root(repository_root)
        configured_path = self._environment.get(config.anvil_executable_env)
        if configured_path is None:
            raise CleanAnvilConfigurationError(
                "the configured clean Anvil executable environment variable is missing"
            )
        workspace = _prepare_private_workspace(private_root, repository_root=repository)
        trusted_executable: _TrustedExecutable | None = None
        transferred = False
        try:
            trusted_executable = _copy_pinned_executable(
                configured_path,
                expected_sha256=config.anvil_sha256,
                repository_root=repository,
                workspace=workspace,
            )
            lease = self._start_trusted(
                config=config,
                workspace=workspace,
                executable=trusted_executable,
                absolute_deadline=absolute_deadline,
            )
            transferred = True
            return lease
        finally:
            if not transferred:
                executable_path = (
                    trusted_executable.path if trusted_executable is not None else None
                )
                if trusted_executable is not None:
                    trusted_executable.close()
                workspace.destroy(executable=executable_path)

    def _start_trusted(
        self,
        *,
        config: RepositoryCleanForkMatrixStateConfig,
        workspace: _PrivateWorkspace,
        executable: _TrustedExecutable,
        absolute_deadline: float,
    ) -> RunningCleanAnvil:
        copied_executable = executable.path
        observed_sha256 = executable.sha256
        child_environment, environment_policy_sha256 = _child_environment(workspace)
        version_deadline = min(
            absolute_deadline,
            self._clock() + CLEAN_ANVIL_VERSION_ATTESTATION_TIMEOUT_SECONDS,
        )
        observed_version = self._attest_version(
            executable,
            expected_version=config.anvil_version,
            cwd=workspace.work,
            environment=child_environment,
            deadline=version_deadline,
        )
        executable.validate()
        if _hash_descriptor(executable) != observed_sha256:
            raise CleanAnvilConfigurationError(
                "the private clean Anvil copy changed during version attestation"
            )

        launch_configuration_sha256 = _launch_configuration_sha256(config)
        startup_deadline = min(
            absolute_deadline,
            self._clock() + config.startup_timeout_seconds,
        )
        observation_deadline = _deadline_with_cleanup_reserve(
            startup_deadline,
            clock=self._clock,
        )
        last_start_error: CleanAnvilError | None = None
        for _attempt in range(_MAX_PORT_ATTEMPTS):
            _require_future_deadline(observation_deadline, clock=self._clock)
            port = _validated_ephemeral_port(self._port_supplier())
            endpoint = f"http://{_LOOPBACK_HOST}:{port}"
            command = _node_command(executable, config=config, port=port)
            started_at = self._clock()
            capture = self._spawn(
                command,
                cwd=workspace.work,
                environment=child_environment,
                trusted_executable=executable,
                deadline=startup_deadline,
            )
            try:
                observation = self._observe_startup(
                    capture,
                    endpoint=endpoint,
                    port=port,
                    config=config,
                    executable=executable,
                    deadline=observation_deadline,
                )
            except _RetryableEarlyExit:
                last_start_error = CleanAnvilUnavailableError(
                    "clean Anvil exited before its genesis identity could be observed"
                )
                _cleanup_failed_process(
                    capture,
                    deadline=startup_deadline,
                    clock=self._clock,
                    sleeper=self._sleeper,
                )
                continue
            except BaseException:
                _cleanup_failed_process(
                    capture,
                    deadline=startup_deadline,
                    clock=self._clock,
                    sleeper=self._sleeper,
                )
                raise

            startup_duration = self._clock() - started_at
            if startup_duration < 0 or startup_duration > config.startup_timeout_seconds:
                _cleanup_failed_process(
                    capture,
                    deadline=startup_deadline,
                    clock=self._clock,
                    sleeper=self._sleeper,
                )
                raise CleanAnvilUnavailableError(
                    "clean Anvil startup exceeded its configured duration"
                )
            return RunningCleanAnvil(
                config=config,
                process_capture=capture,
                endpoint=endpoint,
                copied_executable=copied_executable,
                trusted_executable=executable,
                workspace=workspace,
                observed_tool_version=observed_version,
                observed_tool_sha256=observed_sha256,
                launch_configuration_sha256=launch_configuration_sha256,
                environment_policy_sha256=environment_policy_sha256,
                initial_observation=observation.genesis,
                initial_head_observation=observation.head,
                startup_duration_seconds=startup_duration,
                observer=self._observer,
                head_observer=self._head_observer,
                listener_owner_verifier=self._listener_owner_verifier,
                runtime_executable_verifier=self._runtime_executable_verifier,
                port=port,
                clock=self._clock,
                sleeper=self._sleeper,
            )

        raise last_start_error or CleanAnvilUnavailableError(
            "clean Anvil exhausted its bounded startup attempts"
        )

    def _attest_version(
        self,
        executable: _TrustedExecutable,
        *,
        expected_version: str,
        cwd: Path,
        environment: Mapping[str, str],
        deadline: float,
    ) -> str:
        _require_future_deadline(deadline, clock=self._clock)
        command_deadline = _deadline_with_cleanup_reserve(deadline, clock=self._clock)
        capture = self._spawn(
            [executable.command_path, "--version"],
            cwd=cwd,
            environment=environment,
            trusted_executable=executable,
            deadline=deadline,
        )
        process = capture.process
        wait_error: CleanAnvilUnavailableError | None = None
        try:
            _wait_for_process(
                process,
                deadline=command_deadline,
                clock=self._clock,
                sleeper=self._sleeper,
            )
        except CleanAnvilUnavailableError as exc:
            wait_error = exc
        process.poll()
        lingering_group_after_exit = process.returncode is not None and _process_group_exists(
            process.pid
        )
        termination_error: BaseException | None = None
        process_group_absent = False
        try:
            _, process_group_absent = _terminate_process_group(
                process,
                process_group_id=process.pid,
                deadline=deadline,
                clock=self._clock,
                sleeper=self._sleeper,
            )
        except BaseException as exc:
            termination_error = exc
        finally:
            collectors_finished = capture.finish_collectors(
                deadline=deadline,
                clock=self._clock,
            )
            stdout, stdout_overflow, stdout_failed = capture.stdout.snapshot()
            stderr, stderr_overflow, stderr_failed = capture.stderr.snapshot()
            capture.clear()
        if termination_error is not None:
            raise CleanAnvilConfigurationError(
                "clean Anvil version process group cleanup failed"
            ) from termination_error
        if not process_group_absent:
            raise CleanAnvilConfigurationError(
                "clean Anvil version process group could not be proven absent"
            )
        if lingering_group_after_exit:
            raise CleanAnvilConfigurationError(
                "clean Anvil version process group retained a descendant"
            )
        if wait_error is not None:
            raise CleanAnvilConfigurationError(
                "the clean Anvil version process group exceeded its bound"
            ) from wait_error
        executable.validate()
        expected_output = expected_version.encode("utf-8")
        first_line = stdout.partition(b"\n")[0]
        if (
            process.returncode != 0
            or not collectors_finished
            or stdout_overflow
            or stderr_overflow
            or stdout_failed
            or stderr_failed
            or stderr
            or first_line != expected_output
        ):
            raise CleanAnvilConfigurationError(
                "the copied clean Anvil binary did not emit its exact configured version first line"
            )
        return expected_version

    def _spawn(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        trusted_executable: _TrustedExecutable,
        deadline: float,
    ) -> _ProcessCapture:
        if os.name != "posix":
            raise CleanAnvilUnavailableError(
                "trusted clean Anvil process-group isolation requires a POSIX host"
            )
        trusted_executable.validate()
        trusted_executable.workspace.validate_ancestor_controls()
        try:
            process = self._process_factory(
                tuple(command),
                cwd=str(cwd),
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
                pass_fds=trusted_executable.pass_fds,
            )
        except OSError as exc:
            raise CleanAnvilUnavailableError(
                "the trusted clean Anvil process could not start"
            ) from exc
        try:
            capture = _ProcessCapture(process)
        except BaseException:
            _terminate_process_group(
                process,
                process_group_id=process.pid,
                deadline=deadline,
                clock=self._clock,
                sleeper=self._sleeper,
            )
            raise
        try:
            trusted_executable.validate()
            trusted_executable.workspace.validate_ancestor_controls()
            if _hash_descriptor(trusted_executable) != trusted_executable.sha256:
                raise CleanAnvilConfigurationError(
                    "spawned clean Anvil executable changed across process creation"
                )
        except BaseException:
            _cleanup_failed_process(
                capture,
                deadline=deadline,
                clock=self._clock,
                sleeper=self._sleeper,
            )
            raise
        return capture

    def _observe_startup(
        self,
        capture: _ProcessCapture,
        *,
        endpoint: str,
        port: int,
        config: RepositoryCleanForkMatrixStateConfig,
        executable: _TrustedExecutable,
        deadline: float,
    ) -> _PristineObservation:
        first: _PristineObservation | None = None
        while self._clock() < deadline:
            if capture.process.poll() is not None:
                raise _RetryableEarlyExit
            executable.workspace.validate_ancestor_controls()
            if not capture.output_is_valid():
                raise CleanAnvilUnavailableError(
                    "clean Anvil exceeded its bounded diagnostic output policy"
                )
            if not self._listener_owner_verifier(
                capture.process,
                host=_LOOPBACK_HOST,
                port=port,
                deadline=deadline,
            ):
                self._sleeper(min(_STARTUP_POLL_SECONDS, max(0.0, deadline - self._clock())))
                continue
            if not self._runtime_executable_verifier(
                capture.process,
                executable.identity,
            ):
                raise CleanAnvilConfigurationError(
                    "spawned clean Anvil runtime does not match its pinned executable"
                )
            try:
                observed = _observe_exact_genesis(
                    self._observer,
                    endpoint,
                    expected_chain_id=config.expected_chain_id,
                    deadline=deadline,
                    clock=self._clock,
                )
                pristine = _require_pristine_observation(
                    observed,
                    self._head_observer(
                        endpoint,
                        timeout_seconds=min(
                            _OBSERVATION_TIMEOUT_SECONDS,
                            max(0.0, deadline - self._clock()),
                        ),
                    ),
                )
            except ForkRpcUnavailableError:
                first = None
                self._sleeper(min(_STARTUP_POLL_SECONDS, max(0.0, deadline - self._clock())))
                continue
            if first is None:
                first = pristine
                self._sleeper(
                    min(
                        _PORT_BIND_STABILITY_SECONDS,
                        max(0.0, deadline - self._clock()),
                    )
                )
                continue
            if pristine != first:
                raise CleanAnvilIdentityError(
                    "clean Anvil genesis identity changed during startup attestation"
                )
            if capture.process.poll() is not None:
                raise _RetryableEarlyExit
            if not self._listener_owner_verifier(
                capture.process,
                host=_LOOPBACK_HOST,
                port=port,
                deadline=deadline,
            ):
                raise CleanAnvilUnavailableError(
                    "spawned clean Anvil ceased to own its loopback listener"
                )
            executable.workspace.validate_ancestor_controls()
            return pristine
        raise CleanAnvilUnavailableError(
            "spawned clean Anvil did not own and expose its pristine listener before the "
            "startup deadline"
        )


class RunningCleanAnvil:
    """Process-local lease for one exact clean Anvil genesis state."""

    def __init__(
        self,
        *,
        config: RepositoryCleanForkMatrixStateConfig,
        process_capture: _ProcessCapture,
        endpoint: str,
        copied_executable: Path,
        trusted_executable: _TrustedExecutable,
        workspace: _PrivateWorkspace,
        observed_tool_version: str,
        observed_tool_sha256: str,
        launch_configuration_sha256: str,
        environment_policy_sha256: str,
        initial_observation: PinnedForkObservation,
        initial_head_observation: _HeadObservation,
        startup_duration_seconds: float,
        observer: _Observer,
        head_observer: _HeadObserver,
        listener_owner_verifier: _ListenerOwnerVerifier,
        runtime_executable_verifier: _RuntimeExecutableVerifier,
        port: int,
        clock: Callable[[], float],
        sleeper: Callable[[float], None],
    ) -> None:
        self._config = config
        self._capture: _ProcessCapture | None = process_capture
        self._endpoint: str | None = endpoint
        self._copied_executable: Path | None = copied_executable
        self._trusted_executable: _TrustedExecutable | None = trusted_executable
        self._workspace: _PrivateWorkspace | None = workspace
        self._process_group_id: int | None = process_capture.process.pid
        self._observed_tool_version = observed_tool_version
        self._observed_tool_sha256 = observed_tool_sha256
        self._launch_configuration_sha256 = launch_configuration_sha256
        self._environment_policy_sha256 = environment_policy_sha256
        self._initial_observation = initial_observation
        self._initial_head_observation = initial_head_observation
        self._startup_duration_seconds = startup_duration_seconds
        self._observer = observer
        self._head_observer = head_observer
        self._listener_owner_verifier = listener_owner_verifier
        self._runtime_executable_verifier = runtime_executable_verifier
        self._port: int | None = port
        self._clock = clock
        self._sleeper = sleeper
        self._identity_valid = True
        self._state = "running"
        self._evidence: RepositoryCleanStateAttestationEvidence | None = None
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "<RunningCleanAnvil process-local lease>"

    def __enter__(self) -> RunningCleanAnvil:
        with self._lock:
            if self._state != "running":
                raise CleanAnvilUnavailableError("clean Anvil lease is not running")
            return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object | None,
    ) -> Literal[False]:
        del exception_type, traceback
        try:
            self.stop(self._clock() + self._config.shutdown_timeout_seconds)
        except BaseException as cleanup_error:
            if exception is not None:
                raise CleanAnvilUnavailableError(
                    "clean Anvil exception-path cleanup failed"
                ) from cleanup_error
            raise
        return False

    @property
    def endpoint(self) -> str:
        """Return the loopback endpoint only while the process-local lease is active."""

        with self._lock:
            if self._state != "running" or self._endpoint is None:
                raise CleanAnvilUnavailableError("clean Anvil endpoint is no longer available")
            return self._endpoint

    @property
    def initial_observation(self) -> PinnedForkObservation:
        """Return the exact genesis identity observed twice before lease creation."""

        return self._initial_observation

    def reobserve(self) -> PinnedForkObservation:
        """Revalidate the exact chain and genesis identity while the lease is running."""

        with self._lock:
            if self._state != "running":
                raise CleanAnvilUnavailableError("clean Anvil lease is not running")
            try:
                return self._reobserve_pristine_locked(
                    deadline=self._clock()
                    + min(
                        _OBSERVATION_TIMEOUT_SECONDS,
                        self._config.startup_timeout_seconds,
                    )
                ).genesis
            except (CleanAnvilError, ForkRpcBindingError, ForkRpcUnavailableError):
                self._identity_valid = False
                raise

    def stop(self, deadline: float) -> None:
        """Reobserve, terminate the process group, and seal endpoint-free evidence."""

        with self._lock:
            if self._state == "stopped":
                return
            if self._capture is None or self._process_group_id is None:
                raise CleanAnvilUnavailableError("clean Anvil process state is unavailable")
            _require_future_deadline(deadline, clock=self._clock)
            shutdown_deadline = min(
                deadline,
                self._clock() + self._config.shutdown_timeout_seconds,
            )
            capture = self._capture
            process_group_id = self._process_group_id
            process_was_running = capture.process.poll() is None
            final_observation: _PristineObservation | None = None
            pre_stop_error: BaseException | None = None
            if self._state == "running" and process_was_running and self._identity_valid:
                observation_deadline = min(
                    shutdown_deadline - _MIN_DEADLINE_SLACK_SECONDS,
                    self._clock()
                    + min(
                        _OBSERVATION_TIMEOUT_SECONDS,
                        max(
                            _MIN_DEADLINE_SLACK_SECONDS,
                            (shutdown_deadline - self._clock()) / 3,
                        ),
                    ),
                )
                try:
                    final_observation = self._reobserve_pristine_locked(
                        deadline=observation_deadline
                    )
                except BaseException as exc:
                    self._identity_valid = False
                    pre_stop_error = exc
            elif not process_was_running:
                pre_stop_error = CleanAnvilUnavailableError(
                    "clean Anvil exited before the requested clean stop"
                )
            elif not self._identity_valid:
                pre_stop_error = CleanAnvilIdentityError(
                    "clean Anvil identity was invalidated before shutdown"
                )

            self._state = "stopping"
            termination_started = self._clock()
            termination_method = "kill"
            process_group_absent = False
            termination_error: BaseException | None = None
            try:
                termination_method, process_group_absent = _terminate_process_group(
                    capture.process,
                    process_group_id=process_group_id,
                    deadline=shutdown_deadline,
                    clock=self._clock,
                    sleeper=self._sleeper,
                )
            except BaseException as exc:
                termination_error = exc
                capture.process.poll()
                process_group_absent = (
                    capture.process.returncode is not None
                    and not _process_group_exists(process_group_id)
                )
            finally:
                termination_duration = self._clock() - termination_started
                collectors_finished = capture.finish_collectors(
                    deadline=shutdown_deadline,
                    clock=self._clock,
                )
                output_valid = capture.output_is_valid()
                capture.clear()

            if not process_group_absent:
                self._state = "stop_failed"
                if termination_error is not None:
                    raise CleanAnvilUnavailableError(
                        "clean Anvil process-group cleanup failed"
                    ) from termination_error
                raise CleanAnvilUnavailableError(
                    "clean Anvil process group remained present after bounded termination"
                )

            trusted_executable = self._trusted_executable
            workspace = self._workspace
            copied_executable = self._copied_executable
            cleanup_error: BaseException | None = None
            executable_descriptor_closed = False
            private_workspace_removed = False
            exec_path_binding_kind: RepositoryCleanExecPathBindingKind | None = None
            try:
                if trusted_executable is None or workspace is None:
                    raise CleanAnvilUnavailableError(
                        "clean Anvil trusted workspace ownership was lost"
                    )
                exec_path_binding_kind = trusted_executable.binding_kind
                trusted_executable.close()
                executable_descriptor_closed = trusted_executable.descriptor is None
                workspace.destroy(executable=copied_executable)
                private_workspace_removed = not workspace.root.exists()
            except BaseException as exc:
                cleanup_error = exc

            self._capture = None
            self._endpoint = None
            self._copied_executable = None
            self._process_group_id = None
            self._trusted_executable = None
            self._workspace = None
            self._port = None
            if (
                pre_stop_error is not None
                or final_observation is None
                or final_observation.genesis != self._initial_observation
                or final_observation.head != self._initial_head_observation
                or termination_error is not None
                or not collectors_finished
                or not output_valid
                or cleanup_error is not None
                or exec_path_binding_kind is None
                or not executable_descriptor_closed
                or not private_workspace_removed
                or termination_duration < 0
                or termination_duration > self._config.shutdown_timeout_seconds
            ):
                self._state = "failed"
                if pre_stop_error is not None:
                    raise CleanAnvilIdentityError(
                        "clean Anvil could not prove an unchanged pre/post pristine identity"
                    ) from pre_stop_error
                if cleanup_error is not None:
                    raise CleanAnvilUnavailableError(
                        "clean Anvil private-resource cleanup could not be proven"
                    ) from cleanup_error
                if termination_error is not None:
                    raise CleanAnvilUnavailableError(
                        "clean Anvil process-group cleanup raised despite observed absence"
                    ) from termination_error
                raise CleanAnvilUnavailableError(
                    "clean Anvil shutdown evidence did not satisfy its fixed bounds"
                )
            if exec_path_binding_kind is None:
                raise CleanAnvilUnavailableError(
                    "clean Anvil executable-path binding evidence is unavailable"
                )

            process_attestation_sha256 = _canonical_sha256(
                {
                    "launcher_policy_version": _LAUNCHER_POLICY_VERSION,
                    "observed_tool_version": self._observed_tool_version,
                    "observed_tool_sha256": self._observed_tool_sha256,
                    "launch_configuration_sha256": self._launch_configuration_sha256,
                    "environment_policy_sha256": self._environment_policy_sha256,
                    "expected_chain_id": self._config.expected_chain_id,
                    "genesis_block_number": _GENESIS_BLOCK_NUMBER,
                    "genesis_block_hash": final_observation.genesis.block_hash,
                    "startup_duration_seconds": self._startup_duration_seconds,
                    "termination_method": termination_method,
                    "termination_duration_seconds": termination_duration,
                    "process_group_absent": process_group_absent,
                    "collector_threads_closed": collectors_finished,
                    "executable_descriptor_closed": executable_descriptor_closed,
                    "private_workspace_removed": private_workspace_removed,
                    "listener_owner_pid_bound": True,
                    "listener_ownership_kind": _listener_ownership_kind(),
                    "runtime_executable_matches_pinned_copy": True,
                    "runtime_executable_identity_kind": _runtime_identity_kind(),
                    "exec_path_binding_kind": exec_path_binding_kind,
                    "version_probe_process_group_absent": True,
                    "initial_head_block_number": self._initial_head_observation.block_number,
                    "initial_head_block_hash": self._initial_head_observation.block_hash,
                    "initial_head_state_root": self._initial_head_observation.state_root,
                    "final_head_block_number": final_observation.head.block_number,
                    "final_head_block_hash": final_observation.head.block_hash,
                    "final_head_state_root": final_observation.head.state_root,
                    "pristine_head_pre_post_match": True,
                    "ancestor_config_absent": True,
                }
            )
            self._evidence = RepositoryCleanStateAttestationEvidence.sealed(
                launcher_policy_version=_LAUNCHER_POLICY_VERSION,
                configured_tool_version=self._config.anvil_version,
                observed_tool_version=self._observed_tool_version,
                configured_tool_sha256=self._config.anvil_sha256,
                observed_tool_sha256=self._observed_tool_sha256,
                trust_pin_validated=True,
                launch_configuration_sha256=self._launch_configuration_sha256,
                environment_policy_sha256=self._environment_policy_sha256,
                process_attestation_sha256=process_attestation_sha256,
                target_arguments_inherited=False,
                target_environment_inherited=False,
                fork_or_state_arguments_present=False,
                target_state_input_present=False,
                listener_scope="numeric_loopback",
                listener_ownership_kind=_listener_ownership_kind(),
                listener_owner_pid_bound=True,
                runtime_executable_identity_kind=_runtime_identity_kind(),
                runtime_executable_matches_pinned_copy=True,
                exec_path_binding_kind=exec_path_binding_kind,
                version_probe_process_group_absent=True,
                outbound_network_isolation="not_attested",
                expected_chain_id=self._config.expected_chain_id,
                observed_chain_id=final_observation.genesis.chain_id,
                genesis_block_number=_GENESIS_BLOCK_NUMBER,
                genesis_block_hash=final_observation.genesis.block_hash,
                initial_head_block_number=self._initial_head_observation.block_number,
                initial_head_block_hash=self._initial_head_observation.block_hash,
                initial_head_state_root=self._initial_head_observation.state_root,
                final_head_block_number=final_observation.head.block_number,
                final_head_block_hash=final_observation.head.block_hash,
                final_head_state_root=final_observation.head.state_root,
                pristine_head_pre_post_match=True,
                startup_completed=True,
                startup_duration_seconds=self._startup_duration_seconds,
                termination_method=termination_method,
                termination_duration_seconds=termination_duration,
                process_group_absent=True,
                collector_threads_closed=True,
                executable_descriptor_closed=True,
                private_workspace_removed=True,
                ancestor_config_absent=True,
                no_upstream_fork_configuration=True,
                endpoint_retained=False,
                executable_path_retained=False,
                port_retained=False,
                process_id_retained=False,
                raw_output_retained=False,
            )
            self._state = "stopped"

    def attestation(self) -> RepositoryCleanStateAttestationEvidence:
        """Return sealed lifecycle evidence only after a clean, identity-bound stop."""

        with self._lock:
            if self._state != "stopped" or self._evidence is None:
                raise CleanAnvilUnavailableError(
                    "clean Anvil attestation is unavailable before a clean stop"
                )
            return self._evidence

    def _reobserve_pristine_locked(self, *, deadline: float) -> _PristineObservation:
        capture = self._capture
        endpoint = self._endpoint
        port = self._port
        executable = self._trusted_executable
        if (
            capture is None
            or endpoint is None
            or port is None
            or executable is None
            or capture.process.poll() is not None
        ):
            raise CleanAnvilUnavailableError("clean Anvil process is not running")
        if not capture.output_is_valid():
            raise CleanAnvilUnavailableError(
                "clean Anvil exceeded its bounded diagnostic output policy"
            )
        executable.workspace.validate_ancestor_controls()
        executable.validate()
        if not self._listener_owner_verifier(
            capture.process,
            host=_LOOPBACK_HOST,
            port=port,
            deadline=deadline,
        ):
            raise CleanAnvilIdentityError(
                "clean Anvil process no longer owns its loopback listener"
            )
        if not self._runtime_executable_verifier(capture.process, executable.identity):
            raise CleanAnvilIdentityError(
                "clean Anvil runtime no longer matches its pinned executable"
            )
        observed = _observe_exact_genesis(
            self._observer,
            endpoint,
            expected_chain_id=self._config.expected_chain_id,
            deadline=deadline,
            clock=self._clock,
        )
        pristine = _require_pristine_observation(
            observed,
            self._head_observer(
                endpoint,
                timeout_seconds=min(
                    _OBSERVATION_TIMEOUT_SECONDS,
                    max(0.0, deadline - self._clock()),
                ),
            ),
        )
        if (
            pristine.genesis != self._initial_observation
            or pristine.head != self._initial_head_observation
        ):
            raise CleanAnvilIdentityError(
                "clean Anvil no longer matches its initial pristine identity"
            )
        if not self._listener_owner_verifier(
            capture.process,
            host=_LOOPBACK_HOST,
            port=port,
            deadline=deadline,
        ):
            raise CleanAnvilIdentityError(
                "clean Anvil process lost listener ownership during observation"
            )
        executable.workspace.validate_ancestor_controls()
        return pristine


class _RetryableEarlyExit(Exception):
    pass


class _PrivateWorkspace:
    def __init__(
        self,
        *,
        parent: Path,
        root: Path,
        toolchain: Path,
        work: Path,
        home: Path,
        tmp: Path,
        parent_descriptor: int,
        root_descriptor: int,
        directory_descriptors: dict[str, int],
        directory_identities: dict[str, _ExecutableIdentity],
    ) -> None:
        self.parent = parent
        self.root = root
        self.toolchain = toolchain
        self.work = work
        self.home = home
        self.tmp = tmp
        self.cache = root / "cache"
        self.config = root / "config"
        self.data = root / "data"
        self.parent_descriptor: int | None = parent_descriptor
        self.root_descriptor: int | None = root_descriptor
        self.directory_descriptors = directory_descriptors
        self.directory_identities = directory_identities
        self._locked = False
        self._locked_executable: Path | None = None
        self._destroyed = False

    @property
    def toolchain_descriptor(self) -> int:
        descriptor = self.directory_descriptors.get("toolchain")
        if descriptor is None:
            raise CleanAnvilConfigurationError("clean Anvil toolchain descriptor is unavailable")
        return descriptor

    def validate(self) -> None:
        """Revalidate every private directory against retained no-follow descriptors."""

        if self._destroyed or self.parent_descriptor is None or self.root_descriptor is None:
            raise CleanAnvilConfigurationError("clean Anvil private workspace is unavailable")
        parent_metadata = os.fstat(self.parent_descriptor)
        if not self.directory_identities["<parent>"].matches(parent_metadata):
            raise CleanAnvilConfigurationError("clean Anvil private parent identity changed")
        named_root = os.stat(
            "clean-anvil",
            dir_fd=self.parent_descriptor,
            follow_symlinks=False,
        )
        opened_root = os.fstat(self.root_descriptor)
        expected_root = self.directory_identities["."]
        if not expected_root.matches(named_root) or not expected_root.matches(opened_root):
            raise CleanAnvilConfigurationError("clean Anvil private root identity changed")
        for name, descriptor in self.directory_descriptors.items():
            expected = self.directory_identities[name]
            named = os.stat(name, dir_fd=self.root_descriptor, follow_symlinks=False)
            opened = os.fstat(descriptor)
            if not expected.matches(named) or not expected.matches(opened):
                raise CleanAnvilConfigurationError("clean Anvil private directory identity changed")

    def validate_ancestor_controls(self) -> None:
        """Reject newly introduced control files before evidence can be credited."""

        self.validate()
        _reject_ancestor_control_files(self.parent)

    def lock(self, executable: Path) -> None:
        """Remove pathname write access and apply Darwin user-immutable guards."""

        self.validate()
        os.fchmod(self.toolchain_descriptor, 0o500)
        work_descriptor = self.directory_descriptors["work"]
        os.fchmod(work_descriptor, 0o500)
        if platform.system() == "Darwin":
            immutable = getattr(stat, "UF_IMMUTABLE", 0)
            if immutable == 0 or not hasattr(os, "chflags"):
                raise CleanAnvilConfigurationError(
                    "Darwin clean Anvil execution requires user-immutable file support"
                )
            os.chflags(executable, immutable, follow_symlinks=False)
            os.chflags(self.toolchain, immutable, follow_symlinks=False)
            self._locked_executable = executable
        self.directory_identities["toolchain"] = _ExecutableIdentity.from_stat(
            os.fstat(self.toolchain_descriptor)
        )
        self.directory_identities["work"] = _ExecutableIdentity.from_stat(os.fstat(work_descriptor))
        self._locked = True
        self.validate()
        if stat.S_IMODE(os.fstat(self.toolchain_descriptor).st_mode) != 0o500:
            raise CleanAnvilConfigurationError("clean Anvil toolchain lock was not enforced")
        if stat.S_IMODE(os.fstat(work_descriptor).st_mode) != 0o500:
            raise CleanAnvilConfigurationError("clean Anvil work-directory lock was not enforced")

    def destroy(self, *, executable: Path | None) -> None:
        """Remove only this anchored workspace after all owned processes are absent."""

        if self._destroyed:
            return
        validation_error: BaseException | None = None
        try:
            self.validate()
        except BaseException as exc:
            validation_error = exc
        if platform.system() == "Darwin" and hasattr(os, "chflags"):
            executable_to_unlock = executable or self._locked_executable
            if executable_to_unlock is not None:
                with suppress(OSError):
                    os.chflags(executable_to_unlock, 0, follow_symlinks=False)
            with suppress(OSError):
                os.chflags(self.toolchain, 0, follow_symlinks=False)
        for descriptor in self.directory_descriptors.values():
            with suppress(OSError):
                os.fchmod(descriptor, 0o700)
        if self.root_descriptor is not None:
            with suppress(OSError):
                os.fchmod(self.root_descriptor, 0o700)
        self._close_descriptors()
        if validation_error is not None:
            raise CleanAnvilConfigurationError(
                "clean Anvil workspace identity changed before cleanup"
            ) from validation_error
        try:
            shutil.rmtree(self.root)
        except OSError as exc:
            raise CleanAnvilUnavailableError(
                "clean Anvil private workspace could not be removed"
            ) from exc
        if self.root.exists() or self.root.is_symlink():
            raise CleanAnvilUnavailableError("clean Anvil private workspace remained after cleanup")
        self._destroyed = True

    def _close_descriptors(self) -> None:
        for descriptor in self.directory_descriptors.values():
            with suppress(OSError):
                os.close(descriptor)
        self.directory_descriptors.clear()
        if self.root_descriptor is not None:
            with suppress(OSError):
                os.close(self.root_descriptor)
            self.root_descriptor = None
        if self.parent_descriptor is not None:
            with suppress(OSError):
                os.close(self.parent_descriptor)
            self.parent_descriptor = None


def _trusted_repository_root(repository_root: Path) -> Path:
    if not repository_root.is_absolute():
        raise CleanAnvilConfigurationError("repository root must be absolute")
    lexical = repository_root.absolute()
    try:
        metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except (OSError, CleanAnvilConfigurationError) as exc:
        raise CleanAnvilConfigurationError("repository root could not be resolved") from exc
    if (
        resolved != lexical
        or not stat.S_ISDIR(metadata.st_mode)
        or lexical.is_symlink()
        or lexical.is_junction()
    ):
        raise CleanAnvilConfigurationError("repository root must be a canonical regular directory")
    return resolved


def _reject_ancestor_control_files(private_root: Path) -> None:
    """Reject configuration or dotenv files that Anvil could discover above its cwd."""

    current = private_root
    for _depth in range(_MAX_ANCESTOR_DEPTH):
        entries = 0
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > _MAX_ANCESTOR_ENTRIES:
                        raise CleanAnvilConfigurationError(
                            "clean Anvil ancestor inventory exceeded its fixed bound"
                        )
                    name = entry.name.casefold()
                    if (
                        name == ".env"
                        or name.startswith(".env.")
                        or name in {"foundry.toml", "anvil.toml"}
                    ):
                        raise CleanAnvilConfigurationError(
                            "clean Anvil private cwd has an untrusted ancestor control file"
                        )
        except OSError as exc:
            raise CleanAnvilConfigurationError(
                "clean Anvil ancestor controls could not be inspected"
            ) from exc
        parent = current.parent
        if parent == current:
            return
        current = parent
    raise CleanAnvilConfigurationError("clean Anvil ancestor depth exceeded its fixed bound")


def _prepare_private_workspace(private_root: Path, *, repository_root: Path) -> _PrivateWorkspace:
    if not private_root.is_absolute():
        raise CleanAnvilConfigurationError("clean Anvil private root must be absolute")
    lexical = private_root.absolute()
    try:
        metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise CleanAnvilConfigurationError(
            "clean Anvil private root could not be resolved"
        ) from exc
    if (
        resolved != lexical
        or not stat.S_ISDIR(metadata.st_mode)
        or lexical.is_symlink()
        or lexical.is_junction()
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise CleanAnvilConfigurationError(
            "clean Anvil private root must be a canonical owner-private directory"
        )
    if _paths_overlap(resolved, repository_root):
        raise CleanAnvilConfigurationError(
            "clean Anvil private root must be outside the audited repository"
        )
    _reject_ancestor_control_files(resolved)
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | _required_no_follow_flag() | getattr(os, "O_DIRECTORY", 0)
    )
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    directory_descriptors: dict[str, int] = {}
    root = resolved / "clean-anvil"
    try:
        parent_descriptor = os.open(resolved, directory_flags)
        if not _ExecutableIdentity.from_stat(metadata).matches(os.fstat(parent_descriptor)):
            raise CleanAnvilConfigurationError("clean Anvil private parent identity changed")
        os.mkdir("clean-anvil", 0o700, dir_fd=parent_descriptor)
        root_descriptor = os.open(
            "clean-anvil",
            directory_flags,
            dir_fd=parent_descriptor,
        )
        for name in ("toolchain", "work", "home", "tmp", "cache", "config", "data"):
            os.mkdir(name, 0o700, dir_fd=root_descriptor)
            directory_descriptors[name] = os.open(
                name,
                directory_flags,
                dir_fd=root_descriptor,
            )
    except OSError as exc:
        for descriptor in directory_descriptors.values():
            with suppress(OSError):
                os.close(descriptor)
        if root_descriptor is not None:
            with suppress(OSError):
                os.close(root_descriptor)
        if parent_descriptor is not None:
            with suppress(OSError):
                os.close(parent_descriptor)
        raise CleanAnvilConfigurationError(
            "clean Anvil private workspace could not be created atomically"
        ) from exc
    if parent_descriptor is None or root_descriptor is None:
        raise CleanAnvilConfigurationError("clean Anvil workspace descriptors were not created")
    children = {
        name: root / name
        for name in ("toolchain", "work", "home", "tmp", "cache", "config", "data")
    }
    workspace = _PrivateWorkspace(
        parent=resolved,
        root=root,
        toolchain=children["toolchain"],
        work=children["work"],
        home=children["home"],
        tmp=children["tmp"],
        parent_descriptor=parent_descriptor,
        root_descriptor=root_descriptor,
        directory_descriptors=directory_descriptors,
        directory_identities={
            "<parent>": _ExecutableIdentity.from_stat(os.fstat(parent_descriptor)),
            ".": _ExecutableIdentity.from_stat(os.fstat(root_descriptor)),
            **{
                name: _ExecutableIdentity.from_stat(os.fstat(descriptor))
                for name, descriptor in directory_descriptors.items()
            },
        },
    )
    workspace.validate()
    return workspace


def _copy_pinned_executable(
    configured_path: str,
    *,
    expected_sha256: str,
    repository_root: Path,
    workspace: _PrivateWorkspace,
) -> _TrustedExecutable:
    if not configured_path or configured_path != configured_path.strip():
        raise CleanAnvilConfigurationError("clean Anvil executable path is invalid")
    source = Path(configured_path)
    if not source.is_absolute():
        raise CleanAnvilConfigurationError("clean Anvil executable path must be absolute")
    source = source.absolute()
    try:
        named_before = source.lstat()
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise CleanAnvilConfigurationError("clean Anvil executable could not be resolved") from exc
    if (
        resolved != source
        or source.is_symlink()
        or source.is_junction()
        or not stat.S_ISREG(named_before.st_mode)
        or named_before.st_nlink != 1
        or named_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not named_before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or named_before.st_size < 1
        or named_before.st_size > _MAX_EXECUTABLE_BYTES
        or resolved.is_relative_to(repository_root)
    ):
        raise CleanAnvilConfigurationError(
            "clean Anvil executable is not an approved external regular file"
        )

    source_flags = os.O_RDONLY | os.O_CLOEXEC | _required_no_follow_flag()
    destination = workspace.toolchain / "anvil"
    destination_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | _required_no_follow_flag()
    )
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    digest = hashlib.sha256()
    try:
        source_descriptor = os.open(source, source_flags)
        opened_before = os.fstat(source_descriptor)
        _require_same_file(named_before, opened_before)
        destination_descriptor = os.open(
            "anvil",
            destination_flags,
            0o500,
            dir_fd=workspace.toolchain_descriptor,
        )
        os.fchmod(destination_descriptor, 0o500)
        copied = 0
        while copied < opened_before.st_size:
            chunk = os.read(
                source_descriptor,
                min(_COPY_CHUNK_BYTES, opened_before.st_size - copied),
            )
            if not chunk:
                raise CleanAnvilConfigurationError(
                    "clean Anvil executable changed while it was copied"
                )
            _write_all(destination_descriptor, chunk)
            digest.update(chunk)
            copied += len(chunk)
        if os.read(source_descriptor, 1):
            raise CleanAnvilConfigurationError("clean Anvil executable changed while it was copied")
        os.fsync(destination_descriptor)
        opened_after = os.fstat(source_descriptor)
        named_after = source.lstat()
        _require_same_file(opened_before, opened_after)
        _require_same_file(opened_before, named_after)
        destination_metadata = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_nlink != 1
            or stat.S_IMODE(destination_metadata.st_mode) != 0o500
            or destination_metadata.st_size != opened_before.st_size
        ):
            raise CleanAnvilConfigurationError(
                "private clean Anvil copy did not retain its fixed file policy"
            )
    except OSError as exc:
        raise CleanAnvilConfigurationError(
            "clean Anvil executable could not be copied safely"
        ) from exc
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)

    observed_sha256 = digest.hexdigest()
    read_descriptor: int | None = None
    try:
        workspace.directory_identities["toolchain"] = _ExecutableIdentity.from_stat(
            os.fstat(workspace.toolchain_descriptor)
        )
        read_descriptor = os.open(
            "anvil",
            os.O_RDONLY | os.O_CLOEXEC | _required_no_follow_flag(),
            dir_fd=workspace.toolchain_descriptor,
        )
        if observed_sha256 != expected_sha256:
            raise CleanAnvilConfigurationError(
                "clean Anvil executable does not match its configured SHA-256"
            )
        workspace.lock(destination)
        identity = _ExecutableIdentity.from_stat(os.fstat(read_descriptor))
        trusted = _TrustedExecutable(
            path=destination,
            descriptor=read_descriptor,
            identity=identity,
            sha256=observed_sha256,
            workspace=workspace,
        )
        trusted.validate()
        if _hash_descriptor(trusted) != observed_sha256:
            raise CleanAnvilConfigurationError(
                "private clean Anvil descriptor does not match its copied SHA-256"
            )
    except BaseException:
        if read_descriptor is not None:
            with suppress(OSError):
                os.close(read_descriptor)
        raise
    return trusted


def _hash_descriptor(executable: _TrustedExecutable) -> str:
    descriptor = executable._required_descriptor()
    executable.validate()
    before = os.fstat(descriptor)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise CleanAnvilConfigurationError(
            "private clean Anvil descriptor could not be rewound"
        ) from exc
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, remaining))
        if not chunk:
            raise CleanAnvilConfigurationError(
                "private clean Anvil descriptor changed while it was hashed"
            )
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise CleanAnvilConfigurationError(
            "private clean Anvil descriptor changed while it was hashed"
        )
    executable.validate()
    if not executable.identity.matches(os.fstat(descriptor)):
        raise CleanAnvilConfigurationError(
            "private clean Anvil descriptor identity changed while it was hashed"
        )
    return digest.hexdigest()


def _hash_regular_file(path: Path) -> str:
    before = path.lstat()
    if (
        path.is_symlink()
        or path.is_junction()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > _MAX_EXECUTABLE_BYTES
    ):
        raise CleanAnvilConfigurationError("private clean Anvil copy is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | _required_no_follow_flag())
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        _require_same_file(before, opened)
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise CleanAnvilConfigurationError(
                    "private clean Anvil copy changed while it was hashed"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CleanAnvilConfigurationError(
                "private clean Anvil copy changed while it was hashed"
            )
        _require_same_file(opened, os.fstat(descriptor))
        _require_same_file(opened, path.lstat())
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _require_same_file(expected: os.stat_result, observed: os.stat_result) -> None:
    expected_identity = (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_nlink,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    )
    observed_identity = (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_nlink,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    )
    if expected_identity != observed_identity:
        raise CleanAnvilConfigurationError("clean Anvil executable identity changed")


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written < 1:
            raise CleanAnvilConfigurationError("private clean Anvil copy could not be written")
        offset += written


def _required_no_follow_flag() -> int:
    value = getattr(os, "O_NOFOLLOW", 0)
    if value == 0:
        raise CleanAnvilConfigurationError("clean Anvil executable validation requires O_NOFOLLOW")
    return value


def _child_environment(workspace: _PrivateWorkspace) -> tuple[dict[str, str], str]:
    values = {
        "HOME": str(workspace.home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "TEMP": str(workspace.tmp),
        "TMP": str(workspace.tmp),
        "TMPDIR": str(workspace.tmp),
        "TZ": "UTC",
        "XDG_CACHE_HOME": str(workspace.cache),
        "XDG_CONFIG_HOME": str(workspace.config),
        "XDG_DATA_HOME": str(workspace.data),
    }
    policy_values = {
        **values,
        "HOME": "<private>/home",
        "TEMP": "<private>/tmp",
        "TMP": "<private>/tmp",
        "TMPDIR": "<private>/tmp",
        "XDG_CACHE_HOME": "<private>/cache",
        "XDG_CONFIG_HOME": "<private>/config",
        "XDG_DATA_HOME": "<private>/data",
    }
    return values, _canonical_sha256(
        {
            "policy_version": _LAUNCHER_POLICY_VERSION,
            "inherit_parent_environment": False,
            "values": policy_values,
        }
    )


def _node_command(
    executable: _TrustedExecutable,
    *,
    config: RepositoryCleanForkMatrixStateConfig,
    port: int,
) -> tuple[str, ...]:
    return (
        executable.command_path,
        "--host",
        _LOOPBACK_HOST,
        "--port",
        str(port),
        "--chain-id",
        str(config.expected_chain_id),
        "--number",
        str(_GENESIS_BLOCK_NUMBER),
        "--timestamp",
        str(config.genesis_timestamp),
        "--hardfork",
        config.hardfork,
        "--gas-limit",
        str(_BLOCK_GAS_LIMIT),
        "--block-base-fee-per-gas",
        str(_BLOCK_BASE_FEE_WEI),
        "--gas-price",
        str(_GAS_PRICE_WEI),
        "--accounts",
        "0",
        "--no-mining",
        "--threads",
        "1",
        "--disable-default-create2-deployer",
        "--no-cors",
        "--quiet",
        "--color",
        "never",
    )


def _launch_configuration_sha256(config: RepositoryCleanForkMatrixStateConfig) -> str:
    return _canonical_sha256(
        {
            "launcher_policy_version": _LAUNCHER_POLICY_VERSION,
            "listener_host": _LOOPBACK_HOST,
            "listener_port": "ephemeral",
            "chain_id": config.expected_chain_id,
            "genesis_block_number": _GENESIS_BLOCK_NUMBER,
            "genesis_timestamp": config.genesis_timestamp,
            "hardfork": config.hardfork,
            "block_gas_limit": _BLOCK_GAS_LIMIT,
            "block_base_fee_wei": _BLOCK_BASE_FEE_WEI,
            "gas_price_wei": _GAS_PRICE_WEI,
            "accounts": 0,
            "mining": False,
            "threads": 1,
            "default_create2_deployer": False,
            "cors": False,
            "quiet": True,
            "color": "never",
            "fork_or_state_arguments_present": False,
        }
    )


def _observe_exact_genesis(
    observer: _Observer,
    endpoint: str,
    *,
    expected_chain_id: int,
    deadline: float,
    clock: Callable[[], float],
) -> PinnedForkObservation:
    remaining = deadline - clock()
    if remaining <= 0:
        raise CleanAnvilUnavailableError("clean Anvil observation deadline expired")
    observed = observer(
        endpoint,
        expected_chain_id=expected_chain_id,
        pinned_block_number=_GENESIS_BLOCK_NUMBER,
        timeout_seconds=min(_OBSERVATION_TIMEOUT_SECONDS, remaining),
    )
    if (
        observed.chain_id != expected_chain_id
        or observed.block_number != _GENESIS_BLOCK_NUMBER
        or not _valid_block_hash(observed.block_hash)
    ):
        raise CleanAnvilIdentityError(
            "clean Anvil observation did not match the configured genesis identity"
        )
    return observed


def _require_pristine_observation(
    genesis: PinnedForkObservation,
    head: _HeadObservation,
) -> _PristineObservation:
    if (
        head.block_number != _GENESIS_BLOCK_NUMBER
        or head.block_hash != genesis.block_hash
        or not _valid_block_hash(head.state_root)
    ):
        raise CleanAnvilIdentityError(
            "clean Anvil current head is not the exact pristine genesis state"
        )
    return _PristineObservation(genesis=genesis, head=head)


def _observe_pristine_head(
    endpoint: str,
    *,
    timeout_seconds: float,
) -> _HeadObservation:
    """Observe the current head and state root through strict local JSON-RPC."""

    local_fork_rpc_port(endpoint)
    if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
        raise ForkRpcUnavailableError("clean Anvil head observation deadline expired")
    try:
        with httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            head_number = _rpc_hex_quantity(
                _local_rpc(
                    client,
                    endpoint,
                    request_id=91,
                    method="eth_blockNumber",
                    params=[],
                ),
                "head block number",
            )
            block = _local_rpc(
                client,
                endpoint,
                request_id=92,
                method="eth_getBlockByNumber",
                params=["latest", False],
            )
    except httpx.RequestError as exc:
        raise ForkRpcUnavailableError("clean Anvil head RPC is unavailable") from exc
    if not isinstance(block, dict):
        raise ForkRpcBindingError("clean Anvil current-head response is malformed")
    block_number = _rpc_hex_quantity(block.get("number"), "current block number")
    block_hash = block.get("hash")
    state_root = block.get("stateRoot")
    if (
        block_number != head_number
        or not isinstance(block_hash, str)
        or not isinstance(state_root, str)
        or not _valid_block_hash(block_hash)
        or not _valid_block_hash(state_root)
    ):
        raise ForkRpcBindingError("clean Anvil current-head identity is malformed")
    return _HeadObservation(
        block_number=head_number,
        block_hash=block_hash,
        state_root=state_root,
    )


def _local_rpc(
    client: httpx.Client,
    endpoint: str,
    *,
    request_id: int,
    method: str,
    params: list[object],
) -> object:
    with client.stream(
        "POST",
        endpoint,
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    ) as response:
        if response.status_code != 200:
            raise ForkRpcUnavailableError("clean Anvil head RPC returned an unsuccessful status")
        content = bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > _MAX_RPC_RESPONSE_BYTES:
                raise ForkRpcBindingError("clean Anvil head RPC response exceeded its fixed bound")
    try:
        payload = json.loads(
            content,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        raise ForkRpcBindingError("clean Anvil head RPC was not strict JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or payload.get("id") != request_id
        or "error" in payload
        or "result" not in payload
    ):
        raise ForkRpcBindingError("clean Anvil head RPC envelope is invalid")
    return payload["result"]


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ForkRpcBindingError("clean Anvil head RPC contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ForkRpcBindingError(f"clean Anvil head RPC contains invalid number {value!r}")


def _rpc_hex_quantity(value: object, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or value == "0x"
        or (len(value) > 3 and value[2] == "0")
    ):
        raise ForkRpcBindingError(f"clean Anvil {label} is not canonical")
    try:
        number = int(value[2:], 16)
    except ValueError as exc:
        raise ForkRpcBindingError(f"clean Anvil {label} is malformed") from exc
    if number < 0 or number >= 2**256:
        raise ForkRpcBindingError(f"clean Anvil {label} is outside its fixed bound")
    return number


def _valid_block_hash(value: str) -> bool:
    if len(value) != 66 or not value.startswith("0x") or value != value.lower():
        return False
    try:
        bytes.fromhex(value[2:])
    except ValueError:
        return False
    return True


def _wait_for_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> None:
    while clock() < deadline:
        if process.poll() is not None:
            return
        sleeper(min(_TERMINATION_POLL_SECONDS, max(0.0, deadline - clock())))
    raise CleanAnvilUnavailableError("clean Anvil process exceeded its deadline")


def _cleanup_failed_process(
    capture: _ProcessCapture,
    *,
    deadline: float,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> None:
    process_group_absent = False
    collectors_finished = False
    try:
        _, process_group_absent = _terminate_process_group(
            capture.process,
            process_group_id=capture.process.pid,
            deadline=deadline,
            clock=clock,
            sleeper=sleeper,
        )
    finally:
        collectors_finished = capture.finish_collectors(deadline=deadline, clock=clock)
        capture.clear()
    if not process_group_absent:
        raise CleanAnvilUnavailableError(
            "failed clean Anvil process group remained present after bounded cleanup"
        )
    if not collectors_finished:
        raise CleanAnvilUnavailableError(
            "failed clean Anvil output collectors remained live after bounded cleanup"
        )


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    process_group_id: int,
    deadline: float,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> tuple[str, bool]:
    if process_group_id < 1:
        return "kill", False
    process.poll()
    if process.returncode is not None and not _process_group_exists(process_group_id):
        return "term", True
    remaining = max(0.0, deadline - clock())
    term_deadline = clock() + remaining / 2
    _signal_process_group(process_group_id, signal.SIGTERM)
    if _wait_for_group_absence(
        process,
        process_group_id=process_group_id,
        deadline=term_deadline,
        clock=clock,
        sleeper=sleeper,
    ):
        return "term", True
    _signal_process_group(process_group_id, signal.SIGKILL)
    absent = _wait_for_group_absence(
        process,
        process_group_id=process_group_id,
        deadline=deadline,
        clock=clock,
        sleeper=sleeper,
    )
    return "kill", absent


def _signal_process_group(process_group_id: int, requested_signal: signal.Signals) -> None:
    try:
        os.killpg(process_group_id, requested_signal)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise CleanAnvilUnavailableError("clean Anvil process group could not be signaled") from exc


def _wait_for_group_absence(
    process: subprocess.Popen[bytes],
    *,
    process_group_id: int,
    deadline: float,
    clock: Callable[[], float],
    sleeper: Callable[[float], None],
) -> bool:
    while clock() < deadline:
        process.poll()
        if process.returncode is not None and not _process_group_exists(process_group_id):
            return True
        sleeper(min(_TERMINATION_POLL_SECONDS, max(0.0, deadline - clock())))
    process.poll()
    return process.returncode is not None and not _process_group_exists(process_group_id)


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_owns_loopback_listener(
    process: subprocess.Popen[bytes],
    *,
    host: str,
    port: int,
    deadline: float,
) -> bool:
    """Bind readiness to kernel-observed listener ownership by the spawned PID."""

    if process.poll() is not None or host != _LOOPBACK_HOST:
        return False
    system = platform.system()
    if system == "Linux":
        return _linux_process_owns_listener(process.pid, host=host, port=port)
    if system == "Darwin":
        return _darwin_process_owns_listener(
            process.pid,
            host=host,
            port=port,
            deadline=deadline,
        )
    return False


def _listener_ownership_kind() -> RepositoryCleanListenerOwnershipKind:
    if platform.system() == "Linux":
        return RepositoryCleanListenerOwnershipKind.LINUX_PROC_SOCKET_INODE
    if platform.system() == "Darwin":
        return RepositoryCleanListenerOwnershipKind.DARWIN_ROOT_OWNED_LSOF
    raise CleanAnvilUnavailableError(
        "clean Anvil listener ownership attestation is unavailable on this platform"
    )


def _runtime_identity_kind() -> RepositoryCleanRuntimeExecutableIdentityKind:
    if platform.system() == "Linux":
        return RepositoryCleanRuntimeExecutableIdentityKind.LINUX_PROC_PID_EXE
    if platform.system() == "Darwin":
        return RepositoryCleanRuntimeExecutableIdentityKind.DARWIN_PROC_PIDPATH
    raise CleanAnvilUnavailableError(
        "clean Anvil runtime executable attestation is unavailable on this platform"
    )


def _linux_process_owns_listener(pid: int, *, host: str, port: int) -> bool:
    if host != _LOOPBACK_HOST or pid < 1:
        return False
    process_root = Path("/proc") / str(pid)
    try:
        start_identity = _bounded_proc_text(process_root / "stat", maximum_bytes=16_384)
        start_time = _linux_proc_start_time(start_identity)
        listener_inodes = _linux_listener_inodes(port)
        if len(listener_inodes) != 1:
            return False
        owned_inodes: set[str] = set()
        entries = 0
        with os.scandir(process_root / "fd") as iterator:
            for entry in iterator:
                entries += 1
                if entries > 65_536:
                    return False
                try:
                    target = os.readlink(entry.path)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    owned_inodes.add(target[8:-1])
        end_identity = _bounded_proc_text(process_root / "stat", maximum_bytes=16_384)
        if _linux_proc_start_time(end_identity) != start_time:
            return False
    except (OSError, ValueError):
        return False
    return listener_inodes.issubset(owned_inodes)


def _linux_listener_inodes(port: int) -> set[str]:
    expected_port = f"{port:04X}"
    result: set[str] = set()
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            content = _bounded_proc_text(table, maximum_bytes=4 * 1024 * 1024)
        except OSError:
            continue
        for line in content.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            local_address, separator, local_port = fields[1].partition(":")
            if separator != ":" or local_port.upper() != expected_port:
                continue
            if table.name == "tcp" and local_address.upper() != "0100007F":
                continue
            if table.name == "tcp6" and local_address.upper() not in {
                "0000000000000000FFFF00000100007F",
                "0000000000000000000000000100007F",
            }:
                continue
            result.add(fields[9])
    return result


def _bounded_proc_text(path: Path, *, maximum_bytes: int) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    content = bytearray()
    try:
        while len(content) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
    finally:
        os.close(descriptor)
    if len(content) > maximum_bytes:
        raise ValueError("kernel process metadata exceeded its fixed bound")
    return content.decode("ascii", errors="strict")


def _linux_proc_start_time(content: str) -> str:
    _prefix, separator, remainder = content.rpartition(")")
    if separator != ")":
        raise ValueError("kernel process identity is malformed")
    fields = remainder.strip().split()
    if len(fields) < 20:
        raise ValueError("kernel process identity is incomplete")
    return fields[19]


def _darwin_process_owns_listener(
    pid: int,
    *,
    host: str,
    port: int,
    deadline: float,
) -> bool:
    if (
        pid < 1
        or host != _LOOPBACK_HOST
        or not _trusted_root_owned_system_tool(_MACOS_LSOF)
        or deadline <= time.monotonic()
    ):
        return False
    command = (
        str(_MACOS_LSOF),
        "-nP",
        "-a",
        "-p",
        str(pid),
        f"-iTCP@{host}:{port}",
        "-sTCP:LISTEN",
        "-FpnT",
    )
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            env={"LANG": "C", "LC_ALL": "C", "NO_COLOR": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )
    except OSError:
        return False
    try:
        capture = _ProcessCapture(process)
    except BaseException:
        with suppress(CleanAnvilError):
            _terminate_process_group(
                process,
                process_group_id=process.pid,
                deadline=min(deadline, time.monotonic() + 0.5),
                clock=time.monotonic,
                sleeper=time.sleep,
            )
        return False
    probe_deadline = min(deadline, time.monotonic() + 0.5)
    process_group_absent = False
    try:
        remaining = probe_deadline - time.monotonic()
        if remaining > _MIN_DEADLINE_SLACK_SECONDS * 2:
            with suppress(CleanAnvilUnavailableError):
                _wait_for_process(
                    process,
                    deadline=_deadline_with_cleanup_reserve(
                        probe_deadline,
                        clock=time.monotonic,
                    ),
                    clock=time.monotonic,
                    sleeper=time.sleep,
                )
        with suppress(CleanAnvilError):
            _, process_group_absent = _terminate_process_group(
                process,
                process_group_id=process.pid,
                deadline=probe_deadline,
                clock=time.monotonic,
                sleeper=time.sleep,
            )
    finally:
        collectors_finished = capture.finish_collectors(
            deadline=probe_deadline,
            clock=time.monotonic,
        )
        stdout, stdout_overflow, stdout_failed = capture.stdout.snapshot()
        stderr, stderr_overflow, stderr_failed = capture.stderr.snapshot()
        capture.clear()
    if (
        process.returncode != 0
        or not process_group_absent
        or not collectors_finished
        or stdout_overflow
        or stderr_overflow
        or stdout_failed
        or stderr_failed
        or stderr
    ):
        return False
    try:
        lines = stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        return False
    return f"p{pid}" in lines and f"n{host}:{port}" in lines and "TST=LISTEN" in lines


def _trusted_root_owned_system_tool(path: Path) -> bool:
    try:
        lexical = path.absolute()
        resolved = lexical.resolve(strict=True)
        metadata = lexical.lstat()
    except OSError:
        return False
    return (
        lexical == resolved
        and not lexical.is_symlink()
        and not lexical.is_junction()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_nlink == 1
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and bool(metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    )


def _runtime_executable_matches(
    process: subprocess.Popen[bytes],
    expected_identity: _ExecutableIdentity,
) -> bool:
    if process.poll() is not None:
        return False
    system = platform.system()
    try:
        if system == "Linux":
            observed = os.stat(Path("/proc") / str(process.pid) / "exe")
        elif system == "Darwin":
            observed_path = _darwin_process_path(process.pid)
            if observed_path is None:
                return False
            observed = observed_path.stat()
        else:
            return False
    except OSError:
        return False
    return expected_identity.matches(observed)


def _darwin_process_path(pid: int) -> Path | None:
    if pid < 1:
        return None
    try:
        import ctypes

        library = ctypes.CDLL(None)
        function = library.proc_pidpath
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        function.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = function(pid, buffer, len(buffer))
    except (AttributeError, OSError):
        return None
    if length <= 0 or length >= len(buffer):
        return None
    try:
        value = os.fsdecode(buffer.raw[:length])
    except UnicodeDecodeError:
        return None
    path = Path(value)
    if not path.is_absolute():
        return None
    try:
        return path.resolve(strict=True)
    except OSError:
        return None


def _ephemeral_loopback_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((_LOOPBACK_HOST, 0))
            port = listener.getsockname()[1]
    except OSError as exc:
        raise CleanAnvilUnavailableError(
            "an ephemeral numeric-loopback port could not be reserved"
        ) from exc
    return _validated_ephemeral_port(port)


def _validated_ephemeral_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
        raise CleanAnvilUnavailableError("clean Anvil ephemeral port is invalid")
    return value


def _require_future_deadline(
    value: float,
    *,
    clock: Callable[[], float],
) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
        or value <= clock()
    ):
        raise CleanAnvilUnavailableError("clean Anvil requires a finite future deadline")


def _deadline_with_cleanup_reserve(
    deadline: float,
    *,
    clock: Callable[[], float],
) -> float:
    now = clock()
    remaining = deadline - now
    if remaining <= _MIN_DEADLINE_SLACK_SECONDS * 2:
        raise CleanAnvilUnavailableError(
            "clean Anvil deadline leaves no bounded process-cleanup reserve"
        )
    reserve = min(_MAX_CLEANUP_RESERVE_SECONDS, remaining / 4)
    return deadline - reserve


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _canonical_sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
