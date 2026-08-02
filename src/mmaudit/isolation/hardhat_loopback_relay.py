"""Bounded in-container transport for the trusted Hardhat RPC bridge.

This entrypoint is deliberately policy-agnostic. It forwards raw bytes between one
IPv4 loopback listener and one prevalidated mounted Unix socket. The host-side
``ReadOnlyRpcBridge`` remains the only component that parses or authorizes JSON-RPC.
The container launcher, not this process, establishes and attests network-none.
"""

from __future__ import annotations

import argparse
import os
import re
import select
import signal
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Final

FIXED_LISTEN_HOST: Final = "127.0.0.1"
FIXED_UNIX_SOCKET_PATH: Final = Path("/run/mmaudit/hardhat-rpc.sock")
RELAY_FAILURE_EXIT_CODE: Final = 70
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_COMMAND_ARGUMENTS = 4_096
_MAX_COMMAND_ARGUMENT_CHARACTERS = 8_192
_FIXED_CHILD_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_MUTABLE_EXECUTABLE_ROOTS = (
    Path("/workspace"),
    Path("/mmaudit-output"),
    Path("/tmp"),
    Path("/home/mmaudit"),
)
type _SignalHandler = signal.Handlers | Callable[[int, FrameType | None], object]


class HardhatLoopbackRelayError(RuntimeError):
    """The fixed relay boundary could not be established or supervised safely."""


class _RelayLimitExceeded(HardhatLoopbackRelayError):
    """A fixed transport resource bound was exceeded."""


@dataclass(frozen=True, slots=True)
class RelayLimits:
    """Non-configurable production defaults with narrower values available to tests."""

    maximum_connections: int = 10_000
    maximum_concurrent_connections: int = 32
    maximum_bytes_per_direction: int = 67_108_864
    maximum_total_bytes: int = 134_217_728
    stream_idle_timeout_seconds: float = 15.0
    unix_connect_timeout_seconds: float = 2.0
    child_termination_grace_seconds: float = 2.0
    thread_shutdown_timeout_seconds: float = 2.0
    listen_backlog: int = 32

    def __post_init__(self) -> None:
        if not 1 <= self.maximum_connections <= 100_000:
            raise ValueError("relay connection ceiling is outside its fixed bound")
        if not 1 <= self.maximum_concurrent_connections <= 256:
            raise ValueError("relay concurrency ceiling is outside its fixed bound")
        if self.maximum_concurrent_connections > self.maximum_connections:
            raise ValueError("relay concurrency ceiling exceeds its connection ceiling")
        if not 1 <= self.maximum_bytes_per_direction <= 268_435_456:
            raise ValueError("relay stream byte ceiling is outside its fixed bound")
        if not self.maximum_bytes_per_direction <= self.maximum_total_bytes <= 536_870_912:
            raise ValueError("relay total byte ceiling is outside its fixed bound")
        if not 0.05 <= self.stream_idle_timeout_seconds <= 60.0:
            raise ValueError("relay idle timeout is outside its fixed bound")
        if not 0.05 <= self.unix_connect_timeout_seconds <= 10.0:
            raise ValueError("relay connect timeout is outside its fixed bound")
        if not 0.05 <= self.child_termination_grace_seconds <= 10.0:
            raise ValueError("relay child grace period is outside its fixed bound")
        if not 0.05 <= self.thread_shutdown_timeout_seconds <= 10.0:
            raise ValueError("relay thread timeout is outside its fixed bound")
        if not 1 <= self.listen_backlog <= 256:
            raise ValueError("relay listen backlog is outside its fixed bound")


@dataclass(frozen=True, slots=True)
class _UnixSocketIdentity:
    device: int
    inode: int
    owner_uid: int
    mode: int
    links: int


class _RelayState:
    """Thread-safe lifecycle, socket custody, and aggregate byte accounting."""

    def __init__(self, limits: RelayLimits) -> None:
        self.limits = limits
        self.stop = threading.Event()
        self.failed = threading.Event()
        self._lock = threading.Lock()
        self._accepted_connections = 0
        self._active_connections = 0
        self._total_bytes = 0
        self._sockets: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()

    def begin_connection(self) -> bool:
        with self._lock:
            if (
                self._accepted_connections >= self.limits.maximum_connections
                or self._active_connections >= self.limits.maximum_concurrent_connections
            ):
                self.failed.set()
                self.stop.set()
                return False
            self._accepted_connections += 1
            self._active_connections += 1
            return True

    def finish_connection(self) -> None:
        with self._lock:
            self._active_connections = max(0, self._active_connections - 1)

    def account_bytes(self, amount: int) -> None:
        with self._lock:
            self._total_bytes += amount
            if self._total_bytes > self.limits.maximum_total_bytes:
                self.failed.set()
                self.stop.set()
                raise _RelayLimitExceeded("relay aggregate byte ceiling was exceeded")

    def register_socket(self, value: socket.socket) -> None:
        with self._lock:
            self._sockets.add(value)

    def unregister_socket(self, value: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(value)

    def register_thread(self, value: threading.Thread) -> None:
        with self._lock:
            self._threads.add(value)

    def unregister_thread(self, value: threading.Thread) -> None:
        with self._lock:
            self._threads.discard(value)

    def fail(self) -> None:
        self.failed.set()
        self.stop.set()

    def close_sockets(self) -> None:
        with self._lock:
            values = tuple(self._sockets)
        for value in values:
            with suppress(OSError):
                value.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                value.close()

    def join_threads(self) -> bool:
        deadline = time.monotonic() + self.limits.thread_shutdown_timeout_seconds
        while True:
            with self._lock:
                threads = tuple(self._threads)
            if not threads:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            for thread in threads:
                thread.join(min(remaining, 0.1))


class HardhatLoopbackRelay:
    """Supervise one command behind a bounded raw loopback-to-Unix relay.

    The opaque policy and authority hashes are validated only as invocation binding
    material. This class never interprets them, grants runtime authority from them,
    or claims that it enforces RPC methods.
    """

    def __init__(
        self,
        *,
        unix_socket_path: Path,
        listen_host: str,
        listen_port: int,
        method_policy_sha256: str,
        bridge_authority_sha256: str,
        limits: RelayLimits | None = None,
        workdir: Path | None = None,
    ) -> None:
        if listen_host != FIXED_LISTEN_HOST:
            raise HardhatLoopbackRelayError("relay must listen on fixed IPv4 loopback")
        if type(listen_port) is not int or not 0 <= listen_port <= 65_535:
            raise HardhatLoopbackRelayError("relay listen port is invalid")
        if _SHA256.fullmatch(method_policy_sha256) is None:
            raise HardhatLoopbackRelayError("relay policy binding is invalid")
        if _SHA256.fullmatch(bridge_authority_sha256) is None:
            raise HardhatLoopbackRelayError("relay authority binding is invalid")
        if not unix_socket_path.is_absolute():
            raise HardhatLoopbackRelayError("relay Unix socket path must be absolute")
        self.unix_socket_path = unix_socket_path
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.method_policy_sha256 = method_policy_sha256
        self.bridge_authority_sha256 = bridge_authority_sha256
        self.limits = limits or RelayLimits()
        self.workdir = (workdir or Path.cwd()).resolve(strict=True)
        if not self.workdir.is_dir():
            raise HardhatLoopbackRelayError("relay child working directory is invalid")
        self.ready = threading.Event()
        self._state = _RelayState(self.limits)
        self._bound_port: int | None = None
        self._child: subprocess.Popen[bytes] | None = None
        self._signal_number: int | None = None

    @property
    def bound_port(self) -> int | None:
        """Return the observed listener port after ``ready`` is set."""

        return self._bound_port

    def request_shutdown(self) -> None:
        """Request bounded termination of the listener, streams, and child group."""

        self._state.stop.set()
        self._state.close_sockets()

    def run(
        self,
        command: Sequence[str],
        *,
        install_signal_handlers: bool = True,
    ) -> int:
        """Run exactly one argument vector with no shell or inherited secret environment."""

        validated_command = _validated_command(command)
        socket_identity = _validated_unix_socket_identity(self.unix_socket_path)
        listener = _create_listener(
            self.listen_host,
            self.listen_port,
            backlog=self.limits.listen_backlog,
        )
        self._state.register_socket(listener)
        observed_host, observed_port = listener.getsockname()
        if (
            observed_host != FIXED_LISTEN_HOST
            or not isinstance(observed_port, int)
            or not 1 <= observed_port <= 65_535
            or (self.listen_port != 0 and observed_port != self.listen_port)
        ):
            listener.close()
            raise HardhatLoopbackRelayError("relay listener identity is invalid")
        self._bound_port = observed_port
        child_environment = _sanitized_child_environment(observed_port)
        previous_handlers: dict[int, _SignalHandler] = {}
        try:
            if install_signal_handlers:
                previous_handlers = self._install_signal_handlers()
            self._child = subprocess.Popen(
                validated_command,
                cwd=self.workdir,
                env=child_environment,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
            self.ready.set()
            self._accept_until_child_finishes(listener, socket_identity)
        except (OSError, ValueError) as exc:
            self._state.fail()
            raise HardhatLoopbackRelayError("relay could not supervise its exact child") from exc
        finally:
            self._state.stop.set()
            with suppress(OSError):
                listener.close()
            self._state.unregister_socket(listener)
            self._state.close_sockets()
            child = self._child
            if child is not None and child.poll() is None:
                try:
                    _terminate_child_group(child, self.limits.child_termination_grace_seconds)
                except HardhatLoopbackRelayError:
                    self._state.fail()
            if not self._state.join_threads():
                self._state.fail()
            if child is not None:
                _terminate_residual_process_group(
                    child.pid,
                    self.limits.child_termination_grace_seconds,
                )
            self._restore_signal_handlers(previous_handlers)

        child = self._child
        if child is None:
            return RELAY_FAILURE_EXIT_CODE
        return_code = child.poll()
        if return_code is None:
            self._state.fail()
            _terminate_child_group(child, self.limits.child_termination_grace_seconds)
            return_code = child.wait()
        try:
            final_identity = _validated_unix_socket_identity(self.unix_socket_path)
        except HardhatLoopbackRelayError:
            self._state.fail()
        else:
            if final_identity != socket_identity:
                self._state.fail()
        if self._state.failed.is_set():
            return RELAY_FAILURE_EXIT_CODE
        if self._signal_number is not None:
            return 128 + self._signal_number
        return _public_process_return_code(return_code)

    def _accept_until_child_finishes(
        self,
        listener: socket.socket,
        socket_identity: _UnixSocketIdentity,
    ) -> None:
        child = self._child
        if child is None:
            raise HardhatLoopbackRelayError("relay child is unavailable")
        listener.settimeout(0.1)
        while child.poll() is None and not self._state.stop.is_set():
            try:
                client, address = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._state.stop.is_set():
                    break
                self._state.fail()
                break
            if (
                not isinstance(address, tuple)
                or not address
                or address[0] != FIXED_LISTEN_HOST
                or not self._state.begin_connection()
            ):
                client.close()
                self._state.fail()
                break
            self._state.register_socket(client)
            thread = threading.Thread(
                target=self._relay_connection,
                args=(client, socket_identity),
                name="mmaudit-hardhat-loopback-stream",
                daemon=True,
            )
            self._state.register_thread(thread)
            thread.start()
        if self._state.failed.is_set() or self._state.stop.is_set():
            if child.poll() is None:
                _terminate_child_group(child, self.limits.child_termination_grace_seconds)
        else:
            child.wait()

    def _relay_connection(
        self,
        client: socket.socket,
        expected_identity: _UnixSocketIdentity,
    ) -> None:
        thread = threading.current_thread()
        upstream: socket.socket | None = None
        connected = False
        try:
            if _validated_unix_socket_identity(self.unix_socket_path) != expected_identity:
                raise HardhatLoopbackRelayError("relay Unix socket identity changed")
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._state.register_socket(upstream)
            upstream.settimeout(self.limits.unix_connect_timeout_seconds)
            upstream.connect(str(self.unix_socket_path))
            connected = True
            if _validated_unix_socket_identity(self.unix_socket_path) != expected_identity:
                raise HardhatLoopbackRelayError("relay Unix socket identity changed")
            client.setblocking(False)
            upstream.setblocking(False)
            _pump_raw_streams(client, upstream, self._state)
        except _RelayLimitExceeded:
            self._state.fail()
        except HardhatLoopbackRelayError:
            if not self._state.stop.is_set():
                self._state.fail()
        except OSError:
            # Disconnects after a successful connection are ordinary transport events.
            # Failure to establish the upstream is not: it leaves no authorized route.
            if not connected and not self._state.stop.is_set():
                self._state.fail()
        except Exception:
            # A worker must never fail open or leave its supervised child running.
            if not self._state.stop.is_set():
                self._state.fail()
        finally:
            for value in (client, upstream):
                if value is None:
                    continue
                self._state.unregister_socket(value)
                with suppress(OSError):
                    value.close()
            self._state.finish_connection()
            self._state.unregister_thread(thread)

    def _install_signal_handlers(self) -> dict[int, _SignalHandler]:
        if threading.current_thread() is not threading.main_thread():
            raise HardhatLoopbackRelayError("relay signal handlers require the main thread")
        previous: dict[int, _SignalHandler] = {}

        def handle(signum: int, _frame: FrameType | None) -> None:
            self._signal_number = signum
            self.request_shutdown()

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handler = signal.getsignal(signum)
                if previous_handler is None:
                    raise HardhatLoopbackRelayError("relay could not preserve its signal handler")
                if isinstance(previous_handler, int):
                    previous_handler = signal.Handlers(previous_handler)
                previous[signum] = previous_handler
                signal.signal(signum, handle)
        except BaseException:
            self._restore_signal_handlers(previous)
            raise
        return previous

    @staticmethod
    def _restore_signal_handlers(previous: dict[int, _SignalHandler]) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _pump_raw_streams(
    client: socket.socket,
    upstream: socket.socket,
    state: _RelayState,
) -> None:
    streams: dict[socket.socket, tuple[socket.socket, str]] = {
        client: (upstream, "client_to_unix"),
        upstream: (client, "unix_to_client"),
    }
    directional_bytes = {"client_to_unix": 0, "unix_to_client": 0}
    last_activity = time.monotonic()
    while streams and not state.stop.is_set():
        remaining = state.limits.stream_idle_timeout_seconds - (time.monotonic() - last_activity)
        if remaining <= 0:
            raise _RelayLimitExceeded("relay stream idle timeout was exceeded")
        readable, _, exceptional = select.select(
            list(streams),
            [],
            list(streams),
            min(0.25, remaining),
        )
        if exceptional:
            return
        for source in readable:
            destination, direction = streams[source]
            try:
                data = source.recv(65_536)
            except BlockingIOError:
                continue
            if not data:
                streams.pop(source, None)
                with suppress(OSError):
                    destination.shutdown(socket.SHUT_WR)
                continue
            directional_bytes[direction] += len(data)
            if directional_bytes[direction] > state.limits.maximum_bytes_per_direction:
                raise _RelayLimitExceeded("relay directional byte ceiling was exceeded")
            state.account_bytes(len(data))
            if not _send_with_deadline(
                destination,
                data,
                timeout_seconds=state.limits.stream_idle_timeout_seconds,
                stop=state.stop,
            ):
                return
            last_activity = time.monotonic()


def _send_with_deadline(
    destination: socket.socket,
    data: bytes,
    *,
    timeout_seconds: float,
    stop: threading.Event,
) -> bool:
    pending = memoryview(data)
    deadline = time.monotonic() + timeout_seconds
    while pending and not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _RelayLimitExceeded("relay stream write timeout was exceeded")
        _, writable, exceptional = select.select(
            [],
            [destination],
            [destination],
            min(0.25, remaining),
        )
        if exceptional:
            return False
        if not writable:
            continue
        try:
            written = destination.send(pending)
        except (BlockingIOError, BrokenPipeError, ConnectionResetError):
            return False
        if written <= 0:
            return False
        pending = pending[written:]
    return not pending


def _validated_unix_socket_identity(path: Path) -> _UnixSocketIdentity:
    try:
        before = path.lstat()
    except OSError as exc:
        raise HardhatLoopbackRelayError("relay Unix socket is unavailable") from exc
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISSOCK(before.st_mode)
        or before.st_uid != expected_uid
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
    ):
        raise HardhatLoopbackRelayError("relay Unix socket identity is unsafe")
    try:
        resolved = path.resolve(strict=True)
        after = resolved.lstat()
    except OSError as exc:
        raise HardhatLoopbackRelayError("relay Unix socket identity changed") from exc
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink")
    if resolved != path or any(getattr(before, field) != getattr(after, field) for field in fields):
        raise HardhatLoopbackRelayError("relay Unix socket identity changed")
    return _UnixSocketIdentity(
        device=after.st_dev,
        inode=after.st_ino,
        owner_uid=after.st_uid,
        mode=stat.S_IMODE(after.st_mode),
        links=after.st_nlink,
    )


def _create_listener(host: str, port: int, *, backlog: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((host, port))
        listener.listen(backlog)
    except BaseException:
        listener.close()
        raise
    return listener


def _validated_command(command: Sequence[str]) -> list[str]:
    values = list(command)
    if not values or len(values) > _MAX_COMMAND_ARGUMENTS:
        raise HardhatLoopbackRelayError("relay requires one bounded exact command")
    if any(
        type(value) is not str
        or not value
        or len(value) > _MAX_COMMAND_ARGUMENT_CHARACTERS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        for value in values
    ):
        raise HardhatLoopbackRelayError("relay command contains an unsafe argument")
    executable = Path(values[0])
    if not executable.is_absolute() or ".." in executable.parts:
        raise HardhatLoopbackRelayError("relay executable must be one absolute image path")
    try:
        resolved = executable.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise HardhatLoopbackRelayError("relay executable identity is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(resolved, os.X_OK)
        or any(
            _is_relative_to(executable, root)
            or _is_relative_to(resolved, root.resolve(strict=False))
            for root in _MUTABLE_EXECUTABLE_ROOTS
        )
    ):
        raise HardhatLoopbackRelayError("relay executable identity is unsafe")
    return values


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _sanitized_child_environment(port: int) -> dict[str, str]:
    if not 1 <= port <= 65_535:
        raise HardhatLoopbackRelayError("relay child endpoint has an invalid port")
    return {
        "PATH": _FIXED_CHILD_PATH,
        "HOME": "/home/mmaudit",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "CI": "true",
        "HARDHAT_DISABLE_TELEMETRY_PROMPT": "true",
        "HARDHAT_NETWORK": "hardhat",
        "MMAUDIT_FORK_RPC_URL": f"http://{FIXED_LISTEN_HOST}:{port}",
    }


def _terminate_child_group(child: subprocess.Popen[bytes], grace_seconds: float) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except OSError:
        with suppress(OSError):
            child.terminate()
    try:
        child.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except OSError:
        with suppress(OSError):
            child.kill()
    try:
        child.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as exc:
        raise HardhatLoopbackRelayError("relay child group did not terminate") from exc


def _terminate_residual_process_group(process_group: int, grace_seconds: float) -> None:
    try:
        os.killpg(process_group, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except OSError:
            return
        time.sleep(0.01)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except OSError:
        return


def _public_process_return_code(value: int) -> int:
    return value if value >= 0 else 128 + min(abs(value), 127)


def _parse_arguments(
    argv: Sequence[str] | None,
) -> tuple[Path, str, int, str, str, list[str]]:
    parser = argparse.ArgumentParser(
        prog="mmaudit-hardhat-loopback",
        description="Bounded raw transport to the host-enforced read-only RPC bridge.",
    )
    parser.add_argument("--unix-socket", required=True)
    parser.add_argument("--listen-host", required=True)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--method-policy-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = list(arguments.command)
    if not command or command[0] != "--":
        parser.error("one exact command is required after --")
    command = command[1:]
    socket_path = Path(arguments.unix_socket)
    if socket_path != FIXED_UNIX_SOCKET_PATH:
        parser.error("--unix-socket must identify the fixed mounted bridge socket")
    if arguments.listen_host != FIXED_LISTEN_HOST:
        parser.error("--listen-host must be fixed IPv4 loopback")
    if not 1 <= arguments.listen_port <= 65_535:
        parser.error("--listen-port is outside the supported range")
    if not command:
        parser.error("one exact command is required after --")
    return (
        socket_path,
        arguments.listen_host,
        arguments.listen_port,
        arguments.method_policy_sha256,
        arguments.authority_sha256,
        command,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Console entrypoint for the digest-pinned Hardhat image."""

    (
        socket_path,
        listen_host,
        listen_port,
        policy_sha256,
        authority_sha256,
        command,
    ) = _parse_arguments(argv)
    try:
        relay = HardhatLoopbackRelay(
            unix_socket_path=socket_path,
            listen_host=listen_host,
            listen_port=listen_port,
            method_policy_sha256=policy_sha256,
            bridge_authority_sha256=authority_sha256,
        )
        return relay.run(command)
    except HardhatLoopbackRelayError:
        return RELAY_FAILURE_EXIT_CODE


if __name__ == "__main__":  # pragma: no cover - exercised through the console entrypoint.
    raise SystemExit(main())
