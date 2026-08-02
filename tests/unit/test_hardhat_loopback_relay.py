from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
from collections.abc import Iterator, Sequence
from contextlib import suppress
from pathlib import Path

import pytest

import mmaudit.isolation.hardhat_loopback_relay as relay_module
from mmaudit.isolation.hardhat_loopback_relay import (
    FIXED_LISTEN_HOST,
    FIXED_UNIX_SOCKET_PATH,
    RELAY_FAILURE_EXIT_CODE,
    HardhatLoopbackRelay,
    HardhatLoopbackRelayError,
    RelayLimits,
    _parse_arguments,
    _sanitized_child_environment,
    _validated_command,
    _validated_unix_socket_identity,
    main,
)

_POLICY_SHA256 = "a" * 64
_AUTHORITY_SHA256 = "b" * 64


@pytest.fixture
def short_temp_dir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix=".mmaudit-relay-", dir=Path.cwd()) as value:
        yield Path(value).resolve()


class _UnixEchoServer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(path))
        path.chmod(0o600)
        self._listener.listen(4)
        self._listener.settimeout(0.1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(0.1)
                while not self._stop.is_set():
                    try:
                        data = connection.recv(65_536)
                    except TimeoutError:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    try:
                        connection.sendall(data)
                    except OSError:
                        break

    def close(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._listener.close()
        self._thread.join(1.0)
        self.path.unlink(missing_ok=True)

    def __enter__(self) -> _UnixEchoServer:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _relay(
    socket_path: Path,
    workdir: Path,
    *,
    limits: RelayLimits | None = None,
) -> HardhatLoopbackRelay:
    return HardhatLoopbackRelay(
        unix_socket_path=socket_path,
        listen_host=FIXED_LISTEN_HOST,
        listen_port=0,
        method_policy_sha256=_POLICY_SHA256,
        bridge_authority_sha256=_AUTHORITY_SHA256,
        limits=limits,
        workdir=workdir,
    )


def _start_relay(
    relay: HardhatLoopbackRelay,
    command: Sequence[str],
) -> tuple[threading.Thread, list[int], list[BaseException]]:
    results: list[int] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(relay.run(command, install_signal_handlers=False))
        except BaseException as exc:  # pragma: no cover - surfaced by the caller assertion.
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert relay.ready.wait(2.0)
    return thread, results, errors


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


def test_parser_accepts_backend_hash_bindings_and_exact_entrypoint_shape() -> None:
    parsed = _parse_arguments(
        [
            "--unix-socket",
            str(FIXED_UNIX_SOCKET_PATH),
            "--listen-host",
            FIXED_LISTEN_HOST,
            "--listen-port",
            "8545",
            "--method-policy-sha256",
            _POLICY_SHA256,
            "--authority-sha256",
            _AUTHORITY_SHA256,
            "--",
            "/usr/local/bin/hardhat",
            "test",
        ]
    )

    assert parsed == (
        FIXED_UNIX_SOCKET_PATH,
        FIXED_LISTEN_HOST,
        8545,
        _POLICY_SHA256,
        _AUTHORITY_SHA256,
        ["/usr/local/bin/hardhat", "test"],
    )


@pytest.mark.parametrize(
    "argument,value",
    [
        ("--unix-socket", "/tmp/not-the-mounted-bridge.sock"),
        ("--listen-host", "0.0.0.0"),
        ("--listen-port", "0"),
    ],
)
def test_parser_rejects_nonfixed_transport_boundary(argument: str, value: str) -> None:
    arguments = [
        "--unix-socket",
        str(FIXED_UNIX_SOCKET_PATH),
        "--listen-host",
        FIXED_LISTEN_HOST,
        "--listen-port",
        "8545",
        "--method-policy-sha256",
        _POLICY_SHA256,
        "--authority-sha256",
        _AUTHORITY_SHA256,
        "--",
        "/usr/local/bin/hardhat",
    ]
    arguments[arguments.index(argument) + 1] = value

    with pytest.raises(SystemExit) as raised:
        _parse_arguments(arguments)

    assert raised.value.code == 2


def test_parser_requires_exact_command_separator() -> None:
    with pytest.raises(SystemExit) as raised:
        _parse_arguments(
            [
                "--unix-socket",
                str(FIXED_UNIX_SOCKET_PATH),
                "--listen-host",
                FIXED_LISTEN_HOST,
                "--listen-port",
                "8545",
                "--method-policy-sha256",
                _POLICY_SHA256,
                "--authority-sha256",
                _AUTHORITY_SHA256,
                "/usr/local/bin/hardhat",
            ]
        )

    assert raised.value.code == 2


def test_main_rejects_invalid_opaque_bindings_without_exposing_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(
        [
            "--unix-socket",
            str(FIXED_UNIX_SOCKET_PATH),
            "--listen-host",
            FIXED_LISTEN_HOST,
            "--listen-port",
            "8545",
            "--method-policy-sha256",
            "invalid-policy-canary",
            "--authority-sha256",
            "invalid-authority-canary",
            "--",
            "/usr/local/bin/hardhat",
        ]
    )

    captured = capsys.readouterr()
    assert result == RELAY_FAILURE_EXIT_CODE
    assert "canary" not in captured.out
    assert "canary" not in captured.err


def test_child_environment_is_a_closed_nonsecret_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "relay-secret-canary"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", f"/secret/{canary}")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", canary)
    monkeypatch.setenv("SSH_AUTH_SOCK", f"/secret/{canary}.sock")

    environment = _sanitized_child_environment(8545)

    assert set(environment) == {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "CI",
        "HARDHAT_DISABLE_TELEMETRY_PROMPT",
        "HARDHAT_NETWORK",
        "MMAUDIT_FORK_RPC_URL",
    }
    assert environment["MMAUDIT_FORK_RPC_URL"] == "http://127.0.0.1:8545"
    assert canary not in repr(environment)


def test_unix_socket_requires_stable_owner_only_identity(short_temp_dir: Path) -> None:
    socket_path = short_temp_dir / "bridge.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    try:
        identity = _validated_unix_socket_identity(socket_path)
        assert identity.owner_uid == os.geteuid()
        assert identity.mode == 0o600

        socket_path.chmod(0o660)
        with pytest.raises(HardhatLoopbackRelayError, match="identity is unsafe"):
            _validated_unix_socket_identity(socket_path)

        socket_path.chmod(0o600)
        alias = short_temp_dir / "bridge-alias.sock"
        alias.symlink_to(socket_path)
        with pytest.raises(HardhatLoopbackRelayError, match="identity is unsafe"):
            _validated_unix_socket_identity(alias)
    finally:
        listener.close()


def test_command_must_be_absolute_image_owned_and_nonwritable(
    short_temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(HardhatLoopbackRelayError, match="absolute image path"):
        _validated_command(["hardhat", "test"])

    mutable_executable = short_temp_dir / "hardhat"
    mutable_executable.write_text("#!/bin/sh\nexit 0\n")
    mutable_executable.chmod(0o755)
    monkeypatch.setattr(relay_module, "_MUTABLE_EXECUTABLE_ROOTS", (short_temp_dir,))
    with pytest.raises(HardhatLoopbackRelayError, match="identity is unsafe"):
        _validated_command([str(mutable_executable), "test"])


def test_relay_forwards_opaque_bounded_bytes_and_supervises_child(
    short_temp_dir: Path,
) -> None:
    socket_path = short_temp_dir / "bridge.sock"
    with _UnixEchoServer(socket_path):
        relay = _relay(socket_path, short_temp_dir)
        thread, results, errors = _start_relay(
            relay,
            [sys.executable, "-c", "import time; time.sleep(0.6)"],
        )
        assert relay.bound_port is not None
        payload = b"opaque-transport-bytes\x00\xff"
        with socket.create_connection((FIXED_LISTEN_HOST, relay.bound_port), timeout=1.0) as client:
            client.settimeout(1.0)
            client.sendall(payload)
            assert _receive_exact(client, len(payload)) == payload
        thread.join(3.0)

    assert not thread.is_alive()
    assert errors == []
    assert results == [0]


def test_relay_child_receives_exact_arguments_but_no_inherited_secret(
    short_temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "exact-child-secret-canary"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    output_path = short_temp_dir / "child-output.txt"
    code = (
        "import os,pathlib,sys; "
        "pathlib.Path(sys.argv[1]).write_text("
        "sys.argv[2] + '|' + os.environ.get('OPENROUTER_API_KEY', 'absent'))"
    )
    socket_path = short_temp_dir / "bridge.sock"
    exact_argument = ";literal-not-a-shell-expression"
    with _UnixEchoServer(socket_path):
        relay = _relay(socket_path, short_temp_dir)
        result = relay.run(
            [sys.executable, "-c", code, str(output_path), exact_argument],
            install_signal_handlers=False,
        )

    assert result == 0
    assert output_path.read_text() == f"{exact_argument}|absent"
    assert canary not in output_path.read_text()


def test_directional_limit_fails_closed_and_terminates_child(short_temp_dir: Path) -> None:
    socket_path = short_temp_dir / "bridge.sock"
    limits = RelayLimits(
        maximum_connections=2,
        maximum_concurrent_connections=1,
        maximum_bytes_per_direction=4,
        maximum_total_bytes=8,
        stream_idle_timeout_seconds=1.0,
        unix_connect_timeout_seconds=0.2,
        child_termination_grace_seconds=0.2,
        thread_shutdown_timeout_seconds=0.2,
        listen_backlog=1,
    )
    with _UnixEchoServer(socket_path):
        relay = _relay(socket_path, short_temp_dir, limits=limits)
        thread, results, errors = _start_relay(
            relay,
            [sys.executable, "-c", "import time; time.sleep(30)"],
        )
        assert relay.bound_port is not None
        with socket.create_connection((FIXED_LISTEN_HOST, relay.bound_port), timeout=1.0) as client:
            client.sendall(b"12345")
            with suppress(OSError, TimeoutError):
                client.recv(1)
        thread.join(3.0)

    assert not thread.is_alive()
    assert errors == []
    assert results == [RELAY_FAILURE_EXIT_CODE]


def test_unavailable_prevalidated_socket_fails_closed(short_temp_dir: Path) -> None:
    socket_path = short_temp_dir / "bridge.sock"
    server = _UnixEchoServer(socket_path)
    relay = _relay(socket_path, short_temp_dir)
    thread, results, errors = _start_relay(
        relay,
        [sys.executable, "-c", "import time; time.sleep(30)"],
    )
    server.close()
    assert relay.bound_port is not None
    with socket.create_connection((FIXED_LISTEN_HOST, relay.bound_port), timeout=1.0):
        pass
    thread.join(3.0)

    assert not thread.is_alive()
    assert errors == []
    assert results == [RELAY_FAILURE_EXIT_CODE]


def test_relay_constructor_rejects_nonloopback_and_invalid_authority(
    short_temp_dir: Path,
) -> None:
    with pytest.raises(HardhatLoopbackRelayError, match="fixed IPv4 loopback"):
        HardhatLoopbackRelay(
            unix_socket_path=short_temp_dir / "bridge.sock",
            listen_host="0.0.0.0",
            listen_port=8545,
            method_policy_sha256=_POLICY_SHA256,
            bridge_authority_sha256=_AUTHORITY_SHA256,
            workdir=short_temp_dir,
        )
    with pytest.raises(HardhatLoopbackRelayError, match="authority binding"):
        HardhatLoopbackRelay(
            unix_socket_path=short_temp_dir / "bridge.sock",
            listen_host=FIXED_LISTEN_HOST,
            listen_port=8545,
            method_policy_sha256=_POLICY_SHA256,
            bridge_authority_sha256="not-a-sha256",
            workdir=short_temp_dir,
        )
