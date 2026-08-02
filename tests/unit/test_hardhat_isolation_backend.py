from __future__ import annotations

import copy
import json
import os
import pickle
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import pytest

from mmaudit.isolation.container import (
    HARDHAT_READ_ONLY_RPC_METHODS,
    HardhatReadOnlyRpcBridgeBinding,
    RootlessContainerLimits,
    SingleLoopbackHardhatBackend,
    bind_hardhat_read_only_rpc_bridge,
)
from mmaudit.isolation.provenance import isolation_execution_evidence
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.scanners import read_only_rpc
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge

_IMAGE = "registry.example/mmaudit-hardhat@sha256:" + "a" * 64
_PINNED_BLOCK_HASH = "0x" + "f" * 64


class _OriginServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        content_length = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(content_length))
        requests = request if isinstance(request, list) else [request]
        response = [self._response(cast(dict[str, object], item)) for item in requests]
        payload: object = response if isinstance(request, list) else response[0]
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _response(request: dict[str, object]) -> dict[str, object]:
        method = request["method"]
        if method == "eth_chainId":
            result: object = hex(31_337)
        elif method in {"eth_getBlockByHash", "eth_getBlockByNumber"}:
            result = {"number": "0x0", "hash": _PINNED_BLOCK_HASH}
        else:
            result = None
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def loopback_origin() -> str:
    server = _OriginServer(("127.0.0.1", 0), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def short_private_root() -> Path:
    with TemporaryDirectory(prefix="mmaudit-hardhat-", dir="/private/tmp") as value:
        root = Path(value)
        root.chmod(0o700)
        yield root


def _backend(
    *,
    endpoint: object = "http://127.0.0.1:8545",
    methods: object | None = None,
    **updates: object,
) -> SingleLoopbackHardhatBackend:
    values: dict[str, object] = {
        "executable": "/usr/bin/podman",
        "image": _IMAGE,
        "runtime": "podman",
        "rootless_verified": True,
        "host_uid": max(os.getuid(), 1),
        "host_gid": max(os.getgid(), 0),
        "approved_loopback_rpc_endpoint": endpoint,
    }
    if methods is not None:
        values["allowed_rpc_methods"] = methods
    values.update(updates)
    return SingleLoopbackHardhatBackend(**values)  # type: ignore[arg-type]


@pytest.fixture
def live_private_bridge(
    short_private_root: Path,
    loopback_origin: str,
) -> tuple[
    Path,
    Path,
    SingleLoopbackHardhatBackend,
    ReadOnlyRpcBridge,
    HardhatReadOnlyRpcBridgeBinding,
]:
    private = short_private_root / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    private.chmod(0o700)
    backend = _backend(endpoint=loopback_origin, host_uid=os.getuid())
    bridge = ReadOnlyRpcBridge(
        loopback_origin,
        expected_chain_id=31_337,
        pinned_block_number=0,
        pinned_block_hash=_PINNED_BLOCK_HASH,
        unix_listener_path=private / "hardhat-rpc.sock",
    )
    bridge.start()
    binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    try:
        yield private, workspace, backend, bridge, binding
    finally:
        binding.close()
        bridge.stop()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8545",
        "http://synthetic-user:synthetic-password@127.0.0.1:8545",
        "http://example.invalid:8545",
        "http://127.0.0.1:8545/rpc",
        "http://127.0.0.1:8545/?network=broader",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:8545,http://127.0.0.1:9545",
        ("http://127.0.0.1:8545", "http://127.0.0.1:9545"),
    ],
)
def test_hardhat_backend_rejects_non_exact_or_multiple_loopback_endpoints(
    endpoint: object,
) -> None:
    with pytest.raises(ValueError, match=r"loopback|port|exactly one"):
        _backend(endpoint=endpoint)


@pytest.mark.parametrize(
    "methods",
    [
        (),
        ("eth_call", "eth_call"),
        ("eth_sendTransaction",),
        ("eth_sendRawTransaction",),
        ("hardhat_reset",),
        ("anvil_setBalance",),
        ("debug_traceCall",),
        ("unknown_but_plausibly_read_only",),
        ("eth_call",),
        tuple(sorted(HARDHAT_READ_ONLY_RPC_METHODS)),
        ["eth_call"],
    ],
)
def test_hardhat_backend_rejects_every_caller_supplied_method_policy(
    methods: object,
) -> None:
    with pytest.raises(TypeError, match="allowed_rpc_methods"):
        _backend(methods=methods)


def test_hardhat_backend_method_vocabulary_matches_the_trusted_read_only_bridge() -> None:
    trusted_bridge_methods = read_only_rpc.READ_ONLY_RPC_METHODS

    assert trusted_bridge_methods == HARDHAT_READ_ONLY_RPC_METHODS
    assert trusted_bridge_methods is HARDHAT_READ_ONLY_RPC_METHODS


def test_hardhat_capability_hash_is_derived_from_complete_effective_configuration() -> None:
    baseline = _backend()
    equivalent = _backend()
    other_endpoint = _backend(endpoint="http://127.0.0.1:9545")
    other_image = _backend(image="registry.example/other@sha256:" + "b" * 64)
    other_limits = _backend(
        limits=RootlessContainerLimits(memory_bytes=536_870_912),
    )

    assert baseline.hardhat_loopback_capability_sha256 == (
        baseline.expected_hardhat_loopback_capability_sha256()
    )
    assert baseline.hardhat_loopback_capability_sha256 == (
        equivalent.hardhat_loopback_capability_sha256
    )
    assert (
        len(
            {
                baseline.hardhat_loopback_capability_sha256,
                other_endpoint.hardhat_loopback_capability_sha256,
                other_image.hardhat_loopback_capability_sha256,
                other_limits.hardhat_loopback_capability_sha256,
            }
        )
        == 4
    )
    material = baseline.hardhat_loopback_effective_configuration()
    assert material["network_mode"] == "none"
    assert material["approved_loopback_rpc_endpoint_count"] == 1
    assert material["host_credentials_mounted"] is False
    assert material["container_socket_mounted"] is False
    assert material["allowed_rpc_methods"] == sorted(HARDHAT_READ_ONLY_RPC_METHODS)
    assert material["container_command_allowlist"] == ["hardhat", "node"]
    assert material["container_command_mapping"] == {
        "hardhat": "/usr/local/bin/hardhat",
        "node": "/usr/local/bin/node",
    }
    assert material["container_executable_identity"] == ("requires-separate-image-side-attestation")
    assert material["execution_authority"] == "requires-process-local-unix-bridge-seal"
    assert material["source_mount"] == "read-only"
    assert "hardhat_loopback_capability_sha256" not in material

    with pytest.raises(TypeError, match="unexpected keyword"):
        SingleLoopbackHardhatBackend(
            executable="/usr/bin/podman",
            image=_IMAGE,
            runtime="podman",
            rootless_verified=True,
            host_uid=1_000,
            host_gid=1_000,
            approved_loopback_rpc_endpoint="http://127.0.0.1:8545",
            hardhat_loopback_capability_sha256="f" * 64,  # type: ignore[call-arg]
        )


def test_hardhat_capability_construction_never_grants_execution_authority() -> None:
    backend = _backend()

    assert backend.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


def test_hardhat_wrapper_mounts_only_private_rpc_socket_under_network_none(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
) -> None:
    private, workspace, backend, bridge, binding = live_private_bridge
    rpc_port = backend.approved_loopback_rpc_port

    command = backend.wrap_hardhat_fork_suite(
        ["hardhat", "test", str(workspace / "test/audit")],
        workspace=workspace,
        private_dir=private,
        rpc_port=rpc_port,
    )

    rendered = " ".join(command)
    assert command[command.index("--network") + 1] == "none"
    assert "--network host" not in rendered
    assert "--network bridge" not in rendered
    assert (
        f"type=bind,src={private / 'hardhat-rpc.sock'},dst=/run/mmaudit/hardhat-rpc.sock,readonly"
    ) in command
    assert f"type=bind,src={workspace},dst=/workspace,readonly" in command
    assert command[command.index("--entrypoint") + 1] == ("/usr/local/bin/mmaudit-hardhat-loopback")
    assert command[command.index("--") + 1] == "/usr/local/bin/hardhat"
    assert f"MMAUDIT_FORK_RPC_URL=http://127.0.0.1:{rpc_port}" in command
    assert "MMAUDIT_FORK_RPC_UNIX_SOCKET=/run/mmaudit/hardhat-rpc.sock" in command
    authority_environment = next(
        item for item in command if item.startswith("MMAUDIT_HARDHAT_BRIDGE_AUTHORITY_SHA256=")
    )
    authority_sha256 = authority_environment.removeprefix(
        "MMAUDIT_HARDHAT_BRIDGE_AUTHORITY_SHA256="
    )
    assert len(authority_sha256) == 64
    assert command[command.index("--authority-sha256") + 1] == authority_sha256
    assert "docker.sock" not in rendered
    assert str(Path.home()) not in rendered
    assert "OPENROUTER_API_KEY" not in rendered
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
    assert bridge.live_unix_listener_observation().execution_credit is False
    assert binding is not None

    seccomp_argument = next(item for item in command if item.startswith("seccomp="))
    profile = json.loads(Path(seccomp_argument.removeprefix("seccomp=")).read_text())
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    ordinary = set(profile["syscalls"][0]["names"])
    assert {"connect", "bind", "listen", "accept"} <= ordinary
    assert {"mount", "ptrace", "keyctl"}.isdisjoint(ordinary)
    socket_families = {
        rule["args"][0]["value"] for rule in profile["syscalls"] if rule["names"] == ["socket"]
    }
    assert socket_families == {1, 2, 10}


def test_bridge_binding_rejects_other_private_directory_and_origin(
    short_private_root: Path,
    loopback_origin: str,
) -> None:
    private = short_private_root / "private"
    (private / "workspace").mkdir(parents=True)
    private.chmod(0o700)
    other_private = short_private_root / "other-private"
    other_private.mkdir(mode=0o700)
    other_private.chmod(0o700)
    bridge = ReadOnlyRpcBridge(
        loopback_origin,
        expected_chain_id=31_337,
        pinned_block_number=0,
        pinned_block_hash=_PINNED_BLOCK_HASH,
        unix_listener_path=private / "hardhat-rpc.sock",
    )
    bridge.start()
    try:
        backend = _backend(endpoint=loopback_origin)
        with pytest.raises(ValueError, match="exact private directory"):
            bind_hardhat_read_only_rpc_bridge(backend, other_private, bridge)

        wrong_origin = _backend(endpoint="http://127.0.0.1:65534")
        with pytest.raises(ValueError, match="origin differs"):
            bind_hardhat_read_only_rpc_bridge(wrong_origin, private, bridge)
    finally:
        bridge.stop()


@pytest.mark.parametrize(
    "command",
    [
        ["/synthetic/host/toolchain/hardhat", "test"],
        ["/usr/local/bin/hardhat", "test"],
        ["/usr/local/bin/node", "synthetic-script.cjs"],
        ["./node_modules/.bin/hardhat", "test"],
        ["npx", "hardhat", "test"],
        ["bash", "repository-script.sh"],
        [],
    ],
)
def test_hardhat_wrapper_rejects_host_and_repository_executable_identity(
    tmp_path: Path,
    command: list[str],
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = _backend()

    with pytest.raises(ValueError, match="fixed image-side command"):
        backend.wrap_hardhat_fork_suite(
            command,
            workspace=workspace,
            private_dir=private,
            rpc_port=8545,
        )
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


def test_hardhat_wrapper_maps_node_token_to_fixed_absolute_image_executable(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
) -> None:
    private, workspace, backend, _bridge, _binding = live_private_bridge

    command = backend.wrap_hardhat_fork_suite(
        ["node", "synthetic-script.cjs"],
        workspace=workspace,
        private_dir=private,
        rpc_port=backend.approved_loopback_rpc_port,
    )

    separator = command.index("--")
    assert command[separator + 1 :] == [
        "/usr/local/bin/node",
        "synthetic-script.cjs",
    ]


def test_process_local_binding_cannot_be_copied_serialized_or_reused_by_equal_backend(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
) -> None:
    private, workspace, backend, _bridge, binding = live_private_bridge

    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(binding)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(binding)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(binding)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(_bridge)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(_bridge)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(_bridge)

    copied_backend = copy.copy(backend)
    assert copied_backend == backend
    assert copied_backend is not backend
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        copied_backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=copied_backend.approved_loopback_rpc_port,
        )


def test_binding_close_and_bridge_stop_each_invalidate_command_authority(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
) -> None:
    private, workspace, backend, bridge, binding = live_private_bridge
    rpc_port = backend.approved_loopback_rpc_port

    binding.close()
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )

    rebound = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    bridge.stop()
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    rebound.close()


def test_live_binding_invalidates_on_socket_policy_state_backend_or_directory_drift(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
) -> None:
    private, workspace, backend, bridge, binding = live_private_bridge
    rpc_port = backend.approved_loopback_rpc_port
    socket_path = private / "hardhat-rpc.sock"

    socket_path.chmod(0o660)
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    socket_path.chmod(0o600)
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )

    binding.close()
    policy_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    original_policy = bridge._policy_sha256
    bridge._policy_sha256 = "a" * 64
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    bridge._policy_sha256 = original_policy
    policy_binding.close()

    state_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    original_block_hash = bridge._pinned_block_hash
    bridge._pinned_block_hash = "0x" + "e" * 64
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    bridge._pinned_block_hash = original_block_hash
    state_binding.close()

    origin_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    original_origin_port = bridge._origin_port
    bridge._origin_port = original_origin_port + 1
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    bridge._origin_port = original_origin_port
    origin_binding.close()

    dispatch_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    server = bridge._server
    assert server is not None
    server.bridge = cast(ReadOnlyRpcBridge, object())
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    server.bridge = bridge
    dispatch_binding.close()

    thread_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    original_serve_thread = bridge._serve_thread
    bridge._serve_thread = threading.Thread()
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    bridge._serve_thread = original_serve_thread
    thread_binding.close()

    backend_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    original_image = backend.image
    object.__setattr__(backend, "image", "registry.example/changed@sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    object.__setattr__(backend, "image", original_image)
    backend_binding.close()

    directory_binding = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
    private.chmod(0o750)
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=rpc_port,
        )
    private.chmod(0o700)
    directory_binding.close()

    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


def test_binding_is_invalid_outside_its_creating_process_identity(
    live_private_bridge: tuple[
        Path,
        Path,
        SingleLoopbackHardhatBackend,
        ReadOnlyRpcBridge,
        HardhatReadOnlyRpcBridgeBinding,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, workspace, backend, _bridge, _binding = live_private_bridge
    creating_process_id = os.getpid()
    monkeypatch.setattr("mmaudit.isolation.container.os.getpid", lambda: creating_process_id + 1)

    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=backend.approved_loopback_rpc_port,
        )


def test_hardhat_wrapper_rejects_wrong_port_and_missing_process_local_authority(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    private.chmod(0o700)
    backend = _backend()

    with pytest.raises(ValueError, match="approved loopback capability"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=9545,
        )
    (private / "hardhat-rpc.sock").write_text("same-UID broad proxy placeholder\n")
    with pytest.raises(ValueError, match="process-local Hardhat Unix-bridge authority"):
        backend.wrap_hardhat_fork_suite(
            ["hardhat", "test"],
            workspace=workspace,
            private_dir=private,
            rpc_port=8545,
        )
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED
