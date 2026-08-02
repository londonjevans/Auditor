"""Rootless, digest-pinned container isolation with fixed defensive controls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import weakref
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, SupportsIndex, runtime_checkable
from urllib.parse import urlparse

from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.operator_secrets import RESERVED_OPERATOR_CONTROL_PLANE_NAMES
from mmaudit.scanners.read_only_rpc import (
    READ_ONLY_RPC_METHODS,
    ReadOnlyRpcBridge,
    ReadOnlyRpcBridgeError,
    ReadOnlyRpcUnixListenerObservation,
)

_DIGEST_PINNED_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_CONTAINER_WORKSPACE = Path("/workspace")
_CONTAINER_WRITABLE = Path("/mmaudit-output")
_CONTAINER_HOME = Path("/home/mmaudit")
_CONTAINER_TMP = Path("/tmp")
_HARDHAT_BRIDGE_SOCKET = Path("/run/mmaudit/hardhat-rpc.sock")
_HARDHAT_BRIDGE_SOCKET_NAME = "hardhat-rpc.sock"
_HARDHAT_LOOPBACK_ENTRYPOINT = "/usr/local/bin/mmaudit-hardhat-loopback"
_HARDHAT_LOOPBACK_POLICY_VERSION = "MMAUDIT_HARDHAT_SINGLE_LOOPBACK_V1"
_HARDHAT_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HARDHAT_CONTAINER_EXECUTABLES: Final = MappingProxyType(
    {
        "hardhat": "/usr/local/bin/hardhat",
        "node": "/usr/local/bin/node",
    }
)
# Re-export the exact immutable policy used by the trusted bridge; never duplicate it.
HARDHAT_READ_ONLY_RPC_METHODS: Final = READ_ONLY_RPC_METHODS
_FORBIDDEN_SECCOMP_SYSCALLS = frozenset(
    {
        "accept",
        "accept4",
        "bind",
        "connect",
        "keyctl",
        "listen",
        "mount",
        "perf_event_open",
        "ptrace",
        "reboot",
        "socket",
        "socketpair",
        "umount2",
    }
)
_ALLOWED_SECCOMP_SYSCALLS = (
    "access",
    "arch_prctl",
    "brk",
    "capget",
    "capset",
    "chdir",
    "clone",
    "clone3",
    "close",
    "close_range",
    "dup",
    "dup2",
    "dup3",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fchdir",
    "fcntl",
    "fdatasync",
    "flock",
    "fstat",
    "fsync",
    "ftruncate",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getpid",
    "getppid",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrlimit",
    "gettid",
    "getuid",
    "ioctl",
    "lseek",
    "madvise",
    "membarrier",
    "mkdir",
    "mkdirat",
    "mmap",
    "mprotect",
    "mremap",
    "munmap",
    "nanosleep",
    "newfstatat",
    "open",
    "openat",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "prctl",
    "pread64",
    "prlimit64",
    "pselect6",
    "pwrite64",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_yield",
    "select",
    "set_robust_list",
    "set_tid_address",
    "setgid",
    "setgroups",
    "setresgid",
    "setresuid",
    "setuid",
    "sigaltstack",
    "stat",
    "statx",
    "sysinfo",
    "tgkill",
    "truncate",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "wait4",
    "waitid",
    "write",
    "writev",
)
_HARDHAT_LOOPBACK_SOCKET_SYSCALLS = frozenset(
    {
        "accept",
        "accept4",
        "bind",
        "connect",
        "getpeername",
        "getsockname",
        "getsockopt",
        "listen",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "setsockopt",
        "shutdown",
    }
)


@runtime_checkable
class RepositoryJavaScriptIsolationBackend(Protocol):
    """Off-host boundary for commands that may load repository JavaScript."""

    @property
    def name(self) -> str: ...

    def wrap_repository_javascript(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]: ...


def isolation_host_environment(
    backend: object,
    private_dir: Path,
    fallback: dict[str, str],
) -> dict[str, str]:
    """Select a backend-specific scrubbed client environment when available."""

    provider = getattr(backend, "host_environment", None)
    if not callable(provider):
        environment = dict(fallback)
    else:
        environment = provider(private_dir)
        if not isinstance(environment, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in environment.items()
        ):
            raise ValueError("isolation backend returned an invalid host environment")
        environment = dict(environment)
    for name in RESERVED_OPERATOR_CONTROL_PLANE_NAMES:
        environment.pop(name, None)
    return environment


def cleanup_isolation_backend(backend: object, private_dir: Path) -> None:
    """Invoke verified backend cleanup when the selected backend exposes it."""

    cleanup = getattr(backend, "cleanup", None)
    if callable(cleanup):
        cleanup(private_dir)


def _current_uid() -> int:
    return int(getattr(os, "getuid", lambda: 0)())


def _current_gid() -> int:
    return int(getattr(os, "getgid", lambda: 0)())


@dataclass(frozen=True)
class RootlessContainerLimits:
    """Resource ceilings passed directly to the trusted container runtime."""

    memory_bytes: int = 1_073_741_824
    cpu_count: float = 1.0
    pids: int = 128
    open_files: int = 256
    temporary_bytes: int = 67_108_864
    home_bytes: int = 16_777_216

    def __post_init__(self) -> None:
        if not 67_108_864 <= self.memory_bytes <= 8_589_934_592:
            raise ValueError("container memory limit must be between 64 MiB and 8 GiB")
        if not 0.1 <= self.cpu_count <= 8:
            raise ValueError("container CPU limit must be between 0.1 and 8")
        if not 16 <= self.pids <= 1_024:
            raise ValueError("container PID limit must be between 16 and 1024")
        if not 64 <= self.open_files <= 4_096:
            raise ValueError("container file-descriptor limit must be between 64 and 4096")
        if not 16_777_216 <= self.temporary_bytes <= 1_073_741_824:
            raise ValueError("container temporary storage must be between 16 MiB and 1 GiB")
        if not 4_194_304 <= self.home_bytes <= 268_435_456:
            raise ValueError("container home storage must be between 4 MiB and 256 MiB")


@dataclass(frozen=True)
class RootlessContainerBackend:
    """Construct one no-network container invocation from trusted typed inputs."""

    executable: str
    image: str
    runtime: Literal["docker", "podman"]
    rootless_verified: bool
    host_uid: int = field(default_factory=_current_uid)
    host_gid: int = field(default_factory=_current_gid)
    limits: RootlessContainerLimits = field(default_factory=RootlessContainerLimits)
    name: str = "rootless-container"
    # The host hashes the selected executable, while the image entrypoint is the
    # binary that actually runs. Certification remains unavailable until the
    # digest-pinned image exposes an in-container binary attestation.
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    supports_local_fork_rpc: bool = False

    def __post_init__(self) -> None:
        if not Path(self.executable).is_absolute():
            raise ValueError("container runtime executable must be an absolute path")
        if not _DIGEST_PINNED_IMAGE.fullmatch(self.image):
            raise ValueError("container image must be pinned by a lowercase sha256 digest")
        if not self.rootless_verified:
            raise ValueError("container runtime must be verified as rootless")
        if self.host_uid <= 0:
            raise ValueError("rootless container execution requires a non-root host user")
        if self.host_gid < 0:
            raise ValueError("container host group must be non-negative")

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Return a fixed no-network invocation; local RPC access is intentionally absent."""

        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            writable_workspace=False,
        )

    def wrap_repository_javascript(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Run repository JavaScript off-host in a writable disposable workspace."""

        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            writable_workspace=True,
        )

    def _wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        writable_workspace: bool,
    ) -> list[str]:
        resolved_private = private_dir.resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(resolved_private)
        _validate_runtime_path(resolved_private)
        _validate_runtime_path(resolved_workspace)
        runtime_dir = resolved_private / "container-runtime"
        writable_dir = resolved_private / "container-output"
        runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        writable_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        seccomp_path = runtime_dir / "seccomp.json"
        cidfile = runtime_dir / "container.cid"
        _write_seccomp_profile(seccomp_path)
        translated = _translate_command(
            command,
            workspace=resolved_workspace,
            writable_dir=writable_dir,
        )
        source_mount = f"type=bind,src={resolved_workspace},dst={_CONTAINER_WORKSPACE}"
        if not writable_workspace:
            source_mount += ",readonly"
        writable_mount = f"type=bind,src={writable_dir},dst={_CONTAINER_WRITABLE},rw"
        return [
            self.executable,
            "run",
            "--rm",
            "--pull",
            "never",
            "--cidfile",
            str(cidfile),
            "--network",
            "none",
            "--ipc",
            "none",
            "--pid",
            "private",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={seccomp_path}",
            "--pids-limit",
            str(self.limits.pids),
            "--memory",
            str(self.limits.memory_bytes),
            "--memory-swap",
            str(self.limits.memory_bytes),
            "--cpus",
            str(self.limits.cpu_count),
            "--ulimit",
            f"nofile={self.limits.open_files}:{self.limits.open_files}",
            "--user",
            f"{self.host_uid}:{self.host_gid}",
            "--env",
            f"HOME={_CONTAINER_HOME}",
            "--env",
            f"TMPDIR={_CONTAINER_TMP}",
            "--env",
            "LANG=C.UTF-8",
            "--env",
            "LC_ALL=C.UTF-8",
            "--env",
            "NO_COLOR=1",
            "--env",
            "CI=true",
            "--env",
            "HARDHAT_DISABLE_TELEMETRY_PROMPT=true",
            "--env",
            "HARDHAT_NETWORK=hardhat",
            "--mount",
            source_mount,
            "--mount",
            writable_mount,
            "--tmpfs",
            (f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={self.limits.temporary_bytes}"),
            "--tmpfs",
            (f"{_CONTAINER_HOME}:rw,noexec,nosuid,nodev,size={self.limits.home_bytes}"),
            "--workdir",
            str(_CONTAINER_WORKSPACE),
            "--entrypoint",
            translated[0],
            self.image,
            *translated[1:],
        ]

    def writable_path(self, private_dir: Path) -> Path:
        """Return the dedicated output directory exposed read-write to the container."""

        resolved_private = private_dir.resolve(strict=True)
        writable_dir = resolved_private / "container-output"
        writable_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return writable_dir

    def host_environment(self, private_dir: Path) -> dict[str, str]:
        """Return only rootless-runtime routing state for the host-side client."""

        return rootless_runtime_environment(private_dir / "runtime-client")

    def cleanup(self, private_dir: Path) -> None:
        """Force-remove a residual container and verify that it is absent."""

        runtime_dir = private_dir.resolve(strict=True) / "container-runtime"
        cidfile = runtime_dir / "container.cid"
        if not cidfile.exists():
            return
        container_id = cidfile.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise RuntimeError("container cleanup refused an invalid runtime identifier")
        environment = rootless_runtime_environment(runtime_dir)
        inspect = [self.executable, "container", "inspect", container_id]
        before = subprocess.run(
            inspect,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
            shell=False,
        )
        if before.returncode == 0:
            subprocess.run(
                [self.executable, "rm", "--force", container_id],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
                shell=False,
            )
        after = subprocess.run(
            inspect,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
            shell=False,
        )
        if after.returncode == 0:
            raise RuntimeError("container cleanup could not verify removal")
        cidfile.unlink(missing_ok=True)


@dataclass(frozen=True, kw_only=True)
class SingleLoopbackHardhatBackend(RootlessContainerBackend):
    """Unverified rootless Hardhat command contract for one trusted RPC bridge."""

    approved_loopback_rpc_endpoint: str
    allowed_rpc_methods: tuple[str, ...] = field(
        default_factory=lambda: tuple(sorted(HARDHAT_READ_ONLY_RPC_METHODS)),
        init=False,
    )
    name: str = field(default="single-loopback-hardhat", init=False)
    execution_evidence: ExecutionEvidenceKind = field(
        default=ExecutionEvidenceKind.UNVERIFIED,
        init=False,
    )
    supports_local_fork_rpc: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        canonical_endpoint = _canonical_hardhat_loopback_endpoint(
            self.approved_loopback_rpc_endpoint
        )
        object.__setattr__(self, "approved_loopback_rpc_endpoint", canonical_endpoint)

    @property
    def approved_loopback_rpc_port(self) -> int:
        """Return the one port bound into this capability."""

        port = urlparse(self.approved_loopback_rpc_endpoint).port
        if port is None:  # Defensive against illicit frozen-instance mutation.
            raise ValueError("Hardhat loopback RPC capability has no approved port")
        return port

    @property
    def hardhat_network_policy(self) -> Literal["single-loopback-rpc"]:
        """Expose the exact policy vocabulary expected by the Hardhat adapter."""

        return "single-loopback-rpc"

    @property
    def broad_network_enabled(self) -> Literal[False]:
        """Broad network capability is structurally absent."""

        return False

    @property
    def hardhat_loopback_capability_sha256(self) -> str:
        """Hash effective settings; this configuration fingerprint grants no authority."""

        return self.expected_hardhat_loopback_capability_sha256()

    def expected_hardhat_loopback_capability_sha256(self) -> str:
        """Recompute the exact immutable capability identity from effective settings."""

        return _canonical_sha256(self.hardhat_loopback_effective_configuration())

    def hardhat_loopback_effective_configuration(self) -> dict[str, object]:
        """Return the secret-free primitive configuration sealed by the capability hash."""

        rpc_method_policy_sha256 = _canonical_sha256(
            {
                "version": _HARDHAT_LOOPBACK_POLICY_VERSION,
                "allowed_methods": list(self.allowed_rpc_methods),
                "unknown_methods": "deny",
            }
        )
        container_rpc_endpoint = f"http://127.0.0.1:{self.approved_loopback_rpc_port}"
        return {
            "version": _HARDHAT_LOOPBACK_POLICY_VERSION,
            "runtime": self.runtime,
            "host_runtime_executable": self.executable,
            "image": self.image,
            "rootless_verified": self.rootless_verified,
            "host_uid": self.host_uid,
            "host_gid": self.host_gid,
            "limits": asdict(self.limits),
            "network_mode": "none",
            "broad_network_enabled": False,
            "approved_loopback_rpc_endpoint": self.approved_loopback_rpc_endpoint,
            "approved_loopback_rpc_endpoint_count": 1,
            "container_rpc_endpoint": container_rpc_endpoint,
            "rpc_bridge_transport": "private-unix-socket",
            "host_bridge_socket_relative_path": _HARDHAT_BRIDGE_SOCKET_NAME,
            "container_bridge_socket": str(_HARDHAT_BRIDGE_SOCKET),
            "container_entrypoint": _HARDHAT_LOOPBACK_ENTRYPOINT,
            "container_command_allowlist": sorted(_HARDHAT_CONTAINER_EXECUTABLES),
            "container_command_mapping": dict(_HARDHAT_CONTAINER_EXECUTABLES),
            "container_executable_identity": "requires-separate-image-side-attestation",
            "execution_authority": "requires-process-local-unix-bridge-seal",
            "allowed_rpc_methods": list(self.allowed_rpc_methods),
            "rpc_method_policy_sha256": rpc_method_policy_sha256,
            "seccomp_profile_sha256": hashlib.sha256(
                _seccomp_profile_bytes(allow_loopback_rpc=True)
            ).hexdigest(),
            "source_mount": "read-only",
            "root_filesystem": "read-only",
            "host_credentials_mounted": False,
            "container_socket_mounted": False,
            "fixed_container_environment": [
                f"MMAUDIT_FORK_RPC_METHOD_POLICY_SHA256={rpc_method_policy_sha256}",
                f"MMAUDIT_FORK_RPC_UNIX_SOCKET={_HARDHAT_BRIDGE_SOCKET}",
                f"MMAUDIT_FORK_RPC_URL={container_rpc_endpoint}",
            ],
        }

    def bridge_socket_path(self, private_dir: Path) -> Path:
        """Return the fixed host socket path without accepting caller-selected mounts."""

        resolved_private = private_dir.resolve(strict=True)
        _validate_runtime_path(resolved_private)
        return resolved_private / _HARDHAT_BRIDGE_SOCKET_NAME

    def wrap_hardhat_fork_suite(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Wrap only after a separate process-local bridge authority is verified."""

        if type(rpc_port) is not int or rpc_port != self.approved_loopback_rpc_port:
            raise ValueError("Hardhat RPC port does not match the approved loopback capability")
        image_executable = _HARDHAT_CONTAINER_EXECUTABLES.get(command[0]) if command else None
        if image_executable is None:
            raise ValueError(
                "Hardhat wrapper requires a fixed image-side command without host identity"
            )
        authority = _require_process_local_hardhat_bridge_authority(self, private_dir)
        expected_bridge_socket = self.bridge_socket_path(private_dir)
        try:
            bridge_socket = authority.socket_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("Hardhat bridge authority socket is unavailable") from exc
        if bridge_socket != expected_bridge_socket:
            raise ValueError("Hardhat bridge authority socket is outside its fixed private path")
        _validate_runtime_path(bridge_socket)
        bridge_mount = f"type=bind,src={bridge_socket},dst={_HARDHAT_BRIDGE_SOCKET},readonly"
        container_rpc_endpoint = f"http://127.0.0.1:{rpc_port}"
        rpc_method_policy_sha256 = str(
            self.hardhat_loopback_effective_configuration()["rpc_method_policy_sha256"]
        )
        authority_sha256 = _canonical_sha256(
            {
                "version": "MMAUDIT_HARDHAT_BRIDGE_AUTHORITY_BINDING_V1",
                "capability_sha256": self.hardhat_loopback_capability_sha256,
                "bridge_policy_sha256": authority.bridge_policy_sha256,
                "bridge_state_sha256": authority.bridge_state_sha256,
                "bridge_preflight_snapshot_sha256": (authority.bridge_preflight_snapshot_sha256),
                "bridge_listener_capability_sha256": (authority.bridge_listener_capability_sha256),
                "bridge_socket_identity_sha256": authority.bridge_socket_identity_sha256,
                "bridge_observation_sha256": authority.bridge_observation_sha256,
            }
        )
        return self._wrap_hardhat_command(
            image_executable=image_executable,
            command_arguments=command[1:],
            workspace=workspace,
            private_dir=private_dir,
            bridge_mount=bridge_mount,
            container_rpc_endpoint=container_rpc_endpoint,
            rpc_method_policy_sha256=rpc_method_policy_sha256,
            authority_sha256=authority_sha256,
            rpc_port=rpc_port,
        )

    def _wrap_hardhat_command(
        self,
        *,
        image_executable: str,
        command_arguments: list[str],
        workspace: Path,
        private_dir: Path,
        bridge_mount: str,
        container_rpc_endpoint: str,
        rpc_method_policy_sha256: str,
        authority_sha256: str,
        rpc_port: int,
    ) -> list[str]:
        """Build fixed argv after the non-public authority boundary has succeeded."""

        resolved_private = private_dir.resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(resolved_private)
        _validate_runtime_path(resolved_private)
        _validate_runtime_path(resolved_workspace)
        runtime_dir = resolved_private / "container-runtime"
        writable_dir = resolved_private / "container-output"
        runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        writable_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        seccomp_path = runtime_dir / "hardhat-seccomp.json"
        cidfile = runtime_dir / "container.cid"
        _write_seccomp_profile(seccomp_path, allow_loopback_rpc=True)
        if image_executable not in _HARDHAT_CONTAINER_EXECUTABLES.values():
            raise ValueError("Hardhat wrapper requires one fixed absolute image executable")
        translated_arguments = _translate_command(
            [Path(image_executable).name, *command_arguments],
            workspace=resolved_workspace,
            writable_dir=writable_dir,
        )[1:]
        source_mount = f"type=bind,src={resolved_workspace},dst={_CONTAINER_WORKSPACE},readonly"
        writable_mount = f"type=bind,src={writable_dir},dst={_CONTAINER_WRITABLE},rw"
        return [
            self.executable,
            "run",
            "--rm",
            "--pull",
            "never",
            "--cidfile",
            str(cidfile),
            "--network",
            "none",
            "--ipc",
            "none",
            "--pid",
            "private",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            f"seccomp={seccomp_path}",
            "--pids-limit",
            str(self.limits.pids),
            "--memory",
            str(self.limits.memory_bytes),
            "--memory-swap",
            str(self.limits.memory_bytes),
            "--cpus",
            str(self.limits.cpu_count),
            "--ulimit",
            f"nofile={self.limits.open_files}:{self.limits.open_files}",
            "--user",
            f"{self.host_uid}:{self.host_gid}",
            "--env",
            f"HOME={_CONTAINER_HOME}",
            "--env",
            f"TMPDIR={_CONTAINER_TMP}",
            "--env",
            "LANG=C.UTF-8",
            "--env",
            "LC_ALL=C.UTF-8",
            "--env",
            "NO_COLOR=1",
            "--env",
            "CI=true",
            "--env",
            "HARDHAT_DISABLE_TELEMETRY_PROMPT=true",
            "--env",
            "HARDHAT_NETWORK=hardhat",
            "--env",
            f"MMAUDIT_FORK_RPC_METHOD_POLICY_SHA256={rpc_method_policy_sha256}",
            "--env",
            f"MMAUDIT_FORK_RPC_UNIX_SOCKET={_HARDHAT_BRIDGE_SOCKET}",
            "--env",
            f"MMAUDIT_FORK_RPC_URL={container_rpc_endpoint}",
            "--env",
            f"MMAUDIT_HARDHAT_BRIDGE_AUTHORITY_SHA256={authority_sha256}",
            "--mount",
            source_mount,
            "--mount",
            writable_mount,
            "--mount",
            bridge_mount,
            "--tmpfs",
            f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={self.limits.temporary_bytes}",
            "--tmpfs",
            f"{_CONTAINER_HOME}:rw,noexec,nosuid,nodev,size={self.limits.home_bytes}",
            "--workdir",
            str(_CONTAINER_WORKSPACE),
            "--entrypoint",
            _HARDHAT_LOOPBACK_ENTRYPOINT,
            self.image,
            "--unix-socket",
            str(_HARDHAT_BRIDGE_SOCKET),
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(rpc_port),
            "--method-policy-sha256",
            rpc_method_policy_sha256,
            "--authority-sha256",
            authority_sha256,
            "--",
            image_executable,
            *translated_arguments,
        ]


def _canonical_hardhat_loopback_endpoint(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("Hardhat RPC capability requires exactly one loopback endpoint")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Hardhat RPC capability requires exactly one loopback endpoint")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Hardhat RPC capability has an invalid loopback port") from exc
    if (
        parsed.scheme != "http"
        or not parsed.netloc
        or parsed.hostname not in _HARDHAT_LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port is None
        or not 1 <= port <= 65_535
    ):
        raise ValueError(
            "Hardhat RPC capability requires one credential-free plain HTTP loopback endpoint"
        )
    host = "::1" if parsed.hostname == "::1" else "127.0.0.1"
    return f"http://[{host}]:{port}" if host == "::1" else f"http://{host}:{port}"


@dataclass(frozen=True)
class _PrivateDirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int


@dataclass(frozen=True)
class _ProcessLocalHardhatBridgeAuthority:
    """Fresh internal projection of one exact live process-local bridge seal."""

    socket_path: Path
    bridge_policy_sha256: str
    bridge_state_sha256: str
    bridge_preflight_snapshot_sha256: str
    bridge_listener_capability_sha256: str
    bridge_socket_identity_sha256: str
    bridge_observation_sha256: str

    def __post_init__(self) -> None:
        hashes = (
            self.bridge_policy_sha256,
            self.bridge_state_sha256,
            self.bridge_preflight_snapshot_sha256,
            self.bridge_listener_capability_sha256,
            self.bridge_socket_identity_sha256,
            self.bridge_observation_sha256,
        )
        if not self.socket_path.is_absolute() or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hashes
        ):
            raise ValueError("Hardhat bridge authority identity is invalid")


@dataclass(frozen=True)
class _HardhatBridgeSeal:
    backend_reference: weakref.ReferenceType[SingleLoopbackHardhatBackend]
    bridge_reference: weakref.ReferenceType[ReadOnlyRpcBridge]
    binding_reference: weakref.ReferenceType[HardhatReadOnlyRpcBridgeBinding]
    private_directory_identity: _PrivateDirectoryIdentity
    backend_capability_sha256: str
    observation: ReadOnlyRpcUnixListenerObservation
    seal_nonce: str
    process_id: int


_HARDHAT_BRIDGE_BINDING_FACTORY = object()
_HARDHAT_BRIDGE_SEALS: dict[int, _HardhatBridgeSeal] = {}
_HARDHAT_BRIDGE_SEALS_LOCK = threading.RLock()


class HardhatReadOnlyRpcBridgeBinding:
    """Opaque lifetime handle for one exact process-local Hardhat bridge join.

    The handle is deliberately neither copyable nor serializable. Keeping it live
    only permits construction of an unverified container command; it never grants
    REAL or VERIFIED execution evidence.
    """

    __slots__ = ("__weakref__", "_backend_identity", "_closed", "_seal_nonce")

    def __init__(
        self,
        backend_identity: int,
        seal_nonce: str,
        *,
        factory: object,
    ) -> None:
        if factory is not _HARDHAT_BRIDGE_BINDING_FACTORY:
            raise TypeError("Hardhat bridge bindings must be created by the trusted binder")
        self._backend_identity = backend_identity
        self._seal_nonce = seal_nonce
        self._closed = False

    def __enter__(self) -> HardhatReadOnlyRpcBridgeBinding:
        if self._closed:
            raise ValueError("Hardhat bridge binding is closed")
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Irreversibly remove this exact handle's process-local seal."""

        with _HARDHAT_BRIDGE_SEALS_LOCK:
            current = _HARDHAT_BRIDGE_SEALS.get(self._backend_identity)
            if (
                current is not None
                and current.seal_nonce == self._seal_nonce
                and current.binding_reference() is self
            ):
                _HARDHAT_BRIDGE_SEALS.pop(self._backend_identity, None)
            self._closed = True

    def __copy__(self) -> HardhatReadOnlyRpcBridgeBinding:
        raise TypeError("Hardhat bridge bindings cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> HardhatReadOnlyRpcBridgeBinding:
        raise TypeError("Hardhat bridge bindings cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("Hardhat bridge bindings cannot be serialized")


def bind_hardhat_read_only_rpc_bridge(
    backend: SingleLoopbackHardhatBackend,
    private_dir: Path,
    bridge: ReadOnlyRpcBridge,
) -> HardhatReadOnlyRpcBridgeBinding:
    """Bind an exact live Unix bridge to one backend and private directory.

    Serialized observation values never satisfy this API: the registry retains
    weak references to the exact bridge, backend, and opaque lifetime handle, and
    every use revalidates all live identities.
    """

    if type(backend) is not SingleLoopbackHardhatBackend:
        raise TypeError("Hardhat bridge binding requires the exact supported backend type")
    if type(bridge) is not ReadOnlyRpcBridge:
        raise TypeError("Hardhat bridge binding requires the exact trusted bridge type")
    private_identity = _hardhat_private_directory_identity(private_dir)
    observation = _hardhat_live_bridge_observation(bridge)
    expected_socket_path = backend.bridge_socket_path(private_identity.path)
    if observation.socket_path != expected_socket_path:
        raise ValueError("Hardhat bridge socket is outside the exact private directory")
    if observation.origin_endpoint != backend.approved_loopback_rpc_endpoint:
        raise ValueError("Hardhat bridge origin differs from the approved loopback endpoint")
    backend_capability_sha256 = backend.expected_hardhat_loopback_capability_sha256()
    if (
        backend.hardhat_loopback_capability_sha256 != backend_capability_sha256
        or backend.execution_evidence is not ExecutionEvidenceKind.UNVERIFIED
    ):
        raise ValueError("Hardhat backend capability identity is invalid")

    backend_identity = id(backend)
    seal_nonce = secrets.token_hex(32)
    binding = HardhatReadOnlyRpcBridgeBinding(
        backend_identity,
        seal_nonce,
        factory=_HARDHAT_BRIDGE_BINDING_FACTORY,
    )

    def discard(_reference: object) -> None:
        with _HARDHAT_BRIDGE_SEALS_LOCK:
            current = _HARDHAT_BRIDGE_SEALS.get(backend_identity)
            if current is not None and current.seal_nonce == seal_nonce:
                _HARDHAT_BRIDGE_SEALS.pop(backend_identity, None)

    seal = _HardhatBridgeSeal(
        backend_reference=weakref.ref(backend, discard),
        bridge_reference=weakref.ref(bridge, discard),
        binding_reference=weakref.ref(binding, discard),
        private_directory_identity=private_identity,
        backend_capability_sha256=backend_capability_sha256,
        observation=observation,
        seal_nonce=seal_nonce,
        process_id=os.getpid(),
    )
    with _HARDHAT_BRIDGE_SEALS_LOCK:
        existing = _HARDHAT_BRIDGE_SEALS.get(backend_identity)
        if existing is not None:
            try:
                _authority_from_hardhat_bridge_seal(
                    existing,
                    backend=backend,
                    private_identity=private_identity,
                )
            except ValueError:
                _HARDHAT_BRIDGE_SEALS.pop(backend_identity, None)
            else:
                raise ValueError("Hardhat backend already has a live process-local bridge binding")
        _HARDHAT_BRIDGE_SEALS[backend_identity] = seal
    return binding


def _require_process_local_hardhat_bridge_authority(
    backend: SingleLoopbackHardhatBackend,
    private_dir: Path,
) -> _ProcessLocalHardhatBridgeAuthority:
    """Return authority only while every exact process-local identity remains live."""

    backend_identity = id(backend)
    try:
        private_identity = _hardhat_private_directory_identity(private_dir)
    except ValueError as exc:
        with _HARDHAT_BRIDGE_SEALS_LOCK:
            _HARDHAT_BRIDGE_SEALS.pop(backend_identity, None)
        raise ValueError(
            "trusted process-local Hardhat Unix-bridge authority is unavailable"
        ) from exc
    with _HARDHAT_BRIDGE_SEALS_LOCK:
        seal = _HARDHAT_BRIDGE_SEALS.get(backend_identity)
        if seal is None:
            raise ValueError("trusted process-local Hardhat Unix-bridge authority is unavailable")
        try:
            return _authority_from_hardhat_bridge_seal(
                seal,
                backend=backend,
                private_identity=private_identity,
            )
        except ValueError as exc:
            _HARDHAT_BRIDGE_SEALS.pop(backend_identity, None)
            raise ValueError(
                "trusted process-local Hardhat Unix-bridge authority is unavailable"
            ) from exc


def _authority_from_hardhat_bridge_seal(
    seal: _HardhatBridgeSeal,
    *,
    backend: SingleLoopbackHardhatBackend,
    private_identity: _PrivateDirectoryIdentity,
) -> _ProcessLocalHardhatBridgeAuthority:
    retained_backend = seal.backend_reference()
    bridge = seal.bridge_reference()
    binding = seal.binding_reference()
    if (
        retained_backend is not backend
        or bridge is None
        or binding is None
        or binding._closed
        or binding._seal_nonce != seal.seal_nonce
        or os.getpid() != seal.process_id
        or seal.private_directory_identity != private_identity
        or type(backend) is not SingleLoopbackHardhatBackend
        or type(bridge) is not ReadOnlyRpcBridge
        or backend.execution_evidence is not ExecutionEvidenceKind.UNVERIFIED
        or backend.expected_hardhat_loopback_capability_sha256() != seal.backend_capability_sha256
        or backend.hardhat_loopback_capability_sha256 != seal.backend_capability_sha256
    ):
        raise ValueError("Hardhat process-local bridge seal identity changed")
    observation = _hardhat_live_bridge_observation(bridge)
    if (
        observation != seal.observation
        or observation.socket_path != backend.bridge_socket_path(private_identity.path)
        or observation.origin_endpoint != backend.approved_loopback_rpc_endpoint
    ):
        raise ValueError("Hardhat process-local bridge observation changed")
    return _ProcessLocalHardhatBridgeAuthority(
        socket_path=observation.socket_path,
        bridge_policy_sha256=observation.policy_sha256,
        bridge_state_sha256=observation.state_sha256,
        bridge_preflight_snapshot_sha256=(observation.preflight_origin_observation_sha256),
        bridge_listener_capability_sha256=observation.listener_capability_sha256,
        bridge_socket_identity_sha256=observation.socket_identity_sha256,
        bridge_observation_sha256=observation.observation_sha256,
    )


def _hardhat_live_bridge_observation(
    bridge: ReadOnlyRpcBridge,
) -> ReadOnlyRpcUnixListenerObservation:
    try:
        return bridge.live_unix_listener_observation()
    except (ReadOnlyRpcBridgeError, ValueError) as exc:
        raise ValueError("Hardhat owner-only Unix bridge is not live and stable") from exc


def _hardhat_private_directory_identity(path: Path) -> _PrivateDirectoryIdentity:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("Hardhat private directory must be an exact absolute path")
    try:
        absolute = path.absolute()
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("Hardhat private directory is unavailable") from exc
    get_effective_uid = getattr(os, "geteuid", None)
    if get_effective_uid is None:
        raise ValueError("Hardhat private directory requires effective UID support")
    if (
        absolute != resolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != get_effective_uid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("Hardhat private directory identity or mode is invalid")
    _validate_runtime_path(resolved)
    return _PrivateDirectoryIdentity(
        path=resolved,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def discover_rootless_container_backend(
    image: str | None,
    *,
    runtime: Literal["auto", "docker", "podman"] = "auto",
) -> RootlessContainerBackend | None:
    """Resolve only a local, non-repository runtime that proves rootless operation."""

    if image is None or not _DIGEST_PINNED_IMAGE.fullmatch(image):
        return None
    runtime_names: tuple[Literal["docker", "podman"], ...] = (
        ("podman", "docker") if runtime == "auto" else (runtime,)
    )
    current_root = Path.cwd().resolve()
    for runtime_name in runtime_names:
        executable = shutil.which(runtime_name)
        if executable is None:
            continue
        resolved = Path(executable).resolve(strict=True)
        try:
            resolved.relative_to(current_root)
        except ValueError:
            pass
        else:
            continue
        if not _runtime_is_rootless(str(resolved), runtime_name):
            continue
        try:
            return RootlessContainerBackend(
                executable=str(resolved),
                image=image,
                runtime=runtime_name,
                rootless_verified=True,
            )
        except ValueError:
            return None
    return None


def rootless_runtime_environment(private_dir: Path) -> dict[str, str]:
    """Keep only runtime routing variables; omit registry and application credentials."""

    home = private_dir / "runtime-home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir and Path(runtime_dir).is_absolute():
        environment["XDG_RUNTIME_DIR"] = runtime_dir
    for name in ("DOCKER_HOST", "CONTAINER_HOST"):
        value = os.environ.get(name)
        if value and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", value):
            environment[name] = value
    return environment


def _runtime_is_rootless(executable: str, runtime: str) -> bool:
    try:
        with tempfile.TemporaryDirectory(prefix="mmaudit-runtime-probe-") as raw_private:
            environment = rootless_runtime_environment(Path(raw_private))
            command = (
                [executable, "info", "--format", "json"]
                if runtime == "podman"
                else [executable, "info", "--format", "{{json .SecurityOptions}}"]
            )
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
                shell=False,
            )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    if runtime == "docker":
        return "rootless" in result.stdout.casefold()
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    host = payload.get("host", {})
    if not isinstance(host, dict):
        return False
    security = host.get("security", {})
    return bool(host.get("rootless") or (isinstance(security, dict) and security.get("rootless")))


def _translate_command(
    command: list[str],
    *,
    workspace: Path,
    writable_dir: Path,
) -> list[str]:
    if not command:
        raise ValueError("container command must not be empty")
    translated: list[str] = []
    for index, item in enumerate(command):
        if not item or any(ord(character) < 32 or ord(character) == 127 for character in item):
            raise ValueError("container command contains an unsafe argument")
        if index == 0:
            translated.append(Path(item).name if Path(item).is_absolute() else item)
            continue
        path = Path(item)
        if ".." in path.parts:
            raise ValueError("container command path traversal is not permitted")
        if not path.is_absolute():
            translated.append(item)
            continue
        translated_path = _container_path(path, workspace, writable_dir)
        if translated_path is None:
            raise ValueError("container command references a host path outside isolated mounts")
        translated.append(str(translated_path))
    return translated


def _container_path(path: Path, workspace: Path, writable_dir: Path) -> Path | None:
    for host_root, container_root in (
        (workspace, _CONTAINER_WORKSPACE),
        (writable_dir, _CONTAINER_WRITABLE),
    ):
        try:
            relative = path.relative_to(host_root)
        except ValueError:
            continue
        return container_root / relative
    return None


def _validate_runtime_path(path: Path) -> None:
    value = str(path)
    if "," in value or "\n" in value or "\r" in value:
        raise ValueError("container mount paths must not contain separators or control text")


def _seccomp_profile_payload(*, allow_loopback_rpc: bool) -> dict[str, object]:
    allowed = set(_ALLOWED_SECCOMP_SYSCALLS)
    purpose_specific = (
        _HARDHAT_LOOPBACK_SOCKET_SYSCALLS | {"socket", "socketpair"}
        if allow_loopback_rpc
        else frozenset()
    )
    forbidden = _FORBIDDEN_SECCOMP_SYSCALLS - purpose_specific
    if allowed & forbidden:
        raise RuntimeError("container syscall profile includes a forbidden operation")
    syscall_rules: list[dict[str, object]] = [
        {
            "names": sorted(
                allowed | (_HARDHAT_LOOPBACK_SOCKET_SYSCALLS if allow_loopback_rpc else set())
            ),
            "action": "SCMP_ACT_ALLOW",
        }
    ]
    if allow_loopback_rpc:
        # AF_UNIX reaches the mounted read-only bridge. AF_INET/AF_INET6 are limited
        # to the container's own loopback because the runtime network is exactly none.
        for family in (1, 2, 10):
            syscall_rules.append(
                {
                    "names": ["socket"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [
                        {
                            "index": 0,
                            "value": family,
                            "valueTwo": 0,
                            "op": "SCMP_CMP_EQ",
                        }
                    ],
                }
            )
        syscall_rules.append(
            {
                "names": ["socketpair"],
                "action": "SCMP_ACT_ALLOW",
                "args": [
                    {
                        "index": 0,
                        "value": 1,
                        "valueTwo": 0,
                        "op": "SCMP_CMP_EQ",
                    }
                ],
            }
        )
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "syscalls": syscall_rules,
    }


def _seccomp_profile_bytes(*, allow_loopback_rpc: bool) -> bytes:
    return (
        json.dumps(
            _seccomp_profile_payload(allow_loopback_rpc=allow_loopback_rpc),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_seccomp_profile(path: Path, *, allow_loopback_rpc: bool = False) -> None:
    path.write_bytes(
        _seccomp_profile_bytes(allow_loopback_rpc=allow_loopback_rpc),
    )
