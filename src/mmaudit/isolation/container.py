"""Rootless, digest-pinned container isolation with fixed defensive controls."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from mmaudit.operator_secrets import RESERVED_OPERATOR_CONTROL_PLANE_NAMES

_DIGEST_PINNED_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_CONTAINER_WORKSPACE = Path("/workspace")
_CONTAINER_WRITABLE = Path("/mmaudit-output")
_CONTAINER_HOME = Path("/home/mmaudit")
_CONTAINER_TMP = Path("/tmp")
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


def _write_seccomp_profile(path: Path) -> None:
    allowed = set(_ALLOWED_SECCOMP_SYSCALLS)
    if allowed & _FORBIDDEN_SECCOMP_SYSCALLS:
        raise RuntimeError("container syscall profile includes a forbidden operation")
    payload = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "syscalls": [
            {
                "names": sorted(allowed),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
