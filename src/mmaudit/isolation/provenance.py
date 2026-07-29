"""Process-local provenance for built-in hardened isolation backends."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import tempfile
import weakref
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, cast

from mmaudit.models.schemas import ExecutionEvidenceKind

_PROBE_TIMEOUT_SECONDS = 5.0
_POLICY_PROBE_PORT = 43_179
_SECRET_ENVIRONMENT_NAMES = (
    "OPENROUTER_API_KEY",
    "MMAUDIT_SECRETS_ENV_FILE",
)


class _BuiltInBackend(Protocol):
    """The subset of the built-in backend interface used by attestation."""

    executable: str
    name: str

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]: ...


@dataclass(frozen=True)
class _IsolationProbeResults:
    """Security properties observed by the built-in backend preflight."""

    benign_execution: bool
    workspace_write_allowed: bool
    network_denied: bool
    host_home_read_denied: bool
    secret_environment_denied: bool
    outside_write_denied: bool

    def all_required_passed(self) -> bool:
        """Return whether every mandatory boundary property was observed."""

        return all(asdict(self).values())


@dataclass(frozen=True)
class _IsolationAttestation:
    """Immutable process-local evidence bound to an executable and policy."""

    backend_kind: str
    executable: Path
    executable_sha256: str
    policy_sha256: str
    probes: _IsolationProbeResults
    verification_sha256: str


@dataclass(frozen=True)
class _IsolationSeal:
    """Identity-bound seal retained only in this process."""

    backend: weakref.ReferenceType[object]
    backend_type: type[object]
    name: str
    attestation: _IsolationAttestation


_SEALED_BACKENDS: dict[int, _IsolationSeal] = {}


def _built_in_backend_name(backend_type: type[object]) -> str | None:
    """Resolve exact production types lazily to avoid an import cycle."""

    from mmaudit.solidity.reproduction import BubblewrapBackend, MacOSSandboxBackend

    if backend_type is MacOSSandboxBackend:
        return "sandbox-exec"
    if backend_type is BubblewrapBackend:
        return "bubblewrap"
    return None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _trusted_helper(*candidates: str) -> Path:
    """Resolve a fixed system helper without consulting a target-controlled PATH."""

    for raw_path in candidates:
        path = Path(raw_path)
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    raise FileNotFoundError("required fixed isolation preflight helper is unavailable")


def _probe_environment(private_dir: Path) -> dict[str, str]:
    """Build the same kind of minimal, credential-free environment used by engines."""

    home = private_dir / "home"
    temporary = private_dir / "tmp"
    cache = private_dir / "cache"
    for path in (home, temporary, cache):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "CI": "true",
        "MMAUDIT_ISOLATION_PROBE": "1",
    }


def _normalized_boundary_material(
    backend: _BuiltInBackend,
    *,
    command: list[str],
    probe_root: Path,
    private_dir: Path,
    workspace: Path,
) -> dict[str, object]:
    """Return canonical wrapper and policy material for one representative command."""

    wrapped = backend.wrap(
        command,
        workspace=workspace,
        private_dir=private_dir,
        rpc_port=_POLICY_PROBE_PORT,
    )
    root_texts = (str(probe_root), str(probe_root.resolve(strict=True)))

    def normalize(value: str) -> str:
        normalized = value
        for root_text in root_texts:
            normalized = normalized.replace(root_text, "{PROBE_ROOT}")
        return normalized

    material: dict[str, object] = {"argv": [normalize(value) for value in wrapped]}
    if backend.name == "sandbox-exec":
        policy_path = private_dir / "sandbox.sb"
        policy = policy_path.read_text(encoding="utf-8")
        material["policy"] = normalize(policy)
    return material


def _current_policy_sha256(backend: _BuiltInBackend) -> str:
    """Hash deterministic representative wrappers for all adversarial probe helpers."""

    true_executable = _trusted_helper("/usr/bin/true", "/bin/true")
    shell_executable = _trusted_helper("/bin/sh", "/usr/bin/sh")
    network_executable = _trusted_helper("/usr/bin/nc", "/bin/nc")
    with tempfile.TemporaryDirectory(prefix="mmaudit-isolation-policy-") as raw_root:
        probe_root = Path(raw_root)
        private_dir = probe_root / "private"
        workspace = private_dir / "workspace"
        workspace.mkdir(parents=True, mode=0o700)
        material = [
            _normalized_boundary_material(
                backend,
                command=[str(command)],
                probe_root=probe_root,
                private_dir=private_dir,
                workspace=workspace,
            )
            for command in (true_executable, shell_executable, network_executable)
        ]
    payload = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _execute_probe(
    backend: _BuiltInBackend,
    command: list[str],
    *,
    workspace: Path,
    private_dir: Path,
    rpc_port: int,
    environment: dict[str, str],
) -> int | None:
    """Execute one fixed preflight command and retain no command output."""

    try:
        wrapped = backend.wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )
        result = subprocess.run(
            wrapped,
            cwd=workspace,
            check=False,
            capture_output=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            env=environment,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return result.returncode


def _network_probe_denied(
    backend: _BuiltInBackend,
    network_executable: Path,
    *,
    workspace: Path,
    private_dir: Path,
    environment: dict[str, str],
) -> bool:
    """Require the boundary to reject a connection to a reachable unapproved port."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.2)
            port = int(listener.getsockname()[1])
            control = subprocess.run(
                [
                    str(network_executable),
                    "-z",
                    "-w",
                    "1",
                    "127.0.0.1",
                    str(port),
                ],
                cwd=workspace,
                check=False,
                capture_output=True,
                timeout=_PROBE_TIMEOUT_SECONDS,
                env=environment,
                shell=False,
            )
            try:
                control_connection, _control_address = listener.accept()
            except TimeoutError:
                return False
            control_connection.close()
            if control.returncode != 0:
                return False
            approved_port = port - 1 if port == 65_535 else port + 1
            return_code = _execute_probe(
                backend,
                [
                    str(network_executable),
                    "-z",
                    "-w",
                    "1",
                    "127.0.0.1",
                    str(port),
                ],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=approved_port,
                environment=environment,
            )
            connected = False
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                pass
            else:
                connected = True
                connection.close()
    except (OSError, subprocess.TimeoutExpired):
        return False
    return return_code is not None and return_code != 0 and not connected


def _run_builtin_preflight(backend: _BuiltInBackend) -> _IsolationProbeResults | None:
    """Run benign and adversarial probes through the exact production wrapper."""

    try:
        true_executable = _trusted_helper("/usr/bin/true", "/bin/true")
        shell_executable = _trusted_helper("/bin/sh", "/usr/bin/sh")
        network_executable = _trusted_helper("/usr/bin/nc", "/bin/nc")
        with tempfile.TemporaryDirectory(prefix="mmaudit-isolation-probe-") as raw_root:
            probe_root = Path(raw_root)
            private_dir = probe_root / "private"
            workspace = private_dir / "workspace"
            host_home = probe_root / "host-home"
            workspace.mkdir(parents=True, mode=0o700)
            host_home.mkdir(mode=0o700)
            host_canary = host_home / "host-canary"
            host_canary.write_text("synthetic host boundary canary\n", encoding="utf-8")
            outside_target = host_home / "outside-write"
            workspace_target = workspace / "workspace-write"
            environment = _probe_environment(private_dir)

            benign_execution = (
                _execute_probe(
                    backend,
                    [str(true_executable)],
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=_POLICY_PROBE_PORT,
                    environment=environment,
                )
                == 0
            )
            workspace_write_allowed = (
                _execute_probe(
                    backend,
                    [
                        str(shell_executable),
                        "-c",
                        'printf "workspace-ok" > "$1"',
                        "mmaudit-isolation-probe",
                        str(workspace_target),
                    ],
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=_POLICY_PROBE_PORT,
                    environment=environment,
                )
                == 0
                and workspace_target.is_file()
                and workspace_target.read_text(encoding="utf-8") == "workspace-ok"
            )
            host_home_read_denied = _execute_probe(
                backend,
                [
                    str(shell_executable),
                    "-c",
                    'IFS= read -r _value < "$1"',
                    "mmaudit-isolation-probe",
                    str(host_canary),
                ],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=_POLICY_PROBE_PORT,
                environment=environment,
            ) not in (None, 0)
            outside_write_denied = (
                _execute_probe(
                    backend,
                    [
                        str(shell_executable),
                        "-c",
                        'printf "boundary-failed" > "$1"',
                        "mmaudit-isolation-probe",
                        str(outside_target),
                    ],
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=_POLICY_PROBE_PORT,
                    environment=environment,
                )
                not in (None, 0)
                and not outside_target.exists()
            )
            secret_expression = " && ".join(
                f'test -z "${{{name}+x}}"' for name in _SECRET_ENVIRONMENT_NAMES
            )
            secret_environment_denied = (
                _execute_probe(
                    backend,
                    [str(shell_executable), "-c", secret_expression],
                    workspace=workspace,
                    private_dir=private_dir,
                    rpc_port=_POLICY_PROBE_PORT,
                    environment=environment,
                )
                == 0
            )
            network_denied = _network_probe_denied(
                backend,
                network_executable,
                workspace=workspace,
                private_dir=private_dir,
                environment=environment,
            )
    except (OSError, UnicodeError, ValueError):
        return None

    results = _IsolationProbeResults(
        benign_execution=benign_execution,
        workspace_write_allowed=workspace_write_allowed,
        network_denied=network_denied,
        host_home_read_denied=host_home_read_denied,
        secret_environment_denied=secret_environment_denied,
        outside_write_denied=outside_write_denied,
    )
    return results if results.all_required_passed() else None


def _attestation_verification_sha256(
    *,
    backend_kind: str,
    executable: Path,
    executable_sha256: str,
    policy_sha256: str,
    probes: _IsolationProbeResults,
) -> str:
    payload = {
        "backend_kind": backend_kind,
        "executable": str(executable),
        "executable_sha256": executable_sha256,
        "policy_sha256": policy_sha256,
        "probes": asdict(probes),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _seal_builtin_isolation_backend[BackendT](backend: BackendT) -> BackendT:
    """Seal an exact built-in backend only after every adversarial probe succeeds."""

    backend_type = type(backend)
    expected_name = _built_in_backend_name(backend_type)
    name = getattr(backend, "name", None)
    executable_value = getattr(backend, "executable", None)
    if expected_name is None or name != expected_name or not isinstance(executable_value, str):
        raise ValueError("only exact built-in isolation backends may receive provenance")
    executable = Path(executable_value)
    if not executable.is_absolute():
        raise ValueError("sealed isolation executables must use absolute paths")
    try:
        resolved_executable = executable.resolve(strict=True)
    except OSError as exc:
        raise ValueError("sealed isolation executable could not be resolved") from exc
    if not resolved_executable.is_file():
        raise ValueError("sealed isolation executable must be a regular file")

    typed_backend = cast("_BuiltInBackend", backend)
    probes = _run_builtin_preflight(typed_backend)
    if probes is None or not probes.all_required_passed():
        raise ValueError("built-in isolation backend failed mandatory adversarial preflight")
    try:
        executable_sha256 = _file_sha256(resolved_executable)
        policy_sha256 = _current_policy_sha256(typed_backend)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("built-in isolation attestation hashing failed") from exc
    verification_sha256 = _attestation_verification_sha256(
        backend_kind=expected_name,
        executable=resolved_executable,
        executable_sha256=executable_sha256,
        policy_sha256=policy_sha256,
        probes=probes,
    )
    attestation = _IsolationAttestation(
        backend_kind=expected_name,
        executable=resolved_executable,
        executable_sha256=executable_sha256,
        policy_sha256=policy_sha256,
        probes=probes,
        verification_sha256=verification_sha256,
    )

    identity = id(backend)

    def discard(reference: weakref.ReferenceType[object]) -> None:
        current = _SEALED_BACKENDS.get(identity)
        if current is not None and current.backend is reference:
            _SEALED_BACKENDS.pop(identity, None)

    backend_object: object = backend
    reference = weakref.ref(backend_object, discard)
    _SEALED_BACKENDS[identity] = _IsolationSeal(
        backend=reference,
        backend_type=backend_type,
        name=expected_name,
        attestation=attestation,
    )
    return backend


def _attestation_still_valid(backend: _BuiltInBackend, seal: _IsolationSeal) -> bool:
    attestation = seal.attestation
    try:
        executable = Path(backend.executable).resolve(strict=True)
        executable_sha256 = _file_sha256(executable)
        policy_sha256 = _current_policy_sha256(backend)
    except (OSError, UnicodeError, ValueError):
        return False
    expected_verification = _attestation_verification_sha256(
        backend_kind=seal.name,
        executable=executable,
        executable_sha256=executable_sha256,
        policy_sha256=policy_sha256,
        probes=attestation.probes,
    )
    return (
        attestation.probes.all_required_passed()
        and executable == attestation.executable
        and executable_sha256 == attestation.executable_sha256
        and policy_sha256 == attestation.policy_sha256
        and expected_verification == attestation.verification_sha256
    )


def isolation_execution_evidence(backend: object | None) -> ExecutionEvidenceKind:
    """Return REAL only for an unchanged exact built-in instance with a valid seal."""

    if backend is None:
        return ExecutionEvidenceKind.UNVERIFIED
    seal = _SEALED_BACKENDS.get(id(backend))
    if (
        seal is not None
        and seal.backend() is backend
        and type(backend) is seal.backend_type
        and getattr(backend, "name", None) == seal.name
        and _attestation_still_valid(cast("_BuiltInBackend", backend), seal)
    ):
        return ExecutionEvidenceKind.REAL
    declared = getattr(backend, "execution_evidence", ExecutionEvidenceKind.UNVERIFIED)
    return (
        ExecutionEvidenceKind.MOCK
        if declared is ExecutionEvidenceKind.MOCK
        else ExecutionEvidenceKind.UNVERIFIED
    )


def isolation_attestation_sha256(backend: object | None) -> str | None:
    """Return the current sealed attestation digest for an unchanged built-in backend."""

    if backend is None:
        return None
    seal = _SEALED_BACKENDS.get(id(backend))
    if (
        seal is not None
        and seal.backend() is backend
        and type(backend) is seal.backend_type
        and getattr(backend, "name", None) == seal.name
        and _attestation_still_valid(cast("_BuiltInBackend", backend), seal)
    ):
        return seal.attestation.verification_sha256
    return None
