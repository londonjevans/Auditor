"""Bounded isolated execution of compiler-backed Foundry test inventories."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from mmaudit.isolation.container import (
    cleanup_isolation_backend,
    isolation_host_environment,
)
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    RepositoryCodeExecutionState,
    RepositorySuiteInventoryArtifact,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryPhase,
    RepositorySuiteInventoryRecord,
    RepositorySuiteProjectInventoryEvidence,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.scanners.base import (
    ScannerIsolationBackend,
    sanitized_scanner_environment,
    scanner_workspace_sha256,
)
from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryError,
    FoundryInventoryLimits,
    FoundrySourceInput,
    FoundryTestDeclaration,
    FoundryTestInventory,
    parse_foundry_test_inventory,
)

_SHA256_LENGTH = 64
_NORMALIZED_BUILD_INFO_ID = "0" * 16
_INVENTORY_RPC_SENTINEL_PORT = 1
_POLL_INTERVAL_SECONDS = 0.025
_MAX_GENERATED_DIRECTORY_DEPTH = 256
_DESCRIPTOR_RELATIVE_OPEN_SUPPORTED = os.open in os.supports_dir_fd
_DESCRIPTOR_RELATIVE_STAT_SUPPORTED = os.stat in os.supports_dir_fd
_DESCRIPTOR_SCANDIR_SUPPORTED = os.scandir in os.supports_fd
_SUPPORTED_PROJECT_TYPES = frozenset(
    {
        SolidityProjectType.FOUNDRY,
        SolidityProjectType.MIXED,
    }
)
_HOST_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "CI",
        "CONTAINER_HOST",
        "DOCKER_HOST",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    }
)


class FoundryInventoryRunnerError(RuntimeError):
    """Base class for fail-closed inventory execution failures."""


class FoundryInventoryUnavailableError(FoundryInventoryRunnerError):
    """A mandatory local execution prerequisite is unavailable."""


class FoundryInventoryTimeoutError(FoundryInventoryRunnerError):
    """The bounded inventory process exceeded its deadline."""


class FoundryInventoryInvalidError(FoundryInventoryRunnerError):
    """Execution or compiler evidence failed strict validation."""


class FoundryInventoryOverflowError(FoundryInventoryRunnerError):
    """A configured stream or artifact ceiling was exceeded."""


class _GeneratedTraversalPurpose(StrEnum):
    """Separate live ceiling monitoring from stable post-exit validation."""

    STRICT_SNAPSHOT = "strict_snapshot"
    LIVE_LIMIT_MONITOR = "live_limit_monitor"


class _LiveGeneratedTreeMutation(Exception):
    """One live measurement became stale without yielding trusted observations."""


@dataclass(frozen=True, slots=True)
class FoundryInventoryRunLimits:
    """Resource and evidence ceilings for one pre/post inventory phase."""

    max_stdout_bytes_per_project: int = 10_000_000
    max_stderr_bytes_per_project: int = 5_000_000
    max_total_stream_bytes: int = 50_000_000
    max_generated_entries_per_project: int = 20_000
    max_generated_file_bytes: int = 100_000_000
    max_generated_bytes_per_project: int = 500_000_000
    max_total_generated_bytes: int = 1_000_000_000
    max_combined_output_bytes: int = 1_050_000_000

    def __post_init__(self) -> None:
        if not 1_024 <= self.max_stdout_bytes_per_project <= 100_000_000:
            raise ValueError("Foundry inventory stdout ceiling is out of bounds")
        if not 1_024 <= self.max_stderr_bytes_per_project <= 100_000_000:
            raise ValueError("Foundry inventory stderr ceiling is out of bounds")
        if not (
            max(self.max_stdout_bytes_per_project, self.max_stderr_bytes_per_project)
            <= self.max_total_stream_bytes
            <= 500_000_000
        ):
            raise ValueError("Foundry inventory total stream ceiling is out of bounds")
        if not 1 <= self.max_generated_entries_per_project <= 100_000:
            raise ValueError("Foundry inventory generated-entry ceiling is out of bounds")
        if not 1_024 <= self.max_generated_file_bytes <= 250_000_000:
            raise ValueError("Foundry inventory generated-file ceiling is out of bounds")
        if not (
            self.max_generated_file_bytes <= self.max_generated_bytes_per_project <= 2_000_000_000
        ):
            raise ValueError("Foundry inventory generated-byte ceiling is out of bounds")
        if not (
            self.max_generated_bytes_per_project <= self.max_total_generated_bytes <= 4_000_000_000
        ):
            raise ValueError("Foundry inventory total generated-byte ceiling is out of bounds")
        if not (
            max(self.max_total_stream_bytes, self.max_total_generated_bytes)
            <= self.max_combined_output_bytes
            <= 4_500_000_000
        ):
            raise ValueError("Foundry inventory combined output ceiling is out of bounds")


@dataclass(frozen=True, slots=True)
class FoundryInventoryRunResult:
    """Typed compiler inventories and their isolated runtime evidence."""

    inventories: tuple[FoundryTestInventory, ...]
    evidence: RepositorySuiteInventoryEvidence
    accounted_output_bytes: int
    generated_artifact_bytes: int

    def __post_init__(self) -> None:
        if len(self.inventories) != len(self.evidence.projects):
            raise ValueError("Foundry inventory result project counts differ")
        if self.accounted_output_bytes < 0 or self.generated_artifact_bytes < 0:
            raise ValueError("Foundry inventory byte accounting cannot be negative")


@dataclass(frozen=True, slots=True)
class _GeneratedUsage:
    entries: int
    files: int
    bytes: int


@dataclass(slots=True)
class _GeneratedUsageAccumulator:
    entries: int = 0
    files: int = 0
    bytes: int = 0


@dataclass(slots=True)
class _RetainedDirectoryChain:
    trusted_path: Path
    descriptors: list[int]
    opened: list[os.stat_result]
    names: list[str]

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]


@dataclass(frozen=True, slots=True)
class _ProjectExecution:
    project_root: str
    command_sha256: str
    stdout: bytes
    stderr: bytes
    build_info: tuple[tuple[str, bytes], ...]
    generated_bytes: int


@dataclass(frozen=True, slots=True)
class _NormalizedBuildInfoArtifact:
    name: str
    raw: bytes
    normalized: bytes

    @property
    def raw_sha256(self) -> str:
        return _sha256_bytes(self.raw)

    @property
    def normalized_sha256(self) -> str:
        return _sha256_bytes(self.normalized)


def run_foundry_test_inventory(
    *,
    workspace: Path,
    private_dir: Path,
    projects: Sequence[SolidityProjectMetadata],
    phase: RepositorySuiteInventoryPhase,
    forge_executable: Path,
    copied_solc: Path,
    repository_sha256: str,
    configuration_sha256: str,
    tool_version: str,
    tool_sha256: str,
    compiler_version: str,
    compiler_sha256: str,
    backend: ScannerIsolationBackend,
    timeout_seconds: float,
    limits: FoundryInventoryRunLimits | None = None,
    parser_limits: FoundryInventoryLimits | None = None,
) -> FoundryInventoryRunResult:
    """Run one isolated whole-project Forge inventory for each Foundry project.

    The caller supplies a disposable workspace and exact pinned tool identities.
    This function re-hashes those inputs, executes no fork or network operation,
    reconciles Forge output with compiler AST build information, and returns only
    bounded, hash-linked evidence.
    """

    bounds = limits or FoundryInventoryRunLimits()
    parse_bounds = parser_limits or FoundryInventoryLimits()
    if not isinstance(phase, RepositorySuiteInventoryPhase):
        raise FoundryInventoryInvalidError("Foundry inventory phase is invalid")
    if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 86_400:
        raise FoundryInventoryInvalidError("Foundry inventory timeout is invalid")
    _validate_hash(repository_sha256, "repository")
    _validate_hash(configuration_sha256, "configuration")
    _validate_hash(tool_sha256, "Forge executable")
    _validate_hash(compiler_sha256, "Solidity compiler")
    _validate_text(tool_version, "Forge version")
    _validate_text(compiler_version, "Solidity compiler version")

    resolved_private, resolved_workspace = _validated_roots(private_dir, workspace)
    resolved_forge = _validated_executable(
        forge_executable,
        expected_sha256=tool_sha256,
        label="Forge",
    )
    resolved_solc = _validated_executable(
        copied_solc,
        expected_sha256=compiler_sha256,
        label="Solidity compiler",
    )
    try:
        resolved_solc.relative_to(resolved_private)
    except ValueError as exc:
        raise FoundryInventoryInvalidError(
            "copied Solidity compiler is outside the private execution directory"
        ) from exc
    if scanner_workspace_sha256(resolved_workspace) != repository_sha256:
        raise FoundryInventoryInvalidError(
            "disposable workspace differs from the selected repository"
        )

    execution_evidence = isolation_execution_evidence(backend)
    attestation_sha256 = isolation_attestation_sha256(backend)
    backend_name = str(getattr(backend, "name", ""))
    if execution_evidence is ExecutionEvidenceKind.UNVERIFIED or attestation_sha256 is None:
        raise FoundryInventoryUnavailableError(
            "Foundry inventory isolation lacks current attested execution evidence"
        )
    _validate_text(backend_name, "isolation backend")
    _validate_hash(attestation_sha256, "isolation attestation")

    selected_projects = _validated_projects(projects, resolved_workspace)
    generated_root = _generated_root(backend, resolved_private)
    phase_root = generated_root / "repository-suite" / "inventory" / phase.value
    try:
        phase_root.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError as exc:
        raise FoundryInventoryInvalidError("Foundry inventory phase output already exists") from exc
    except OSError as exc:
        raise FoundryInventoryUnavailableError(
            f"Foundry inventory output directory is unavailable: {type(exc).__name__}"
        ) from exc

    base_environment = _inventory_environment(backend, resolved_private)
    runtime_solc = _runtime_solc_path(
        backend=backend,
        copied_solc=resolved_solc,
        generated_root=generated_root,
        expected_sha256=compiler_sha256,
    )
    deadline = time.monotonic() + float(timeout_seconds)
    project_executions: list[_ProjectExecution] = []
    total_stream_bytes = 0
    total_generated_bytes = 0
    for index, project in enumerate(selected_projects):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FoundryInventoryTimeoutError("Foundry inventory total deadline expired")
        remaining_output_bytes = (
            bounds.max_combined_output_bytes - total_stream_bytes - total_generated_bytes
        )
        if remaining_output_bytes <= 0:
            raise FoundryInventoryOverflowError(
                "Foundry inventory exhausted its combined output ceiling"
            )
        execution = _execute_project_inventory(
            workspace=resolved_workspace,
            private_dir=resolved_private,
            artifact_root=generated_root,
            phase_root=phase_root,
            project=project,
            output_index=index,
            forge_executable=resolved_forge,
            copied_solc=runtime_solc,
            backend=backend,
            environment=base_environment,
            timeout_seconds=remaining,
            bounds=bounds,
            remaining_total_output_bytes=remaining_output_bytes,
        )
        project_executions.append(execution)
        total_stream_bytes += len(execution.stdout) + len(execution.stderr)
        total_generated_bytes += execution.generated_bytes
        if total_stream_bytes > bounds.max_total_stream_bytes:
            raise FoundryInventoryOverflowError(
                "Foundry inventory streams exceeded the total byte ceiling"
            )
        if total_generated_bytes > bounds.max_total_generated_bytes:
            raise FoundryInventoryOverflowError(
                "Foundry inventory artifacts exceeded the total byte ceiling"
            )
        if total_stream_bytes + total_generated_bytes > bounds.max_combined_output_bytes:
            raise FoundryInventoryOverflowError(
                "Foundry inventory exceeded the combined output ceiling"
            )
        if _sha256_file(resolved_forge) != tool_sha256:
            raise FoundryInventoryInvalidError(
                "Forge executable changed during inventory execution"
            )
        if _sha256_file(resolved_solc) != compiler_sha256:
            raise FoundryInventoryInvalidError(
                "copied Solidity compiler changed during inventory execution"
            )
        if _sha256_file(runtime_solc) != compiler_sha256:
            raise FoundryInventoryInvalidError(
                "isolated Solidity compiler changed during inventory execution"
            )
        if scanner_workspace_sha256(resolved_workspace) != repository_sha256:
            raise FoundryInventoryInvalidError(
                "disposable workspace changed during inventory execution"
            )

    inventories: list[FoundryTestInventory] = []
    project_evidence: list[RepositorySuiteProjectInventoryEvidence] = []
    try:
        for execution in project_executions:
            if time.monotonic() >= deadline:
                raise FoundryInventoryTimeoutError(
                    "Foundry inventory total deadline expired during validation"
                )
            project_path = _project_path(resolved_workspace, execution.project_root)
            build_info_artifacts = tuple(
                _NormalizedBuildInfoArtifact(
                    name=name,
                    raw=raw,
                    normalized=_normalize_build_info_json(
                        raw,
                        project_path=project_path,
                        project_root=execution.project_root,
                        maximum_bytes=parse_bounds.max_build_info_json_bytes,
                    ),
                )
                for name, raw in execution.build_info
            )
            build_info_payloads = tuple(artifact.normalized for artifact in build_info_artifacts)
            source_inputs = _read_bound_sources(
                project_path,
                build_info_payloads,
                parse_bounds,
            )
            inventory = parse_foundry_test_inventory(
                forge_list_json=execution.stdout,
                build_info_jsons=build_info_payloads,
                sources=source_inputs,
                project_root=execution.project_root,
                compiler_version=compiler_version,
                compiler_sha256=compiler_sha256,
                limits=parse_bounds,
            )
            if time.monotonic() >= deadline:
                raise FoundryInventoryTimeoutError(
                    "Foundry inventory total deadline expired during validation"
                )
            inventories.append(inventory)
            records = tuple(
                sorted(
                    (
                        _inventory_record(execution.project_root, declaration)
                        for declaration in inventory.tests
                    ),
                    key=lambda item: item.canonical_key,
                )
            )
            artifact_records = tuple(
                RepositorySuiteInventoryArtifact(
                    name=artifact.name,
                    sha256=artifact.raw_sha256,
                    normalized_sha256=artifact.normalized_sha256,
                    bytes=len(artifact.raw),
                )
                for artifact in build_info_artifacts
            )
            project_evidence.append(
                RepositorySuiteProjectInventoryEvidence.sealed(
                    project_root=execution.project_root,
                    command_sha256=execution.command_sha256,
                    process_exit_code=0,
                    machine_output_validated=True,
                    stdout_sha256=_sha256_bytes(execution.stdout),
                    stdout_bytes=len(execution.stdout),
                    stderr_sha256=_sha256_bytes(execution.stderr),
                    stderr_bytes=len(execution.stderr),
                    build_info_artifacts=artifact_records,
                    build_info_bundle_sha256=_canonical_sha256(
                        [artifact.model_dump(mode="json") for artifact in artifact_records]
                    ),
                    normalized_build_info_bundle_sha256=_canonical_sha256(
                        sorted(artifact.normalized_sha256 for artifact in build_info_artifacts)
                    ),
                    parser_inventory_sha256=inventory.inventory_sha256,
                    records=records,
                    normalized_inventory_sha256=_canonical_sha256(
                        sorted(record.record_sha256 for record in records)
                    ),
                )
            )
    except FoundryInventoryRunnerError:
        raise
    except (FoundryInventoryError, ValidationError, OSError, UnicodeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            f"Foundry compiler inventory failed validation: {type(exc).__name__}"
        ) from exc

    projects_tuple = tuple(project_evidence)
    record_hashes = sorted(
        record.record_sha256 for project in projects_tuple for record in project.records
    )
    evidence = RepositorySuiteInventoryEvidence.sealed(
        phase=phase,
        repository_sha256=repository_sha256,
        configuration_sha256=configuration_sha256,
        tool_version=tool_version,
        tool_sha256=tool_sha256,
        compiler_version=compiler_version,
        compiler_sha256=compiler_sha256,
        isolation_backend=backend_name,
        isolation_attestation_sha256=attestation_sha256,
        execution_evidence=execution_evidence,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        projects=projects_tuple,
        project_bundle_sha256=_canonical_sha256(
            [project.project_inventory_sha256 for project in projects_tuple]
        ),
        normalized_inventory_sha256=_canonical_sha256(record_hashes),
        inventory_record_count=len(record_hashes),
        safety_claim=False,
    )
    return FoundryInventoryRunResult(
        inventories=tuple(inventories),
        evidence=evidence,
        accounted_output_bytes=total_stream_bytes,
        generated_artifact_bytes=total_generated_bytes,
    )


def _validated_roots(private_dir: Path, workspace: Path) -> tuple[Path, Path]:
    private_before = _non_link_directory_metadata(
        private_dir,
        label="Foundry inventory private directory",
    )
    workspace_before = _non_link_directory_metadata(
        workspace,
        label="Foundry inventory workspace",
    )
    try:
        resolved_private = private_dir.resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(resolved_private)
    except (OSError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            "Foundry inventory workspace must be inside its private directory"
        ) from exc
    private_after = _non_link_directory_metadata(
        private_dir,
        label="Foundry inventory private directory",
    )
    workspace_after = _non_link_directory_metadata(
        workspace,
        label="Foundry inventory workspace",
    )
    try:
        resolved_private_metadata = resolved_private.stat()
        resolved_workspace_metadata = resolved_workspace.stat()
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry inventory roots could not be inspected after resolution"
        ) from exc
    if (
        _file_identity(private_before) != _file_identity(private_after)
        or _file_identity(private_before) != _file_identity(resolved_private_metadata)
        or _file_identity(workspace_before) != _file_identity(workspace_after)
        or _file_identity(workspace_before) != _file_identity(resolved_workspace_metadata)
    ):
        raise FoundryInventoryInvalidError("Foundry inventory roots changed during validation")
    return resolved_private, resolved_workspace


def _non_link_directory_metadata(path: Path, *, label: str) -> os.stat_result:
    """Inspect a supplied root without resolving its final path component."""

    try:
        metadata = path.lstat()
        is_junction = path.is_junction()
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or is_junction:
        raise FoundryInventoryInvalidError(f"{label} is not a non-link directory")
    return metadata


def _validated_executable(path: Path, *, expected_sha256: str, label: str) -> Path:
    if not path.is_absolute():
        raise FoundryInventoryInvalidError(f"{label} executable path is not absolute")
    try:
        if path.is_symlink() or path.is_junction():
            raise FoundryInventoryInvalidError(f"{label} executable path is a link")
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise FoundryInventoryUnavailableError(f"{label} executable is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not os.access(resolved, os.X_OK)
    ):
        raise FoundryInventoryInvalidError(f"{label} executable is not a unique regular file")
    if _sha256_file(resolved) != expected_sha256:
        raise FoundryInventoryInvalidError(f"{label} executable differs from its trust pin")
    return resolved


def _validated_projects(
    projects: Sequence[SolidityProjectMetadata],
    workspace: Path,
) -> tuple[SolidityProjectMetadata, ...]:
    selected: list[SolidityProjectMetadata] = []
    observed_roots: set[str] = set()
    for project in projects:
        if not isinstance(project, SolidityProjectMetadata):
            raise FoundryInventoryInvalidError("Foundry project metadata is invalid")
        if project.project_type not in _SUPPORTED_PROJECT_TYPES:
            continue
        root = _normalized_project_root(project.project_root)
        if root in observed_roots:
            raise FoundryInventoryInvalidError("Foundry project roots are duplicated")
        observed_roots.add(root)
        _project_path(workspace, root)
        selected.append(project.model_copy(update={"project_root": root}))
    selected.sort(key=lambda item: item.project_root)
    if not selected:
        raise FoundryInventoryUnavailableError("no Foundry project is available for inventory")
    if len(selected) > 1_000:
        raise FoundryInventoryOverflowError(
            "Foundry project inventory exceeded its project ceiling"
        )
    return tuple(selected)


def _normalized_project_root(value: str) -> str:
    try:
        normalized = normalize_relative_path(value)
    except (TypeError, ValueError) as exc:
        raise FoundryInventoryInvalidError("Foundry project root is unsafe") from exc
    if normalized != value or not normalized:
        raise FoundryInventoryInvalidError("Foundry project root is not canonical")
    return normalized


def _project_path(workspace: Path, project_root: str) -> Path:
    path = (
        workspace if project_root == "." else workspace.joinpath(*PurePosixPath(project_root).parts)
    )
    try:
        cursor = workspace
        for part in () if project_root == "." else PurePosixPath(project_root).parts:
            cursor /= part
            if cursor.is_symlink() or cursor.is_junction():
                raise FoundryInventoryInvalidError("Foundry project root traverses a link")
        resolved = path.resolve(strict=True)
        resolved.relative_to(workspace)
    except OSError as exc:
        raise FoundryInventoryUnavailableError("Foundry project root is unavailable") from exc
    except ValueError as exc:
        raise FoundryInventoryInvalidError("Foundry project root escapes the workspace") from exc
    if not resolved.is_dir():
        raise FoundryInventoryInvalidError("Foundry project root is not a directory")
    return resolved


def _generated_root(backend: ScannerIsolationBackend, private_dir: Path) -> Path:
    provider = getattr(backend, "writable_path", None)
    try:
        root = provider(private_dir) if callable(provider) else private_dir
        resolved = Path(root).resolve(strict=True)
        resolved.relative_to(private_dir)
    except (OSError, TypeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            "isolation backend returned an invalid writable path"
        ) from exc
    if resolved.is_symlink() or not resolved.is_dir():
        raise FoundryInventoryInvalidError("isolation writable path is not a regular directory")
    return resolved


def _runtime_solc_path(
    *,
    backend: ScannerIsolationBackend,
    copied_solc: Path,
    generated_root: Path,
    expected_sha256: str,
) -> Path:
    if generated_root == copied_solc.parent.parent:
        return copied_solc
    provider = getattr(backend, "writable_path", None)
    if not callable(provider):
        return copied_solc
    runtime_solc = generated_root / "toolchain" / "solc"
    try:
        runtime_solc.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if runtime_solc.exists():
            raise FoundryInventoryInvalidError(
                "runtime Solidity compiler destination already exists"
            )
        with copied_solc.open("rb") as source, runtime_solc.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                destination.write(chunk)
        runtime_solc.chmod(0o500)
    except FoundryInventoryRunnerError:
        raise
    except OSError as exc:
        raise FoundryInventoryUnavailableError(
            "could not stage the pinned Solidity compiler for isolation"
        ) from exc
    if _sha256_file(runtime_solc) != expected_sha256:
        raise FoundryInventoryInvalidError("staged Solidity compiler differs from its trust pin")
    return runtime_solc


def _inventory_environment(
    backend: ScannerIsolationBackend,
    private_dir: Path,
) -> dict[str, str]:
    fallback = sanitized_scanner_environment(private_dir)
    try:
        supplied = isolation_host_environment(backend, private_dir, fallback)
    except (OSError, TypeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            "isolation backend returned an invalid host environment"
        ) from exc
    environment = {
        name: value for name, value in supplied.items() if name in _HOST_ENVIRONMENT_ALLOWLIST
    }
    environment.update(
        {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "FOUNDRY_FFI": "false",
            "FOUNDRY_FS_PERMISSIONS": "[]",
            "FOUNDRY_NO_STORAGE_CACHING": "true",
            "FOUNDRY_PROFILE": "default",
        }
    )
    return environment


def _execute_project_inventory(
    *,
    workspace: Path,
    private_dir: Path,
    artifact_root: Path,
    phase_root: Path,
    project: SolidityProjectMetadata,
    output_index: int,
    forge_executable: Path,
    copied_solc: Path,
    backend: ScannerIsolationBackend,
    environment: Mapping[str, str],
    timeout_seconds: float,
    bounds: FoundryInventoryRunLimits,
    remaining_total_output_bytes: int,
) -> _ProjectExecution:
    if not 0 < remaining_total_output_bytes <= bounds.max_combined_output_bytes:
        raise FoundryInventoryInvalidError("Foundry inventory remaining output ceiling is invalid")
    project_root = project.project_root
    project_path = _project_path(workspace, project_root)
    execution_dir = phase_root / f"{output_index:05d}"
    try:
        execution_dir.mkdir(mode=0o700, exist_ok=False)
        build_info_path = execution_dir / "build-info"
        cache_path = execution_dir / "cache"
        output_path = execution_dir / "out"
        for path in (build_info_path, cache_path, output_path):
            path.mkdir(mode=0o700)
    except OSError as exc:
        raise FoundryInventoryUnavailableError(
            "could not create private Foundry inventory directories"
        ) from exc
    stdout_path = execution_dir / "stdout.json"
    stderr_path = execution_dir / "stderr.txt"
    command = [
        str(forge_executable),
        "test",
        "--list",
        "--json",
        "--ast",
        "--build-info",
        "--build-info-path",
        str(build_info_path),
        "--force",
        "--offline",
        "--no-auto-detect",
        "--use",
        str(copied_solc),
        "--cache-path",
        str(cache_path),
        "--out",
        str(output_path),
        "--threads",
        "1",
        "--no-storage-caching",
    ]
    display_command = list(command)
    display_command[0] = "forge"
    display_command[display_command.index(str(build_info_path))] = "[PRIVATE_BUILD_INFO_PATH]"
    display_command[display_command.index(str(copied_solc))] = "[PINNED_SOLC]"
    display_command[display_command.index(str(cache_path))] = "[PRIVATE_CACHE_PATH]"
    display_command[display_command.index(str(output_path))] = "[PRIVATE_OUTPUT_PATH]"
    command_sha256 = _canonical_sha256(display_command)
    try:
        no_network_wrapper = getattr(backend, "wrap_without_network", None)
        wrapped = (
            no_network_wrapper(
                command,
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=_INVENTORY_RPC_SENTINEL_PORT,
            )
            if callable(no_network_wrapper)
            else backend.wrap(
                command,
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=_INVENTORY_RPC_SENTINEL_PORT,
            )
        )
        _validate_wrapped_command(wrapped)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            f"Foundry inventory isolation setup failed: {type(exc).__name__}"
        ) from exc

    timed_out = False
    overflowed = False
    overflow_error = "Foundry inventory process exceeded an output or artifact ceiling"
    process: subprocess.Popen[bytes] | None = None
    return_code: int | None = None
    process_error: OSError | subprocess.SubprocessError | None = None
    validation_error: FoundryInventoryRunnerError | None = None
    generated_usage = _GeneratedUsage(entries=0, files=0, bytes=0)
    try:
        with stdout_path.open("xb") as stdout_handle, stderr_path.open("xb") as stderr_handle:
            process = subprocess.Popen(
                wrapped,
                cwd=project_path,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=dict(environment),
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=(
                    int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                    if os.name == "nt"
                    else 0
                ),
                preexec_fn=_limit_inventory_process if os.name != "nt" else None,
            )
            deadline = time.monotonic() + timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    _stop_process(process)
                    break
                try:
                    stdout_bytes = stdout_path.stat().st_size
                    stderr_bytes = stderr_path.stat().st_size
                    if (
                        stdout_bytes > bounds.max_stdout_bytes_per_project
                        or stderr_bytes > bounds.max_stderr_bytes_per_project
                    ):
                        overflowed = True
                        overflow_error = (
                            "Foundry inventory process exceeded a stream output ceiling"
                        )
                        _stop_process(process)
                        break
                    generated_usage = _generated_usage(
                        (build_info_path, cache_path, output_path),
                        bounds,
                        trusted_root=artifact_root,
                        purpose=_GeneratedTraversalPurpose.LIVE_LIMIT_MONITOR,
                    )
                    if (
                        stdout_bytes + stderr_bytes + generated_usage.bytes
                        > remaining_total_output_bytes
                    ):
                        overflowed = True
                        overflow_error = (
                            "Foundry inventory process exceeded its combined output ceiling"
                        )
                        _stop_process(process)
                        break
                except FoundryInventoryRunnerError as exc:
                    validation_error = exc
                    _stop_process(process)
                    break
                except OSError:
                    validation_error = FoundryInventoryInvalidError(
                        "Foundry inventory streams could not be inspected"
                    )
                    _stop_process(process)
                    break
                time.sleep(_POLL_INTERVAL_SECONDS)
            return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            _stop_process(process)
            return_code = process.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        process_error = exc
        if process is not None:
            _stop_process(process)
    cleanup_error: Exception | None = None
    try:
        cleanup_isolation_backend(backend, private_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        cleanup_error = exc
    if cleanup_error is not None:
        raise FoundryInventoryInvalidError(
            f"Foundry inventory isolation cleanup failed: {type(cleanup_error).__name__}"
        ) from cleanup_error
    if process_error is not None:
        raise FoundryInventoryUnavailableError(
            f"Foundry inventory process was unavailable: {type(process_error).__name__}"
        ) from process_error
    if validation_error is not None:
        raise validation_error
    if timed_out:
        raise FoundryInventoryTimeoutError("Foundry inventory process exceeded its deadline")
    if overflowed:
        raise FoundryInventoryOverflowError(overflow_error)
    if return_code != 0:
        raise FoundryInventoryInvalidError(
            f"Foundry inventory process exited with code {return_code}"
        )
    stdout = _read_bounded_file_beneath(
        stdout_path,
        trusted_root=artifact_root,
        maximum_bytes=bounds.max_stdout_bytes_per_project,
        allow_empty=False,
        label="Foundry inventory stdout",
    )
    stderr = _read_bounded_file_beneath(
        stderr_path,
        trusted_root=artifact_root,
        maximum_bytes=bounds.max_stderr_bytes_per_project,
        allow_empty=True,
        label="Foundry inventory stderr",
    )
    generated_usage = _generated_usage(
        (build_info_path, cache_path, output_path),
        bounds,
        trusted_root=artifact_root,
    )
    if len(stdout) + len(stderr) + generated_usage.bytes > remaining_total_output_bytes:
        raise FoundryInventoryOverflowError(
            "Foundry inventory process exceeded its combined output ceiling"
        )
    build_info = _read_build_info_artifacts(
        build_info_path,
        bounds,
        trusted_root=artifact_root,
    )
    return _ProjectExecution(
        project_root=project_root,
        command_sha256=command_sha256,
        stdout=stdout,
        stderr=stderr,
        build_info=build_info,
        generated_bytes=generated_usage.bytes,
    )


def _generated_usage(
    roots: Sequence[Path],
    bounds: FoundryInventoryRunLimits,
    *,
    trusted_root: Path | None = None,
    purpose: _GeneratedTraversalPurpose = _GeneratedTraversalPurpose.STRICT_SNAPSHOT,
) -> _GeneratedUsage:
    if not isinstance(purpose, _GeneratedTraversalPurpose):
        raise FoundryInventoryInvalidError("Foundry generated traversal purpose is invalid")
    require_stable_snapshot = purpose is _GeneratedTraversalPurpose.STRICT_SNAPSHOT
    usage = _GeneratedUsageAccumulator()
    for root in roots:
        try:
            root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FoundryInventoryInvalidError(
                "Foundry inventory generated path could not be inspected"
            ) from exc

        chain: _RetainedDirectoryChain | None = None
        provisional = _GeneratedUsageAccumulator(
            entries=usage.entries,
            files=usage.files,
            bytes=usage.bytes,
        )
        try:
            chain = _open_directory_beneath(
                trusted_root or root,
                root,
                label="Foundry inventory generated root",
                require_stable_snapshot=require_stable_snapshot,
            )
            _accumulate_generated_directory_usage(
                chain.descriptor,
                bounds=bounds,
                usage=provisional,
                depth=0,
                purpose=purpose,
            )
            _validate_directory_chain(
                chain,
                label="Foundry inventory generated root",
                require_stable_snapshot=require_stable_snapshot,
            )
        except _LiveGeneratedTreeMutation:
            continue
        else:
            usage = provisional
        finally:
            if chain is not None:
                _close_directory_chain(
                    chain,
                    validate=False,
                    label="Foundry inventory generated root",
                )

    return _GeneratedUsage(entries=usage.entries, files=usage.files, bytes=usage.bytes)


def _accumulate_generated_directory_usage(
    descriptor: int,
    *,
    bounds: FoundryInventoryRunLimits,
    usage: _GeneratedUsageAccumulator,
    depth: int,
    purpose: _GeneratedTraversalPurpose,
) -> None:
    require_stable_snapshot = purpose is _GeneratedTraversalPurpose.STRICT_SNAPSHOT
    if depth > _MAX_GENERATED_DIRECTORY_DEPTH:
        raise FoundryInventoryOverflowError(
            "Foundry inventory generated directory depth exceeded its ceiling"
        )
    for name in _directory_entry_names(
        descriptor,
        label="Foundry inventory generated directory",
    ):
        usage.entries += 1
        if usage.entries > bounds.max_generated_entries_per_project:
            raise FoundryInventoryOverflowError(
                "Foundry inventory generated entries exceeded their ceiling"
            )
        try:
            metadata = _directory_entry_metadata(
                descriptor,
                name,
                label="Foundry inventory generated entry",
            )
        except FoundryInventoryInvalidError as exc:
            if not require_stable_snapshot and _caused_by_file_not_found(exc):
                raise _LiveGeneratedTreeMutation from exc
            raise
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor, opened = _open_directory_at(
                descriptor,
                name,
                expected=metadata,
                label="Foundry inventory generated directory",
                require_stable_snapshot=require_stable_snapshot,
            )
            try:
                _accumulate_generated_directory_usage(
                    child_descriptor,
                    bounds=bounds,
                    usage=usage,
                    depth=depth + 1,
                    purpose=purpose,
                )
                _revalidate_directory_at(
                    descriptor,
                    name,
                    child_descriptor,
                    expected=opened,
                    label="Foundry inventory generated directory",
                    require_stable_snapshot=require_stable_snapshot,
                )
            finally:
                _close_descriptor(
                    child_descriptor,
                    label="Foundry inventory generated directory",
                )
            continue
        file_bytes = _inspect_regular_file_at(
            descriptor,
            name,
            expected=metadata,
            label="Foundry inventory generated entry",
            require_stable_snapshot=require_stable_snapshot,
        )
        usage.files += 1
        if file_bytes > bounds.max_generated_file_bytes:
            raise FoundryInventoryOverflowError(
                "Foundry inventory generated file exceeded its byte ceiling"
            )
        usage.bytes += file_bytes
        if usage.bytes > bounds.max_generated_bytes_per_project:
            raise FoundryInventoryOverflowError(
                "Foundry inventory generated files exceeded their byte ceiling"
            )


def _read_build_info_artifacts(
    build_info_path: Path,
    bounds: FoundryInventoryRunLimits,
    *,
    trusted_root: Path | None = None,
) -> tuple[tuple[str, bytes], ...]:
    chain = _open_directory_beneath(
        trusted_root or build_info_path,
        build_info_path,
        label="Foundry build-info directory",
    )
    descriptor = chain.descriptor
    try:
        names = _directory_entry_names(
            descriptor,
            label="Foundry build-info directory",
        )
        if not names:
            raise FoundryInventoryInvalidError("Foundry build-info inventory is empty")
        if len(names) > bounds.max_generated_entries_per_project:
            raise FoundryInventoryOverflowError(
                "Foundry build-info artifacts exceeded their entry ceiling"
            )
        artifacts: list[tuple[str, bytes]] = []
        total_bytes = 0
        for name in names:
            if Path(name).suffix != ".json":
                raise FoundryInventoryInvalidError("Foundry build-info artifact is invalid")
            metadata = _directory_entry_metadata(
                descriptor,
                name,
                label="Foundry build-info artifact",
            )
            raw = _read_bounded_file_at(
                descriptor,
                name,
                expected=metadata,
                maximum_bytes=bounds.max_generated_file_bytes,
                allow_empty=False,
                label="Foundry build-info artifact",
            )
            total_bytes += len(raw)
            if total_bytes > bounds.max_generated_bytes_per_project:
                raise FoundryInventoryOverflowError(
                    "Foundry build-info artifacts exceeded their byte ceiling"
                )
            artifacts.append((name, raw))
        _validate_directory_chain(
            chain,
            label="Foundry build-info directory",
        )
        return tuple(artifacts)
    finally:
        _close_directory_chain(
            chain,
            validate=False,
            label="Foundry build-info directory",
        )


def _directory_open_flags(*, label: str) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        not isinstance(no_follow, int)
        or no_follow == 0
        or not isinstance(directory, int)
        or directory == 0
        or not _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED
        or not _DESCRIPTOR_RELATIVE_STAT_SUPPORTED
        or not _DESCRIPTOR_SCANDIR_SUPPORTED
    ):
        raise FoundryInventoryUnavailableError(
            f"{label} cannot be traversed safely because descriptor-relative "
            "no-follow directory access is unavailable"
        )
    return os.O_RDONLY | no_follow | directory | int(getattr(os, "O_CLOEXEC", 0))


def _open_directory_path(
    path: Path,
    *,
    label: str,
    require_stable_snapshot: bool,
) -> tuple[int, os.stat_result]:
    descriptor: int | None = None
    try:
        named_before = path.lstat()
        if (
            not stat.S_ISDIR(named_before.st_mode)
            or stat.S_ISLNK(named_before.st_mode)
            or path.is_junction()
        ):
            raise FoundryInventoryInvalidError(f"{label} is not a non-link directory")
        descriptor = os.open(path, _directory_open_flags(label=label))
        os.set_inheritable(descriptor, False)
        opened = os.fstat(descriptor)
        named_after = path.lstat()
        unsafe_type = (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named_after.st_mode)
            or stat.S_ISLNK(named_after.st_mode)
        )
        identity_changed = _file_identity(named_before) != _file_identity(opened) or _file_identity(
            opened
        ) != _file_identity(named_after)
        snapshot_changed = _file_snapshot(named_before) != _file_snapshot(opened) or _file_snapshot(
            opened
        ) != _file_snapshot(named_after)
        if not require_stable_snapshot and not unsafe_type and identity_changed:
            raise _LiveGeneratedTreeMutation
        if unsafe_type or identity_changed or (require_stable_snapshot and snapshot_changed):
            raise FoundryInventoryInvalidError(f"{label} changed while it was opened")
        return descriptor, opened
    except _LiveGeneratedTreeMutation:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise
    except FoundryInventoryRunnerError:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise
    except FileNotFoundError as exc:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        if not require_stable_snapshot:
            raise _LiveGeneratedTreeMutation from exc
        raise FoundryInventoryInvalidError(f"{label} could not be opened safely") from exc
    except OSError as exc:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise FoundryInventoryInvalidError(f"{label} could not be opened safely") from exc


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    expected: os.stat_result,
    label: str,
    require_stable_snapshot: bool,
) -> tuple[int, os.stat_result]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            _directory_open_flags(label=label),
            dir_fd=parent_descriptor,
        )
        os.set_inheritable(descriptor, False)
        opened = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        unsafe_type = (
            not stat.S_ISDIR(expected.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named_after.st_mode)
            or stat.S_ISLNK(named_after.st_mode)
        )
        identity_changed = _file_identity(expected) != _file_identity(opened) or _file_identity(
            opened
        ) != _file_identity(named_after)
        snapshot_changed = _file_snapshot(expected) != _file_snapshot(opened) or _file_snapshot(
            opened
        ) != _file_snapshot(named_after)
        if not require_stable_snapshot and not unsafe_type and identity_changed:
            raise _LiveGeneratedTreeMutation
        if unsafe_type or identity_changed or (require_stable_snapshot and snapshot_changed):
            raise FoundryInventoryInvalidError(f"{label} changed while it was opened")
        return descriptor, opened
    except _LiveGeneratedTreeMutation:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise
    except FoundryInventoryRunnerError:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise
    except FileNotFoundError as exc:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        if not require_stable_snapshot:
            raise _LiveGeneratedTreeMutation from exc
        raise FoundryInventoryInvalidError(f"{label} could not be opened safely") from exc
    except OSError as exc:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
        raise FoundryInventoryInvalidError(f"{label} could not be opened safely") from exc


def _open_directory_beneath(
    trusted_root: Path,
    target: Path,
    *,
    label: str,
    require_stable_snapshot: bool = True,
) -> _RetainedDirectoryChain:
    """Retain every no-follow directory descriptor from a trusted root to target."""

    trusted_path = Path(os.path.abspath(trusted_root))
    target_path = Path(os.path.abspath(target))
    try:
        relative = target_path.relative_to(trusted_path)
    except ValueError as exc:
        raise FoundryInventoryInvalidError(f"{label} lies outside its trusted root") from exc
    if any(part in {"", ".", ".."} or "/" in part or "\x00" in part for part in relative.parts):
        raise FoundryInventoryInvalidError(f"{label} has an invalid relative path")

    trusted_descriptor, trusted_opened = _open_directory_path(
        trusted_path,
        label=f"{label} trusted root",
        require_stable_snapshot=require_stable_snapshot,
    )
    chain = _RetainedDirectoryChain(
        trusted_path=trusted_path,
        descriptors=[trusted_descriptor],
        opened=[trusted_opened],
        names=[],
    )
    try:
        for part in relative.parts:
            parent = chain.descriptors[-1]
            try:
                metadata = _directory_entry_metadata(
                    parent,
                    part,
                    label=label,
                )
            except FoundryInventoryInvalidError as exc:
                if not require_stable_snapshot and _caused_by_file_not_found(exc):
                    raise _LiveGeneratedTreeMutation from exc
                raise
            descriptor, opened = _open_directory_at(
                parent,
                part,
                expected=metadata,
                label=label,
                require_stable_snapshot=require_stable_snapshot,
            )
            chain.names.append(part)
            chain.descriptors.append(descriptor)
            chain.opened.append(opened)
        return chain
    except BaseException:
        _close_directory_chain(chain, validate=False, label=label)
        raise


def _validate_directory_chain(
    chain: _RetainedDirectoryChain,
    *,
    label: str,
    require_stable_snapshot: bool = True,
) -> None:
    _revalidate_directory_path(
        chain.trusted_path,
        chain.descriptors[0],
        expected=chain.opened[0],
        label=f"{label} trusted root",
        require_stable_snapshot=require_stable_snapshot,
    )
    for index, name in enumerate(chain.names, start=1):
        _revalidate_directory_at(
            chain.descriptors[index - 1],
            name,
            chain.descriptors[index],
            expected=chain.opened[index],
            label=label,
            require_stable_snapshot=require_stable_snapshot,
        )


def _close_directory_chain(
    chain: _RetainedDirectoryChain,
    *,
    validate: bool,
    label: str,
) -> None:
    pending_error: BaseException | None = None
    if validate:
        try:
            _validate_directory_chain(chain, label=label)
        except BaseException as exc:
            pending_error = exc
    for descriptor in reversed(chain.descriptors):
        try:
            _close_descriptor(descriptor, label=label)
        except BaseException as exc:
            if pending_error is None:
                pending_error = exc
    if pending_error is not None:
        raise pending_error


def _directory_entry_names(descriptor: int, *, label: str) -> tuple[str, ...]:
    try:
        with os.scandir(descriptor) as iterator:
            names = tuple(sorted(entry.name for entry in iterator))
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be read") from exc
    if any(not name or name in {".", ".."} or "/" in name or "\x00" in name for name in names):
        raise FoundryInventoryInvalidError(f"{label} contains an invalid entry name")
    return names


def _directory_entry_metadata(
    descriptor: int,
    name: str,
    *,
    label: str,
) -> os.stat_result:
    try:
        return os.stat(
            name,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be inspected") from exc


def _revalidate_directory_path(
    path: Path,
    descriptor: int,
    *,
    expected: os.stat_result,
    label: str,
    require_stable_snapshot: bool,
) -> None:
    try:
        opened_after = os.fstat(descriptor)
        named_after = path.lstat()
    except FileNotFoundError as exc:
        if not require_stable_snapshot:
            raise _LiveGeneratedTreeMutation from exc
        raise FoundryInventoryInvalidError(f"{label} could not be revalidated") from exc
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be revalidated") from exc
    unsafe_type = (
        not stat.S_ISDIR(opened_after.st_mode)
        or not stat.S_ISDIR(named_after.st_mode)
        or stat.S_ISLNK(named_after.st_mode)
    )
    identity_changed = _file_identity(expected) != _file_identity(opened_after) or _file_identity(
        opened_after
    ) != _file_identity(named_after)
    snapshot_changed = _file_snapshot(expected) != _file_snapshot(opened_after) or _file_snapshot(
        opened_after
    ) != _file_snapshot(named_after)
    if not require_stable_snapshot and not unsafe_type and identity_changed:
        raise _LiveGeneratedTreeMutation
    if unsafe_type or identity_changed or (require_stable_snapshot and snapshot_changed):
        raise FoundryInventoryInvalidError(f"{label} changed during traversal")


def _revalidate_directory_at(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    *,
    expected: os.stat_result,
    label: str,
    require_stable_snapshot: bool,
) -> None:
    try:
        opened_after = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        if not require_stable_snapshot:
            raise _LiveGeneratedTreeMutation from exc
        raise FoundryInventoryInvalidError(f"{label} could not be revalidated") from exc
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be revalidated") from exc
    unsafe_type = (
        not stat.S_ISDIR(opened_after.st_mode)
        or not stat.S_ISDIR(named_after.st_mode)
        or stat.S_ISLNK(named_after.st_mode)
    )
    identity_changed = _file_identity(expected) != _file_identity(opened_after) or _file_identity(
        opened_after
    ) != _file_identity(named_after)
    snapshot_changed = _file_snapshot(expected) != _file_snapshot(opened_after) or _file_snapshot(
        opened_after
    ) != _file_snapshot(named_after)
    if not require_stable_snapshot and not unsafe_type and identity_changed:
        raise _LiveGeneratedTreeMutation
    if unsafe_type or identity_changed or (require_stable_snapshot and snapshot_changed):
        raise FoundryInventoryInvalidError(f"{label} changed during traversal")


def _inspect_regular_file_at(
    parent_descriptor: int,
    name: str,
    *,
    expected: os.stat_result,
    label: str,
    require_stable_snapshot: bool,
) -> int:
    if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
        raise FoundryInventoryInvalidError(f"{label} is not a unique regular file")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0 or not _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED:
        raise FoundryInventoryUnavailableError(
            f"{label} cannot be inspected safely because descriptor-relative "
            "no-follow access is unavailable"
        )
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | no_follow | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_BINARY", 0))
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        os.set_inheritable(descriptor, False)
        opened_before = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened_after = os.fstat(descriptor)
        observed = (expected, opened_before, opened_after, named_after)
        unsafe_type = any(
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 for metadata in observed
        )
        identity_changed = len({_file_identity(metadata) for metadata in observed}) != 1
        snapshot_changed = len({_file_snapshot(metadata) for metadata in observed}) != 1
        if not require_stable_snapshot and not unsafe_type and identity_changed:
            raise _LiveGeneratedTreeMutation
        if unsafe_type or identity_changed or (require_stable_snapshot and snapshot_changed):
            raise FoundryInventoryInvalidError(f"{label} is not a unique regular file")
        return max(metadata.st_size for metadata in observed)
    except _LiveGeneratedTreeMutation:
        raise
    except FoundryInventoryRunnerError:
        raise
    except FileNotFoundError as exc:
        if not require_stable_snapshot:
            raise _LiveGeneratedTreeMutation from exc
        raise FoundryInventoryInvalidError(f"{label} is not a unique regular file") from exc
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} is not a unique regular file") from exc
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)


def _read_bounded_file_beneath(
    path: Path,
    *,
    trusted_root: Path,
    maximum_bytes: int,
    allow_empty: bool,
    label: str,
) -> bytes:
    chain = _open_directory_beneath(
        trusted_root,
        path.parent,
        label=f"{label} parent directory",
    )
    try:
        metadata = _directory_entry_metadata(
            chain.descriptor,
            path.name,
            label=label,
        )
        raw = _read_bounded_file_at(
            chain.descriptor,
            path.name,
            expected=metadata,
            maximum_bytes=maximum_bytes,
            allow_empty=allow_empty,
            label=label,
        )
        _validate_directory_chain(
            chain,
            label=f"{label} parent directory",
        )
        return raw
    finally:
        _close_directory_chain(
            chain,
            validate=False,
            label=f"{label} parent directory",
        )


def _read_bounded_file_at(
    parent_descriptor: int,
    name: str,
    *,
    expected: os.stat_result,
    maximum_bytes: int,
    allow_empty: bool,
    label: str,
) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0 or not _DESCRIPTOR_RELATIVE_OPEN_SUPPORTED:
        raise FoundryInventoryUnavailableError(
            f"{label} cannot be read safely because descriptor-relative "
            "no-follow access is unavailable"
        )
    flags = os.O_RDONLY | no_follow | int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_BINARY", 0))
    descriptor: int | None = None
    try:
        named_before = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(expected.st_mode)
            or expected.st_nlink != 1
            or _file_snapshot(expected) != _file_snapshot(named_before)
        ):
            raise FoundryInventoryInvalidError(f"{label} changed before it was read")
        if named_before.st_size > maximum_bytes:
            raise FoundryInventoryOverflowError(f"{label} exceeded its byte ceiling")
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        os.set_inheritable(descriptor, False)
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _file_identity(named_before) != _file_identity(opened_before)
        ):
            raise FoundryInventoryInvalidError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes - consumed + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise FoundryInventoryOverflowError(f"{label} exceeded its byte ceiling")
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        named_after = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FoundryInventoryRunnerError:
        raise
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be read") from exc
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor, label=label)
    if (
        _file_snapshot(opened_before) != _file_snapshot(opened_after)
        or _file_identity(opened_before) != _file_identity(named_after)
        or not stat.S_ISREG(named_after.st_mode)
        or named_after.st_nlink != 1
        or len(raw) != opened_before.st_size
    ):
        raise FoundryInventoryInvalidError(f"{label} changed while it was read")
    if not allow_empty and not raw:
        raise FoundryInventoryInvalidError(f"{label} is empty")
    return raw


def _close_descriptor(descriptor: int, *, label: str) -> None:
    try:
        os.close(descriptor)
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} descriptor could not be closed") from exc


def _normalize_build_info_json(
    raw: bytes,
    *,
    project_path: Path,
    project_root: str,
    maximum_bytes: int,
) -> bytes:
    """Canonicalize only volatile Forge build-info identity and private paths."""

    if not raw or len(raw) > maximum_bytes:
        raise FoundryInventoryOverflowError(
            "Foundry build-info normalization input exceeded its byte ceiling"
        )
    normalized_project_root = _normalized_project_root(project_root)
    try:
        resolved_project = project_path.resolve(strict=True)
    except OSError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry build-info project root is unavailable"
        ) from exc
    if project_path.is_symlink() or project_path.is_junction() or not resolved_project.is_dir():
        raise FoundryInventoryInvalidError(
            "Foundry build-info project root is not a regular directory"
        )
    payload = _strict_json_object(raw, label="Foundry build-info")
    build_id = payload.get("id")
    if (
        not isinstance(build_id, str)
        or not 16 <= len(build_id) <= 64
        or any(character not in "0123456789abcdef" for character in build_id)
    ):
        raise FoundryInventoryInvalidError("Foundry build-info identifier is invalid")
    compiler_input = payload.get("input")
    if not isinstance(compiler_input, dict):
        raise FoundryInventoryInvalidError("Foundry build-info input is missing")
    payload["id"] = _NORMALIZED_BUILD_INFO_ID

    base_path = compiler_input.get("basePath")
    if "basePath" in compiler_input:
        if not isinstance(base_path, str):
            raise FoundryInventoryInvalidError("Foundry build-info input.basePath is not a string")
        compiler_input["basePath"] = _normalize_build_info_path(
            base_path,
            project_path=resolved_project,
            project_root=normalized_project_root,
            require_project_root=True,
        )
    for field_name in ("allowPaths", "includePaths"):
        raw_paths = compiler_input.get(field_name)
        if field_name not in compiler_input:
            continue
        if not isinstance(raw_paths, list):
            raise FoundryInventoryInvalidError(
                f"Foundry build-info input.{field_name} is not an array"
            )
        normalized_paths: list[str] = []
        for raw_path in raw_paths:
            if not isinstance(raw_path, str):
                raise FoundryInventoryInvalidError(
                    f"Foundry build-info input.{field_name} contains a non-string entry"
                )
            normalized_paths.append(
                _normalize_build_info_path(
                    raw_path,
                    project_path=resolved_project,
                    project_root=normalized_project_root,
                    require_project_root=False,
                )
            )
        if len(normalized_paths) != len(set(normalized_paths)):
            raise FoundryInventoryInvalidError(
                f"Foundry build-info input.{field_name} contains duplicate normalized paths"
            )
        # Preserve compiler search-path precedence; only the private root
        # prefix is normalized. Reordering include paths could conceal a
        # semantically different import-resolution policy.
        compiler_input[field_name] = normalized_paths
    try:
        normalized_bytes = _canonical_json_bytes(payload)
    except (UnicodeEncodeError, ValueError) as exc:
        raise FoundryInventoryInvalidError(
            "Foundry build-info could not be canonically serialized"
        ) from exc
    if len(normalized_bytes) > maximum_bytes:
        raise FoundryInventoryOverflowError(
            "normalized Foundry build-info exceeded its byte ceiling"
        )
    return normalized_bytes


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FoundryInventoryInvalidError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> object:
        raise FoundryInventoryInvalidError(f"{label} contains a non-finite JSON number: {value}")

    try:
        text = raw.decode("utf-8")
        payload: object = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except FoundryInventoryRunnerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FoundryInventoryInvalidError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise FoundryInventoryInvalidError(f"{label} root is not an object")
    return payload


def _normalize_build_info_path(
    value: str,
    *,
    project_path: Path,
    project_root: str,
    require_project_root: bool,
) -> str:
    if (
        not value
        or value != value.strip()
        or len(value.encode("utf-8", errors="surrogatepass")) > 4_096
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(
            ord(character) == 127 or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            for character in value
        )
    ):
        raise FoundryInventoryInvalidError("Foundry build-info path is malformed")
    raw_path = Path(value)
    if raw_path.is_absolute():
        candidate = raw_path
    else:
        try:
            normalized = normalize_relative_path(value)
        except ValueError as exc:
            raise FoundryInventoryInvalidError("Foundry build-info path is unsafe") from exc
        if normalized in {"", "."}:
            candidate = project_path
        else:
            candidate = project_path.joinpath(*PurePosixPath(normalized).parts)
    try:
        resolved = candidate.resolve(strict=require_project_root)
        relative = resolved.relative_to(project_path)
    except OSError as exc:
        raise FoundryInventoryInvalidError("Foundry build-info path is unavailable") from exc
    except ValueError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry build-info path escapes its project root"
        ) from exc
    if require_project_root and resolved != project_path:
        raise FoundryInventoryInvalidError(
            "Foundry build-info basePath differs from its project root"
        )
    if require_project_root and (
        candidate.is_symlink() or candidate.is_junction() or not resolved.is_dir()
    ):
        raise FoundryInventoryInvalidError(
            "Foundry build-info basePath is not a non-link directory"
        )
    if not require_project_root and (candidate.is_symlink() or candidate.is_junction()):
        raise FoundryInventoryInvalidError(
            "Foundry build-info include or allow path is not a non-link directory"
        )
    if not require_project_root and candidate.exists() and not candidate.is_dir():
        raise FoundryInventoryInvalidError(
            "Foundry build-info include or allow path is not a directory"
        )
    relative_text = relative.as_posix()
    if relative_text == ".":
        return project_root
    repository_relative = (
        relative_text if project_root == "." else f"{project_root}/{relative_text}"
    )
    try:
        if normalize_relative_path(repository_relative) != repository_relative:
            raise ValueError("normalized path changed")
    except ValueError as exc:
        raise FoundryInventoryInvalidError(
            "Foundry build-info path is not canonical repository-relative POSIX"
        ) from exc
    return repository_relative


def _read_bound_sources(
    project_path: Path,
    build_info_payloads: Sequence[bytes],
    limits: FoundryInventoryLimits,
) -> tuple[FoundrySourceInput, ...]:
    source_paths: set[str] = set()
    for index, raw in enumerate(build_info_payloads):
        if len(raw) > limits.max_build_info_json_bytes:
            raise FoundryInventoryOverflowError("Foundry build-info exceeded its parser ceiling")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FoundryInventoryInvalidError(
                f"Foundry build-info {index} is not valid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise FoundryInventoryInvalidError("Foundry build-info root is not an object")
        compiler_input = payload.get("input")
        if not isinstance(compiler_input, dict):
            raise FoundryInventoryInvalidError("Foundry build-info input is missing")
        sources = compiler_input.get("sources")
        if not isinstance(sources, dict) or not sources:
            raise FoundryInventoryInvalidError("Foundry build-info source inventory is empty")
        for raw_path in sources:
            if not isinstance(raw_path, str):
                raise FoundryInventoryInvalidError("Foundry compiler source path is not text")
            try:
                normalized = normalize_relative_path(raw_path)
            except ValueError as exc:
                raise FoundryInventoryInvalidError(
                    "Foundry compiler source path is unsafe"
                ) from exc
            if normalized != raw_path or normalized in {"", "."}:
                raise FoundryInventoryInvalidError("Foundry compiler source path is not canonical")
            if is_sensitive_workspace_path(normalized):
                raise FoundryInventoryInvalidError(
                    "Foundry compiler source path is permanently excluded"
                )
            source_paths.add(normalized)
            if len(source_paths) > limits.max_sources:
                raise FoundryInventoryOverflowError(
                    "Foundry compiler sources exceeded their file ceiling"
                )
    result: list[FoundrySourceInput] = []
    total_bytes = 0
    for source_path in sorted(source_paths):
        candidate = project_path.joinpath(*PurePosixPath(source_path).parts)
        cursor = project_path
        for part in PurePosixPath(source_path).parts:
            cursor /= part
            if cursor.is_symlink() or cursor.is_junction():
                raise FoundryInventoryInvalidError("Foundry compiler source path traverses a link")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(project_path)
            metadata = resolved.stat()
        except OSError as exc:
            raise FoundryInventoryInvalidError("Foundry compiler source is unavailable") from exc
        except ValueError as exc:
            raise FoundryInventoryInvalidError(
                "Foundry compiler source escapes its project root"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise FoundryInventoryInvalidError(
                "Foundry compiler source is not a unique regular file"
            )
        if metadata.st_size > limits.max_source_bytes:
            raise FoundryInventoryOverflowError("Foundry compiler source exceeded its byte ceiling")
        total_bytes += metadata.st_size
        if total_bytes > limits.max_total_source_bytes:
            raise FoundryInventoryOverflowError(
                "Foundry compiler sources exceeded their total byte ceiling"
            )
        content = _read_bounded_file(
            resolved,
            maximum_bytes=limits.max_source_bytes,
            allow_empty=True,
            label="Foundry compiler source",
        )
        result.append(
            FoundrySourceInput(
                path=source_path,
                content=content,
                source_sha256=_sha256_bytes(content),
            )
        )
    return tuple(result)


def _inventory_record(
    project_root: str,
    declaration: FoundryTestDeclaration,
) -> RepositorySuiteInventoryRecord:
    return RepositorySuiteInventoryRecord.sealed(
        project_root=project_root,
        execution_path=_repository_path(project_root, declaration.execution_path),
        execution_suite_name=declaration.execution_suite_name,
        test_name=declaration.test_name,
        execution_signature=declaration.test_signature,
        execution_source_sha256=declaration.execution_source_sha256,
        execution_start_line=declaration.execution_start_line,
        execution_end_line=declaration.execution_end_line,
        execution_contract_ast_id=declaration.execution_contract_ast_id,
        declaration_path=_repository_path(project_root, declaration.declaration_path),
        declaration_suite_name=declaration.declaration_contract,
        declaration_signature=declaration.declaration_signature,
        declaration_source_sha256=declaration.source_sha256,
        declaration_start_line=declaration.start_line,
        declaration_end_line=declaration.end_line,
        declaration_contract_ast_id=declaration.declaration_contract_ast_id,
        declaration_function_ast_id=declaration.function_ast_id,
        build_info_sha256=declaration.build_info_sha256,
    )


def _repository_path(project_root: str, project_relative_path: str) -> str:
    return (
        project_relative_path if project_root == "." else f"{project_root}/{project_relative_path}"
    )


def _read_bounded_file(
    path: Path,
    *,
    maximum_bytes: int,
    allow_empty: bool,
    label: str,
) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow == 0:
        raise FoundryInventoryUnavailableError(
            f"{label} cannot be read safely because no no-follow open flag is available"
        )
    flags = os.O_RDONLY | no_follow
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_BINARY", 0))
    descriptor: int | None = None
    try:
        named_before = path.lstat()
        if (
            not stat.S_ISREG(named_before.st_mode)
            or named_before.st_nlink != 1
            or stat.S_ISLNK(named_before.st_mode)
            or path.is_junction()
        ):
            raise FoundryInventoryInvalidError(f"{label} is not a unique regular file")
        if named_before.st_size > maximum_bytes:
            raise FoundryInventoryOverflowError(f"{label} exceeded its byte ceiling")
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or _file_identity(named_before) != _file_identity(opened_before)
        ):
            raise FoundryInventoryInvalidError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes - consumed + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise FoundryInventoryOverflowError(f"{label} exceeded its byte ceiling")
        raw = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        named_after = path.lstat()
    except FoundryInventoryRunnerError:
        raise
    except OSError as exc:
        raise FoundryInventoryInvalidError(f"{label} could not be read") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as exc:
                raise FoundryInventoryInvalidError(
                    f"{label} descriptor could not be closed"
                ) from exc
    if (
        _file_snapshot(opened_before) != _file_snapshot(opened_after)
        or _file_identity(opened_before) != _file_identity(named_after)
        or not stat.S_ISREG(named_after.st_mode)
        or named_after.st_nlink != 1
        or len(raw) != opened_before.st_size
    ):
        raise FoundryInventoryInvalidError(f"{label} changed while it was read")
    if not allow_empty and not raw:
        raise FoundryInventoryInvalidError(f"{label} is empty")
    return raw


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _caused_by_file_not_found(error: BaseException) -> bool:
    current: BaseException | None = error
    observed: set[int] = set()
    while current is not None and id(current) not in observed:
        if isinstance(current, FileNotFoundError):
            return True
        observed.add(id(current))
        current = current.__cause__
    return False


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_wrapped_command(command: object) -> None:
    if (
        not isinstance(command, list)
        or not command
        or any(
            not isinstance(argument, str)
            or not argument
            or any(ord(character) < 32 or ord(character) == 127 for character in argument)
            for argument in command
        )
    ):
        raise ValueError("isolation wrapper returned an invalid command")


def _validate_hash(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FoundryInventoryInvalidError(f"{label} SHA-256 is invalid")


def _validate_text(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 1_000
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FoundryInventoryInvalidError(f"{label} is invalid")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise FoundryInventoryInvalidError("pinned executable could not be hashed") from exc
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _limit_inventory_process() -> None:
    try:
        import resource
    except ImportError as exc:
        raise RuntimeError("inventory resource limit setup failed") from exc

    limits = [
        (resource.RLIMIT_CPU, (900, 900)),
        (resource.RLIMIT_FSIZE, (250_000_000, 250_000_000)),
        (resource.RLIMIT_NOFILE, (256, 256)),
    ]
    # Darwin applies RLIMIT_NPROC to the whole login UID rather than this
    # isolated process tree. A low per-child limit can therefore prevent
    # Forge from spawning the pinned compiler when unrelated user
    # processes already exceed it. The sandbox boundary and the remaining
    # per-process limits still constrain this local inventory execution.
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_NPROC"):
        limits.append((resource.RLIMIT_NPROC, (64, 64)))
    # Darwin exposes RLIMIT_AS but rejects setrlimit for it.
    if sys.platform != "darwin" and hasattr(resource, "RLIMIT_AS"):
        limits.append((resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3)))

    failures = 0
    for resource_kind, value in limits:
        try:
            resource.setrlimit(resource_kind, value)
        except (OSError, ValueError):
            failures += 1
    if failures:
        raise RuntimeError(f"inventory resource limit setup failed for {failures} limit(s)")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
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
