"""Opt-in isolated Solidity compilation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.config import SmartContractsConfig
from mmaudit.isolation.container import (
    RepositoryJavaScriptIsolationBackend,
    cleanup_isolation_backend,
    isolation_host_environment,
)
from mmaudit.models.schemas import (
    CompilationStatus,
    RepositoryCodeExecutionState,
    SolidityCompilationResult,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.repository.workspace import validate_copyable_workspace
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.reproduction import (
    IsolationBackend,
    default_isolation_backend,
)

_OUTPUT_LIMIT = 50_000_000
_EXCLUDED_DYNAMIC_WORKSPACE_NAMES = frozenset(
    {
        ".git",
        ".mmaudit",
        "artifacts",
        "broadcast",
        "cache",
        "node_modules",
        "out",
    }
)


@dataclass(frozen=True)
class CompilationRun:
    results: list[SolidityCompilationResult]
    artifact_roots: list[Path]


def compile_solidity_projects(
    repository_root: Path,
    projects: list[SolidityProjectMetadata],
    config: SmartContractsConfig,
    private_dir: Path,
    *,
    backend: IsolationBackend | None = None,
    prepared_dependencies: Mapping[str, Path] | None = None,
    require_prepared_dependencies: bool = False,
    excluded_repository_paths: tuple[str, ...] = (),
) -> CompilationRun:
    """Compile supported projects in copied private workspaces when explicitly enabled."""

    if not projects:
        return CompilationRun(results=[], artifact_roots=[])
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not config.compile:
        return CompilationRun(
            results=[
                SolidityCompilationResult(
                    status=CompilationStatus.SKIPPED,
                    framework=project.project_type,
                    project_root=project.project_root,
                    command=project.build_command,
                    compiler_versions=project.compiler_versions,
                    warnings=["compilation disabled by configuration"],
                    repository_code_execution=(
                        RepositoryCodeExecutionState.DISABLED
                        if project.project_type is SolidityProjectType.HARDHAT
                        else RepositoryCodeExecutionState.NOT_APPLICABLE
                    ),
                )
                for project in projects
            ],
            artifact_roots=_existing_artifact_roots(repository_root, projects),
        )
    results: list[SolidityCompilationResult] = []
    artifact_roots: list[Path] = []
    resolved_backend = backend or default_isolation_backend("auto")
    for project in projects:
        compiled = _compile_one(
            repository_root,
            project,
            config,
            private_dir,
            resolved_backend,
            prepared_dependencies or {},
            require_prepared_dependencies,
            excluded_repository_paths,
        )
        results.append(compiled.result)
        artifact_roots.extend(compiled.artifact_roots)
    artifact_roots.extend(_existing_artifact_roots(repository_root, projects))
    return CompilationRun(results=results, artifact_roots=_unique_paths(artifact_roots))


@dataclass(frozen=True)
class _CompileOneResult:
    result: SolidityCompilationResult
    artifact_roots: list[Path]


def _compile_one(
    repository_root: Path,
    project: SolidityProjectMetadata,
    config: SmartContractsConfig,
    private_dir: Path,
    backend: IsolationBackend | None,
    prepared_dependencies: Mapping[str, Path],
    require_prepared_dependencies: bool,
    excluded_repository_paths: tuple[str, ...],
) -> _CompileOneResult:
    monotonic_start = time.monotonic()
    loads_repository_code = project.project_type is SolidityProjectType.HARDHAT
    isolation_backend = (str(getattr(backend, "name", "")) or None) if backend is not None else None
    repository_code_execution = (
        RepositoryCodeExecutionState.BLOCKED
        if loads_repository_code
        else RepositoryCodeExecutionState.NOT_APPLICABLE
    )
    if project.project_type is SolidityProjectType.PLAIN or not project.build_command:
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.SKIPPED,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                warnings=["plain Solidity project has no trusted build command"],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    if backend is None:
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.UNAVAILABLE,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[
                    "hardened compilation isolation is unavailable; target build was not executed"
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    if loads_repository_code and config.allow_network:
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.UNAVAILABLE,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[
                    "Hardhat repository code cannot receive network access during audit "
                    "execution; prepare pinned dependencies separately"
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    if loads_repository_code and not isinstance(
        backend,
        RepositoryJavaScriptIsolationBackend,
    ):
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.UNAVAILABLE,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[
                    "off-host repository-JavaScript isolation is unavailable; "
                    "Hardhat configuration and plugins were not executed"
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    prepared_dependency_root = (
        prepared_dependencies.get(project.project_root) if loads_repository_code else None
    )
    if loads_repository_code and require_prepared_dependencies and prepared_dependency_root is None:
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.UNAVAILABLE,
                framework=project.project_type,
                project_root=project.project_root,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[
                    "validated offline dependencies are unavailable; "
                    "Hardhat repository code was not executed"
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    executable_path: Path | None = None
    executable_sha256: str | None = None
    executable_name = project.build_command[0]
    if not loads_repository_code:
        executable = shutil.which(executable_name)
        if executable is None:
            return _CompileOneResult(
                result=SolidityCompilationResult(
                    status=CompilationStatus.UNAVAILABLE,
                    framework=project.project_type,
                    project_root=project.project_root,
                    command=project.build_command,
                    compiler_versions=project.compiler_versions,
                    duration_seconds=time.monotonic() - monotonic_start,
                    errors=[f"{executable_name} is not installed"],
                    isolation_backend=isolation_backend,
                    repository_code_execution=repository_code_execution,
                ),
                artifact_roots=[],
            )
        executable_path = Path(executable).resolve(strict=True)
        try:
            executable_path.relative_to(repository_root.resolve(strict=True))
        except ValueError:
            pass
        else:
            return _CompileOneResult(
                result=SolidityCompilationResult(
                    status=CompilationStatus.UNAVAILABLE,
                    framework=project.project_type,
                    project_root=project.project_root,
                    command=project.build_command,
                    compiler_versions=project.compiler_versions,
                    duration_seconds=time.monotonic() - monotonic_start,
                    errors=["refusing compiler/build tool resolved from inside audited repository"],
                    isolation_backend=isolation_backend,
                    repository_code_execution=repository_code_execution,
                ),
                artifact_roots=[],
            )
        try:
            executable_sha256 = _file_sha256(executable_path)
        except OSError as exc:
            return _CompileOneResult(
                result=SolidityCompilationResult(
                    status=CompilationStatus.UNAVAILABLE,
                    framework=project.project_type,
                    project_root=project.project_root,
                    command=project.build_command,
                    compiler_versions=project.compiler_versions,
                    duration_seconds=time.monotonic() - monotonic_start,
                    errors=[f"could not hash compiler/build tool: {type(exc).__name__}"],
                    isolation_backend=isolation_backend,
                    repository_code_execution=repository_code_execution,
                ),
                artifact_roots=[],
            )
    digest = hashlib.sha256(project.project_root.encode()).hexdigest()[:12]
    workspace = private_dir / digest / "workspace"
    stdout_path = private_dir / digest / "compile.stdout.txt"
    stderr_path = private_dir / digest / "compile.stderr.txt"
    try:
        _copy_project(
            repository_root,
            project,
            workspace,
            excluded_repository_paths=excluded_repository_paths,
        )
        if prepared_dependency_root is not None:
            _copy_prepared_dependencies(
                prepared_dependency_root,
                workspace / "node_modules",
                trusted_private_root=private_dir.parent,
            )
    except (OSError, ValueError) as exc:
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.FAILED,
                framework=project.project_type,
                project_root=project.project_root,
                executable_sha256=executable_sha256,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[f"could not create isolated compilation workspace: {type(exc).__name__}"],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    environment = _compilation_environment(private_dir / digest, config)
    command = [
        str(executable_path) if executable_path is not None else executable_name,
        *project.build_command[1:],
    ]
    try:
        if loads_repository_code:
            assert isinstance(backend, RepositoryJavaScriptIsolationBackend)
            command = backend.wrap_repository_javascript(
                command,
                workspace=workspace,
                private_dir=private_dir / digest,
                rpc_port=1,
            )
            repository_code_execution = RepositoryCodeExecutionState.ISOLATED
        elif config.allow_network:
            network_wrapper = getattr(backend, "wrap_allowing_network", None)
            if not callable(network_wrapper):
                return _CompileOneResult(
                    result=SolidityCompilationResult(
                        status=CompilationStatus.UNAVAILABLE,
                        framework=project.project_type,
                        project_root=project.project_root,
                        executable_sha256=executable_sha256,
                        command=project.build_command,
                        compiler_versions=project.compiler_versions,
                        duration_seconds=time.monotonic() - monotonic_start,
                        errors=[
                            "selected isolation backend cannot honor explicitly requested "
                            "compilation network access"
                        ],
                        isolation_backend=isolation_backend,
                        repository_code_execution=repository_code_execution,
                    ),
                    artifact_roots=[],
                )
            command = network_wrapper(
                command,
                workspace=workspace,
                private_dir=private_dir / digest,
                rpc_port=1,
            )
        else:
            command = backend.wrap(
                command,
                workspace=workspace,
                private_dir=private_dir / digest,
                rpc_port=1,
            )
        process_environment = isolation_host_environment(
            backend,
            private_dir / digest,
            environment,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        cleanup_error = _cleanup_error(backend, private_dir / digest)
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.FAILED,
                framework=project.project_type,
                project_root=project.project_root,
                executable_sha256=executable_sha256,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                errors=[
                    f"invalid compilation isolation configuration: {type(exc).__name__}",
                    *([cleanup_error] if cleanup_error else []),
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    stdout_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    timed_out = False
    output_exceeded = False
    process: subprocess.Popen[bytes] | None = None
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                command,
                cwd=workspace,
                stdout=stdout_handle,
                stderr=stderr_handle,
                env=process_environment,
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=(
                    int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                    if os.name == "nt"
                    else 0
                ),
                preexec_fn=_limit_process if os.name != "nt" else None,
            )
            deadline = time.monotonic() + config.compilation_timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    _stop_process(process)
                    break
                if (
                    stdout_path.stat().st_size > _OUTPUT_LIMIT
                    or stderr_path.stat().st_size > _OUTPUT_LIMIT
                ):
                    output_exceeded = True
                    _stop_process(process)
                    break
                time.sleep(0.05)
            return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process is not None:
            _stop_process(process)
        return_code = process.returncode if process is not None else -1
    except OSError as exc:
        cleanup_error = _cleanup_error(backend, private_dir / digest)
        return _CompileOneResult(
            result=SolidityCompilationResult(
                status=CompilationStatus.FAILED,
                framework=project.project_type,
                project_root=project.project_root,
                executable_sha256=executable_sha256,
                command=project.build_command,
                compiler_versions=project.compiler_versions,
                duration_seconds=time.monotonic() - monotonic_start,
                tool_versions={},
                errors=[
                    f"compilation process failed: {type(exc).__name__}",
                    *([cleanup_error] if cleanup_error else []),
                ],
                isolation_backend=isolation_backend,
                repository_code_execution=repository_code_execution,
            ),
            artifact_roots=[],
        )
    cleanup_error = _cleanup_error(backend, private_dir / digest)
    stdout = (
        stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
    )
    stderr = (
        stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
    )
    roots = [
        path
        for path in (workspace / "out", workspace / "artifacts", workspace / "build-info")
        if path.exists()
    ]
    summary = _artifact_summary(roots)
    errors = _diagnostic_lines(stdout, stderr, "error")
    warnings = _diagnostic_lines(stdout, stderr, "warning")
    status = CompilationStatus.SUCCESS if return_code == 0 else CompilationStatus.FAILED
    if timed_out:
        status = CompilationStatus.TIMED_OUT
        errors.append(f"compilation exceeded {config.compilation_timeout_seconds:.0f}s timeout")
    if output_exceeded:
        status = CompilationStatus.FAILED
        errors.append("compilation output exceeded the private output limit")
    if cleanup_error:
        status = CompilationStatus.FAILED
        errors.append(cleanup_error)
    if status is CompilationStatus.FAILED and not errors:
        errors.append(f"compiler exited with code {return_code}")
    tool_versions: dict[str, str] = {}
    version_cleanup_error: str | None = None
    if cleanup_error is None:
        tool_versions, version_cleanup_error = _isolated_tool_versions(
            str(executable_path) if executable_path is not None else executable_name,
            backend,
            workspace,
            private_dir / digest,
            environment,
            repository_javascript=loads_repository_code,
        )
    if version_cleanup_error:
        status = CompilationStatus.FAILED
        errors.append(version_cleanup_error)
    return _CompileOneResult(
        result=SolidityCompilationResult(
            status=status,
            framework=project.project_type,
            project_root=project.project_root,
            executable_sha256=executable_sha256,
            command=project.build_command,
            compiler_versions=project.compiler_versions,
            contracts_compiled=summary["contracts"],
            warnings=warnings[:100],
            errors=errors[:100],
            artifacts=[
                path.relative_to(private_dir).as_posix()
                for root in roots
                for path in root.glob("**/*.json")
            ][:500],
            source_maps_available=summary["source_maps_available"],
            ast_available=summary["ast_available"],
            duration_seconds=time.monotonic() - monotonic_start,
            tool_versions=tool_versions,
            stdout_path=stdout_path.relative_to(private_dir.parent).as_posix(),
            stderr_path=stderr_path.relative_to(private_dir.parent).as_posix(),
            isolation_backend=isolation_backend,
            repository_code_execution=repository_code_execution,
        ),
        artifact_roots=roots,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_project(
    repository_root: Path,
    project: SolidityProjectMetadata,
    workspace: Path,
    *,
    excluded_repository_paths: tuple[str, ...],
) -> None:
    repository = repository_root.resolve(strict=True)
    source = repository if project.project_root == "." else repository / project.project_root
    source = source.resolve(strict=True)
    source.relative_to(repository)
    if workspace.exists():
        raise OSError("workspace already exists")
    exclusions = _project_copy_exclusions(
        repository,
        source,
        excluded_repository_paths,
    )
    validate_copyable_workspace(
        source,
        excluded=lambda path: _compilation_workspace_path_excluded(
            PurePosixPath(path.relative_to(source).as_posix()),
            exclusions,
        ),
    )
    shutil.copytree(
        source,
        workspace,
        ignore=lambda directory, names: _dynamic_workspace_ignore(
            directory,
            names,
            source=source,
            exclusions=exclusions,
        ),
    )


def _copy_prepared_dependencies(
    source: Path,
    destination: Path,
    *,
    trusted_private_root: Path,
) -> None:
    resolved_private = trusted_private_root.resolve(strict=True)
    resolved_source = source.resolve(strict=True)
    try:
        resolved_source.relative_to(resolved_private)
    except ValueError as exc:
        raise OSError("prepared dependencies must remain inside the private run directory") from exc
    if (
        not resolved_source.is_dir()
        or resolved_source.is_symlink()
        or resolved_source.is_junction()
        or destination.exists()
    ):
        raise OSError("invalid prepared dependency source or destination")
    for path in resolved_source.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise OSError("prepared dependencies may not contain links")
        if path.is_file() and path.stat().st_nlink != 1:
            raise OSError("prepared dependencies may contain only unique regular files")
    shutil.copytree(resolved_source, destination)


def _project_copy_exclusions(
    repository_root: Path,
    project_root: Path,
    values: tuple[str, ...],
) -> frozenset[PurePosixPath]:
    exclusions: set[PurePosixPath] = set()
    for value in values:
        if not value or "\\" in value:
            raise OSError("compilation exclusion must be a normalized repository-relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise OSError("compilation exclusion must be a normalized repository-relative path")
        candidate = repository_root.joinpath(*path.parts)
        try:
            relative = candidate.relative_to(project_root)
        except ValueError:
            continue
        if not relative.parts:
            raise OSError("compilation exclusion cannot remove the entire project")
        exclusions.add(PurePosixPath(relative.as_posix()))
    return frozenset(exclusions)


def _dynamic_workspace_ignore(
    directory: str,
    names: list[str],
    *,
    source: Path,
    exclusions: frozenset[PurePosixPath],
) -> set[str]:
    directory_relative = Path(directory).relative_to(source)
    prefix = (
        PurePosixPath()
        if not directory_relative.parts
        else PurePosixPath(directory_relative.as_posix())
    )
    return {
        name for name in names if _compilation_workspace_path_excluded(prefix / name, exclusions)
    }


def _compilation_workspace_path_excluded(
    relative: PurePosixPath,
    exclusions: frozenset[PurePosixPath],
) -> bool:
    return (
        any(part.lower() in _EXCLUDED_DYNAMIC_WORKSPACE_NAMES for part in relative.parts)
        or any(is_sensitive_workspace_name(part) for part in relative.parts)
        or any(relative == exclusion or exclusion in relative.parents for exclusion in exclusions)
    )


def _compilation_environment(private_dir: Path, config: SmartContractsConfig) -> dict[str, str]:
    environment = sanitized_scanner_environment(private_dir)
    environment.update(
        {
            "CI": "true",
            "NO_COLOR": "1",
            "FOUNDRY_DISABLE_NIGHTLY_WARNING": "true",
            "FOUNDRY_FFI": "false",
            "HARDHAT_DISABLE_TELEMETRY_PROMPT": "true",
            "HARDHAT_NETWORK": "hardhat",
        }
    )
    if not config.allow_network:
        environment["MMAUDIT_NETWORK_DISABLED"] = "1"
    return environment


def _isolated_tool_versions(
    executable: str,
    backend: IsolationBackend,
    workspace: Path,
    private_dir: Path,
    environment: dict[str, str],
    *,
    repository_javascript: bool,
) -> tuple[dict[str, str], str | None]:
    result: subprocess.CompletedProcess[str] | None = None
    try:
        if repository_javascript:
            if not isinstance(backend, RepositoryJavaScriptIsolationBackend):
                return {}, None
            command = backend.wrap_repository_javascript(
                [executable, "--version"],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=1,
            )
        else:
            command = backend.wrap(
                [executable, "--version"],
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=1,
            )
        process_environment = isolation_host_environment(
            backend,
            private_dir,
            environment,
        )
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=process_environment,
            cwd=workspace,
            shell=False,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError):
        result = None
    cleanup_error = _cleanup_error(backend, private_dir)
    if result is None or cleanup_error:
        return {}, cleanup_error
    output = (result.stdout or result.stderr).strip().splitlines()
    versions = {Path(executable).name: output[0][:200]} if output else {}
    return versions, None


def _cleanup_error(backend: object, private_dir: Path) -> str | None:
    try:
        cleanup_isolation_backend(backend, private_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        return f"isolation cleanup verification failed: {type(exc).__name__}"
    return None


def _artifact_summary(roots: list[Path]) -> dict[str, Any]:
    contracts: set[str] = set()
    ast_available = False
    source_maps_available = False
    for path in [item for root in roots for item in root.glob("**/*.json")][:2_000]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if contract_name := payload.get("contractName"):
            contracts.add(str(contract_name))
        if "ast" in payload or payload.get("output", {}).get("sources"):
            ast_available = True
        source_maps_available = source_maps_available or _has_source_map(payload)
    return {
        "contracts": sorted(contracts),
        "ast_available": ast_available,
        "source_maps_available": source_maps_available,
    }


def _has_source_map(payload: dict[str, Any]) -> bool:
    if payload.get("sourceMap"):
        return True
    deployed = payload.get("deployedBytecode", {})
    if isinstance(deployed, dict) and deployed.get("sourceMap"):
        return True
    evm = payload.get("evm", {})
    return isinstance(evm, dict) and bool(
        evm.get("bytecode", {}).get("sourceMap") or evm.get("deployedBytecode", {}).get("sourceMap")
    )


def _diagnostic_lines(stdout: str, stderr: str, token: str) -> list[str]:
    diagnostics = []
    for line in [*stdout.splitlines(), *stderr.splitlines()]:
        if token in line.lower():
            diagnostics.append(" ".join(line.split())[:500])
    return diagnostics


def _existing_artifact_roots(
    repository_root: Path,
    projects: list[SolidityProjectMetadata],
) -> list[Path]:
    roots: list[Path] = []
    for project in projects:
        for raw_path in project.artifact_paths:
            path = repository_root / raw_path
            try:
                path.resolve(strict=True).relative_to(repository_root.resolve(strict=True))
            except (OSError, ValueError):
                continue
            if path.is_dir():
                roots.append(path)
    return _unique_paths(roots)


def _unique_paths(paths: list[Path]) -> list[Path]:
    result: dict[str, Path] = {}
    for path in paths:
        result[path.resolve(strict=False).as_posix()] = path
    return list(result.values())


def _limit_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (3_600, 3_600))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


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
