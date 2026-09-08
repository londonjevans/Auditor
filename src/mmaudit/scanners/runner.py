"""Concurrent coordination of the fixed scanner adapters."""

from __future__ import annotations

import asyncio
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from mmaudit.config import AuditConfig, ScannerConfig
from mmaudit.isolation.container import RepositoryJavaScriptIsolationBackend
from mmaudit.isolation.managed import managed_isolation_backend
from mmaudit.isolation.repository_code import contains_hardhat_repository_code
from mmaudit.models.schemas import (
    AuditedSuiteEntityCatalog,
    LanguageCapabilityProfile,
    RepositoryCodeExecutionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
)
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchives
from mmaudit.orchestration.managed_host_tools import ManagedHostToolMaterialization
from mmaudit.orchestration.managed_toolchain import MANAGED_SCANNER_ROLES, ManagedToolchainRole
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    ScannerSourceIntegrityError,
    preflight_scanner_executable,
    retain_scanner_workspace_source_custody,
    sanitized_scanner_environment,
    scanner_executable_candidate,
)
from mmaudit.scanners.codeql import CodeQLScanner
from mmaudit.scanners.diagnostics import (
    ExecutableVersionProbeStatus,
    ScannerExecutablePreflight,
    ScannerExecutableState,
)
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.hardhat import HardhatForkScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.runtime_evidence import _invoke_builtin_foundry_adapter
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner
from mmaudit.solidity.reproduction import default_isolation_backend

_ISOLATION_UNAVAILABLE_DIAGNOSTIC = (
    "hardened isolation is unavailable; the resolved tool was not executed"
)
_REPOSITORY_EXECUTABLE_DIAGNOSTIC = (
    "resolved executable is inside the audited repository and was not executed"
)
_PREFLIGHT_FAILURE_DIAGNOSTIC = (
    "tool preflight failed inside the hardened isolation boundary; the tool was not executed"
)
_REPOSITORY_JAVASCRIPT_ISOLATION_DIAGNOSTIC = (
    "tool requires off-host repository-JavaScript isolation, which is unavailable"
)
_HARDHAT_CONTAINER_IDENTITY_DIAGNOSTIC = (
    "Hardhat repository-JavaScript requires an independently attested image-side "
    "toolchain; host PATH is not container executable identity"
)
_SCANNER_PREFLIGHT_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def preflight_configured_scanner_tools(
    adapters: Mapping[str, ScannerAdapter],
    *,
    backend: ScannerIsolationBackend | None,
    repository_root: Path,
    trusted_output_root: Path,
    private_dir: Path,
    timeout_seconds: float = 15.0,
) -> dict[str, ScannerExecutablePreflight]:
    """Probe every configured executable without falling back outside isolation.

    PATH is resolved before execution so a repository-local shadow is refused. Raw
    version output remains in the per-tool private directory managed by the shared
    version probe and is never included in the returned diagnostics.
    """

    if not 0 < timeout_seconds <= 15.0:
        raise ValueError("scanner preflight timeout is outside its fixed bound")
    resolved_repository = repository_root.resolve(strict=True)
    resolved_private = _prepare_private_preflight_root(trusted_output_root, private_dir)
    diagnostics: dict[str, ScannerExecutablePreflight] = {}
    for name, adapter in sorted(adapters.items()):
        if _SCANNER_PREFLIGHT_NAME.fullmatch(name) is None:
            raise ValueError("scanner preflight name must be one safe path component")
        tool_private = resolved_private / name
        tool_private.mkdir(mode=0o700)
        tool_private.chmod(0o700)
        _require_private_directory(tool_private)
        workspace = tool_private / "workspace"
        workspace.mkdir(mode=0o700)
        workspace.chmod(0o700)
        _require_private_directory(workspace)
        workspace.resolve(strict=True).relative_to(resolved_private)
        if isinstance(adapter, HardhatForkScanner):
            # A host `hardhat` path is not the executable that a digest-pinned image
            # would run. Generic preflight translates an absolute command to its
            # basename at the container boundary, so pairing that image response with
            # the host path would create false identity evidence. Remain unavailable
            # until a dedicated image-side probe produces process-bound attestation.
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
                resolved_path=None,
                version=None,
                failure_kind=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
                diagnostic=_HARDHAT_CONTAINER_IDENTITY_DIAGNOSTIC,
            )
            continue
        candidate = scanner_executable_candidate(adapter.executable)
        resolved = _resolved_executable(candidate)
        if candidate is not None and resolved is None:
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
                resolved_path=None,
                version=None,
                failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
                diagnostic="resolved tool identity could not be validated safely",
            )
            continue
        if candidate is None:
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.ABSENT,
                resolved_path=None,
                version=None,
                failure_kind=None,
                diagnostic=(
                    "explicit tool path is unavailable"
                    if Path(adapter.executable).is_absolute()
                    else "tool was not found on PATH"
                ),
            )
            continue
        if resolved is not None and _is_relative_to(resolved, resolved_repository):
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
                resolved_path=resolved,
                version=None,
                failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
                diagnostic=_REPOSITORY_EXECUTABLE_DIAGNOSTIC,
            )
            continue
        if backend is None:
            diagnostics[name] = _preflight_without_isolation(candidate, resolved)
            continue
        repository_javascript = isinstance(adapter, HardhatForkScanner)
        if repository_javascript and not isinstance(
            backend,
            RepositoryJavaScriptIsolationBackend,
        ):
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
                resolved_path=resolved,
                version=None,
                failure_kind=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
                diagnostic=_REPOSITORY_JAVASCRIPT_ISOLATION_DIAGNOSTIC,
            )
            continue
        try:
            diagnostics[name] = preflight_scanner_executable(
                resolved if resolved is not None else adapter.executable,
                sanitized_scanner_environment(tool_private),
                backend,
                workspace,
                tool_private,
                repository_javascript=repository_javascript,
                timeout_seconds=timeout_seconds,
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            diagnostics[name] = ScannerExecutablePreflight(
                state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
                resolved_path=resolved,
                version=None,
                failure_kind=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
                diagnostic=_PREFLIGHT_FAILURE_DIAGNOSTIC,
            )
    return diagnostics


def _prepare_private_preflight_root(
    trusted_output_root: Path,
    private_dir: Path,
) -> Path:
    trusted_absolute = trusted_output_root.absolute()
    _require_trusted_output_directory(trusted_absolute)
    candidate = private_dir.absolute()
    try:
        relative = candidate.relative_to(trusted_absolute)
    except ValueError as exc:
        raise ValueError("scanner preflight private directory must be inside output") from exc
    if not relative.parts:
        raise ValueError("scanner preflight private directory cannot be the output root")
    current = trusted_absolute
    for component in relative.parts:
        if component in {"", ".", ".."}:
            raise ValueError("scanner preflight private path contains an unsafe component")
        current = current / component
        if current.exists() or current.is_symlink():
            _require_private_directory(current)
            continue
        current.mkdir(mode=0o700)
        current.chmod(0o700)
        _require_private_directory(current)
    resolved_output = trusted_absolute.resolve(strict=True)
    resolved_private = current.resolve(strict=True)
    resolved_private.relative_to(resolved_output)
    return resolved_private


def _require_trusted_output_directory(path: Path) -> None:
    _require_trusted_output_ancestors(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("trusted scanner preflight output directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(path, "is_junction", lambda: False)())
    ):
        raise ValueError("trusted scanner preflight output root must be a non-link directory")
    _require_current_owner(metadata, "trusted scanner preflight output root")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError("trusted scanner preflight output root permissions are too broad")


def _require_trusted_output_ancestors(path: Path) -> None:
    for ancestor in path.parents:
        try:
            metadata = ancestor.lstat()
        except OSError as exc:
            raise ValueError("trusted scanner preflight output ancestor is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(ancestor, "is_junction", lambda: False)())
        ):
            raise ValueError(
                "trusted scanner preflight output ancestor must be a non-link directory"
            )
        if os.name == "nt":
            continue
        permissions = stat.S_IMODE(metadata.st_mode)
        # A sticky shared parent (for example /tmp) cannot be used by another
        # unprivileged user to rename this caller-owned output tree. Other
        # group/world-writable ancestors leave the trusted root replaceable.
        if permissions & 0o022 and not permissions & stat.S_ISVTX:
            raise ValueError("trusted scanner preflight output ancestor permissions are too broad")


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("scanner preflight private directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(getattr(path, "is_junction", lambda: False)())
    ):
        raise ValueError("scanner preflight private path must be a non-link directory")
    _require_current_owner(metadata, "scanner preflight private directory")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("scanner preflight private directory permissions are too broad")


def _require_current_owner(metadata: os.stat_result, label: str) -> None:
    current_uid = getattr(os, "getuid", lambda: None)()
    if current_uid is not None and metadata.st_uid != current_uid:
        raise ValueError(f"{label} is not owned by the current user")


def _resolved_executable(candidate: str | None) -> Path | None:
    if candidate is None:
        return None
    try:
        return Path(candidate).resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _preflight_without_isolation(
    candidate: str | None,
    resolved: Path | None,
) -> ScannerExecutablePreflight:
    if candidate is None:
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.ABSENT,
            resolved_path=None,
            version=None,
            failure_kind=None,
            diagnostic="tool was not found on PATH",
        )
    if resolved is None or not resolved.is_file() or not os.access(resolved, os.X_OK):
        return ScannerExecutablePreflight(
            state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
            resolved_path=resolved,
            version=None,
            failure_kind=ExecutableVersionProbeStatus.EXECUTION_REFUSED,
            diagnostic="resolved tool identity could not be validated safely",
        )
    return ScannerExecutablePreflight(
        state=ScannerExecutableState.PRESENT_ISOLATION_UNEXECUTABLE,
        resolved_path=resolved,
        version=None,
        failure_kind=ExecutableVersionProbeStatus.ISOLATION_FAILURE,
        diagnostic=_ISOLATION_UNAVAILABLE_DIAGNOSTIC,
    )


def _managed_scanner_paths(
    config: AuditConfig, host_tools: ManagedHostToolMaterialization
) -> dict[str, Path]:
    """Reverify one exact material/config selection, not installed execution authority."""

    if type(host_tools) is not ManagedHostToolMaterialization or type(config) is not AuditConfig:
        raise ValueError("managed scanner selection requires exact material and config types")
    if config != host_tools.config:
        raise ValueError("managed scanner configuration differs from prepared host material")
    host_tools.verify()
    by_role = {item.role: host_tools.directory / item.locator for item in host_tools.manifest.files}
    # The manifest requires every selected direct host role. Image-side roles cannot
    # occur here; retain their own closed execution boundary without a host substitute.
    paths = {name: by_role[role] for name, role in MANAGED_SCANNER_ROLES if role in by_role}
    if ManagedToolchainRole.SOLC in by_role:
        paths["solc"] = by_role[ManagedToolchainRole.SOLC]
    return paths


def _verify_managed_fork_source(
    config: AuditConfig,
    host_tools: ManagedHostToolMaterialization | None,
    offline_forks: ManagedForkArchives | None,
) -> None:
    if offline_forks is not None:
        if (
            type(offline_forks) is not ManagedForkArchives
            or type(host_tools) is not ManagedHostToolMaterialization
        ):
            raise ValueError("managed scanner forks require exact prepared material")
        offline_forks.verify(config)
        offline_forks.verify_roots(host_tools.directory)


def configured_scanner_adapters(
    config: AuditConfig,
    *,
    host_tools: ManagedHostToolMaterialization | None = None,
    offline_forks: ManagedForkArchives | None = None,
) -> dict[str, ScannerAdapter]:
    """Build fixed adapters, optionally bound to reverified explicit host material.

    Managed paths do not attest the backend, transitive dependencies or image-side
    tools, and cannot authorize an audit. No ambient discovery happens here.
    """

    paths = _managed_scanner_paths(config, host_tools) if host_tools is not None else {}
    _verify_managed_fork_source(config, host_tools, offline_forks)
    if host_tools is not None:
        config = host_tools.config
    adapters: dict[str, ScannerAdapter] = {
        "semgrep": SemgrepScanner(),
        "gitleaks": GitleaksScanner(),
        "trivy": TrivyScanner(),
        "osv": OsvScanner(),
        "codeql": CodeQLScanner(
            config.scanners.codeql.database_path,
            config.scanners.codeql.query_suite,
        ),
        "slither": SlitherScanner(config.smart_contracts, solc_path=paths.get("solc")),
        "foundry_fork": FoundryForkScanner(
            config.smart_contracts,
            reproduction=config.reproduction,
            executable_path=paths.get("foundry_fork"),
            solc_path=paths.get("solc"),
            offline_forks=offline_forks,
            managed_primary_fork=host_tools is not None,
        ),
        "hardhat_fork": HardhatForkScanner(
            config.smart_contracts,
            config.scanners.hardhat_fork,
        ),
    }
    for name, path in paths.items():
        if name != "solc":
            adapters[name].executable = str(path)
    return adapters


class ScannerRunner:
    def __init__(
        self,
        config: AuditConfig,
        *,
        adapters: dict[str, ScannerAdapter] | None = None,
        backend: ScannerIsolationBackend | None = None,
        host_tools: ManagedHostToolMaterialization | None = None,
        offline_forks: ManagedForkArchives | None = None,
    ) -> None:
        self.backend: ScannerIsolationBackend | None
        self._managed_host_tools = host_tools
        self.offline_forks = offline_forks
        self._managed_offline_forks = offline_forks
        _verify_managed_fork_source(config, host_tools, offline_forks)
        if host_tools is not None:
            if adapters is not None:
                raise ValueError("managed scanners require fixed adapters")
            self.adapters = configured_scanner_adapters(
                config, host_tools=host_tools, offline_forks=offline_forks
            )
            self.config = host_tools.config
            self.backend = backend if backend is not None else managed_isolation_backend(host_tools)
        else:
            self.config = config
            self.backend = backend or default_isolation_backend("auto")
            self.adapters = configured_scanner_adapters(config) if adapters is None else adapters

    def verify_managed_selection(self) -> None:
        """Retain the prepared fork input across queued work and public adapter replacement."""

        if self.offline_forks is not self._managed_offline_forks:
            raise ValueError("managed scanner fork selection changed")
        if self._managed_host_tools is not None:
            _managed_scanner_paths(self.config, self._managed_host_tools)
        _verify_managed_fork_source(self.config, self._managed_host_tools, self.offline_forks)

    def scanner_config(self, name: str) -> ScannerConfig:
        value = getattr(self.config.scanners, name)
        if not isinstance(value, ScannerConfig):
            raise TypeError(f"invalid scanner configuration for {name}")
        return value

    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        audited_relative_paths: Sequence[str],
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
        allow_custom_repository_exclusion: bool = False,
        audited_suite_entity_catalog: AuditedSuiteEntityCatalog | None = None,
    ) -> list[ScannerRun]:
        # Rebuild fixed managed adapters from the retained selection for each run;
        # caller edits to an earlier public adapter view cannot substitute a tool.
        self.verify_managed_selection()
        if self.offline_forks is not None:
            self.offline_forks.verify_roots(root, private_dir)
            if repository_exclusion_root is not None:
                self.offline_forks.verify_roots(repository_exclusion_root)
        adapters = (
            configured_scanner_adapters(
                self.config, host_tools=self._managed_host_tools, offline_forks=self.offline_forks
            )
            if self._managed_host_tools is not None
            else self.adapters
        )
        canonical_entity_catalog = (
            AuditedSuiteEntityCatalog.model_validate(
                audited_suite_entity_catalog.model_dump(mode="json")
            )
            if audited_suite_entity_catalog is not None
            else None
        )
        try:
            source_custody = retain_scanner_workspace_source_custody(
                root,
                repository_exclusion_root,
                audited_relative_paths=audited_relative_paths,
                allow_custom_private_exclusion=allow_custom_repository_exclusion,
            )
        except (OSError, ValueError) as exc:
            raise ScannerSourceIntegrityError(
                "scanner execution could not acquire frozen audited source custody"
            ) from exc

        frozen_repository_sha256 = (
            source_custody.source_inventory_sha256_before
            if expected_repository_sha256 is None
            else expected_repository_sha256
        )
        try:
            if source_custody.source_inventory_sha256_before != frozen_repository_sha256:
                raise ScannerSourceIntegrityError(
                    "scanner audited source inventory differs from its frozen identity"
                )
            if (
                canonical_entity_catalog is not None
                and canonical_entity_catalog.repository_sha256 != frozen_repository_sha256
            ):
                raise ScannerSourceIntegrityError(
                    "audited-suite entity catalog differs from frozen source identity"
                )
            tasks: list[asyncio.Task[ScannerRun]] = []
            results: list[ScannerRun] = []
            semaphore = asyncio.Semaphore(self.config.execution.concurrency)

            async def run_one(
                adapter: ScannerAdapter,
                scanner_config: ScannerConfig,
            ) -> ScannerRun:
                def dispatch() -> ScannerRun:
                    # Queued work must not rely on an earlier construction-time check.
                    if self._managed_host_tools is not None:
                        self.verify_managed_selection()
                    if type(adapter) is FoundryForkScanner:
                        return _invoke_builtin_foundry_adapter(
                            adapter,
                            root,
                            private_dir / adapter.name,
                            self.config.execution.scanner_timeout_seconds,
                            backend=self.backend,
                            expected_version=scanner_config.version,
                            expected_sha256=scanner_config.sha256,
                        )
                    if type(adapter).run is not ScannerAdapter.run:
                        return adapter.run(
                            root,
                            private_dir / adapter.name,
                            self.config.execution.scanner_timeout_seconds,
                            backend=self.backend,
                            expected_version=scanner_config.version,
                            expected_sha256=scanner_config.sha256,
                        )
                    return adapter.run_source_bound(
                        root,
                        private_dir / adapter.name,
                        self.config.execution.scanner_timeout_seconds,
                        backend=self.backend,
                        expected_version=scanner_config.version,
                        expected_sha256=scanner_config.sha256,
                        expected_repository_sha256=frozen_repository_sha256,
                        audited_relative_paths=audited_relative_paths,
                        repository_exclusion_root=repository_exclusion_root,
                        allow_custom_repository_exclusion=(allow_custom_repository_exclusion),
                    )

                async with semaphore:
                    return await asyncio.to_thread(dispatch)

            for name, adapter in adapters.items():
                scanner_config = self.scanner_config(name)
                evm_scanner_outside_capability = (
                    self.config.language_profile is LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW
                    and name in {"slither", "foundry_fork", "hardhat_fork"}
                )
                if (
                    not scanner_config.enabled
                    or (name == "codeql" and skip_codeql)
                    or evm_scanner_outside_capability
                ):
                    now = datetime.now(UTC)
                    results.append(
                        ScannerRun(
                            scanner=name,
                            status=ScannerStatus.SKIPPED,
                            started_at=now,
                            finished_at=now,
                            duration_seconds=0,
                            error=(
                                "not applicable to generic-source-review capability"
                                if evm_scanner_outside_capability
                                else "disabled by configuration or command line"
                            ),
                            repository_code_execution=(
                                RepositoryCodeExecutionState.DISABLED
                                if (
                                    adapter.may_execute_repository_code
                                    and contains_hardhat_repository_code(root)
                                )
                                else RepositoryCodeExecutionState.NOT_APPLICABLE
                            ),
                        )
                    )
                    continue
                if type(adapter) is FoundryForkScanner:
                    adapter = adapter.with_runtime_context(
                        allow_fork_probing=allow_fork_probing,
                        projects=projects,
                        expected_repository_sha256=frozen_repository_sha256,
                        repository_exclusion_root=repository_exclusion_root,
                        audited_suite_entity_catalog=canonical_entity_catalog,
                    )
                elif isinstance(adapter, HardhatForkScanner):
                    adapter = adapter.with_runtime_allowance(allow_fork_probing)
                tasks.append(
                    asyncio.create_task(
                        run_one(adapter, scanner_config),
                        name=f"scanner:{name}",
                    )
                )
            if tasks:
                outcomes = await asyncio.gather(*tasks, return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome, BaseException):
                        raise outcome
                    results.append(outcome)
            if self._managed_host_tools is not None:
                await asyncio.to_thread(self.verify_managed_selection)
            return sorted(results, key=lambda result: result.scanner)
        finally:
            if not source_custody.closed:
                try:
                    observed_after = source_custody.finalize()
                except (OSError, ValueError) as exc:
                    raise ScannerSourceIntegrityError(
                        "audited source changed during scanner execution"
                    ) from exc
                if observed_after != source_custody.source_inventory_sha256_before:
                    raise ScannerSourceIntegrityError(
                        "audited source changed during scanner execution"
                    )

    def required_failures(self, runs: list[ScannerRun]) -> list[str]:
        failures: list[str] = []
        for run in runs:
            if self.scanner_config(run.scanner).required and run.status.is_failure:
                failures.append(f"{run.scanner}: {run.status.value}")
        return failures
