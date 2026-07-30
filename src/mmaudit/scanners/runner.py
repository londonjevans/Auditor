"""Concurrent coordination of the fixed scanner adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mmaudit.config import AuditConfig, ScannerConfig
from mmaudit.isolation.repository_code import contains_hardhat_repository_code
from mmaudit.models.schemas import (
    RepositoryCodeExecutionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
)
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    ScannerSourceIntegrityError,
    retain_scanner_workspace_source_custody,
)
from mmaudit.scanners.codeql import CodeQLScanner
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.hardhat import HardhatForkScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.runtime_evidence import _invoke_builtin_foundry_adapter
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner
from mmaudit.solidity.reproduction import default_isolation_backend


class ScannerRunner:
    def __init__(
        self,
        config: AuditConfig,
        *,
        adapters: dict[str, ScannerAdapter] | None = None,
        backend: ScannerIsolationBackend | None = None,
    ) -> None:
        self.config = config
        self.backend = backend or default_isolation_backend("auto")
        self.adapters = adapters or {
            "semgrep": SemgrepScanner(),
            "gitleaks": GitleaksScanner(),
            "trivy": TrivyScanner(),
            "osv": OsvScanner(),
            "codeql": CodeQLScanner(
                config.scanners.codeql.database_path,
                config.scanners.codeql.query_suite,
            ),
            "slither": SlitherScanner(),
            "foundry_fork": FoundryForkScanner(
                config.smart_contracts,
                reproduction=config.reproduction,
            ),
            "hardhat_fork": HardhatForkScanner(
                config.smart_contracts,
                config.scanners.hardhat_fork,
            ),
        }

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
    ) -> list[ScannerRun]:
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
            tasks: list[asyncio.Task[ScannerRun]] = []
            results: list[ScannerRun] = []
            semaphore = asyncio.Semaphore(self.config.execution.concurrency)

            async def run_one(
                adapter: ScannerAdapter,
                scanner_config: ScannerConfig,
            ) -> ScannerRun:
                async with semaphore:
                    if type(adapter) is FoundryForkScanner:
                        return await asyncio.to_thread(
                            _invoke_builtin_foundry_adapter,
                            adapter,
                            root,
                            private_dir / adapter.name,
                            self.config.execution.scanner_timeout_seconds,
                            backend=self.backend,
                            expected_version=scanner_config.version,
                            expected_sha256=scanner_config.sha256,
                        )
                    if type(adapter).run is not ScannerAdapter.run:
                        return await asyncio.to_thread(
                            adapter.run,
                            root,
                            private_dir / adapter.name,
                            self.config.execution.scanner_timeout_seconds,
                            backend=self.backend,
                            expected_version=scanner_config.version,
                            expected_sha256=scanner_config.sha256,
                        )
                    return await asyncio.to_thread(
                        adapter.run_source_bound,
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

            for name, adapter in self.adapters.items():
                scanner_config = self.scanner_config(name)
                if not scanner_config.enabled or (name == "codeql" and skip_codeql):
                    now = datetime.now(UTC)
                    results.append(
                        ScannerRun(
                            scanner=name,
                            status=ScannerStatus.SKIPPED,
                            started_at=now,
                            finished_at=now,
                            duration_seconds=0,
                            error="disabled by configuration or command line",
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
            if (
                self.scanner_config(run.scanner).required
                and run.status is not ScannerStatus.SUCCESS
            ):
                failures.append(f"{run.scanner}: {run.status.value}")
        return failures
