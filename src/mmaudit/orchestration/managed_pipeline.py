"""Compose prepared tool consumers without granting audit or installed-closure authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mmaudit.config import AuditConfig
from mmaudit.orchestration.managed_fork_archives import ManagedForkArchives
from mmaudit.orchestration.managed_fork_matrix import verify_managed_fork_matrix_config
from mmaudit.orchestration.managed_host_tools import ManagedHostToolMaterialization
from mmaudit.scanners.base import _observe_scanner_executable, _ScannerExecutableObservation
from mmaudit.scanners.fork_matrix import RepositoryForkMatrixRunner
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.formal import FormalRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import ForkReproductionRunner, IsolationBackend


def verify_managed_pipeline_config(
    material: ManagedHostToolMaterialization, config: AuditConfig
) -> None:
    """Require the exact prepared configuration and selected matrix tool roles."""

    if type(material) is not ManagedHostToolMaterialization or type(config) is not AuditConfig:
        raise ValueError("managed pipeline requires exact prepared material and config types")
    if config != material.config or config.effective() != config:
        raise ValueError("managed pipeline config differs from prepared effective config")
    verify_managed_fork_matrix_config(material, config.smart_contracts, config.reproduction)


def _verify_roots(material: ManagedHostToolMaterialization, repo: Path, output: Path) -> None:
    for root in (repo.resolve(strict=True), output.resolve(strict=False)):
        if material.directory.is_relative_to(root) or root.is_relative_to(material.directory):
            raise ValueError("managed pipeline material overlaps source or writable output")
    if repo.resolve(strict=True) != repo or output.resolve(strict=False) != output:
        raise ValueError("managed pipeline roots are no longer canonical")


@dataclass(frozen=True, slots=True)
class ManagedPipelineTools:
    """Retained selection rechecked at phase boundaries, not an atomic execution attestation."""

    material: ManagedHostToolMaterialization
    repo: Path
    output: Path
    tools: tuple[tuple[Path, _ScannerExecutableObservation], ...]
    backend: IsolationBackend
    scanners: ScannerRunner
    reproduction: ForkReproductionRunner
    invariants: FoundryInvariantRunner
    formal: FormalRunner
    fork_matrix: RepositoryForkMatrixRunner

    def verify(
        self,
        *,
        config: AuditConfig,
        repo: Path,
        output: Path,
        scanners: ScannerRunner,
        reproduction: ForkReproductionRunner,
        invariants: FoundryInvariantRunner,
        formal: FormalRunner,
        fork_matrix: RepositoryForkMatrixRunner,
    ) -> None:
        """Reject config/root/consumer/tool drift; existing engine admission remains mandatory."""

        verify_managed_pipeline_config(self.material, config)
        if repo != self.repo or output != self.output:
            raise ValueError("managed pipeline root selection changed")
        _verify_roots(self.material, repo, output)
        for path, observation in self.tools:
            if _observe_scanner_executable(path) != observation:
                raise ValueError("managed pipeline tool identity changed")
        if (
            scanners is not self.scanners
            or reproduction is not self.reproduction
            or invariants is not self.invariants
            or formal is not self.formal
            or fork_matrix is not self.fork_matrix
        ):
            raise ValueError("managed pipeline consumer selection changed")
        if any(
            runner.backend is not self.backend
            for runner in (scanners, reproduction, invariants, formal, fork_matrix)
        ):
            raise ValueError("managed pipeline consumer backend changed")
        if (
            scanners.config != config
            or reproduction.reproduction != config.reproduction
            or reproduction.smart_contracts != config.smart_contracts
            or invariants.reproduction != config.reproduction
            or invariants.smart_contracts != config.smart_contracts
            or formal.config != config.formal
            or fork_matrix.smart_contracts != config.smart_contracts
            or fork_matrix.reproduction != config.reproduction
        ):
            raise ValueError("managed pipeline consumer config changed")
        scanners.verify_managed_selection()
        reproduction._verify_managed_selection()
        invariants._verify_managed_selection()
        if (
            scanners.offline_forks is not fork_matrix.offline_forks
            or reproduction.offline_forks is not scanners.offline_forks
            or invariants.offline_forks is not scanners.offline_forks
        ):
            raise ValueError("managed pipeline fork consumers have different prepared archives")
        fork_matrix.verify_managed_selection()


def prepare_managed_pipeline_tools(
    material: ManagedHostToolMaterialization,
    config: AuditConfig,
    *,
    repo: Path,
    output: Path,
    backend: IsolationBackend | None = None,
    offline_forks: ManagedForkArchives | None = None,
) -> ManagedPipelineTools:
    """Build fixed consumers with one selected backend, including disabled reproduction mode."""

    verify_managed_pipeline_config(material, config)
    _verify_roots(material, repo, output)
    if offline_forks is not None:
        if type(offline_forks) is not ManagedForkArchives:
            raise ValueError("managed pipeline requires exact prepared archive material")
        offline_forks.verify(config)
        offline_forks.verify_roots(repo, output, material.directory)
    observations = []
    for item in material.manifest.files:
        path = material.directory / item.locator
        observation = _observe_scanner_executable(path)
        if observation.sha256 != item.sha256:
            raise ValueError("managed pipeline tool differs from its prepared pin")
        observations.append((path, observation))
    if backend is None:
        from mmaudit.isolation.managed import managed_isolation_backend

        backend = managed_isolation_backend(material)
    selected = ManagedPipelineTools(
        material=material,
        repo=repo,
        output=output,
        tools=tuple(observations),
        backend=backend,
        scanners=ScannerRunner(
            config, backend=backend, host_tools=material, offline_forks=offline_forks
        ),
        reproduction=ForkReproductionRunner(
            config.reproduction,
            config.smart_contracts,
            backend=backend,
            host_tools=material,
            offline_forks=offline_forks,
        ),
        invariants=FoundryInvariantRunner(
            config.reproduction,
            config.smart_contracts,
            backend=backend,
            host_tools=material,
            offline_forks=offline_forks,
        ),
        formal=FormalRunner(config.formal, backend=backend, host_tools=material),
        fork_matrix=RepositoryForkMatrixRunner(
            config.smart_contracts,
            config.reproduction,
            host_tools=material,
            managed_backend=backend,
            offline_forks=offline_forks,
        ),
    )
    selected.verify(
        config=config,
        repo=repo,
        output=output,
        scanners=selected.scanners,
        reproduction=selected.reproduction,
        invariants=selected.invariants,
        formal=selected.formal,
        fork_matrix=selected.fork_matrix,
    )
    return selected
