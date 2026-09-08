"""Fixed prepared matrix tool composition; preparation grants no execution authority."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from mmaudit.config import (
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.isolation.provenance import isolation_attestation_sha256, isolation_execution_evidence
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerRun, SolidityProjectMetadata
from mmaudit.orchestration.managed_host_tools import ManagedHostToolMaterialization
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.scanners.base import (
    ScannerIsolationBackend,
    _observe_scanner_executable,
    _ScannerExecutableObservation,
)
from mmaudit.scanners.fork_rpc import local_fork_rpc_port
from mmaudit.scanners.foundry import FoundryForkScanner

if TYPE_CHECKING:
    from mmaudit.scanners.fork_matrix import ForkMatrixBridge


def verify_managed_fork_matrix_config(
    material: ManagedHostToolMaterialization,
    smart_contracts: SmartContractsConfig,
    reproduction: ReproductionConfig,
) -> None:
    """Require exact prepared config and all three selected roles before backend setup."""

    if type(material) is not ManagedHostToolMaterialization:
        raise ValueError("managed fork matrix requires exact prepared material type")
    config = material.config
    if (
        type(smart_contracts) is not SmartContractsConfig
        or type(reproduction) is not ReproductionConfig
        or smart_contracts != config.smart_contracts
        or reproduction != config.reproduction
    ):
        raise ValueError("managed fork matrix config differs from prepared config")
    material.verify()
    if not smart_contracts.repository_suite.fork_matrix_states:
        return
    required = {ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC, ManagedToolchainRole.ANVIL}
    foundry = config.scanners.foundry_fork
    if not foundry.enabled or not required.issubset(
        {item.role for item in material.manifest.files}
    ):
        raise ValueError("managed fork matrix requires prepared Foundry, Solc and Anvil roles")


@dataclass(frozen=True, slots=True)
class ManagedForkMatrixTools:
    """Retain file/config/backend selection without replacing per-process attestation."""

    material: ManagedHostToolMaterialization
    backend: ScannerIsolationBackend | None
    backend_attestation_sha256: str | None
    tools: tuple[tuple[Path, _ScannerExecutableObservation], ...]

    def verify(
        self, smart_contracts: SmartContractsConfig, reproduction: ReproductionConfig
    ) -> None:
        verify_managed_fork_matrix_config(self.material, smart_contracts, reproduction)
        for path, observation in self.tools:
            if _observe_scanner_executable(path) != observation:
                raise ValueError("managed fork matrix tool identity changed")

    def verify_roots(self, *roots: Path) -> None:
        for root in roots:
            canonical = root.resolve(strict=False)
            if canonical != root:
                raise ValueError("managed fork matrix roots are no longer canonical")
            if self.material.directory.is_relative_to(root) or root.is_relative_to(
                self.material.directory
            ):
                raise ValueError("managed fork matrix material overlaps source or private roots")

    def backend_limitation(self, backend: ScannerIsolationBackend) -> str | None:
        if (
            backend is not self.backend
            or getattr(backend, "supports_local_fork_rpc", False) is not True
            or isolation_execution_evidence(backend) is not ExecutionEvidenceKind.REAL
            or self.backend_attestation_sha256 is None
            or isolation_attestation_sha256(backend) != self.backend_attestation_sha256
        ):
            return "The prepared matrix requires unchanged attested local-RPC isolation."
        return None

    def baseline_limitation(self, run: ScannerRun) -> str | None:
        forge = next(
            item for item in self.material.manifest.files if item.role is ManagedToolchainRole.FORGE
        )
        if (
            run.version != forge.version
            or run.executable_sha256 != forge.sha256
            or run.isolation_attestation_sha256 != self.backend_attestation_sha256
        ):
            return "The qualifying baseline differs from the prepared Forge or isolation pins."
        return None

    def scanner_factory(
        self,
        config: SmartContractsConfig,
        *,
        reproduction: ReproductionConfig,
        projects: Sequence[SolidityProjectMetadata],
        allow_fork_probing: bool,
        expected_repository_sha256: str,
        repository_exclusion_root: Path,
        fork_rpc_url_override: str,
        fork_rpc_scope_recorder: ForkMatrixBridge,
        attempt_binding_sha256: str,
    ) -> FoundryForkScanner:
        """Accept only paired declared state overrides, retaining detached prepared config."""

        prepared = self.material.config
        self.verify(prepared.smart_contracts, prepared.reproduction)
        self.verify_roots(repository_exclusion_root)
        if allow_fork_probing is not True:
            raise ValueError("managed fork matrix requires the baseline-authorized fork context")
        local_fork_rpc_port(fork_rpc_url_override)
        if fork_rpc_url_override != fork_rpc_scope_recorder.endpoint:
            raise ValueError("managed fork matrix bridge endpoint differs from its recorder")
        for state in prepared.smart_contracts.repository_suite.fork_matrix_states:
            state_smart = prepared.smart_contracts.model_copy(
                update={
                    "fork_rpc_url_env": state.rpc_url_env
                    if isinstance(state, RepositoryPinnedForkMatrixStateConfig)
                    else prepared.smart_contracts.fork_rpc_url_env
                }
            )
            state_reproduction = prepared.reproduction.model_copy(
                update={
                    "expected_chain_id": state.expected_chain_id,
                    "pinned_block_number": (
                        state.pinned_block_number
                        if isinstance(state, RepositoryPinnedForkMatrixStateConfig)
                        else 0
                    ),
                }
            )
            if (
                type(config) is SmartContractsConfig
                and type(reproduction) is ReproductionConfig
                and config == state_smart
                and reproduction == state_reproduction
            ):
                paths = {
                    item.role: self.material.directory / item.locator
                    for item in self.material.manifest.files
                }
                return FoundryForkScanner(
                    state_smart,
                    reproduction=state_reproduction,
                    projects=projects,
                    allow_fork_probing=True,
                    expected_repository_sha256=expected_repository_sha256,
                    repository_exclusion_root=repository_exclusion_root,
                    fork_rpc_url_override=fork_rpc_url_override,
                    fork_rpc_scope_recorder=fork_rpc_scope_recorder,
                    attempt_binding_sha256=attempt_binding_sha256,
                    executable_path=paths[ManagedToolchainRole.FORGE],
                    solc_path=paths[ManagedToolchainRole.SOLC],
                )
        raise ValueError("managed fork matrix child config is not a declared prepared state")


def prepare_managed_fork_matrix_tools(
    material: ManagedHostToolMaterialization,
    smart_contracts: SmartContractsConfig,
    reproduction: ReproductionConfig,
    *,
    backend: ScannerIsolationBackend | None,
) -> ManagedForkMatrixTools:
    verify_managed_fork_matrix_config(material, smart_contracts, reproduction)
    observations = []
    for item in material.manifest.files:
        path = material.directory / item.locator
        observation = _observe_scanner_executable(path)
        if observation.sha256 != item.sha256:
            raise ValueError("managed fork matrix tool differs from its prepared pin")
        observations.append((path, observation))
    if backend is None and smart_contracts.repository_suite.fork_matrix_states:
        from mmaudit.isolation.managed import managed_isolation_backend

        backend = managed_isolation_backend(material)
    selected = ManagedForkMatrixTools(
        material=material,
        backend=backend,
        backend_attestation_sha256=isolation_attestation_sha256(backend),
        tools=tuple(observations),
    )
    selected.verify(smart_contracts, reproduction)
    return selected
