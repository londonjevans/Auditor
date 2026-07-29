"""Deterministic offline replay of sealed local run evidence."""

from __future__ import annotations

import asyncio
import math
import tempfile
import time
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
    REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    CandidateFinding,
    ExecutionEvidenceKind,
    FalsificationDecision,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSuite,
    RepositoryCleanStateAttestationEvidence,
    RepositoryDifferentialRunStatus,
    RepositoryForkEgressStatus,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteStateWorkspaceCleanupEvidence,
    RepositorySuiteWorkspaceCopyEvidence,
    RepositorySuiteWorkspaceLifecycleEvidence,
    RepositorySuiteWorkspaceLifecycleStatus,
    RepositoryTestForkRpcScopeEvidence,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
    StrictModel,
)
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    canonical_sha256,
    load_run_evidence_manifest,
    resolve_run_evidence_config,
)
from mmaudit.orchestration.verification import (
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.scanners.base import ScannerIsolationBackend, scanner_workspace_sha256
from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
from mmaudit.scanners.fork_matrix import (
    ForkMatrixDependencies,
    RepositoryForkMatrixRunner,
)
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import (
    ForkReproductionRunner,
    default_isolation_backend,
)

_MAX_ARTIFACT_BYTES = 100_000_000
_MAX_REPLAY_BYTES = 100_000_000


class ReplayComponentKind(StrEnum):
    SCANNER = "scanner"
    SAVED_TEST = "saved_test"
    COUNTEREXAMPLE = "counterexample"
    REPOSITORY_SUITE_DIFFERENTIAL = "repository_suite_differential"


class ReplayComponentStatus(StrEnum):
    MATCHED = "matched"
    DRIFTED = "drifted"
    BLOCKED = "blocked"


class OfflineReplayStatus(StrEnum):
    REPLAYED = "replayed"
    DRIFTED = "drifted"
    INCOMPLETE = "incomplete"


class OfflineReplayComponent(StrictModel):
    """Stable expected-versus-observed projection for one local replay unit."""

    kind: ReplayComponentKind
    identifier: str = Field(min_length=1, max_length=1_000)
    status: ReplayComponentStatus
    executed: bool
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    isolation_backend: str | None = Field(default=None, min_length=1, max_length=100)
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    expected_state: str = Field(min_length=1, max_length=200)
    observed_state: str | None = Field(default=None, min_length=1, max_length=200)
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    limitations: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("identifier", "expected_state", "observed_state")
    @classmethod
    def text_is_printable(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("offline replay identifiers and states must be printable")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_are_bounded(cls, value: list[str]) -> list[str]:
        if value != list(dict.fromkeys(value)):
            raise ValueError("offline replay limitations must be unique and ordered")
        if any(
            not item
            or len(item) > 1_000
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in value
        ):
            raise ValueError("offline replay limitations must be bounded printable text")
        return value

    @model_validator(mode="after")
    def status_matches_evidence(self) -> OfflineReplayComponent:
        if self.status is ReplayComponentStatus.MATCHED and (
            not self.executed
            or self.observed_state is None
            or self.observed_sha256 != self.expected_sha256
            or self.limitations
        ):
            raise ValueError("matched replay components require executed identical evidence")
        if self.status is ReplayComponentStatus.DRIFTED and (
            not self.executed
            or self.observed_state is None
            or self.observed_sha256 is None
            or self.observed_sha256 == self.expected_sha256
        ):
            raise ValueError("drifted replay components require differing executed evidence")
        if self.status is ReplayComponentStatus.BLOCKED and (self.executed or not self.limitations):
            raise ValueError("blocked replay components require a limitation and no execution")
        return self


class OfflineReplayPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    status: OfflineReplayStatus
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_provider_contacted: Literal[False] = False
    remote_network_policy: Literal["denied"] = "denied"
    loopback_policy: Literal["local_only"] = "local_only"
    components: list[OfflineReplayComponent] = Field(max_length=200_000)
    applicable_kinds: list[ReplayComponentKind] = Field(min_length=1, max_length=4)
    missing_kinds: list[ReplayComponentKind] = Field(max_length=4)

    @model_validator(mode="after")
    def status_and_components_are_consistent(self) -> OfflineReplayPayload:
        keys = [(item.kind.value, item.identifier) for item in self.components]
        if keys != sorted(set(keys)):
            raise ValueError("offline replay components must be unique and sorted")
        if self.missing_kinds != sorted(set(self.missing_kinds), key=lambda item: item.value):
            raise ValueError("offline replay missing kinds must be unique and sorted")
        if self.applicable_kinds != sorted(
            set(self.applicable_kinds),
            key=lambda item: item.value,
        ):
            raise ValueError("offline replay applicable kinds must be unique and sorted")
        observed_kinds = {
            item.kind
            for item in self.components
            if item.status is ReplayComponentStatus.MATCHED and item.executed
        }
        expected_missing = sorted(
            set(self.applicable_kinds) - observed_kinds,
            key=lambda item: item.value,
        )
        if self.missing_kinds != expected_missing:
            raise ValueError("offline replay missing-kind accounting is inconsistent")
        expected_status = (
            OfflineReplayStatus.DRIFTED
            if any(item.status is ReplayComponentStatus.DRIFTED for item in self.components)
            else (
                OfflineReplayStatus.INCOMPLETE
                if self.missing_kinds
                or any(item.status is ReplayComponentStatus.BLOCKED for item in self.components)
                else OfflineReplayStatus.REPLAYED
            )
        )
        if self.status is not expected_status:
            raise ValueError("offline replay status is inconsistent")
        return self


class OfflineReplay(OfflineReplayPayload):
    replay_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def replay_hash_matches(self) -> OfflineReplay:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"replay_sha256"}))
        if self.replay_sha256 != expected:
            raise ValueError("offline replay hash is inconsistent")
        return self


class ScannerReplayRunner(Protocol):
    async def run_all(
        self,
        root: Path,
        private_dir: Path,
        *,
        skip_codeql: bool = False,
        allow_fork_probing: bool = False,
        projects: Sequence[SolidityProjectMetadata] = (),
        expected_repository_sha256: str | None = None,
        repository_exclusion_root: Path | None = None,
    ) -> list[ScannerRun]: ...


class InvariantReplayRunner(Protocol):
    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        specification: FoundryInvariantHarnessSpec,
        private_dir: Path,
    ) -> InvariantExecutionResult: ...


class ReproductionReplayRunner(Protocol):
    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate: CandidateFinding,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult: ...


class RepositoryDifferentialReplayRunner(Protocol):
    """Trusted local adapter that re-executes one sealed repository-state matrix."""

    def run(
        self,
        repository_root: Path,
        private_dir: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun | None: ...


class _BackendBoundRepositoryDifferentialReplayRunner:
    """Bind replay to the exact isolation backend already selected for scanners."""

    def __init__(
        self,
        runner: RepositoryForkMatrixRunner,
        backend: ScannerIsolationBackend,
    ) -> None:
        self.runner = runner
        self.backend = backend

    def run(
        self,
        repository_root: Path,
        private_dir: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun | None:
        return self.runner.run(
            repository_root,
            private_dir,
            projects=projects,
            repository_sha256=repository_sha256,
            repository_exclusion_root=repository_exclusion_root,
            backend=self.backend,
            baseline_run=baseline_run,
            absolute_deadline=absolute_deadline,
        )


def _configured_replay_isolation_backend(config: AuditConfig) -> ScannerIsolationBackend:
    """Resolve the effective configured backend exactly once or refuse replay."""

    backend = default_isolation_backend(
        config.reproduction.isolation_backend,
        rootless_container_image=config.reproduction.rootless_container_image,
        rootless_container_runtime=config.reproduction.rootless_container_runtime,
    )
    if backend is None:
        raise ValueError("configured hardened isolation backend is unavailable for offline replay")
    try:
        name = backend.name
        wrap = backend.wrap
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(
            "configured hardened isolation backend is invalid for offline replay"
        ) from exc
    if not isinstance(name, str) or not name or not callable(wrap):
        raise ValueError("configured hardened isolation backend is invalid for offline replay")
    return backend


def _repository_suite_replay_identity(
    repository: Path,
    expected: Sequence[ScannerRun],
) -> tuple[str | None, Path | None]:
    """Reconstruct and verify one unambiguous frozen repository-suite identity."""

    identities = {
        (
            selection.repository_sha256,
            selection.repository_exclusion_path,
        )
        for run in expected
        if (selection := run.repository_suite_selection) is not None
    }
    if not identities:
        return None, None
    if len(identities) != 1:
        raise ValueError("repository suite replay identities conflict")

    expected_sha256, relative_exclusion = identities.pop()
    if normalize_relative_path(relative_exclusion) != relative_exclusion:
        raise ValueError("repository suite replay exclusion is not normalized")
    exclusion_root = repository.joinpath(*PurePosixPath(relative_exclusion).parts)
    try:
        exclusion_root.absolute().relative_to(repository.absolute())
    except ValueError as exc:
        raise ValueError("repository suite replay exclusion leaves the repository") from exc
    if scanner_workspace_sha256(repository, exclusion_root) != expected_sha256:
        raise ValueError("repository suite replay source differs from its frozen identity")
    return expected_sha256, exclusion_root


class _ScannerArtifact(StrictModel):
    schema_version: Literal["1.0"]
    runs: list[ScannerRun] = Field(max_length=100)

    @model_validator(mode="after")
    def scanners_are_unique(self) -> _ScannerArtifact:
        names = [item.scanner for item in self.runs]
        if len(names) != len(set(names)):
            raise ValueError("saved scanner runs must be unique")
        return self


class _SolidityProjectsArtifact(StrictModel):
    schema_version: Literal["1.0"]
    projects: list[SolidityProjectMetadata] = Field(max_length=200)


class _InvariantArtifact(StrictModel):
    schema_version: Literal["1.0"]
    invariants: InvariantSuite | None


class _InvariantHarnessArtifact(StrictModel):
    schema_version: Literal["1.0"]
    harnesses: list[FoundryInvariantHarnessSpec] = Field(max_length=100_000)
    limitations: list[str] = Field(default_factory=list, max_length=100_000)

    @model_validator(mode="after")
    def harnesses_are_unique(self) -> _InvariantHarnessArtifact:
        keys = [(item.invariant_id, item.name) for item in self.harnesses]
        if len(keys) != len(set(keys)):
            raise ValueError("saved invariant harnesses must be unique")
        return self


class _InvariantExecutionArtifact(StrictModel):
    schema_version: Literal["1.0"]
    harnesses: list[FoundryInvariantHarnessSpec] = Field(default_factory=list, max_length=100_000)
    results: list[InvariantExecutionResult] = Field(max_length=100_000)

    @model_validator(mode="after")
    def results_are_unique(self) -> _InvariantExecutionArtifact:
        keys = [(item.invariant_id, item.harness_name) for item in self.results]
        if len(keys) != len(set(keys)):
            raise ValueError("saved invariant results must be unique")
        return self


class _CandidateArtifact(StrictModel):
    schema_version: Literal["1.0"]
    findings: list[CandidateFinding] = Field(max_length=100_000)

    @model_validator(mode="after")
    def candidates_are_unique(self) -> _CandidateArtifact:
        identifiers = [item.candidate_id for item in self.findings]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("saved candidates must be unique")
        return self


class _ReproductionArtifact(StrictModel):
    schema_version: Literal["1.0"]
    test_specifications: list[GeneratedFoundryTestSpec] = Field(max_length=100_000)
    results: list[ReproductionResult] = Field(max_length=100_000)
    falsification_decisions: list[FalsificationDecision] = Field(
        default_factory=list,
        max_length=100_000,
    )

    @model_validator(mode="after")
    def tests_and_results_are_unique(self) -> _ReproductionArtifact:
        specification_keys = [(item.candidate_id, item.name) for item in self.test_specifications]
        result_keys = [(item.candidate_id, item.test_name) for item in self.results]
        if len(specification_keys) != len(set(specification_keys)):
            raise ValueError("saved test specifications must be unique")
        if len(result_keys) != len(set(result_keys)):
            raise ValueError("saved reproduction results must be unique")
        return self


class OfflineReplayOrchestrator:
    """Re-execute only typed, sealed deterministic evidence using local runners."""

    def __init__(
        self,
        config: AuditConfig | None = None,
        *,
        file_config: AuditConfig | None = None,
        scanner_runner: ScannerReplayRunner | None = None,
        invariant_runner: InvariantReplayRunner | None = None,
        reproduction_runner: ReproductionReplayRunner | None = None,
        differential_runner: RepositoryDifferentialReplayRunner | None = None,
    ) -> None:
        self.config = config
        self.file_config = file_config
        self._injected_scanner_runner = scanner_runner
        self._injected_invariant_runner = invariant_runner
        self._injected_reproduction_runner = reproduction_runner
        self._injected_differential_runner = differential_runner
        self.scanner_runner: ScannerReplayRunner | None = scanner_runner
        self.invariant_runner: InvariantReplayRunner | None = invariant_runner
        self.reproduction_runner: ReproductionReplayRunner | None = reproduction_runner
        self.differential_runner: RepositoryDifferentialReplayRunner | None = differential_runner
        self._differential_runner_limitation: str | None = None

    async def replay(
        self,
        *,
        manifest_path: Path,
        run_dir: Path,
        repository_root: Path,
        work_dir: Path,
    ) -> OfflineReplay:
        """Verify then replay sealed evidence without constructing a model provider."""

        manifest = load_run_evidence_manifest(manifest_path)
        effective_config, verification_file_config = self._resolve_effective_config(manifest)
        self.config = effective_config
        verification = verify_run_evidence(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository_root,
            config=effective_config,
            file_config=verification_file_config,
        )
        if verification.status is not RunVerificationStatus.CURRENT:
            raise ValueError("offline replay refused stale run evidence")
        root = _safe_directory(run_dir, "run")
        repository = _safe_directory(repository_root, "repository")
        work_parent = _safe_work_directory(work_dir)
        artifacts = _load_replay_artifacts(root, config=effective_config)

        scanner_required = bool(artifacts.scanners.runs)
        invariant_required = bool(artifacts.harnesses.harnesses)
        reproduction_required = bool(artifacts.reproductions.test_specifications)
        differential_required = artifacts.differential is not None
        default_backend_required = (
            (self._injected_scanner_runner is None and scanner_required)
            or (self._injected_invariant_runner is None and invariant_required)
            or (self._injected_reproduction_runner is None and reproduction_required)
            or (self._injected_differential_runner is None and differential_required)
        )
        shared_backend = (
            _configured_replay_isolation_backend(effective_config)
            if default_backend_required
            else None
        )
        self.scanner_runner = self._injected_scanner_runner
        if self.scanner_runner is None and scanner_required:
            if shared_backend is None:
                raise RuntimeError("offline replay lacks its resolved isolation backend")
            self.scanner_runner = ScannerRunner(
                effective_config,
                backend=shared_backend,
            )
        self.invariant_runner = self._injected_invariant_runner
        if self.invariant_runner is None and invariant_required:
            if shared_backend is None:
                raise RuntimeError("offline replay lacks its resolved isolation backend")
            self.invariant_runner = FoundryInvariantRunner(
                effective_config.reproduction,
                effective_config.smart_contracts,
                backend=shared_backend,
            )
        self.reproduction_runner = self._injected_reproduction_runner
        if self.reproduction_runner is None and reproduction_required:
            if shared_backend is None:
                raise RuntimeError("offline replay lacks its resolved isolation backend")
            self.reproduction_runner = ForkReproductionRunner(
                effective_config.reproduction,
                effective_config.smart_contracts,
                backend=shared_backend,
            )
        self._configure_differential_runner(
            effective_config,
            backend=shared_backend,
            default_required=differential_required,
        )

        components: list[OfflineReplayComponent] = []
        observed_scanner_runs: list[ScannerRun] = []
        with tempfile.TemporaryDirectory(prefix="mmaudit-replay-", dir=work_parent) as temporary:
            private = Path(temporary)
            components.extend(
                await self._replay_scanners(
                    repository=repository,
                    private_dir=private / "scanners",
                    projects=artifacts.projects.projects,
                    expected=artifacts.scanners.runs,
                    observed_runs=observed_scanner_runs,
                )
            )
            components.extend(
                await self._replay_repository_differential(
                    repository=repository,
                    private_dir=private / "repository-suite-differential",
                    projects=artifacts.projects.projects,
                    expected=artifacts.differential,
                    artifact_required=artifacts.differential_required,
                    artifact_limitation=artifacts.differential_limitation,
                    expected_scanner_runs=artifacts.scanners.runs,
                    observed_scanner_runs=observed_scanner_runs,
                )
            )
            components.extend(
                await self._replay_invariants(
                    repository=repository,
                    private_dir=private / "invariants",
                    projects=artifacts.projects.projects,
                    suite=artifacts.invariants.invariants,
                    harnesses=artifacts.harnesses.harnesses,
                    expected_results=artifacts.invariant_results.results,
                )
            )
            components.extend(
                await self._replay_reproductions(
                    repository=repository,
                    private_dir=private / "saved-tests",
                    projects=artifacts.projects.projects,
                    candidates=artifacts.candidates.findings,
                    specifications=artifacts.reproductions.test_specifications,
                    expected_results=artifacts.reproductions.results,
                )
            )

        ordered = sorted(components, key=lambda item: (item.kind.value, item.identifier))
        applicable = _applicable_replay_kinds(artifacts)
        observed_kinds = {
            item.kind
            for item in ordered
            if item.status is ReplayComponentStatus.MATCHED and item.executed
        }
        missing = sorted(
            set(applicable) - observed_kinds,
            key=lambda item: item.value,
        )
        status = (
            OfflineReplayStatus.DRIFTED
            if any(item.status is ReplayComponentStatus.DRIFTED for item in ordered)
            else (
                OfflineReplayStatus.INCOMPLETE
                if missing or any(item.status is ReplayComponentStatus.BLOCKED for item in ordered)
                else OfflineReplayStatus.REPLAYED
            )
        )
        payload = OfflineReplayPayload(
            status=status,
            run_id=verification.run_id,
            manifest_sha256=verification.manifest_sha256,
            run_verification_sha256=verification.verification_sha256,
            components=ordered,
            applicable_kinds=applicable,
            missing_kinds=missing,
        )
        serialized = payload.model_dump(mode="json")
        return OfflineReplay.model_validate(
            {
                **serialized,
                "replay_sha256": canonical_sha256(serialized),
            }
        )

    def _resolve_effective_config(
        self,
        manifest: RunEvidenceManifest,
    ) -> tuple[AuditConfig, AuditConfig | None]:
        if manifest.run_configuration is None:
            legacy = self.config or self.file_config
            if legacy is None:
                raise ValueError("legacy run manifest requires an explicit configuration")
            return legacy.effective(), None
        if self.file_config is not None:
            return (
                resolve_run_evidence_config(
                    manifest,
                    file_config=self.file_config,
                ),
                self.file_config,
            )
        if self.config is not None:
            if self.config.stable_hash() == manifest.run_configuration.effective_config_sha256:
                return self.config.effective(), None
            return (
                resolve_run_evidence_config(
                    manifest,
                    file_config=self.config,
                ),
                self.config,
            )
        return resolve_run_evidence_config(manifest), None

    def _configure_differential_runner(
        self,
        config: AuditConfig,
        *,
        backend: ScannerIsolationBackend | None,
        default_required: bool,
    ) -> None:
        """Construct the trusted default only for an effective configured matrix."""

        self.differential_runner = self._injected_differential_runner
        self._differential_runner_limitation = None
        if (
            self.differential_runner is not None
            or not default_required
            or not config.smart_contracts.repository_suite.fork_matrix_states
        ):
            return
        if backend is None:
            self._differential_runner_limitation = (
                "trusted local repository differential replay lacks the exact configured "
                "isolation backend"
            )
            return
        try:
            matrix_runner = RepositoryForkMatrixRunner(
                config.smart_contracts,
                config.reproduction,
                dependencies=ForkMatrixDependencies(
                    clean_state_provider=TrustedCleanAnvilLauncher(),
                ),
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            self._differential_runner_limitation = (
                "trusted local repository differential replay runner construction failed safely"
            )
            return
        self.differential_runner = _BackendBoundRepositoryDifferentialReplayRunner(
            matrix_runner,
            backend,
        )

    async def _replay_scanners(
        self,
        *,
        repository: Path,
        private_dir: Path,
        projects: list[SolidityProjectMetadata],
        expected: list[ScannerRun],
        observed_runs: list[ScannerRun] | None = None,
    ) -> list[OfflineReplayComponent]:
        if not expected:
            return []
        assert self.scanner_runner is not None
        expected_by_name = {item.scanner: item for item in expected}
        try:
            (
                expected_repository_sha256,
                repository_exclusion_root,
            ) = _repository_suite_replay_identity(repository, expected)
            fork_acknowledged = any(
                item.scanner in {"foundry_fork", "hardhat_fork"}
                and item.repository_suite_selection is not None
                and bool(item.repository_test_executions)
                for item in expected
            )
            observed = await self.scanner_runner.run_all(
                repository,
                private_dir,
                skip_codeql=False,
                allow_fork_probing=fork_acknowledged,
                projects=projects,
                expected_repository_sha256=expected_repository_sha256,
                repository_exclusion_root=repository_exclusion_root,
            )
            if observed_runs is not None:
                observed_runs.extend(observed)
            if (
                expected_repository_sha256 is not None
                and repository_exclusion_root is not None
                and scanner_workspace_sha256(repository, repository_exclusion_root)
                != expected_repository_sha256
            ):
                raise ValueError("repository execution source changed during scanner replay")
        except (OSError, RuntimeError, ValueError) as exc:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.SCANNER,
                    identifier=item.scanner,
                    expected_state=item.status.value,
                    expected_projection=_scanner_projection(item),
                    limitation=f"scanner replay failed safely: {type(exc).__name__}",
                )
                for item in expected
            ]
        observed_by_name = {item.scanner: item for item in observed}
        components: list[OfflineReplayComponent] = []
        for name in sorted(set(expected_by_name) | set(observed_by_name)):
            prior = expected_by_name.get(name)
            current = observed_by_name.get(name)
            if prior is None and current is not None:
                components.append(
                    _drifted_component(
                        kind=ReplayComponentKind.SCANNER,
                        identifier=name,
                        expected_state="absent",
                        observed_state=current.status.value,
                        expected_projection={"scanner": name, "state": "absent"},
                        observed_projection=_scanner_projection(current),
                        executed=current.status is ScannerStatus.SUCCESS,
                    )
                )
            elif prior is not None and current is None:
                components.append(
                    _blocked_component(
                        kind=ReplayComponentKind.SCANNER,
                        identifier=name,
                        expected_state=prior.status.value,
                        expected_projection=_scanner_projection(prior),
                        limitation="configured scanner produced no replay result",
                    )
                )
            elif prior is not None and current is not None:
                executed = current.status is ScannerStatus.SUCCESS
                components.append(
                    _compared_component(
                        kind=ReplayComponentKind.SCANNER,
                        identifier=name,
                        expected_state=prior.status.value,
                        observed_state=current.status.value,
                        expected_projection=_scanner_projection(prior),
                        observed_projection=_scanner_projection(current),
                        executed=executed,
                        execution_evidence=current.execution_evidence,
                        isolation_backend=current.isolation_backend,
                        isolation_attestation_sha256=current.isolation_attestation_sha256,
                        blocked_limitation=(
                            None
                            if executed
                            else f"scanner replay did not execute successfully: {current.status.value}"
                        ),
                    )
                )
        return components

    async def _replay_repository_differential(
        self,
        *,
        repository: Path,
        private_dir: Path,
        projects: list[SolidityProjectMetadata],
        expected: RepositorySuiteDifferentialRun | None,
        artifact_required: bool,
        artifact_limitation: str | None,
        expected_scanner_runs: list[ScannerRun],
        observed_scanner_runs: list[ScannerRun],
    ) -> list[OfflineReplayComponent]:
        """Replay a state matrix separately from the qualifying scanner portfolio."""

        if not artifact_required:
            return []
        identifier = "repository-suite-differential"
        config = self.config
        expected_projection: object = (
            _repository_differential_projection(expected)
            if expected is not None
            else _configured_differential_projection(config)
        )
        expected_state = expected.status.value if expected is not None else "configured_missing"
        if artifact_limitation is not None or expected is None:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation=artifact_limitation
                    or "configured repository differential artifact is missing",
                )
            ]
        if config is None:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation="repository differential replay lacks effective configuration",
                )
            ]
        suite = config.smart_contracts.repository_suite
        configured_state_ids = tuple(state.state_id for state in suite.fork_matrix_states)
        if (
            not configured_state_ids
            or expected.configuration_sha256 != suite.stable_hash()
            or expected.requested_state_ids != configured_state_ids
            or expected.required_repetitions != suite.fork_matrix_repetitions
        ):
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation=(
                        "repository differential artifact differs from effective configuration"
                    ),
                )
            ]
        if self.differential_runner is None:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation=(
                        self._differential_runner_limitation
                        or "trusted local repository differential runner is unavailable"
                    ),
                )
            ]
        try:
            expected_repository_sha256, repository_exclusion_root = (
                _repository_suite_replay_identity(repository, expected_scanner_runs)
            )
        except (OSError, RuntimeError, ValueError):
            expected_repository_sha256 = None
            repository_exclusion_root = None
        expected_baselines = [
            run
            for run in expected_scanner_runs
            if run.scanner == "foundry_fork" and run.repository_suite_selection is not None
        ]
        observed_baselines = [
            run
            for run in observed_scanner_runs
            if run.scanner == "foundry_fork" and run.repository_suite_selection is not None
        ]
        baseline_valid = (
            expected_repository_sha256 is not None
            and repository_exclusion_root is not None
            and len(expected_baselines) == 1
            and len(observed_baselines) == 1
            and observed_baselines[0].status is ScannerStatus.SUCCESS
            and observed_baselines[0].execution_evidence is ExecutionEvidenceKind.REAL
            and canonical_sha256(_scanner_projection(expected_baselines[0]))
            == canonical_sha256(_scanner_projection(observed_baselines[0]))
            and (
                expected.matrix is None
                or expected.matrix.repository_sha256 == expected_repository_sha256
            )
        )
        if not baseline_valid:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation=("repository differential replay lacks a matching real baseline"),
                )
            ]
        assert expected_repository_sha256 is not None
        assert repository_exclusion_root is not None
        baseline_run = observed_baselines[0]
        timeout_seconds = suite.total_timeout_seconds
        absolute_deadline = time.monotonic() + timeout_seconds
        try:
            current_value = await asyncio.wait_for(
                asyncio.to_thread(
                    self.differential_runner.run,
                    repository,
                    private_dir,
                    projects=projects,
                    repository_sha256=expected_repository_sha256,
                    repository_exclusion_root=repository_exclusion_root,
                    baseline_run=baseline_run,
                    absolute_deadline=absolute_deadline,
                ),
                timeout=timeout_seconds,
            )
            if current_value is None:
                raise RuntimeError("repository differential runner returned no result")
            current = RepositorySuiteDifferentialRun.model_validate(
                current_value.model_dump(mode="json")
            )
            if (
                scanner_workspace_sha256(repository, repository_exclusion_root)
                != expected_repository_sha256
            ):
                raise ValueError("repository changed during differential replay")
        except (OSError, RuntimeError, TypeError, ValueError, TimeoutError) as exc:
            return [
                _blocked_component(
                    kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                    identifier=identifier,
                    expected_state=expected_state,
                    expected_projection=expected_projection,
                    limitation=(
                        f"repository differential replay failed safely: {type(exc).__name__}"
                    ),
                )
            ]
        executed = _repository_differential_is_qualifying(
            current,
            config=config,
            repository_sha256=expected_repository_sha256,
        )
        evidence, isolation_backend, isolation_attestation_sha256 = (
            _repository_differential_execution_identity(current)
        )
        return [
            _compared_component(
                kind=ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                identifier=identifier,
                expected_state=expected_state,
                observed_state=current.status.value,
                expected_projection=expected_projection,
                observed_projection=_repository_differential_projection(current),
                executed=executed,
                execution_evidence=evidence,
                isolation_backend=isolation_backend,
                isolation_attestation_sha256=isolation_attestation_sha256,
                blocked_limitation=(
                    None
                    if executed
                    else (
                        "repository differential replay did not produce complete real "
                        "isolated read-only evidence"
                    )
                ),
            )
        ]

    async def _replay_invariants(
        self,
        *,
        repository: Path,
        private_dir: Path,
        projects: list[SolidityProjectMetadata],
        suite: InvariantSuite | None,
        harnesses: list[FoundryInvariantHarnessSpec],
        expected_results: list[InvariantExecutionResult],
    ) -> list[OfflineReplayComponent]:
        if not harnesses:
            return []
        assert self.invariant_runner is not None
        invariants = {
            invariant.id: invariant for invariant in (suite.invariants if suite is not None else [])
        }
        expected = {(item.invariant_id, item.harness_name): item for item in expected_results}
        components: list[OfflineReplayComponent] = []
        for harness in harnesses:
            key = (harness.invariant_id, harness.name)
            prior = expected.get(key)
            kind = (
                ReplayComponentKind.COUNTEREXAMPLE
                if prior is not None and prior.status is InvariantExecutionStatus.COUNTEREXAMPLE
                else ReplayComponentKind.SAVED_TEST
            )
            identifier = f"{harness.invariant_id}/{harness.name}"
            if prior is None:
                components.append(
                    _blocked_component(
                        kind=kind,
                        identifier=identifier,
                        expected_state="missing_baseline",
                        expected_projection=harness.model_dump(mode="json"),
                        limitation="saved invariant harness has no baseline result",
                    )
                )
                continue
            source_path = _invariant_source_path(harness, invariants.get(harness.invariant_id))
            project = _project_for_path(source_path, projects) if source_path else None
            if project is None:
                components.append(
                    _blocked_component(
                        kind=kind,
                        identifier=identifier,
                        expected_state=prior.status.value,
                        expected_projection=_invariant_projection(prior),
                        limitation="saved invariant is not bound to a detected project",
                    )
                )
                continue
            try:
                current = await asyncio.to_thread(
                    self.invariant_runner.run,
                    repository_root=repository,
                    project=project,
                    specification=harness,
                    private_dir=private_dir / canonical_sha256(identifier)[:16],
                )
            except (OSError, RuntimeError, ValueError) as exc:
                components.append(
                    _blocked_component(
                        kind=kind,
                        identifier=identifier,
                        expected_state=prior.status.value,
                        expected_projection=_invariant_projection(prior),
                        limitation=f"invariant replay failed safely: {type(exc).__name__}",
                    )
                )
                continue
            executed = current.attempts > 0 and current.status in {
                InvariantExecutionStatus.PASSED,
                InvariantExecutionStatus.COUNTEREXAMPLE,
            }
            components.append(
                _compared_component(
                    kind=kind,
                    identifier=identifier,
                    expected_state=prior.status.value,
                    observed_state=current.status.value,
                    expected_projection=_invariant_projection(prior),
                    observed_projection=_invariant_projection(current),
                    executed=executed,
                    execution_evidence=current.execution_evidence,
                    isolation_backend=current.isolation_backend,
                    isolation_attestation_sha256=current.isolation_attestation_sha256,
                    blocked_limitation=(
                        None
                        if executed
                        else f"invariant replay did not complete: {current.status.value}"
                    ),
                )
            )
        return components

    async def _replay_reproductions(
        self,
        *,
        repository: Path,
        private_dir: Path,
        projects: list[SolidityProjectMetadata],
        candidates: list[CandidateFinding],
        specifications: list[GeneratedFoundryTestSpec],
        expected_results: list[ReproductionResult],
    ) -> list[OfflineReplayComponent]:
        if not specifications:
            return []
        assert self.reproduction_runner is not None
        candidates_by_id = {item.candidate_id: item for item in candidates}
        expected = {(item.candidate_id, item.test_name): item for item in expected_results}
        components: list[OfflineReplayComponent] = []
        for specification in specifications:
            identifier = f"{specification.candidate_id}/{specification.name}"
            prior = expected.get((specification.candidate_id, specification.name))
            candidate = candidates_by_id.get(specification.candidate_id)
            project = (
                _project_for_path(candidate.locations[0].path, projects)
                if candidate is not None and candidate.locations
                else None
            )
            if prior is None or candidate is None or project is None:
                components.append(
                    _blocked_component(
                        kind=ReplayComponentKind.SAVED_TEST,
                        identifier=identifier,
                        expected_state=prior.state.value
                        if prior is not None
                        else "missing_baseline",
                        expected_projection=(
                            _reproduction_projection(prior)
                            if prior is not None
                            else specification.model_dump(mode="json")
                        ),
                        limitation=(
                            "saved test has no baseline result"
                            if prior is None
                            else (
                                "saved test candidate is missing"
                                if candidate is None
                                else "saved test is not bound to a detected project"
                            )
                        ),
                    )
                )
                continue
            specification_sha256 = canonical_sha256(specification.model_dump(mode="json"))
            if prior.specification_sha256 != specification_sha256:
                components.append(
                    _blocked_component(
                        kind=ReplayComponentKind.SAVED_TEST,
                        identifier=identifier,
                        expected_state=prior.state.value,
                        expected_projection=_reproduction_projection(prior),
                        limitation="saved test baseline is not bound to its typed specification",
                    )
                )
                continue
            try:
                current = await asyncio.to_thread(
                    self.reproduction_runner.run,
                    repository_root=repository,
                    project=project,
                    candidate=candidate,
                    specification=specification,
                    private_dir=private_dir / canonical_sha256(identifier)[:16],
                )
            except (OSError, RuntimeError, ValueError) as exc:
                components.append(
                    _blocked_component(
                        kind=ReplayComponentKind.SAVED_TEST,
                        identifier=identifier,
                        expected_state=prior.state.value,
                        expected_projection=_reproduction_projection(prior),
                        limitation=f"saved-test replay failed safely: {type(exc).__name__}",
                    )
                )
                continue
            executed = current.attempts > 0 and current.state in {
                ReproductionState.NOT_REPRODUCED,
                ReproductionState.PARTIALLY_REPRODUCED,
                ReproductionState.REPRODUCED,
                ReproductionState.REPRODUCED_AND_MINIMIZED,
                ReproductionState.DISPROVEN,
            }
            components.append(
                _compared_component(
                    kind=ReplayComponentKind.SAVED_TEST,
                    identifier=identifier,
                    expected_state=prior.state.value,
                    observed_state=current.state.value,
                    expected_projection=_reproduction_projection(prior),
                    observed_projection=_reproduction_projection(current),
                    executed=executed,
                    execution_evidence=current.execution_evidence,
                    isolation_backend=current.isolation_backend,
                    isolation_attestation_sha256=current.isolation_attestation_sha256,
                    blocked_limitation=(
                        None
                        if executed
                        else f"saved-test replay did not complete: {current.state.value}"
                    ),
                )
            )
        return components


class _ReplayArtifacts(StrictModel):
    scanners: _ScannerArtifact
    projects: _SolidityProjectsArtifact
    invariants: _InvariantArtifact
    harnesses: _InvariantHarnessArtifact
    invariant_results: _InvariantExecutionArtifact
    candidates: _CandidateArtifact
    reproductions: _ReproductionArtifact
    differential: RepositorySuiteDifferentialRun | None = None
    differential_required: bool = False
    differential_limitation: str | None = None

    @model_validator(mode="after")
    def duplicated_replay_inputs_are_consistent(self) -> _ReplayArtifacts:
        planned_harnesses = {
            (item.invariant_id, item.name): canonical_sha256(item.model_dump(mode="json"))
            for item in self.harnesses.harnesses
        }
        execution_harnesses = {
            (item.invariant_id, item.name): canonical_sha256(item.model_dump(mode="json"))
            for item in self.invariant_results.harnesses
        }
        if execution_harnesses != planned_harnesses:
            raise ValueError("saved invariant execution inputs differ from the harness plan")
        invariant_result_keys = {
            (item.invariant_id, item.harness_name) for item in self.invariant_results.results
        }
        if invariant_result_keys != set(planned_harnesses):
            raise ValueError("saved invariant results do not exactly cover the harness plan")
        specification_keys = {
            (item.candidate_id, item.name) for item in self.reproductions.test_specifications
        }
        reproduction_result_keys = {
            (item.candidate_id, item.test_name) for item in self.reproductions.results
        }
        if reproduction_result_keys != specification_keys:
            raise ValueError("saved reproduction results do not exactly cover saved tests")
        candidate_ids = {item.candidate_id for item in self.candidates.findings}
        if not {candidate_id for candidate_id, _name in specification_keys} <= candidate_ids:
            raise ValueError("saved test specifications reference missing candidates")
        if self.differential is not None and not self.differential_required:
            raise ValueError("loaded differential evidence must create a replay obligation")
        if self.differential is None and self.differential_required:
            if self.differential_limitation is None:
                raise ValueError("missing differential evidence requires a replay limitation")
        elif self.differential_limitation is not None:
            raise ValueError("valid differential evidence cannot carry a load limitation")
        return self


def write_offline_replay(path: Path, replay: OfflineReplay) -> None:
    """Write bounded normalized replay evidence without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive offline-replay filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("offline-replay destination may not be a link")
    if path.exists() and (
        not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_REPLAY_BYTES
    ):
        raise ValueError("offline-replay destination must be an unshared file")
    serialized = stable_json(replay)
    if len(serialized.encode("utf-8")) > _MAX_REPLAY_BYTES:
        raise ValueError("offline replay exceeds the bounded output size")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def load_offline_replay(path: Path) -> OfflineReplay:
    """Load bounded normalized replay evidence without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive offline-replay filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("offline replay must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_REPLAY_BYTES:
        raise ValueError("offline replay must be a bounded unshared file")
    return OfflineReplay.model_validate_json(path.read_text(encoding="utf-8"))


def _load_replay_artifacts(
    run_dir: Path,
    *,
    config: AuditConfig | None = None,
) -> _ReplayArtifacts:
    differential_path = run_dir / "repository-suite-differential.json"
    configured = bool(
        config is not None and config.smart_contracts.repository_suite.fork_matrix_states
    )
    artifact_exists = (
        differential_path.exists()
        or differential_path.is_symlink()
        or differential_path.is_junction()
    )
    differential: RepositorySuiteDifferentialRun | None = None
    differential_limitation: str | None = None
    if artifact_exists:
        try:
            differential = _load_artifact(
                run_dir,
                "repository-suite-differential.json",
                RepositorySuiteDifferentialRun,
            )
        except (OSError, ValueError):
            differential_limitation = (
                "repository differential artifact failed bounded typed validation"
            )
    elif configured:
        differential_limitation = "configured repository differential artifact is missing"
    return _ReplayArtifacts(
        scanners=_load_artifact(run_dir, "scanner-results.json", _ScannerArtifact),
        projects=_load_artifact(run_dir, "solidity-projects.json", _SolidityProjectsArtifact),
        invariants=_load_artifact(run_dir, "solidity-invariants.json", _InvariantArtifact),
        harnesses=_load_artifact(
            run_dir,
            "invariant-harness-plan.json",
            _InvariantHarnessArtifact,
        ),
        invariant_results=_load_artifact(
            run_dir,
            "invariant-execution-results.json",
            _InvariantExecutionArtifact,
        ),
        candidates=_load_artifact(run_dir, "candidate-findings.json", _CandidateArtifact),
        reproductions=_load_artifact(
            run_dir,
            "reproduction-results.json",
            _ReproductionArtifact,
        ),
        differential=differential,
        differential_required=configured or artifact_exists,
        differential_limitation=differential_limitation,
    )


def _load_artifact[ModelT: BaseModel](
    run_dir: Path,
    name: str,
    model: type[ModelT],
) -> ModelT:
    path = run_dir / name
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError(f"offline replay artifact is missing or linked: {name}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"offline replay artifact is not a bounded unshared file: {name}")
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def _safe_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"offline replay {label} root may not be a link")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"offline replay {label} root must be a directory")
    return resolved


def _safe_work_directory(path: Path) -> Path:
    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing a sensitive offline-replay work directory")
    if path.is_symlink() or path.is_junction():
        raise ValueError("offline-replay work directory may not be a link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("offline-replay work directory must be a directory")
    return resolved


def _scanner_projection(run: ScannerRun) -> dict[str, object]:
    repository_executions: list[dict[str, object]] = []
    stable_execution_refs: dict[str, str] = {}
    stable_pre_inventory_ref = (
        canonical_sha256(_repository_suite_inventory_projection(run.repository_suite_inventory))
        if run.repository_suite_inventory is not None
        else None
    )
    stable_post_inventory_ref = (
        canonical_sha256(
            _repository_suite_inventory_projection(run.repository_suite_post_inventory)
        )
        if run.repository_suite_post_inventory is not None
        else None
    )
    for execution in run.repository_test_executions:
        payload = execution.model_dump(
            mode="json",
            exclude={
                "duration_seconds",
                "execution_sha256",
                "output_bytes",
                "output_sha256",
            },
        )
        if execution.inventory_sha256 is not None:
            payload["inventory_sha256"] = stable_pre_inventory_ref
            payload["post_inventory_sha256"] = stable_post_inventory_ref
        repository_executions.append(payload)
        stable_execution_refs[execution.execution_sha256] = canonical_sha256(payload)
    findings: list[dict[str, object]] = []
    for finding in run.findings:
        payload = finding.model_dump(mode="json")
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            reference = metadata.get("repository_test_execution_sha256")
            if isinstance(reference, str) and reference in stable_execution_refs:
                payload["metadata"] = {
                    **metadata,
                    "repository_test_execution_sha256": stable_execution_refs[reference],
                }
        findings.append(payload)
    findings.sort(key=lambda item: str(item["fingerprint"]))
    repository_suite = run.repository_suite_selection is not None
    return {
        "scanner": run.scanner,
        "status": run.status.value,
        "execution_evidence": run.execution_evidence.value,
        "version": run.version,
        "executable_sha256": run.executable_sha256,
        "raw_output_sha256": None if repository_suite else run.raw_output_sha256,
        "raw_output_bytes": 0 if repository_suite else run.raw_output_bytes,
        "process_exit_code": run.process_exit_code,
        "foundry_summary": (
            run.foundry_summary.model_dump(mode="json") if run.foundry_summary is not None else None
        ),
        "repository_suite_selection": (
            run.repository_suite_selection.model_dump(mode="json")
            if run.repository_suite_selection is not None
            else None
        ),
        "repository_suite_inventory": (
            _repository_suite_inventory_projection(run.repository_suite_inventory)
            if run.repository_suite_inventory is not None
            else None
        ),
        "repository_suite_post_inventory": (
            _repository_suite_inventory_projection(run.repository_suite_post_inventory)
            if run.repository_suite_post_inventory is not None
            else None
        ),
        "repository_suite_execution_policy": (
            run.repository_suite_execution_policy.model_dump(mode="json")
            if run.repository_suite_execution_policy is not None
            else None
        ),
        "repository_test_executions": repository_executions,
        "findings": findings,
        "isolation_backend": run.isolation_backend,
        "isolation_attestation_sha256": run.isolation_attestation_sha256,
        "repository_code_execution": run.repository_code_execution.value,
    }


def _repository_suite_inventory_projection(
    inventory: RepositorySuiteInventoryEvidence,
) -> dict[str, object]:
    """Project compiler inventory onto path-independent replay semantics."""

    projects: list[dict[str, object]] = []
    for project in inventory.projects:
        projects.append(
            {
                "project_root": project.project_root,
                "command_sha256": project.command_sha256,
                "process_exit_code": project.process_exit_code,
                "machine_output_validated": project.machine_output_validated,
                "stdout_sha256": project.stdout_sha256,
                "stdout_bytes": project.stdout_bytes,
                "stderr_sha256": project.stderr_sha256,
                "stderr_bytes": project.stderr_bytes,
                "normalized_build_info_sha256s": sorted(
                    artifact.normalized_sha256 for artifact in project.build_info_artifacts
                ),
                "normalized_build_info_bundle_sha256": (
                    project.normalized_build_info_bundle_sha256
                ),
                "parser_inventory_sha256": project.parser_inventory_sha256,
                "records": [record.model_dump(mode="json") for record in project.records],
                "normalized_inventory_sha256": project.normalized_inventory_sha256,
            }
        )
    return {
        "schema_version": inventory.schema_version,
        "phase": inventory.phase.value,
        "framework": inventory.framework.value,
        "repository_sha256": inventory.repository_sha256,
        "configuration_sha256": inventory.configuration_sha256,
        "tool_version": inventory.tool_version,
        "tool_sha256": inventory.tool_sha256,
        "compiler_version": inventory.compiler_version,
        "compiler_sha256": inventory.compiler_sha256,
        "isolation_backend": inventory.isolation_backend,
        "isolation_attestation_sha256": inventory.isolation_attestation_sha256,
        "execution_evidence": inventory.execution_evidence.value,
        "repository_code_execution": inventory.repository_code_execution.value,
        "projects": projects,
        "normalized_inventory_sha256": inventory.normalized_inventory_sha256,
        "inventory_record_count": inventory.inventory_record_count,
        "safety_claim": inventory.safety_claim,
    }


def _applicable_replay_kinds(artifacts: _ReplayArtifacts) -> list[ReplayComponentKind]:
    """Derive replay obligations from the sealed baseline rather than a fixed universe."""

    return sorted(
        {kind for kind, _identifier in _applicable_replay_components(artifacts)},
        key=lambda item: item.value,
    )


def _applicable_replay_components(
    artifacts: _ReplayArtifacts,
) -> set[tuple[ReplayComponentKind, str]]:
    """Derive every exact replay member from the sealed baseline."""

    applicable = {(ReplayComponentKind.SCANNER, run.scanner) for run in artifacts.scanners.runs}
    invariant_results = {
        (item.invariant_id, item.harness_name): item for item in artifacts.invariant_results.results
    }
    for harness in artifacts.harnesses.harnesses:
        result = invariant_results[(harness.invariant_id, harness.name)]
        applicable.add(
            (
                ReplayComponentKind.COUNTEREXAMPLE
                if result.status is InvariantExecutionStatus.COUNTEREXAMPLE
                else ReplayComponentKind.SAVED_TEST,
                f"{harness.invariant_id}/{harness.name}",
            )
        )
    applicable.update(
        (
            ReplayComponentKind.SAVED_TEST,
            f"{specification.candidate_id}/{specification.name}",
        )
        for specification in artifacts.reproductions.test_specifications
    )
    if artifacts.differential_required:
        applicable.add(
            (
                ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL,
                "repository-suite-differential",
            )
        )
    if not applicable:
        raise ValueError("offline replay has no sealed deterministic component to execute")
    return applicable


def expected_replay_kinds_for_run(run_dir: Path) -> set[ReplayComponentKind]:
    """Derive replay obligations from bounded sealed run artifacts."""

    root = _safe_directory(run_dir, "run")
    return set(_applicable_replay_kinds(_load_replay_artifacts(root)))


def expected_replay_components_for_run(
    run_dir: Path,
) -> set[tuple[ReplayComponentKind, str]]:
    """Derive exact replay member obligations from bounded sealed run artifacts."""

    root = _safe_directory(run_dir, "run")
    return _applicable_replay_components(_load_replay_artifacts(root))


def _configured_differential_projection(
    config: AuditConfig | None,
) -> dict[str, object]:
    """Project the operator-authored replay obligation without secret variable names."""

    if config is None:
        return {"configured": False}
    suite = config.smart_contracts.repository_suite
    states: list[dict[str, object]] = []
    for state in suite.fork_matrix_states:
        projected: dict[str, object] = {
            "state_id": state.state_id,
            "kind": state.kind,
            "expected_chain_id": state.expected_chain_id,
        }
        if state.kind == "clean_local":
            projected.update(
                {
                    "anvil_version": state.anvil_version,
                    "anvil_sha256": state.anvil_sha256,
                    "hardfork": state.hardfork,
                    "genesis_timestamp": state.genesis_timestamp,
                }
            )
        else:
            projected.update(
                {
                    "pinned_block_number": state.pinned_block_number,
                    "state_source_sha256": state.state_source_sha256,
                }
            )
        states.append(projected)
    return {
        "configured": bool(states),
        "configuration_sha256": suite.stable_hash(),
        "requested_state_ids": [item["state_id"] for item in states],
        "required_repetitions": suite.fork_matrix_repetitions,
        "fuzz_seed": suite.fuzz_seed,
        "states": states,
    }


def _clean_state_attestation_projection(
    attestation: RepositoryCleanStateAttestationEvidence,
) -> dict[str, object]:
    """Retain reusable clean-state facts without process- or timing-local identity."""

    return attestation.model_dump(
        mode="json",
        exclude={
            "attestation_sha256",
            "process_attestation_sha256",
            "startup_duration_seconds",
            "termination_method",
            "termination_duration_seconds",
        },
    )


def _stable_clean_state_source_sha256(
    attestation: RepositoryCleanStateAttestationEvidence,
) -> str:
    """Bind replay to stable clean-state semantics rather than one process instance."""

    return canonical_sha256(
        {
            "domain": "mmaudit.repository-clean-state-replay.v1",
            "attestation": _clean_state_attestation_projection(attestation),
        }
    )


def _workspace_copy_projection(
    evidence: RepositorySuiteWorkspaceCopyEvidence,
) -> dict[str, object]:
    """Project source-copy evidence without attempt-local descriptors or self hashes."""

    return evidence.model_dump(
        mode="json",
        exclude={
            "attempt_binding_sha256",
            "source_root_device_before",
            "source_root_inode_before",
            "source_root_device_after",
            "source_root_inode_after",
            "workspace_root_device_before",
            "workspace_root_inode_before",
            "workspace_root_device_after",
            "workspace_root_inode_after",
            "workspace_parent_device",
            "workspace_parent_inode",
            "copy_evidence_sha256",
        },
    )


def _workspace_lifecycle_projection(
    evidence: RepositorySuiteWorkspaceLifecycleEvidence,
) -> dict[str, object]:
    """Retain disposal policy, bounds, and non-retention without local identities."""

    return evidence.model_dump(
        mode="json",
        exclude={
            "attempt_binding_sha256",
            "workspace_copy_evidence_sha256",
            "scanner_execution_observation_sha256",
            "freshness_attestation_sha256",
            "attempt_root_device",
            "attempt_root_inode",
            "removal_duration_seconds",
            "lifecycle_evidence_sha256",
        },
    )


def _state_workspace_cleanup_projection(
    evidence: RepositorySuiteStateWorkspaceCleanupEvidence,
) -> dict[str, object]:
    """Retain aggregate disposal semantics without attempt hashes or timings."""

    projection = evidence.model_dump(
        mode="json",
        exclude={
            "attempt_cleanup_sequence_lifecycle_sha256s",
            "attempt_cumulative_removal_duration_seconds",
            "removal_duration_seconds",
            "aggregate_evidence_sha256",
        },
    )
    projection["attempt_cleanup_sequence"] = "reverse_attempt_order"
    return projection


def _repository_test_fork_rpc_scope_projection(
    scope: RepositoryTestForkRpcScopeEvidence,
) -> dict[str, object]:
    """Retain descriptor-scoped RPC semantics without attempt-local bindings."""

    return scope.model_dump(
        mode="json",
        exclude={
            "attempt_binding_sha256",
            "selection_sha256",
            "bridge_scope_snapshot_sha256",
            "evidence_sha256",
        },
    )


def _repository_differential_projection(
    result: RepositorySuiteDifferentialRun,
) -> dict[str, object]:
    """Project matrix evidence onto deterministic endpoint- and workspace-free semantics."""

    matrix = result.matrix
    if matrix is None:
        return {
            "schema_version": result.schema_version,
            "status": result.status.value,
            "configuration_sha256": result.configuration_sha256,
            "requested_state_ids": list(result.requested_state_ids),
            "required_repetitions": result.required_repetitions,
            "matrix": None,
            "limitation_count": len(result.limitations),
        }
    states: list[dict[str, object]] = []
    for state in matrix.states:
        clean_attestation = state.clean_state_attestation
        clean_projection = (
            _clean_state_attestation_projection(clean_attestation)
            if clean_attestation is not None
            else None
        )
        states.append(
            {
                "state_id": state.state_id,
                "kind": state.kind.value,
                "state_source_sha256": (
                    _stable_clean_state_source_sha256(clean_attestation)
                    if clean_attestation is not None
                    else state.state_source_sha256
                ),
                "expected_chain_id": state.expected_chain_id,
                "pinned_block_number": state.pinned_block_number,
                "observation_status": state.observation_status.value,
                "observed_chain_id": state.observed_chain_id,
                "observed_block_number": state.observed_block_number,
                "observed_block_hash": state.observed_block_hash,
                "clean_state_attestation": clean_projection,
            }
        )
    attempts: list[dict[str, object]] = []
    for attempt in matrix.attempts:
        run = attempt.scanner_run
        policy = run.repository_suite_execution_policy
        egress = run.fork_rpc_egress
        workspace_copy = run.repository_suite_workspace_copy
        executions = [
            execution.model_dump(
                mode="json",
                exclude={
                    "duration_seconds",
                    "execution_sha256",
                    "output_bytes",
                    "output_sha256",
                    "terminal_detail",
                },
            )
            for execution in run.repository_test_executions
        ]
        attempts.append(
            {
                "state_id": attempt.state_id,
                "attempt_index": attempt.attempt_index,
                "workspace_kind": attempt.workspace_kind,
                "workspace_disposal_policy_sha256": (attempt.workspace_disposal_policy_sha256),
                "scanner": run.scanner,
                "scanner_status": run.status.value,
                "execution_evidence": run.execution_evidence.value,
                "tool_version": run.version,
                "tool_sha256": run.executable_sha256,
                "process_exit_code": run.process_exit_code,
                "isolation_backend": run.isolation_backend,
                "isolation_attestation_sha256": run.isolation_attestation_sha256,
                "machine_output_validated": run.machine_output_validated,
                "repository_code_execution": run.repository_code_execution.value,
                "foundry_summary": (
                    run.foundry_summary.model_dump(mode="json")
                    if run.foundry_summary is not None
                    else None
                ),
                "selection": (
                    {
                        "repository_sha256": run.repository_suite_selection.repository_sha256,
                        "selection_sha256": run.repository_suite_selection.selection_sha256,
                        "configuration_sha256": (
                            run.repository_suite_selection.configuration_sha256
                        ),
                        "descriptor_sha256s": [
                            descriptor.descriptor_sha256
                            for descriptor in run.repository_suite_selection.tests
                        ],
                    }
                    if run.repository_suite_selection is not None
                    else None
                ),
                "execution_policy": (
                    policy.model_dump(mode="json") if policy is not None else None
                ),
                "workspace_copy": (
                    _workspace_copy_projection(workspace_copy)
                    if workspace_copy is not None
                    else None
                ),
                "workspace_lifecycle": _workspace_lifecycle_projection(attempt.workspace_lifecycle),
                "fork_rpc_egress": (
                    egress.model_dump(
                        mode="json",
                        exclude={
                            "bridge_snapshot_sha256",
                            "evidence_sha256",
                            "selected_test_scope_snapshot_sha256s",
                        },
                    )
                    if egress is not None
                    else None
                ),
                "repository_test_fork_rpc_scopes": [
                    _repository_test_fork_rpc_scope_projection(scope)
                    for scope in run.repository_test_fork_rpc_scopes
                ],
                "test_executions": executions,
            }
        )
    consensuses = [
        {
            "state_id": consensus.state_id,
            "descriptor_sha256": consensus.descriptor_sha256,
            "status": consensus.status.value,
            "observed_status": (
                consensus.observed_status.value if consensus.observed_status is not None else None
            ),
            "machine_result_sha256": consensus.machine_result_sha256,
            "inconclusive_reasons": [reason.value for reason in consensus.inconclusive_reasons],
        }
        for consensus in matrix.state_consensuses
    ]
    comparisons = [
        {
            "clean_state_id": comparison.clean_state_id,
            "pinned_state_id": comparison.pinned_state_id,
            "descriptor_sha256": comparison.descriptor_sha256,
            "classification": comparison.classification.value,
            "direction": (comparison.direction.value if comparison.direction is not None else None),
        }
        for comparison in matrix.comparisons
    ]
    state_workspace_cleanups = [
        _state_workspace_cleanup_projection(cleanup) for cleanup in matrix.state_workspace_cleanups
    ]
    return {
        "schema_version": result.schema_version,
        "status": result.status.value,
        "configuration_sha256": result.configuration_sha256,
        "requested_state_ids": list(result.requested_state_ids),
        "required_repetitions": result.required_repetitions,
        "limitation_count": len(result.limitations),
        "matrix": {
            "repository_sha256": matrix.repository_sha256,
            "selection_sha256": matrix.selection_sha256,
            "selection_configuration_sha256": (matrix.selection_configuration_sha256),
            "descriptor_sha256s": list(matrix.descriptor_sha256s),
            "required_repetitions": matrix.required_repetitions,
            "fuzz_seed": matrix.fuzz_seed,
            "execution_configuration_sha256": (matrix.execution_configuration_sha256),
            "fork_rpc_policy_sha256": matrix.fork_rpc_policy_sha256,
            "states": states,
            "attempts": attempts,
            "state_workspace_cleanups": state_workspace_cleanups,
            "state_consensuses": consensuses,
            "comparisons": comparisons,
            "safety_claim": matrix.safety_claim,
        },
    }


def _state_workspace_cleanups_are_qualifying(
    matrix: RepositorySuiteDifferentialMatrix,
) -> bool:
    """Recheck aggregate state cleanup joins, bounds, and non-retention."""

    try:
        state_ids = tuple(state.state_id for state in matrix.states)
        if tuple(cleanup.state_id for cleanup in matrix.state_workspace_cleanups) != state_ids:
            return False
        states_by_id = {state.state_id: state for state in matrix.states}
        for cleanup in matrix.state_workspace_cleanups:
            state = states_by_id[cleanup.state_id]
            state_attempts = tuple(
                attempt for attempt in matrix.attempts if attempt.state_id == cleanup.state_id
            )
            cleanup_order = tuple(reversed(state_attempts))
            expected_sequence = tuple(
                attempt.workspace_lifecycle.lifecycle_evidence_sha256 for attempt in cleanup_order
            )
            cumulative_entries: list[int] = []
            cumulative_durations: list[float] = []
            entry_total = 0
            duration_total = 0.0
            for attempt in cleanup_order:
                lifecycle = attempt.workspace_lifecycle
                entry_total += lifecycle.removed_entry_count
                duration_total = math.fsum((duration_total, lifecycle.removal_duration_seconds))
                cumulative_entries.append(entry_total)
                cumulative_durations.append(duration_total)
            auxiliary_count = 1 if state.kind.value == "clean_local" else 0
            if (
                not cleanup_order
                or cleanup.state_sha256 != state.state_sha256
                or cleanup.disposal_policy_sha256
                != REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256
                or cleanup.attempt_cleanup_sequence_lifecycle_sha256s != expected_sequence
                or cleanup.attempt_cumulative_removed_entry_counts != tuple(cumulative_entries)
                or len(cleanup.attempt_cumulative_removal_duration_seconds)
                != len(cumulative_durations)
                or any(
                    observed + 1e-9 < minimum
                    for observed, minimum in zip(
                        cleanup.attempt_cumulative_removal_duration_seconds,
                        cumulative_durations,
                        strict=True,
                    )
                )
                or cleanup.auxiliary_directory_count != auxiliary_count
                or cleanup.owned_directory_count != len(cleanup_order) + auxiliary_count
                or cleanup.removal_entry_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT
                or cleanup.removal_depth_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT
                or cleanup.removal_timeout_seconds
                != REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
                or cleanup.removed_entry_count < cumulative_entries[-1] + auxiliary_count
                or (auxiliary_count == 0 and cleanup.removed_entry_count != cumulative_entries[-1])
                or cleanup.removed_entry_count > cleanup.removal_entry_limit
                or cleanup.maximum_removed_depth
                < max(
                    attempt.workspace_lifecycle.maximum_removed_depth for attempt in cleanup_order
                )
                or cleanup.maximum_removed_depth > cleanup.removal_depth_limit
                or cleanup.removal_duration_seconds
                < cleanup.attempt_cumulative_removal_duration_seconds[-1]
                or cleanup.removal_duration_seconds > cleanup.removal_timeout_seconds
                or not cleanup.all_owned_descriptors_closed
                or not cleanup.all_owned_paths_absent
                or cleanup.private_path_retained
                or cleanup.rpc_endpoint_retained
                or cleanup.aggregate_evidence_sha256 != cleanup.expected_aggregate_evidence_sha256()
            ):
                return False
    except (IndexError, KeyError, TypeError, ValueError):
        return False
    return True


def _repository_differential_is_qualifying(
    result: RepositorySuiteDifferentialRun,
    *,
    config: AuditConfig,
    repository_sha256: str,
) -> bool:
    """Require complete real isolated execution behind one local read-only boundary."""

    matrix = result.matrix
    suite = config.smart_contracts.repository_suite
    if (
        result.status is not RepositoryDifferentialRunStatus.COMPLETE
        or matrix is None
        or result.configuration_sha256 != suite.stable_hash()
        or result.requested_state_ids != tuple(state.state_id for state in suite.fork_matrix_states)
        or result.required_repetitions != suite.fork_matrix_repetitions
        or matrix.repository_sha256 != repository_sha256
        or any(state.observation_status.value != "observed" for state in matrix.states)
    ):
        return False
    if not _state_workspace_cleanups_are_qualifying(matrix):
        return False
    for attempt in matrix.attempts:
        run = attempt.scanner_run
        egress = run.fork_rpc_egress
        selection = run.repository_suite_selection
        workspace_copy = run.repository_suite_workspace_copy
        lifecycle = attempt.workspace_lifecycle
        if (
            run.status is not ScannerStatus.SUCCESS
            or run.execution_evidence is not ExecutionEvidenceKind.REAL
            or run.repository_code_execution.value != "isolated"
            or run.isolation_backend is None
            or run.isolation_attestation_sha256 is None
            or not run.machine_output_validated
            or egress is None
            or egress.status is not RepositoryForkEgressStatus.ENFORCED
            or egress.boundary_kind != "trusted_read_only_loopback_bridge"
            or egress.network_scope != "single_loopback_origin"
            or egress.policy_sha256 != matrix.fork_rpc_policy_sha256
            or egress.transaction_capable_request_forwarded
            or egress.credentials_forwarded
            or egress.raw_payloads_retained
            or egress.rpc_endpoint_recorded
            or selection is None
            or selection.selection_sha256 != matrix.selection_sha256
            or selection.repository_sha256 != matrix.repository_sha256
            or attempt.workspace_kind != "fresh_disposable_copy"
            or attempt.workspace_disposal_policy_sha256
            != REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256
            or workspace_copy is None
            or workspace_copy.copy_policy_sha256 != REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256
            or workspace_copy.attempt_binding_sha256 != attempt.workspace_identity_sha256
            or workspace_copy.selection_sha256 != matrix.selection_sha256
            or workspace_copy.repository_sha256 != matrix.repository_sha256
            or not workspace_copy.workspace_created_exclusively
            or not workspace_copy.workspace_direct_child
            or not workspace_copy.audited_inventory_symlink_free
            or not workspace_copy.source_descriptor_custody_validated
            or not workspace_copy.workspace_descriptor_custody_validated
            or not workspace_copy.workspace_parent_descriptor_custody_validated
            or not workspace_copy.copy_matches_source
            or not workspace_copy.source_identity_stable
            or not workspace_copy.workspace_identity_stable
            or workspace_copy.workspace_removed
            or any(
                inventory_sha256 != matrix.repository_sha256
                for inventory_sha256 in (
                    workspace_copy.source_inventory_sha256_before,
                    workspace_copy.source_inventory_sha256_after,
                    workspace_copy.workspace_inventory_sha256_after_copy,
                    workspace_copy.workspace_inventory_sha256_after_execution,
                )
            )
            or (
                workspace_copy.source_root_device_before,
                workspace_copy.source_root_inode_before,
            )
            != (
                workspace_copy.source_root_device_after,
                workspace_copy.source_root_inode_after,
            )
            or (
                workspace_copy.workspace_root_device_before,
                workspace_copy.workspace_root_inode_before,
            )
            != (
                workspace_copy.workspace_root_device_after,
                workspace_copy.workspace_root_inode_after,
            )
            or lifecycle.status is not RepositorySuiteWorkspaceLifecycleStatus.VALIDATED
            or lifecycle.attempt_binding_sha256 != attempt.workspace_identity_sha256
            or lifecycle.selection_sha256 != matrix.selection_sha256
            or lifecycle.repository_sha256 != matrix.repository_sha256
            or (
                workspace_copy.workspace_parent_device,
                workspace_copy.workspace_parent_inode,
            )
            != (
                lifecycle.attempt_root_device,
                lifecycle.attempt_root_inode,
            )
            or lifecycle.workspace_copy_evidence_sha256 != workspace_copy.copy_evidence_sha256
            or lifecycle.scanner_execution_observation_sha256 != run.execution_observation_sha256
            or lifecycle.freshness_attestation_sha256
            != attempt.workspace_freshness_attestation_sha256
            or lifecycle.disposal_policy_sha256 != REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256
            or not lifecycle.attempt_root_created_exclusively
            or not lifecycle.attempt_root_direct_child
            or lifecycle.removal_entry_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT
            or lifecycle.removal_depth_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT
            or lifecycle.removal_timeout_seconds
            != REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
            or lifecycle.removed_entry_count > lifecycle.removal_entry_limit
            or lifecycle.maximum_removed_depth > lifecycle.removal_depth_limit
            or lifecycle.removal_duration_seconds > lifecycle.removal_timeout_seconds
            or not lifecycle.attempt_descriptor_closed
            or not lifecycle.workspace_path_absent
            or not lifecycle.attempt_path_absent
            or lifecycle.private_path_retained
            or lifecycle.rpc_endpoint_retained
            or run.execution_observation_sha256 is None
        ):
            return False
        try:
            if (
                workspace_copy.copy_evidence_sha256
                != workspace_copy.expected_copy_evidence_sha256()
                or lifecycle.freshness_attestation_sha256
                != lifecycle.expected_freshness_attestation_sha256()
                or lifecycle.lifecycle_evidence_sha256
                != lifecycle.expected_lifecycle_evidence_sha256()
                or run.execution_observation_sha256 != run.expected_execution_observation_sha256()
            ):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _repository_differential_execution_identity(
    result: RepositorySuiteDifferentialRun,
) -> tuple[ExecutionEvidenceKind, str | None, str | None]:
    matrix = result.matrix
    if matrix is None or not matrix.attempts:
        return ExecutionEvidenceKind.UNVERIFIED, None, None
    runs = [attempt.scanner_run for attempt in matrix.attempts]
    evidence = (
        ExecutionEvidenceKind.REAL
        if all(run.execution_evidence is ExecutionEvidenceKind.REAL for run in runs)
        else (
            ExecutionEvidenceKind.MOCK
            if any(run.execution_evidence is ExecutionEvidenceKind.MOCK for run in runs)
            else ExecutionEvidenceKind.UNVERIFIED
        )
    )
    backends = {run.isolation_backend for run in runs}
    attestations = {run.isolation_attestation_sha256 for run in runs}
    return (
        evidence,
        next(iter(backends)) if len(backends) == 1 else None,
        next(iter(attestations)) if len(attestations) == 1 else None,
    )


def _invariant_projection(result: InvariantExecutionResult) -> dict[str, object]:
    return result.model_dump(
        mode="json",
        exclude={
            "command",
            "duration_seconds",
            "source_path",
            "stdout_path",
            "stderr_path",
        },
    )


def _reproduction_projection(result: ReproductionResult) -> dict[str, object]:
    return result.model_dump(
        mode="json",
        exclude={
            "command",
            "duration_seconds",
            "generated_test_path",
            "regression_test_path",
            "stdout_path",
            "stderr_path",
        },
    )


def _invariant_source_path(
    harness: FoundryInvariantHarnessSpec,
    invariant: object | None,
) -> str | None:
    locations = getattr(invariant, "locations", None)
    if isinstance(locations, list) and locations:
        path = getattr(locations[0], "path", None)
        if isinstance(path, str):
            return path
    if harness.local_deployments:
        return harness.local_deployments[0].source_path
    return None


def _project_for_path(
    path: str,
    projects: list[SolidityProjectMetadata],
) -> SolidityProjectMetadata | None:
    try:
        normalized_path = normalize_relative_path(path)
    except ValueError:
        return None
    matches: list[tuple[int, SolidityProjectMetadata]] = []
    for project in projects:
        try:
            root = normalize_relative_path(project.project_root)
        except ValueError:
            continue
        if root == "." or normalized_path == root or normalized_path.startswith(f"{root}/"):
            matches.append((0 if root == "." else len(root), project))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _compared_component(
    *,
    kind: ReplayComponentKind,
    identifier: str,
    expected_state: str,
    observed_state: str,
    expected_projection: object,
    observed_projection: object,
    executed: bool,
    execution_evidence: ExecutionEvidenceKind,
    isolation_backend: str | None,
    isolation_attestation_sha256: str | None,
    blocked_limitation: str | None,
) -> OfflineReplayComponent:
    expected_sha256 = canonical_sha256(expected_projection)
    observed_sha256 = canonical_sha256(observed_projection)
    if not executed:
        return OfflineReplayComponent(
            kind=kind,
            identifier=identifier,
            status=ReplayComponentStatus.BLOCKED,
            executed=False,
            execution_evidence=execution_evidence,
            isolation_backend=isolation_backend,
            isolation_attestation_sha256=isolation_attestation_sha256,
            expected_state=expected_state,
            observed_state=observed_state,
            expected_sha256=expected_sha256,
            observed_sha256=observed_sha256,
            limitations=[blocked_limitation or "offline replay did not execute"],
        )
    return OfflineReplayComponent(
        kind=kind,
        identifier=identifier,
        status=(
            ReplayComponentStatus.MATCHED
            if observed_sha256 == expected_sha256
            else ReplayComponentStatus.DRIFTED
        ),
        executed=True,
        execution_evidence=execution_evidence,
        isolation_backend=isolation_backend,
        isolation_attestation_sha256=isolation_attestation_sha256,
        expected_state=expected_state,
        observed_state=observed_state,
        expected_sha256=expected_sha256,
        observed_sha256=observed_sha256,
    )


def _blocked_component(
    *,
    kind: ReplayComponentKind,
    identifier: str,
    expected_state: str,
    expected_projection: object,
    limitation: str,
) -> OfflineReplayComponent:
    return OfflineReplayComponent(
        kind=kind,
        identifier=identifier,
        status=ReplayComponentStatus.BLOCKED,
        executed=False,
        expected_state=expected_state,
        expected_sha256=canonical_sha256(expected_projection),
        limitations=[limitation],
    )


def _drifted_component(
    *,
    kind: ReplayComponentKind,
    identifier: str,
    expected_state: str,
    observed_state: str,
    expected_projection: object,
    observed_projection: object,
    executed: bool,
) -> OfflineReplayComponent:
    if not executed:
        return _blocked_component(
            kind=kind,
            identifier=identifier,
            expected_state=expected_state,
            expected_projection=expected_projection,
            limitation="unexpected replay component did not execute successfully",
        )
    return OfflineReplayComponent(
        kind=kind,
        identifier=identifier,
        status=ReplayComponentStatus.DRIFTED,
        executed=True,
        expected_state=expected_state,
        observed_state=observed_state,
        expected_sha256=canonical_sha256(expected_projection),
        observed_sha256=canonical_sha256(observed_projection),
    )
