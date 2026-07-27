"""Deterministic offline replay of sealed local run evidence."""

from __future__ import annotations

import asyncio
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    CandidateFinding,
    FalsificationDecision,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSuite,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
    StrictModel,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.verification import (
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import ForkReproductionRunner

_MAX_ARTIFACT_BYTES = 100_000_000
_MAX_REPLAY_BYTES = 100_000_000


class ReplayComponentKind(StrEnum):
    SCANNER = "scanner"
    SAVED_TEST = "saved_test"
    COUNTEREXAMPLE = "counterexample"


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
    missing_kinds: list[ReplayComponentKind] = Field(max_length=3)

    @model_validator(mode="after")
    def status_and_components_are_consistent(self) -> OfflineReplayPayload:
        keys = [(item.kind.value, item.identifier) for item in self.components]
        if keys != sorted(set(keys)):
            raise ValueError("offline replay components must be unique and sorted")
        if self.missing_kinds != sorted(set(self.missing_kinds), key=lambda item: item.value):
            raise ValueError("offline replay missing kinds must be unique and sorted")
        observed_kinds = {
            item.kind
            for item in self.components
            if item.status is ReplayComponentStatus.MATCHED and item.executed
        }
        expected_missing = sorted(
            set(ReplayComponentKind) - observed_kinds,
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
        config: AuditConfig,
        *,
        scanner_runner: ScannerReplayRunner | None = None,
        invariant_runner: InvariantReplayRunner | None = None,
        reproduction_runner: ReproductionReplayRunner | None = None,
    ) -> None:
        self.config = config
        self.scanner_runner = scanner_runner or ScannerRunner(config)
        self.invariant_runner = invariant_runner or FoundryInvariantRunner(
            config.reproduction,
            config.smart_contracts,
        )
        self.reproduction_runner = reproduction_runner or ForkReproductionRunner(
            config.reproduction,
            config.smart_contracts,
        )

    async def replay(
        self,
        *,
        manifest_path: Path,
        run_dir: Path,
        repository_root: Path,
        work_dir: Path,
    ) -> OfflineReplay:
        """Verify then replay sealed evidence without constructing a model provider."""

        verification = verify_run_evidence(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=repository_root,
            config=self.config,
        )
        if verification.status is not RunVerificationStatus.CURRENT:
            raise ValueError("offline replay refused stale run evidence")
        root = _safe_directory(run_dir, "run")
        repository = _safe_directory(repository_root, "repository")
        work_parent = _safe_work_directory(work_dir)
        artifacts = _load_replay_artifacts(root)

        components: list[OfflineReplayComponent] = []
        with tempfile.TemporaryDirectory(prefix="mmaudit-replay-", dir=work_parent) as temporary:
            private = Path(temporary)
            components.extend(
                await self._replay_scanners(
                    repository=repository,
                    private_dir=private / "scanners",
                    expected=artifacts.scanners.runs,
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
        observed_kinds = {
            item.kind
            for item in ordered
            if item.status is ReplayComponentStatus.MATCHED and item.executed
        }
        missing = sorted(
            set(ReplayComponentKind) - observed_kinds,
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
            missing_kinds=missing,
        )
        serialized = payload.model_dump(mode="json")
        return OfflineReplay.model_validate(
            {
                **serialized,
                "replay_sha256": canonical_sha256(serialized),
            }
        )

    async def _replay_scanners(
        self,
        *,
        repository: Path,
        private_dir: Path,
        expected: list[ScannerRun],
    ) -> list[OfflineReplayComponent]:
        expected_by_name = {item.scanner: item for item in expected}
        try:
            observed = await self.scanner_runner.run_all(
                repository,
                private_dir,
                skip_codeql=False,
                allow_fork_probing=False,
            )
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
                        blocked_limitation=(
                            None
                            if executed
                            else f"scanner replay did not execute successfully: {current.status.value}"
                        ),
                    )
                )
        return components

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


def _load_replay_artifacts(run_dir: Path) -> _ReplayArtifacts:
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
    findings = sorted(
        (finding.model_dump(mode="json") for finding in run.findings),
        key=lambda item: str(item["fingerprint"]),
    )
    return {
        "scanner": run.scanner,
        "status": run.status.value,
        "version": run.version,
        "executable_sha256": run.executable_sha256,
        "findings": findings,
        "isolation_backend": run.isolation_backend,
        "repository_code_execution": run.repository_code_execution.value,
    }


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
