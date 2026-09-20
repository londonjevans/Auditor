"""Source-local generated-property mutation orchestration; collected evidence grants no authority."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from mmaudit.benchmark.foundry_mutation_executor import canonical_foundry_inventory_mutation_test_id
from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    MutationScorecard,
    MutationSpecification,
    MutationSuiteObservation,
    MutationSuiteTestObservation,
    MutationSuiteTestStatus,
    _MutationRemovalBudget,
    _open_owned_mutation_root,
    build_property_bound_inventory_mutation_plan,
    mutation_repository_sha256,
    run_owned_mutation_campaign,
    score_planned_mutation_campaigns,
)
from mmaudit.isolation.provenance import isolation_attestation_sha256
from mmaudit.models.schemas import (
    EconomicSimulationKind,
    ExecutionEvidenceKind,
    FoundryInvariantHarnessSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    PropertyCorpus,
    RepositorySuiteInventoryPhase,
    SolidityProjectMetadata,
    SolidityProjectType,
    StrictModel,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.orchestration.mutation_reconstruction import (
    RetainedMutationCompilerManifest,
    RetainedMutationCompilerProject,
    reconstruct_mutation_project,
)
from mmaudit.release_io import read_file_evidence
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.workspace import audited_workspace_bindings_sha256
from mmaudit.scanners.base import (
    copy_scanner_workspace_with_custody,
    retain_scanner_workspace_source_custody,
    scanner_workspace_file_records,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryInventoryRunResult,
    run_foundry_test_inventory,
)
from mmaudit.solidity.invariant_execution import (
    FoundryInvariantRunner,
    InvariantExecutionBudget,
    _external_executable_version,
    _file_sha256,
    _validated_external_executable,
)
from mmaudit.solidity.properties import _corpus, generated_local_property_source
from mmaudit.solidity.reproduction import _external_executable

_SHA = r"^[0-9a-f]{64}$"


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class MutationPipelineLimits(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    maximum_campaigns: int = Field(default=16, ge=0, le=200)
    maximum_runner_attempts: int = Field(default=40, ge=0, le=500)
    inventory_timeout_seconds: float = Field(default=30, gt=0, le=3_600)
    stage_timeout_seconds: float = Field(default=900, gt=0, le=7_200)
    minimum_property_kill_score: float = Field(default=0.95, ge=0, le=1)


class MutationSourceFile(StrictModel):
    path: str = Field(min_length=1, max_length=1_000)
    sha256: str = Field(pattern=_SHA)
    size: int = Field(ge=0)

    @model_validator(mode="after")
    def canonical_source_path(self) -> Self:
        if normalize_relative_path(self.path) != self.path or self.path == ".":
            raise ValueError("mutation source binding path is not canonical")
        return self


class GeneratedMutationWorkspace(StrictModel):
    """Exact additive lineage; a generated workspace never substitutes for the audited source."""

    original_files: list[MutationSourceFile] = Field(min_length=1, max_length=100_000)
    generated_files: list[MutationSourceFile] = Field(min_length=1, max_length=10_000)
    original_sha256: str = Field(pattern=_SHA)
    augmented_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_additions_and_both_identities(self) -> Self:
        for records in (self.original_files, self.generated_files):
            paths = [r.path for r in records]
            if paths != sorted(set(paths)):
                raise ValueError("mutation workspace files must be unique and sorted")
        originals = {r.path: r for r in self.original_files}
        for generated in self.generated_files:
            if generated.path in originals and originals[generated.path] != generated:
                raise ValueError("generated mutation harness cannot replace existing source")
        combined = {**originals, **{r.path: r for r in self.generated_files}}
        for expected, records in (
            (self.original_sha256, self.original_files),
            (self.augmented_sha256, list(combined.values())),
        ):
            if expected != audited_workspace_bindings_sha256([r.model_dump() for r in records]):
                raise ValueError("mutation original/augmented inventory digest differs")
        return self


class CollectedMutationExecution(StrictModel):
    """Retained original runner result and private raw artifacts, without runtime admission."""

    mutation_id: str
    stage: Literal["baseline", "mutant"]
    artifact_path: str
    result: InvariantExecutionResult

    @model_validator(mode="after")
    def canonical_artifact_path(self) -> Self:
        if (
            normalize_relative_path(self.artifact_path) != self.artifact_path
            or self.artifact_path == "."
        ):
            raise ValueError("mutation execution artifact path is not canonical")
        return self


class MutationProjectExecution(StrictModel):
    project_root: str
    property_ids: list[str] = Field(max_length=10_000)
    projected_corpus_hash: str = Field(pattern=_SHA)
    workspace: GeneratedMutationWorkspace | None = None
    plan: MutationApplicabilityPlan | None = None
    campaigns: list[MutationCampaignEvidence] = Field(default_factory=list, max_length=200)
    score: MutationScorecard | None = None
    executions: list[CollectedMutationExecution] = Field(default_factory=list, max_length=500)
    compiler_input_files: list[MutationSourceFile] = Field(default_factory=list, max_length=100_000)
    limitations: list[str] = Field(default_factory=list, max_length=1_000)
    source_preserved: bool = False
    workspace_disposed: bool = False

    @model_validator(mode="after")
    def project_results_bind_the_actual_augmented_plan(self) -> Self:
        if normalize_relative_path(self.project_root) != self.project_root:
            raise ValueError("mutation project root is not canonical")
        if self.property_ids != sorted(set(self.property_ids)):
            raise ValueError("mutation project property IDs must be unique and sorted")
        if self.plan is None:
            if self.campaigns or self.executions or self.score is not None:
                raise ValueError("mutation results require the exact prepared plan")
        else:
            if (
                self.workspace is None
                or self.plan.discovery is None
                or self.plan.discovery.project_root != self.project_root
                or self.plan.source_repository_sha256 != self.workspace.augmented_sha256
                or self.plan.property_corpus_hash != self.projected_corpus_hash
                or list(self.plan.property_repositories) != self.property_ids
            ):
                raise ValueError(
                    "mutation plan lost original/generated workspace or corpus lineage"
                )
            expected = score_planned_mutation_campaigns(
                plan=self.plan,
                campaigns=self.campaigns,
                minimum_property_kill_score=self.score.minimum_property_kill_score
                if self.score is not None
                else 0.95,
            )
            if self.score != expected:
                raise ValueError("pipeline mutation score must retain all unverified planned pairs")
            mapping = self.plan.property_tests
            if mapping is None:
                raise ValueError("pipeline mutations require exact generated property mappings")
            expected_harnesses = {h.name: h.specification_sha256() for h in mapping.harnesses}
            identities = [(e.mutation_id, e.stage, e.result.harness_name) for e in self.executions]
            if len(identities) != len(set(identities)) or any(
                e.mutation_id not in {s.id for s in self.plan.specifications}
                or expected_harnesses.get(e.result.harness_name) != e.result.harness_spec_sha256
                for e in self.executions
            ):
                raise ValueError("collected mutation executions changed planned test identities")
        if not self.limitations and (
            self.plan is None or not self.source_preserved or not self.workspace_disposed
        ):
            raise ValueError("incomplete mutation lifecycle requires an explicit limitation")
        return self


class MutationPipelineArtifact(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["source_local_mutation_pipeline"] = "source_local_mutation_pipeline"
    evidence_authority: Literal["COLLECTED_UNATTESTED"] = "COLLECTED_UNATTESTED"
    corpus_hash: str = Field(pattern=_SHA)
    corpus: PropertyCorpus
    expected_source_sha256: str | None = Field(default=None, pattern=_SHA)
    property_ids: list[str] = Field(max_length=10_000)
    unresolved_property_ids: list[str] = Field(max_length=10_000)
    projects: list[MutationProjectExecution] = Field(max_length=1_000)
    limits: MutationPipelineLimits
    runner_attempts: int = Field(default=0, ge=0, le=500)
    limitations: list[str] = Field(default_factory=list, max_length=1_000)
    execution_validated: Literal[False] = False
    qualification_eligible: Literal[False] = False
    audit_complete: Literal[False] = False

    @model_validator(mode="after")
    def preserve_complete_property_population(self) -> Self:
        if self.corpus_hash != self.corpus.corpus_hash or self.property_ids != [
            p.id for p in self.corpus.properties
        ]:
            raise ValueError("mutation pipeline lost the exact original property corpus")
        if (
            self.runner_attempts > self.limits.maximum_runner_attempts
            or sum(len(p.campaigns) for p in self.projects) > self.limits.maximum_campaigns
        ):
            raise ValueError("mutation pipeline exceeded its shared execution limits")
        for project in self.projects:
            projected_corpus = _corpus(
                [p for p in self.corpus.properties if p.id in project.property_ids],
                self.corpus.limitations,
            )
            if project.projected_corpus_hash != projected_corpus.corpus_hash:
                raise ValueError("mutation project corpus is not the exact original projection")
            if (
                project.workspace is not None
                and project.workspace.original_sha256 != self.expected_source_sha256
            ):
                raise ValueError("mutation project lost its original audited-source identity")
            if (
                project.score is not None
                and project.score.minimum_property_kill_score
                != self.limits.minimum_property_kill_score
            ):
                raise ValueError("mutation project score changed the declared comparison threshold")
        projected = [p for project in self.projects for p in project.property_ids]
        if (
            self.property_ids != sorted(set(self.property_ids))
            or self.unresolved_property_ids != sorted(set(self.unresolved_property_ids))
            or len(projected) != len(set(projected))
            or set(projected) & set(self.unresolved_property_ids)
            or set(projected) | set(self.unresolved_property_ids) != set(self.property_ids)
        ):
            raise ValueError("mutation pipeline must retain every original property exactly once")
        roots = [p.project_root for p in self.projects]
        if roots != sorted(set(roots)):
            raise ValueError("mutation pipeline project roots must be unique and sorted")
        return self


def _file_records(root: Path) -> list[MutationSourceFile]:
    return [
        MutationSourceFile(path=r.relative_path, sha256=r.sha256, size=r.size)
        for r in scanner_workspace_file_records(root)
    ]


def _write_generated(workspace: Path, path: str, content: bytes) -> MutationSourceFile:
    record = MutationSourceFile(
        path=path, sha256=hashlib.sha256(content).hexdigest(), size=len(content)
    )
    target = workspace / path
    parent = workspace
    for part in PurePosixPath(path).parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError("generated mutation source parent cannot be a link")
        parent.mkdir(mode=0o700, exist_ok=True)
    if target.exists() or target.is_symlink():
        existing = read_file_evidence(
            evidence_root=workspace, relative_path=path, max_bytes=max(1, len(content))
        )
        if existing.content != content:
            raise ValueError("generated mutation harness collides with existing source")
    else:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return record


def _retain_compiler_inputs(
    private: Path, inventory: FoundryInventoryRunResult
) -> list[MutationSourceFile]:
    """Persist original reconstruction metadata with every exact compiler input binding."""

    bindings: list[MutationSourceFile] = []

    def write(path: str, raw: bytes) -> ManifestFileBinding:
        record = _write_generated(private, path, raw)
        bindings.append(record)
        return ManifestFileBinding(**record.model_dump())

    evidence = write("compiler-inputs/evidence.json", inventory.evidence.model_dump_json().encode())
    projects = []
    for index, snapshot in enumerate(inventory.compiler_inputs):
        prefix = f"compiler-inputs/project-{index:04d}"
        projects.append(
            RetainedMutationCompilerProject(
                project_root=snapshot.project_root,
                forge_list=write(prefix + "/forge-list.json", snapshot.forge_list_json),
                parser_limits=write(
                    prefix + "/parser-limits.json",
                    snapshot.parser_limits.model_dump_json().encode(),
                ),
                build_info=[
                    write(f"{prefix}/build-{i:04d}.json", raw)
                    for i, raw in enumerate(snapshot.build_info_jsons)
                ],
                sources=[
                    write(prefix + "/sources/" + source.path, source.content)
                    for source in snapshot.sources
                ],
            )
        )
    manifest = RetainedMutationCompilerManifest(
        evidence=evidence,
        projects=projects,
        accounted_output_bytes=inventory.accounted_output_bytes,
        generated_artifact_bytes=inventory.generated_artifact_bytes,
    )
    write("compiler-inputs/manifest.json", manifest.model_dump_json().encode())
    return sorted(bindings, key=lambda b: b.path)


@dataclass
class _LocalInvariantMutationExecutor:
    runner: FoundryInvariantRunner
    project: SolidityProjectMetadata
    plan: MutationApplicabilityPlan
    artifact_root: Path
    execution_root: Path
    budget: InvariantExecutionBudget
    executions: list[CollectedMutationExecution]

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: MutationSpecification,
    ) -> MutationSuiteObservation:
        assert self.plan.property_tests is not None and self.plan.compiler_inventory is not None
        mapping = self.plan.property_tests
        project_inventory = next(
            p
            for p in self.plan.compiler_inventory.projects
            if p.project_root == self.project.project_root
        )
        observations: list[list[MutationSuiteTestObservation]] = []
        for stage, workspace in (("baseline", baseline_workspace), ("mutant", mutant_workspace)):
            tests: list[MutationSuiteTestObservation] = []
            for harness in mapping.harnesses:
                relative = f"{specification.id}/{stage}/{harness.name}"
                output = self.execution_root / relative
                result = self.runner.run(
                    repository_root=workspace,
                    project=self.project,
                    specification=harness,
                    private_dir=output,
                    execution_budget=self.budget,
                )
                retained = self.artifact_root / relative
                retained.mkdir(mode=0o700, parents=True)
                _write_generated(retained, "result.json", result.model_dump_json().encode())
                if result.source_path is not None:
                    original_source = read_file_evidence(
                        evidence_root=output, relative_path=result.source_path, max_bytes=4_000_000
                    )
                    if original_source.binding.sha256 != result.source_sha256:
                        raise ValueError("local mutation original generated source changed")
                    _write_generated(retained, result.source_path, original_source.content)
                raw_attempts = []
                for attempt in result.attempt_evidence:
                    for path, digest in (
                        (attempt.stdout_path, attempt.stdout_sha256),
                        (attempt.stderr_path, attempt.stderr_sha256),
                    ):
                        raw = read_file_evidence(
                            evidence_root=output,
                            relative_path=path,
                            max_bytes=self.runner.reproduction.max_output_bytes,
                        )
                        if raw.binding.sha256 != digest:
                            raise ValueError("local mutation original attempt output changed")
                        _write_generated(retained, path, raw.content)
                        if path == attempt.stdout_path:
                            raw_attempts.append(raw.content)
                self.executions.append(
                    CollectedMutationExecution(
                        mutation_id=specification.id,
                        stage=stage,
                        artifact_path="observations/" + relative,
                        result=result,
                    )
                )
                if result.status not in {
                    InvariantExecutionStatus.PASSED,
                    InvariantExecutionStatus.COUNTEREXAMPLE,
                }:
                    raise ValueError("local mutation invariant execution did not complete")
                if (
                    len(result.attempt_evidence) != max(2, self.runner.reproduction.repetitions)
                    or result.attempts != len(result.attempt_evidence)
                    or result.successful_attempts != len(result.attempt_evidence)
                    or (result.runs, result.depth, result.seed)
                    != (harness.runs, harness.depth, harness.seed)
                    or result.source_path is None
                    or not result.replay_confirmed
                    or result.harness_spec_sha256 != harness.specification_sha256()
                    or result.executable_sha256 != self.plan.compiler_inventory.tool_sha256
                    or result.compiler_sha256 != self.plan.compiler_inventory.compiler_sha256
                    or result.execution_observation_sha256
                    != result.expected_execution_observation_sha256()
                ):
                    raise ValueError(
                        "local mutation execution omitted exact original attempt evidence"
                    )
                prefix = f"MMAuditInvariant_{harness.name}"
                generated = generated_local_property_source(
                    harness,
                    project_root=self.project.project_root,
                    expected_chain_id=mapping.expected_chain_id,
                )
                assert generated is not None
                expected = {
                    r.declaration_signature: r
                    for r in project_inventory.records
                    if r.execution_path == generated[0] and r.execution_suite_name == prefix
                }
                expected_source = hashlib.sha256(generated[1]).hexdigest()
                if not expected or result.source_sha256 != expected_source:
                    raise ValueError(
                        "local mutation generated source differs from its compiler binding"
                    )
                suite_name = (
                    str(PurePosixPath(generated[0]).relative_to(self.project.project_root))
                    + ":"
                    + prefix
                )
                outcomes = []
                for attempt, raw_bytes in zip(result.attempt_evidence, raw_attempts, strict=True):
                    if (
                        not attempt.machine_output_validated
                        or not attempt.fresh_workspace
                        or attempt.source_sha256 != expected_source
                        or attempt.status != result.status
                    ):
                        raise ValueError(
                            "local mutation replay is incomplete or changed its source"
                        )
                    payload = json.loads(raw_bytes)
                    if not isinstance(payload, dict) or set(payload) != {suite_name}:
                        raise ValueError("local mutation output differs from its compiler suite")
                    suite = payload[suite_name]
                    observed = suite.get("test_results") if isinstance(suite, dict) else None
                    if not isinstance(observed, dict) or set(observed) != set(expected):
                        raise ValueError(
                            "local mutation output differs from its compiler test population"
                        )
                    if any(
                        not isinstance(v, dict) or v.get("status") not in {"Success", "Failure"}
                        for v in observed.values()
                    ):
                        raise ValueError("local mutation test outcome is unclassified")
                    statuses = {name: value["status"] for name, value in observed.items()}
                    if attempt.process_exit_code != (1 if "Failure" in statuses.values() else 0):
                        raise ValueError("local mutation test status and process exit disagree")
                    outcomes.append(statuses)
                if any(outcome != outcomes[0] for outcome in outcomes):
                    raise ValueError("local mutation individual test outcomes changed on replay")
                for name, status in outcomes[0].items():
                    tests.append(
                        MutationSuiteTestObservation(
                            test_id=canonical_foundry_inventory_mutation_test_id(
                                expected[name], inventory_sha256=mapping.inventory_sha256
                            ),
                            status=MutationSuiteTestStatus.PASSED
                            if status == "Success"
                            else MutationSuiteTestStatus.FAILED,
                        )
                    )
            observations.append(sorted(tests, key=lambda test: test.test_id))
        ids = sorted(t.test_id for t in observations[0])
        return MutationSuiteObservation.sealed(
            mutation_id=specification.id,
            baseline_source_sha256=mutation_repository_sha256(baseline_workspace),
            mutant_source_sha256=mutation_repository_sha256(mutant_workspace),
            suite_selection_sha256=MutationSuiteObservation.calculate_selection_sha256(ids),
            executor_sha256=self.plan.approved_executor_sha256,
            isolation_policy_sha256=self.plan.approved_isolation_policy_sha256,
            baseline_execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
            mutant_execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
            baseline_compilation_succeeded=True,
            mutant_compilation_succeeded=True,
            baseline_tests=observations[0],
            mutant_tests=observations[1],
        )


def _tools(
    runner: FoundryInvariantRunner,
    source: Path,
    private: Path,
    budget: InvariantExecutionBudget,
) -> tuple[Path, Path, str, str]:
    budget.remaining_seconds()
    runner._verify_managed_selection()
    if runner.backend is None:
        raise ValueError(
            "source-local mutations require the existing prepared invariant tool selection"
        )
    if runner._managed is not None:
        if not runner._managed.enabled:
            raise ValueError("managed mutation execution requires enabled generated invariants")
        runner._managed.verify_roots(source, private)
        versions = runner._managed.preflight(runner.backend, private, execution_budget=budget)
        runner._verify_managed_selection()
        forge = runner._managed.tool(ManagedToolchainRole.FORGE)[0]
        solc = runner._managed.tool(ManagedToolchainRole.SOLC)[0]
        version = versions[ManagedToolchainRole.FORGE.value]
        compiler = versions[ManagedToolchainRole.SOLC.value]
    else:
        selected_forge = runner.forge_executable or _external_executable(source, "forge")
        if selected_forge is None or runner.solc_executable is None:
            raise ValueError("source-local mutations require explicit external tools")
        forge = _validated_external_executable(source, selected_forge)
        solc = _validated_external_executable(source, runner.solc_executable)
        version = _external_executable_version(
            forge, backend=runner.backend, private_dir=private, absolute_deadline=budget.deadline
        )
        budget.remaining_seconds()
        compiler = _external_executable_version(
            solc, backend=runner.backend, private_dir=private, absolute_deadline=budget.deadline
        )
    budget.remaining_seconds()
    matches = re.findall(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", compiler)
    if len(set(matches)) != 1:
        raise ValueError("source-local compiler version is ambiguous")
    return forge, solc, version, matches[0]


def _run_project(
    *,
    source: Path,
    exclusion: Path | None,
    expected_source_sha256: str,
    private: Path,
    runner: FoundryInvariantRunner,
    project: SolidityProjectMetadata,
    corpus: PropertyCorpus,
    harnesses: list[FoundryInvariantHarnessSpec],
    limits: MutationPipelineLimits,
    budget: InvariantExecutionBudget,
    remaining_campaigns: int,
) -> MutationProjectExecution:
    values: dict[str, Any] = dict(
        project_root=project.project_root,
        property_ids=[p.id for p in corpus.properties],
        projected_corpus_hash=corpus.corpus_hash,
    )
    limitations: list[str] = []
    root = None
    child = None
    source_custody = None
    plan: MutationApplicabilityPlan | None = None
    campaigns: list[MutationCampaignEvidence] = []
    executions: list[CollectedMutationExecution] = []
    phase = "admission"
    try:
        budget.remaining_seconds()
        private.mkdir(parents=True, mode=0o700)
        root = _open_owned_mutation_root(private)
        child = root.create_child("mmaudit-generated-" + uuid.uuid4().hex)
        child_path = root.path / child.name
        phase = "source custody"
        source_custody = retain_scanner_workspace_source_custody(
            source, private_dir=exclusion, allow_custom_private_exclusion=exclusion is not None
        )
        if source_custody.source_inventory_sha256_before != expected_source_sha256:
            raise ValueError("audited source changed before mutation preparation")
        phase = "prepared tools"
        forge, solc, version, compiler = _tools(runner, source, child_path / "probe", budget)
        phase = "generated workspace"
        workspace = child_path / "source"
        budget.remaining_seconds()
        copy = copy_scanner_workspace_with_custody(
            source,
            workspace,
            private_dir=exclusion or source / ".mmaudit",
            allow_custom_private_exclusion=exclusion is not None,
        )
        copied = copy.finalize()
        if copied.workspace_inventory_sha256_after_copy != expected_source_sha256:
            raise ValueError("mutation copy differs from original audited source")
        originals = _file_records(workspace)
        generated = []
        for harness in harnesses:
            selected = generated_local_property_source(
                harness,
                project_root=project.project_root,
                expected_chain_id=runner.reproduction.expected_chain_id,
            )
            if selected is None:
                raise ValueError("mutation harness requires source-local deployment")
            generated.append(_write_generated(workspace, *selected))
        augmented_sha = mutation_repository_sha256(workspace)
        lineage = GeneratedMutationWorkspace(
            original_files=originals,
            generated_files=sorted(generated, key=lambda r: r.path),
            original_sha256=expected_source_sha256,
            augmented_sha256=augmented_sha,
        )
        values["workspace"] = lineage
        copied_solc = child_path / "solc"
        shutil.copyfile(solc, copied_solc)
        copied_solc.chmod(0o500)
        runner._verify_managed_selection()
        configuration_sha = _hash(
            {
                "smart_contracts": runner.smart_contracts.model_dump(mode="json"),
                "reproduction": runner.reproduction.model_dump(mode="json"),
                "limits": limits.model_dump(mode="json"),
                "corpus_hash": corpus.corpus_hash,
            }
        )
        assert runner.backend is not None
        phase = "compiler inventory"
        inventory = run_foundry_test_inventory(
            workspace=workspace,
            private_dir=child_path,
            projects=(project,),
            phase=RepositorySuiteInventoryPhase.PRE_EXECUTION,
            forge_executable=forge,
            copied_solc=copied_solc,
            repository_sha256=augmented_sha,
            configuration_sha256=configuration_sha,
            tool_version=version,
            tool_sha256=_file_sha256(forge),
            compiler_version=compiler,
            compiler_sha256=_file_sha256(solc),
            backend=runner.backend,
            timeout_seconds=min(limits.inventory_timeout_seconds, budget.remaining_seconds()),
            absolute_deadline=budget.deadline,
            verify_execution_inputs=runner._verify_managed_selection,
        )
        runner._verify_managed_selection()
        budget.remaining_seconds()
        values["compiler_input_files"] = _retain_compiler_inputs(private, inventory)
        phase = "property plan"
        target_paths = tuple(
            sorted(
                {
                    PurePosixPath(e.location.path).relative_to(project.project_root).as_posix()
                    for prop in corpus.properties
                    for e in prop.source_evidence
                }
            )
        )
        plan = build_property_bound_inventory_mutation_plan(
            inventory_result=inventory,
            project_root=project.project_root,
            target_paths=target_paths,
            corpus=corpus,
            harnesses=harnesses,
            repository_id="audited-source",
            approved_executor_sha256=_file_sha256(Path(__file__)),
            approved_isolation_policy_sha256=_hash(
                {
                    "evidence_authority": "COLLECTED_UNATTESTED",
                    "backend": runner.backend.name,
                    "attestation": isolation_attestation_sha256(runner.backend),
                }
            ),
            expected_chain_id=runner.reproduction.expected_chain_id,
        )
        values["plan"] = plan
        phase = "retained compiler reconstruction"
        prepared = MutationProjectExecution(
            **values,
            score=score_planned_mutation_campaigns(
                plan=plan,
                campaigns=[],
                minimum_property_kill_score=limits.minimum_property_kill_score,
            ),
            limitations=["Source-local mutation campaign lifecycle is not finalized."],
        )
        reconstructed = reconstruct_mutation_project(
            project=prepared,
            expected_project_sha256=canonical_sha256(prepared.model_dump(mode="json")),
            artifact_root=private,
            absolute_deadline=budget.deadline,
        )
        if reconstructed.plan != plan:
            raise ValueError("retained mutation plan differs before campaign execution")
        runner._verify_managed_selection()
        budget.remaining_seconds()
        phase = "owned campaigns"
        attempts = max(2, runner.reproduction.repetitions)
        per_campaign = (
            2
            * attempts
            * sum(
                1
                + (
                    len(h.required_action_sequence)
                    if h.economic_template is EconomicSimulationKind.STATE_ORDERING
                    else 0
                )
                for h in harnesses
            )
        )
        owned = child_path / "campaigns"
        owned.mkdir(mode=0o700)
        executor = _LocalInvariantMutationExecutor(
            runner,
            project,
            plan,
            private / "observations",
            child_path / "execution",
            budget,
            executions,
        )
        for specification in plan.specifications:
            if (
                len(campaigns) >= remaining_campaigns
                or time.monotonic() >= budget.deadline
                or budget.maximum_attempts - budget.attempts < per_campaign
            ):
                limitations.append(
                    "Mutation campaign budget exhausted; remaining candidates are inconclusive."
                )
                break
            campaigns.append(
                run_owned_mutation_campaign(
                    source_repository=workspace,
                    private_root=owned,
                    plan=plan,
                    mutation_id=specification.id,
                    executor=executor,
                )
            )
        if any(c.failure_kind is not None for c in campaigns):
            limitations.append(
                "One or more source-local mutation campaigns failed; no runtime credit."
            )
        if mutation_repository_sha256(workspace) != augmented_sha:
            raise ValueError("generated mutation workspace changed outside planned campaigns")
    except (OSError, ValueError, RuntimeError) as exc:
        limitations.append(f"Source-local mutation {phase} incomplete: {type(exc).__name__}.")
    finally:
        try:
            if source_custody is not None:
                values["source_preserved"] = source_custody.finalize() == expected_source_sha256
                if not values["source_preserved"]:
                    limitations.append(
                        "Original audited-source identity differs from the selected source."
                    )
        except (OSError, ValueError):
            limitations.append("Original audited-source custody could not be revalidated.")
        try:
            if child is not None:
                values["workspace_disposed"] = child.dispose(_MutationRemovalBudget())
                if not values["workspace_disposed"]:
                    limitations.append("Owned generated-workspace absence could not be verified.")
        except (OSError, ValueError):
            limitations.append("Owned generated-workspace disposal could not be verified.")
            if child is not None:
                child.close()
        finally:
            if root is not None:
                root.close()
    values["campaigns"] = campaigns
    values["executions"] = executions
    values["score"] = (
        None
        if plan is None
        else score_planned_mutation_campaigns(
            plan=plan,
            campaigns=campaigns,
            minimum_property_kill_score=limits.minimum_property_kill_score,
        )
    )
    return MutationProjectExecution(**values, limitations=sorted(set(limitations)))


def run_source_local_mutation_pipeline(
    *,
    repository_root: Path,
    repository_exclusion_root: Path | None,
    expected_source_sha256: str | None,
    private_dir: Path,
    corpus: PropertyCorpus,
    harnesses: list[FoundryInvariantHarnessSpec],
    projects: list[SolidityProjectMetadata],
    invariant_runner: FoundryInvariantRunner,
    enabled: bool,
    limits: MutationPipelineLimits | None = None,
) -> MutationPipelineArtifact:
    """Automatically collect local mutation evidence, with complete scope and no authority uplift."""

    corpus = PropertyCorpus.model_validate(corpus.model_dump(mode="python"))
    if type(enabled) is not bool or (
        expected_source_sha256 is not None
        and (
            type(expected_source_sha256) is not str
            or re.fullmatch(_SHA, expected_source_sha256) is None
        )
    ):
        raise ValueError("mutation pipeline enablement or original source identity is invalid")
    harnesses = [
        FoundryInvariantHarnessSpec.model_validate(h.model_dump(mode="python")) for h in harnesses
    ]
    projects = [
        SolidityProjectMetadata.model_validate(p.model_dump(mode="python")) for p in projects
    ]
    selected_limits = MutationPipelineLimits.model_validate(
        (limits or MutationPipelineLimits()).model_dump()
    )
    identifiers = [p.id for p in corpus.properties]
    values: dict[str, Any] = dict(
        corpus=corpus,
        corpus_hash=corpus.corpus_hash,
        property_ids=identifiers,
        expected_source_sha256=expected_source_sha256,
        limits=selected_limits,
    )
    if (
        not enabled
        or not identifiers
        or expected_source_sha256 is None
        or type(invariant_runner) is not FoundryInvariantRunner
    ):
        return MutationPipelineArtifact(
            **values,
            unresolved_property_ids=identifiers,
            projects=[],
            limitations=[
                "Source-local mutation execution is disabled or lacks typed source/runtime prerequisites."
            ],
        )
    by_name = {h.name: h for h in harnesses}
    if len(by_name) != len(harnesses):
        raise ValueError("mutation pipeline harness identities are ambiguous")
    selected = {
        p.project_root: p
        for p in projects
        if p.project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}
    }
    if len({p.project_root for p in projects}) != len(projects):
        raise ValueError("mutation pipeline project identities are ambiguous")
    if (
        not private_dir.is_absolute()
        or ".." in private_dir.parts
        or any(p.is_symlink() for p in (private_dir, *private_dir.parents))
    ):
        raise ValueError("mutation pipeline requires an absolute unlinked private directory")
    if private_dir.is_relative_to(repository_root) and (
        repository_exclusion_root is None
        or not private_dir.is_relative_to(repository_exclusion_root)
    ):
        raise ValueError("mutation pipeline output lies outside the selected source exclusion")
    grouped: dict[str, list[Any]] = {}
    unresolved = []
    for prop in corpus.properties:
        harness = by_name.get(prop.harness_name)
        candidates = [
            root
            for root in selected
            if all(
                PurePosixPath(e.location.path).is_relative_to(root) for e in prop.source_evidence
            )
        ]
        if (
            harness is None
            or not harness.local_deployments
            or not prop.source_evidence
            or not candidates
        ):
            unresolved.append(prop.id)
            continue
        root = max(candidates, key=lambda value: len(PurePosixPath(value).parts))
        grouped.setdefault(root, []).append(prop)
    budget = InvariantExecutionBudget(
        selected_limits.maximum_runner_attempts,
        time.monotonic() + selected_limits.stage_timeout_seconds,
    )
    results: list[MutationProjectExecution] = []
    for index, (root, properties) in enumerate(sorted(grouped.items())):
        projected = _corpus(properties, corpus.limitations)
        names = sorted({p.harness_name for p in properties})
        results.append(
            _run_project(
                source=repository_root,
                exclusion=repository_exclusion_root,
                expected_source_sha256=expected_source_sha256,
                private=private_dir / f"project-{index:04d}",
                runner=invariant_runner,
                project=selected[root],
                corpus=projected,
                harnesses=[by_name[name] for name in names],
                limits=selected_limits,
                budget=budget,
                remaining_campaigns=selected_limits.maximum_campaigns
                - sum(len(p.campaigns) for p in results),
            )
        )
    return MutationPipelineArtifact(
        **values,
        unresolved_property_ids=unresolved,
        projects=results,
        runner_attempts=budget.attempts,
        limitations=[
            "Collected local comparisons are not admitted runtime, qualification or audit evidence."
        ],
    )
