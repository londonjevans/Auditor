"""Bounded compiler-input reconstruction; retained files never grant runtime authority."""

from __future__ import annotations

import math
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import ConfigDict, Field, model_validator

from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    build_property_bound_inventory_mutation_plan,
)
from mmaudit.models.schemas import RepositorySuiteInventoryEvidence, StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import (
    _decode_json,
    _open_root,
    _require_same_root,
    read_composed_file_evidence,
    read_file_evidence,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryLimits,
    FoundrySourceInput,
    parse_foundry_compiler_statement_catalog,
    parse_foundry_test_inventory,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryCompilerInputSnapshot,
    FoundryInventoryRunResult,
    validated_foundry_compiler_input,
)

if TYPE_CHECKING:
    from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution

_MANIFEST_PATH = "compiler-inputs/manifest.json"


class RetainedMutationCompilerProject(StrictModel):
    project_root: str
    forge_list: ManifestFileBinding
    parser_limits: ManifestFileBinding
    build_info: list[ManifestFileBinding] = Field(min_length=1, max_length=1_000)
    sources: list[ManifestFileBinding] = Field(min_length=1, max_length=100_000)


class RetainedMutationCompilerManifest(StrictModel):
    """Original writer values and exact file index, not authenticated execution evidence."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["retained_mutation_compiler_inputs"] = (
        "retained_mutation_compiler_inputs"
    )
    evidence_authority: Literal["COLLECTED_UNATTESTED"] = "COLLECTED_UNATTESTED"
    evidence: ManifestFileBinding
    accounted_output_bytes: int = Field(ge=0, le=500_000_000)
    generated_artifact_bytes: int = Field(ge=0, le=4_000_000_000)
    projects: list[RetainedMutationCompilerProject] = Field(min_length=1, max_length=1_000)
    execution_validated: Literal[False] = False
    qualification_eligible: Literal[False] = False

    @property
    def files(self) -> tuple[ManifestFileBinding, ...]:
        return (
            self.evidence,
            *(
                item
                for p in self.projects
                for item in (p.forge_list, p.parser_limits, *p.build_info, *p.sources)
            ),
        )

    @model_validator(mode="after")
    def exact_original_layout(self) -> Self:
        if self.evidence.path != "compiler-inputs/evidence.json":
            raise ValueError("retained compiler evidence path differs")
        roots = [p.project_root for p in self.projects]
        if roots != sorted(set(roots)) or any(normalize_relative_path(p) != p for p in roots):
            raise ValueError("retained compiler projects must be canonical and unique")
        for index, project in enumerate(self.projects):
            prefix = f"compiler-inputs/project-{index:04d}"
            if (
                project.forge_list.path != prefix + "/forge-list.json"
                or project.parser_limits.path != prefix + "/parser-limits.json"
                or [b.path for b in project.build_info]
                != [f"{prefix}/build-{i:04d}.json" for i in range(len(project.build_info))]
            ):
                raise ValueError("retained compiler index differs from original writer layout")
            paths = [s.path for s in project.sources]
            if paths != sorted(set(paths)) or any(
                not p.startswith(prefix + "/sources/") for p in paths
            ):
                raise ValueError("retained compiler source paths differ from their project")
        paths = [f.path for f in self.files]
        if len(paths) != len(set(paths)) or len(paths) >= 100_000:
            raise ValueError("retained compiler file population is ambiguous or unbounded")
        if any(normalize_relative_path(f.path) != f.path for f in self.files):
            raise ValueError("retained compiler input paths must be canonical")
        return self


class MutationReconstructionLimits(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    maximum_files: int = Field(default=100_000, ge=1, le=100_000)
    maximum_file_bytes: int = Field(default=256_000_000, ge=1, le=256_000_000)
    maximum_total_bytes: int = Field(default=1_500_000_000, ge=1, le=8_000_000_000)
    timeout_seconds: float = Field(default=120, gt=0, le=600)


@dataclass(frozen=True, slots=True)
class ReconstructedMutationProject:
    """Consistency-only parser/plan replay, never a transferable runtime capability."""

    project_sha256: str
    inventory: FoundryInventoryRunResult
    plan: MutationApplicabilityPlan
    evidence_authority: Literal["COLLECTED_UNATTESTED"] = field(
        default="COLLECTED_UNATTESTED", init=False
    )
    execution_validated: Literal[False] = field(default=False, init=False)
    qualification_eligible: Literal[False] = field(default=False, init=False)


def _deadline_check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError("mutation input reconstruction deadline exceeded")


def _metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _input_tree(
    root: Path, expected: set[str], *, deadline: float
) -> tuple[tuple[int, int, int], dict[str, tuple[int, ...]]]:
    """Enumerate only the exact selected private tree, retaining directory descriptors."""

    directories: set[str] = set()
    for path in expected:
        _deadline_check(deadline)
        for parent in PurePosixPath(path).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
                if len(directories) > 200_000:
                    raise ValueError("mutation input directory count exceeds its bound")
    allowed = expected | directories
    selected = _open_root(root)
    observed: dict[str, tuple[int, ...]] = {}

    def walk(descriptor: int, prefix: str, depth: int) -> None:
        _deadline_check(deadline)
        if depth > 256:
            raise ValueError("mutation input directory depth exceeds its bound")
        before = os.fstat(descriptor)
        with os.scandir(descriptor) as entries:
            for entry in entries:
                _deadline_check(deadline)
                relative = prefix + entry.name
                if relative in observed or relative not in allowed:
                    raise ValueError("mutation input tree contains extra or duplicate entries")
                metadata = entry.stat(follow_symlinks=False)
                observed[relative] = _metadata(metadata)
                if relative in directories:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ValueError("mutation input parent is not a direct directory")
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    try:
                        if _metadata(os.fstat(child)) != _metadata(metadata):
                            raise ValueError("mutation input directory identity changed")
                        walk(child, relative + "/", depth + 1)
                        if _metadata(
                            os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                        ) != _metadata(metadata):
                            raise ValueError("mutation input parent was replaced")
                    finally:
                        os.close(child)
                elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("mutation input is linked or not a regular file")
        if _metadata(os.fstat(descriptor)) != _metadata(before):
            raise ValueError("mutation input directory changed during traversal")

    try:
        walk(selected.descriptor, "", 0)
        if set(observed) != allowed:
            raise ValueError("mutation input tree has missing entries")
        _require_same_root(selected.path, selected.identity)
        return selected.identity, observed
    finally:
        os.close(selected.descriptor)


def reconstruct_mutation_project(
    *,
    project: MutationProjectExecution,
    expected_project_sha256: str,
    artifact_root: Path,
    limits: MutationReconstructionLimits | None = None,
    absolute_deadline: float | None = None,
) -> ReconstructedMutationProject:
    """Rebuild one complete original plan without a compiler, process, network or writes.

    The caller pins the project projection from its selected artifact. This binds bytes,
    not provenance or runtime authority. Synchronous reads/parsers check the shared
    deadline at boundaries; they cannot forcibly preempt a blocked operating-system call.
    """

    from mmaudit.orchestration.mutation_pipeline import MutationProjectExecution

    bounds = MutationReconstructionLimits.model_validate(
        (limits or MutationReconstructionLimits()).model_dump()
    )
    deadline = time.monotonic() + bounds.timeout_seconds
    if absolute_deadline is not None:
        if type(absolute_deadline) not in {int, float} or not math.isfinite(absolute_deadline):
            raise ValueError("mutation reconstruction requires a finite shared deadline")
        deadline = min(deadline, absolute_deadline)
    _deadline_check(deadline)
    if not artifact_root.is_absolute() or ".." in artifact_root.parts:
        raise ValueError("mutation reconstruction requires an explicit direct artifact root")
    if type(project) is not MutationProjectExecution:
        raise ValueError("mutation reconstruction requires the exact project artifact")
    selected = MutationProjectExecution.model_validate(project.model_dump(mode="python"))
    if canonical_sha256(selected.model_dump(mode="json")) != expected_project_sha256:
        raise ValueError("mutation project artifact differs from its selected pin")
    plan = selected.plan
    if plan is None or plan.property_tests is None or plan.discovery is None:
        raise ValueError("mutation project has no reconstructable complete plan")
    bindings = {
        item.path: ManifestFileBinding(**item.model_dump())
        for item in selected.compiler_input_files
    }
    if (
        len(bindings) != len(selected.compiler_input_files)
        or list(bindings) != sorted(bindings)
        or _MANIFEST_PATH not in bindings
        or any(not p.startswith("compiler-inputs/") for p in bindings)
    ):
        raise ValueError("mutation compiler inputs lack a complete canonical writer manifest")
    if (
        len(bindings) > bounds.maximum_files
        or any(not 0 <= b.size <= bounds.maximum_file_bytes for b in bindings.values())
        or sum(b.size for b in bindings.values()) > bounds.maximum_total_bytes
    ):
        raise ValueError("mutation compiler input set exceeds its reconstruction bounds")
    expected = {p.removeprefix("compiler-inputs/") for p in bindings}
    root = artifact_root / "compiler-inputs"
    before = _input_tree(root, expected, deadline=deadline)

    def read(binding: ManifestFileBinding) -> bytes:
        _deadline_check(deadline)
        relative = binding.path.removeprefix("compiler-inputs/")
        local = ManifestFileBinding(path=relative, sha256=binding.sha256, size=binding.size)
        if binding.size == 0:
            empty = read_file_evidence(evidence_root=root, relative_path=relative, max_bytes=1)
            if empty.binding != local:
                raise ValueError("empty mutation input differs from its original binding")
            return empty.content
        raw = read_composed_file_evidence(
            evidence_root=root,
            relative_path=relative,
            expected_binding=local,
            max_bytes=bounds.maximum_file_bytes,
        ).content
        _deadline_check(deadline)
        return raw

    manifest = RetainedMutationCompilerManifest.model_validate(
        _decode_json(read(bindings[_MANIFEST_PATH]))
    )
    if {b.path: b for b in manifest.files} != {
        p: b for p, b in bindings.items() if p != _MANIFEST_PATH
    }:
        raise ValueError("retained compiler manifest differs from the complete artifact file set")
    evidence = RepositorySuiteInventoryEvidence.model_validate(
        _decode_json(read(manifest.evidence))
    )
    if evidence != plan.compiler_inventory or [p.project_root for p in manifest.projects] != [
        p.project_root for p in evidence.projects
    ]:
        raise ValueError("retained compiler evidence differs from the original project/plan")
    if manifest.accounted_output_bytes != sum(
        p.stdout_bytes + p.stderr_bytes for p in evidence.projects
    ):
        raise ValueError("retained compiler byte accounting differs from original streams")
    inventories, catalogs, snapshots = [], [], []
    for index, inputs in enumerate(manifest.projects):
        parser_limits = FoundryInventoryLimits.model_validate(
            _decode_json(read(inputs.parser_limits))
        )
        prefix = f"compiler-inputs/project-{index:04d}/sources/"
        snapshot = FoundryCompilerInputSnapshot(
            project_root=inputs.project_root,
            forge_list_json=read(inputs.forge_list),
            build_info_jsons=tuple(read(b) for b in inputs.build_info),
            sources=tuple(
                FoundrySourceInput(b.path.removeprefix(prefix), read(b), b.sha256)
                for b in inputs.sources
            ),
            parser_limits=parser_limits,
        )
        common: dict[str, Any] = dict(
            build_info_jsons=snapshot.build_info_jsons,
            sources=snapshot.sources,
            project_root=snapshot.project_root,
            compiler_version=evidence.compiler_version,
            compiler_sha256=evidence.compiler_sha256,
            limits=parser_limits,
        )
        _deadline_check(deadline)
        inventories.append(
            parse_foundry_test_inventory(forge_list_json=snapshot.forge_list_json, **common)
        )
        _deadline_check(deadline)
        catalogs.append(parse_foundry_compiler_statement_catalog(**common))
        _deadline_check(deadline)
        snapshots.append(snapshot)
    inventory = FoundryInventoryRunResult(
        inventories=tuple(inventories),
        statement_catalogs=tuple(catalogs),
        evidence=evidence,
        accounted_output_bytes=manifest.accounted_output_bytes,
        generated_artifact_bytes=manifest.generated_artifact_bytes,
        compiler_inputs=tuple(snapshots),
    )
    for inputs in manifest.projects:
        _deadline_check(deadline)
        validated_foundry_compiler_input(inventory, project_root=inputs.project_root)
    repositories = set(plan.property_repositories.values())
    if len(repositories) != 1:
        raise ValueError("mutation reconstruction cannot infer a repository selection")
    rebuilt = build_property_bound_inventory_mutation_plan(
        inventory_result=inventory,
        project_root=selected.project_root,
        target_paths=tuple(
            PurePosixPath(p).relative_to(selected.project_root).as_posix()
            for p in plan.discovery.target_paths
        ),
        corpus=plan.property_tests.corpus,
        harnesses=plan.property_tests.harnesses,
        repository_id=next(iter(repositories)),
        approved_executor_sha256=plan.approved_executor_sha256,
        approved_isolation_policy_sha256=plan.approved_isolation_policy_sha256,
        expected_chain_id=plan.property_tests.expected_chain_id,
        include_compiler_reachability=plan.property_tests.compiler_reachability is not None,
        limits=plan.discovery.limits,
    )
    _deadline_check(deadline)
    if rebuilt != plan:
        raise ValueError("reconstructed mutation plan differs from its full original selection")
    if _input_tree(root, expected, deadline=deadline) != before:
        raise ValueError("mutation input root or file identity changed during reconstruction")
    _deadline_check(deadline)
    return ReconstructedMutationProject(expected_project_sha256, inventory, rebuilt)
