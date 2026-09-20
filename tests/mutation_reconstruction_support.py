"""Original retained synthetic compiler data for bounded source-only reconstruction tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

from mmaudit.benchmark.mutations import score_planned_mutation_campaigns
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.orchestration.mutation_pipeline import (
    GeneratedMutationWorkspace,
    MutationProjectExecution,
    MutationSourceFile,
    _retain_compiler_inputs,
)
from mmaudit.repository.workspace import audited_workspace_bindings_sha256
from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryRunResult
from mmaudit.solidity.properties import generated_local_property_source
from tests.property_mutation_support import (
    FIXTURE,
    SOURCE,
    property_inputs,
    property_plan,
    retained_property_fixture,
)


def source_binding(path: str, raw: bytes) -> MutationSourceFile:
    return MutationSourceFile(path=path, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))


def reconstruction_case(root: Path) -> tuple[MutationProjectExecution, FoundryInventoryRunResult]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    inventory = retained_property_fixture()
    corpus, harnesses = property_inputs()
    originals = [source_binding(p, (FIXTURE / p).read_bytes()) for p in ("foundry.toml", SOURCE)]
    generated = []
    for harness in harnesses:
        selected = generated_local_property_source(harness, project_root=".")
        assert selected is not None
        generated.append(source_binding(*selected))
    workspace = GeneratedMutationWorkspace(
        original_files=originals,
        generated_files=generated,
        original_sha256=audited_workspace_bindings_sha256([b.model_dump() for b in originals]),
        augmented_sha256=audited_workspace_bindings_sha256(
            [b.model_dump() for b in (*originals, *generated)]
        ),
    )
    assert workspace.augmented_sha256 == inventory.evidence.repository_sha256
    plan = property_plan(inventory)
    project = MutationProjectExecution(
        project_root=".",
        property_ids=[p.id for p in corpus.properties],
        projected_corpus_hash=corpus.corpus_hash,
        workspace=workspace,
        plan=plan,
        score=score_planned_mutation_campaigns(
            plan=plan, campaigns=[], minimum_property_kill_score=0.95
        ),
        compiler_input_files=_retain_compiler_inputs(root, inventory),
        limitations=["Synthetic retained compiler reconstruction fixture; no runtime authority."],
    )
    return project, inventory


def project_pin(project: MutationProjectExecution) -> str:
    return canonical_sha256(project.model_dump(mode="json"))
