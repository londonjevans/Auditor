"""Offline complete-tree planning and exact source, remapping, policy and plan custody."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    DevelopmentCorpusScope,
)
from mmaudit.models.development_review import _development_metadata
from mmaudit.models.development_tree_plan import (
    MAX_DEVELOPMENT_TREE_PLAN_BYTES,
    DevelopmentTreePlan,
    DevelopmentTreePlanPolicy,
    plan_development_tree,
    read_development_tree_plan,
)
from mmaudit.models.development_tree_request_bounds import development_tree_review_claims_bound
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.repository.development_corpus import (
    LoadedDevelopmentCorpus,
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.development_corpus_tree import (
    CapturedDevelopmentCorpusTree,
    capture_development_corpus_tree,
    revalidate_captured_development_corpus_tree,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)
from mmaudit.solidity.dependency_closure import MAX_DEPENDENCY_GRAPH_BYTES

MAX_DEVELOPMENT_TREE_POLICY_BYTES = 4_000_000


@dataclass(frozen=True)
class LoadedDevelopmentTreePlan:
    """Local file ownership only; a READY plan does not authorize source egress or spending."""

    plan: DevelopmentTreePlan
    reference: LoadedDevelopmentCorpus
    captured: CapturedDevelopmentCorpusTree
    directory: DirectoryCustodyObservation
    plan_file: RegularFileCustodyObservation
    manifest_file: RegularFileCustodyObservation
    policy_file: RegularFileCustodyObservation
    remappings_file: RegularFileCustodyObservation


def _read_bound(path: Path, maximum: int) -> tuple[bytes, RegularFileCustodyObservation]:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ValueError("automatic tree input must be an absolute normalized file")
    observed = read_file_evidence(
        evidence_root=path.parent, relative_path=path.name, max_bytes=maximum
    )
    custody = observe_regular_file_custody(
        root=path.parent,
        relative_path=path.name,
        expected_binding=observed.binding,
        label="automatic tree input",
        max_bytes=maximum,
        allow_directory_entry_metadata_change=True,
    )
    return observed.content, custody


def _capture(
    corpus_root: Path,
    remappings_file: Path,
    corpus_id: str,
    source_scope: DevelopmentCorpusScope,
    graph_byte_limit: int,
) -> CapturedDevelopmentCorpusTree:
    return capture_development_corpus_tree(
        corpus_root=corpus_root,
        remappings_file=remappings_file,
        corpus_id=corpus_id,
        source_scope=source_scope,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
        dependency_modifier_context=True,
        dependency_constructor_context=True,
        dependency_static_closure=True,
        dependency_graph_byte_limit=graph_byte_limit,
    )


def _require_file(file: RegularFileCustodyObservation) -> None:
    # Empty remappings still bind exact bytes and identity; the reader needs a positive limit.
    require_regular_file_custody_unchanged(
        file,
        label="automatic tree input",
        max_bytes=max(1, file.binding.size),
        allow_directory_entry_metadata_change=True,
    )


def write_development_tree_plan(
    *,
    corpus_root: Path,
    remappings_file: Path,
    policy_file: Path,
    corpus_id: str,
    source_scope: DevelopmentCorpusScope,
    output_dir: Path,
) -> LoadedDevelopmentTreePlan:
    """Derive all resource envelopes before writing bundles or accessing a ledger or credentials.

    Refused plans retain every source and shortfall too; only their execution is unavailable.
    All outputs are new, private and disjoint from the explicitly supplied inputs.
    """

    paths = (corpus_root, remappings_file, policy_file, output_dir)
    if any(not isinstance(p, Path) or not p.is_absolute() or ".." in p.parts for p in paths):
        raise ValueError("automatic tree paths must be absolute and normalized")
    if output_dir.is_relative_to(corpus_root) or any(
        p.is_relative_to(output_dir) or output_dir.is_relative_to(p)
        for p in (corpus_root, remappings_file, policy_file)
    ):
        raise ValueError("automatic tree input and output overlap")
    policy_content, policy_custody = _read_bound(policy_file, MAX_DEVELOPMENT_TREE_POLICY_BYTES)
    policy = DevelopmentTreePlanPolicy.model_validate_json(policy_content, strict=True)
    _, remappings_custody = _read_bound(remappings_file, MAX_DEVELOPMENT_TREE_POLICY_BYTES)
    captured = _capture(
        corpus_root, remappings_file, corpus_id, source_scope, MAX_DEPENDENCY_GRAPH_BYTES
    )
    if captured.remappings_binding != remappings_custody.binding:
        raise ValueError("automatic tree remappings changed during capture")
    plan = plan_development_tree(reference=captured.material, policy=policy)
    _require_file(policy_custody)
    _require_file(remappings_custody)
    revalidate_captured_development_corpus_tree(captured)
    owned = prepare_owned_empty_directory(output_dir, label="automatic tree plan output")

    def require_inputs() -> None:
        _require_file(policy_custody)
        _require_file(remappings_custody)
        revalidate_captured_development_corpus_tree(captured)
        require_same_unlinked_directory_objects(owned, label="automatic tree plan output")

    for filename, artifact, maximum in (
        ("manifest.json", captured.material.manifest, MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES),
        ("plan.json", plan, MAX_DEVELOPMENT_TREE_PLAN_BYTES),
    ):
        require_inputs()
        write_json_evidence(
            evidence_root=output_dir,
            relative_path=filename,
            value=artifact,
            max_bytes=maximum,
            require_private_parent=True,
        )
        require_inputs()
    loaded = load_development_tree_plan(
        plan_file=output_dir / "plan.json",
        corpus_root=corpus_root,
        remappings_file=remappings_file,
        policy_file=policy_file,
    )
    require_inputs()
    if loaded.plan != plan:
        raise ValueError("automatic tree retained plan differs from its derivation")
    return loaded


def load_development_tree_plan(
    *, plan_file: Path, corpus_root: Path, remappings_file: Path, policy_file: Path
) -> LoadedDevelopmentTreePlan:
    """Recompute the original tree and policy when reopening a persisted plan."""

    content, plan_custody = _read_bound(plan_file, MAX_DEVELOPMENT_TREE_PLAN_BYTES)
    plan = read_development_tree_plan(content)
    policy_content, policy_custody = _read_bound(policy_file, MAX_DEVELOPMENT_TREE_POLICY_BYTES)
    if DevelopmentTreePlanPolicy.model_validate_json(policy_content, strict=True) != plan.policy:
        raise ValueError("automatic tree original policy differs from the plan")
    _, remappings_custody = _read_bound(remappings_file, MAX_DEVELOPMENT_TREE_POLICY_BYTES)
    witness = plan.reference.manifest.dependency_evidence
    assert witness is not None
    captured = _capture(
        corpus_root,
        remappings_file,
        plan.reference.manifest.corpus_id,
        plan.reference.manifest.source_scope,
        witness.graph_artifact_byte_limit,
    )
    _, manifest_custody = _read_bound(
        plan_file.parent / "manifest.json", MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES
    )
    reference = load_development_corpus(
        manifest_file=plan_file.parent / "manifest.json", corpus_root=corpus_root
    )
    loaded = LoadedDevelopmentTreePlan(
        plan=plan,
        reference=reference,
        captured=captured,
        directory=observe_unlinked_directory(plan_file.parent, label="automatic tree plan"),
        plan_file=plan_custody,
        manifest_file=manifest_custody,
        policy_file=policy_custody,
        remappings_file=remappings_custody,
    )
    revalidate_loaded_development_tree_plan(loaded)
    return loaded


def revalidate_loaded_development_tree_plan(loaded: LoadedDevelopmentTreePlan) -> None:
    """Preserve actual original inputs and retained bytes, including same-byte file replacement."""

    _revalidate_loaded_development_tree_plan_inputs(loaded)
    observed = read_file_evidence(
        evidence_root=loaded.plan_file.root,
        relative_path=loaded.plan_file.binding.path,
        max_bytes=MAX_DEVELOPMENT_TREE_PLAN_BYTES,
    )
    if read_development_tree_plan(observed.content) != loaded.plan:
        raise ValueError("automatic tree retained plan differs from its handle")


def bind_development_tree_plan_replay(loaded: LoadedDevelopmentTreePlan) -> Callable[[], None]:
    """Pin one fully recomputed invocation, never cache source custody or live eligibility.

    A private detached snapshot keeps in-memory changes detectable. Every call still checks
    original source bytes, namespace/object custody, all retained inputs, revocations and the
    review grammar. Only repeated construction of identical future request envelopes is shared.
    This process-local callback is not serialized, and confers no spending or audit authority.
    """

    revalidate_loaded_development_tree_plan(loaded)
    selected = deepcopy(loaded)
    selected_json = selected.plan.model_dump_json()

    def require_current_inputs() -> None:
        if loaded != selected or loaded.plan.model_dump_json() != selected_json:
            raise ValueError("automatic tree invocation differs from its replayed selection")
        _revalidate_loaded_development_tree_plan_inputs(selected)
        for metadata in selected.plan.policy.role_metadata:
            _development_metadata(metadata)
        if development_tree_review_claims_bound()[1] != selected.plan.review_claim_schema_sha256:
            raise ValueError("automatic tree invocation review grammar changed")
        if loaded != selected or loaded.plan.model_dump_json() != selected_json:
            raise ValueError("automatic tree invocation changed during input replay")

    require_current_inputs()
    return require_current_inputs


def _revalidate_loaded_development_tree_plan_inputs(loaded: LoadedDevelopmentTreePlan) -> None:
    """Live root/file/source checks are never replaced by a cached model or matching digest."""

    if (
        type(loaded) is not LoadedDevelopmentTreePlan
        or type(loaded.plan) is not DevelopmentTreePlan
        or type(loaded.reference) is not LoadedDevelopmentCorpus
        or type(loaded.captured) is not CapturedDevelopmentCorpusTree
        or loaded.reference.material != loaded.plan.reference
        or loaded.captured.material != loaded.plan.reference
        or loaded.reference.manifest_file != loaded.directory.path / "manifest.json"
        or loaded.reference.corpus_root != loaded.captured.observation.root
        or loaded.plan_file.root != loaded.directory.path
        or loaded.plan_file.binding.path != "plan.json"
        or loaded.manifest_file.root != loaded.directory.path
        or loaded.manifest_file.binding != loaded.reference.manifest_binding
        or loaded.remappings_file.root / loaded.remappings_file.binding.path
        != loaded.captured.remappings_file
        or loaded.remappings_file.binding != loaded.captured.remappings_binding
    ):
        raise ValueError("automatic tree plan custody selection differs")
    if not 0 < loaded.plan_file.binding.size <= MAX_DEVELOPMENT_TREE_PLAN_BYTES:
        raise ValueError("automatic tree retained plan exceeds its byte bound")
    for file in (
        loaded.plan_file,
        loaded.manifest_file,
        loaded.policy_file,
        loaded.remappings_file,
    ):
        _require_file(file)
    require_same_unlinked_directory_objects(loaded.directory, label="automatic tree plan")
    revalidate_captured_development_corpus_tree(loaded.captured)
    revalidate_loaded_development_corpus(loaded.reference)
