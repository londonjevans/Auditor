"""Computed source-only projections; both the original and derived roots still need replay."""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import (
    _SHA,
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusPartitionOrigin,
    DevelopmentCorpusSource,
    DevelopmentCorpusSourcePartition,
    DevelopmentCorpusText,
    DevelopmentCorpusTreeDirectory,
    DevelopmentCorpusTreeEvidence,
    freeze_development_corpus,
)
from mmaudit.models.development_corpus_replay import replay_development_corpus_material
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_PARTITION_BYTES = MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES + 4096


class DevelopmentCorpusPartition(_AuditArtifact):
    """A bundle recipe, not authority to omit sources from the original audit universe."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_partition"] = "development_corpus_partition"
    policy: Literal["ORIGINAL_TREE_STATIC_CLOSURE_MINIMAL_SOURCE_UNION_V1"] = (
        "ORIGINAL_TREE_STATIC_CLOSURE_MINIMAL_SOURCE_UNION_V1"
    )
    reference_manifest_sha256: str = Field(pattern=_SHA)
    reference_tree_sha256: str = Field(pattern=_SHA)
    reference_static_closure_sha256: str = Field(pattern=_SHA)
    reference_replay_required: Literal[True] = True
    manifest: DevelopmentCorpusManifest
    partition_sha256: str = Field(pattern=_SHA)

    @field_validator("reference_replay_required", mode="before")
    @classmethod
    def original_tree_replay_is_mandatory(cls, value: object) -> Literal[True]:
        if value is not True:
            raise ValueError("source partition always requires original tree replay")
        return True

    @model_validator(mode="after")
    def exact_closed_source_bundle(self) -> Self:
        if (
            self.manifest.schema_version != "1.11"
            or self.manifest.source_partition is None
            or self.manifest.dependency_closure != "CALL_CLOSED"
            or self.manifest.source_tree_evidence is None
            or self.manifest.source_tree_evidence.non_source_file_count != 0
            or self.manifest.source_tree_evidence
            != source_only_tree_evidence(self.manifest.sources)
            or self.manifest.source_origin
            != DevelopmentCorpusPartitionOrigin(
                reference_manifest_sha256=self.reference_manifest_sha256,
                reference_tree_sha256=self.reference_tree_sha256,
                reference_static_closure_sha256=self.reference_static_closure_sha256,
            )
        ):
            raise ValueError("source partition requires an exact closed source-only bundle")
        if self.partition_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"partition_sha256"})
        ):
            raise ValueError("source partition digest differs")
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_PARTITION_BYTES:
            raise ValueError("source partition recipe exceeds its byte bound")
        return self


def source_only_tree_evidence(
    sources: tuple[DevelopmentCorpusSource, ...],
) -> DevelopmentCorpusTreeEvidence:
    """Describe a proposed exact source-only layout; this never observes a filesystem."""

    rows: dict[str, set[tuple[str, str]]] = {".": set()}
    for source in sources:
        parts = source.filename.split("/")
        parent = "."
        for part in parts[:-1]:
            rows[parent].add((part, "DIRECTORY"))
            parent = part if parent == "." else parent + "/" + part
            rows.setdefault(parent, set())
        rows[parent].add((parts[-1], "REGULAR_FILE"))
    provisional = DevelopmentCorpusTreeEvidence.model_construct(
        source_inventory_sha256=canonical_sha256([s.model_dump(mode="json") for s in sources]),
        solidity_file_count=len(sources),
        non_source_file_count=0,
        directories=tuple(
            DevelopmentCorpusTreeDirectory(
                path=path,
                entry_count=len(entries),
                entries_sha256=canonical_sha256(sorted(entries)),
            )
            for path, entries in sorted(rows.items())
        ),
        tree_sha256="0" * 64,
    )
    return DevelopmentCorpusTreeEvidence.model_validate(
        {
            **provisional.model_dump(mode="python"),
            "tree_sha256": canonical_sha256(
                provisional.model_dump(mode="json", exclude={"tree_sha256"})
            ),
        }
    )


def derive_development_corpus_partition(
    *, reference: DevelopmentCorpusMaterial, primary_filenames: tuple[str, ...]
) -> DevelopmentCorpusPartition:
    """Use the original graph's complete member sets, then recompute closure on the bundle."""

    if type(reference) is not DevelopmentCorpusMaterial or type(primary_filenames) is not tuple:
        raise ValueError("source partition requires exact reference and primary tuple types")
    DevelopmentCorpusSourcePartition(primary_filenames=primary_filenames, context_filenames=())
    reference = replay_development_corpus_material(reference.model_dump_json())
    return _derive_partition_from_replayed_reference(reference, primary_filenames)


def _derive_partition_from_replayed_reference(
    reference: DevelopmentCorpusMaterial, primary_filenames: tuple[str, ...]
) -> DevelopmentCorpusPartition:
    """Internal composition after original material validation; never a custody replacement."""

    manifest = reference.manifest
    evidence = manifest.dependency_evidence
    tree = manifest.source_tree_evidence
    if (
        tree is None
        or evidence is None
        or evidence.static_call_closure is None
        or manifest.source_origin is not None
    ):
        raise ValueError("source partition requires full original tree and computed static closure")
    proof = evidence.static_call_closure
    closures = {p.primary: p for p in proof.primaries}
    if any(
        p not in closures or closures[p].call_closure != "CALL_CLOSED" for p in primary_filenames
    ):
        raise ValueError("source partition primary has missing or unresolved original closure")
    members = set().union(*(closures[p].members for p in primary_filenames))
    selected = tuple(s for s in manifest.sources if s.filename in members)
    source_files = tuple((p, raw) for p, raw in reference.source_files if p in members)
    selected_manifest = freeze_development_corpus(
        corpus_id="dvp-" + canonical_sha256([manifest.manifest_sha256, primary_filenames])[:60],
        source_scope=manifest.source_scope,
        source_files=source_files,
        dependency_remapping_text=evidence.remapping_text,
        dependency_target_context=True,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
        dependency_modifier_context=True,
        dependency_constructor_context=True,
        dependency_static_closure=True,
        dependency_graph_byte_limit=evidence.graph_artifact_byte_limit,
        source_tree_evidence=source_only_tree_evidence(selected),
        primary_filenames=primary_filenames,
        source_origin=DevelopmentCorpusPartitionOrigin(
            reference_manifest_sha256=manifest.manifest_sha256,
            reference_tree_sha256=tree.tree_sha256,
            reference_static_closure_sha256=proof.proof_sha256,
        ),
    )
    values: dict[str, Any] = dict(
        reference_manifest_sha256=manifest.manifest_sha256,
        reference_tree_sha256=tree.tree_sha256,
        reference_static_closure_sha256=proof.proof_sha256,
        manifest=selected_manifest,
    )
    provisional = DevelopmentCorpusPartition.model_construct(**values, partition_sha256="0" * 64)
    values["partition_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"partition_sha256"})
    )
    return DevelopmentCorpusPartition.model_validate(values)


def validate_development_corpus_partition(
    *, reference: DevelopmentCorpusMaterial, partition: DevelopmentCorpusPartition
) -> DevelopmentCorpusMaterial:
    """Replay the original and derived closures; a matching self-hash is insufficient."""

    if type(reference) is not DevelopmentCorpusMaterial:
        raise ValueError("source partition requires its exact original material type")
    reference = replay_development_corpus_material(reference.model_dump_json())
    return _validate_partition_from_replayed_reference(reference, partition)


def _validate_partition_from_replayed_reference(
    reference: DevelopmentCorpusMaterial, partition: DevelopmentCorpusPartition
) -> DevelopmentCorpusMaterial:
    """Share the already replayed original universe across one bounded coverage computation."""

    if type(partition) is not DevelopmentCorpusPartition:
        raise ValueError("source partition requires its exact recipe type")
    partition = read_development_corpus_partition(partition.model_dump_json().encode())
    computed = _derive_partition_from_replayed_reference(
        reference,
        tuple(s.filename for s in partition.manifest.primary_sources),
    )
    if partition != computed:
        raise ValueError("source partition differs from its exact original tree and closure")
    members = {s.filename for s in partition.manifest.sources}
    return DevelopmentCorpusMaterial(
        manifest=partition.manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=path, content=raw.decode("utf-8"))
            for path, raw in reference.source_files
            if path in members
        ),
    )


def read_development_corpus_partition(content: bytes) -> DevelopmentCorpusPartition:
    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_PARTITION_BYTES:
        raise ValueError("source partition input exceeds its byte bound")
    return DevelopmentCorpusPartition.model_validate_json(content, strict=True)
