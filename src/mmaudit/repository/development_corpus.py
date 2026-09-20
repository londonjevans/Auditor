"""Read selected source; explicit tree-version manifests additionally require exhaustive replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mmaudit.models.development_audit import DevelopmentSourceBytes
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusText,
)
from mmaudit.models.development_corpus_partition import (
    MAX_DEVELOPMENT_PARTITION_BYTES,
    DevelopmentCorpusPartition,
    _validate_partition_from_replayed_reference,
    read_development_corpus_partition,
)
from mmaudit.models.development_corpus_replay import (
    replay_development_corpus_manifest,
    replay_development_corpus_material,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    read_file_evidence,
    read_json_evidence,
    revalidate_evidence_file_bindings,
)
from mmaudit.repository.development_corpus_tree import (
    DevelopmentCorpusTreeObservation,
    development_corpus_tree_evidence,
    observe_development_corpus_tree,
    revalidate_development_corpus_tree,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    require_regular_file_custody_unchanged,
)


@dataclass(frozen=True)
class LoadedDevelopmentCorpus:
    material: DevelopmentCorpusMaterial
    corpus_root: Path
    manifest_file: Path
    manifest_binding: ManifestFileBinding
    source_bindings: tuple[ManifestFileBinding, ...]
    corpus_custody: DirectoryCustodyObservation
    tree_observation: DevelopmentCorpusTreeObservation | None = None
    partition_custody: DevelopmentCorpusPartitionCustody | None = field(default=None, repr=False)


@dataclass(frozen=True)
class DevelopmentCorpusPartitionCustody:
    """One-level original-tree ownership accompanies every derived source consumer."""

    reference: LoadedDevelopmentCorpus = field(repr=False)
    partition: DevelopmentCorpusPartition
    file: RegularFileCustodyObservation


def _require_partition_origin(
    loaded: LoadedDevelopmentCorpus,
    material: DevelopmentCorpusMaterial,
    replayed: dict[str, DevelopmentCorpusMaterial],
    manifests: dict[bytes, DevelopmentCorpusManifest],
) -> None:
    custody = loaded.partition_custody
    if (material.manifest.source_origin is not None) != (custody is not None):
        raise ValueError("derived corpus cannot detach or invent its mandatory origin custody")
    if custody is None:
        return
    if (
        type(custody) is not DevelopmentCorpusPartitionCustody
        or type(custody.reference) is not LoadedDevelopmentCorpus
        or custody.reference.partition_custody is not None
        or type(custody.partition) is not DevelopmentCorpusPartition
        or type(custody.file) is not RegularFileCustodyObservation
    ):
        raise ValueError("derived corpus requires exact unnested original-tree custody")
    reference = custody.reference
    if any(
        path.is_relative_to(reference.corpus_root) or reference.corpus_root.is_relative_to(path)
        for path in (
            loaded.corpus_root,
            loaded.manifest_file,
            custody.file.root / custody.file.binding.path,
        )
    ):
        raise ValueError("derived corpus overlaps its original source tree")
    _revalidate_loaded_corpus(reference, replayed, manifests)
    require_regular_file_custody_unchanged(
        custody.file,
        label="development partition recipe",
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    recipe = read_json_evidence(
        evidence_root=custody.file.root,
        relative_path=custody.file.binding.path,
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
    )
    if (
        recipe.binding != custody.file.binding
        or read_development_corpus_partition(recipe.content) != custody.partition
        or _validate_partition_from_replayed_reference(
            _replay_material(reference.material, replayed), custody.partition
        )
        != material
    ):
        raise ValueError("derived corpus changed its original tree or computed source selection")
    require_regular_file_custody_unchanged(
        custody.file,
        label="development partition recipe",
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    _revalidate_loaded_corpus(reference, replayed, manifests)
    require_regular_file_custody_unchanged(
        custody.file,
        label="development partition recipe",
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
        allow_directory_entry_metadata_change=True,
    )


def load_development_corpus(
    *,
    manifest_file: Path,
    corpus_root: Path,
    partition_custody: DevelopmentCorpusPartitionCustody | None = None,
) -> LoadedDevelopmentCorpus:
    """Capture exact selected bytes; declared source scope grants no execution or audit authority."""

    if any(not p.is_absolute() or ".." in p.parts for p in (manifest_file, corpus_root)):
        raise ValueError("development corpus input paths must be absolute and normalized")
    custody = observe_unlinked_directory(corpus_root, label="development corpus source root")
    manifest_input = read_json_evidence(
        evidence_root=manifest_file.parent,
        relative_path=manifest_file.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    )
    manifest = replay_development_corpus_manifest(manifest_input.content)
    if (manifest.source_origin is not None) != (partition_custody is not None):
        raise ValueError("derived corpus must load its original origin custody with the bundle")
    tree = (
        observe_development_corpus_tree(corpus_root)
        if manifest.source_tree_evidence is not None
        else None
    )
    if tree is not None and development_corpus_tree_evidence(tree, manifest.sources) != (
        manifest.source_tree_evidence
    ):
        raise ValueError("development manifest differs from the complete source tree namespace")
    sources = tuple(
        read_file_evidence(
            evidence_root=corpus_root,
            relative_path=s.filename,
            max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
        for s in manifest.sources
    )
    material = DevelopmentCorpusMaterial(
        manifest=manifest,
        sources=tuple(
            DevelopmentCorpusText(
                filename=s.filename,
                content=raw.content.decode("utf-8", errors="strict"),
            )
            for s, raw in zip(manifest.sources, sources, strict=True)
        ),
    )
    result = LoadedDevelopmentCorpus(
        material,
        corpus_root,
        manifest_file,
        manifest_input.binding,
        tuple(s.binding for s in sources),
        custody,
        tree,
        partition_custody,
    )
    revalidate_loaded_development_corpus(result)
    return result


def revalidate_loaded_development_corpus(loaded: LoadedDevelopmentCorpus) -> None:
    """Recheck every live input; bounded tables share pure JSON parsing, never input custody.

    Guard-local tables are discarded on return. An owning tree invocation may additionally reuse
    detached strict parse results; all reads, inode/root/namespace and policy checks stay live.
    """

    _revalidate_loaded_corpus(loaded, {}, {})


def _replay_material(
    material: DevelopmentCorpusMaterial, replayed: dict[str, DevelopmentCorpusMaterial]
) -> DevelopmentCorpusMaterial:
    content = material.model_dump_json()
    if content not in replayed:
        if len(replayed) >= 2:
            raise ValueError(
                "development corpus replay exceeds its original/derived material bound"
            )
        replayed[content] = replay_development_corpus_material(content)
    return replayed[content]


def _replay_manifest(
    content: bytes, replayed: dict[bytes, DevelopmentCorpusManifest]
) -> DevelopmentCorpusManifest:
    """Reuse strict parsing of identical freshly read bytes, never an input-custody verdict."""

    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES:
        raise ValueError("development corpus replay requires bounded immutable manifest bytes")
    if content not in replayed:
        if len(replayed) >= 2:
            raise ValueError(
                "development corpus replay exceeds its original/derived manifest bound"
            )
        replayed[content] = replay_development_corpus_manifest(content)
    return replayed[content]


def _revalidate_loaded_corpus(
    loaded: LoadedDevelopmentCorpus,
    replayed: dict[str, DevelopmentCorpusMaterial],
    manifests: dict[bytes, DevelopmentCorpusManifest],
) -> None:
    """Keep every original live guard; only exact pure JSON parsing may be shared."""

    if (
        type(loaded) is not LoadedDevelopmentCorpus
        or type(loaded.material) is not DevelopmentCorpusMaterial
        or type(loaded.source_bindings) is not tuple
        or type(loaded.manifest_binding) is not ManifestFileBinding
        or any(type(b) is not ManifestFileBinding for b in loaded.source_bindings)
        or type(loaded.corpus_custody) is not DirectoryCustodyObservation
        or loaded.corpus_custody.path != loaded.corpus_root
    ):
        raise ValueError("development corpus handoff requires exact loaded input types")
    material = _replay_material(loaded.material, replayed)
    _require_partition_origin(loaded, material, replayed, manifests)
    if (loaded.tree_observation is None) != (material.manifest.source_tree_evidence is None):
        raise ValueError("development tree replay observation is missing or unselected")
    if loaded.tree_observation is not None and loaded.tree_observation.root != loaded.corpus_root:
        raise ValueError("development tree replay belongs to a different source root")
    if loaded.manifest_binding.path != loaded.manifest_file.name or tuple(
        (b.path, b.sha256, b.size) for b in loaded.source_bindings
    ) != tuple((s.filename, s.sha256, s.size) for s in material.manifest.sources):
        raise ValueError("development corpus handoff changed selected source bindings")
    require_same_unlinked_directory_objects(
        loaded.corpus_custody, label="development corpus source root"
    )
    manifest_input = read_json_evidence(
        evidence_root=loaded.manifest_file.parent,
        relative_path=loaded.manifest_file.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    )
    if (
        manifest_input.binding != loaded.manifest_binding
        or _replay_manifest(manifest_input.content, manifests) != material.manifest
    ):
        raise ValueError("development corpus material differs from the selected manifest file")
    revalidate_evidence_file_bindings(
        evidence_root=loaded.corpus_root,
        bindings=loaded.source_bindings,
        max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    )
    if loaded.tree_observation is not None:
        revalidate_development_corpus_tree(loaded.tree_observation, material.manifest)
    _require_partition_origin(loaded, material, replayed, manifests)
    if loaded.material.model_dump_json() != material.model_dump_json():
        raise ValueError("development corpus material changed during input replay")


def require_development_corpus_source_custody(
    *,
    manifest: DevelopmentCorpusManifest,
    source_files: DevelopmentSourceBytes,
    source_custody: LoadedDevelopmentCorpus | None,
) -> None:
    """Replay the actual selected root; serialized receipts cannot admit tree-backed work."""

    if source_custody is None:
        if manifest.source_tree_evidence is not None:
            raise ValueError(
                "tree-backed development preparation requires actual loaded source custody"
            )
        return
    if type(source_custody) is not LoadedDevelopmentCorpus or (
        type(source_custody.material) is not DevelopmentCorpusMaterial
        or source_custody.material.manifest != manifest
        or source_custody.material.source_files != source_files
    ):
        raise ValueError(
            "development source custody differs from the exact selected manifest and bytes"
        )
    revalidate_loaded_development_corpus(source_custody)
