"""Materialize exact closed bundles while retaining the original complete-tree custody."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.development_corpus import MAX_DEVELOPMENT_CORPUS_FILE_BYTES
from mmaudit.models.development_corpus_partition import (
    MAX_DEVELOPMENT_PARTITION_BYTES,
    DevelopmentCorpusPartition,
    read_development_corpus_partition,
    validate_development_corpus_partition,
)
from mmaudit.release_io import read_json_evidence, write_file_evidence, write_json_evidence
from mmaudit.repository.development_corpus import (
    DevelopmentCorpusPartitionCustody,
    LoadedDevelopmentCorpus,
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.directory_custody import (
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


def load_development_corpus_partition(
    *,
    reference: LoadedDevelopmentCorpus,
    partition_file: Path,
    manifest_file: Path,
    corpus_root: Path,
) -> LoadedDevelopmentCorpus:
    """Restore original and derived custody together; no source or recipe is trusted by hash alone."""

    if type(reference) is not LoadedDevelopmentCorpus or reference.partition_custody is not None:
        raise ValueError("source partition requires one original non-derived reference")
    if any(
        not p.is_absolute() or ".." in p.parts for p in (partition_file, manifest_file, corpus_root)
    ):
        raise ValueError("source partition paths must be absolute and normalized")
    revalidate_loaded_development_corpus(reference)
    recipe = read_json_evidence(
        evidence_root=partition_file.parent,
        relative_path=partition_file.name,
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
    )
    file = observe_regular_file_custody(
        root=partition_file.parent,
        relative_path=partition_file.name,
        expected_binding=recipe.binding,
        label="development partition recipe",
        max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    partition = read_development_corpus_partition(recipe.content)
    expected = validate_development_corpus_partition(
        reference=reference.material, partition=partition
    )
    loaded = load_development_corpus(
        manifest_file=manifest_file,
        corpus_root=corpus_root,
        partition_custody=DevelopmentCorpusPartitionCustody(reference, partition, file),
    )
    if loaded.material != expected:
        raise ValueError("materialized source bundle differs from its original closure recipe")
    revalidate_loaded_development_corpus(loaded)
    return loaded


def materialize_development_corpus_partition(
    *, reference: LoadedDevelopmentCorpus, partition: DevelopmentCorpusPartition, output_dir: Path
) -> LoadedDevelopmentCorpus:
    """Write fresh private exact-byte context only; original files are never moved or changed."""

    if type(reference) is not LoadedDevelopmentCorpus or reference.partition_custody is not None:
        raise ValueError("source partition requires one original non-derived reference")
    if not isinstance(output_dir, Path) or not output_dir.is_absolute() or ".." in output_dir.parts:
        raise ValueError("source partition output must be absolute and normalized")
    if any(
        path.is_relative_to(output_dir) or output_dir.is_relative_to(path)
        for path in (reference.corpus_root, reference.manifest_file)
    ):
        raise ValueError("source partition input/output paths overlap")
    revalidate_loaded_development_corpus(reference)
    material = validate_development_corpus_partition(
        reference=reference.material, partition=partition
    )
    revalidate_loaded_development_corpus(reference)
    owned = [prepare_owned_empty_directory(output_dir, label="development partition output")]
    files: list[RegularFileCustodyObservation] = []

    def require_context() -> None:
        revalidate_loaded_development_corpus(reference)
        for directory in owned:
            require_same_unlinked_directory_objects(directory, label="development partition output")
        for file in files:
            require_regular_file_custody_unchanged(
                file,
                label="development partition output file",
                max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
                allow_directory_entry_metadata_change=True,
            )

    source_root = output_dir / "source"
    tree = material.manifest.source_tree_evidence
    if tree is None:
        raise ValueError("source partition has no derived tree layout")
    for directory in tree.directories:
        require_context()
        path = source_root if directory.path == "." else source_root / directory.path
        owned.append(prepare_owned_empty_directory(path, label="development partition source"))
        require_context()
    for name, content in material.source_files:
        require_context()
        binding = write_file_evidence(
            evidence_root=source_root,
            relative_path=name,
            content=content,
            max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
        files.append(
            observe_regular_file_custody(
                root=source_root,
                relative_path=name,
                expected_binding=binding,
                label="development partition source",
                max_bytes=MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        )
        require_context()
    for name, artifact in (("manifest.json", material.manifest), ("partition.json", partition)):
        require_context()
        binding = write_json_evidence(
            evidence_root=output_dir,
            relative_path=name,
            value=artifact,
            max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
            require_private_parent=True,
        )
        files.append(
            observe_regular_file_custody(
                root=output_dir,
                relative_path=name,
                expected_binding=binding,
                label="development partition metadata",
                max_bytes=MAX_DEVELOPMENT_PARTITION_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        )
        require_context()
    result = load_development_corpus_partition(
        reference=reference,
        partition_file=output_dir / "partition.json",
        manifest_file=output_dir / "manifest.json",
        corpus_root=source_root,
    )
    require_context()
    return result
