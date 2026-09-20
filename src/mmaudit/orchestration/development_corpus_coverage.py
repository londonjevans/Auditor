"""Provider-free tree coverage from exact retained records and a replayed source root."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.development_corpus_coverage import (
    MAX_DEVELOPMENT_COVERAGE_BYTES,
    MAX_DEVELOPMENT_COVERAGE_RUNS,
    DevelopmentCorpusCoverage,
    compute_development_corpus_coverage,
    read_development_corpus_coverage,
    read_development_coverage_record,
)
from mmaudit.models.development_corpus_partition import (
    MAX_DEVELOPMENT_PARTITION_BYTES,
    read_development_corpus_partition,
)
from mmaudit.release_io import read_json_evidence, write_json_evidence
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


def measure_development_corpus_coverage_files(
    *,
    manifest_file: Path,
    corpus_root: Path,
    record_files: tuple[Path, ...],
    output_dir: Path,
    partition_files: tuple[Path, ...] = (),
) -> DevelopmentCorpusCoverage:
    """Read explicit originals/histories only; no ledger, provider, discovery or output reuse."""

    if (
        type(record_files) is not tuple
        or len(record_files) > MAX_DEVELOPMENT_COVERAGE_RUNS
        or type(partition_files) is not tuple
        or len(partition_files) > MAX_DEVELOPMENT_COVERAGE_RUNS
    ):
        raise ValueError("corpus coverage requires a bounded explicit record-file tuple")
    inputs = (manifest_file, corpus_root, *record_files, *partition_files)
    if any(
        not isinstance(p, Path) or not p.is_absolute() or ".." in p.parts
        for p in (*inputs, output_dir)
    ):
        raise ValueError("corpus coverage paths must be absolute and normalized")
    if len(set((*record_files, *partition_files))) != len(record_files) + len(
        partition_files
    ) or any(p.is_relative_to(output_dir) or output_dir.is_relative_to(p) for p in inputs):
        raise ValueError("corpus coverage input/output paths overlap or repeat")
    parent = observe_unlinked_directory(
        output_dir.parent, label="corpus coverage output parent", allow_entry_metadata_change=True
    )
    loaded = load_development_corpus(manifest_file=manifest_file, corpus_root=corpus_root)
    files = []
    records = []
    partitions = []
    total = len(loaded.material.model_dump_json().encode())
    for path in record_files:
        remaining = MAX_DEVELOPMENT_COVERAGE_BYTES - total
        if remaining <= 0:
            raise ValueError("corpus coverage selected input bytes exceed their whole bound")
        observed = read_json_evidence(
            evidence_root=path.parent, relative_path=path.name, max_bytes=remaining
        )
        custody = observe_regular_file_custody(
            root=path.parent,
            relative_path=path.name,
            expected_binding=observed.binding,
            label="corpus coverage input",
            max_bytes=remaining,
            allow_directory_entry_metadata_change=True,
        )
        total += len(observed.content)
        files.append(custody)
        records.append(read_development_coverage_record(observed.content))
    for path in partition_files:
        remaining = min(MAX_DEVELOPMENT_PARTITION_BYTES, MAX_DEVELOPMENT_COVERAGE_BYTES - total)
        if remaining <= 0:
            raise ValueError("corpus coverage selected input bytes exceed their whole bound")
        observed = read_json_evidence(
            evidence_root=path.parent, relative_path=path.name, max_bytes=remaining
        )
        files.append(
            observe_regular_file_custody(
                root=path.parent,
                relative_path=path.name,
                expected_binding=observed.binding,
                label="corpus coverage partition",
                max_bytes=remaining,
                allow_directory_entry_metadata_change=True,
            )
        )
        total += len(observed.content)
        partitions.append(read_development_corpus_partition(observed.content))

    def require_inputs() -> None:
        revalidate_loaded_development_corpus(loaded)
        for item in files:
            require_regular_file_custody_unchanged(
                item,
                label="corpus coverage input",
                max_bytes=MAX_DEVELOPMENT_COVERAGE_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        require_same_unlinked_directory_objects(parent, label="corpus coverage output parent")

    require_inputs()
    result = compute_development_corpus_coverage(
        reference=loaded.material,
        records=tuple(records),
        partitions=tuple(partitions) if partition_files else None,
    )
    require_inputs()
    output = prepare_owned_empty_directory(output_dir, label="corpus coverage output")

    def require_context() -> None:
        require_inputs()
        require_same_unlinked_directory_objects(output, label="corpus coverage output")

    def validate(content: bytes) -> None:
        require_context()
        if read_development_corpus_coverage(content) != result:
            raise ValueError("corpus coverage output differs from its original source-bound inputs")
        require_context()

    binding = write_json_evidence(
        evidence_root=output_dir,
        relative_path="coverage.json",
        value=result,
        max_bytes=MAX_DEVELOPMENT_COVERAGE_BYTES,
        validate_content=validate,
        require_private_parent=True,
    )
    written = observe_regular_file_custody(
        root=output_dir,
        relative_path="coverage.json",
        expected_binding=binding,
        label="corpus coverage output",
        max_bytes=MAX_DEVELOPMENT_COVERAGE_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    require_context()
    require_regular_file_custody_unchanged(
        written,
        label="corpus coverage output",
        max_bytes=MAX_DEVELOPMENT_COVERAGE_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    require_context()
    return result
