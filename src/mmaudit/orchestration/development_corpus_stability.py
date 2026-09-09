"""Provider-free retained-series ingestion with exact, private, bounded file custody."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    read_development_corpus_control_measurement,
)
from mmaudit.benchmark.development_corpus_stability import (
    MAX_DEVELOPMENT_STABILITY_BYTES,
    MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES,
    DevelopmentCorpusStability,
    measure_development_corpus_stability,
    read_development_corpus_stability,
    read_development_stability_selection,
)
from mmaudit.release_io import (
    read_composed_file_evidence,
    read_file_evidence,
    write_composed_json_evidence,
)
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


def write_development_corpus_stability(
    output_dir: Path,
    stability: DevelopmentCorpusStability,
    *,
    revalidate_context: Callable[[], object],
) -> RegularFileCustodyObservation:
    """Write a composed result only while every selected source remains the same file and bytes."""

    if type(stability) is not DevelopmentCorpusStability:
        raise ValueError("stability output requires its exact artifact type")

    def validate(content: bytes) -> None:
        revalidate_context()
        if read_development_corpus_stability(content) != stability:
            raise ValueError("stability output differs from its retained measurements")
        revalidate_context()

    revalidate_context()
    binding = write_composed_json_evidence(
        evidence_root=output_dir,
        relative_path="stability.json",
        value=stability.model_dump(mode="json"),
        max_bytes=MAX_DEVELOPMENT_STABILITY_BYTES,
        validate_content=validate,
    )
    result = observe_regular_file_custody(
        root=output_dir,
        relative_path=binding.path,
        expected_binding=binding,
        label="stability output",
        max_bytes=MAX_DEVELOPMENT_STABILITY_BYTES,
        allow_composed_evidence=True,
        allow_directory_entry_metadata_change=True,
    )
    revalidate_context()
    return result


def measure_development_corpus_stability_files(
    *, selection_file: Path, output_dir: Path
) -> DevelopmentCorpusStability:
    """Read a bounded explicit file selection only; never discover files, providers or credentials."""

    if any(
        not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
        for path in (selection_file, output_dir)
    ):
        raise ValueError("stability paths must be absolute and normalized")
    if selection_file.is_relative_to(output_dir) or output_dir.is_relative_to(selection_file):
        raise ValueError("stability selection and output overlap")
    parent = observe_unlinked_directory(
        output_dir.parent, label="stability output parent", allow_entry_metadata_change=True
    )
    selected = observe_regular_file_custody(
        root=selection_file.parent,
        relative_path=selection_file.name,
        label="stability selection",
        max_bytes=MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    raw = read_file_evidence(
        evidence_root=selection_file.parent,
        relative_path=selection_file.name,
        max_bytes=MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES,
    )
    if raw.binding != selected.binding:
        raise ValueError("stability selection changed during its read")
    selection = read_development_stability_selection(raw.content)
    if any(
        (selection_file.parent / f.path).is_relative_to(output_dir)
        or output_dir.is_relative_to(selection_file.parent / f.path)
        or selection_file.parent / f.path == selection_file
        for f in selection.measurements
    ):
        raise ValueError("stability selected measurement overlaps its selection or output")
    inputs: list[RegularFileCustodyObservation] = []

    def require_inputs() -> None:
        require_regular_file_custody_unchanged(
            selected,
            label="stability selection",
            max_bytes=MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES,
            allow_directory_entry_metadata_change=True,
        )
        for retained in inputs:
            require_regular_file_custody_unchanged(
                retained,
                label="stability measurement",
                max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
                allow_composed_evidence=True,
                allow_directory_entry_metadata_change=True,
            )
        require_same_unlinked_directory_objects(parent, label="stability output parent")

    measurements = []
    for binding in selection.measurements:
        require_inputs()
        retained = observe_regular_file_custody(
            root=selection_file.parent,
            relative_path=binding.path,
            expected_binding=binding,
            label="stability measurement",
            max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
            allow_composed_evidence=True,
            allow_directory_entry_metadata_change=True,
        )
        inputs.append(retained)
        content = read_composed_file_evidence(
            evidence_root=selection_file.parent,
            relative_path=binding.path,
            expected_binding=binding,
            max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
        ).content
        measurements.append(read_development_corpus_control_measurement(content))
        require_inputs()
    result = measure_development_corpus_stability(measurements=tuple(measurements))
    require_inputs()
    output = prepare_owned_empty_directory(output_dir, label="stability output")

    def require_context() -> None:
        require_inputs()
        require_same_unlinked_directory_objects(output, label="stability output")

    require_context()
    written = write_development_corpus_stability(
        output_dir, result, revalidate_context=require_context
    )
    require_context()
    require_regular_file_custody_unchanged(
        written,
        label="stability output",
        max_bytes=MAX_DEVELOPMENT_STABILITY_BYTES,
        allow_composed_evidence=True,
        allow_directory_entry_metadata_change=True,
    )
    require_context()
    return result
