"""Private automatic and provider-free control measurements under exact retained score custody."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    DevelopmentCorpusControlMeasurement,
    _source_limit,
    measure_development_corpus_controls,
    read_development_corpus_control_measurement,
    read_development_corpus_control_source,
)
from mmaudit.benchmark.development_corpus_resume import MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES
from mmaudit.release_io import read_file_evidence, write_composed_json_evidence
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


def write_development_corpus_control_measurement(
    output_dir: Path,
    measurement: DevelopmentCorpusControlMeasurement,
    *,
    revalidate_context: Callable[[], object],
) -> RegularFileCustodyObservation:
    """Use a separate bounded sidecar; upstream evidence and old input/output limits never change."""

    if type(measurement) is not DevelopmentCorpusControlMeasurement:
        raise ValueError("control measurement output requires its exact artifact type")

    def validate(content: bytes) -> None:
        revalidate_context()
        if read_development_corpus_control_measurement(content) != measurement:
            raise ValueError("control measurement output differs from retained source evidence")
        revalidate_context()

    revalidate_context()
    binding = write_composed_json_evidence(
        evidence_root=output_dir,
        relative_path="control-measurement.json",
        value=measurement.model_dump(mode="json"),
        max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
        validate_content=validate,
    )
    result = observe_regular_file_custody(
        root=output_dir,
        relative_path="control-measurement.json",
        expected_binding=binding,
        label="control measurement output",
        max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
        allow_directory_entry_metadata_change=True,
        allow_composed_evidence=True,
    )
    revalidate_context()
    return result


def measure_development_corpus_score_file(
    *, score_file: Path, output_dir: Path
) -> DevelopmentCorpusControlMeasurement:
    """Consume only an explicitly supplied original/cumulative score; no labels or provider inputs."""

    if any(
        not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
        for path in (score_file, output_dir)
    ):
        raise ValueError("control measurement paths must be absolute and normalized")
    if score_file.is_relative_to(output_dir) or output_dir.is_relative_to(score_file):
        raise ValueError("control measurement paths overlap")
    parent = observe_unlinked_directory(
        output_dir.parent,
        label="control measurement output parent",
        allow_entry_metadata_change=True,
    )
    retained = observe_regular_file_custody(
        root=score_file.parent,
        relative_path=score_file.name,
        label="control measurement input",
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
        allow_directory_entry_metadata_change=True,
    )
    raw = read_file_evidence(
        evidence_root=score_file.parent,
        relative_path=score_file.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
    )
    if raw.binding != retained.binding:
        raise ValueError("control measurement input changed during its selected read")
    score = read_development_corpus_control_source(raw.content)
    maximum = _source_limit(score)

    def require_input() -> None:
        require_regular_file_custody_unchanged(
            retained,
            label="control measurement input",
            max_bytes=maximum,
            allow_directory_entry_metadata_change=True,
        )
        require_same_unlinked_directory_objects(parent, label="control measurement output parent")

    require_input()
    result = measure_development_corpus_controls(score=score)
    require_input()
    output = prepare_owned_empty_directory(output_dir, label="control measurement output")

    def require_context() -> None:
        require_input()
        require_same_unlinked_directory_objects(output, label="control measurement output")

    require_context()
    written = write_development_corpus_control_measurement(
        output_dir, result, revalidate_context=require_context
    )
    require_context()
    require_regular_file_custody_unchanged(
        written,
        label="control measurement output",
        max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
        allow_directory_entry_metadata_change=True,
        allow_composed_evidence=True,
    )
    require_context()
    return result
