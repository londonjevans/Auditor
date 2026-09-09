"""Provider-free existing-history scoring with exact upstream custody and private derived output."""

from __future__ import annotations

from pathlib import Path

from mmaudit.benchmark.development_corpus_control_measurement import (
    MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
    measure_development_corpus_controls,
)
from mmaudit.benchmark.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
    DevelopmentCorpusResumeBenchmarkScore,
    score_development_corpus_resume,
)
from mmaudit.orchestration.development_corpus_control_measurement import (
    write_development_corpus_control_measurement,
)
from mmaudit.orchestration.development_corpus_resume import (
    _require_file,
    _write_cumulative_score,
    read_development_corpus_resume_inputs,
    require_development_corpus_resume_inputs,
)
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    require_regular_file_custody_unchanged,
)


def score_development_corpus_history_file(
    *, history_file: Path, output_dir: Path
) -> DevelopmentCorpusResumeBenchmarkScore:
    """Read only the explicit history and its original labels; no credential, ledger or provider."""

    if any(
        not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
        for path in (history_file, output_dir)
    ):
        raise ValueError("cumulative scoring paths must be absolute and normalized")
    if history_file.is_relative_to(output_dir) or output_dir.is_relative_to(history_file):
        raise ValueError("cumulative scoring input and output paths overlap")
    parent = observe_unlinked_directory(
        output_dir.parent,
        label="cumulative scoring output parent",
        allow_entry_metadata_change=True,
    )
    inputs = read_development_corpus_resume_inputs(history_file=history_file)
    score = score_development_corpus_resume(history=inputs.history)
    require_development_corpus_resume_inputs(inputs)
    require_same_unlinked_directory_objects(parent, label="cumulative scoring output parent")
    output = prepare_owned_empty_directory(output_dir, label="cumulative scoring output")
    bound: RegularFileCustodyObservation | None = None
    measurement_binding: RegularFileCustodyObservation | None = None

    def require_context() -> None:
        require_development_corpus_resume_inputs(inputs)
        require_same_unlinked_directory_objects(parent, label="cumulative scoring output parent")
        require_same_unlinked_directory_objects(output, label="cumulative scoring output")
        if bound is not None:
            _require_file(bound, max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES)
        if measurement_binding is not None:
            require_regular_file_custody_unchanged(
                measurement_binding,
                label="cumulative control measurement",
                max_bytes=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES,
                allow_directory_entry_metadata_change=True,
                allow_composed_evidence=True,
            )

    require_context()
    bound = _write_cumulative_score(output_dir, score, revalidate_context=require_context)
    require_context()
    _require_file(bound, max_bytes=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES)
    measured = measure_development_corpus_controls(score=score)
    require_context()
    measurement_binding = write_development_corpus_control_measurement(
        output_dir, measured, revalidate_context=require_context
    )
    require_context()
    return score
