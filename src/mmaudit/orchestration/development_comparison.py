"""Bounded local score comparison with exact input custody and exclusive private output."""

from __future__ import annotations

from pathlib import Path

from mmaudit.benchmark.development import DevelopmentBenchmarkScore
from mmaudit.benchmark.development_comparison import (
    MAX_DEVELOPMENT_COMPARISON_BYTES,
    MAX_DEVELOPMENT_COMPARISON_RUNS,
    MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES,
    DevelopmentBenchmarkComparison,
    compare_development_scores,
)
from mmaudit.release_io import (
    read_json_evidence,
    revalidate_evidence_file_binding,
    write_json_evidence,
)


def compare_development_score_files(
    *, score_files: tuple[Path, ...], output_file: Path
) -> DevelopmentBenchmarkComparison:
    """Read only explicitly selected scores; never load credentials, a ledger or a provider."""

    if (
        type(score_files) is not tuple
        or not 2 <= len(score_files) <= MAX_DEVELOPMENT_COMPARISON_RUNS
    ):
        raise ValueError("development comparison requires two through eight input files")
    paths = (*score_files, output_file)
    if any(not isinstance(path, Path) for path in paths) or any(
        not path.is_absolute() or ".." in path.parts for path in paths
    ):
        raise ValueError("development comparison paths must be absolute and normalized")
    if len(set(paths)) != len(paths) or any(
        path.is_relative_to(output_file) or output_file.is_relative_to(path) for path in score_files
    ):
        raise ValueError("development comparison paths overlap or repeat")
    observed = tuple(
        read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES,
        )
        for path in score_files
    )
    result = compare_development_scores(
        tuple(
            DevelopmentBenchmarkScore.model_validate_json(item.content, strict=True)
            for item in observed
        )
    )

    def revalidate_inputs() -> None:
        for path, item in zip(score_files, observed, strict=True):
            revalidate_evidence_file_binding(
                evidence_root=path.parent,
                binding=item.binding,
                max_bytes=MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES,
            )

    def validate_output(content: bytes) -> None:
        revalidate_inputs()
        restored = DevelopmentBenchmarkComparison.model_validate_json(content, strict=True)
        if restored != result:
            raise ValueError("development comparison output differs from its exact inputs")

    revalidate_inputs()
    write_json_evidence(
        evidence_root=output_file.parent,
        relative_path=output_file.name,
        value=result.model_dump(mode="json"),
        max_bytes=MAX_DEVELOPMENT_COMPARISON_BYTES,
        validate_content=validate_output,
        require_private_parent=True,
    )
    return result
