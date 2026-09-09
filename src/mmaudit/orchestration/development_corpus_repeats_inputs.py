"""Exact local repeat-series input handoff; no credentials, discovery or provider execution."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import TypeAdapter

from mmaudit.benchmark.development_corpus import MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES
from mmaudit.models.development_corpus_repeats import (
    PreparedDevelopmentCorpusRepeats,
    prepare_development_corpus_repeats,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_review import DevelopmentReviewMetadata
from mmaudit.orchestration.development_corpus_repeats import _rebuild as rebuild_repeats
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import JsonEvidenceObservation, read_json_evidence
from mmaudit.repository.development_corpus import (
    LoadedDevelopmentCorpus,
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


@dataclass(frozen=True)
class DevelopmentCorpusRepeatsInputs:
    prepared: PreparedDevelopmentCorpusRepeats = field(repr=False)
    loaded: LoadedDevelopmentCorpus = field(repr=False)
    metadata_file: Path
    metadata_input: JsonEvidenceObservation = field(repr=False)
    truth_file: Path
    truth_input: JsonEvidenceObservation = field(repr=False)
    files: tuple[RegularFileCustodyObservation, ...]


def require_development_corpus_repeats_inputs(inputs: DevelopmentCorpusRepeatsInputs) -> None:
    """Recheck original bytes, identities and ancestors through handoff, never omitted members."""

    if (
        type(inputs) is not DevelopmentCorpusRepeatsInputs
        or type(inputs.loaded) is not LoadedDevelopmentCorpus
        or type(inputs.metadata_input) is not JsonEvidenceObservation
        or type(inputs.truth_input) is not JsonEvidenceObservation
        or type(inputs.files) is not tuple
        or any(type(f) is not RegularFileCustodyObservation for f in inputs.files)
    ):
        raise ValueError("repeat input handoff requires exact input and custody types")
    for raw, maximum in (
        (inputs.metadata_input, 2_000_000),
        (inputs.truth_input, MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES),
    ):
        if (
            type(raw.content) is not bytes
            or type(raw.binding) is not ManifestFileBinding
            or not 0 < len(raw.content) <= maximum
            or raw.binding.size != len(raw.content)
            or raw.binding.sha256 != hashlib.sha256(raw.content).hexdigest()
        ):
            raise ValueError("repeat raw input differs from its bounded original file binding")
    loaded = inputs.loaded
    expected = (
        (loaded.manifest_file.parent, loaded.manifest_binding),
        (inputs.metadata_file.parent, inputs.metadata_input.binding),
        (inputs.truth_file.parent, inputs.truth_input.binding),
        *((loaded.corpus_root, binding) for binding in loaded.source_bindings),
    )
    if (
        len(inputs.files) != len(expected)
        or tuple((f.root, f.binding) for f in inputs.files) != expected
        or inputs.metadata_input.binding.path != inputs.metadata_file.name
        or inputs.truth_input.binding.path != inputs.truth_file.name
    ):
        raise ValueError("repeat input handoff loses or substitutes original file bindings")
    revalidate_loaded_development_corpus(loaded)
    for retained in inputs.files:
        require_regular_file_custody_unchanged(
            retained,
            label="repeat input",
            max_bytes=retained.binding.size,
            allow_directory_entry_metadata_change=True,
        )
    prepared = rebuild_repeats(inputs.prepared)
    first = prepared.trials[0].shards[0]
    metadata: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
        inputs.metadata_input.content, strict=True
    )
    if (
        prepared.plan.trials[0].manifest != loaded.material.manifest
        or first.source_files != loaded.material.source_files
        or (first.discovery or first.endpoint_snapshot) != metadata
        or prepared.plan.benchmark.truth_file_content.encode() != inputs.truth_input.content
        or prepared.plan.benchmark.truth_file_sha256 != inputs.truth_input.binding.sha256
    ):
        raise ValueError("repeat prepared series differs from its original selected files")


def read_development_corpus_repeats_inputs(
    *,
    source_manifest: Path,
    corpus_root: Path,
    endpoint_snapshot: Path,
    truth_manifest: Path,
    truth_sha256: str,
    policy: DevelopmentCostPolicy,
    run_id: str,
    trial_count: int,
    maximum_completion_tokens: int = 4096,
    maximum_trial_seconds: float = 600.0,
    maximum_run_seconds: float = 600.0,
) -> DevelopmentCorpusRepeatsInputs:
    """Freeze all planned requests and local input custody before any credential is needed."""

    paths = (source_manifest, corpus_root, endpoint_snapshot, truth_manifest)
    if any(not p.is_absolute() or ".." in p.parts for p in paths) or len(set(paths)) != len(paths):
        raise ValueError("repeat input paths must be absolute, distinct and normalized")
    loaded = load_development_corpus(manifest_file=source_manifest, corpus_root=corpus_root)
    metadata_input = read_json_evidence(
        evidence_root=endpoint_snapshot.parent,
        relative_path=endpoint_snapshot.name,
        max_bytes=2_000_000,
    )
    truth_input = read_json_evidence(
        evidence_root=truth_manifest.parent,
        relative_path=truth_manifest.name,
        max_bytes=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
    )
    prepared = prepare_development_corpus_repeats(
        policy=policy,
        endpoint_snapshot=TypeAdapter(DevelopmentReviewMetadata).validate_json(
            metadata_input.content, strict=True
        ),
        manifest=loaded.material.manifest,
        source_files=loaded.material.source_files,
        run_id=run_id,
        trial_count=trial_count,
        truth_content=truth_input.content,
        expected_truth_sha256=truth_sha256,
        maximum_completion_tokens=maximum_completion_tokens,
        maximum_trial_seconds=maximum_trial_seconds,
        maximum_run_seconds=maximum_run_seconds,
    )
    bindings = (
        (source_manifest.parent, loaded.manifest_binding),
        (endpoint_snapshot.parent, metadata_input.binding),
        (truth_manifest.parent, truth_input.binding),
        *((corpus_root, binding) for binding in loaded.source_bindings),
    )
    files = tuple(
        observe_regular_file_custody(
            root=root,
            relative_path=binding.path,
            label="repeat input",
            expected_binding=binding,
            max_bytes=binding.size,
            allow_directory_entry_metadata_change=True,
        )
        for root, binding in bindings
    )
    result = DevelopmentCorpusRepeatsInputs(
        prepared, loaded, endpoint_snapshot, metadata_input, truth_manifest, truth_input, files
    )
    require_development_corpus_repeats_inputs(result)
    return result
