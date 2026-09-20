"""Source-bound whole-tree primary response accounting, never validated audit coverage."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Any, Literal, Self

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    TypeAdapter,
    field_validator,
    model_serializer,
    model_validator,
)

from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import (
    _PATH,
    _SHA,
    MAX_DEVELOPMENT_CORPUS_FILES,
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    validate_development_corpus_sources,
)
from mmaudit.models.development_corpus_partition import (
    DevelopmentCorpusPartition,
    _validate_partition_from_replayed_reference,
    read_development_corpus_partition,
)
from mmaudit.models.development_corpus_replay import replay_development_corpus_material
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    DevelopmentCorpusResumeHistory,
)
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_COVERAGE_RUNS = 256
MAX_DEVELOPMENT_COVERAGE_BYTES = MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
type CoveragePath = Annotated[str, Field(min_length=1, max_length=512, pattern=_PATH)]
type CoveragePaths = Annotated[
    tuple[CoveragePath, ...], Field(max_length=MAX_DEVELOPMENT_CORPUS_FILES)
]
type CoverageRecord = DevelopmentCorpusObservation | DevelopmentCorpusResumeHistory
type CoverageIdentityShortfall = Literal[
    "SOURCE_BYTES_DIFFER",
    "TREE_IDENTITY_DIFFERS",
    "SOURCE_SCOPE_DIFFERS",
    "SOURCE_ORIGIN_NOT_REPLAYED",
]


class DevelopmentCorpusCoverageRun(_DevelopmentModel):
    record_sha256: str = Field(pattern=_SHA)
    original_observation_sha256: str = Field(pattern=_SHA)
    manifest_sha256: str = Field(pattern=_SHA)
    primary_paths: CoveragePaths
    context_paths: CoveragePaths
    original_successful_primary_paths: CoveragePaths
    successful_primary_paths: CoveragePaths
    failed_primary_paths: CoveragePaths
    missing_primary_paths: CoveragePaths
    source_drift_paths: CoveragePaths
    invalidated_primary_paths: CoveragePaths
    identity_shortfalls: tuple[CoverageIdentityShortfall, ...] = Field(max_length=4)


class DevelopmentCorpusCoverageSummary(_DevelopmentModel):
    status: Literal["ALL_PRIMARY_RESPONSES_OBSERVED", "INCOMPLETE"]
    original_first_attempt_complete: bool
    selected_primary_paths: CoveragePaths
    original_successful_primary_paths: CoveragePaths
    successful_primary_paths: CoveragePaths
    context_paths: CoveragePaths
    context_only_paths: CoveragePaths
    failed_primary_paths: CoveragePaths
    missing_primary_paths: CoveragePaths
    unobserved_primary_paths: CoveragePaths
    unselected_paths: CoveragePaths
    not_successfully_observed_paths: CoveragePaths
    invalidated_primary_paths: CoveragePaths
    source_drift_paths: tuple[CoveragePath, ...] = Field(
        max_length=MAX_DEVELOPMENT_COVERAGE_RUNS * MAX_DEVELOPMENT_CORPUS_FILES
    )


def _project(
    reference: DevelopmentCorpusMaterial,
    records: tuple[CoverageRecord, ...],
    partitions: tuple[DevelopmentCorpusPartition, ...] | None = None,
) -> tuple[tuple[DevelopmentCorpusCoverageRun, ...], DevelopmentCorpusCoverageSummary]:
    """Recompute every credit from an original response and its exact source population."""

    tree = reference.manifest.source_tree_evidence
    if tree is None or reference.manifest.source_origin is not None:
        raise ValueError("corpus coverage requires a complete-tree reference and root replay")
    originals = tuple(
        r.original if isinstance(r, DevelopmentCorpusResumeHistory) else r for r in records
    )
    if (
        reference.manifest.total_source_bytes
        + sum(r.plan.manifest.total_source_bytes for r in originals)
        + sum(p.manifest.total_source_bytes for p in partitions or ())
        > MAX_DEVELOPMENT_COVERAGE_BYTES
    ):
        raise ValueError("corpus coverage source replay work exceeds its bound")
    recipes = {p.manifest.manifest_sha256: p for p in partitions or ()}
    if len(recipes) != len(partitions or ()):
        raise ValueError("corpus coverage repeats a derived source manifest")
    original_manifests = {o.plan.manifest.manifest_sha256 for o in originals}
    if not recipes.keys() <= original_manifests:
        raise ValueError("corpus coverage includes an unused source partition")
    for selected_recipe in recipes.values():
        _validate_partition_from_replayed_reference(reference, selected_recipe)
    sources = {s.filename: s for s in reference.manifest.sources}
    source_bytes = dict(reference.source_files)
    reference_paths = set(sources)
    requests: set[str] = set()
    reservations: set[str] = set()
    generations: set[str] = set()
    projected = []
    for record, original in zip(records, originals, strict=True):
        manifest = original.plan.manifest
        stages: tuple[DevelopmentCorpusObservation | DevelopmentCorpusResumeAttempt, ...] = (
            (original, *record.continuations)
            if isinstance(record, DevelopmentCorpusResumeHistory)
            else (original,)
        )
        for stage in stages:
            planned = (
                stage.plan
                if isinstance(stage, DevelopmentCorpusObservation)
                else stage.plan.candidate
            )
            current_requests = {s.estimate.request_id for s in planned.shards}
            current_reservations = {a.reservation_id for a in stage.accounting}
            current_generations = {
                s.generation_id for s in stage.observations if s.generation_id is not None
            }
            if (
                requests & current_requests
                or reservations & current_reservations
                or generations & current_generations
            ):
                raise ValueError(
                    "corpus coverage overlaps original/resumed requests, reservations or generations"
                )
            requests.update(current_requests)
            reservations.update(current_reservations)
            generations.update(current_generations)
        drift = {s.filename for s in manifest.sources if sources.get(s.filename) != s}
        shortfalls: list[CoverageIdentityShortfall] = []
        recipe = recipes.get(manifest.manifest_sha256)
        origin_replayed = recipe is not None and recipe.manifest == manifest
        if manifest.source_origin is not None and not origin_replayed:
            shortfalls.append("SOURCE_ORIGIN_NOT_REPLAYED")
        if drift:
            shortfalls.append("SOURCE_BYTES_DIFFER")
        if (
            manifest.source_tree_evidence is not None
            and manifest.source_tree_evidence != tree
            and not origin_replayed
        ):
            shortfalls.append("TREE_IDENTITY_DIFFERS")
        if manifest.source_scope != reference.manifest.source_scope:
            shortfalls.append("SOURCE_SCOPE_DIFFERS")
        if not shortfalls:
            validate_development_corpus_sources(
                manifest, tuple((s.filename, source_bytes[s.filename]) for s in manifest.sources)
            )
        primary = {s.filename for s in manifest.primary_sources}
        context = {s.filename for s in manifest.context_sources}
        attempted = {s.source_filename for stage in stages for s in stage.observations}
        successful = {
            s.source_filename
            for stage in stages
            for s in stage.observations
            if s.status == "OBSERVED"
        }
        first = {s.source_filename for s in original.observations if s.status == "OBSERVED"}
        failed = {
            s.source_filename
            for stage in stages
            for s in stage.observations
            if s.status != "OBSERVED"
        }
        projected.append(
            DevelopmentCorpusCoverageRun(
                record_sha256=canonical_sha256(record.model_dump(mode="json")),
                original_observation_sha256=canonical_sha256(original.model_dump(mode="json")),
                manifest_sha256=manifest.manifest_sha256,
                primary_paths=tuple(sorted(primary)),
                context_paths=tuple(sorted(context)),
                original_successful_primary_paths=tuple(sorted(first if not shortfalls else ())),
                successful_primary_paths=tuple(sorted(successful if not shortfalls else ())),
                failed_primary_paths=tuple(sorted(failed)),
                missing_primary_paths=tuple(sorted(primary - attempted)),
                source_drift_paths=tuple(sorted(drift)),
                invalidated_primary_paths=tuple(sorted(primary if shortfalls else ())),
                identity_shortfalls=tuple(shortfalls),
            )
        )

    def union(paths: Iterable[tuple[str, ...]]) -> set[str]:
        return set().union(*paths)

    selected = union(r.primary_paths for r in projected) & reference_paths
    context = union(r.context_paths for r in projected) & reference_paths
    first = union(r.original_successful_primary_paths for r in projected) & reference_paths
    complete = union(r.successful_primary_paths for r in projected) & reference_paths
    invalidated = union(r.invalidated_primary_paths for r in projected) & reference_paths
    identity_failure = any(r.identity_shortfalls for r in projected)
    summary = DevelopmentCorpusCoverageSummary(
        status="ALL_PRIMARY_RESPONSES_OBSERVED"
        if complete == reference_paths and not identity_failure
        else "INCOMPLETE",
        original_first_attempt_complete=(
            first == reference_paths
            and not identity_failure
            and all(original.status == "OBSERVED_ALL_SHARDS" for original in originals)
        ),
        selected_primary_paths=tuple(sorted(selected)),
        original_successful_primary_paths=tuple(sorted(first)),
        successful_primary_paths=tuple(sorted(complete)),
        context_paths=tuple(sorted(context)),
        context_only_paths=tuple(sorted(context - selected)),
        failed_primary_paths=tuple(
            sorted(union(r.failed_primary_paths for r in projected) & reference_paths)
        ),
        missing_primary_paths=tuple(
            sorted(union(r.missing_primary_paths for r in projected) & reference_paths)
        ),
        unobserved_primary_paths=tuple(sorted(selected - complete)),
        unselected_paths=tuple(sorted(reference_paths - selected)),
        not_successfully_observed_paths=tuple(sorted(reference_paths - complete)),
        invalidated_primary_paths=tuple(sorted(invalidated)),
        source_drift_paths=tuple(sorted(union(r.source_drift_paths for r in projected))),
    )
    return tuple(projected), summary


class DevelopmentCorpusCoverage(_AuditArtifact):
    """Recorded response completion only; self-hashes never replace actual source custody."""

    schema_version: Literal["1.0", "1.1"] = "1.0"
    artifact_kind: Literal["development_corpus_coverage"] = "development_corpus_coverage"
    interpretation: Literal["SOURCE_BOUND_PRIMARY_RESPONSES_NOT_VALIDATED_AUDIT_COVERAGE"] = (
        "SOURCE_BOUND_PRIMARY_RESPONSES_NOT_VALIDATED_AUDIT_COVERAGE"
    )
    reference: DevelopmentCorpusMaterial
    records: tuple[CoverageRecord, ...] = Field(max_length=MAX_DEVELOPMENT_COVERAGE_RUNS)
    partitions: tuple[DevelopmentCorpusPartition, ...] | None = Field(
        default=None, min_length=1, max_length=MAX_DEVELOPMENT_COVERAGE_RUNS
    )
    run_coverage: tuple[DevelopmentCorpusCoverageRun, ...] = Field(
        max_length=MAX_DEVELOPMENT_COVERAGE_RUNS
    )
    summary: DevelopmentCorpusCoverageSummary
    root_replay_required: Literal[True] = True
    coverage_sha256: str = Field(pattern=_SHA)

    @model_serializer(mode="wrap")
    def preserve_legacy_coverage_bytes(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        if self.partitions is None:
            result.pop("partitions", None)
        return result

    @field_validator("root_replay_required", mode="before")
    @classmethod
    def actual_root_replay_is_required(cls, value: object) -> Literal[True]:
        if value is not True:
            raise ValueError("corpus coverage always requires actual root replay")
        return True

    @model_validator(mode="after")
    def all_source_roles_attempts_and_shortfalls_recompute(self) -> Self:
        if (self.schema_version == "1.1") != (self.partitions is not None):
            raise ValueError("corpus coverage partitions require their exact version")
        partition_ids = tuple(p.partition_sha256 for p in self.partitions or ())
        if partition_ids != tuple(sorted(set(partition_ids))):
            raise ValueError("corpus coverage requires canonical distinct source partitions")
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_COVERAGE_BYTES:
            raise ValueError("corpus coverage artifact exceeds its byte bound")
        identities = tuple(canonical_sha256(r.model_dump(mode="json")) for r in self.records)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("corpus coverage requires canonically ordered distinct records")
        runs, summary = _project(self.reference, self.records, self.partitions)
        if self.run_coverage != runs or self.summary != summary:
            raise ValueError(
                "corpus coverage hides or changes source roles, attempts or shortfalls"
            )
        if self.coverage_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"coverage_sha256"})
        ):
            raise ValueError("corpus coverage digest differs")
        return self


def read_development_coverage_record(content: bytes) -> CoverageRecord:
    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_COVERAGE_BYTES:
        raise ValueError("corpus coverage record exceeds its byte bound")
    return TypeAdapter(CoverageRecord).validate_json(content, strict=True)


def compute_development_corpus_coverage(
    *,
    reference: DevelopmentCorpusMaterial,
    records: tuple[CoverageRecord, ...],
    partitions: tuple[DevelopmentCorpusPartition, ...] | None = None,
) -> DevelopmentCorpusCoverage:
    """Join exact supplied records without dispatch, discovery, accounting mutation or I/O."""

    if (
        type(reference) is not DevelopmentCorpusMaterial
        or type(records) is not tuple
        or len(records) > MAX_DEVELOPMENT_COVERAGE_RUNS
        or (
            partitions is not None
            and (
                type(partitions) is not tuple
                or not 0 < len(partitions) <= MAX_DEVELOPMENT_COVERAGE_RUNS
                or any(type(p) is not DevelopmentCorpusPartition for p in partitions)
            )
        )
    ):
        raise ValueError("corpus coverage requires exact bounded reference and record types")
    if any(
        type(r) not in {DevelopmentCorpusObservation, DevelopmentCorpusResumeHistory}
        for r in records
    ):
        raise ValueError("corpus coverage requires exact original or resumed record types")
    reference_json = reference.model_dump_json()
    contents = tuple(r.model_dump_json().encode() for r in records)
    recipes = tuple(p.model_dump_json().encode() for p in partitions or ())
    if (
        len(reference_json.encode()) + sum(map(len, (*contents, *recipes)))
        > MAX_DEVELOPMENT_COVERAGE_BYTES
    ):
        raise ValueError("corpus coverage selected input bytes exceed their whole bound")
    reference = replay_development_corpus_material(reference_json)
    retained = tuple(
        sorted(
            (read_development_coverage_record(raw) for raw in contents),
            key=lambda r: canonical_sha256(r.model_dump(mode="json")),
        )
    )
    retained_partitions = (
        tuple(
            sorted(
                (read_development_corpus_partition(raw) for raw in recipes),
                key=lambda p: p.partition_sha256,
            )
        )
        if partitions is not None
        else None
    )
    runs, summary = _project(reference, retained, retained_partitions)
    values: dict[str, Any] = dict(
        reference=reference, records=retained, run_coverage=runs, summary=summary
    )
    if retained_partitions is not None:
        values.update(schema_version="1.1", partitions=retained_partitions)
    provisional = DevelopmentCorpusCoverage.model_construct(**values, coverage_sha256="0" * 64)
    values["coverage_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"coverage_sha256"})
    )
    return DevelopmentCorpusCoverage.model_validate(values)


def read_development_corpus_coverage(content: bytes) -> DevelopmentCorpusCoverage:
    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_COVERAGE_BYTES:
        raise ValueError("corpus coverage artifact exceeds its byte bound")
    return DevelopmentCorpusCoverage.model_validate_json(content, strict=True)
