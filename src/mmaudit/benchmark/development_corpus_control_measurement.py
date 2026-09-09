"""Annotation-independent control locations, never semantic findings or replacement old scores."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development import _WEIGHTS, _contains
from mmaudit.benchmark.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_SCORE_BYTES,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusBenchmarkTruth,
    DevelopmentCorpusMeasurementRatio,
    _ratio,
)
from mmaudit.benchmark.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
    DevelopmentCorpusResumeBenchmarkScore,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import (
    DevelopmentCorpusPlan,
    DevelopmentCorpusShardObservation,
)
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import _decode_json
from mmaudit.repository.redaction import detect_secrets

MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES = 128_000_000
_SHA = r"^[0-9a-f]{64}$"
_ID = r"^[a-z][a-z0-9-]{0,63}$"
_REQUEST = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
_CLAIM = r"^file-00(?:0[1-9]|[1-5][0-9]|6[0-4]):(?:0[1-9]|1[0-6])$"
type _Category = Literal["access_control", "accounting", "reservation", "pause", "other"]
type DevelopmentCorpusControlSource = Annotated[
    DevelopmentCorpusBenchmarkScore | DevelopmentCorpusResumeBenchmarkScore,
    Field(discriminator="artifact_kind"),
]


class DevelopmentCorpusControlClaim(_DevelopmentModel):
    """One original claim, its location predicates and annotations; no inferred semantic verdict."""

    claim_id: str = Field(pattern=_CLAIM)
    stage_index: int = Field(ge=0, le=8)
    run_id: str = Field(pattern=_REQUEST)
    request_id: str = Field(pattern=_REQUEST)
    reported_kind: Literal["invariant_violation", "advisory"]
    reported_category: _Category | None
    declared_category: _Category | None
    category_agrees: bool | None
    origin_basis: Literal["EXPLICIT_ROOT_REFERENCE", "PRIMARY_SPAN"]
    primary_site_candidate_count: int = Field(ge=0, le=1024)
    anchored_candidate_count: int = Field(ge=0, le=1024)
    control_id: str | None = Field(pattern=_ID)
    expected: Literal["PLANTED", "GUARDED"] | None
    disposition: Literal["PLANTED_LOCATION", "GUARDED_LOCATION", "AMBIGUOUS", "UNMATCHED"]
    duplicate_location: bool
    duplicate_assertion: bool
    weight: int = Field(ge=1, le=10)


class DevelopmentCorpusControlSummary(_DevelopmentModel):
    """Location coverage and asserted-violation coverage have separate sets and shared denominators."""

    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    total_claim_count: int = Field(ge=0, le=1024)
    invariant_claim_count: int = Field(ge=0, le=1024)
    advisory_claim_count: int = Field(ge=0, le=1024)
    ambiguous_claim_count: int = Field(ge=0, le=1024)
    unmatched_claim_count: int = Field(ge=0, le=1024)
    duplicate_location_count: int = Field(ge=0, le=1024)
    duplicate_assertion_count: int = Field(ge=0, le=1024)
    guarded_invariant_claim_count: int = Field(ge=0, le=1024)
    guarded_advisory_claim_count: int = Field(ge=0, le=1024)
    matched_category_agreement_count: int = Field(ge=0, le=1024)
    matched_category_disagreement_count: int = Field(ge=0, le=1024)
    matched_category_unreported_count: int = Field(ge=0, le=1024)
    expected_root_ids: tuple[str, ...] = Field(max_length=1024)
    located_root_ids: tuple[str, ...] = Field(max_length=1024)
    invariant_asserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    advisory_only_root_ids: tuple[str, ...] = Field(max_length=1024)
    unlocated_root_ids: tuple[str, ...] = Field(max_length=1024)
    observed_unlocated_root_ids: tuple[str, ...] = Field(max_length=1024)
    unobserved_unlocated_root_ids: tuple[str, ...] = Field(max_length=1024)
    unasserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    observed_unasserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    unobserved_unasserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    unique_root_location_coverage: DevelopmentCorpusMeasurementRatio
    severity_weighted_root_location_coverage: DevelopmentCorpusMeasurementRatio
    severity_weighted_structural_precision: DevelopmentCorpusMeasurementRatio
    invariant_asserted_root_coverage: DevelopmentCorpusMeasurementRatio
    severity_weighted_asserted_root_coverage: DevelopmentCorpusMeasurementRatio
    severity_weighted_asserted_structural_precision: DevelopmentCorpusMeasurementRatio


def _json_object(content: bytes, *, maximum: int) -> dict[str, Any]:
    if type(content) is not bytes or not 0 < len(content) <= maximum:
        raise ValueError("control measurement JSON exceeds its byte bound")
    content.decode("utf-8")
    try:
        value = _decode_json(content)
    except (RecursionError, OverflowError):
        raise ValueError("control measurement JSON exceeds its structural bound") from None
    if type(value) is not dict:
        raise ValueError("control measurement requires an unambiguous JSON object")
    return value


def read_development_corpus_control_source(content: bytes) -> DevelopmentCorpusControlSource:
    """Read only an existing exact score; each source keeps its own old 32/96 MB bound."""

    value = _json_object(content, maximum=MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES)
    if value.get("artifact_kind") == "development_corpus_benchmark_score":
        if len(content) > MAX_DEVELOPMENT_CORPUS_SCORE_BYTES:
            raise ValueError("original control measurement source exceeds its original bound")
        return DevelopmentCorpusBenchmarkScore.model_validate_json(content, strict=True)
    if value.get("artifact_kind") == "development_corpus_resume_benchmark_score":
        return DevelopmentCorpusResumeBenchmarkScore.model_validate_json(content, strict=True)
    raise ValueError("control measurement requires an original or cumulative retained score")


def _source_limit(source: DevelopmentCorpusControlSource) -> int:
    if type(source) is DevelopmentCorpusBenchmarkScore:
        return MAX_DEVELOPMENT_CORPUS_SCORE_BYTES
    if type(source) is DevelopmentCorpusResumeBenchmarkScore:
        return MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES
    raise ValueError("control measurement requires an exact retained score type")


@dataclass(frozen=True)
class _ObservedShard:
    stage_index: int
    run_id: str
    request_id: str
    observation: DevelopmentCorpusShardObservation


def _source_parts(
    source: DevelopmentCorpusControlSource,
) -> tuple[DevelopmentCorpusBenchmarkTruth, tuple[_ObservedShard, ...], bool]:
    stages: tuple[tuple[DevelopmentCorpusPlan, tuple[DevelopmentCorpusShardObservation, ...]], ...]
    if isinstance(source, DevelopmentCorpusBenchmarkScore):
        original = source.observation
        truth = source.binding.truth
        stages = ((original.plan, original.observations),)
        complete = original.status == "OBSERVED_ALL_SHARDS"
    else:
        original = source.history.original
        assert source.history.original_score is not None
        truth = source.history.original_score.binding.truth
        stages = (
            (original.plan, original.observations),
            *(
                (attempt.plan.candidate, attempt.observations)
                for attempt in source.history.continuations
            ),
        )
        complete = source.cumulative_quality.quality_scope == "COMPLETE_OBSERVATIONS"
    observed: dict[str, _ObservedShard] = {}
    for index, (plan, observations) in enumerate(stages):
        requests = {shard.shard_id: shard.estimate.request_id for shard in plan.shards}
        for shard in observations:
            if shard.status != "OBSERVED":
                continue
            if shard.shard_id in observed:
                raise ValueError(
                    "control measurement cannot choose between repeated source responses"
                )
            observed[shard.shard_id] = _ObservedShard(
                index, plan.run_id, requests[shard.shard_id], shard
            )
    return (
        truth,
        tuple(observed[s.shard_id] for s in original.plan.shards if s.shard_id in observed),
        complete,
    )


def _measure_locations(
    truth: DevelopmentCorpusBenchmarkTruth,
    observations: tuple[_ObservedShard, ...],
    *,
    complete: bool,
) -> tuple[tuple[DevelopmentCorpusControlClaim, ...], DevelopmentCorpusControlSummary]:
    claims: list[DevelopmentCorpusControlClaim] = []
    located: set[str] = set()
    asserted: set[str] = set()
    observed_files = {item.observation.source_filename for item in observations}
    for item in observations:
        shard = item.observation
        assert shard.response is not None
        for index, finding in enumerate(shard.response.findings, 1):
            primary = tuple(
                control
                for control in truth.controls
                if any(
                    _contains(site, shard.source_filename, finding.line_start, finding.line_end)
                    for site in control.claim_sites
                )
            )
            origin = finding.root_cause_ref
            filename = origin.filename if origin is not None else shard.source_filename
            start = origin.line_start if origin is not None else finding.line_start
            end = origin.line_end if origin is not None else finding.line_end
            candidates = tuple(
                control
                for control in primary
                if _contains(control.origin, filename, start, end)
                and start <= control.required_origin_line <= end
            )
            control = candidates[0] if len(candidates) == 1 else None
            planted_id = (
                control.control_id
                if control is not None and control.expected == "PLANTED"
                else None
            )
            planted = planted_id is not None
            duplicate = planted_id is not None and planted_id in located
            duplicate_assertion = (
                planted_id is not None
                and finding.kind == "invariant_violation"
                and planted_id in asserted
            )
            if planted_id is not None:
                located.add(planted_id)
                if finding.kind == "invariant_violation":
                    asserted.add(planted_id)
            claims.append(
                DevelopmentCorpusControlClaim(
                    claim_id=f"{shard.shard_id}:{index:02d}",
                    stage_index=item.stage_index,
                    run_id=item.run_id,
                    request_id=item.request_id,
                    reported_kind=finding.kind,
                    reported_category=finding.vulnerability_class,
                    declared_category=control.vulnerability_class if control is not None else None,
                    category_agrees=(finding.vulnerability_class == control.vulnerability_class)
                    if control is not None and finding.vulnerability_class is not None
                    else None,
                    origin_basis="EXPLICIT_ROOT_REFERENCE"
                    if origin is not None
                    else "PRIMARY_SPAN",
                    primary_site_candidate_count=len(primary),
                    anchored_candidate_count=len(candidates),
                    control_id=control.control_id if control is not None else None,
                    expected=control.expected if control is not None else None,
                    disposition="PLANTED_LOCATION"
                    if planted
                    else "GUARDED_LOCATION"
                    if control is not None
                    else "AMBIGUOUS"
                    if candidates
                    else "UNMATCHED",
                    duplicate_location=duplicate,
                    duplicate_assertion=duplicate_assertion,
                    weight=max(_WEIGHTS[c.severity] for c in candidates)
                    if candidates
                    else _WEIGHTS[finding.severity],
                )
            )
    roots = tuple(c for c in truth.controls if c.expected == "PLANTED")
    weight = sum(_WEIGHTS[c.severity] for c in roots)
    located_weight = sum(_WEIGHTS[c.severity] for c in roots if c.control_id in located)
    asserted_weight = sum(_WEIGHTS[c.severity] for c in roots if c.control_id in asserted)
    claim_weight = sum(c.weight for c in claims)
    unlocated = tuple(c for c in roots if c.control_id not in located)
    unasserted = tuple(c for c in roots if c.control_id not in asserted)

    fully_observed_roots = {
        c.control_id
        for c in roots
        if all(site.filename in observed_files for site in c.claim_sites)
    }

    summary = DevelopmentCorpusControlSummary(
        quality_scope="COMPLETE_OBSERVATIONS" if complete else "INCOMPLETE_OBSERVATIONS",
        total_claim_count=len(claims),
        invariant_claim_count=sum(c.reported_kind == "invariant_violation" for c in claims),
        advisory_claim_count=sum(c.reported_kind == "advisory" for c in claims),
        ambiguous_claim_count=sum(c.disposition == "AMBIGUOUS" for c in claims),
        unmatched_claim_count=sum(c.disposition == "UNMATCHED" for c in claims),
        duplicate_location_count=sum(c.duplicate_location for c in claims),
        duplicate_assertion_count=sum(c.duplicate_assertion for c in claims),
        guarded_invariant_claim_count=sum(
            c.expected == "GUARDED" and c.reported_kind == "invariant_violation" for c in claims
        ),
        guarded_advisory_claim_count=sum(
            c.expected == "GUARDED" and c.reported_kind == "advisory" for c in claims
        ),
        matched_category_agreement_count=sum(c.category_agrees is True for c in claims),
        matched_category_disagreement_count=sum(c.category_agrees is False for c in claims),
        matched_category_unreported_count=sum(
            c.control_id is not None and c.reported_category is None for c in claims
        ),
        expected_root_ids=tuple(c.control_id for c in roots),
        located_root_ids=tuple(c.control_id for c in roots if c.control_id in located),
        invariant_asserted_root_ids=tuple(c.control_id for c in roots if c.control_id in asserted),
        advisory_only_root_ids=tuple(
            c.control_id for c in roots if c.control_id in located - asserted
        ),
        unlocated_root_ids=tuple(c.control_id for c in unlocated),
        observed_unlocated_root_ids=tuple(
            c.control_id for c in unlocated if c.control_id in fully_observed_roots
        ),
        unobserved_unlocated_root_ids=tuple(
            c.control_id for c in unlocated if c.control_id not in fully_observed_roots
        ),
        unasserted_root_ids=tuple(c.control_id for c in unasserted),
        observed_unasserted_root_ids=tuple(
            c.control_id for c in unasserted if c.control_id in fully_observed_roots
        ),
        unobserved_unasserted_root_ids=tuple(
            c.control_id for c in unasserted if c.control_id not in fully_observed_roots
        ),
        unique_root_location_coverage=_ratio(len(located), len(roots), complete=complete),
        severity_weighted_root_location_coverage=_ratio(located_weight, weight, complete=complete),
        severity_weighted_structural_precision=_ratio(
            located_weight, claim_weight, complete=complete
        ),
        invariant_asserted_root_coverage=_ratio(len(asserted), len(roots), complete=complete),
        severity_weighted_asserted_root_coverage=_ratio(asserted_weight, weight, complete=complete),
        severity_weighted_asserted_structural_precision=_ratio(
            asserted_weight, claim_weight, complete=complete
        ),
    )
    return tuple(claims), summary


def _projection(source: DevelopmentCorpusControlSource) -> dict[str, Any]:
    truth, observations, complete = _source_parts(source)
    claims, summary = _measure_locations(truth, observations, complete=complete)
    return {
        "source_score": source,
        "source_score_sha256": canonical_sha256(source.model_dump(mode="json")),
        "source_scope": "ORIGINAL_FIRST_ATTEMPT"
        if type(source) is DevelopmentCorpusBenchmarkScore
        else "CUMULATIVE_RECORDED_ATTEMPTS",
        "claims": claims,
        "summary": summary,
    }


class DevelopmentCorpusControlMeasurement(_AuditArtifact):
    """A new measurement beside an immutable old score, not rewritten truth or qualified recall."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_control_measurement"] = (
        "development_corpus_control_measurement"
    )
    scorer_version: Literal["manifest-annotation-independent-controls-v1"] = (
        "manifest-annotation-independent-controls-v1"
    )
    interpretation: Literal["CONTROL_LOCATIONS_NOT_VALIDATED_FINDINGS"] = (
        "CONTROL_LOCATIONS_NOT_VALIDATED_FINDINGS"
    )
    root_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    annotation_policy: Literal["CATEGORY_AND_KIND_ARE_NOT_LOCATION_MATCH_PREDICATES"] = (
        "CATEGORY_AND_KIND_ARE_NOT_LOCATION_MATCH_PREDICATES"
    )
    origin_policy: Literal["EXPLICIT_REFERENCE_OR_SAME_FILE_ANCHORED_PRIMARY_SPAN"] = (
        "EXPLICIT_REFERENCE_OR_SAME_FILE_ANCHORED_PRIMARY_SPAN"
    )
    precision_denominator: Literal["ALL_CLAIMS_WITH_FROZEN_MATCH_OR_MAX_AMBIGUOUS_WEIGHTS"] = (
        "ALL_CLAIMS_WITH_FROZEN_MATCH_OR_MAX_AMBIGUOUS_WEIGHTS"
    )
    cost_runtime_reference: Literal["EXACT_EMBEDDED_SCORE_NOT_NEW_RECONCILIATION_OR_END_TO_END"] = (
        "EXACT_EMBEDDED_SCORE_NOT_NEW_RECONCILIATION_OR_END_TO_END"
    )
    source_score: DevelopmentCorpusControlSource
    source_score_sha256: str = Field(pattern=_SHA)
    source_scope: Literal["ORIGINAL_FIRST_ATTEMPT", "CUMULATIVE_RECORDED_ATTEMPTS"]
    claims: tuple[DevelopmentCorpusControlClaim, ...] = Field(max_length=1024)
    summary: DevelopmentCorpusControlSummary
    measurement_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def retained_score_reproduces_locations_annotations_and_all_denominators(self) -> Self:
        source = self.source_score.model_dump_json()
        if (
            len(source.encode()) > _source_limit(self.source_score)
            or detect_secrets(source)
            or len(self.model_dump_json().encode())
            > MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES
        ):
            raise ValueError("control measurement exceeds its bounds or contains secret-like data")
        if any(
            getattr(self, key) != value for key, value in _projection(self.source_score).items()
        ):
            raise ValueError("control measurement differs from its exact retained score")
        if self.measurement_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"measurement_sha256"})
        ):
            raise ValueError("control measurement digest differs")
        return self


def measure_development_corpus_controls(
    *, score: DevelopmentCorpusControlSource
) -> DevelopmentCorpusControlMeasurement:
    """Measure only retained labels and responses; no provider, truth override or semantic verdict."""

    maximum = _source_limit(score)
    content = score.model_dump_json().encode()
    if len(content) > maximum:
        raise ValueError("control measurement source exceeds its original bound")
    source = read_development_corpus_control_source(content)
    fields = _projection(source)
    draft = DevelopmentCorpusControlMeasurement.model_construct(
        **fields, measurement_sha256="0" * 64
    )
    digest = canonical_sha256(draft.model_dump(mode="json", exclude={"measurement_sha256"}))
    return DevelopmentCorpusControlMeasurement(**fields, measurement_sha256=digest)


def read_development_corpus_control_measurement(
    content: bytes,
) -> DevelopmentCorpusControlMeasurement:
    """Bound and reproduce the new artifact without rebinding its embedded older evidence."""

    _json_object(content, maximum=MAX_DEVELOPMENT_CORPUS_CONTROL_MEASUREMENT_BYTES)
    return DevelopmentCorpusControlMeasurement.model_validate_json(content, strict=True)
