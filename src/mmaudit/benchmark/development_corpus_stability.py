"""Bounded retained-run control jitter, not predictive stability or qualified audit evidence."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development import _WEIGHTS, DevelopmentMeasurementRatio
from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusTruthControl,
)
from mmaudit.benchmark.development_corpus_control_measurement import (
    DevelopmentCorpusControlMeasurement,
    _json_object,
    _source_parts,
    read_development_corpus_control_measurement,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import DevelopmentCorpusObservation, DevelopmentCorpusPlan
from mmaudit.models.development_corpus_resume import DevelopmentCorpusResumeAttempt
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.models.schemas import Severity
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256

MAX_DEVELOPMENT_STABILITY_TRIALS = 8
MAX_DEVELOPMENT_STABILITY_INPUT_BYTES = 128_000_000
MAX_DEVELOPMENT_STABILITY_BYTES = 192_000_000
MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES = 65_536
_SHA = r"^[0-9a-f]{64}$"
_ID = r"^[a-z][a-z0-9-]{0,63}$"
_REQUEST = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
type _Indices = tuple[Annotated[int, Field(ge=0, le=7)], ...]
type _Stage = DevelopmentCorpusObservation | DevelopmentCorpusResumeAttempt
type _Scope = Literal["ORIGINAL_FIRST_ATTEMPT", "CUMULATIVE_RECORDED_ATTEMPTS"]
type _FrequencyClass = Literal[
    "INCOMPLETE_OBSERVATIONS", "NO_REPEATS", "STABLE", "INTERMITTENT", "SINGLE_RUN", "NEVER"
]
type _ComparisonScope = Literal[
    "SAME_ORIGINAL_REQUEST_CONFIGURATION",
    "SAME_REQUEST_CONFIGURATION_CONTINUATION_CHAINS_NOT_SINGLE_PASSES",
    "MIXED_CONFIGURATION_SCOPE_OR_TRANSPORT",
]


def _bounded_selection_files_schema(schema: dict[str, Any]) -> None:
    """Keep the generated file-binding reference while constraining this consumer's size only."""

    schema["items"] = {
        "allOf": [
            schema["items"],
            {"properties": {"size": {"minimum": 1, "maximum": 128_000_000}}},
        ]
    }


class DevelopmentStabilitySelection(_AuditArtifact):
    """Explicit retained files, not preregistration, source authority or permission to execute."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_stability_selection"] = (
        "development_corpus_stability_selection"
    )
    measurements: tuple[ManifestFileBinding, ...] = Field(
        min_length=2,
        max_length=8,
        json_schema_extra=_bounded_selection_files_schema,
    )

    @model_validator(mode="after")
    def distinct_files_fit_the_aggregate_read_bound(self) -> Self:
        if len({f.path for f in self.measurements}) != len(self.measurements):
            raise ValueError("stability selection repeats a measurement file")
        if any(not 0 < f.size <= MAX_DEVELOPMENT_STABILITY_INPUT_BYTES for f in self.measurements):
            raise ValueError("stability selection has an invalid measurement byte bound")
        if sum(f.size for f in self.measurements) > MAX_DEVELOPMENT_STABILITY_INPUT_BYTES:
            raise ValueError("stability selection exceeds its aggregate read bound")
        return self


def read_development_stability_selection(content: bytes) -> DevelopmentStabilitySelection:
    """Read only exact bounded file selections; default evidence limits remain unchanged."""

    _json_object(content, maximum=MAX_DEVELOPMENT_STABILITY_SELECTION_BYTES)
    return DevelopmentStabilitySelection.model_validate_json(content, strict=True)


class DevelopmentStabilityRatio(DevelopmentMeasurementRatio):
    numerator: int = Field(ge=0, le=81_920)
    denominator: int = Field(ge=0, le=81_920)


def _ratio(numerator: int, denominator: int, *, complete: bool) -> DevelopmentStabilityRatio:
    return DevelopmentStabilityRatio(
        numerator=numerator,
        denominator=denominator,
        state="INCOMPLETE_SCOPE"
        if not complete
        else "OBSERVED"
        if denominator
        else "EMPTY_DENOMINATOR",
        value=round(numerator / denominator, 6) if complete and denominator else None,
    )


class DevelopmentControlFrequency(_DevelopmentModel):
    """Every selected trial remains in the denominator, including unavailable source observations."""

    positive_trial_indexes: _Indices = Field(max_length=8)
    known_absence_trial_indexes: _Indices = Field(max_length=8)
    unobserved_trial_indexes: _Indices = Field(max_length=8)
    frequency: DevelopmentStabilityRatio
    classification: _FrequencyClass


class DevelopmentControlStability(_DevelopmentModel):
    control_id: str = Field(pattern=_ID)
    expected: Literal["PLANTED", "GUARDED"]
    severity: Severity
    location: DevelopmentControlFrequency
    assertion: DevelopmentControlFrequency


class DevelopmentStabilityTrial(_DevelopmentModel):
    trial_index: int = Field(ge=0, le=7)
    measurement_sha256: str = Field(pattern=_SHA)
    source_score_sha256: str = Field(pattern=_SHA)
    source_scope: _Scope
    original_run_id: str = Field(pattern=_REQUEST)
    run_ids: tuple[str, ...] = Field(min_length=1, max_length=9)
    configuration_sha256: str = Field(pattern=_SHA)
    cohort_sha256: str = Field(pattern=_SHA)
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    selected_request_count: int = Field(ge=1, le=576)
    missing_accounting_request_ids: tuple[str, ...] = Field(max_length=576)
    unknown_actual_cost_request_ids: tuple[str, ...] = Field(max_length=72)
    missing_runtime_request_ids: tuple[str, ...] = Field(max_length=576)
    accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    sum_run_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)


class DevelopmentStabilitySeverity(_DevelopmentModel):
    severity: Severity
    expected_root_count: int = Field(ge=0, le=1024)
    located_union_root_ids: tuple[str, ...] = Field(max_length=1024)
    asserted_union_root_ids: tuple[str, ...] = Field(max_length=1024)
    stable_asserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    intermittent_asserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    single_run_asserted_root_ids: tuple[str, ...] = Field(max_length=1024)
    unobserved_assertion_root_ids: tuple[str, ...] = Field(max_length=1024)
    guarded_assertion_control_ids: tuple[str, ...] = Field(max_length=1024)


class DevelopmentStabilityPair(_DevelopmentModel):
    left_trial_index: int = Field(ge=0, le=7)
    right_trial_index: int = Field(ge=0, le=7)
    same_cohort: bool
    location_jaccard: DevelopmentStabilityRatio
    assertion_jaccard: DevelopmentStabilityRatio


class DevelopmentStabilityGroup(_DevelopmentModel):
    """Aggregate location coverage is distinct from fixed-configuration single-pass jitter."""

    trial_indexes: _Indices = Field(min_length=1, max_length=8)
    role: Literal["CANDIDATE"] = "CANDIDATE"
    comparison_scope: _ComparisonScope
    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    total_claim_count: int = Field(ge=0, le=8192)
    guarded_invariant_claim_count: int = Field(ge=0, le=8192)
    guarded_advisory_claim_count: int = Field(ge=0, le=8192)
    unmatched_claim_count: int = Field(ge=0, le=8192)
    ambiguous_claim_count: int = Field(ge=0, le=8192)
    union_location_coverage: DevelopmentStabilityRatio
    union_assertion_coverage: DevelopmentStabilityRatio
    severity_weighted_union_location_coverage: DevelopmentStabilityRatio
    severity_weighted_union_assertion_coverage: DevelopmentStabilityRatio
    pooled_per_trial_location_precision: DevelopmentStabilityRatio
    pooled_per_trial_assertion_precision: DevelopmentStabilityRatio
    mean_selected_run_location_coverage: float | None = Field(ge=0, le=1)
    population_variance_selected_run_location_coverage: float | None = Field(ge=0, le=1)
    mean_selected_run_assertion_coverage: float | None = Field(ge=0, le=1)
    population_variance_selected_run_assertion_coverage: float | None = Field(ge=0, le=1)
    controls: tuple[DevelopmentControlStability, ...] = Field(min_length=1, max_length=1024)
    severity: tuple[DevelopmentStabilitySeverity, ...] = Field(min_length=5, max_length=5)


@dataclass(frozen=True)
class _Trial:
    index: int
    measurement: DevelopmentCorpusControlMeasurement
    binding: DevelopmentCorpusBenchmarkBinding
    stages: tuple[_Stage, ...]
    projection: DevelopmentStabilityTrial
    planned_requests: frozenset[str]
    generation_ids: frozenset[str]
    reservation_ids: frozenset[str]
    observed_files: frozenset[str]
    locations: frozenset[str]
    assertions: frozenset[str]


def _plan(stage: _Stage) -> DevelopmentCorpusPlan:
    return stage.plan if isinstance(stage, DevelopmentCorpusObservation) else stage.plan.candidate


def _configuration(plan: DevelopmentCorpusPlan) -> str:
    # Only execution identity and its enclosing digest are excluded. Prompt/schema/request,
    # routing metadata, timeouts, prices and policies remain exact, including future fields.
    value = plan.model_dump(mode="json")
    value.pop("run_id")
    value.pop("plan_sha256")
    for shard in value["shards"]:
        shard["estimate"].pop("request_id")
    return canonical_sha256(value)


def _elapsed_total(values: Iterable[float]) -> float:
    try:
        result = math.fsum(values)
    except OverflowError:
        raise ValueError("stability elapsed total exceeds its finite range") from None
    if not math.isfinite(result):
        raise ValueError("stability elapsed total exceeds its finite range")
    return result


def _trial(index: int, measurement: DevelopmentCorpusControlMeasurement) -> _Trial:
    source = measurement.source_score
    if isinstance(source, DevelopmentCorpusBenchmarkScore):
        binding = source.binding
        stages: tuple[_Stage, ...] = (source.observation,)
    else:
        original = source.history.original_score
        if original is None:
            raise ValueError("stability requires the exact original label binding")
        binding = original.binding
        stages = (source.history.original, *source.history.continuations)
    original_plan = _plan(stages[0])
    configuration = _configuration(original_plan)
    if any(_configuration(_plan(stage)) != configuration for stage in stages):
        raise ValueError("stability continuation changes its original request configuration")
    requests: set[str] = set()
    missing_accounts: list[str] = []
    unknown_costs: list[str] = []
    missing_runtime: list[str] = []
    for stage in stages:
        plan = _plan(stage)
        selected = (
            tuple(s.shard_id for s in plan.shards)
            if isinstance(stage, DevelopmentCorpusObservation)
            else stage.plan.selected_shard_ids
        )
        accounts = {a.shard_id: a for a in stage.accounting}
        observations = {o.shard_id: o for o in stage.observations}
        for shard in plan.shards:
            if shard.shard_id not in selected:
                continue
            request = shard.estimate.request_id
            if request in requests:
                raise ValueError("stability input reuses a selected request")
            requests.add(request)
            account = accounts.get(shard.shard_id)
            if account is None:
                missing_accounts.append(request)
            elif account.status is not CostEntryStatus.RELEASED and account.actual_cost_usd is None:
                unknown_costs.append(request)
            if shard.shard_id not in observations:
                missing_runtime.append(request)
    entries = tuple(a for stage in stages for a in stage.accounting)
    cohort = canonical_sha256(
        {
            "configuration_sha256": configuration,
            "source_scope": measurement.source_scope,
            "transport": stages[0].transport,
        }
    )
    elapsed = _elapsed_total(s.elapsed_seconds for s in stages)
    projection = DevelopmentStabilityTrial(
        trial_index=index,
        measurement_sha256=measurement.measurement_sha256,
        source_score_sha256=measurement.source_score_sha256,
        source_scope=measurement.source_scope,
        original_run_id=original_plan.run_id,
        run_ids=tuple(_plan(stage).run_id for stage in stages),
        configuration_sha256=configuration,
        cohort_sha256=cohort,
        transport=stages[0].transport,
        quality_scope=measurement.summary.quality_scope,
        selected_request_count=len(requests),
        missing_accounting_request_ids=tuple(missing_accounts),
        unknown_actual_cost_request_ids=tuple(unknown_costs),
        missing_runtime_request_ids=tuple(missing_runtime),
        accounted_cost_usd=_money_sum(a.accounted_cost_usd for a in entries),
        reported_actual_cost_usd=_money_sum(
            a.actual_cost_usd for a in entries if a.actual_cost_usd is not None
        ),
        uncertain_accounted_cost_usd=_money_sum(
            a.accounted_cost_usd for a in entries if a.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            a.reserved_usd for a in entries if a.status is CostEntryStatus.RESERVED
        ),
        sum_run_elapsed_seconds=elapsed,
    )
    return _Trial(
        index=index,
        measurement=measurement,
        binding=binding,
        stages=stages,
        projection=projection,
        planned_requests=frozenset(requests),
        generation_ids=frozenset(
            o.generation_id
            for stage in stages
            for o in stage.observations
            if o.generation_id is not None
        ),
        reservation_ids=frozenset(a.reservation_id for a in entries),
        observed_files=frozenset(o.observation.source_filename for o in _source_parts(source)[1]),
        locations=frozenset(c.control_id for c in measurement.claims if c.control_id is not None),
        assertions=frozenset(
            c.control_id
            for c in measurement.claims
            if c.control_id is not None and c.reported_kind == "invariant_violation"
        ),
    )


def _frequency(
    trials: tuple[_Trial, ...], control: DevelopmentCorpusTruthControl, *, assertion: bool
) -> DevelopmentControlFrequency:
    positive, absent, unknown = [], [], []
    required_files = {site.filename for site in control.claim_sites}
    for trial in trials:
        matched = trial.assertions if assertion else trial.locations
        if control.control_id in matched:
            positive.append(trial.index)
        elif required_files <= trial.observed_files:
            absent.append(trial.index)
        else:
            unknown.append(trial.index)
    classification: _FrequencyClass = (
        "INCOMPLETE_OBSERVATIONS"
        if unknown
        else "NO_REPEATS"
        if len(trials) < 2
        else "STABLE"
        if len(positive) == len(trials)
        else "NEVER"
        if not positive
        else "SINGLE_RUN"
        if len(positive) == 1
        else "INTERMITTENT"
    )
    return DevelopmentControlFrequency(
        positive_trial_indexes=tuple(positive),
        known_absence_trial_indexes=tuple(absent),
        unobserved_trial_indexes=tuple(unknown),
        frequency=_ratio(len(positive), len(trials), complete=not unknown),
        classification=classification,
    )


def _variance(
    counts: tuple[int, ...], denominator: int, *, available: bool
) -> tuple[float | None, float | None]:
    if not available or not denominator or len(counts) < 2:
        return None, None
    values = tuple(Fraction(count, denominator) for count in counts)
    mean = sum(values, Fraction()) / len(values)
    variance = sum(((v - mean) ** 2 for v in values), Fraction()) / len(values)
    return round(float(mean), 12), round(float(variance), 12)


def _group(trials: tuple[_Trial, ...]) -> DevelopmentStabilityGroup:
    truth = trials[0].binding.truth
    roots = tuple(c for c in truth.controls if c.expected == "PLANTED")
    root_ids = {c.control_id for c in roots}
    located = set().union(*(t.locations & root_ids for t in trials))
    asserted = set().union(*(t.assertions & root_ids for t in trials))
    complete = all(t.projection.quality_scope == "COMPLETE_OBSERVATIONS" for t in trials)
    same = len({t.projection.cohort_sha256 for t in trials}) == 1
    scope: _ComparisonScope = (
        "MIXED_CONFIGURATION_SCOPE_OR_TRANSPORT"
        if not same
        else "SAME_ORIGINAL_REQUEST_CONFIGURATION"
        if trials[0].projection.source_scope == "ORIGINAL_FIRST_ATTEMPT"
        else "SAME_REQUEST_CONFIGURATION_CONTINUATION_CHAINS_NOT_SINGLE_PASSES"
    )
    controls = tuple(
        DevelopmentControlStability(
            control_id=c.control_id,
            expected=c.expected,
            severity=c.severity,
            location=_frequency(trials, c, assertion=False),
            assertion=_frequency(trials, c, assertion=True),
        )
        for c in truth.controls
    )
    weight = sum(_WEIGHTS[c.severity] for c in roots)
    claim_weight = sum(c.weight for t in trials for c in t.measurement.claims)
    location_mean, location_variance = _variance(
        tuple(len(t.locations & root_ids) for t in trials), len(roots), available=complete and same
    )
    assertion_mean, assertion_variance = _variance(
        tuple(len(t.assertions & root_ids) for t in trials), len(roots), available=complete and same
    )
    severity = tuple(
        DevelopmentStabilitySeverity(
            severity=level,
            expected_root_count=sum(
                c.expected == "PLANTED" for c in controls if c.severity == level
            ),
            located_union_root_ids=tuple(
                c.control_id
                for c in controls
                if c.severity == level
                and c.expected == "PLANTED"
                and c.location.positive_trial_indexes
            ),
            asserted_union_root_ids=tuple(
                c.control_id
                for c in controls
                if c.severity == level
                and c.expected == "PLANTED"
                and c.assertion.positive_trial_indexes
            ),
            **{
                field: tuple(
                    c.control_id
                    for c in controls
                    if c.severity == level
                    and c.expected == "PLANTED"
                    and c.assertion.classification == classification
                )
                for field, classification in (
                    ("stable_asserted_root_ids", "STABLE"),
                    ("intermittent_asserted_root_ids", "INTERMITTENT"),
                    ("single_run_asserted_root_ids", "SINGLE_RUN"),
                    ("unobserved_assertion_root_ids", "INCOMPLETE_OBSERVATIONS"),
                )
            },
            guarded_assertion_control_ids=tuple(
                c.control_id
                for c in controls
                if c.severity == level
                and c.expected == "GUARDED"
                and c.assertion.positive_trial_indexes
            ),
        )
        for level in Severity
    )
    return DevelopmentStabilityGroup(
        trial_indexes=tuple(t.index for t in trials),
        comparison_scope=scope,
        quality_scope="COMPLETE_OBSERVATIONS" if complete else "INCOMPLETE_OBSERVATIONS",
        total_claim_count=sum(t.measurement.summary.total_claim_count for t in trials),
        guarded_invariant_claim_count=sum(
            t.measurement.summary.guarded_invariant_claim_count for t in trials
        ),
        guarded_advisory_claim_count=sum(
            t.measurement.summary.guarded_advisory_claim_count for t in trials
        ),
        unmatched_claim_count=sum(t.measurement.summary.unmatched_claim_count for t in trials),
        ambiguous_claim_count=sum(t.measurement.summary.ambiguous_claim_count for t in trials),
        union_location_coverage=_ratio(len(located), len(roots), complete=complete),
        union_assertion_coverage=_ratio(len(asserted), len(roots), complete=complete),
        severity_weighted_union_location_coverage=_ratio(
            sum(_WEIGHTS[c.severity] for c in roots if c.control_id in located),
            weight,
            complete=complete,
        ),
        severity_weighted_union_assertion_coverage=_ratio(
            sum(_WEIGHTS[c.severity] for c in roots if c.control_id in asserted),
            weight,
            complete=complete,
        ),
        pooled_per_trial_location_precision=_ratio(
            sum(_WEIGHTS[c.severity] for t in trials for c in roots if c.control_id in t.locations),
            claim_weight,
            complete=complete,
        ),
        pooled_per_trial_assertion_precision=_ratio(
            sum(
                _WEIGHTS[c.severity] for t in trials for c in roots if c.control_id in t.assertions
            ),
            claim_weight,
            complete=complete,
        ),
        mean_selected_run_location_coverage=location_mean,
        population_variance_selected_run_location_coverage=location_variance,
        mean_selected_run_assertion_coverage=assertion_mean,
        population_variance_selected_run_assertion_coverage=assertion_variance,
        controls=controls,
        severity=severity,
    )


def _project(measurements: tuple[DevelopmentCorpusControlMeasurement, ...]) -> dict[str, Any]:
    if not 2 <= len(measurements) <= MAX_DEVELOPMENT_STABILITY_TRIALS:
        raise ValueError("stability requires two to eight explicitly selected measurements")
    if (
        sum(len(m.model_dump_json().encode()) for m in measurements)
        > MAX_DEVELOPMENT_STABILITY_INPUT_BYTES
    ):
        raise ValueError("stability selected measurements exceed the aggregate input bound")
    trials = tuple(_trial(i, m) for i, m in enumerate(measurements))
    first = trials[0].binding
    for trial in trials:
        if (
            trial.binding.truth != first.truth
            or trial.binding.truth_file_content != first.truth_file_content
        ):
            raise ValueError("stability requires the exact same complete source and label bytes")
    seen: dict[str, set[str]] = {
        k: set() for k in ("measurement", "run", "request", "generation", "reservation")
    }
    for trial in trials:
        identities = {
            "measurement": {trial.measurement.measurement_sha256},
            "run": set(trial.projection.run_ids),
            "request": set(trial.planned_requests),
            "generation": set(trial.generation_ids),
            "reservation": set(trial.reservation_ids),
        }
        for kind, values in identities.items():
            if seen[kind] & values:
                raise ValueError("stability reuses " + kind + " evidence across selected trials")
            seen[kind].update(values)
    root_ids = set(measurements[0].summary.expected_root_ids)
    pairs = []
    for left in trials:
        for right in trials[left.index + 1 :]:
            complete = all(
                t.projection.quality_scope == "COMPLETE_OBSERVATIONS" for t in (left, right)
            )
            a, b = left.locations & root_ids, right.locations & root_ids
            x, y = left.assertions & root_ids, right.assertions & root_ids
            pairs.append(
                DevelopmentStabilityPair(
                    left_trial_index=left.index,
                    right_trial_index=right.index,
                    same_cohort=left.projection.cohort_sha256 == right.projection.cohort_sha256,
                    location_jaccard=_ratio(len(a & b), len(a | b), complete=complete),
                    assertion_jaccard=_ratio(len(x & y), len(x | y), complete=complete),
                )
            )
    return {
        "measurements": measurements,
        "trials": tuple(t.projection for t in trials),
        "combined": _group(trials),
        "cohorts": tuple(
            _group(tuple(t for t in trials if t.projection.cohort_sha256 == key))
            for key in sorted({t.projection.cohort_sha256 for t in trials})
        ),
        "pairs": tuple(pairs),
        "accounted_cost_usd": _money_sum(t.projection.accounted_cost_usd for t in trials),
        "reported_actual_cost_usd": _money_sum(
            t.projection.reported_actual_cost_usd for t in trials
        ),
        "uncertain_accounted_cost_usd": _money_sum(
            t.projection.uncertain_accounted_cost_usd for t in trials
        ),
        "active_reserved_usd": _money_sum(t.projection.active_reserved_usd for t in trials),
        "sum_recorded_run_elapsed_seconds": _elapsed_total(
            t.projection.sum_run_elapsed_seconds for t in trials
        ),
    }


class DevelopmentCorpusStability(_AuditArtifact):
    """Self-recomputed retained evidence; selected-run frequencies never predict an unseen audit."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_stability"] = "development_corpus_stability"
    scorer_version: Literal["retained-control-jitter-v1"] = "retained-control-jitter-v1"
    interpretation: Literal["DESCRIPTIVE_RETAINED_CONTROL_LOCATIONS_NOT_VALIDATED_FINDINGS"] = (
        "DESCRIPTIVE_RETAINED_CONTROL_LOCATIONS_NOT_VALIDATED_FINDINGS"
    )
    selection_scope: Literal[
        "EXPLICIT_RETAINED_INPUTS_NOT_VERIFIED_PREREGISTERED_OR_EXHAUSTIVE"
    ] = "EXPLICIT_RETAINED_INPUTS_NOT_VERIFIED_PREREGISTERED_OR_EXHAUSTIVE"
    trial_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    root_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    predictive_stability: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    role_scope: Literal["CANDIDATE_ONLY_OTHER_AUDIT_ROLES_NOT_MEASURED"] = (
        "CANDIDATE_ONLY_OTHER_AUDIT_ROLES_NOT_MEASURED"
    )
    precision_policy: Literal[
        "SUM_PER_TRIAL_UNIQUE_ROOT_WEIGHTS_OVER_ALL_RETAINED_CLAIM_WEIGHTS"
    ] = "SUM_PER_TRIAL_UNIQUE_ROOT_WEIGHTS_OVER_ALL_RETAINED_CLAIM_WEIGHTS"
    cost_scope: Literal["SUM_REPORTED_RETAINED_LIABILITIES_NOT_RECONCILIATION_OR_TOTAL_BILL"] = (
        "SUM_REPORTED_RETAINED_LIABILITIES_NOT_RECONCILIATION_OR_TOTAL_BILL"
    )
    runtime_scope: Literal["SUM_RECORDED_RUN_DURATIONS_NOT_END_TO_END"] = (
        "SUM_RECORDED_RUN_DURATIONS_NOT_END_TO_END"
    )
    measurements: tuple[DevelopmentCorpusControlMeasurement, ...] = Field(
        min_length=2, max_length=8
    )
    trials: tuple[DevelopmentStabilityTrial, ...] = Field(min_length=2, max_length=8)
    combined: DevelopmentStabilityGroup
    cohorts: tuple[DevelopmentStabilityGroup, ...] = Field(min_length=1, max_length=8)
    pairs: tuple[DevelopmentStabilityPair, ...] = Field(min_length=1, max_length=28)
    accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    sum_recorded_run_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    stability_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def retained_inputs_reproduce_every_frequency_scope_cost_and_digest(self) -> Self:
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_STABILITY_BYTES:
            raise ValueError("stability artifact exceeds its composed output bound")
        if any(getattr(self, key) != value for key, value in _project(self.measurements).items()):
            raise ValueError("stability artifact differs from its exact retained measurements")
        if self.stability_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"stability_sha256"})
        ):
            raise ValueError("stability artifact digest differs")
        return self


def measure_development_corpus_stability(
    *, measurements: tuple[DevelopmentCorpusControlMeasurement, ...]
) -> DevelopmentCorpusStability:
    """Measure selected same-source trials without reading a provider, labels, ledger or private path."""

    if (
        type(measurements) is not tuple
        or not 2 <= len(measurements) <= MAX_DEVELOPMENT_STABILITY_TRIALS
    ):
        raise ValueError("stability requires an exact bounded tuple of retained measurements")
    total = 0
    validated = []
    for measurement in measurements:
        if type(measurement) is not DevelopmentCorpusControlMeasurement:
            raise ValueError("stability requires exact retained control measurement types")
        content = measurement.model_dump_json().encode()
        total += len(content)
        if total > MAX_DEVELOPMENT_STABILITY_INPUT_BYTES:
            raise ValueError("stability selected measurements exceed the aggregate input bound")
        validated.append(read_development_corpus_control_measurement(content))
    fields = _project(tuple(validated))
    draft = DevelopmentCorpusStability.model_construct(**fields, stability_sha256="0" * 64)
    digest = canonical_sha256(draft.model_dump(mode="json", exclude={"stability_sha256"}))
    return DevelopmentCorpusStability(**fields, stability_sha256=digest)


def read_development_corpus_stability(content: bytes) -> DevelopmentCorpusStability:
    """Reject ambiguous, oversize or unreproducible retained-series output; never grant authority."""

    _json_object(content, maximum=MAX_DEVELOPMENT_STABILITY_BYTES)
    return DevelopmentCorpusStability.model_validate_json(content, strict=True)
