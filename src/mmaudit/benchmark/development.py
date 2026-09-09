"""Deterministic, non-qualifying measurement of public labelled development controls.

Location/class matches are not semantic validation. The agent-constructed manifests
are frozen independently of responses, not external or exhaustive ground truth.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from decimal import Decimal
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    DevelopmentAuditSource,
    DevelopmentCorpusId,
    DevelopmentScoredAuditShardObservation,
    _AuditArtifact,
    _sources,
    development_corpus_sha256,
)
from mmaudit.models.development_judgment import DevelopmentJudgmentObservation, _money_sum
from mmaudit.models.development_review import (
    DevelopmentRootCauseReference,
    DevelopmentScoredFinding,
    _DevelopmentModel,
)
from mmaudit.models.schemas import Severity
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_TRUTH_BYTES = 65_536
# (Exact fixture bytes, canonical typed content). No response-derived expectation.
DEVELOPMENT_TRUTH_PINS = {
    "unit-ledger-a-v1": (
        "c1000c240b6fce775b73157d6fcce56a2255f309c7ad05689219f55485d93941",
        "26ce6e7a91689d815b0cb7ea02741e2697097ff5cbe48c301516536f39060a4d",
    ),
    "unit-ledger-b-v1": (
        "1c050bd6034cc1ed114a9086097e3b599bc95a788c68aafdbc6b5e7c83dba050",
        "0bcf38771327708ebf81fa2a2a26cc937e20fabd96ef923372e3108fd591f23c",
    ),
}
_SHA = r"^[0-9a-f]{64}$"
_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 1,
}


class DevelopmentTruthControl(_DevelopmentModel):
    control_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    expected: Literal["PLANTED", "GUARDED"]
    vulnerability_class: Literal["access_control", "accounting", "reservation", "pause", "other"]
    severity: Severity
    invariant: str = Field(min_length=1, max_length=1_000)
    origin: DevelopmentRootCauseReference
    required_origin_line: int = Field(ge=1, le=1_000)
    claim_sites: tuple[DevelopmentRootCauseReference, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def origin_is_bounded(self) -> Self:
        if not self.origin.line_start <= self.required_origin_line <= self.origin.line_end:
            raise ValueError("development truth origin anchor is outside its source span")
        if len(set(self.claim_sites)) != len(self.claim_sites):
            raise ValueError("development truth repeats a claim site")
        return self


class DevelopmentBenchmarkTruth(_AuditArtifact):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_constructed_truth"] = "development_constructed_truth"
    provenance: Literal["AGENT_CONSTRUCTED_PUBLIC_LABELLED_DEVELOPMENT_CONTROL"] = (
        "AGENT_CONSTRUCTED_PUBLIC_LABELLED_DEVELOPMENT_CONTROL"
    )
    truth_scope: Literal["RESPONSE_INDEPENDENT_NOT_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH"] = (
        "RESPONSE_INDEPENDENT_NOT_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH"
    )
    corpus_id: DevelopmentCorpusId
    corpus_sha256: str = Field(pattern=_SHA)
    sources: tuple[DevelopmentAuditSource, ...] = Field(min_length=3, max_length=3)
    controls: tuple[DevelopmentTruthControl, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def truth_is_exactly_frozen(self) -> Self:
        if (
            self.sources != _sources(self.corpus_id)
            or self.corpus_sha256 != development_corpus_sha256(self.corpus_id)
            or canonical_sha256(self.model_dump(mode="json"))
            != DEVELOPMENT_TRUTH_PINS[self.corpus_id][1]
        ):
            raise ValueError("development truth differs from the frozen constructed control")
        return self


def read_development_benchmark_truth(content: bytes) -> DevelopmentBenchmarkTruth:
    """Admit only exact bounded manifest bytes; never derive truth from a response."""

    if type(content) is not bytes or not 0 < len(content) <= MAX_DEVELOPMENT_TRUTH_BYTES:
        raise ValueError("development truth is not bounded immutable bytes")
    digest = hashlib.sha256(content).hexdigest()
    if digest not in {pins[0] for pins in DEVELOPMENT_TRUTH_PINS.values()}:
        raise ValueError("development truth bytes are not frozen")
    truth = DevelopmentBenchmarkTruth.model_validate_json(content, strict=True)
    if digest != DEVELOPMENT_TRUTH_PINS[truth.corpus_id][0]:
        raise ValueError("development truth file and corpus identity differ")
    return truth


class DevelopmentBenchmarkBinding(_AuditArtifact):
    """Pre-dispatch scoring inputs; a digest establishes identity, not authority."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_benchmark_binding"] = "development_benchmark_binding"
    scorer_version: Literal["structural-controls-v1"] = "structural-controls-v1"
    plan_sha256: str = Field(pattern=_SHA)
    truth_file_sha256: str = Field(pattern=_SHA)
    truth: DevelopmentBenchmarkTruth

    @model_validator(mode="after")
    def manifest_bytes_are_pinned(self) -> Self:
        if self.truth_file_sha256 != DEVELOPMENT_TRUTH_PINS[self.truth.corpus_id][0]:
            raise ValueError("development benchmark binding differs from the frozen truth file")
        return self


def bind_development_benchmark(
    *, plan: DevelopmentAuditPlan, truth: DevelopmentBenchmarkTruth
) -> DevelopmentBenchmarkBinding:
    """Bind the complete v2 plan and frozen control before entering the dispatch loop."""

    if type(plan) is not DevelopmentAuditPlan or type(truth) is not DevelopmentBenchmarkTruth:
        raise ValueError("development scoring requires exact typed plan and truth")
    plan = DevelopmentAuditPlan.model_validate_json(plan.model_dump_json(), strict=True)
    truth = DevelopmentBenchmarkTruth.model_validate_json(truth.model_dump_json(), strict=True)
    if (
        plan.schema_version != "2.0"
        or plan.corpus_id != truth.corpus_id
        or plan.corpus_sha256 != truth.corpus_sha256
        or plan.sources != truth.sources
    ):
        raise ValueError("development scoring plan version or frozen source differs")
    return DevelopmentBenchmarkBinding(
        plan_sha256=plan.plan_sha256,
        truth_file_sha256=DEVELOPMENT_TRUTH_PINS[truth.corpus_id][0],
        truth=truth,
    )


class DevelopmentMeasurementRatio(_DevelopmentModel):
    """A descriptive six-decimal ratio, without passing thresholds or empty-scope credit."""

    numerator: int = Field(ge=0, le=10_000)
    denominator: int = Field(ge=0, le=10_000)
    state: Literal["OBSERVED", "INCOMPLETE_SCOPE", "EMPTY_DENOMINATOR"]
    value: float | None = Field(ge=0, le=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def ratio_is_exact(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("development ratio numerator exceeds its full denominator")
        if self.state == "INCOMPLETE_SCOPE":
            expected = None
        else:
            state = "OBSERVED" if self.denominator else "EMPTY_DENOMINATOR"
            if self.state != state:
                raise ValueError("development ratio state differs from its denominator")
            expected = round(self.numerator / self.denominator, 6) if self.denominator else None
        if self.value != expected:
            raise ValueError("development ratio value differs from its scope and counts")
        return self


def _ratio(numerator: int, denominator: int, *, complete: bool) -> DevelopmentMeasurementRatio:
    return DevelopmentMeasurementRatio(
        numerator=numerator,
        denominator=denominator,
        state=(
            "INCOMPLETE_SCOPE"
            if not complete
            else "OBSERVED"
            if denominator
            else "EMPTY_DENOMINATOR"
        ),
        value=round(numerator / denominator, 6) if complete and denominator else None,
    )


class DevelopmentClaimMeasurement(_DevelopmentModel):
    claim_id: str = Field(pattern=r"^file-0[123]:[0-9]{2}$")
    disposition: Literal[
        "MATCHED_ROOT",
        "DUPLICATE_OR_CONSEQUENCE",
        "UNMATCHED_INVARIANT",
        "GUARDED_CONTROL_CLAIM",
        "ADVISORY",
        "ADVISORY_AT_PLANTED_SITE",
    ]
    control_id: str | None = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    weight: int = Field(ge=1, le=10)


class DevelopmentBenchmarkSummary(_DevelopmentModel):
    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    total_claim_count: int = Field(ge=0, le=48)
    invariant_claim_count: int = Field(ge=0, le=48)
    advisory_claim_count: int = Field(ge=0, le=48)
    advisories_at_planted_sites_count: int = Field(ge=0, le=48)
    duplicate_claim_count: int = Field(ge=0, le=48)
    unmatched_invariant_claim_count: int = Field(ge=0, le=48)
    guarded_control_claim_count: int = Field(ge=0, le=48)
    expected_root_ids: tuple[str, ...] = Field(max_length=16)
    matched_root_ids: tuple[str, ...] = Field(max_length=16)
    unmatched_expected_root_ids: tuple[str, ...] = Field(max_length=16)
    observed_missed_root_ids: tuple[str, ...] = Field(max_length=16)
    unobserved_root_ids: tuple[str, ...] = Field(max_length=16)
    unique_root_recall: DevelopmentMeasurementRatio
    severity_weighted_root_recall: DevelopmentMeasurementRatio
    all_claim_unique_root_fraction: DevelopmentMeasurementRatio
    severity_weighted_structural_precision: DevelopmentMeasurementRatio
    first_attempt_shard_completion: DevelopmentMeasurementRatio
    unobserved_shard_ids: tuple[str, ...] = Field(max_length=3)
    missing_accounting_shard_ids: tuple[str, ...] = Field(max_length=3)
    unknown_actual_cost_shard_ids: tuple[str, ...] = Field(max_length=3)
    missing_shard_runtime_ids: tuple[str, ...] = Field(max_length=3)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    accounted_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)


def _contains(site: DevelopmentRootCauseReference, filename: str, start: int, end: int) -> bool:
    return site.filename == filename and site.line_start <= start <= end <= site.line_end


def _control_for_claim(
    truth: DevelopmentBenchmarkTruth, filename: str, finding: DevelopmentScoredFinding
) -> DevelopmentTruthControl | None:
    return match_development_control(truth.controls, filename, finding)


def match_development_control(
    controls: tuple[DevelopmentTruthControl, ...],
    filename: str,
    finding: DevelopmentScoredFinding,
) -> DevelopmentTruthControl | None:
    """Match supplied source-bound labels, without choosing arbitrarily among ambiguous controls."""

    candidates = []
    for control in controls:
        if not any(
            _contains(site, filename, finding.line_start, finding.line_end)
            for site in control.claim_sites
        ):
            continue
        if finding.kind == "advisory":
            if control.expected == "PLANTED":
                candidates.append(control)
            continue
        origin = finding.root_cause_ref
        if (
            origin is not None
            and finding.vulnerability_class == control.vulnerability_class
            and _contains(control.origin, origin.filename, origin.line_start, origin.line_end)
            and origin.line_start <= control.required_origin_line <= origin.line_end
        ):
            candidates.append(control)
    # Ambiguity is unmatched, never an arbitrary first-root credit.
    return candidates[0] if len(candidates) == 1 else None


def _measure(
    binding: DevelopmentBenchmarkBinding, observation: DevelopmentAuditObservation
) -> tuple[tuple[DevelopmentClaimMeasurement, ...], DevelopmentBenchmarkSummary]:
    if binding != bind_development_benchmark(plan=observation.plan, truth=binding.truth):
        raise ValueError("development score does not match its pre-dispatch binding")
    claims: list[DevelopmentClaimMeasurement] = []
    matched: set[str] = set()
    timed: set[str] = set()
    observed_files: set[str] = set()
    shard_seconds = 0.0
    for shard in observation.observations:
        if type(shard) is not DevelopmentScoredAuditShardObservation:
            raise ValueError("development scorer cannot reinterpret v1 observations")
        timed.add(shard.shard_id)
        shard_seconds += shard.elapsed_seconds
        if shard.status != "OBSERVED":
            continue
        observed_files.add(shard.source_filename)
        assert shard.response is not None
        for index, finding in enumerate(shard.response.findings, 1):
            control = _control_for_claim(binding.truth, shard.source_filename, finding)
            disposition: Literal[
                "MATCHED_ROOT",
                "DUPLICATE_OR_CONSEQUENCE",
                "UNMATCHED_INVARIANT",
                "GUARDED_CONTROL_CLAIM",
                "ADVISORY",
                "ADVISORY_AT_PLANTED_SITE",
            ]
            if finding.kind == "advisory":
                disposition = "ADVISORY_AT_PLANTED_SITE" if control is not None else "ADVISORY"
            elif control is None:
                disposition = "UNMATCHED_INVARIANT"
            elif control.expected == "GUARDED":
                disposition = "GUARDED_CONTROL_CLAIM"
            elif control.control_id in matched:
                disposition = "DUPLICATE_OR_CONSEQUENCE"
            else:
                disposition = "MATCHED_ROOT"
                matched.add(control.control_id)
            claims.append(
                DevelopmentClaimMeasurement(
                    claim_id=f"{shard.shard_id}:{index:02d}",
                    disposition=disposition,
                    control_id=control.control_id if control is not None else None,
                    # Planted/guarded sites use frozen severity even after kind/severity relabeling.
                    # Every other claim retains at least weight one, including informationals.
                    weight=_WEIGHTS[control.severity if control is not None else finding.severity],
                )
            )
    if shard_seconds > observation.elapsed_seconds + 1e-9:
        raise ValueError("development shard timing exceeds its owned aggregate duration")
    roots = tuple(control for control in binding.truth.controls if control.expected == "PLANTED")
    misses = tuple(control for control in roots if control.control_id not in matched)
    complete = observation.status == "OBSERVED_ALL_SHARDS"
    matched_weight = sum(
        _WEIGHTS[control.severity] for control in roots if control.control_id in matched
    )
    root_weight = sum(_WEIGHTS[control.severity] for control in roots)
    accounted = {entry.shard_id for entry in observation.accounting}
    expected_shards = tuple(shard.shard_id for shard in observation.plan.shards)
    advisories = sum(
        claim.disposition in {"ADVISORY", "ADVISORY_AT_PLANTED_SITE"} for claim in claims
    )
    summary = DevelopmentBenchmarkSummary(
        quality_scope="COMPLETE_OBSERVATIONS" if complete else "INCOMPLETE_OBSERVATIONS",
        total_claim_count=len(claims),
        invariant_claim_count=len(claims) - advisories,
        advisory_claim_count=advisories,
        advisories_at_planted_sites_count=sum(
            claim.disposition == "ADVISORY_AT_PLANTED_SITE" for claim in claims
        ),
        duplicate_claim_count=sum(
            claim.disposition == "DUPLICATE_OR_CONSEQUENCE" for claim in claims
        ),
        unmatched_invariant_claim_count=sum(
            claim.disposition in {"UNMATCHED_INVARIANT", "GUARDED_CONTROL_CLAIM"}
            for claim in claims
        ),
        guarded_control_claim_count=sum(
            claim.disposition == "GUARDED_CONTROL_CLAIM" for claim in claims
        ),
        expected_root_ids=tuple(control.control_id for control in roots),
        matched_root_ids=tuple(
            control.control_id for control in roots if control.control_id in matched
        ),
        unmatched_expected_root_ids=tuple(control.control_id for control in misses),
        observed_missed_root_ids=tuple(
            control.control_id
            for control in misses
            if all(site.filename in observed_files for site in control.claim_sites)
        ),
        unobserved_root_ids=tuple(
            control.control_id
            for control in misses
            if any(site.filename not in observed_files for site in control.claim_sites)
        ),
        unique_root_recall=_ratio(len(matched), len(roots), complete=complete),
        severity_weighted_root_recall=_ratio(matched_weight, root_weight, complete=complete),
        all_claim_unique_root_fraction=_ratio(len(matched), len(claims), complete=complete),
        severity_weighted_structural_precision=_ratio(
            matched_weight, sum(claim.weight for claim in claims), complete=complete
        ),
        first_attempt_shard_completion=_ratio(
            observation.completed_shard_count, len(expected_shards), complete=True
        ),
        unobserved_shard_ids=observation.unobserved_shard_ids,
        missing_accounting_shard_ids=tuple(
            shard for shard in expected_shards if shard not in accounted
        ),
        unknown_actual_cost_shard_ids=tuple(
            entry.shard_id
            for entry in observation.accounting
            if entry.status not in {CostEntryStatus.RELEASED} and entry.actual_cost_usd is None
        ),
        missing_shard_runtime_ids=tuple(shard for shard in expected_shards if shard not in timed),
        reported_actual_cost_usd=sum(
            (
                entry.actual_cost_usd
                for entry in observation.accounting
                if entry.actual_cost_usd is not None
            ),
            Decimal(0),
        ),
        accounted_cost_usd=observation.total_accounted_cost_usd,
        uncertain_accounted_cost_usd=sum(
            (
                entry.accounted_cost_usd
                for entry in observation.accounting
                if entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            ),
            Decimal(0),
        ),
        active_reserved_usd=observation.active_reserved_usd,
        elapsed_seconds=observation.elapsed_seconds,
    )
    return tuple(claims), summary


class DevelopmentBenchmarkScore(_AuditArtifact):
    """Recomputed descriptive measurements, with exact input evidence and no authority.

    The embedded observation preserves every request, cost and missing/failed shard.
    This consistency check is not independent authentication of a provider response.
    """

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_benchmark_score"] = "development_benchmark_score"
    interpretation: Literal["STRUCTURAL_MATCHES_NOT_SEMANTICALLY_VALIDATED_PRECISION"] = (
        "STRUCTURAL_MATCHES_NOT_SEMANTICALLY_VALIDATED_PRECISION"
    )
    binding: DevelopmentBenchmarkBinding
    observation: DevelopmentAuditObservation
    observation_sha256: str = Field(pattern=_SHA)
    claims: tuple[DevelopmentClaimMeasurement, ...] = Field(max_length=48)
    summary: DevelopmentBenchmarkSummary

    @model_validator(mode="after")
    def measurements_recompute_from_exact_inputs(self) -> Self:
        if self.observation_sha256 != canonical_sha256(self.observation.model_dump(mode="json")):
            raise ValueError("development score observation digest differs")
        claims, summary = _measure(self.binding, self.observation)
        if self.claims != claims or self.summary != summary:
            raise ValueError("development score does not reproduce from its exact inputs")
        return self


def score_development_audit(
    *, binding: DevelopmentBenchmarkBinding, observation: DevelopmentAuditObservation
) -> DevelopmentBenchmarkScore:
    """Measure each bounded claim once; no model call, truth inference or quality pass."""

    if (
        type(binding) is not DevelopmentBenchmarkBinding
        or type(observation) is not DevelopmentAuditObservation
    ):
        raise ValueError("development scorer requires exact input types")
    binding = DevelopmentBenchmarkBinding.model_validate_json(
        binding.model_dump_json(), strict=True
    )
    observation = DevelopmentAuditObservation.model_validate_json(
        observation.model_dump_json(), strict=True
    )
    claims, summary = _measure(binding, observation)
    return DevelopmentBenchmarkScore(
        binding=binding,
        observation=observation,
        observation_sha256=canonical_sha256(observation.model_dump(mode="json")),
        claims=claims,
        summary=summary,
    )


class DevelopmentJudgmentImpactRow(_DevelopmentModel):
    """Preserve the original scorer's disposition beside an unvalidated review opinion."""

    candidate_claim: DevelopmentClaimMeasurement
    judgment: Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE", "UNREVIEWED"]


class DevelopmentJudgmentImpactSummary(_DevelopmentModel):
    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS", "NO_CANDIDATES"]
    candidate_claim_count: int = Field(ge=0, le=48)
    supported_claim_count: int = Field(ge=0, le=48)
    refuted_claim_count: int = Field(ge=0, le=48)
    inconclusive_claim_count: int = Field(ge=0, le=48)
    unreviewed_claim_count: int = Field(ge=0, le=48)
    supported_planted_root_ids: tuple[str, ...] = Field(max_length=16)
    refuted_planted_candidate_count: int = Field(ge=0, le=48)
    supported_guarded_claim_count: int = Field(ge=0, le=48)
    supported_unmatched_invariant_count: int = Field(ge=0, le=48)
    supported_advisory_count: int = Field(ge=0, le=48)
    first_attempt_claim_observation_rate: DevelopmentMeasurementRatio
    supported_root_recall: DevelopmentMeasurementRatio
    supported_severity_weighted_structural_precision: DevelopmentMeasurementRatio
    all_candidate_severity_weighted_structural_precision: DevelopmentMeasurementRatio
    combined_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    summed_stage_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)


def _judgment_impact_parts(
    candidate_score: DevelopmentBenchmarkScore, observation: DevelopmentJudgmentObservation
) -> tuple[tuple[DevelopmentJudgmentImpactRow, ...], DevelopmentJudgmentImpactSummary]:
    if candidate_score.observation != observation.plan.candidate:
        raise ValueError("development judgment score changed its retained candidate audit")
    decisions = {
        decision.claim_id: decision.verdict
        for shard in observation.observations
        if shard.status == "OBSERVED" and shard.response is not None
        for decision in shard.response.decisions
    }
    return _review_impact_parts(
        candidate_score,
        decisions,
        complete=observation.status != "INCOMPLETE",
        no_candidates=observation.status == "NO_CANDIDATES",
        combined_accounted_cost_usd=_money_sum(
            (
                candidate_score.observation.total_accounted_cost_usd,
                observation.judgment_accounted_cost_usd,
            )
        ),
        active_reserved_usd=observation.active_reserved_usd,
        summed_stage_elapsed_seconds=observation.summed_stage_elapsed_seconds,
    )


def _review_impact_parts(
    candidate_score: DevelopmentBenchmarkScore,
    decisions: Mapping[str, Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE"]],
    *,
    complete: bool,
    no_candidates: bool,
    combined_accounted_cost_usd: Decimal,
    active_reserved_usd: Decimal,
    summed_stage_elapsed_seconds: float,
) -> tuple[tuple[DevelopmentJudgmentImpactRow, ...], DevelopmentJudgmentImpactSummary]:
    """Measure supplied opinions against unchanged claims; never synthesize a provider record."""

    rows = tuple(
        DevelopmentJudgmentImpactRow(
            candidate_claim=claim, judgment=decisions.get(claim.claim_id, "UNREVIEWED")
        )
        for claim in candidate_score.claims
    )
    supported = tuple(row.candidate_claim for row in rows if row.judgment == "SUPPORTED")
    roots = tuple(
        control
        for control in candidate_score.binding.truth.controls
        if control.expected == "PLANTED"
    )
    supported_roots = tuple(
        sorted(
            {
                claim.control_id
                for claim in supported
                if claim.disposition in {"MATCHED_ROOT", "DUPLICATE_OR_CONSEQUENCE"}
                and claim.control_id is not None
            }
        )
    )
    matched_weight = sum(
        _WEIGHTS[root.severity] for root in roots if root.control_id in supported_roots
    )
    summary = DevelopmentJudgmentImpactSummary(
        quality_scope="NO_CANDIDATES"
        if no_candidates
        else ("COMPLETE_OBSERVATIONS" if complete else "INCOMPLETE_OBSERVATIONS"),
        candidate_claim_count=len(rows),
        supported_claim_count=len(supported),
        refuted_claim_count=sum(row.judgment == "REFUTED" for row in rows),
        inconclusive_claim_count=sum(row.judgment == "INCONCLUSIVE" for row in rows),
        unreviewed_claim_count=sum(row.judgment == "UNREVIEWED" for row in rows),
        supported_planted_root_ids=supported_roots,
        refuted_planted_candidate_count=sum(
            row.judgment == "REFUTED"
            and row.candidate_claim.disposition in {"MATCHED_ROOT", "DUPLICATE_OR_CONSEQUENCE"}
            for row in rows
        ),
        supported_guarded_claim_count=sum(
            claim.disposition == "GUARDED_CONTROL_CLAIM" for claim in supported
        ),
        supported_unmatched_invariant_count=sum(
            claim.disposition == "UNMATCHED_INVARIANT" for claim in supported
        ),
        supported_advisory_count=sum(
            claim.disposition in {"ADVISORY", "ADVISORY_AT_PLANTED_SITE"} for claim in supported
        ),
        first_attempt_claim_observation_rate=_ratio(len(decisions), len(rows), complete=True),
        supported_root_recall=_ratio(len(supported_roots), len(roots), complete=complete),
        supported_severity_weighted_structural_precision=_ratio(
            matched_weight, sum(claim.weight for claim in supported), complete=complete
        ),
        all_candidate_severity_weighted_structural_precision=_ratio(
            matched_weight, sum(claim.weight for claim in candidate_score.claims), complete=complete
        ),
        combined_accounted_cost_usd=combined_accounted_cost_usd,
        active_reserved_usd=active_reserved_usd,
        summed_stage_elapsed_seconds=summed_stage_elapsed_seconds,
    )
    return rows, summary


class DevelopmentJudgmentImpactScore(_AuditArtifact):
    """Same frozen truth and original denominators; no manufactured filtered audit record."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_judgment_impact_score"] = (
        "development_judgment_impact_score"
    )
    interpretation: Literal[
        "MODEL_REVIEW_OPINIONS_AND_STRUCTURAL_MATCHES_NOT_VALIDATED_FINDINGS"
    ] = "MODEL_REVIEW_OPINIONS_AND_STRUCTURAL_MATCHES_NOT_VALIDATED_FINDINGS"
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    candidate_score: DevelopmentBenchmarkScore
    observation: DevelopmentJudgmentObservation
    observation_sha256: str = Field(pattern=_SHA)
    claims: tuple[DevelopmentJudgmentImpactRow, ...] = Field(max_length=48)
    summary: DevelopmentJudgmentImpactSummary

    @model_validator(mode="after")
    def impact_recomputes_from_exact_inputs(self) -> Self:
        if self.observation_sha256 != canonical_sha256(self.observation.model_dump(mode="json")):
            raise ValueError("development judgment impact observation digest differs")
        claims, summary = _judgment_impact_parts(self.candidate_score, self.observation)
        if self.claims != claims or self.summary != summary:
            raise ValueError("development judgment impact does not reproduce from its exact inputs")
        return self


def score_development_judgment(
    *, binding: DevelopmentBenchmarkBinding, observation: DevelopmentJudgmentObservation
) -> DevelopmentJudgmentImpactScore:
    """Compare review opinions with original structural controls without new truth or credit."""

    if (
        type(binding) is not DevelopmentBenchmarkBinding
        or type(observation) is not DevelopmentJudgmentObservation
    ):
        raise ValueError("development judgment scorer requires exact input types")
    binding = DevelopmentBenchmarkBinding.model_validate_json(
        binding.model_dump_json(), strict=True
    )
    observation = DevelopmentJudgmentObservation.model_validate_json(
        observation.model_dump_json(), strict=True
    )
    candidate_score = score_development_audit(
        binding=binding, observation=observation.plan.candidate
    )
    claims, summary = _judgment_impact_parts(candidate_score, observation)
    return DevelopmentJudgmentImpactScore(
        candidate_score=candidate_score,
        observation=observation,
        observation_sha256=canonical_sha256(observation.model_dump(mode="json")),
        claims=claims,
        summary=summary,
    )
