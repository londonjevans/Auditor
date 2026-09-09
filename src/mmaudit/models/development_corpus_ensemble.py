"""Exact manifest stage composition; two opinions never establish truth or independent roots."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.development_audit import (
    DevelopmentSourceBytes,
    _AuditArtifact,
    development_ledger_request_id,
)
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusManifest,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusShardPlan,
    PreparedDevelopmentCorpus,
    prepare_development_corpus,
)
from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentClaim,
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentPlan,
    DevelopmentCorpusJudgmentShardPlan,
    development_corpus_judgment_claims,
    require_development_corpus_judgment_candidate,
)
from mmaudit.models.development_costs import DevelopmentCostError, DevelopmentCostPolicy
from mmaudit.models.development_ensemble import (
    DEVELOPMENT_ENSEMBLE_REVIEWERS,
    DEVELOPMENT_ENSEMBLE_STAGES,
    DevelopmentEnsembleOpinion,
    DevelopmentEnsembleReviewer,
    DevelopmentEnsembleStageId,
    _require_distinct_roles,
    development_ensemble_stage_run_id,
)
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import (
    DevelopmentReviewMetadata,
    _development_metadata,
    _DevelopmentModel,
)
from mmaudit.models.development_routing import DevelopmentRoutingContext
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES = 256_000_000
_RUN_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
_SHA = r"^[0-9a-f]{64}$"
type DevelopmentCorpusRefutationScope = Literal[
    "NO_REFUTATION_OBSERVED", "REFUTED_BY_ONE", "REFUTED_BY_BOTH"
]


class DevelopmentCorpusEnsemblePlan(_AuditArtifact):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_ensemble_plan"] = "development_corpus_ensemble_plan"
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    consensus_policy: Literal["TWO_REVIEW_UNANIMOUS_OPINION_ONLY"] = (
        "TWO_REVIEW_UNANIMOUS_OPINION_ONLY"
    )
    run_id: str = Field(pattern=_RUN_ID)
    candidate: DevelopmentCorpusPlan
    reviewers: tuple[DevelopmentEnsembleReviewer, ...] = Field(min_length=2, max_length=2)
    maximum_run_seconds: float = Field(gt=0, le=1800, allow_inf_nan=False)
    estimated_headroom_usd: Decimal = Field(gt=0, le=250)
    plan_sha256: str = Field(pattern=_SHA)

    @property
    def policy(self) -> DevelopmentCostPolicy:
        return self.candidate.policy

    @model_validator(mode="after")
    def exact_roles_source_deadline_and_estimated_headroom(self) -> Self:
        if (
            self.candidate.run_id != development_ensemble_stage_run_id(self.run_id, "candidate")
            or self.candidate.maximum_run_seconds != self.maximum_run_seconds
            or tuple(r.stage_id for r in self.reviewers) != DEVELOPMENT_ENSEMBLE_REVIEWERS
            or any(
                r.run_id != development_ensemble_stage_run_id(self.run_id, r.stage_id)
                for r in self.reviewers
            )
        ):
            raise ValueError("manifest ensemble changes its ordered roles, candidate or deadline")
        _require_distinct_roles((self.candidate.routing, *(r.routing for r in self.reviewers)))
        expected = _money_sum(
            (
                self.candidate.estimated_total_cost_usd,
                self.policy.per_attempt_budget_usd * 2 * len(self.candidate.shards),
            )
        )
        if self.estimated_headroom_usd != expected or expected > self.policy.total_budget_usd:
            raise ValueError("manifest ensemble estimated headroom exceeds its shared target")
        if (
            canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
            != self.plan_sha256
        ):
            raise ValueError("manifest ensemble plan digest differs")
        return self


@dataclass(frozen=True)
class PreparedDevelopmentCorpusEnsemble:
    plan: DevelopmentCorpusEnsemblePlan
    candidate: PreparedDevelopmentCorpus = field(repr=False)
    reviewer_metadata: tuple[DevelopmentReviewMetadata, ...] = field(repr=False)


def prepare_development_corpus_ensemble(
    *,
    policy: DevelopmentCostPolicy,
    candidate_metadata: DevelopmentReviewMetadata,
    reviewer_metadata: tuple[DevelopmentReviewMetadata, ...],
    manifest: DevelopmentCorpusManifest,
    source_files: DevelopmentSourceBytes,
    run_id: str,
    candidate_maximum_completion_tokens: int = 4096,
    reviewer_maximum_completion_tokens: tuple[int, int] = (4096, 4096),
    maximum_run_seconds: float = 600.0,
) -> PreparedDevelopmentCorpusEnsemble:
    """Freeze all roles and conservative future per-file allowances, never reserved capacity."""

    if (
        type(policy) is not DevelopmentCostPolicy
        or policy.maximum_attempts != 1
        or type(reviewer_metadata) is not tuple
        or len(reviewer_metadata) != 2
        or type(reviewer_maximum_completion_tokens) is not tuple
        or len(reviewer_maximum_completion_tokens) != 2
        or type(maximum_run_seconds) not in {int, float}
    ):
        raise DevelopmentCostError("manifest ensemble requires exact bounded stage inputs")
    metadata = tuple(_development_metadata(m) for m in reviewer_metadata)
    for (snapshot, _discovery), tokens in zip(
        metadata, reviewer_maximum_completion_tokens, strict=True
    ):
        if type(tokens) is not int or not 1 <= tokens <= min(
            65536, snapshot.endpoints[0].max_completion_tokens
        ):
            raise DevelopmentCostError("manifest ensemble reviewer allowance exceeds metadata")
    candidate = prepare_development_corpus(
        policy=policy,
        endpoint_snapshot=candidate_metadata,
        manifest=manifest,
        source_files=source_files,
        run_id=development_ensemble_stage_run_id(run_id, "candidate"),
        maximum_completion_tokens=candidate_maximum_completion_tokens,
        maximum_run_seconds=maximum_run_seconds,
    )
    reviewers = tuple(
        DevelopmentEnsembleReviewer(
            stage_id=stage,
            run_id=development_ensemble_stage_run_id(run_id, stage),
            routing=DevelopmentRoutingContext.from_metadata(snapshot, discovery),
            maximum_completion_tokens=tokens,
        )
        for stage, (snapshot, discovery), tokens in zip(
            DEVELOPMENT_ENSEMBLE_REVIEWERS,
            metadata,
            reviewer_maximum_completion_tokens,
            strict=True,
        )
    )
    values: dict[str, Any] = dict(
        run_id=run_id,
        candidate=candidate.plan,
        reviewers=reviewers,
        maximum_run_seconds=maximum_run_seconds,
        estimated_headroom_usd=_money_sum(
            (
                candidate.plan.estimated_total_cost_usd,
                policy.per_attempt_budget_usd * 2 * len(candidate.shards),
            )
        ),
    )
    provisional = DevelopmentCorpusEnsemblePlan.model_construct(**values, plan_sha256="0" * 64)
    values["plan_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"plan_sha256"})
    )
    return PreparedDevelopmentCorpusEnsemble(
        DevelopmentCorpusEnsemblePlan.model_validate(values),
        candidate,
        tuple(discovery or snapshot for snapshot, discovery in metadata),
    )


def manifest_review_has_all_available_opinions(
    observation: DevelopmentCorpusJudgmentObservation,
) -> bool:
    """Complete available-claim review does not complete an incomplete candidate's source scope."""

    return not observation.unreviewed_claim_ids and (
        observation.status == "OBSERVED_ALL_JUDGMENTS"
        or observation.stop_reason == "CANDIDATE_INCOMPLETE"
    )


def manifest_refutation_scope(
    opinions: tuple[DevelopmentEnsembleOpinion | None, ...],
) -> DevelopmentCorpusRefutationScope:
    """Count observed refutations without treating missing opinions or consensus as truth."""

    count = opinions.count("REFUTED")
    return (
        "REFUTED_BY_BOTH"
        if count == 2
        else "REFUTED_BY_ONE"
        if count == 1
        else "NO_REFUTATION_OBSERVED"
    )


class DevelopmentCorpusEnsembleClaim(_DevelopmentModel):
    candidate_claim: DevelopmentCorpusJudgmentClaim
    opinions: tuple[DevelopmentEnsembleOpinion | None, ...] = Field(min_length=2, max_length=2)
    consensus: Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE", "UNREVIEWED"]
    refutation_scope: DevelopmentCorpusRefutationScope

    @model_validator(mode="after")
    def original_opinions_determine_only_descriptive_consensus(self) -> Self:
        expected = (
            "UNREVIEWED"
            if None in self.opinions
            else self.opinions[0]
            if self.opinions[0] == self.opinions[1]
            else "INCONCLUSIVE"
        )
        if self.consensus != expected or self.refutation_scope != manifest_refutation_scope(
            self.opinions
        ):
            raise ValueError("manifest ensemble conceals missing, conflicting or refuting opinions")
        return self


def development_corpus_ensemble_claims(
    candidate: DevelopmentCorpusObservation | None,
    judgments: tuple[DevelopmentCorpusJudgmentObservation, ...],
) -> tuple[DevelopmentCorpusEnsembleClaim, ...]:
    """Retain every available original claim, including incomplete candidates and missing reviews."""

    if candidate is None:
        return ()
    opinions = tuple(
        {
            d.claim_id: d.verdict
            for s in j.observations
            if s.status == "OBSERVED" and s.response is not None
            for d in s.response.decisions
        }
        for j in judgments
    )
    result = []
    for shard in candidate.plan.shards:
        for claim in development_corpus_judgment_claims(candidate, shard.shard_id):
            pair = tuple(
                opinions[i].get(claim.claim_id) if i < len(opinions) else None for i in range(2)
            )
            consensus = (
                "UNREVIEWED" if None in pair else pair[0] if pair[0] == pair[1] else "INCONCLUSIVE"
            )
            result.append(
                DevelopmentCorpusEnsembleClaim.model_validate(
                    dict(
                        candidate_claim=claim,
                        opinions=pair,
                        consensus=consensus,
                        refutation_scope=manifest_refutation_scope(pair),
                    )
                )
            )
    return tuple(result)


class DevelopmentCorpusEnsembleAccountingEntry(_DevelopmentModel):
    stage_id: DevelopmentEnsembleStageId
    entry: DevelopmentCorpusAccountingEntry


class DevelopmentCorpusEnsembleObservation(_AuditArtifact):
    """Exact stage joins, original incomplete scope and unique charges; never an audit pass."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_ensemble_observation"] = (
        "development_corpus_ensemble_observation"
    )
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    plan: DevelopmentCorpusEnsemblePlan
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
    status: Literal["OBSERVED_ALL_STAGES", "NO_CANDIDATES", "INCOMPLETE"]
    stop_reason: (
        Literal["CANDIDATE_INCOMPLETE", "REVIEW_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None
    )
    candidate: DevelopmentCorpusObservation | None
    judgment_plans: tuple[DevelopmentCorpusJudgmentPlan, ...] = Field(max_length=2)
    judgments: tuple[DevelopmentCorpusJudgmentObservation, ...] = Field(max_length=2)
    accounting: tuple[DevelopmentCorpusEnsembleAccountingEntry, ...] = Field(max_length=192)
    claims: tuple[DevelopmentCorpusEnsembleClaim, ...] = Field(max_length=1024)
    unobserved_candidate_shard_ids: tuple[str, ...] = Field(max_length=64)
    unobserved_stage_ids: tuple[DevelopmentEnsembleStageId, ...] = Field(max_length=3)
    completed_stage_count: int = Field(ge=0, le=3)
    completed_judgment_count: int = Field(ge=0, le=2048)
    available_claim_reviews_complete: bool
    total_accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    observed_stage_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def exact_source_stages_claims_and_cumulative_costs(self) -> Self:
        candidate = self.candidate
        if candidate is not None:
            require_development_corpus_judgment_candidate(candidate)
            if candidate.plan != self.plan.candidate or candidate.transport != self.transport:
                raise ValueError(
                    "manifest ensemble changes its original candidate plan or transport"
                )
        if not len(self.judgments) <= len(self.judgment_plans) <= len(self.judgments) + 1:
            raise ValueError("manifest ensemble loses sequential review-plan scope")
        if self.judgment_plans and (candidate is None or not candidate.candidate_claim_count):
            raise ValueError("manifest ensemble reviews missing or empty candidates")
        for i, review_plan in enumerate(self.judgment_plans):
            selected = self.plan.reviewers[i]
            if (
                review_plan.candidate != candidate
                or review_plan.run_id != selected.run_id
                or review_plan.reviewer != selected.routing
                or review_plan.policy != self.plan.policy
                or review_plan.maximum_completion_tokens != selected.maximum_completion_tokens
                or review_plan.maximum_run_seconds > self.plan.maximum_run_seconds
                or not review_plan.shards
            ):
                raise ValueError("manifest ensemble review selection differs from frozen roles")
        for i, judgment in enumerate(self.judgments):
            if (
                judgment.plan != self.judgment_plans[i]
                or judgment.transport != self.transport
                or (
                    i < len(self.judgment_plans) - 1
                    and not manifest_review_has_all_available_opinions(judgment)
                )
            ):
                raise ValueError("manifest ensemble continued a failed or substituted review")
        generations = [
            s.generation_id
            for s in (() if candidate is None else candidate.observations)
            if s.status == "OBSERVED" and s.generation_id is not None
        ]
        generations.extend(
            s.generation_id
            for j in self.judgments
            for s in j.observations
            if s.status == "OBSERVED" and s.generation_id is not None
        )
        if len(generations) != len(set(generations)):
            raise ValueError("manifest ensemble reuses an observed generation across roles")
        plans: dict[
            DevelopmentEnsembleStageId, DevelopmentCorpusPlan | DevelopmentCorpusJudgmentPlan
        ] = {
            "candidate": self.plan.candidate,
            **{self.plan.reviewers[i].stage_id: p for i, p in enumerate(self.judgment_plans)},
        }
        if any(row.stage_id not in plans for row in self.accounting):
            raise ValueError("manifest ensemble accounts an unplanned stage")
        grouped = {
            stage: tuple(row.entry for row in self.accounting if row.stage_id == stage)
            for stage in plans
        }
        if tuple((r.stage_id, r.entry) for r in self.accounting) != tuple(
            (stage, entry) for stage, entries in grouped.items() for entry in entries
        ):
            raise ValueError("manifest ensemble reorders stage accounting")
        reservations = [r.entry.reservation_id for r in self.accounting]
        requests = [r.entry.ledger_request_id for r in self.accounting]
        if len(reservations) != len(set(reservations)) or len(requests) != len(set(requests)):
            raise ValueError("manifest ensemble double-counts a reservation or request")
        for stage, entries in grouped.items():
            planned: tuple[DevelopmentCorpusShardPlan | DevelopmentCorpusJudgmentShardPlan, ...] = (
                plans[stage].shards
            )
            if tuple(e.shard_id for e in entries) != tuple(
                s.shard_id for s in planned[: len(entries)]
            ):
                raise ValueError("manifest ensemble loses an ordered stage accounting prefix")
            for entry, shard in zip(entries, planned, strict=False):
                if (
                    entry.ledger_request_id
                    != development_ledger_request_id(shard.estimate.request_id)
                    or entry.reserved_usd != shard.estimate.estimated_cost_per_attempt_usd
                ):
                    raise ValueError("manifest ensemble charge differs from its exact request")
        if candidate is not None and grouped["candidate"] != candidate.accounting:
            raise ValueError("manifest ensemble changes original candidate accounting")
        for i, judgment in enumerate(self.judgments):
            if grouped[self.plan.reviewers[i].stage_id] != judgment.accounting:
                raise ValueError("manifest ensemble changes retained review accounting")
        if (
            candidate is not None
            and self.judgment_plans
            and (
                any(
                    e.status in {CostEntryStatus.RESERVED, CostEntryStatus.RESERVATION_OVERRUN}
                    for e in candidate.accounting
                )
                or (
                    self.plan.policy.uncertain_cost_policy == "STOP"
                    and any(
                        e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                        for e in candidate.accounting
                    )
                )
            )
        ):
            raise ValueError("manifest ensemble continued a blocked candidate liability")
        for stage, entries in grouped.items():
            if any(e.status is not CostEntryStatus.RECONCILED for e in entries[:-1]):
                raise ValueError("manifest ensemble continued an unsettled within-stage request")
            if (
                stage == "review-01"
                and "review-02" in plans
                and any(e.status is not CostEntryStatus.RECONCILED for e in entries)
            ):
                raise ValueError("manifest ensemble continued an unsettled current review")
        rows = development_corpus_ensemble_claims(candidate, self.judgments)
        candidate_complete = candidate is not None and candidate.status == "OBSERVED_ALL_SHARDS"
        completed = (
            candidate_complete,
            *(
                i < len(self.judgments) and self.judgments[i].status == "OBSERVED_ALL_JUDGMENTS"
                for i in range(2)
            ),
        )
        gaps = tuple(
            stage
            for stage, done in zip(DEVELOPMENT_ENSEMBLE_STAGES, completed, strict=True)
            if not done
        )
        empty = candidate_complete and not rows
        expected_status = (
            "INCOMPLETE"
            if self.stop_reason is not None or not candidate_complete or (gaps and not empty)
            else "NO_CANDIDATES"
            if empty
            else "OBSERVED_ALL_STAGES"
        )
        available_complete = bool(rows) and all(None not in row.opinions for row in rows)
        source_gaps = (
            tuple(s.shard_id for s in self.plan.candidate.shards)
            if candidate is None
            else candidate.unobserved_shard_ids
        )
        if (
            self.claims != rows
            or self.status != expected_status
            or (self.status == "INCOMPLETE" and self.stop_reason is None)
            or self.unobserved_stage_ids != gaps
            or self.unobserved_candidate_shard_ids != source_gaps
            or self.completed_stage_count != sum(completed)
            or self.completed_judgment_count
            != sum(op is not None for row in rows for op in row.opinions)
            or self.available_claim_reviews_complete != available_complete
        ):
            raise ValueError(
                "manifest ensemble conceals source gaps, claims, opinions or failed scope"
            )
        costs = (
            _money_sum(r.entry.accounted_cost_usd for r in self.accounting),
            _money_sum(r.entry.actual_cost_usd or Decimal(0) for r in self.accounting),
            _money_sum(
                r.entry.accounted_cost_usd
                for r in self.accounting
                if r.entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            ),
            _money_sum(
                r.entry.reserved_usd
                for r in self.accounting
                if r.entry.status is CostEntryStatus.RESERVED
            ),
        )
        if costs != (
            self.total_accounted_cost_usd,
            self.reported_actual_cost_usd,
            self.uncertain_accounted_cost_usd,
            self.active_reserved_usd,
        ):
            raise ValueError(
                "manifest ensemble loses or duplicates known/unknown stage liabilities"
            )
        elapsed = (candidate.elapsed_seconds if candidate is not None else 0) + sum(
            j.elapsed_seconds for j in self.judgments
        )
        if self.observed_stage_elapsed_seconds != elapsed or elapsed > self.elapsed_seconds + 1e-9:
            raise ValueError("manifest ensemble stage time exceeds its measured whole run")
        return self
