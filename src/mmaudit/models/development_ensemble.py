"""Frozen development stage composition; model agreement never grants audit authority."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.development_audit import (
    DevelopmentAuditAccountingEntry,
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    DevelopmentCorpusId,
    DevelopmentScoredAuditShardObservation,
    DevelopmentSourceBytes,
    PreparedDevelopmentAudit,
    _AuditArtifact,
    development_ledger_request_id,
    prepare_development_audit,
)
from mmaudit.models.development_costs import DevelopmentCostError, DevelopmentCostPolicy
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentClaim,
    DevelopmentJudgmentObservation,
    DevelopmentJudgmentPlan,
    _money_sum,
    development_judgment_claims,
)
from mmaudit.models.development_review import (
    DevelopmentReviewMetadata,
    _development_metadata,
    _DevelopmentModel,
)
from mmaudit.models.development_routing import DevelopmentRoutingContext
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256

type DevelopmentEnsembleStageId = Literal["candidate", "review-01", "review-02"]
type DevelopmentEnsembleReviewerId = Literal["review-01", "review-02"]
type DevelopmentEnsembleOpinion = Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE"]
DEVELOPMENT_ENSEMBLE_REVIEWERS: tuple[DevelopmentEnsembleReviewerId, ...] = (
    "review-01",
    "review-02",
)
DEVELOPMENT_ENSEMBLE_STAGES: tuple[DevelopmentEnsembleStageId, ...] = (
    "candidate",
    "review-01",
    "review-02",
)
MAX_DEVELOPMENT_ENSEMBLE_ARTIFACT_BYTES = 16_000_000
_RUN_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
_SHA = r"^[0-9a-f]{64}$"


def development_ensemble_stage_run_id(run_id: str, stage_id: DevelopmentEnsembleStageId) -> str:
    """Separate every first-attempt stage identity without making an automatic retry ID."""

    if (
        type(run_id) is not str
        or re.fullmatch(_RUN_ID, run_id) is None
        or type(stage_id) is not str
        or stage_id not in DEVELOPMENT_ENSEMBLE_STAGES
    ):
        raise DevelopmentCostError("development ensemble stage identity is invalid")
    return "dve-" + canonical_sha256({"run_id": run_id, "stage_id": stage_id})[:60]


def _require_distinct_roles(contexts: tuple[DevelopmentRoutingContext, ...]) -> None:
    seen: set[str] = set()
    for context in contexts:
        identities = {context.exact_model_id}
        if context.canonical_model_id is not None:
            identities.add(context.canonical_model_id)
        if seen & identities:
            raise DevelopmentCostError("development ensemble roles share a model or known alias")
        seen.update(identities)


class DevelopmentEnsembleReviewer(_DevelopmentModel):
    stage_id: DevelopmentEnsembleReviewerId
    run_id: str = Field(pattern=_RUN_ID)
    routing: DevelopmentRoutingContext
    maximum_completion_tokens: int = Field(ge=1, le=65_536)


class DevelopmentEnsemblePlan(_AuditArtifact):
    """Candidate plus two independent prompts, not evidence of independent root lineages."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_ensemble_plan"] = "development_ensemble_plan"
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    consensus_policy: Literal["TWO_REVIEW_UNANIMOUS_OPINION_ONLY"] = (
        "TWO_REVIEW_UNANIMOUS_OPINION_ONLY"
    )
    run_id: str = Field(pattern=_RUN_ID)
    candidate: DevelopmentAuditPlan
    candidate_routing: DevelopmentRoutingContext
    reviewers: tuple[DevelopmentEnsembleReviewer, ...] = Field(min_length=2, max_length=2)
    maximum_run_seconds: float = Field(gt=0, le=1800, allow_inf_nan=False)
    estimated_headroom_usd: Decimal = Field(gt=0, le=250)
    plan_sha256: str = Field(pattern=_SHA)

    @property
    def policy(self) -> DevelopmentCostPolicy:
        return self.candidate.shards[0].estimate.policy

    @model_validator(mode="after")
    def exact_stage_selection_and_headroom(self) -> Self:
        estimate = self.candidate.shards[0].estimate
        if (
            self.candidate.schema_version != "2.0"
            or self.candidate.run_id != development_ensemble_stage_run_id(self.run_id, "candidate")
            or estimate.exact_model_id != self.candidate_routing.exact_model_id
            or estimate.provider_endpoint != self.candidate_routing.provider_endpoint
            or estimate.endpoint_snapshot_sha256 != self.candidate_routing.endpoint_snapshot_sha256
            or tuple(item.stage_id for item in self.reviewers) != DEVELOPMENT_ENSEMBLE_STAGES[1:]
        ):
            raise ValueError("development ensemble candidate or stage selection differs")
        for reviewer in self.reviewers:
            if reviewer.run_id != development_ensemble_stage_run_id(self.run_id, reviewer.stage_id):
                raise ValueError("development ensemble reviewer run identity differs")
        _require_distinct_roles((self.candidate_routing, *(r.routing for r in self.reviewers)))
        expected = _money_sum(
            (self.candidate.estimated_total_cost_usd, *(self.policy.per_attempt_budget_usd,) * 6)
        )
        if self.estimated_headroom_usd != expected or expected > self.policy.total_budget_usd:
            raise ValueError("development ensemble estimated stage headroom exceeds its target")
        if (
            canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
            != self.plan_sha256
        ):
            raise ValueError("development ensemble plan digest differs")
        return self


@dataclass(frozen=True)
class PreparedDevelopmentEnsemble:
    plan: DevelopmentEnsemblePlan
    candidate: PreparedDevelopmentAudit = field(repr=False)
    reviewer_metadata: tuple[DevelopmentReviewMetadata, ...] = field(repr=False)


def prepare_development_ensemble(
    *,
    policy: DevelopmentCostPolicy,
    candidate_metadata: DevelopmentReviewMetadata,
    reviewer_metadata: tuple[DevelopmentReviewMetadata, ...],
    corpus_id: DevelopmentCorpusId,
    source_files: DevelopmentSourceBytes,
    run_id: str,
    candidate_maximum_completion_tokens: int = 4096,
    reviewer_maximum_completion_tokens: tuple[int, int] = (4096, 4096),
    maximum_run_seconds: float = 600.0,
) -> PreparedDevelopmentEnsemble:
    """Freeze all roles before dispatch; each role keeps its separately selected allowance."""

    if (
        type(policy) is not DevelopmentCostPolicy
        or policy.maximum_attempts != 1
        or type(reviewer_metadata) is not tuple
        or len(reviewer_metadata) != 2
        or type(reviewer_maximum_completion_tokens) is not tuple
        or len(reviewer_maximum_completion_tokens) != 2
        or type(maximum_run_seconds) not in {int, float}
    ):
        raise DevelopmentCostError("development ensemble requires exact bounded stage inputs")
    candidate_snapshot, candidate_discovery = _development_metadata(candidate_metadata)
    metadata = tuple(_development_metadata(item) for item in reviewer_metadata)
    for (snapshot, _discovery), tokens in zip(
        metadata, reviewer_maximum_completion_tokens, strict=True
    ):
        if type(tokens) is not int or not 1 <= tokens <= min(
            65_536, snapshot.endpoints[0].max_completion_tokens
        ):
            raise DevelopmentCostError("development ensemble reviewer allowance exceeds metadata")
    contexts = (
        DevelopmentRoutingContext.from_metadata(candidate_snapshot, candidate_discovery),
        *(
            DevelopmentRoutingContext.from_metadata(snapshot, discovery)
            for snapshot, discovery in metadata
        ),
    )
    _require_distinct_roles(contexts)
    candidate = prepare_development_audit(
        policy=policy,
        endpoint_snapshot=candidate_discovery or candidate_snapshot,
        corpus_id=corpus_id,
        source_files=source_files,
        run_id=development_ensemble_stage_run_id(run_id, "candidate"),
        maximum_completion_tokens=candidate_maximum_completion_tokens,
        schema_version="2.0",
    )
    reviewers = tuple(
        DevelopmentEnsembleReviewer(
            stage_id=stage_id,
            run_id=development_ensemble_stage_run_id(run_id, stage_id),
            routing=context,
            maximum_completion_tokens=tokens,
        )
        for stage_id, context, tokens in zip(
            DEVELOPMENT_ENSEMBLE_REVIEWERS,
            contexts[1:],
            reviewer_maximum_completion_tokens,
            strict=True,
        )
    )
    values: dict[str, Any] = dict(
        run_id=run_id,
        candidate=candidate.plan,
        candidate_routing=contexts[0],
        reviewers=reviewers,
        maximum_run_seconds=maximum_run_seconds,
        estimated_headroom_usd=_money_sum(
            (candidate.plan.estimated_total_cost_usd, *(policy.per_attempt_budget_usd,) * 6)
        ),
    )
    provisional = DevelopmentEnsemblePlan.model_construct(**values, plan_sha256="0" * 64)
    values["plan_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"plan_sha256"})
    )
    return PreparedDevelopmentEnsemble(
        DevelopmentEnsemblePlan.model_validate(values),
        candidate,
        tuple(discovery or snapshot for snapshot, discovery in metadata),
    )


class DevelopmentEnsembleAccountingEntry(_DevelopmentModel):
    stage_id: DevelopmentEnsembleStageId
    entry: DevelopmentAuditAccountingEntry


class DevelopmentEnsembleClaim(_DevelopmentModel):
    """Retain each original claim and both opinions, including absent or conflicting reviews."""

    candidate_claim: DevelopmentJudgmentClaim
    opinions: tuple[DevelopmentEnsembleOpinion | None, ...] = Field(min_length=2, max_length=2)
    consensus: Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE", "UNREVIEWED"]

    @model_validator(mode="after")
    def consensus_is_only_a_deterministic_opinion(self) -> Self:
        expected = (
            "UNREVIEWED"
            if None in self.opinions
            else self.opinions[0]
            if self.opinions[0] == self.opinions[1]
            else "INCONCLUSIVE"
        )
        if self.consensus != expected:
            raise ValueError("development ensemble consensus hides missing or conflicting opinions")
        return self


def development_ensemble_claims(
    candidate: DevelopmentAuditObservation | None,
    judgments: tuple[DevelopmentJudgmentObservation, ...],
) -> tuple[DevelopmentEnsembleClaim, ...]:
    """Keep observed partial-candidate claims; missing future candidates are never invented."""

    if candidate is None:
        return ()
    opinions = tuple(
        {
            decision.claim_id: decision.verdict
            for shard in judgment.observations
            if shard.status == "OBSERVED" and shard.response is not None
            for decision in shard.response.decisions
        }
        for judgment in judgments
    )
    rows: list[DevelopmentEnsembleClaim] = []
    for shard in candidate.observations:
        if type(shard) is not DevelopmentScoredAuditShardObservation or shard.status != "OBSERVED":
            continue
        for claim in development_judgment_claims(candidate, shard.shard_id):
            pair = tuple(
                opinions[index].get(claim.claim_id) if index < len(opinions) else None
                for index in range(2)
            )
            consensus = (
                "UNREVIEWED" if None in pair else pair[0] if pair[0] == pair[1] else "INCONCLUSIVE"
            )
            rows.append(
                DevelopmentEnsembleClaim.model_validate(
                    {"candidate_claim": claim, "opinions": pair, "consensus": consensus}
                )
            )
    return tuple(rows)


class DevelopmentEnsembleObservation(_AuditArtifact):
    """Executed stage joins and unique request accounting, never a qualified ensemble result."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_ensemble_observation"] = "development_ensemble_observation"
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    plan: DevelopmentEnsemblePlan
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
    status: Literal["OBSERVED_ALL_STAGES", "NO_CANDIDATES", "INCOMPLETE"]
    stop_reason: (
        Literal["CANDIDATE_INCOMPLETE", "REVIEW_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None
    )
    candidate: DevelopmentAuditObservation | None
    judgment_plans: tuple[DevelopmentJudgmentPlan, ...] = Field(max_length=2)
    judgments: tuple[DevelopmentJudgmentObservation, ...] = Field(max_length=2)
    accounting: tuple[DevelopmentEnsembleAccountingEntry, ...] = Field(max_length=9)
    claims: tuple[DevelopmentEnsembleClaim, ...] = Field(max_length=48)
    unobserved_stage_ids: tuple[DevelopmentEnsembleStageId, ...] = Field(max_length=3)
    completed_stage_count: int = Field(ge=0, le=3)
    completed_judgment_count: int = Field(ge=0, le=96)
    total_accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    observed_stage_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def exact_stage_observations_and_costs(self) -> Self:
        candidate = self.candidate
        if candidate is not None and (
            candidate.plan != self.plan.candidate or candidate.transport != self.transport
        ):
            raise ValueError("development ensemble candidate differs from its frozen plan")
        candidate_complete = candidate is not None and candidate.status == "OBSERVED_ALL_SHARDS"
        if (self.judgment_plans or self.judgments) and not candidate_complete:
            raise ValueError("development ensemble reviewed an incomplete candidate")
        if not len(self.judgments) <= len(self.judgment_plans) <= len(self.judgments) + 1:
            raise ValueError("development ensemble review plans lose sequential execution scope")
        for ordinal, judgment_plan in enumerate(self.judgment_plans):
            selected = self.plan.reviewers[ordinal]
            if (
                judgment_plan.candidate != candidate
                or judgment_plan.run_id != selected.run_id
                or judgment_plan.reviewer != selected.routing
                or judgment_plan.policy != self.plan.policy
                or judgment_plan.maximum_completion_tokens != selected.maximum_completion_tokens
                or not judgment_plan.shards
            ):
                raise ValueError("development ensemble judgment plan differs from selected inputs")
        for ordinal, judgment in enumerate(self.judgments):
            if (
                judgment.plan != self.judgment_plans[ordinal]
                or judgment.transport != self.transport
                or (
                    ordinal < len(self.judgment_plans) - 1
                    and judgment.status != "OBSERVED_ALL_JUDGMENTS"
                )
            ):
                raise ValueError("development ensemble continued an incomplete or changed review")
        generations: list[str] = []
        if candidate is not None:
            generations.extend(
                item.generation_id
                for item in candidate.observations
                if item.status == "OBSERVED" and item.generation_id is not None
            )
        generations.extend(
            item.generation_id
            for judgment in self.judgments
            for item in judgment.observations
            if item.status == "OBSERVED" and item.generation_id is not None
        )
        if len(generations) != len(set(generations)):
            raise ValueError("development ensemble reuses an observed generation across roles")

        plans: dict[DevelopmentEnsembleStageId, DevelopmentAuditPlan | DevelopmentJudgmentPlan] = {
            "candidate": self.plan.candidate,
            **{self.plan.reviewers[i].stage_id: plan for i, plan in enumerate(self.judgment_plans)},
        }
        expected_order = tuple(
            (stage_id, shard.shard_id)
            for stage_id, stage_plan in plans.items()
            for shard in stage_plan.shards
        )
        actual_order = tuple((row.stage_id, row.entry.shard_id) for row in self.accounting)
        if actual_order != expected_order[: len(actual_order)]:
            raise ValueError("development ensemble accounting loses its ordered stage/request plan")
        reservations = [row.entry.reservation_id for row in self.accounting]
        requests = [row.entry.ledger_request_id for row in self.accounting]
        if len(reservations) != len(set(reservations)) or len(requests) != len(set(requests)):
            raise ValueError("development ensemble double-counts a request or reservation")
        if any(row.entry.status is not CostEntryStatus.RECONCILED for row in self.accounting[:-1]):
            raise ValueError("development ensemble continued after an unsettled current request")
        for row in self.accounting:
            estimate = next(
                shard.estimate
                for shard in plans[row.stage_id].shards
                if shard.shard_id == row.entry.shard_id
            )
            if (
                row.entry.ledger_request_id != development_ledger_request_id(estimate.request_id)
                or row.entry.reserved_usd != estimate.estimated_cost_per_attempt_usd
            ):
                raise ValueError("development ensemble accounting differs from its exact request")
        observed_accounting: dict[
            DevelopmentEnsembleStageId, tuple[DevelopmentAuditAccountingEntry, ...]
        ] = {
            "candidate": () if candidate is None else candidate.accounting,
        }
        for ordinal, judgment in enumerate(self.judgments):
            observed_accounting[self.plan.reviewers[ordinal].stage_id] = judgment.accounting
        for stage_id, entries in observed_accounting.items():
            if stage_id == "candidate" and candidate is None:
                continue
            if tuple(row.entry for row in self.accounting if row.stage_id == stage_id) != entries:
                raise ValueError("development ensemble changed retained stage costs")
        rows = development_ensemble_claims(candidate, self.judgments)
        if self.claims != rows:
            raise ValueError("development ensemble changed candidate claims or review opinions")
        completed = (
            bool(candidate_complete),
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
        if (
            self.status != expected_status
            or (self.status == "INCOMPLETE" and self.stop_reason is None)
            or self.unobserved_stage_ids != gaps
            or self.completed_stage_count != sum(completed)
            or self.completed_judgment_count
            != sum(opinion is not None for row in rows for opinion in row.opinions)
        ):
            raise ValueError("development ensemble completion hides missing or empty stage scope")
        costs = (
            _money_sum(row.entry.accounted_cost_usd for row in self.accounting),
            _money_sum(row.entry.actual_cost_usd or Decimal(0) for row in self.accounting),
            _money_sum(
                row.entry.accounted_cost_usd
                for row in self.accounting
                if row.entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            ),
            _money_sum(
                row.entry.reserved_usd
                for row in self.accounting
                if row.entry.status is CostEntryStatus.RESERVED
            ),
        )
        if costs != (
            self.total_accounted_cost_usd,
            self.reported_actual_cost_usd,
            self.uncertain_accounted_cost_usd,
            self.active_reserved_usd,
        ):
            raise ValueError("development ensemble loses or double-counts stage costs")
        elapsed = (candidate.elapsed_seconds if candidate is not None else 0) + sum(
            j.elapsed_seconds for j in self.judgments
        )
        if self.observed_stage_elapsed_seconds != elapsed or elapsed > self.elapsed_seconds + 1e-9:
            raise ValueError("development ensemble stage times exceed the measured whole run")
        return self
