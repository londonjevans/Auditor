"""Predeclared candidate series; local ordering is not external registration or independent truth."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    bind_development_corpus_benchmark,
)
from mmaudit.benchmark.development_corpus_control_measurement import _json_object
from mmaudit.benchmark.development_corpus_stability import _configuration, _elapsed_total
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
    PreparedDevelopmentCorpus,
    prepare_development_corpus,
)
from mmaudit.models.development_costs import DevelopmentCostError, DevelopmentCostPolicy
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import DevelopmentReviewMetadata, _DevelopmentModel
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES = 16_000_000
MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES = 192_000_000
_RUN_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
_SHA = r"^[0-9a-f]{64}$"
type DevelopmentCorpusRepeatsStop = Literal[
    "TRIAL_INCOMPLETE", "BUDGET_STOP", "LOCAL_FAILURE", "INTERRUPTED", "IDENTITY_REUSE"
]


def development_corpus_repeat_run_id(run_id: str, trial_index: int) -> str:
    """Derive distinct planned identities, without asserting stochastic independence."""

    if (
        type(run_id) is not str
        or re.fullmatch(_RUN_ID, run_id) is None
        or type(trial_index) is not int
        or not 0 <= trial_index < 8
    ):
        raise DevelopmentCostError("candidate repeat identity is invalid")
    return "dvr-" + canonical_sha256({"run_id": run_id, "trial_index": trial_index})[:60]


class DevelopmentCorpusRepeatsPlan(_AuditArtifact):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_repeats_plan"] = "development_corpus_repeats_plan"
    selection_scope: Literal["LOCAL_PREDECLARATION_NOT_EXTERNALLY_REGISTERED"] = (
        "LOCAL_PREDECLARATION_NOT_EXTERNALLY_REGISTERED"
    )
    execution_policy: Literal["ORDERED_PREDECLARED_TRIALS_NO_RETRIES"] = (
        "ORDERED_PREDECLARED_TRIALS_NO_RETRIES"
    )
    trial_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    budget_scope: Literal["SHARED_ESTIMATED_PREFLIGHT_NOT_PROVIDER_ENFORCED_CEILING"] = (
        "SHARED_ESTIMATED_PREFLIGHT_NOT_PROVIDER_ENFORCED_CEILING"
    )
    role_scope: Literal["CANDIDATE_ONLY_OTHER_AUDIT_ROLES_NOT_MEASURED"] = (
        "CANDIDATE_ONLY_OTHER_AUDIT_ROLES_NOT_MEASURED"
    )
    run_id: str = Field(pattern=_RUN_ID)
    trial_count: int = Field(ge=2, le=8)
    trials: tuple[DevelopmentCorpusPlan, ...] = Field(min_length=2, max_length=8)
    benchmark: DevelopmentCorpusBenchmarkBinding
    configuration_sha256: str = Field(pattern=_SHA)
    maximum_run_seconds: float = Field(gt=0, le=1800, allow_inf_nan=False)
    estimated_total_cost_usd: Decimal = Field(gt=0, le=250)
    plan_sha256: str = Field(pattern=_SHA)

    @property
    def policy(self) -> DevelopmentCostPolicy:
        return self.trials[0].policy

    @model_validator(mode="after")
    def all_trials_are_frozen_before_selection(self) -> Self:
        if self.trial_count != len(self.trials):
            raise ValueError("repeat plan loses a predeclared trial")
        for index, plan in enumerate(self.trials):
            if (
                plan.run_id != development_corpus_repeat_run_id(self.run_id, index)
                or _configuration(plan) != self.configuration_sha256
            ):
                raise ValueError("repeat plan changes a trial identity or fixed configuration")
        requests = [s.estimate.request_id for p in self.trials for s in p.shards]
        if len(requests) != len(set(requests)):
            raise ValueError("repeat plan reuses a request identity")
        if self.benchmark != bind_development_corpus_benchmark(
            plan=self.trials[0],
            truth_content=self.benchmark.truth_file_content.encode(),
            expected_truth_sha256=self.benchmark.truth_file_sha256,
        ):
            raise ValueError("repeat plan changes the original source or raw labels")
        total = _money_sum(p.estimated_total_cost_usd for p in self.trials)
        if total != self.estimated_total_cost_usd or total > self.policy.total_budget_usd:
            raise ValueError("repeat series exceeds its shared estimated budget")
        if canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"})) != (
            self.plan_sha256
        ):
            raise ValueError("repeat plan digest differs")
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES:
            raise ValueError("repeat plan exceeds its retained byte bound")
        return self


@dataclass(frozen=True)
class PreparedDevelopmentCorpusRepeats:
    plan: DevelopmentCorpusRepeatsPlan
    trials: tuple[PreparedDevelopmentCorpus, ...] = field(repr=False)


def prepare_development_corpus_repeats(
    *,
    policy: DevelopmentCostPolicy,
    endpoint_snapshot: DevelopmentReviewMetadata,
    manifest: DevelopmentCorpusManifest,
    source_files: DevelopmentSourceBytes,
    run_id: str,
    trial_count: int,
    truth_content: bytes,
    expected_truth_sha256: str,
    maximum_completion_tokens: int = 4096,
    maximum_trial_seconds: float = 600.0,
    maximum_run_seconds: float = 600.0,
) -> PreparedDevelopmentCorpusRepeats:
    """Prepare all requests and their total estimate without dispatch, credentials or output writes."""

    if type(trial_count) is not int or not 2 <= trial_count <= 8:
        raise DevelopmentCostError("candidate repeats require two to eight planned trials")
    if type(maximum_run_seconds) not in {int, float}:
        raise DevelopmentCostError("candidate repeats require a finite parent deadline")
    trials = tuple(
        prepare_development_corpus(
            policy=policy,
            endpoint_snapshot=endpoint_snapshot,
            manifest=manifest,
            source_files=source_files,
            run_id=development_corpus_repeat_run_id(run_id, index),
            maximum_completion_tokens=maximum_completion_tokens,
            maximum_run_seconds=maximum_trial_seconds,
        )
        for index in range(trial_count)
    )
    values: dict[str, Any] = dict(
        run_id=run_id,
        trial_count=trial_count,
        trials=tuple(t.plan for t in trials),
        benchmark=bind_development_corpus_benchmark(
            plan=trials[0].plan,
            truth_content=truth_content,
            expected_truth_sha256=expected_truth_sha256,
        ),
        configuration_sha256=_configuration(trials[0].plan),
        maximum_run_seconds=maximum_run_seconds,
        estimated_total_cost_usd=_money_sum(t.plan.estimated_total_cost_usd for t in trials),
    )
    provisional = DevelopmentCorpusRepeatsPlan.model_construct(**values, plan_sha256="0" * 64)
    values["plan_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"plan_sha256"})
    )
    return PreparedDevelopmentCorpusRepeats(
        DevelopmentCorpusRepeatsPlan.model_validate(values), trials
    )


class DevelopmentCorpusRepeatTrial(_DevelopmentModel):
    """Missing durable output never becomes an invented empty candidate observation."""

    trial_index: int = Field(ge=0, le=7)
    status: Literal["NOT_STARTED", "MISSING_RESULT", "INCOMPLETE", "COMPLETE"]
    observation: DevelopmentCorpusObservation | None
    accounting: tuple[DevelopmentCorpusAccountingEntry, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def slot_preserves_original_observation_and_costs(self) -> Self:
        if self.observation is None:
            if self.status not in {"NOT_STARTED", "MISSING_RESULT"} or (
                self.status == "NOT_STARTED" and self.accounting
            ):
                raise ValueError("repeat slot invents an observation or hides dispatch")
        elif (
            self.status
            != ("COMPLETE" if self.observation.status == "OBSERVED_ALL_SHARDS" else "INCOMPLETE")
            or self.accounting != self.observation.accounting
        ):
            raise ValueError("repeat slot changes its original observation or accounting")
        return self


def repeat_projection(
    plan: DevelopmentCorpusRepeatsPlan,
    trials: tuple[DevelopmentCorpusRepeatTrial, ...],
    reason: DevelopmentCorpusRepeatsStop | None,
) -> dict[str, Any]:
    """Every declared request remains in scope even when an entire trial has no durable result."""

    selected = [
        development_ledger_request_id(s.estimate.request_id) for p in plan.trials for s in p.shards
    ]
    accounts = [a for t in trials for a in t.accounting]
    observed = [t.observation for t in trials if t.observation is not None]
    account_ids = {a.ledger_request_id for a in accounts}
    runtime_ids = {
        development_ledger_request_id(s.estimate.request_id)
        for o in observed
        for s in o.observations
    }
    generations = [s.generation_id for o in observed for s in o.observations if s.generation_id]
    reused = len(generations) != len(set(generations))
    missing = tuple(t.trial_index for t in trials if t.observation is None)
    complete = sum(t.status == "COMPLETE" for t in trials)
    return dict(
        status="COMPLETE"
        if complete == plan.trial_count and reason is None and not reused
        else "INCOMPLETE",
        started_trial_count=sum(t.status != "NOT_STARTED" for t in trials),
        completed_trial_count=complete,
        missing_result_trial_indexes=missing,
        selected_request_count=len(selected),
        missing_accounting_request_ids=tuple(r for r in selected if r not in account_ids),
        missing_runtime_request_ids=tuple(r for r in selected if r not in runtime_ids),
        unknown_actual_cost_request_ids=tuple(
            a.ledger_request_id for a in accounts if a.actual_cost_usd is None
        ),
        total_accounted_cost_usd=_money_sum(a.accounted_cost_usd for a in accounts),
        reported_actual_cost_usd=_money_sum(a.actual_cost_usd or Decimal(0) for a in accounts),
        uncertain_accounted_cost_usd=_money_sum(
            a.accounted_cost_usd
            for a in accounts
            if a.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            a.reserved_usd for a in accounts if a.status is CostEntryStatus.RESERVED
        ),
        observed_trial_elapsed_seconds=_elapsed_total(o.elapsed_seconds for o in observed),
        generation_identity_reused=reused,
        measurement_scope="MISSING_PLANNED_TRIAL_RESULTS"
        if missing
        else "REUSED_EVIDENCE_IDENTITIES"
        if reused
        else "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED",
    )


class DevelopmentCorpusRepeatsObservation(_AuditArtifact):
    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_repeats_observation"] = (
        "development_corpus_repeats_observation"
    )
    interpretation: Literal["CANDIDATE_SERIES_NOT_QUALIFIED_AUDITS"] = (
        "CANDIDATE_SERIES_NOT_QUALIFIED_AUDITS"
    )
    elapsed_scope: Literal["THROUGH_CHILD_RECOVERY_EXCLUDES_FINAL_SERIES_MEASUREMENT"] = (
        "THROUGH_CHILD_RECOVERY_EXCLUDES_FINAL_SERIES_MEASUREMENT"
    )
    plan: DevelopmentCorpusRepeatsPlan
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
    trials: tuple[DevelopmentCorpusRepeatTrial, ...] = Field(min_length=2, max_length=8)
    status: Literal["COMPLETE", "INCOMPLETE"]
    stop_reason: DevelopmentCorpusRepeatsStop | None
    started_trial_count: int = Field(ge=0, le=8)
    completed_trial_count: int = Field(ge=0, le=8)
    missing_result_trial_indexes: tuple[int, ...] = Field(max_length=8)
    selected_request_count: int = Field(ge=2, le=512)
    missing_accounting_request_ids: tuple[str, ...] = Field(max_length=512)
    missing_runtime_request_ids: tuple[str, ...] = Field(max_length=512)
    unknown_actual_cost_request_ids: tuple[str, ...] = Field(max_length=512)
    total_accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    observed_trial_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    generation_identity_reused: bool
    measurement_scope: Literal[
        "MISSING_PLANNED_TRIAL_RESULTS",
        "REUSED_EVIDENCE_IDENTITIES",
        "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED",
    ]
    observation_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_all_planned_slots_and_derived_scope(self) -> Self:
        if tuple(t.trial_index for t in self.trials) != tuple(range(self.plan.trial_count)):
            raise ValueError("repeat observation loses or reorders planned trials")
        ended = False
        reservations: set[str] = set()
        for planned, trial in zip(self.plan.trials, self.trials, strict=True):
            if ended and trial.status != "NOT_STARTED":
                raise ValueError("repeat series skips or continues after an unretained trial")
            ended = trial.status in {"NOT_STARTED", "MISSING_RESULT"}
            if trial.observation is not None and (
                trial.observation.plan != planned or trial.observation.transport != self.transport
            ):
                raise ValueError("repeat trial changes its predeclared plan or transport")
            for shard, account in zip(planned.shards, trial.accounting, strict=False):
                if (
                    account.shard_id != shard.shard_id
                    or account.ledger_request_id
                    != development_ledger_request_id(shard.estimate.request_id)
                    or account.reserved_usd != shard.estimate.estimated_cost_per_attempt_usd
                    or account.reservation_id in reservations
                ):
                    raise ValueError("repeat accounting loses planned identities or reuses charges")
                reservations.add(account.reservation_id)
            if len(trial.accounting) > len(planned.shards):
                raise ValueError("repeat accounting exceeds planned requests")
            if any(a.status is not CostEntryStatus.RECONCILED for a in trial.accounting[:-1]):
                raise ValueError("repeat child accounting continues after an unsettled request")
            ended = ended or any(
                a.status in {CostEntryStatus.RESERVED, CostEntryStatus.RESERVATION_OVERRUN}
                or (
                    a.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                    and self.plan.policy.uncertain_cost_policy == "STOP"
                )
                for a in trial.accounting
            )
        expected = repeat_projection(self.plan, self.trials, self.stop_reason)
        if any(getattr(self, key) != value for key, value in expected.items()):
            raise ValueError("repeat result changes costs, missing scope or whole-series status")
        if (
            (self.status == "INCOMPLETE" and self.stop_reason is None)
            or (self.stop_reason == "IDENTITY_REUSE" and not self.generation_identity_reused)
            or (
                self.stop_reason == "TRIAL_INCOMPLETE"
                and all(t.status == "COMPLETE" for t in self.trials)
            )
        ):
            raise ValueError("repeat result omits its stop reason")
        if self.observed_trial_elapsed_seconds > self.elapsed_seconds + 1e-9:
            raise ValueError("repeat child duration exceeds retained parent duration")
        if canonical_sha256(self.model_dump(mode="json", exclude={"observation_sha256"})) != (
            self.observation_sha256
        ):
            raise ValueError("repeat observation digest differs")
        if len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES:
            raise ValueError("repeat observation exceeds its retained byte bound")
        return self


def read_development_corpus_repeats(content: bytes) -> DevelopmentCorpusRepeatsObservation:
    """Strict bounded reader; the local plan/result is not external registration or authority."""

    _json_object(content, maximum=MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES)
    return DevelopmentCorpusRepeatsObservation.model_validate_json(content, strict=True)


def read_development_corpus_repeats_plan(content: bytes) -> DevelopmentCorpusRepeatsPlan:
    """Read a bounded local predeclaration without granting execution or truth authority."""

    _json_object(content, maximum=MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES)
    return DevelopmentCorpusRepeatsPlan.model_validate_json(content, strict=True)
