"""Frozen, comparison-only verdict policy for evidence-sealed model benchmarks.

The types in this module never issue runtime authority.  They bind one verifier-
compiled policy and deterministic comparison results so a future authenticated
runner and external transparency verifier can consume them without accepting
caller-selected thresholds, baselines, clocks, or budgets.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from enum import StrEnum
from itertools import islice
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.benchmark.models import ModelBenchmarkDimension
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_MODEL_PATTERN = r"^[A-Za-z0-9._-]+/[A-Za-z0-9._:/-]+$"
_CASE_ID_PATTERN = r"^case-[0-9a-f]{16}$"
_USD_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$"
_MAX_POLICY_BYTES = 100_000
_MICROS = 1_000_000


def _exact_decimal_context() -> Context:
    """Return arithmetic settings independent of caller Decimal state."""

    return Context(
        prec=160,
        rounding=ROUND_HALF_EVEN,
        Emin=-999_999,
        Emax=999_999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


_BoundedRequestIdentity = Annotated[str, Field(min_length=1, max_length=500)]
_Sha256Value = Annotated[str, Field(pattern=_SHA256_PATTERN)]

AUTONOMOUS_BENCHMARK_VERDICT_POLICY_FILENAME = "verdict_policy.json"
AUTONOMOUS_BENCHMARK_OBJECTIVE_SHA256 = (
    "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
)
AUTONOMOUS_BENCHMARK_PROVENANCE_SHA256 = (
    "2a5aefecae5de53f2a390cefc1ee7bfe86922e41b51298e212c50f05d56e6ae9"
)
AUTONOMOUS_BENCHMARK_SOURCE_REVISION = "f794db0ba0e16e8cd1f028ac623b0486ce86c879"
AUTONOMOUS_BENCHMARK_CORPUS_SHA256 = (
    "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
)
AUTONOMOUS_BENCHMARK_GROUND_TRUTH_SHA256 = (
    "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
)
AUTONOMOUS_BENCHMARK_CASE_BINDING_SET_SHA256 = (
    "65043d8b6cb2bc4eb6cf710b67c8a462542cd0dc0d94d44e7d23630986cb70fe"
)
AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_SHA256 = (
    "1df14052e97a8ceb2cf3ec9fd25637f5f2f3a821818a54382a7c1f241059da8c"
)
AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_FILE_SHA256 = (
    "4c6dd1cfe4370d23afe04057c80a8af7f518594f1375f9975ce0d9f616e0fb0a"
)
# The semantic verifier below is independently complete, so this raw-byte pin is
# an additional custody join rather than the sole policy authority.
AUTONOMOUS_BENCHMARK_VERDICT_POLICY_FILE_SHA256 = (
    "834d8d8234782d89697193ba23817231c180c6a6c1b51d1e111f007bdc9f75b2"
)

_EXPECTED_DENOMINATORS = {
    ModelBenchmarkDimension.ACCESS_CONTROL: 4,
    ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: 4,
    ModelBenchmarkDimension.CROSS_CONTRACT_BUSINESS_LOGIC: 4,
    ModelBenchmarkDimension.EXACT_SOURCE_LOCATION: 2,
    ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION: 4,
    ModelBenchmarkDimension.FALSIFIER_QUALITY: 4,
    ModelBenchmarkDimension.INVARIANT_GENERATION: 4,
    ModelBenchmarkDimension.ORACLE_ASSUMPTIONS: 4,
    ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE: 3,
    ModelBenchmarkDimension.REPORT_QUALITY: 4,
    ModelBenchmarkDimension.SAFE_NEAR_MISS_REJECTION: 4,
    ModelBenchmarkDimension.SIGNATURE_REPLAY: 4,
    ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING: 4,
    ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE: 24,
    ModelBenchmarkDimension.UNSUPPORTED_ASSUMPTION_DISCLOSURE: 4,
    ModelBenchmarkDimension.UPGRADE_STORAGE: 4,
    ModelBenchmarkDimension.VERIFIER_QUALITY: 4,
}
_SAFETY_DIMENSIONS = (
    ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION,
    ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE,
    ModelBenchmarkDimension.SAFE_NEAR_MISS_REJECTION,
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EvidenceSealRequirementState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNEVALUABLE = "UNEVALUABLE"


class EvidenceSealPolicyDisposition(StrEnum):
    STRUCTURALLY_SATISFIED = "STRUCTURALLY_SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    UNEVALUABLE = "UNEVALUABLE"


class EvidenceSealBaselineDisposition(StrEnum):
    OUTPERFORMS_FROZEN_BASELINE_ON_BOUND_CORPUS = "OUTPERFORMS_FROZEN_BASELINE_ON_BOUND_CORPUS"
    DOES_NOT_OUTPERFORM = "DOES_NOT_OUTPERFORM"
    UNEVALUABLE = "UNEVALUABLE"


class EvidenceSealPairedOutcomeRelation(StrEnum):
    """Pure vector relation with no claim that either input is a frozen baseline."""

    EQUAL = "EQUAL"
    INCOMPARABLE = "INCOMPARABLE"
    REGRESSES_OR_MIXED = "REGRESSES_OR_MIXED"
    STRICTLY_DOMINATES = "STRICTLY_DOMINATES"


class EvidenceSealVerdictReason(StrEnum):
    BASELINE_NOT_FROZEN = "BASELINE_NOT_FROZEN"
    BUDGET_AT_OR_ABOVE_CEILING = "BUDGET_AT_OR_ABOVE_CEILING"
    BUDGET_CLOSURE_MISSING = "BUDGET_CLOSURE_MISSING"
    BUDGET_CLOSURE_UNRESOLVED = "BUDGET_CLOSURE_UNRESOLVED"
    CASE_EXECUTION_FAILED = "CASE_EXECUTION_FAILED"
    DIMENSION_FLOOR_NOT_MET = "DIMENSION_FLOOR_NOT_MET"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_TIME_UNBOUND = "EVIDENCE_TIME_UNBOUND"
    EXECUTION_NOT_REAL = "EXECUTION_NOT_REAL"
    LINEAGE_COLLISION = "LINEAGE_COLLISION"
    OVERALL_FLOOR_NOT_MET = "OVERALL_FLOOR_NOT_MET"
    REPLAY_DIVERGED = "REPLAY_DIVERGED"
    REPLAY_IDENTITY_REUSED = "REPLAY_IDENTITY_REUSED"


class EvidenceSealBudgetScope(StrEnum):
    REPORT_USAGE_LOWER_BOUND = "REPORT_USAGE_LOWER_BOUND"
    CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN = (
        "CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN"
    )


class EvidenceSealDimensionFloor(_FrozenModel):
    dimension: ModelBenchmarkDimension
    exact_evaluated: int = Field(ge=1, le=10_000)
    minimum_score_micros: int = Field(ge=0, le=_MICROS)


class EvidenceSealFrozenBaselinePolicy(_FrozenModel):
    status: Literal["NOT_FROZEN"] = "NOT_FROZEN"
    comparison_rule: Literal["PAIRED_CASE_DIMENSION_NON_REGRESSION_ONE_STRICT"] = (
        "PAIRED_CASE_DIMENSION_NON_REGRESSION_ONE_STRICT"
    )
    baseline_projection_sha256: None = None
    baseline_authority_subject_sha256: None = None


class EvidenceSealVerdictPolicy(_FrozenModel):
    """The one source-pinned autonomous verdict policy accepted by this release."""

    schema_version: Literal["1.0"] = "1.0"
    authority_basis: Literal["EVIDENCE_SEALED_REPRODUCIBLE"] = "EVIDENCE_SEALED_REPRODUCIBLE"
    objective_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_source_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_case_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_case_count: Literal[24] = 24
    qualification_policy_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy: QualificationPolicy
    dimension_floors: tuple[EvidenceSealDimensionFloor, ...] = Field(
        min_length=17,
        max_length=17,
    )
    minimum_overall_score_micros: Literal[1_000_000] = 1_000_000
    safety_dimensions: tuple[ModelBenchmarkDimension, ...] = Field(
        min_length=3,
        max_length=3,
    )
    required_execution_evidence: Literal["real"] = "real"
    exact_primary_count: Literal[1] = 1
    minimum_replay_count: Literal[1] = 1
    minimum_distinct_judge_roots: Literal[2] = 2
    require_zero_case_errors: Literal[True] = True
    require_distinct_report_request_and_generation_ids: Literal[True] = True
    require_byte_identical_replay: Literal[True] = True
    maximum_evidence_age_days: Literal[7] = 7
    maximum_campaign_cost_usd_exact: Literal["250"] = "250"
    budget_comparator: Literal["LESS_THAN"] = "LESS_THAN"
    budget_scope: Literal["CANDIDATE_PRIMARY_AND_REPLAY"] = "CANDIDATE_PRIMARY_AND_REPLAY"
    require_closed_ledger_reconciliation: Literal[True] = True
    frozen_baseline: EvidenceSealFrozenBaselinePolicy
    comparison_only: Literal[True] = True
    durable_authority: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "comparison_only",
        "require_zero_case_errors",
        "require_distinct_report_request_and_generation_ids",
        "require_byte_identical_replay",
        "require_closed_ledger_reconciliation",
        mode="before",
    )
    @classmethod
    def true_flags_are_exact(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("autonomous verdict policy required flag must be literal true")
        return value

    @field_validator(
        "durable_authority",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        "source_egress_authorized",
        mode="before",
    )
    @classmethod
    def false_flags_are_exact(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("autonomous verdict policy authority flag must be literal false")
        return value

    @model_validator(mode="after")
    def compiled_policy_and_hash_are_exact(self) -> Self:
        if self.model_dump(mode="json", exclude={"policy_sha256"}) != _compiled_policy_payload():
            raise ValueError("autonomous verdict policy differs from verifier-compiled inputs")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 != expected:
            raise ValueError("autonomous verdict policy hash is inconsistent")
        return self


class EvidenceSealDimensionVerdict(_FrozenModel):
    dimension: ModelBenchmarkDimension
    passed: int = Field(ge=0, le=10_000)
    evaluated: int = Field(ge=1, le=10_000)
    score_micros: int = Field(ge=0, le=_MICROS)
    minimum_score_micros: int = Field(ge=0, le=_MICROS)
    state: EvidenceSealRequirementState

    @model_validator(mode="after")
    def arithmetic_and_state_are_exact(self) -> Self:
        if self.passed > self.evaluated:
            raise ValueError("autonomous verdict dimension passed count exceeds its denominator")
        expected_score = _rounded_score_micros(self.passed, self.evaluated)
        expected_state = (
            EvidenceSealRequirementState.PASS
            if expected_score >= self.minimum_score_micros
            else EvidenceSealRequirementState.FAIL
        )
        if self.score_micros != expected_score or self.state is not expected_state:
            raise ValueError("autonomous verdict dimension arithmetic is inconsistent")
        return self


class EvidenceSealCaseDimensionOutcome(_FrozenModel):
    """One exact Boolean used by the frozen paired baseline comparison rule."""

    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    dimension: ModelBenchmarkDimension
    passed: bool

    @field_validator("passed", mode="before")
    @classmethod
    def pass_flag_is_exact(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("autonomous benchmark case-dimension outcome must be Boolean")
        return value


class EvidenceSealVerdictReportBinding(_FrozenModel):
    run_kind: Literal["PRIMARY", "REPLAY"]
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    decision_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    runner_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    deterministic_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    execution_evidence: Literal["mock", "real", "unverified"]
    request_ids: tuple[_BoundedRequestIdentity, ...] = Field(max_length=10_000)
    request_id_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_ids: tuple[_BoundedRequestIdentity, ...] = Field(max_length=10_000)
    generation_id_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    usage_record_count: int = Field(ge=0, le=10_000)
    case_count: int = Field(ge=1, le=10_000)
    failed_case_count: int = Field(ge=0, le=10_000)
    accounted_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    evidence_started_at: datetime | None
    evidence_ended_at: datetime | None
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evidence_started_at", "evidence_ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("autonomous verdict report timestamps must use UTC")
        return value

    @model_validator(mode="after")
    def interval_and_hash_are_exact(self) -> Self:
        if (
            self.request_ids != tuple(sorted(set(self.request_ids)))
            or self.generation_ids != tuple(sorted(set(self.generation_ids)))
            or self.request_id_set_sha256 != canonical_sha256(list(self.request_ids))
            or self.generation_id_set_sha256 != canonical_sha256(list(self.generation_ids))
            or self.usage_record_count != len(self.request_ids)
            or self.failed_case_count > self.case_count
        ):
            raise ValueError("autonomous verdict report identity inventory is inconsistent")
        if (self.evidence_started_at is None) != (self.evidence_ended_at is None):
            raise ValueError("autonomous verdict report interval must be atomic")
        if (
            self.evidence_started_at is not None
            and self.evidence_ended_at is not None
            and self.evidence_ended_at < self.evidence_started_at
        ):
            raise ValueError("autonomous verdict report ends before it starts")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("autonomous verdict report binding hash is inconsistent")
        return self


class EvidenceSealBudgetProjection(_FrozenModel):
    scope: EvidenceSealBudgetScope
    report_usage_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    campaign_cost_usd_exact: str | None = Field(default=None, pattern=_USD_PATTERN)
    maximum_campaign_cost_usd_exact: Literal["250"] = "250"
    portfolio_sha256s: tuple[_Sha256Value, ...] = Field(max_length=64)
    initial_ledger_snapshot_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    final_ledger_snapshot_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    unresolved_cost_count: int = Field(ge=0, le=10_000)
    state: EvidenceSealRequirementState
    projection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def scope_state_and_hash_are_exact(self) -> Self:
        closed = (
            self.scope is EvidenceSealBudgetScope.CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN
        )
        if closed:
            if (
                len(self.portfolio_sha256s) < 2
                or self.portfolio_sha256s != tuple(sorted(set(self.portfolio_sha256s)))
                or self.campaign_cost_usd_exact is None
                or self.initial_ledger_snapshot_sha256 is None
                or self.final_ledger_snapshot_sha256 is None
            ):
                raise ValueError("closed autonomous benchmark budget projection is incomplete")
            expected_state = (
                EvidenceSealRequirementState.PASS
                if self.unresolved_cost_count == 0
                and Decimal(self.campaign_cost_usd_exact)
                < Decimal(self.maximum_campaign_cost_usd_exact)
                else EvidenceSealRequirementState.FAIL
            )
        else:
            if (
                self.portfolio_sha256s
                or self.campaign_cost_usd_exact is not None
                or self.initial_ledger_snapshot_sha256 is not None
                or self.final_ledger_snapshot_sha256 is not None
                or self.unresolved_cost_count != 0
            ):
                raise ValueError("report-only budget projection cannot claim ledger closure")
            expected_state = EvidenceSealRequirementState.UNEVALUABLE
        if self.state is not expected_state:
            raise ValueError("autonomous benchmark budget state is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"projection_sha256"}))
        if self.projection_sha256 != expected:
            raise ValueError("autonomous benchmark budget projection hash is inconsistent")
        return self


class EvidenceSealVerdictProjection(_FrozenModel):
    """Deterministic comparison result; serialized bytes never grant authority."""

    schema_version: Literal["1.0"] = "1.0"
    authority_basis: Literal["EVIDENCE_SEALED_REPRODUCIBLE"] = "EVIDENCE_SEALED_REPRODUCIBLE"
    policy: EvidenceSealVerdictPolicy
    candidate_exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    candidate_root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    candidate_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    collision_map_sha256: str = Field(pattern=_SHA256_PATTERN)
    report_bindings: tuple[EvidenceSealVerdictReportBinding, ...] = Field(
        min_length=2,
        max_length=64,
    )
    report_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    decision_projection_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    deterministic_decision_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    case_dimension_outcomes: tuple[EvidenceSealCaseDimensionOutcome, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    case_dimension_outcome_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    dimensions: tuple[EvidenceSealDimensionVerdict, ...] = Field(
        min_length=17,
        max_length=17,
    )
    overall_score_micros: int = Field(ge=0, le=_MICROS)
    overall_state: EvidenceSealRequirementState
    case_execution_state: EvidenceSealRequirementState
    execution_evidence_state: EvidenceSealRequirementState
    replay_state: EvidenceSealRequirementState
    lineage_state: EvidenceSealRequirementState
    freshness_state: EvidenceSealRequirementState
    evidence_started_at: datetime | None
    evidence_ended_at: datetime | None
    evaluated_at: datetime | None
    fresh_through: datetime | None
    budget: EvidenceSealBudgetProjection
    policy_disposition: EvidenceSealPolicyDisposition
    baseline_disposition: Literal[EvidenceSealBaselineDisposition.UNEVALUABLE] = (
        EvidenceSealBaselineDisposition.UNEVALUABLE
    )
    reason_codes: tuple[EvidenceSealVerdictReason, ...] = Field(max_length=32)
    comparison_only: Literal[True] = True
    durable_authority: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    verdict_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("evidence_started_at", "evidence_ended_at", "evaluated_at", "fresh_through")
    @classmethod
    def verdict_timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("autonomous benchmark verdict timestamps must use UTC")
        return value

    @field_validator("comparison_only", mode="before")
    @classmethod
    def comparison_flag_is_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("autonomous benchmark verdict must remain comparison-only")
        return value

    @field_validator(
        "durable_authority",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        "source_egress_authorized",
        mode="before",
    )
    @classmethod
    def verdict_authority_flags_are_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("autonomous benchmark verdict authority flag must be literal false")
        return value

    @model_validator(mode="after")
    def inventory_states_reasons_and_hash_are_exact(self) -> Self:
        expected_order = tuple(
            sorted(
                self.report_bindings,
                key=lambda item: (
                    0 if item.run_kind == "PRIMARY" else 1,
                    item.benchmark_report_sha256,
                ),
            )
        )
        if self.report_bindings != expected_order:
            raise ValueError("autonomous benchmark verdict reports are not canonically ordered")
        if (
            sum(item.run_kind == "PRIMARY" for item in self.report_bindings) != 1
            or sum(item.run_kind == "REPLAY" for item in self.report_bindings) < 1
            or len({item.benchmark_report_sha256 for item in self.report_bindings})
            != len(self.report_bindings)
        ):
            raise ValueError("autonomous benchmark verdict requires distinct primary and replay")
        expected_report_set = canonical_sha256(
            [item.model_dump(mode="json") for item in self.report_bindings]
        )
        if self.report_binding_set_sha256 != expected_report_set:
            raise ValueError("autonomous benchmark report-binding set hash is inconsistent")
        all_request_ids = [
            request_id for item in self.report_bindings for request_id in item.request_ids
        ]
        all_generation_ids = [
            generation_id for item in self.report_bindings for generation_id in item.generation_ids
        ]
        expected_replay_state = (
            EvidenceSealRequirementState.PASS
            if len(all_request_ids) == len(set(all_request_ids))
            and len(all_generation_ids) == len(set(all_generation_ids))
            and {item.deterministic_output_sha256 for item in self.report_bindings}
            == {self.deterministic_decision_output_sha256}
            else EvidenceSealRequirementState.FAIL
        )
        if self.replay_state is not expected_replay_state:
            raise ValueError("autonomous benchmark replay identity state is inconsistent")
        expected_case_state = (
            EvidenceSealRequirementState.PASS
            if not any(item.failed_case_count for item in self.report_bindings)
            else EvidenceSealRequirementState.FAIL
        )
        if self.case_execution_state is not expected_case_state:
            raise ValueError("autonomous benchmark case execution state is inconsistent")
        expected_execution_state = (
            EvidenceSealRequirementState.PASS
            if all(item.execution_evidence == "real" for item in self.report_bindings)
            else EvidenceSealRequirementState.UNEVALUABLE
        )
        if self.execution_evidence_state is not expected_execution_state:
            raise ValueError("autonomous benchmark execution-evidence state is inconsistent")
        expected_dimensions = tuple(sorted(ModelBenchmarkDimension, key=lambda item: item.value))
        if tuple(item.dimension for item in self.dimensions) != expected_dimensions:
            raise ValueError("autonomous benchmark verdict must retain every dimension")
        expected_outcome_order = tuple(
            sorted(
                self.case_dimension_outcomes,
                key=lambda item: (item.case_id, item.dimension.value),
            )
        )
        outcome_keys = tuple(
            (item.case_id, item.dimension) for item in self.case_dimension_outcomes
        )
        if (
            self.case_dimension_outcomes != expected_outcome_order
            or len(outcome_keys) != len(set(outcome_keys))
            or self.case_dimension_outcome_set_sha256
            != canonical_sha256(
                [item.model_dump(mode="json") for item in self.case_dimension_outcomes]
            )
        ):
            raise ValueError("autonomous benchmark case-dimension inventory is inconsistent")
        observed_counts = {
            dimension: (
                sum(
                    item.passed
                    for item in self.case_dimension_outcomes
                    if item.dimension is dimension
                ),
                sum(item.dimension is dimension for item in self.case_dimension_outcomes),
            )
            for dimension in ModelBenchmarkDimension
        }
        if any(
            observed_counts[item.dimension] != (item.passed, item.evaluated)
            for item in self.dimensions
        ):
            raise ValueError("autonomous benchmark dimensions differ from paired case outcomes")
        floors = {item.dimension: item for item in self.policy.dimension_floors}
        if any(
            item.evaluated != floors[item.dimension].exact_evaluated
            or item.minimum_score_micros != floors[item.dimension].minimum_score_micros
            for item in self.dimensions
        ):
            raise ValueError("autonomous benchmark verdict differs from its frozen floors")
        if self.overall_score_micros != _overall_score_micros(self.dimensions):
            raise ValueError("autonomous benchmark overall score is inconsistent")
        expected_overall_state = (
            EvidenceSealRequirementState.PASS
            if self.overall_score_micros >= self.policy.minimum_overall_score_micros
            else EvidenceSealRequirementState.FAIL
        )
        if self.overall_state is not expected_overall_state:
            raise ValueError("autonomous benchmark overall state is inconsistent")
        interval_values = (
            self.evidence_started_at,
            self.evidence_ended_at,
            self.fresh_through,
        )
        if any(value is None for value in interval_values) and not all(
            value is None for value in interval_values
        ):
            raise ValueError("autonomous benchmark evidence interval must be atomic")
        if self.evaluated_at is not None and any(value is None for value in interval_values):
            raise ValueError("autonomous benchmark evaluation time requires an evidence interval")
        if all(value is not None for value in interval_values):
            started, ended, fresh_through = interval_values
            assert started is not None
            assert ended is not None
            assert fresh_through is not None
            if not started <= ended <= fresh_through:
                raise ValueError("autonomous benchmark evidence interval is inconsistent")
        if self.evaluated_at is None:
            expected_freshness = EvidenceSealRequirementState.UNEVALUABLE
        else:
            started, ended, fresh_through = interval_values
            assert started is not None
            assert ended is not None
            assert fresh_through is not None
            evaluated = self.evaluated_at
            expected_freshness = (
                EvidenceSealRequirementState.PASS
                if self.policy.qualification_policy.created_at
                <= started
                <= ended
                <= evaluated
                <= fresh_through
                else EvidenceSealRequirementState.FAIL
            )
        if self.freshness_state is not expected_freshness:
            raise ValueError("autonomous benchmark freshness state is inconsistent")
        component_states = (
            *(item.state for item in self.dimensions),
            self.overall_state,
            self.case_execution_state,
            self.execution_evidence_state,
            self.replay_state,
            self.lineage_state,
            self.freshness_state,
            self.budget.state,
        )
        expected_disposition = _policy_disposition(component_states)
        if self.policy_disposition is not expected_disposition:
            raise ValueError("autonomous benchmark policy disposition is inconsistent")
        expected_reasons = _verdict_reasons(self)
        if self.reason_codes != expected_reasons:
            raise ValueError("autonomous benchmark verdict reason inventory is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"verdict_sha256"}))
        if self.verdict_sha256 != expected:
            raise ValueError("autonomous benchmark verdict hash is inconsistent")
        return self


def load_evidence_seal_verdict_policy(path: Path) -> EvidenceSealVerdictPolicy:
    """Load the sole raw-byte-pinned policy artifact accepted by this release."""

    observation = read_json_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        max_bytes=_MAX_POLICY_BYTES,
    )
    if observation.binding.sha256 != AUTONOMOUS_BENCHMARK_VERDICT_POLICY_FILE_SHA256:
        raise ValueError("autonomous verdict policy file differs from its compiled byte pin")
    try:
        return EvidenceSealVerdictPolicy.model_validate_json(observation.content, strict=True)
    except ValueError as exc:
        raise ValueError("autonomous verdict policy artifact is invalid") from exc


def compiled_evidence_seal_verdict_policy() -> EvidenceSealVerdictPolicy:
    """Return a fresh validated copy of the verifier-compiled policy."""

    payload = _compiled_policy_payload()
    return EvidenceSealVerdictPolicy.model_validate_json(
        json.dumps(
            {**payload, "policy_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
        strict=True,
    )


def compare_evidence_seal_case_dimension_outcomes(
    *,
    candidate: tuple[EvidenceSealCaseDimensionOutcome, ...],
    baseline: tuple[EvidenceSealCaseDimensionOutcome, ...],
) -> EvidenceSealPairedOutcomeRelation:
    """Compare two vectors without claiming either is a pinned baseline."""

    bounded_candidate = tuple(islice(iter(candidate), 10_001))
    bounded_baseline = tuple(islice(iter(baseline), 10_001))
    if len(bounded_candidate) > 10_000 or len(bounded_baseline) > 10_000:
        raise ValueError("autonomous benchmark paired outcome inventory exceeds its bound")
    candidate_values = _case_dimension_values(bounded_candidate, label="candidate")
    baseline_values = _case_dimension_values(bounded_baseline, label="baseline")
    if candidate_values.keys() != baseline_values.keys():
        return EvidenceSealPairedOutcomeRelation.INCOMPARABLE
    if any(not candidate_values[key] and baseline_values[key] for key in candidate_values):
        return EvidenceSealPairedOutcomeRelation.REGRESSES_OR_MIXED
    if any(candidate_values[key] and not baseline_values[key] for key in candidate_values):
        return EvidenceSealPairedOutcomeRelation.STRICTLY_DOMINATES
    return EvidenceSealPairedOutcomeRelation.EQUAL


def _compiled_policy_payload() -> dict[str, object]:
    qualification_policy = {
        "schema_version": "1.0",
        "created_at": "2026-08-17T04:43:40Z",
        "thresholds": [
            {
                "dimension": dimension.value,
                "minimum_cases": _EXPECTED_DENOMINATORS[dimension],
                "minimum_score": 1.0,
            }
            for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
        ],
        "tier_a_minimum_overall_score": 1.0,
        "maximum_validity_days": 30,
        "maximum_benchmark_evidence_age_days": 7,
        "require_real_execution": True,
        "require_certification_routing": True,
        "policy_sha256": AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_SHA256,
    }
    return {
        "schema_version": "1.0",
        "authority_basis": "EVIDENCE_SEALED_REPRODUCIBLE",
        "objective_sha256": AUTONOMOUS_BENCHMARK_OBJECTIVE_SHA256,
        "ground_truth_provenance_sha256": AUTONOMOUS_BENCHMARK_PROVENANCE_SHA256,
        "ground_truth_source_revision": AUTONOMOUS_BENCHMARK_SOURCE_REVISION,
        "benchmark_corpus_sha256": AUTONOMOUS_BENCHMARK_CORPUS_SHA256,
        "benchmark_ground_truth_sha256": AUTONOMOUS_BENCHMARK_GROUND_TRUTH_SHA256,
        "ground_truth_case_binding_set_sha256": (AUTONOMOUS_BENCHMARK_CASE_BINDING_SET_SHA256),
        "benchmark_case_count": 24,
        "qualification_policy_file_sha256": (AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_FILE_SHA256),
        "qualification_policy": qualification_policy,
        "dimension_floors": [
            {
                "dimension": dimension.value,
                "exact_evaluated": _EXPECTED_DENOMINATORS[dimension],
                "minimum_score_micros": _MICROS,
            }
            for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
        ],
        "minimum_overall_score_micros": _MICROS,
        "safety_dimensions": [item.value for item in _SAFETY_DIMENSIONS],
        "required_execution_evidence": "real",
        "exact_primary_count": 1,
        "minimum_replay_count": 1,
        "minimum_distinct_judge_roots": 2,
        "require_zero_case_errors": True,
        "require_distinct_report_request_and_generation_ids": True,
        "require_byte_identical_replay": True,
        "maximum_evidence_age_days": 7,
        "maximum_campaign_cost_usd_exact": "250",
        "budget_comparator": "LESS_THAN",
        "budget_scope": "CANDIDATE_PRIMARY_AND_REPLAY",
        "require_closed_ledger_reconciliation": True,
        "frozen_baseline": {
            "status": "NOT_FROZEN",
            "comparison_rule": "PAIRED_CASE_DIMENSION_NON_REGRESSION_ONE_STRICT",
            "baseline_projection_sha256": None,
            "baseline_authority_subject_sha256": None,
        },
        "comparison_only": True,
        "durable_authority": False,
        "authority_issuance_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "provider_access_authorized": False,
        "source_egress_authorized": False,
    }


def _case_dimension_values(
    outcomes: tuple[EvidenceSealCaseDimensionOutcome, ...],
    *,
    label: str,
) -> dict[tuple[str, ModelBenchmarkDimension], bool]:
    if not outcomes:
        raise ValueError(f"autonomous benchmark {label} outcome inventory is empty")
    values = {(item.case_id, item.dimension): item.passed for item in outcomes}
    if len(values) != len(outcomes):
        raise ValueError(f"autonomous benchmark {label} outcome inventory repeats a key")
    return values


def _rounded_score_micros(passed: int, evaluated: int) -> int:
    with localcontext(_exact_decimal_context()):
        value = Decimal(str(round(passed / evaluated, 6))) * Decimal(_MICROS)
    if value != value.to_integral_value():
        raise ValueError("benchmark score does not project to canonical micros")
    return int(value)


def _overall_score_micros(dimensions: tuple[EvidenceSealDimensionVerdict, ...]) -> int:
    score = round(
        sum(item.score_micros / _MICROS for item in dimensions) / len(dimensions),
        6,
    )
    with localcontext(_exact_decimal_context()):
        value = Decimal(str(score)) * Decimal(_MICROS)
    if value != value.to_integral_value():
        raise ValueError("benchmark overall score does not project to canonical micros")
    return int(value)


def _policy_disposition(
    states: tuple[EvidenceSealRequirementState, ...],
) -> EvidenceSealPolicyDisposition:
    if EvidenceSealRequirementState.FAIL in states:
        return EvidenceSealPolicyDisposition.NOT_SATISFIED
    if EvidenceSealRequirementState.UNEVALUABLE in states:
        return EvidenceSealPolicyDisposition.UNEVALUABLE
    return EvidenceSealPolicyDisposition.STRUCTURALLY_SATISFIED


def _verdict_reasons(
    verdict: EvidenceSealVerdictProjection,
) -> tuple[EvidenceSealVerdictReason, ...]:
    reasons: set[EvidenceSealVerdictReason] = {EvidenceSealVerdictReason.BASELINE_NOT_FROZEN}
    if any(item.state is EvidenceSealRequirementState.FAIL for item in verdict.dimensions):
        reasons.add(EvidenceSealVerdictReason.DIMENSION_FLOOR_NOT_MET)
    if verdict.overall_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.OVERALL_FLOOR_NOT_MET)
    if verdict.case_execution_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.CASE_EXECUTION_FAILED)
    if verdict.execution_evidence_state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.EXECUTION_NOT_REAL)
    if verdict.replay_state is EvidenceSealRequirementState.FAIL and any(
        item.deterministic_output_sha256 != verdict.deterministic_decision_output_sha256
        for item in verdict.report_bindings
    ):
        reasons.add(EvidenceSealVerdictReason.REPLAY_DIVERGED)
    if verdict.lineage_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.LINEAGE_COLLISION)
    if verdict.freshness_state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.EVIDENCE_TIME_UNBOUND)
    elif verdict.freshness_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.EVIDENCE_STALE)
    if verdict.budget.state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.BUDGET_CLOSURE_MISSING)
    elif verdict.budget.state is EvidenceSealRequirementState.FAIL:
        if verdict.budget.unresolved_cost_count:
            reasons.add(EvidenceSealVerdictReason.BUDGET_CLOSURE_UNRESOLVED)
        if verdict.budget.campaign_cost_usd_exact is not None and Decimal(
            verdict.budget.campaign_cost_usd_exact
        ) >= Decimal(verdict.budget.maximum_campaign_cost_usd_exact):
            reasons.add(EvidenceSealVerdictReason.BUDGET_AT_OR_ABOVE_CEILING)
    request_ids = [value for item in verdict.report_bindings for value in item.request_ids]
    generation_ids = [value for item in verdict.report_bindings for value in item.generation_ids]
    if len(request_ids) != len(set(request_ids)) or len(generation_ids) != len(set(generation_ids)):
        reasons.add(EvidenceSealVerdictReason.REPLAY_IDENTITY_REUSED)
    return tuple(sorted(reasons, key=lambda item: item.value))


def canonical_usd_sum(values: tuple[str, ...]) -> str:
    """Sum bounded exact USD text without inheriting ambient Decimal precision."""

    try:
        with localcontext(_exact_decimal_context()):
            total = sum((Decimal(item) for item in values), Decimal(0))
    except InvalidOperation as exc:
        raise ValueError("autonomous benchmark cost evidence is invalid") from exc
    rendered = format(total, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"
