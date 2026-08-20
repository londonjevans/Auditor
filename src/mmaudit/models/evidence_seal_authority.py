"""Non-authorizing cross-lineage benchmark and transparency-prefix evidence.

This module validates deterministic comparison artifacts only.  It deliberately
does not issue runtime authority: a future issuer must require authenticated REAL
cross-lineage execution and an independently verified external-log receipt.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable, Sequence
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
from itertools import islice, pairwise
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import mmaudit.benchmark.cross_lineage_adjudication as _adjudication_module
import mmaudit.models.authenticated_runner as _authenticated_runner_module
import mmaudit.orchestration.manifest as _manifest_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationReport,
)
from mmaudit.benchmark.model_portfolio import ModelBenchmarkPortfolio
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    verify_model_benchmark_report_structure,
)
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerEvidence,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
    VerifiedCrossLineageRunnerProjection,
    require_verified_cross_lineage_runner_custody,
)
from mmaudit.models.autonomous_benchmark_verdict import (
    AUTONOMOUS_BENCHMARK_CASE_BINDING_SET_SHA256,
    AUTONOMOUS_BENCHMARK_CORPUS_SHA256,
    AUTONOMOUS_BENCHMARK_GROUND_TRUTH_SHA256,
    AUTONOMOUS_BENCHMARK_OBJECTIVE_SHA256,
    AUTONOMOUS_BENCHMARK_PROVENANCE_SHA256,
    AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_SHA256,
    AUTONOMOUS_BENCHMARK_SOURCE_REVISION,
    EvidenceSealBaselineDisposition,
    EvidenceSealBudgetProjection,
    EvidenceSealBudgetScope,
    EvidenceSealCaseDimensionOutcome,
    EvidenceSealDimensionVerdict,
    EvidenceSealPolicyDisposition,
    EvidenceSealRequirementState,
    EvidenceSealVerdictPolicy,
    EvidenceSealVerdictProjection,
    EvidenceSealVerdictReason,
    EvidenceSealVerdictReportBinding,
    canonical_usd_sum,
    compiled_evidence_seal_verdict_policy,
)
from mmaudit.models.candidate_benchmark import CandidateCostLedgerSnapshot
from mmaudit.models.ground_truth_authority import (
    GroundTruthOriginKind,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.orchestration.manifest import canonical_sha256

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_MODEL_PATTERN = r"^[A-Za-z0-9._-]+/[A-Za-z0-9._:/-]+$"
_SOURCE_REVISION_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_VERDICT_USD_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$"
_MAX_VERDICT_USD_TEXT = 49
_MAX_PARTICIPANTS = 64
_MAX_CASES = 10_000
_MAX_LOG_LEAVES = 10_000
_EMPTY_TREE_ROOT_SHA256 = hashlib.sha256(b"").hexdigest()
_Sha256Value = Annotated[str, Field(pattern=_SHA256_PATTERN)]


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


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EvidenceSealLineageRole(StrEnum):
    CANDIDATE = "CANDIDATE"
    JUDGE = "JUDGE"


class EvidenceSealRunKind(StrEnum):
    PRIMARY = "PRIMARY"
    REPLAY = "REPLAY"


class EvidenceSealLineageBinding(_FrozenModel):
    """One exact candidate or judge identity and its independently assigned root."""

    exact_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    role: EvidenceSealLineageRole
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_hash_is_exact(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("evidence-seal lineage binding hash is inconsistent")
        return self


class EvidenceSealLineagePair(_FrozenModel):
    """Explicit same-root predicate for one candidate/judge pair."""

    candidate_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    candidate_root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    judge_model_id: str = Field(pattern=_MODEL_PATTERN, max_length=300)
    judge_root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    same_root: bool
    pair_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def predicate_and_hash_are_exact(self) -> Self:
        if self.same_root is not (self.candidate_root_lineage == self.judge_root_lineage):
            raise ValueError("evidence-seal same-root predicate is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"pair_sha256"}))
        if self.pair_sha256 != expected:
            raise ValueError("evidence-seal lineage-pair hash is inconsistent")
        return self


class EvidenceSealCollisionMap(_FrozenModel):
    """Exact candidate-by-judge lineage collision inventory."""

    schema_version: Literal["1.0"] = "1.0"
    candidate: EvidenceSealLineageBinding
    judges: tuple[EvidenceSealLineageBinding, ...] = Field(
        min_length=2,
        max_length=_MAX_PARTICIPANTS,
    )
    pairs: tuple[EvidenceSealLineagePair, ...] = Field(
        min_length=2,
        max_length=_MAX_PARTICIPANTS,
    )
    collision_map_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def exact_inventory_and_hash_are_consistent(self) -> Self:
        if self.candidate.role is not EvidenceSealLineageRole.CANDIDATE:
            raise ValueError("evidence-seal collision map requires one candidate")
        judge_keys = tuple((item.exact_model_id, item.root_lineage) for item in self.judges)
        if (
            any(item.role is not EvidenceSealLineageRole.JUDGE for item in self.judges)
            or judge_keys != tuple(sorted(set(judge_keys)))
            or self.candidate.exact_model_id in {item.exact_model_id for item in self.judges}
        ):
            raise ValueError("evidence-seal judges must be distinct, sorted judge identities")
        expected_pairs = tuple(_lineage_pair(self.candidate, judge) for judge in self.judges)
        if self.pairs != expected_pairs:
            raise ValueError("evidence-seal collision map is not the exact candidate-by-judge map")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"collision_map_sha256"}))
        if self.collision_map_sha256 != expected:
            raise ValueError("evidence-seal collision-map hash is inconsistent")
        return self


class EvidenceSealDecisionProjection(_FrozenModel):
    """Deterministic scoring output from one candidate benchmark execution."""

    schema_version: Literal["1.0"] = "1.0"
    run_kind: EvidenceSealRunKind
    candidate: EvidenceSealLineageBinding
    runner: EvidenceSealLineageBinding
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    case_outcome_sha256s: tuple[_Sha256Value, ...] = Field(
        min_length=1,
        max_length=_MAX_CASES,
    )
    case_dimension_outcome_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    dimension_score_sha256s: tuple[_Sha256Value, ...] = Field(min_length=1, max_length=100)
    overall_score_micros: int = Field(ge=0, le=1_000_000)
    execution_evidence: Literal["mock", "real", "unverified"]
    deterministic_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False

    @field_validator(
        "model_qualification_authorized",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def durable_flags_are_false(cls, value: object) -> object:
        return _literal_false(value, label="decision projection authority")

    @model_validator(mode="after")
    def exact_output_and_hash_are_consistent(self) -> Self:
        if (
            self.candidate.role is not EvidenceSealLineageRole.CANDIDATE
            or self.runner.role is not EvidenceSealLineageRole.JUDGE
        ):
            raise ValueError("evidence-seal projection roles are inconsistent")
        expected_output = _decision_output_sha256(
            candidate=self.candidate,
            corpus_sha256=self.benchmark_corpus_sha256,
            ground_truth_sha256=self.benchmark_ground_truth_sha256,
            case_outcome_sha256s=self.case_outcome_sha256s,
            case_dimension_outcome_set_sha256=self.case_dimension_outcome_set_sha256,
            dimension_score_sha256s=self.dimension_score_sha256s,
            overall_score_micros=self.overall_score_micros,
            execution_evidence=self.execution_evidence,
        )
        if self.deterministic_output_sha256 != expected_output:
            raise ValueError("evidence-seal deterministic decision output is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"projection_sha256"}))
        if self.projection_sha256 != expected:
            raise ValueError("evidence-seal decision projection hash is inconsistent")
        return self


class EvidenceAuthoritySubject(_FrozenModel):
    """Pre-publication subject whose digest becomes the transparency-log leaf."""

    schema_version: Literal["2.0"] = "2.0"
    authority_basis: Literal["EVIDENCE_SEALED_REPRODUCIBLE"] = "EVIDENCE_SEALED_REPRODUCIBLE"
    objective_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_case_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    collision_map: EvidenceSealCollisionMap
    decision_projections: tuple[EvidenceSealDecisionProjection, ...] = Field(
        min_length=2,
        max_length=_MAX_PARTICIPANTS,
    )
    decision_projection_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    deterministic_decision_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    verdict_projection: EvidenceSealVerdictProjection
    authority_subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_egress_authorized: Literal[False] = False
    benchmark_scoring_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False

    @field_validator(
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        mode="before",
    )
    @classmethod
    def durable_flags_are_false(cls, value: object) -> object:
        return _literal_false(value, label="authority subject")

    @model_validator(mode="after")
    def replay_lineage_and_hashes_are_exact(self) -> Self:
        expected_order = tuple(
            sorted(
                self.decision_projections,
                key=lambda item: (
                    0 if item.run_kind is EvidenceSealRunKind.PRIMARY else 1,
                    item.benchmark_report_sha256,
                ),
            )
        )
        if self.decision_projections != expected_order:
            raise ValueError("evidence-seal decision projections must be canonically ordered")
        primary = [
            item
            for item in self.decision_projections
            if item.run_kind is EvidenceSealRunKind.PRIMARY
        ]
        replay = [
            item
            for item in self.decision_projections
            if item.run_kind is EvidenceSealRunKind.REPLAY
        ]
        if len(primary) != 1 or not replay:
            raise ValueError(
                "evidence-seal authority requires one primary and an independent replay"
            )
        if len({item.benchmark_report_sha256 for item in self.decision_projections}) != len(
            self.decision_projections
        ):
            raise ValueError("evidence-seal replay cannot reuse benchmark report evidence")
        if len({item.runner.root_lineage for item in self.decision_projections}) != len(
            self.decision_projections
        ):
            raise ValueError("evidence-seal runners require distinct root lineages")
        expected_judges = tuple(
            (item.exact_model_id, item.root_lineage) for item in self.collision_map.judges
        )
        observed_judges = tuple(
            sorted(
                (item.runner.exact_model_id, item.runner.root_lineage)
                for item in self.decision_projections
            )
        )
        if observed_judges != expected_judges:
            raise ValueError("evidence-seal projections do not exactly cover the judge inventory")
        if any(item.same_root for item in self.collision_map.pairs):
            raise ValueError("same-root judgment voids evidence-sealed authority")
        candidate = self.collision_map.candidate
        if any(
            item.candidate != candidate
            or item.benchmark_corpus_sha256 != self.benchmark_corpus_sha256
            or item.benchmark_ground_truth_sha256 != self.benchmark_ground_truth_sha256
            or item.ground_truth_provenance_sha256 != self.ground_truth_provenance_sha256
            for item in self.decision_projections
        ):
            raise ValueError("evidence-seal decision projections differ from their frozen subject")
        outputs = {item.deterministic_output_sha256 for item in self.decision_projections}
        if outputs != {self.deterministic_decision_output_sha256}:
            raise ValueError("independent evidence-seal replay output is not byte-identical")
        expected_set = canonical_sha256(
            [item.model_dump(mode="json") for item in self.decision_projections]
        )
        if self.decision_projection_set_sha256 != expected_set:
            raise ValueError("evidence-seal decision-projection set hash is inconsistent")
        verdict = self.verdict_projection
        expected_dimension_hashes = tuple(
            canonical_sha256(
                {
                    "dimension": item.dimension.value,
                    "passed": item.passed,
                    "evaluated": item.evaluated,
                    "score": item.score_micros / 1_000_000,
                }
            )
            for item in verdict.dimensions
        )
        if (
            verdict.policy.objective_sha256 != self.objective_sha256
            or verdict.policy.ground_truth_provenance_sha256 != self.ground_truth_provenance_sha256
            or verdict.policy.ground_truth_source_revision != self.ground_truth_source_revision
            or verdict.policy.benchmark_corpus_sha256 != self.benchmark_corpus_sha256
            or verdict.policy.benchmark_ground_truth_sha256 != self.benchmark_ground_truth_sha256
            or verdict.policy.ground_truth_case_binding_set_sha256
            != self.ground_truth_case_binding_set_sha256
            or verdict.candidate_exact_model_id != candidate.exact_model_id
            or verdict.candidate_root_lineage != candidate.root_lineage
            or verdict.candidate_binding_sha256 != candidate.binding_sha256
            or verdict.collision_map_sha256 != self.collision_map.collision_map_sha256
            or verdict.decision_projection_set_sha256 != self.decision_projection_set_sha256
            or verdict.deterministic_decision_output_sha256
            != self.deterministic_decision_output_sha256
            or {
                (
                    item.benchmark_report_sha256,
                    item.decision_projection_sha256,
                    item.run_kind,
                    item.runner_binding_sha256,
                    item.deterministic_output_sha256,
                    item.execution_evidence,
                )
                for item in verdict.report_bindings
            }
            != {
                (
                    item.benchmark_report_sha256,
                    item.projection_sha256,
                    item.run_kind.value,
                    item.runner.binding_sha256,
                    item.deterministic_output_sha256,
                    item.execution_evidence,
                )
                for item in self.decision_projections
            }
            or any(
                item.case_dimension_outcome_set_sha256 != verdict.case_dimension_outcome_set_sha256
                or item.dimension_score_sha256s != expected_dimension_hashes
                or item.overall_score_micros != verdict.overall_score_micros
                for item in self.decision_projections
            )
            or verdict.lineage_state
            is not (
                EvidenceSealRequirementState.FAIL
                if any(item.same_root for item in self.collision_map.pairs)
                else EvidenceSealRequirementState.PASS
            )
        ):
            raise ValueError("evidence-seal verdict differs from its authority subject")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"authority_subject_sha256"})
        )
        if self.authority_subject_sha256 != expected:
            raise ValueError("evidence-seal authority-subject hash is inconsistent")
        return self


class EvidenceTransparencyCheckpoint(_FrozenModel):
    """One append-only log checkpoint, still non-authorizing when serialized."""

    schema_version: Literal["1.0"] = "1.0"
    log_id_sha256: str = Field(pattern=_SHA256_PATTERN)
    tree_size: int = Field(ge=1, le=_MAX_LOG_LEAVES)
    tree_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_checkpoint_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    checkpoint_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def checkpoint_hash_is_exact(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"checkpoint_sha256"}))
        if self.checkpoint_sha256 != expected:
            raise ValueError("evidence transparency checkpoint hash is inconsistent")
        return self


class EvidenceTransparencyPrefixProof(_FrozenModel):
    """Bounded full-prefix proof of inclusion and append-only extension."""

    schema_version: Literal["1.0"] = "1.0"
    previous_checkpoint: EvidenceTransparencyCheckpoint | None
    checkpoint: EvidenceTransparencyCheckpoint
    authority_subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    subject_leaf_index: int = Field(ge=0, lt=_MAX_LOG_LEAVES)
    subject_leaf_sha256: str = Field(pattern=_SHA256_PATTERN)
    leaf_sha256s: tuple[str, ...] = Field(min_length=1, max_length=_MAX_LOG_LEAVES)
    prefix_proof_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def inclusion_prefix_and_hash_are_exact(self) -> Self:
        if self.checkpoint.tree_size != len(self.leaf_sha256s):
            raise ValueError("evidence transparency proof has a different tree size")
        if len(set(self.leaf_sha256s)) != len(self.leaf_sha256s):
            raise ValueError("evidence transparency proof reuses a log leaf")
        if self.subject_leaf_index >= len(self.leaf_sha256s):
            raise ValueError("evidence transparency subject index is outside the tree")
        expected_leaf = _subject_leaf_sha256(self.authority_subject_sha256)
        if (
            self.subject_leaf_sha256 != expected_leaf
            or self.leaf_sha256s[self.subject_leaf_index] != expected_leaf
        ):
            raise ValueError("evidence transparency subject inclusion is inconsistent")
        if _tree_root_sha256(self.leaf_sha256s) != self.checkpoint.tree_root_sha256:
            raise ValueError("evidence transparency tree root is inconsistent")
        previous_size = 0
        if self.previous_checkpoint is None:
            if self.checkpoint.previous_checkpoint_sha256 is not None:
                raise ValueError("initial evidence checkpoint cannot name a predecessor")
        else:
            previous = self.previous_checkpoint
            previous_size = previous.tree_size
            if (
                previous.log_id_sha256 != self.checkpoint.log_id_sha256
                or previous.tree_size >= self.checkpoint.tree_size
                or self.checkpoint.previous_checkpoint_sha256 != previous.checkpoint_sha256
                or _tree_root_sha256(self.leaf_sha256s[:previous_size]) != previous.tree_root_sha256
            ):
                raise ValueError("evidence transparency log is not an exact append-only extension")
        if self.subject_leaf_index < previous_size:
            raise ValueError(
                "evidence transparency subject was not appended after the prior checkpoint"
            )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"prefix_proof_sha256"}))
        if self.prefix_proof_sha256 != expected:
            raise ValueError("evidence transparency prefix-proof hash is inconsistent")
        return self


class EvidenceSealedAuthorityEvidence(_FrozenModel):
    """Durable comparison evidence; only its paired opaque capability authorizes use."""

    schema_version: Literal["2.0"] = "2.0"
    authority_basis: Literal["EVIDENCE_SEALED_REPRODUCIBLE"] = "EVIDENCE_SEALED_REPRODUCIBLE"
    subject: EvidenceAuthoritySubject
    transparency_proof: EvidenceTransparencyPrefixProof
    authority_sha256: str = Field(pattern=_SHA256_PATTERN)
    external_comparison_required: Literal[True] = True
    durable_authority: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    benchmark_scoring_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False

    @field_validator(
        "durable_authority",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        mode="before",
    )
    @classmethod
    def durable_flags_are_false(cls, value: object) -> object:
        return _literal_false(value, label="durable evidence-sealed authority")

    @field_validator("external_comparison_required", mode="before")
    @classmethod
    def external_comparison_is_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("evidence-sealed authority requires external comparison")
        return value

    @model_validator(mode="after")
    def subject_proof_and_hash_are_exact(self) -> Self:
        if (
            self.transparency_proof.authority_subject_sha256
            != self.subject.authority_subject_sha256
        ):
            raise ValueError("evidence-sealed authority proof belongs to another subject")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"authority_sha256"}))
        if self.authority_sha256 != expected:
            raise ValueError("evidence-sealed authority hash is inconsistent")
        return self


def build_evidence_seal_lineage_binding(
    *,
    exact_model_id: str,
    root_lineage: str,
    role: EvidenceSealLineageRole,
) -> EvidenceSealLineageBinding:
    payload = {
        "exact_model_id": exact_model_id,
        "root_lineage": root_lineage,
        "role": role.value,
    }
    return _model_from_json_payload(
        EvidenceSealLineageBinding,
        {**payload, "binding_sha256": canonical_sha256(payload)},
    )


def build_evidence_seal_collision_map(
    *,
    candidate: EvidenceSealLineageBinding,
    judges: Sequence[EvidenceSealLineageBinding],
) -> EvidenceSealCollisionMap:
    candidate = _exact_model(candidate, EvidenceSealLineageBinding, label="candidate lineage")
    bounded_judges = _bounded_items(
        judges,
        maximum=_MAX_PARTICIPANTS,
        label="judge lineage inventory",
    )
    exact_judges = tuple(
        _exact_model(item, EvidenceSealLineageBinding, label="judge lineage")
        for item in bounded_judges
    )
    payload = {
        "schema_version": "1.0",
        "candidate": candidate.model_dump(mode="json"),
        "judges": [item.model_dump(mode="json") for item in exact_judges],
        "pairs": [_lineage_pair(candidate, item).model_dump(mode="json") for item in exact_judges],
    }
    return _model_from_json_payload(
        EvidenceSealCollisionMap,
        {**payload, "collision_map_sha256": canonical_sha256(payload)},
    )


def _build_evidence_seal_decision_projection(
    *,
    suite: ModelBenchmarkSuite,
    report: ModelBenchmarkReport,
    candidate: EvidenceSealLineageBinding,
    runner: EvidenceSealLineageBinding,
    run_kind: EvidenceSealRunKind,
    ground_truth_projection: VerifiedFrozenGroundTruthProjection,
    authenticated_rootless_candidate: bool,
) -> EvidenceSealDecisionProjection:
    suite = _exact_model(suite, ModelBenchmarkSuite, label="benchmark suite")
    report = _exact_model(report, ModelBenchmarkReport, label="benchmark report")
    candidate = _exact_model(candidate, EvidenceSealLineageBinding, label="candidate lineage")
    runner = _exact_model(runner, EvidenceSealLineageBinding, label="runner lineage")
    if type(ground_truth_projection) is not VerifiedFrozenGroundTruthProjection:
        raise ValueError("verified frozen ground-truth projection is absent")
    _verify_model_benchmark_report_structure_exact(report, suite=suite)
    if (
        ground_truth_projection.benchmark_corpus_sha256 != suite.corpus_sha256
        or ground_truth_projection.benchmark_ground_truth_sha256 != suite.ground_truth_sha256
        or len(report.results) != 1
    ):
        raise ValueError("evidence-seal report differs from frozen ground truth")
    result = report.results[0]
    if result.target.model_id != candidate.exact_model_id or (
        result.target.root_lineage != candidate.root_lineage
        and not (authenticated_rootless_candidate and result.target.root_lineage is None)
    ):
        raise ValueError("evidence-seal report target differs from its candidate lineage")
    case_hashes = tuple(
        canonical_sha256(
            {
                "case_id": item.case_id,
                "validated_response_sha256": item.validated_response_sha256,
                "observed_classification": (
                    item.observed_classification.value
                    if item.observed_classification is not None
                    else None
                ),
                "observed_locations": [
                    value.model_dump(mode="json") for value in item.observed_locations
                ],
                "observed_invariant_kind": (
                    item.observed_invariant_kind.value
                    if item.observed_invariant_kind is not None
                    else None
                ),
                "dimensions": [value.model_dump(mode="json") for value in item.dimensions],
                "error_kind": item.error_kind,
            }
        )
        for item in result.cases
    )
    case_dimension_outcomes = tuple(
        {
            "case_id": case.case_id,
            "dimension": dimension.dimension.value,
            "passed": dimension.passed,
        }
        for case in result.cases
        for dimension in case.dimensions
    )
    case_dimension_outcome_set_sha256 = canonical_sha256(case_dimension_outcomes)
    dimension_hashes = tuple(
        canonical_sha256(item.model_dump(mode="json")) for item in result.dimensions
    )
    overall_micros = _score_micros(result.overall_score)
    output_sha256 = _decision_output_sha256(
        candidate=candidate,
        corpus_sha256=suite.corpus_sha256,
        ground_truth_sha256=suite.ground_truth_sha256,
        case_outcome_sha256s=case_hashes,
        case_dimension_outcome_set_sha256=case_dimension_outcome_set_sha256,
        dimension_score_sha256s=dimension_hashes,
        overall_score_micros=overall_micros,
        execution_evidence=report.execution_evidence.value,
    )
    payload = {
        "schema_version": "1.0",
        "run_kind": run_kind.value,
        "candidate": candidate.model_dump(mode="json"),
        "runner": runner.model_dump(mode="json"),
        "benchmark_report_sha256": report.report_sha256,
        "benchmark_corpus_sha256": suite.corpus_sha256,
        "benchmark_ground_truth_sha256": suite.ground_truth_sha256,
        "ground_truth_provenance_sha256": ground_truth_projection.provenance_sha256,
        "case_outcome_sha256s": list(case_hashes),
        "case_dimension_outcome_set_sha256": case_dimension_outcome_set_sha256,
        "dimension_score_sha256s": list(dimension_hashes),
        "overall_score_micros": overall_micros,
        "execution_evidence": report.execution_evidence.value,
        "deterministic_output_sha256": output_sha256,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
    }
    return _model_from_json_payload(
        EvidenceSealDecisionProjection,
        {**payload, "projection_sha256": canonical_sha256(payload)},
    )


def build_evidence_seal_decision_projection(
    *,
    suite: ModelBenchmarkSuite,
    report: ModelBenchmarkReport,
    candidate: EvidenceSealLineageBinding,
    runner: EvidenceSealLineageBinding,
    run_kind: EvidenceSealRunKind,
    ground_truth_projection: VerifiedFrozenGroundTruthProjection,
) -> EvidenceSealDecisionProjection:
    """Build detached comparison evidence from an already rooted report.

    Rootless candidate reports are intentionally refused here.  Only the authenticated
    runner consumer below may bind one to a freshly replayed public-lineage root.
    """

    return _build_evidence_seal_decision_projection(
        suite=suite,
        report=report,
        candidate=candidate,
        runner=runner,
        run_kind=run_kind,
        ground_truth_projection=ground_truth_projection,
        authenticated_rootless_candidate=False,
    )


def build_evidence_seal_verdict_projection(
    *,
    benchmark_suite: ModelBenchmarkSuite,
    ground_truth_projection: VerifiedFrozenGroundTruthProjection,
    policy: EvidenceSealVerdictPolicy,
    collision_map: EvidenceSealCollisionMap,
    decision_projections: Sequence[EvidenceSealDecisionProjection],
    benchmark_reports: Sequence[ModelBenchmarkReport],
    campaign_portfolios: Sequence[ModelBenchmarkPortfolio] = (),
) -> EvidenceSealVerdictProjection:
    """Evaluate frozen score, replay, freshness, and budget requirements.

    This builder produces durable comparison evidence only.  A REAL enum value is
    structurally necessary for a satisfied score policy but is never treated as an
    authenticated runner capability.
    """

    suite = _exact_model(benchmark_suite, ModelBenchmarkSuite, label="benchmark suite")
    _require_compiled_ground_truth_projection(ground_truth_projection)
    if (
        suite.corpus_sha256 != ground_truth_projection.benchmark_corpus_sha256
        or suite.ground_truth_sha256 != ground_truth_projection.benchmark_ground_truth_sha256
    ):
        raise ValueError("autonomous verdict suite differs from frozen ground truth")
    policy = _exact_model(policy, EvidenceSealVerdictPolicy, label="verdict policy")
    if policy != compiled_evidence_seal_verdict_policy():
        raise ValueError("evidence-seal verdict policy is not the compiled release policy")
    collision_map = _exact_model(
        collision_map,
        EvidenceSealCollisionMap,
        label="collision map",
    )
    raw_projections = _bounded_items(
        decision_projections,
        maximum=_MAX_PARTICIPANTS,
        label="decision projection inventory",
    )
    raw_reports = _bounded_items(
        benchmark_reports,
        maximum=_MAX_PARTICIPANTS,
        label="benchmark report inventory",
    )
    raw_portfolios = _bounded_items(
        campaign_portfolios,
        maximum=_MAX_PARTICIPANTS,
        label="campaign portfolio inventory",
    )
    projection_count = len(raw_projections)
    report_count = len(raw_reports)
    portfolio_count = len(raw_portfolios)
    if (
        projection_count != len(collision_map.judges)
        or report_count != projection_count
        or projection_count < 2
        or projection_count > _MAX_PARTICIPANTS
        or portfolio_count not in (0, report_count)
    ):
        raise ValueError("autonomous verdict input inventory is outside its exact bound")
    projections = tuple(
        sorted(
            (
                _exact_model(item, EvidenceSealDecisionProjection, label="decision projection")
                for item in raw_projections
            ),
            key=lambda item: (
                0 if item.run_kind is EvidenceSealRunKind.PRIMARY else 1,
                item.benchmark_report_sha256,
            ),
        )
    )
    reports = tuple(
        _exact_model(item, ModelBenchmarkReport, label="benchmark report") for item in raw_reports
    )
    report_by_sha = {item.report_sha256: item for item in reports}
    if len(report_by_sha) != len(reports) or set(report_by_sha) != {
        item.benchmark_report_sha256 for item in projections
    }:
        raise ValueError("verdict reports do not exactly cover decision projections")
    if (
        sum(item.run_kind is EvidenceSealRunKind.PRIMARY for item in projections) != 1
        or sum(item.run_kind is EvidenceSealRunKind.REPLAY for item in projections) < 1
    ):
        raise ValueError("autonomous verdict requires one primary and at least one replay")

    candidate = collision_map.candidate
    expected_judges = tuple(
        (item.exact_model_id, item.root_lineage) for item in collision_map.judges
    )
    observed_judges = tuple(
        sorted((item.runner.exact_model_id, item.runner.root_lineage) for item in projections)
    )
    if observed_judges != expected_judges:
        raise ValueError("autonomous verdict projections do not cover the collision map")
    bindings: list[EvidenceSealVerdictReportBinding] = []
    for projection in projections:
        report = report_by_sha[projection.benchmark_report_sha256]
        _verify_model_benchmark_report_structure_exact(report, suite=suite)
        rebuilt_projection = build_evidence_seal_decision_projection(
            suite=suite,
            report=report,
            candidate=candidate,
            runner=projection.runner,
            run_kind=projection.run_kind,
            ground_truth_projection=ground_truth_projection,
        )
        if projection != rebuilt_projection:
            raise ValueError("autonomous verdict decision projection differs from its report")
        if (
            len(report.results) != 1
            or report.results[0].target.model_id != candidate.exact_model_id
            or report.results[0].target.root_lineage != candidate.root_lineage
            or projection.candidate != candidate
            or projection.benchmark_corpus_sha256 != suite.corpus_sha256
            or projection.benchmark_ground_truth_sha256 != suite.ground_truth_sha256
            or projection.ground_truth_provenance_sha256
            != ground_truth_projection.provenance_sha256
        ):
            raise ValueError("autonomous verdict report differs from its candidate projection")
        result = report.results[0]
        usage = tuple(case.usage_record for case in result.cases if case.usage_record is not None)
        request_ids = tuple(sorted(record.request_id for record in usage))
        generation_ids = tuple(
            sorted(
                record.openrouter_generation_id
                for record in usage
                if record.openrouter_generation_id is not None
            )
        )
        starts = tuple(record.started_at for record in usage if record.started_at is not None)
        ends = tuple(record.ended_at for record in usage if record.ended_at is not None)
        complete_interval = len(starts) == len(usage) == len(ends) and bool(usage)
        binding_payload = {
            "run_kind": projection.run_kind.value,
            "benchmark_report_sha256": report.report_sha256,
            "decision_projection_sha256": projection.projection_sha256,
            "runner_binding_sha256": projection.runner.binding_sha256,
            "deterministic_output_sha256": projection.deterministic_output_sha256,
            "execution_evidence": report.execution_evidence.value,
            "request_ids": list(request_ids),
            "request_id_set_sha256": canonical_sha256(list(request_ids)),
            "generation_ids": list(generation_ids),
            "generation_id_set_sha256": canonical_sha256(list(generation_ids)),
            "usage_record_count": len(usage),
            "case_count": len(result.cases),
            "failed_case_count": sum(case.error_kind is not None for case in result.cases),
            "accounted_cost_usd_exact": canonical_usd_sum(
                tuple(record.accounted_cost_usd_exact or "0" for record in usage)
            ),
            "evidence_started_at": _json_datetime(min(starts)) if complete_interval else None,
            "evidence_ended_at": _json_datetime(max(ends)) if complete_interval else None,
        }
        bindings.append(
            _model_from_json_payload(
                EvidenceSealVerdictReportBinding,
                {
                    **binding_payload,
                    "binding_sha256": canonical_sha256(binding_payload),
                },
            )
        )
    canonical_bindings = tuple(
        sorted(
            bindings,
            key=lambda item: (
                0 if item.run_kind == "PRIMARY" else 1,
                item.benchmark_report_sha256,
            ),
        )
    )
    primary_projection = next(
        item for item in projections if item.run_kind is EvidenceSealRunKind.PRIMARY
    )
    primary_result = report_by_sha[primary_projection.benchmark_report_sha256].results[0]
    case_dimension_outcomes = tuple(
        sorted(
            (
                EvidenceSealCaseDimensionOutcome(
                    case_id=case.case_id,
                    dimension=dimension.dimension,
                    passed=dimension.passed,
                )
                for case in primary_result.cases
                for dimension in case.dimensions
            ),
            key=lambda item: (item.case_id, item.dimension.value),
        )
    )
    expected_case_dimension_values = tuple(
        (item.case_id, item.dimension, item.passed) for item in case_dimension_outcomes
    )
    for report in reports:
        result = report.results[0]
        observed = tuple(
            sorted(
                (
                    (case.case_id, dimension.dimension, dimension.passed)
                    for case in result.cases
                    for dimension in case.dimensions
                ),
                key=lambda item: (item[0], item[1].value),
            )
        )
        if observed != expected_case_dimension_values:
            raise ValueError("autonomous benchmark replay case outcomes diverge")
    floors = {item.dimension: item for item in policy.dimension_floors}
    dimensions = tuple(
        EvidenceSealDimensionVerdict(
            dimension=item.dimension,
            passed=item.passed,
            evaluated=item.evaluated,
            score_micros=_score_micros(item.score),
            minimum_score_micros=floors[item.dimension].minimum_score_micros,
            state=(
                EvidenceSealRequirementState.PASS
                if _score_micros(item.score) >= floors[item.dimension].minimum_score_micros
                else EvidenceSealRequirementState.FAIL
            ),
        )
        for item in primary_result.dimensions
    )
    overall_micros = _score_micros(primary_result.overall_score)
    overall_state = (
        EvidenceSealRequirementState.PASS
        if overall_micros >= policy.minimum_overall_score_micros
        else EvidenceSealRequirementState.FAIL
    )
    case_state = (
        EvidenceSealRequirementState.PASS
        if not any(item.failed_case_count for item in canonical_bindings)
        else EvidenceSealRequirementState.FAIL
    )
    execution_state = (
        EvidenceSealRequirementState.PASS
        if all(item.execution_evidence == "real" for item in canonical_bindings)
        else EvidenceSealRequirementState.UNEVALUABLE
    )
    all_request_ids = [value for item in canonical_bindings for value in item.request_ids]
    all_generation_ids = [value for item in canonical_bindings for value in item.generation_ids]
    replay_state = (
        EvidenceSealRequirementState.PASS
        if len(all_request_ids) == len(set(all_request_ids))
        and len(all_generation_ids) == len(set(all_generation_ids))
        and {item.deterministic_output_sha256 for item in canonical_bindings}
        == {primary_projection.deterministic_output_sha256}
        else EvidenceSealRequirementState.FAIL
    )
    lineage_state = (
        EvidenceSealRequirementState.FAIL
        if any(item.same_root for item in collision_map.pairs)
        or len({item.root_lineage for item in collision_map.judges})
        < policy.minimum_distinct_judge_roots
        else EvidenceSealRequirementState.PASS
    )
    budget = _evidence_seal_budget_projection(
        policy=policy,
        reports=reports,
        report_bindings=canonical_bindings,
        portfolios=raw_portfolios,
    )
    starts = tuple(
        item.evidence_started_at
        for item in canonical_bindings
        if item.evidence_started_at is not None
    )
    ends = tuple(
        item.evidence_ended_at for item in canonical_bindings if item.evidence_ended_at is not None
    )
    complete_times = len(starts) == len(canonical_bindings) and len(ends) == len(canonical_bindings)
    evidence_started_at = min(starts) if complete_times else None
    evidence_ended_at = max(ends) if complete_times else None
    fresh_through = (
        min(ends) + timedelta(days=policy.maximum_evidence_age_days) if complete_times else None
    )
    # The campaign portfolio is durable comparison evidence, not a trusted clock.
    # A later externally anchored consumer may bind an evaluation instant; this
    # provider-free builder therefore cannot promote freshness beyond UNEVALUABLE.
    evaluated_at = None
    freshness_state = EvidenceSealRequirementState.UNEVALUABLE
    component_states = (
        *(item.state for item in dimensions),
        overall_state,
        case_state,
        execution_state,
        replay_state,
        lineage_state,
        freshness_state,
        budget.state,
    )
    disposition = _evidence_seal_policy_disposition(component_states)
    reason_codes = _evidence_seal_verdict_reasons(
        dimensions=dimensions,
        overall_state=overall_state,
        case_state=case_state,
        execution_state=execution_state,
        replay_state=replay_state,
        lineage_state=lineage_state,
        freshness_state=freshness_state,
        budget=budget,
        bindings=canonical_bindings,
    )
    payload = {
        "schema_version": "1.0",
        "authority_basis": "EVIDENCE_SEALED_REPRODUCIBLE",
        "policy": policy.model_dump(mode="json"),
        "candidate_exact_model_id": candidate.exact_model_id,
        "candidate_root_lineage": candidate.root_lineage,
        "candidate_binding_sha256": candidate.binding_sha256,
        "collision_map_sha256": collision_map.collision_map_sha256,
        "report_bindings": [item.model_dump(mode="json") for item in canonical_bindings],
        "report_binding_set_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in canonical_bindings]
        ),
        "decision_projection_set_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in projections]
        ),
        "deterministic_decision_output_sha256": (primary_projection.deterministic_output_sha256),
        "case_dimension_outcomes": [
            item.model_dump(mode="json") for item in case_dimension_outcomes
        ],
        "case_dimension_outcome_set_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in case_dimension_outcomes]
        ),
        "dimensions": [item.model_dump(mode="json") for item in dimensions],
        "overall_score_micros": overall_micros,
        "overall_state": overall_state.value,
        "case_execution_state": case_state.value,
        "execution_evidence_state": execution_state.value,
        "replay_state": replay_state.value,
        "lineage_state": lineage_state.value,
        "freshness_state": freshness_state.value,
        "evidence_started_at": (
            _json_datetime(evidence_started_at) if evidence_started_at is not None else None
        ),
        "evidence_ended_at": (
            _json_datetime(evidence_ended_at) if evidence_ended_at is not None else None
        ),
        "evaluated_at": _json_datetime(evaluated_at) if evaluated_at is not None else None,
        "fresh_through": _json_datetime(fresh_through) if fresh_through is not None else None,
        "budget": budget.model_dump(mode="json"),
        "policy_disposition": disposition.value,
        "baseline_disposition": EvidenceSealBaselineDisposition.UNEVALUABLE.value,
        "reason_codes": [item.value for item in reason_codes],
        "comparison_only": True,
        "durable_authority": False,
        "authority_issuance_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "provider_access_authorized": False,
        "source_egress_authorized": False,
    }
    return _model_from_json_payload(
        EvidenceSealVerdictProjection,
        {**payload, "verdict_sha256": canonical_sha256(payload)},
    )


def _evidence_seal_budget_projection(
    *,
    policy: EvidenceSealVerdictPolicy,
    reports: tuple[ModelBenchmarkReport, ...],
    report_bindings: tuple[EvidenceSealVerdictReportBinding, ...],
    portfolios: Sequence[ModelBenchmarkPortfolio],
) -> EvidenceSealBudgetProjection:
    report_usage_cost = canonical_usd_sum(
        tuple(item.accounted_cost_usd_exact for item in report_bindings)
    )
    if not portfolios:
        payload: dict[str, object] = {
            "scope": EvidenceSealBudgetScope.REPORT_USAGE_LOWER_BOUND.value,
            "report_usage_cost_usd_exact": report_usage_cost,
            "campaign_cost_usd_exact": None,
            "maximum_campaign_cost_usd_exact": policy.maximum_campaign_cost_usd_exact,
            "portfolio_sha256s": [],
            "initial_ledger_snapshot_sha256": None,
            "final_ledger_snapshot_sha256": None,
            "unresolved_cost_count": 0,
            "state": EvidenceSealRequirementState.UNEVALUABLE.value,
        }
        return _model_from_json_payload(
            EvidenceSealBudgetProjection,
            {**payload, "projection_sha256": canonical_sha256(payload)},
        )
    for index, portfolio in enumerate(portfolios):
        if type(portfolio) is not ModelBenchmarkPortfolio:
            raise ValueError("benchmark campaign portfolio must be exact and typed")
        _require_bounded_candidate_ledger_snapshot_text(
            portfolio.initial_cost_ledger_snapshot,
            label=f"benchmark campaign portfolio {index} initial ledger",
        )
        _require_bounded_candidate_ledger_snapshot_text(
            portfolio.cost_ledger_snapshot,
            label=f"benchmark campaign portfolio {index} final ledger",
        )
    exact_portfolios = tuple(
        _exact_model(item, ModelBenchmarkPortfolio, label="benchmark campaign portfolio")
        for item in portfolios
    )
    if len(exact_portfolios) != len(reports) or any(
        item.started_at is None
        or item.ended_at is None
        or item.campaign_journal_sha256 is None
        or item.qualification_policy_sha256 != AUTONOMOUS_BENCHMARK_QUALIFICATION_POLICY_SHA256
        or item.initial_cost_ledger_snapshot is None
        or item.cost_ledger_snapshot is None
        for item in exact_portfolios
    ):
        raise ValueError("autonomous benchmark budget portfolios lack campaign closure")
    ordered = tuple(
        sorted(
            exact_portfolios,
            key=lambda item: (item.started_at, item.portfolio_sha256),
        )
    )
    reports_by_sha = {item.report_sha256: item for item in reports}
    observed_report_shas: set[str] = set()
    for portfolio in ordered:
        assert portfolio.initial_cost_ledger_snapshot is not None
        assert portfolio.cost_ledger_snapshot is not None
        _require_candidate_ledger_snapshot_consistency(
            portfolio.initial_cost_ledger_snapshot,
            label="initial campaign ledger",
        )
        _require_candidate_ledger_snapshot_consistency(
            portfolio.cost_ledger_snapshot,
            label="final campaign ledger",
        )
        if (
            portfolio.corpus_sha256 != policy.benchmark_corpus_sha256
            or portfolio.ground_truth_sha256 != policy.benchmark_ground_truth_sha256
            or len(portfolio.report_artifacts) != 1
        ):
            raise ValueError("autonomous benchmark budget portfolio has a different corpus")
        artifact = portfolio.report_artifacts[0]
        report = reports_by_sha.get(artifact.report_sha256)
        if report is None or artifact.report_sha256 in observed_report_shas:
            raise ValueError("autonomous benchmark budget portfolio report coverage differs")
        observed_report_shas.add(artifact.report_sha256)
        if (
            artifact.exact_model_id != report.results[0].target.model_id
            or artifact.execution_evidence is not report.execution_evidence
            or portfolio.execution_evidence is not report.execution_evidence
        ):
            raise ValueError("autonomous benchmark portfolio differs from its report identity")
        expected_usage = tuple(
            case.usage_record for case in report.results[0].cases if case.usage_record is not None
        )
        if portfolio.observed_usage_records != expected_usage:
            raise ValueError("autonomous benchmark portfolio usage differs from its report")
        if (
            portfolio.initial_cost_ledger_snapshot.cap_usd != policy.maximum_campaign_cost_usd_exact
            or portfolio.cost_ledger_snapshot.cap_usd != policy.maximum_campaign_cost_usd_exact
        ):
            raise ValueError("autonomous benchmark ledger cap differs from its frozen ceiling")
    if observed_report_shas != set(reports_by_sha):
        raise ValueError("autonomous benchmark portfolios omit a candidate report")
    for previous, current in pairwise(ordered):
        if previous.cost_ledger_snapshot != current.initial_cost_ledger_snapshot:
            raise ValueError("autonomous benchmark ledger chain is not contiguous")
    initial = ordered[0].initial_cost_ledger_snapshot
    final = ordered[-1].cost_ledger_snapshot
    assert initial is not None
    assert final is not None
    if not _candidate_ledger_snapshot_is_closed(
        initial
    ) or not _candidate_ledger_snapshot_is_closed(final):
        raise ValueError("autonomous benchmark ledger chain is not fully closed")
    with localcontext(_exact_decimal_context()):
        report_delta = Decimal(report_usage_cost)
        ledger_delta = Decimal(final.spent_usd) - Decimal(initial.spent_usd)
    if ledger_delta != report_delta or ledger_delta < 0:
        raise ValueError("autonomous benchmark ledger delta differs from retained report usage")
    unresolved = (
        final.reserved_count
        + final.uncertain_accounted_count
        + final.reservation_overrun_count
        + int(final.over_cap)
        + int(final.has_reservation_overrun)
    )
    payload = {
        "scope": (EvidenceSealBudgetScope.CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN.value),
        "report_usage_cost_usd_exact": report_usage_cost,
        # Aggregate objective-budget enforcement uses the cumulative final spend,
        # not merely this report set's lower delta.
        "campaign_cost_usd_exact": final.spent_usd,
        "maximum_campaign_cost_usd_exact": policy.maximum_campaign_cost_usd_exact,
        "portfolio_sha256s": sorted(item.portfolio_sha256 for item in ordered),
        "initial_ledger_snapshot_sha256": initial.snapshot_sha256,
        "final_ledger_snapshot_sha256": final.snapshot_sha256,
        "unresolved_cost_count": unresolved,
        "state": (
            EvidenceSealRequirementState.PASS.value
            if not unresolved
            and Decimal(final.spent_usd) < Decimal(policy.maximum_campaign_cost_usd_exact)
            else EvidenceSealRequirementState.FAIL.value
        ),
    }
    return _model_from_json_payload(
        EvidenceSealBudgetProjection,
        {**payload, "projection_sha256": canonical_sha256(payload)},
    )


def _evidence_seal_policy_disposition(
    states: tuple[EvidenceSealRequirementState, ...],
) -> EvidenceSealPolicyDisposition:
    if EvidenceSealRequirementState.FAIL in states:
        return EvidenceSealPolicyDisposition.NOT_SATISFIED
    if EvidenceSealRequirementState.UNEVALUABLE in states:
        return EvidenceSealPolicyDisposition.UNEVALUABLE
    return EvidenceSealPolicyDisposition.STRUCTURALLY_SATISFIED


def _evidence_seal_verdict_reasons(
    *,
    dimensions: tuple[EvidenceSealDimensionVerdict, ...],
    overall_state: EvidenceSealRequirementState,
    case_state: EvidenceSealRequirementState,
    execution_state: EvidenceSealRequirementState,
    replay_state: EvidenceSealRequirementState,
    lineage_state: EvidenceSealRequirementState,
    freshness_state: EvidenceSealRequirementState,
    budget: EvidenceSealBudgetProjection,
    bindings: tuple[EvidenceSealVerdictReportBinding, ...],
) -> tuple[EvidenceSealVerdictReason, ...]:
    reasons: set[EvidenceSealVerdictReason] = {EvidenceSealVerdictReason.BASELINE_NOT_FROZEN}
    if any(item.state is EvidenceSealRequirementState.FAIL for item in dimensions):
        reasons.add(EvidenceSealVerdictReason.DIMENSION_FLOOR_NOT_MET)
    if overall_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.OVERALL_FLOOR_NOT_MET)
    if case_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.CASE_EXECUTION_FAILED)
    if execution_state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.EXECUTION_NOT_REAL)
    request_ids = [value for item in bindings for value in item.request_ids]
    generation_ids = [value for item in bindings for value in item.generation_ids]
    if len(request_ids) != len(set(request_ids)) or len(generation_ids) != len(set(generation_ids)):
        reasons.add(EvidenceSealVerdictReason.REPLAY_IDENTITY_REUSED)
    if (
        replay_state is EvidenceSealRequirementState.FAIL
        and len({item.deterministic_output_sha256 for item in bindings}) != 1
    ):
        reasons.add(EvidenceSealVerdictReason.REPLAY_DIVERGED)
    if lineage_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.LINEAGE_COLLISION)
    if freshness_state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.EVIDENCE_TIME_UNBOUND)
    elif freshness_state is EvidenceSealRequirementState.FAIL:
        reasons.add(EvidenceSealVerdictReason.EVIDENCE_STALE)
    if budget.state is EvidenceSealRequirementState.UNEVALUABLE:
        reasons.add(EvidenceSealVerdictReason.BUDGET_CLOSURE_MISSING)
    elif budget.state is EvidenceSealRequirementState.FAIL:
        if budget.unresolved_cost_count:
            reasons.add(EvidenceSealVerdictReason.BUDGET_CLOSURE_UNRESOLVED)
        if budget.campaign_cost_usd_exact is not None and Decimal(
            budget.campaign_cost_usd_exact
        ) >= Decimal(budget.maximum_campaign_cost_usd_exact):
            reasons.add(EvidenceSealVerdictReason.BUDGET_AT_OR_ABOVE_CEILING)
    return tuple(sorted(reasons, key=lambda item: item.value))


def _score_micros(value: float) -> int:
    with localcontext(_exact_decimal_context()):
        projected = Decimal(str(value)) * Decimal(1_000_000)
    if projected != projected.to_integral_value():
        raise ValueError("model benchmark score cannot be represented in exact micros")
    return int(projected)


def _require_candidate_ledger_snapshot_consistency(
    snapshot: CandidateCostLedgerSnapshot,
    *,
    label: str,
) -> None:
    with localcontext(_exact_decimal_context()):
        available = (
            Decimal(snapshot.cap_usd)
            - Decimal(snapshot.spent_usd)
            - Decimal(snapshot.active_reserved_usd)
        )
        expected_remaining = max(Decimal(0), available)
    if (
        Decimal(snapshot.remaining_usd) != expected_remaining
        or snapshot.over_cap is not (available < 0)
        or snapshot.has_reservation_overrun is not (snapshot.reservation_overrun_count > 0)
    ):
        raise ValueError(f"{label} snapshot arithmetic is inconsistent")


def _require_bounded_candidate_ledger_snapshot_text(
    snapshot: CandidateCostLedgerSnapshot | None,
    *,
    label: str,
) -> None:
    if snapshot is None:
        return
    if type(snapshot) is not CandidateCostLedgerSnapshot:
        raise ValueError(f"{label} snapshot must be exact and typed")
    for field in ("cap_usd", "spent_usd", "active_reserved_usd", "remaining_usd"):
        value = object.__getattribute__(snapshot, field)
        if (
            type(value) is not str
            or len(value) > _MAX_VERDICT_USD_TEXT
            or re.fullmatch(_VERDICT_USD_PATTERN, value) is None
        ):
            raise ValueError(f"{label} {field} exceeds the autonomous verdict USD bound")


def _candidate_ledger_snapshot_is_closed(snapshot: CandidateCostLedgerSnapshot) -> bool:
    return (
        Decimal(snapshot.active_reserved_usd) == 0
        and snapshot.reserved_count == 0
        and snapshot.uncertain_accounted_count == 0
        and snapshot.reservation_overrun_count == 0
        and not snapshot.over_cap
        and not snapshot.has_reservation_overrun
    )


def _json_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _require_compiled_ground_truth_projection(
    projection: VerifiedFrozenGroundTruthProjection,
) -> None:
    if type(projection) is not VerifiedFrozenGroundTruthProjection or (
        projection.objective_sha256,
        projection.provenance_sha256,
        projection.source_revision,
        projection.benchmark_corpus_sha256,
        projection.benchmark_ground_truth_sha256,
        projection.case_binding_set_sha256,
        projection.case_count,
        projection.origin_kinds,
    ) != (
        AUTONOMOUS_BENCHMARK_OBJECTIVE_SHA256,
        AUTONOMOUS_BENCHMARK_PROVENANCE_SHA256,
        AUTONOMOUS_BENCHMARK_SOURCE_REVISION,
        AUTONOMOUS_BENCHMARK_CORPUS_SHA256,
        AUTONOMOUS_BENCHMARK_GROUND_TRUTH_SHA256,
        AUTONOMOUS_BENCHMARK_CASE_BINDING_SET_SHA256,
        24,
        (GroundTruthOriginKind.SYNTHETIC_PLANTED,),
    ):
        raise ValueError("autonomous verdict ground-truth projection differs from compiled pins")


def build_evidence_authority_subject(
    *,
    benchmark_suite: ModelBenchmarkSuite,
    ground_truth_projection: VerifiedFrozenGroundTruthProjection,
    collision_map: EvidenceSealCollisionMap,
    decision_projections: Sequence[EvidenceSealDecisionProjection],
    benchmark_reports: Sequence[ModelBenchmarkReport],
    verdict_projection: EvidenceSealVerdictProjection,
    campaign_portfolios: Sequence[ModelBenchmarkPortfolio] = (),
) -> EvidenceAuthoritySubject:
    _require_compiled_ground_truth_projection(ground_truth_projection)
    collision_map = _exact_model(
        collision_map,
        EvidenceSealCollisionMap,
        label="collision map",
    )
    raw_projections = _bounded_items(
        decision_projections,
        maximum=_MAX_PARTICIPANTS,
        label="decision projection inventory",
    )
    raw_reports = _bounded_items(
        benchmark_reports,
        maximum=_MAX_PARTICIPANTS,
        label="benchmark report inventory",
    )
    raw_portfolios = _bounded_items(
        campaign_portfolios,
        maximum=_MAX_PARTICIPANTS,
        label="campaign portfolio inventory",
    )
    projection_count = len(raw_projections)
    report_count = len(raw_reports)
    portfolio_count = len(raw_portfolios)
    if (
        projection_count != len(collision_map.judges)
        or report_count != projection_count
        or projection_count < 2
        or projection_count > _MAX_PARTICIPANTS
        or portfolio_count not in (0, report_count)
    ):
        raise ValueError("evidence-seal subject input inventory is outside its exact bound")
    projections = tuple(
        sorted(
            (
                _exact_model(item, EvidenceSealDecisionProjection, label="decision projection")
                for item in raw_projections
            ),
            key=lambda item: (
                0 if item.run_kind is EvidenceSealRunKind.PRIMARY else 1,
                item.benchmark_report_sha256,
            ),
        )
    )
    output_hashes = {item.deterministic_output_sha256 for item in projections}
    if len(output_hashes) != 1:
        raise ValueError("independent evidence-seal replay output is not byte-identical")
    verdict = _exact_model(
        verdict_projection,
        EvidenceSealVerdictProjection,
        label="benchmark verdict projection",
    )
    payload = {
        "schema_version": "2.0",
        "authority_basis": "EVIDENCE_SEALED_REPRODUCIBLE",
        "objective_sha256": ground_truth_projection.objective_sha256,
        "ground_truth_provenance_sha256": ground_truth_projection.provenance_sha256,
        "ground_truth_source_revision": ground_truth_projection.source_revision,
        "benchmark_corpus_sha256": ground_truth_projection.benchmark_corpus_sha256,
        "benchmark_ground_truth_sha256": ground_truth_projection.benchmark_ground_truth_sha256,
        "ground_truth_case_binding_set_sha256": ground_truth_projection.case_binding_set_sha256,
        "collision_map": collision_map.model_dump(mode="json"),
        "decision_projections": [item.model_dump(mode="json") for item in projections],
        "decision_projection_set_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in projections]
        ),
        "deterministic_decision_output_sha256": next(iter(output_hashes)),
        "verdict_projection": verdict.model_dump(mode="json"),
        "source_egress_authorized": False,
        "benchmark_scoring_authorized": False,
        "authority_issuance_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "provider_access_authorized": False,
    }
    subject = _model_from_json_payload(
        EvidenceAuthoritySubject,
        {**payload, "authority_subject_sha256": canonical_sha256(payload)},
    )
    rebuilt_verdict = build_evidence_seal_verdict_projection(
        benchmark_suite=benchmark_suite,
        ground_truth_projection=ground_truth_projection,
        policy=verdict.policy,
        collision_map=collision_map,
        decision_projections=projections,
        benchmark_reports=raw_reports,
        campaign_portfolios=raw_portfolios,
    )
    if verdict != rebuilt_verdict:
        raise ValueError("evidence-seal verdict differs from its exact benchmark inputs")
    return subject


def build_transparency_prefix_proof(
    *,
    log_id_sha256: str,
    authority_subject_sha256s: Sequence[str],
    previous_checkpoint: EvidenceTransparencyCheckpoint | None = None,
) -> EvidenceTransparencyPrefixProof:
    _require_sha256(log_id_sha256, label="transparency log ID")
    subjects = _bounded_items(
        authority_subject_sha256s,
        maximum=_MAX_LOG_LEAVES,
        label="transparency subject inventory",
    )
    if not subjects or len(subjects) > _MAX_LOG_LEAVES:
        raise ValueError("transparency subject inventory is empty or over its bound")
    for subject in subjects:
        _require_sha256(subject, label="transparency subject")
    if len(set(subjects)) != len(subjects):
        raise ValueError("transparency subject inventory contains duplicates")
    leaves = tuple(_subject_leaf_sha256(item) for item in subjects)
    previous = (
        _exact_model(
            previous_checkpoint,
            EvidenceTransparencyCheckpoint,
            label="previous transparency checkpoint",
        )
        if previous_checkpoint is not None
        else None
    )
    if previous is not None and (
        previous.log_id_sha256 != log_id_sha256
        or previous.tree_size >= len(leaves)
        or _tree_root_sha256(leaves[: previous.tree_size]) != previous.tree_root_sha256
    ):
        raise ValueError("transparency subjects do not extend the previous checkpoint")
    checkpoint_payload = {
        "schema_version": "1.0",
        "log_id_sha256": log_id_sha256,
        "tree_size": len(leaves),
        "tree_root_sha256": _tree_root_sha256(leaves),
        "previous_checkpoint_sha256": previous.checkpoint_sha256 if previous is not None else None,
    }
    checkpoint = _model_from_json_payload(
        EvidenceTransparencyCheckpoint,
        {**checkpoint_payload, "checkpoint_sha256": canonical_sha256(checkpoint_payload)},
    )
    proof_payload = {
        "schema_version": "1.0",
        "previous_checkpoint": previous.model_dump(mode="json") if previous is not None else None,
        "checkpoint": checkpoint.model_dump(mode="json"),
        "authority_subject_sha256": subjects[-1],
        "subject_leaf_index": len(subjects) - 1,
        "subject_leaf_sha256": leaves[-1],
        "leaf_sha256s": list(leaves),
    }
    return _model_from_json_payload(
        EvidenceTransparencyPrefixProof,
        {**proof_payload, "prefix_proof_sha256": canonical_sha256(proof_payload)},
    )


def build_evidence_sealed_authority_evidence(
    *,
    subject: EvidenceAuthoritySubject,
    transparency_proof: EvidenceTransparencyPrefixProof,
) -> EvidenceSealedAuthorityEvidence:
    """Seal comparison evidence without issuing runtime or qualification authority."""

    subject = _exact_model(subject, EvidenceAuthoritySubject, label="authority subject")
    proof = _exact_model(
        transparency_proof,
        EvidenceTransparencyPrefixProof,
        label="transparency proof",
    )
    if proof.authority_subject_sha256 != subject.authority_subject_sha256:
        raise ValueError("transparency proof belongs to another authority subject")
    payload = {
        "schema_version": "2.0",
        "authority_basis": "EVIDENCE_SEALED_REPRODUCIBLE",
        "subject": subject.model_dump(mode="json"),
        "transparency_proof": proof.model_dump(mode="json"),
        "external_comparison_required": True,
        "durable_authority": False,
        "source_egress_authorized": False,
        "benchmark_scoring_authorized": False,
        "authority_issuance_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "provider_access_authorized": False,
    }
    return _model_from_json_payload(
        EvidenceSealedAuthorityEvidence,
        {**payload, "authority_sha256": canonical_sha256(payload)},
    )


def _lineage_pair(
    candidate: EvidenceSealLineageBinding,
    judge: EvidenceSealLineageBinding,
) -> EvidenceSealLineagePair:
    payload = {
        "candidate_model_id": candidate.exact_model_id,
        "candidate_root_lineage": candidate.root_lineage,
        "judge_model_id": judge.exact_model_id,
        "judge_root_lineage": judge.root_lineage,
        "same_root": candidate.root_lineage == judge.root_lineage,
    }
    return _model_from_json_payload(
        EvidenceSealLineagePair,
        {**payload, "pair_sha256": canonical_sha256(payload)},
    )


def _decision_output_sha256(
    *,
    candidate: EvidenceSealLineageBinding,
    corpus_sha256: str,
    ground_truth_sha256: str,
    case_outcome_sha256s: tuple[str, ...],
    case_dimension_outcome_set_sha256: str,
    dimension_score_sha256s: tuple[str, ...],
    overall_score_micros: int,
    execution_evidence: str,
) -> str:
    return canonical_sha256(
        {
            "candidate_model_id": candidate.exact_model_id,
            "candidate_root_lineage": candidate.root_lineage,
            "benchmark_corpus_sha256": corpus_sha256,
            "benchmark_ground_truth_sha256": ground_truth_sha256,
            "case_outcome_sha256s": list(case_outcome_sha256s),
            "case_dimension_outcome_set_sha256": case_dimension_outcome_set_sha256,
            "dimension_score_sha256s": list(dimension_score_sha256s),
            "overall_score_micros": overall_score_micros,
            "execution_evidence": execution_evidence,
        }
    )


def _subject_leaf_sha256(subject_sha256: str) -> str:
    _require_sha256(subject_sha256, label="authority subject")
    return hashlib.sha256(b"\x00" + bytes.fromhex(subject_sha256)).hexdigest()


def _tree_root_sha256(leaf_sha256s: Sequence[str]) -> str:
    leaves = tuple(leaf_sha256s)
    if not leaves:
        return _EMPTY_TREE_ROOT_SHA256
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << (len(leaves) - 1).bit_length() - 1
    if split == len(leaves):
        split //= 2
    left = _tree_root_sha256(leaves[:split])
    right = _tree_root_sha256(leaves[split:])
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _literal_false(value: object, *, label: str) -> object:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label} flag must be literal false")
    return value


def _require_sha256(value: str, *, label: str) -> None:
    if type(value) is not str or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{label} SHA-256 is invalid")


def _bounded_items[ItemT](
    values: Sequence[ItemT],
    *,
    maximum: int,
    label: str,
) -> tuple[ItemT, ...]:
    items = tuple(islice(iter(values), maximum + 1))
    if len(items) > maximum:
        raise ValueError(f"{label} exceeds its bound")
    return items


def _exact_model[ModelT: BaseModel](value: ModelT, model: type[ModelT], *, label: str) -> ModelT:
    if type(value) is not model:
        raise ValueError(f"{label} must be exact and typed")
    try:
        with localcontext(_exact_decimal_context()):
            return model.model_validate(value.model_dump(mode="python"), strict=True)
    except Exception:
        raise ValueError(f"{label} is structurally invalid") from None


def _model_from_json_payload[ModelT: BaseModel](
    model: type[ModelT],
    payload: object,
) -> ModelT:
    with localcontext(_exact_decimal_context()):
        return model.model_validate_json(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )


def _verify_model_benchmark_report_structure_exact(
    report: ModelBenchmarkReport,
    *,
    suite: ModelBenchmarkSuite,
) -> None:
    with localcontext(_exact_decimal_context()):
        verify_model_benchmark_report_structure(report, corpus=suite)


def _build_authenticated_evidence_seal_runner_consumer() -> Callable[
    ...,
    tuple[EvidenceSealCollisionMap, tuple[EvidenceSealDecisionProjection, ...]],
]:
    """Capture the exact AUTHRUNNER verifier used by the AUTHSEAL input boundary."""

    namespace = globals()
    trusted_sys_module = sys
    trusted_json_module = json
    trusted_hashlib_module = hashlib
    trusted_self_module = trusted_sys_module.modules[__name__]
    trusted_runner_module = _authenticated_runner_module
    trusted_adjudication_module = _adjudication_module
    trusted_manifest_module = _manifest_module
    trusted_require_runner = require_verified_cross_lineage_runner_custody
    trusted_exact_model = _exact_model
    trusted_require_ground_truth = _require_compiled_ground_truth_projection
    trusted_lineage_binding = build_evidence_seal_lineage_binding
    trusted_collision_map = build_evidence_seal_collision_map
    trusted_decision_projection = _build_evidence_seal_decision_projection
    trusted_json_dumps = json.dumps
    trusted_hashlib_sha256 = hashlib.sha256
    trusted_model_dump = BaseModel.model_dump
    trusted_model_validate = BaseModel.__dict__["model_validate"]
    trusted_model_validate_json = BaseModel.__dict__["model_validate_json"]
    trusted_types = {
        "AuthenticatedCrossLineageRunnerEvidence": AuthenticatedCrossLineageRunnerEvidence,
        "CrossLineageAdjudicationDisposition": CrossLineageAdjudicationDisposition,
        "CrossLineageAdjudicationReport": CrossLineageAdjudicationReport,
        "CrossLineageRunnerRunCustody": CrossLineageRunnerRunCustody,
        "VerifiedCrossLineageRunnerCustody": VerifiedCrossLineageRunnerCustody,
        "VerifiedCrossLineageRunnerProjection": VerifiedCrossLineageRunnerProjection,
        "EvidenceSealCollisionMap": EvidenceSealCollisionMap,
        "EvidenceSealDecisionProjection": EvidenceSealDecisionProjection,
        "EvidenceSealLineageBinding": EvidenceSealLineageBinding,
        "EvidenceSealLineageRole": EvidenceSealLineageRole,
        "EvidenceSealRunKind": EvidenceSealRunKind,
        "ModelBenchmarkPortfolio": ModelBenchmarkPortfolio,
        "ModelBenchmarkReport": ModelBenchmarkReport,
        "ModelBenchmarkSuite": ModelBenchmarkSuite,
        "VerifiedFrozenGroundTruthProjection": VerifiedFrozenGroundTruthProjection,
    }
    trusted_functions = {
        "require_verified_cross_lineage_runner_custody": trusted_require_runner,
        "_exact_model": trusted_exact_model,
        "_require_compiled_ground_truth_projection": trusted_require_ground_truth,
        "build_evidence_seal_lineage_binding": trusted_lineage_binding,
        "build_evidence_seal_collision_map": trusted_collision_map,
        "_build_evidence_seal_decision_projection": trusted_decision_projection,
        "_bounded_items": _bounded_items,
        "_decision_output_sha256": _decision_output_sha256,
        "_exact_decimal_context": _exact_decimal_context,
        "_lineage_pair": _lineage_pair,
        "_model_from_json_payload": _model_from_json_payload,
        "_score_micros": _score_micros,
        "_verify_model_benchmark_report_structure_exact": (
            _verify_model_benchmark_report_structure_exact
        ),
        "canonical_sha256": canonical_sha256,
        "verify_model_benchmark_report_structure": verify_model_benchmark_report_structure,
    }
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            namespace.get("sys") is not trusted_sys_module
            or namespace.get("json") is not trusted_json_module
            or namespace.get("hashlib") is not trusted_hashlib_module
            or trusted_sys_module.modules.get(__name__) is not trusted_self_module
            or trusted_sys_module.modules.get(trusted_runner_module.__name__)
            is not trusted_runner_module
            or trusted_sys_module.modules.get(trusted_adjudication_module.__name__)
            is not trusted_adjudication_module
            or trusted_sys_module.modules.get(trusted_manifest_module.__name__)
            is not trusted_manifest_module
            or namespace.get("_authenticated_runner_module") is not trusted_runner_module
            or namespace.get("_adjudication_module") is not trusted_adjudication_module
            or namespace.get("_manifest_module") is not trusted_manifest_module
            or any(namespace.get(name) is not value for name, value in trusted_types.items())
            or any(namespace.get(name) is not value for name, value in trusted_functions.items())
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
            or trusted_runner_module.AuthenticatedCrossLineageRunnerEvidence
            is not AuthenticatedCrossLineageRunnerEvidence
            or trusted_runner_module.CrossLineageRunnerRunCustody
            is not CrossLineageRunnerRunCustody
            or trusted_runner_module.VerifiedCrossLineageRunnerCustody
            is not VerifiedCrossLineageRunnerCustody
            or trusted_runner_module.VerifiedCrossLineageRunnerProjection
            is not VerifiedCrossLineageRunnerProjection
            or trusted_runner_module.require_verified_cross_lineage_runner_custody
            is not trusted_require_runner
            or trusted_adjudication_module.CrossLineageAdjudicationDisposition
            is not CrossLineageAdjudicationDisposition
            or trusted_adjudication_module.CrossLineageAdjudicationReport
            is not CrossLineageAdjudicationReport
            or trusted_manifest_module.canonical_sha256 is not canonical_sha256
            or trusted_json_module.dumps is not trusted_json_dumps
            or trusted_hashlib_module.sha256 is not trusted_hashlib_sha256
            or BaseModel.model_dump is not trusted_model_dump
            or BaseModel.__dict__.get("model_validate") is not trusted_model_validate
            or BaseModel.__dict__.get("model_validate_json") is not trusted_model_validate_json
        ):
            raise ValueError("authenticated evidence-seal verifier runtime is not pristine")

    def exact_runs(
        runs: tuple[CrossLineageRunnerRunCustody, ...],
        *,
        runner_projection: VerifiedCrossLineageRunnerProjection,
        runner_evidence: AuthenticatedCrossLineageRunnerEvidence,
        suite: ModelBenchmarkSuite,
    ) -> tuple[CrossLineageRunnerRunCustody, ...]:
        if type(runs) is not tuple or not (2 <= len(runs) <= _MAX_PARTICIPANTS):
            raise ValueError("authenticated evidence-seal runs require an exact bounded tuple")
        if len(runs) != len(runner_projection.runs) or len(runs) != len(runner_evidence.runs):
            raise ValueError("authenticated evidence-seal run inventory differs from custody")
        validated: list[CrossLineageRunnerRunCustody] = []
        for run, live, durable in zip(
            runs,
            runner_projection.runs,
            runner_evidence.runs,
            strict=True,
        ):
            if type(run) is not CrossLineageRunnerRunCustody:
                raise ValueError("authenticated evidence-seal run has the wrong exact type")
            report = trusted_exact_model(
                run.candidate_report,
                ModelBenchmarkReport,
                label="authenticated candidate report",
            )
            portfolio = trusted_exact_model(
                run.candidate_portfolio,
                ModelBenchmarkPortfolio,
                label="authenticated candidate portfolio",
            )
            adjudication = trusted_exact_model(
                run.adjudication_report,
                CrossLineageAdjudicationReport,
                label="authenticated adjudication report",
            )
            if type(run.candidate_campaign_reports) is not tuple:
                raise ValueError("authenticated candidate campaign reports require an exact tuple")
            campaign_reports = tuple(
                trusted_exact_model(
                    item,
                    ModelBenchmarkReport,
                    label="authenticated candidate campaign report",
                )
                for item in run.candidate_campaign_reports
            )
            campaign_hashes = tuple(sorted(item.report_sha256 for item in campaign_reports))
            result = report.results[0] if len(report.results) == 1 else None
            target = adjudication.target
            if (
                result is None
                or run.run_kind is not live.run_kind
                or run.run_kind is not durable.run_kind
                or report.report_sha256 != live.candidate_report_sha256
                or report.report_sha256 != durable.candidate_report_sha256
                or portfolio.portfolio_sha256 != live.candidate_portfolio_sha256
                or portfolio.portfolio_sha256 != durable.candidate_portfolio_sha256
                or adjudication.prepared_run_sha256 != live.prepared_run_sha256
                or adjudication.prepared_run_sha256 != durable.prepared_run_sha256
                or adjudication.report_sha256 != live.adjudication_report_sha256
                or adjudication.report_sha256 != durable.adjudication_report_sha256
                or campaign_hashes != durable.candidate_campaign_report_sha256s
                or result.target.model_id != live.candidate_model_id
                or live.candidate_model_id != durable.candidate_model_id
                or result.target.root_lineage not in (None, live.candidate_root_lineage)
                or live.candidate_root_lineage != durable.candidate_root_lineage
                or target.candidate_model_id != live.candidate_model_id
                or target.candidate_root_lineage != live.candidate_root_lineage
                or target.judge_model_id != live.judge_model_id
                or live.judge_model_id != durable.judge_model_id
                or target.judge_root_lineage != live.judge_root_lineage
                or live.judge_root_lineage != durable.judge_root_lineage
                or tuple(report.case_ids) != runner_evidence.case_ids
                or live.case_ids != runner_evidence.case_ids
                or adjudication.case_ids != live.case_ids
                or adjudication.candidate_report_sha256 != report.report_sha256
                or report.corpus_sha256 != suite.corpus_sha256
                or report.ground_truth_sha256 != suite.ground_truth_sha256
                or adjudication.corpus_sha256 != suite.corpus_sha256
                or adjudication.ground_truth_sha256 != suite.ground_truth_sha256
                or any(
                    case.response.disposition is not CrossLineageAdjudicationDisposition.CONFIRMED
                    or case.response.dimension_outcomes != case.request.expected_dimension_outcomes
                    for case in adjudication.cases
                )
            ):
                raise ValueError(
                    "authenticated evidence-seal report, campaign, portfolio, or run binding "
                    "differs from custody"
                )
            validated.append(run)
        return tuple(validated)

    def consume(
        *,
        runner_custody: VerifiedCrossLineageRunnerCustody,
        runner_evidence: AuthenticatedCrossLineageRunnerEvidence,
        benchmark_suite: ModelBenchmarkSuite,
        ground_truth_projection: VerifiedFrozenGroundTruthProjection,
        runs: tuple[CrossLineageRunnerRunCustody, ...],
    ) -> tuple[EvidenceSealCollisionMap, tuple[EvidenceSealDecisionProjection, ...]]:
        """Recompute non-authorizing AUTHSEAL inputs from fresh AUTHRUNNER custody.

        The caller supplies no lineage labels.  A candidate report may be rootless only
        because the retained opaque runner custody freshly derives its root from public
        lineage on this invocation.  Returned Pydantic artifacts remain durable comparison
        evidence and cannot replace either the runner custody or an external-log capability.
        """

        require_pristine()
        runner_projection = trusted_require_runner(
            runner_custody,
            evidence=runner_evidence,
        )
        require_pristine()
        if type(runner_projection) is not VerifiedCrossLineageRunnerProjection:
            raise ValueError("authenticated runner returned the wrong projection type")
        suite = trusted_exact_model(
            benchmark_suite,
            ModelBenchmarkSuite,
            label="authenticated evidence-seal benchmark suite",
        )
        trusted_require_ground_truth(ground_truth_projection)
        ledger_evidence = runner_evidence.ledger_interval
        ledger_request_ids = tuple(item.request_id for item in ledger_evidence.entries)
        case_attempt_request_ids = tuple(
            attempt_id
            for run in runner_evidence.runs
            for cases in (run.candidate_cases, run.judge_cases)
            for case in cases
            for attempt_id in case.attempt_request_ids
        )
        if (
            runner_projection.evidence_sha256 != runner_evidence.evidence_sha256
            or runner_projection.runner_custody_authorized is not True
            or runner_projection.serialized_authority is not False
            or runner_projection.seal_publication_authorized is not False
            or runner_projection.model_qualification_authorized is not False
            or runner_projection.production_selection_authorized is not False
            or runner_projection.objective_sha256 != ground_truth_projection.objective_sha256
            or runner_projection.frozen_ground_truth_provenance_sha256
            != ground_truth_projection.provenance_sha256
            or runner_projection.frozen_source_revision != ground_truth_projection.source_revision
            or runner_projection.benchmark_corpus_sha256 != suite.corpus_sha256
            or runner_projection.benchmark_ground_truth_sha256 != suite.ground_truth_sha256
            or runner_projection.benchmark_corpus_sha256
            != ground_truth_projection.benchmark_corpus_sha256
            or runner_projection.benchmark_ground_truth_sha256
            != ground_truth_projection.benchmark_ground_truth_sha256
            or runner_projection.ground_truth_case_binding_set_sha256
            != ground_truth_projection.case_binding_set_sha256
            or runner_evidence.case_ids != tuple(item.case_id for item in suite.cases)
            or runner_projection.ledger_initial_snapshot_sha256
            != ledger_evidence.initial_snapshot_sha256
            or runner_projection.ledger_final_snapshot_sha256
            != ledger_evidence.final_snapshot_sha256
            or runner_projection.ledger_final_spent_usd != ledger_evidence.final_spent_usd
            or runner_projection.ledger_request_ids != ledger_request_ids
            or tuple(sorted(case_attempt_request_ids)) != tuple(sorted(ledger_request_ids))
        ):
            raise ValueError(
                "authenticated runner projection differs from the frozen AUTHSEAL inputs"
            )
        retained_runs = exact_runs(
            runs,
            runner_projection=runner_projection,
            runner_evidence=runner_evidence,
            suite=suite,
        )
        live_runs = runner_projection.runs
        candidate_identities = {
            (item.candidate_model_id, item.candidate_root_lineage) for item in live_runs
        }
        judge_identities = tuple(
            sorted((item.judge_model_id, item.judge_root_lineage) for item in live_runs)
        )
        if (
            len(candidate_identities) != 1
            or len(judge_identities) != len(set(judge_identities))
            or len({root for _, root in judge_identities}) != len(judge_identities)
        ):
            raise ValueError("authenticated evidence-seal lineage inventory is not independent")
        candidate_model_id, candidate_root = next(iter(candidate_identities))
        if any(root == candidate_root for _, root in judge_identities):
            raise ValueError("authenticated evidence-seal same-root judgment is void")
        candidate = trusted_lineage_binding(
            exact_model_id=candidate_model_id,
            root_lineage=candidate_root,
            role=EvidenceSealLineageRole.CANDIDATE,
        )
        judges = tuple(
            trusted_lineage_binding(
                exact_model_id=model_id,
                root_lineage=root,
                role=EvidenceSealLineageRole.JUDGE,
            )
            for model_id, root in judge_identities
        )
        collision_map = trusted_collision_map(candidate=candidate, judges=judges)
        judges_by_identity = {(item.exact_model_id, item.root_lineage): item for item in judges}
        decision_projections = tuple(
            trusted_decision_projection(
                suite=suite,
                report=run.candidate_report,
                candidate=candidate,
                runner=judges_by_identity[(live.judge_model_id, live.judge_root_lineage)],
                run_kind=EvidenceSealRunKind(live.run_kind.value),
                ground_truth_projection=ground_truth_projection,
                authenticated_rootless_candidate=True,
            )
            for run, live in zip(retained_runs, live_runs, strict=True)
        )
        if (
            any(item.candidate != candidate for item in decision_projections)
            or tuple(item.benchmark_report_sha256 for item in decision_projections)
            != tuple(item.candidate_report_sha256 for item in live_runs)
            or tuple(item.run_kind.value for item in decision_projections)
            != tuple(item.run_kind.value for item in live_runs)
            or any(item.model_qualification_authorized for item in decision_projections)
            or any(item.production_selection_authorized for item in decision_projections)
        ):
            raise ValueError("authenticated evidence-seal decision projection is inconsistent")
        require_pristine()
        return collision_map, decision_projections

    public_bindings["build_authenticated_evidence_seal_runner_inputs"] = consume
    return consume


build_authenticated_evidence_seal_runner_inputs = (
    _build_authenticated_evidence_seal_runner_consumer()
)
del _build_authenticated_evidence_seal_runner_consumer
