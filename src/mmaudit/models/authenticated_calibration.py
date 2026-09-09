"""Signer-free calibration from live cross-lineage custody, never release authority.

Each selected candidate contributes its original PRIMARY distribution exactly once.
Every independently judged REPLAY and closed cost interval remains bound. The
derived P2 is a proposal: external anchoring, successor-release admission and an
independent qualification campaign are separate, still mandatory consumers.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from types import FunctionType
from typing import Any, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkDimensionScore,
    ModelBenchmarkSuite,
)
from mmaudit.models import calibration as _calibration_rules
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerEvidence,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
    require_verified_cross_lineage_runner_custody,
)
from mmaudit.models.autonomous_benchmark_verdict import canonical_usd_sum
from mmaudit.models.calibration import (
    _AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE,
    _CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS,
    _CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS,
    _CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
    _CALIBRATION_GLOBAL_ROOT_SUPPORT,
    ModelCalibrationCandidateObservation,
    ModelCalibrationDimensionDistribution,
    ModelCalibrationDimensionObservation,
    ModelCalibrationScoreFrequency,
    _derive_calibration_policy_components,
    _required_calibration_root_lineage,
    _verify_policy_threshold_bindings,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkRunState,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
    EvidenceSealRunKind,
    build_authenticated_evidence_seal_runner_inputs,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruth,
)
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.qualification import QualificationPolicy, seal_qualification_policy
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

MAX_AUTHENTICATED_CALIBRATION_BYTES = 32_000_000
_MAX_CANDIDATES = 128
_SHA = r"^[0-9a-f]{64}$"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AuthenticatedCalibrationRun(_FrozenModel):
    """Exact source dimensions joined to one retained authenticated decision."""

    decision: EvidenceSealDecisionProjection
    diagnostic: CandidateBenchmarkDiagnostic
    dimensions: tuple[ModelBenchmarkDimensionScore, ...] = Field(min_length=17, max_length=17)
    candidate_registry_sha256: str = Field(pattern=_SHA)
    discovery_manifest_sha256: str = Field(pattern=_SHA)
    campaign_journal_sha256: str = Field(pattern=_SHA)
    portfolio_sha256: str = Field(pattern=_SHA)
    policy_sha256: str = Field(pattern=_SHA)
    effective_config_sha256: str = Field(pattern=_SHA)
    ended_at: datetime

    @field_validator("ended_at")
    @classmethod
    def completion_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("authenticated calibration completion requires UTC")
        return value

    @model_validator(mode="after")
    def dimensions_match_retained_decision(self) -> Self:
        decision = self.decision
        dimensions = tuple(item.dimension.value for item in self.dimensions)
        if dimensions != tuple(sorted(item.value for item in ModelBenchmarkDimension)):
            raise ValueError("authenticated calibration must retain every dimension")
        if (
            tuple(canonical_sha256(item.model_dump(mode="json")) for item in self.dimensions)
            != decision.dimension_score_sha256s
            or round(sum(item.score for item in self.dimensions) / len(self.dimensions), 6)
            != decision.overall_score_micros / 1_000_000
            or decision.execution_evidence != "real"
            or self.diagnostic.exact_model_id != decision.candidate.exact_model_id
            or self.diagnostic.report_sha256 != decision.benchmark_report_sha256
            or self.diagnostic.execution_evidence is not ExecutionEvidenceKind.REAL
            or self.diagnostic.state is not CandidateBenchmarkRunState.COMPLETE
            or self.diagnostic.failed_cases
            or self.diagnostic.unresolved_cost_count
            or self.diagnostic.corpus_cases != len(decision.case_outcome_sha256s)
            or self.diagnostic.requests_observed != self.diagnostic.corpus_cases
            or self.diagnostic.successful_request_count != self.diagnostic.corpus_cases
        ):
            raise ValueError("authenticated calibration dimensions or diagnostic differ")
        return self


def _retained_cost(sources: tuple[AuthenticatedCalibrationCandidateSource, ...]) -> str:
    """Count prior spend once per ledger, rejecting gaps, overlaps and reused intervals."""

    grouped: dict[str, list[AuthenticatedCrossLineageRunnerEvidence]] = {}
    for source in sources:
        evidence = source.runner_evidence
        grouped.setdefault(evidence.ledger_interval.ledger_identity_sha256, []).append(evidence)
    totals: list[str] = []
    for evidence_set in grouped.values():
        intervals = [item.ledger_interval for item in evidence_set]
        by_start = {item.initial_snapshot_sha256: item for item in intervals}
        ends = {item.final_snapshot_sha256 for item in intervals}
        starts = set(by_start) - ends
        if len(by_start) != len(intervals) or len(ends) != len(intervals) or len(starts) != 1:
            raise ValueError("authenticated calibration ledger chain overlaps or is ambiguous")
        current = by_start[next(iter(starts))]
        visited: set[str] = set()
        while True:
            if current.initial_snapshot_sha256 in visited:
                raise ValueError("authenticated calibration ledger chain cycles")
            visited.add(current.initial_snapshot_sha256)
            following = by_start.get(current.final_snapshot_sha256)
            if following is None:
                break
            if following.initial_spent_usd != current.final_spent_usd:
                raise ValueError("authenticated calibration ledger chain changes prior spend")
            current = following
        if len(visited) != len(intervals):
            raise ValueError("authenticated calibration ledger chain has a missing interval")
        totals.append(current.final_spent_usd)
    total = canonical_usd_sum(tuple(totals))
    if Decimal(total) >= Decimal("250"):
        raise ValueError("authenticated calibration retained cost reaches the 250 USD ceiling")
    return total


def _distributions(
    candidates: tuple[ModelCalibrationCandidateObservation, ...],
) -> tuple[ModelCalibrationDimensionDistribution, ...]:
    values: list[ModelCalibrationDimensionDistribution] = []
    for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value):
        observations = tuple(
            ModelCalibrationDimensionObservation(
                exact_model_id=candidate.exact_model_id,
                root_lineage=_required_calibration_root_lineage(candidate),
                passed=score.passed,
                evaluated=score.evaluated,
                score=score.score,
            )
            for candidate in candidates
            for score in candidate.dimensions
            if score.dimension is dimension
        )
        frequencies: dict[float, int] = {}
        for observation in observations:
            frequencies[observation.score] = frequencies.get(observation.score, 0) + 1
        values.append(
            ModelCalibrationDimensionDistribution(
                dimension=dimension,
                candidate_count=len(candidates),
                included_candidate_count=len(candidates),
                excluded_candidate_count=0,
                observations=observations,
                score_frequencies=tuple(
                    ModelCalibrationScoreFrequency(score=score, candidate_count=count)
                    for score, count in sorted(frequencies.items())
                ),
                mean_score=round(sum(item.score for item in observations) / len(observations), 6),
            )
        )
    return tuple(values)


class AuthenticatedCalibrationCandidateSource(_FrozenModel):
    """All primary/replay identities and liabilities, not a serialized capability."""

    runner_evidence: AuthenticatedCrossLineageRunnerEvidence
    collision_map: EvidenceSealCollisionMap
    runs: tuple[AuthenticatedCalibrationRun, ...] = Field(min_length=2, max_length=32)

    @model_validator(mode="after")
    def exact_runner_join(self) -> Self:
        evidence = self.runner_evidence
        candidate = self.collision_map.candidate
        if (
            evidence.effective_config_sha256 is None
            or len(self.runs) != len(evidence.runs)
            or len(self.runs) != len(self.collision_map.judges)
            or any(pair.same_root for pair in self.collision_map.pairs)
        ):
            raise ValueError("authenticated calibration requires exact cross-lineage run scope")
        for run, retained in zip(self.runs, evidence.runs, strict=True):
            decision = run.decision
            if (
                decision.candidate != candidate
                or candidate.exact_model_id != retained.candidate_model_id
                or candidate.root_lineage != retained.candidate_root_lineage
                or decision.runner not in self.collision_map.judges
                or decision.runner.exact_model_id != retained.judge_model_id
                or decision.runner.root_lineage != retained.judge_root_lineage
                or decision.run_kind.value != retained.run_kind.value
                or decision.benchmark_report_sha256 != retained.candidate_report_sha256
                or run.portfolio_sha256 != retained.candidate_portfolio_sha256
                or run.effective_config_sha256 != evidence.effective_config_sha256
                or decision.benchmark_corpus_sha256 != evidence.benchmark_corpus_sha256
                or decision.benchmark_ground_truth_sha256 != evidence.benchmark_ground_truth_sha256
                or decision.ground_truth_provenance_sha256
                != evidence.frozen_ground_truth_provenance_sha256
                or run.diagnostic.corpus_cases != len(evidence.case_ids)
                or run.diagnostic.provider_attempt_count
                != sum(case.attempt_count for case in retained.candidate_cases)
            ):
                raise ValueError("authenticated calibration source differs from retained custody")
        if self.runs[0].decision.run_kind is not EvidenceSealRunKind.PRIMARY:
            raise ValueError("authenticated calibration requires original primary first")
        if len({run.policy_sha256 for run in self.runs}) != 1:
            raise ValueError("authenticated calibration changes policy between retained runs")
        return self


@dataclass(frozen=True, slots=True)
class AuthenticatedCalibrationCandidateInputs:
    """In-process inputs only; no callback or caller-supplied lineage is accepted."""

    runner_custody: VerifiedCrossLineageRunnerCustody
    runner_evidence: AuthenticatedCrossLineageRunnerEvidence
    runs: tuple[CrossLineageRunnerRunCustody, ...]


class AuthenticatedModelCalibrationArtifact(_FrozenModel):
    """Non-dispositive measurements; loading them never recreates live verification."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_basis: Literal["AUTHENTICATED_CROSS_LINEAGE_RUNNER"] = (
        "AUTHENTICATED_CROSS_LINEAGE_RUNNER"
    )
    selection_scope: Literal["EXACT_SELECTED_POPULATION_NOT_CAMPAIGN_REGISTRATION"] = (
        "EXACT_SELECTED_POPULATION_NOT_CAMPAIGN_REGISTRATION"
    )
    sampling_rule: Literal["PRIMARY_ONCE_ALL_REPLAYS_RETAINED"] = (
        "PRIMARY_ONCE_ALL_REPLAYS_RETAINED"
    )
    selected_model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_CANDIDATES)
    sources: tuple[AuthenticatedCalibrationCandidateSource, ...] = Field(
        min_length=1, max_length=_MAX_CANDIDATES
    )
    created_at: datetime
    candidates: tuple[ModelCalibrationCandidateObservation, ...] = Field(
        min_length=1, max_length=_MAX_CANDIDATES
    )
    distributions: tuple[ModelCalibrationDimensionDistribution, ...] = Field(
        min_length=17, max_length=17
    )
    included_root_lineage_count: int = Field(ge=1, le=_MAX_CANDIDATES)
    retained_cost_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    cost_scope: Literal["CLOSED_LEDGER_CHAINS_INCLUDING_PRIOR_SPEND_NOT_GLOBAL_ADMISSION"] = (
        "CLOSED_LEDGER_CHAINS_INCLUDING_PRIOR_SPEND_NOT_GLOBAL_ADMISSION"
    )
    external_seal_required: Literal[True] = True
    serialized_authority: Literal[False] = False
    policy_adoption_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    artifact_sha256: str = Field(pattern=_SHA)

    @field_validator(
        "serialized_authority",
        "policy_adoption_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_call_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def durable_authority_is_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("authenticated calibration has no serialized authority")
        return value

    @field_validator("external_seal_required", mode="before")
    @classmethod
    def external_seal_remains_required(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("authenticated calibration still requires an external seal")
        return value

    @model_validator(mode="after")
    def observations_and_self_hash_are_exact(self) -> Self:
        expected = _measurement_payload(self.selected_model_ids, self.sources)
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise ValueError("authenticated calibration projection differs from its sources")
        if self.artifact_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"artifact_sha256"})
        ):
            raise ValueError("authenticated calibration self-hash differs")
        return self


def _measurement_payload(
    selected: tuple[str, ...], sources: tuple[AuthenticatedCalibrationCandidateSource, ...]
) -> dict[str, object]:
    if not sources or len(selected) != len(sources) or len(sources) > _MAX_CANDIDATES:
        raise ValueError("authenticated calibration loses a selected candidate")
    if selected != tuple(sorted({require_exact_openrouter_model_id(item) for item in selected})):
        raise ValueError("authenticated calibration selection must be exact, unique and sorted")
    if selected != tuple(source.collision_map.candidate.exact_model_id for source in sources):
        raise ValueError("authenticated calibration source order differs from selected candidates")
    reference = sources[0].runner_evidence
    if (
        reference.objective_sha256 != FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256
        or reference.frozen_ground_truth_provenance_sha256 != FROZEN_GROUND_TRUTH_PROVENANCE_SHA256
        or reference.frozen_source_revision != FROZEN_GROUND_TRUTH_SOURCE_REVISION
    ):
        raise ValueError("authenticated calibration changes the frozen objective or truth")
    common = (
        "effective_config_sha256",
        "objective_sha256",
        "frozen_ground_truth_provenance_sha256",
        "frozen_source_revision",
        "benchmark_corpus_sha256",
        "benchmark_ground_truth_sha256",
        "ground_truth_case_binding_set_sha256",
        "public_lineage_bundle_sha256",
        "public_lineage_manifest_file_sha256",
        "case_ids",
    )
    policy = sources[0].runs[0].policy_sha256
    seen: dict[str, set[str]] = {
        key: set() for key in ("request_id", "generation_id", "request_body_sha256")
    }
    report_ids: set[str] = set()
    attempt_ids: set[str] = set()
    for source in sources:
        evidence = source.runner_evidence
        if any(getattr(evidence, key) != getattr(reference, key) for key in common):
            raise ValueError("authenticated calibration mixes truth, lineage or configuration")
        if any(run.policy_sha256 != policy for run in source.runs):
            raise ValueError("authenticated calibration mixes benchmark policies")
        source_attempts = tuple(
            attempt
            for run in evidence.runs
            for case in (*run.candidate_cases, *run.judge_cases)
            for attempt in case.attempt_request_ids
        )
        if (
            len(source_attempts) != len(set(source_attempts))
            or attempt_ids.intersection(source_attempts)
            or set(source_attempts)
            != {entry.request_id for entry in evidence.ledger_interval.entries}
        ):
            raise ValueError("authenticated calibration reuses or loses a billed attempt")
        attempt_ids.update(source_attempts)
        entries = {entry.request_id: entry for entry in evidence.ledger_interval.entries}
        for run in evidence.runs:
            if run.candidate_report_sha256 in report_ids:
                raise ValueError("authenticated calibration reuses a candidate report")
            report_ids.add(run.candidate_report_sha256)
            for case in (*run.candidate_cases, *run.judge_cases):
                if case.accounted_cost_usd != canonical_usd_sum(
                    tuple(entries[attempt].actual_cost_usd for attempt in case.attempt_request_ids)
                ):
                    raise ValueError("authenticated calibration case costs differ from its ledger")
                for key, values in seen.items():
                    value = getattr(case, key)
                    if value in values:
                        raise ValueError("authenticated calibration reuses execution identities")
                    values.add(value)
    candidates = tuple(
        ModelCalibrationCandidateObservation(
            exact_model_id=source.collision_map.candidate.exact_model_id,
            root_lineage=source.collision_map.candidate.root_lineage,
            lineage_binding_sha256=source.collision_map.candidate.binding_sha256,
            report_sha256=source.runs[0].decision.benchmark_report_sha256,
            report_execution_evidence=ExecutionEvidenceKind.REAL,
            diagnostic=source.runs[0].diagnostic,
            included_in_distribution=True,
            dimensions=source.runs[0].dimensions,
            overall_score=source.runs[0].decision.overall_score_micros / 1_000_000,
        )
        for source in sources
    )
    return {
        "created_at": max(run.ended_at for source in sources for run in source.runs).replace(
            microsecond=0
        ),
        "candidates": candidates,
        "distributions": _distributions(candidates),
        "included_root_lineage_count": len({candidate.root_lineage for candidate in candidates}),
        "retained_cost_usd": _retained_cost(sources),
    }


def _assemble_artifact(
    selected: tuple[str, ...], sources: tuple[AuthenticatedCalibrationCandidateSource, ...]
) -> AuthenticatedModelCalibrationArtifact:
    payload: dict[str, Any] = {
        "selected_model_ids": selected,
        "sources": sources,
        **_measurement_payload(selected, sources),
    }
    provisional = AuthenticatedModelCalibrationArtifact.model_construct(**payload)
    return AuthenticatedModelCalibrationArtifact.model_validate_json(
        stable_json(
            provisional.model_copy(
                update={"artifact_sha256": canonical_sha256(provisional.model_dump(mode="json"))}
            )
        ).encode(),
        strict=True,
    )


def authenticated_model_calibration_bytes(artifact: AuthenticatedModelCalibrationArtifact) -> bytes:
    """Return bounded canonical non-authorizing evidence after strict reconstruction."""

    if type(artifact) is not AuthenticatedModelCalibrationArtifact:
        raise ValueError("authenticated calibration requires its exact artifact type")
    raw = stable_json(artifact).encode()
    read_authenticated_model_calibration(raw)
    return raw


def read_authenticated_model_calibration(raw: bytes) -> AuthenticatedModelCalibrationArtifact:
    """Reading data can never manufacture the live capability required for P2 derivation."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_AUTHENTICATED_CALIBRATION_BYTES:
        raise ValueError("authenticated calibration bytes are absent or exceed the bound")
    artifact = AuthenticatedModelCalibrationArtifact.model_validate_json(raw, strict=True)
    if raw != stable_json(artifact).encode():
        raise ValueError("authenticated calibration encoding is not canonical")
    return artifact


def _observe_inputs(
    *,
    selected_model_ids: tuple[str, ...],
    benchmark_suite: ModelBenchmarkSuite,
    ground_truth: VerifiedFrozenGroundTruth,
    inputs: tuple[AuthenticatedCalibrationCandidateInputs, ...],
) -> AuthenticatedModelCalibrationArtifact:
    if (
        type(selected_model_ids) is not tuple
        or type(inputs) is not tuple
        or not 1 <= len(inputs) <= _MAX_CANDIDATES
        or len(inputs) != len(selected_model_ids)
        or any(type(item) is not AuthenticatedCalibrationCandidateInputs for item in inputs)
        or type(benchmark_suite) is not ModelBenchmarkSuite
        or type(ground_truth) is not VerifiedFrozenGroundTruth
    ):
        raise ValueError("authenticated calibration requires exact bounded live inputs")
    projection = ground_truth.require_for(
        objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
        provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
        source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
        benchmark_corpus_sha256=benchmark_suite.corpus_sha256,
        benchmark_ground_truth_sha256=benchmark_suite.ground_truth_sha256,
    )
    sources: list[AuthenticatedCalibrationCandidateSource] = []
    for item in inputs:
        collision, decisions = build_authenticated_evidence_seal_runner_inputs(
            runner_custody=item.runner_custody,
            runner_evidence=item.runner_evidence,
            benchmark_suite=benchmark_suite,
            ground_truth_projection=projection,
            runs=item.runs,
        )
        observed: list[AuthenticatedCalibrationRun] = []
        for run, decision in zip(item.runs, decisions, strict=True):
            portfolio = run.candidate_portfolio
            diagnostics = tuple(
                value
                for value in portfolio.diagnostics
                if value.exact_model_id == collision.candidate.exact_model_id
                and value.report_sha256 == decision.benchmark_report_sha256
            )
            if len(diagnostics) != 1 or portfolio.campaign_journal_sha256 is None:
                raise ValueError("authenticated calibration lacks one exact journal diagnostic")
            if portfolio.ended_at is None:
                raise ValueError("authenticated calibration candidate completion time is missing")
            observed.append(
                AuthenticatedCalibrationRun(
                    decision=decision,
                    diagnostic=diagnostics[0],
                    dimensions=tuple(run.candidate_report.results[0].dimensions),
                    candidate_registry_sha256=portfolio.candidate_registry_sha256,
                    discovery_manifest_sha256=portfolio.discovery_run_manifest_sha256,
                    campaign_journal_sha256=portfolio.campaign_journal_sha256,
                    portfolio_sha256=portfolio.portfolio_sha256,
                    policy_sha256=run.candidate_campaign_policy_sha256,
                    effective_config_sha256=run.candidate_campaign_effective_config_sha256,
                    ended_at=portfolio.ended_at,
                )
            )
        sources.append(
            AuthenticatedCalibrationCandidateSource(
                runner_evidence=item.runner_evidence, collision_map=collision, runs=tuple(observed)
            )
        )
    artifact = _assemble_artifact(selected_model_ids, tuple(sources))
    authenticated_model_calibration_bytes(artifact)
    # Earlier candidates must still be live after every later candidate was consumed.
    for item in inputs:
        require_verified_cross_lineage_runner_custody(
            item.runner_custody, evidence=item.runner_evidence
        )
    return artifact


def _policy_proposal(artifact: AuthenticatedModelCalibrationArtifact) -> QualificationPolicy:
    if (
        len(artifact.candidates) < _CALIBRATION_GLOBAL_CANDIDATE_SUPPORT
        or artifact.included_root_lineage_count < _CALIBRATION_GLOBAL_ROOT_SUPPORT
    ):
        raise ValueError("authenticated calibration lacks the required candidate/root support")
    thresholds, roles, overall = _derive_calibration_policy_components(artifact)
    _verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=thresholds,
        role_policies=roles,
        tier_a_minimum_overall_score=overall,
    )
    return seal_qualification_policy(
        created_at=artifact.created_at,
        thresholds=thresholds,
        role_policies=roles,
        tier_a_minimum_overall_score=overall,
        maximum_validity_days=_CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS,
        maximum_benchmark_evidence_age_days=_CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS,
        calibration_artifact_sha256=artifact.artifact_sha256,
        calibration_included_candidate_count=len(artifact.candidates),
        calibration_included_root_lineage_count=artifact.included_root_lineage_count,
        tier_a_overall_rationale=_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE,
    )


class VerifiedAuthenticatedModelCalibration:
    """PID-local live calibration verification; not production or release authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedAuthenticatedModelCalibration:
        del cls
        raise TypeError("authenticated calibration verification cannot be constructed directly")

    def require_for(self, artifact: AuthenticatedModelCalibrationArtifact) -> None:
        _require_verified_authenticated_model_calibration(self, artifact)

    def __copy__(self) -> Never:
        raise TypeError("authenticated calibration verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("authenticated calibration verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("authenticated calibration verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated calibration verification cannot be serialized")


@dataclass(frozen=True, slots=True)
class _VerifiedInputs:
    selected: tuple[str, ...]
    suite: ModelBenchmarkSuite
    truth: VerifiedFrozenGroundTruth
    inputs: tuple[AuthenticatedCalibrationCandidateInputs, ...]
    artifact_sha256: str


def _policy_rule_values() -> dict[str, object]:
    """Snapshot frozen numeric rules; nested shared mappings must not drift in place."""

    return {
        "native": {
            name: globals()[name]
            for name in (
                "MAX_AUTHENTICATED_CALIBRATION_BYTES",
                "_MAX_CANDIDATES",
                "_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT",
                "_CALIBRATION_GLOBAL_ROOT_SUPPORT",
                "_CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS",
                "_CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS",
                "_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE",
                "FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256",
                "FROZEN_GROUND_TRUTH_PROVENANCE_SHA256",
                "FROZEN_GROUND_TRUTH_SOURCE_REVISION",
            )
        },
        "shared": {
            name: getattr(_calibration_rules, name)
            for name in (
                "_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT",
                "_CALIBRATION_GLOBAL_ROOT_SUPPORT",
                "_CALIBRATION_ROLE_ROOT_SUPPORT",
                "_CALIBRATION_ROLE_DIMENSIONS",
                "_DETERMINISTIC_EMPIRICAL_SUPPORT_RATIONALE",
                "_JUDGMENT_EMPIRICAL_SUPPORT_RATIONALE",
                "_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE",
            )
        },
        "deterministic_dimensions": sorted(
            item.value
            for item in vars(_calibration_rules)["DETERMINISTIC_QUALIFICATION_DIMENSIONS"]
        ),
    }


def _build_calibration_authority() -> tuple[
    Callable[
        ..., tuple[AuthenticatedModelCalibrationArtifact, VerifiedAuthenticatedModelCalibration]
    ],
    Callable[..., QualificationPolicy],
    Callable[[VerifiedAuthenticatedModelCalibration, AuthenticatedModelCalibrationArtifact], None],
    Callable[[VerifiedAuthenticatedModelCalibration], None],
]:
    registry: dict[
        int, tuple[weakref.ReferenceType[VerifiedAuthenticatedModelCalibration], _VerifiedInputs]
    ] = {}
    lock = threading.RLock()
    trusted_pid = os.getpid
    owner_pid = trusted_pid()
    trusted_observe = _observe_inputs
    trusted_read = read_authenticated_model_calibration
    trusted_bytes = authenticated_model_calibration_bytes
    trusted_proposal = _policy_proposal
    trusted_truth_require = VerifiedFrozenGroundTruth.require_for
    trusted_capability_type = VerifiedAuthenticatedModelCalibration
    trusted_rule_hash = canonical_sha256(_policy_rule_values())
    shared = {
        name: getattr(_calibration_rules, name)
        for name in (
            "_derive_calibration_policy_components",
            "_derive_dimension_threshold",
            "_verify_policy_threshold_bindings",
            "calibration_distribution_sha256",
            "_required_calibration_root_lineage",
            "_require_threshold_distribution_binding",
            "_greatest_supported_nonabsolute_score",
            "_require_overall_threshold_binding",
            "_derived_supported_overall_score",
            "_require_joint_policy_support",
            "_candidate_passes_thresholds",
            "_candidate_aggregate_score",
            "_has_required_empirical_support",
        )
    }
    shared_codes = {name: value.__code__ for name, value in shared.items()}
    protected = {
        name: value
        for name, value in globals().items()
        if (
            name
            in {
                "_FrozenModel",
                "_VerifiedInputs",
                "_calibration_rules",
                "AuthenticatedCalibrationRun",
                "AuthenticatedCalibrationCandidateSource",
                "AuthenticatedCalibrationCandidateInputs",
                "AuthenticatedModelCalibrationArtifact",
                "VerifiedAuthenticatedModelCalibration",
                "VerifiedFrozenGroundTruth",
                "ModelBenchmarkSuite",
                "_required_calibration_root_lineage",
                "build_authenticated_evidence_seal_runner_inputs",
                "require_verified_cross_lineage_runner_custody",
                "canonical_sha256",
                "stable_json",
                "canonical_usd_sum",
                "_derive_calibration_policy_components",
                "_verify_policy_threshold_bindings",
                "seal_qualification_policy",
            }
            or name
            in {
                "_retained_cost",
                "_policy_rule_values",
                "_distributions",
                "_measurement_payload",
                "_assemble_artifact",
                "_observe_inputs",
                "_policy_proposal",
                "read_authenticated_model_calibration",
                "authenticated_model_calibration_bytes",
            }
        )
    }
    codes = {
        name: value.__code__ for name, value in protected.items() if hasattr(value, "__code__")
    }
    guarded_types = (
        _FrozenModel,
        _VerifiedInputs,
        AuthenticatedCalibrationCandidateInputs,
        AuthenticatedModelCalibrationArtifact,
        AuthenticatedCalibrationCandidateSource,
        AuthenticatedCalibrationRun,
        VerifiedAuthenticatedModelCalibration,
        QualificationPolicy,
    )
    methods: dict[tuple[type[object], str], FunctionType] = {}
    for cls in guarded_types:
        for method_name in vars(cls):
            method_value = getattr(cls, method_name)
            method_function = getattr(method_value, "__func__", method_value)
            if isinstance(method_function, FunctionType):
                methods[cls, method_name] = method_function
        if issubclass(cls, BaseModel):
            for name in ("model_validate_json", "model_validate", "model_dump", "model_copy"):
                method_value = getattr(cls, name)
                method_function = getattr(method_value, "__func__", method_value)
                if not isinstance(method_function, FunctionType):
                    raise TypeError("authenticated calibration model method is unavailable")
                methods[cls, name] = method_function
    method_codes = {key: value.__code__ for key, value in methods.items()}
    model_internals = {
        (cls, name): getattr(cls, name)
        for cls in guarded_types
        if issubclass(cls, BaseModel)
        for name in (
            "__pydantic_validator__",
            "__pydantic_serializer__",
            "__pydantic_core_schema__",
        )
    }
    public: dict[str, object] = {}
    public_codes: dict[str, object] = {}

    def pristine() -> None:
        namespace = globals()
        if (
            trusted_pid() != owner_pid
            or os.getpid is not trusted_pid
            or VerifiedFrozenGroundTruth.require_for is not trusted_truth_require
            or any(namespace.get(name) is not value for name, value in protected.items())
            or any(
                getattr(namespace.get(name), "__code__", None) is not code
                for name, code in codes.items()
            )
            or any(namespace.get(name) is not value for name, value in public.items())
            or any(
                getattr(namespace.get(name), "__code__", None) is not code
                for name, code in public_codes.items()
            )
            or any(
                getattr(_calibration_rules, name, None) is not value
                for name, value in shared.items()
            )
            or any(shared[name].__code__ is not code for name, code in shared_codes.items())
            or any(
                getattr(getattr(cls, name, None), "__func__", getattr(cls, name, None)) is not value
                or value.__code__ is not method_codes[cls, name]
                for (cls, name), value in methods.items()
            )
            or any(
                getattr(cls, name, None) is not value
                for (cls, name), value in model_internals.items()
            )
            or canonical_sha256(_policy_rule_values()) != trusted_rule_hash
        ):
            raise ValueError("authenticated calibration verifier is not pristine in this PID")

    def observe(
        *,
        selected_model_ids: tuple[str, ...],
        benchmark_suite: ModelBenchmarkSuite,
        ground_truth: VerifiedFrozenGroundTruth,
        inputs: tuple[AuthenticatedCalibrationCandidateInputs, ...],
    ) -> tuple[AuthenticatedModelCalibrationArtifact, VerifiedAuthenticatedModelCalibration]:
        """Measure every selected live runner, without requiring an operator signature."""

        pristine()
        artifact = trusted_observe(
            selected_model_ids=selected_model_ids,
            benchmark_suite=benchmark_suite,
            ground_truth=ground_truth,
            inputs=inputs,
        )
        pristine()
        capability = object.__new__(VerifiedAuthenticatedModelCalibration)
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[VerifiedAuthenticatedModelCalibration],
        ) -> None:
            if trusted_pid() != owner_pid:
                return
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        with lock:
            registry[key] = (
                weakref.ref(capability, discard),
                _VerifiedInputs(
                    selected_model_ids,
                    benchmark_suite,
                    ground_truth,
                    inputs,
                    artifact.artifact_sha256,
                ),
            )
        return artifact, capability

    def require(
        capability: VerifiedAuthenticatedModelCalibration,
        artifact: AuthenticatedModelCalibrationArtifact,
    ) -> None:
        pristine()
        if type(capability) is not VerifiedAuthenticatedModelCalibration:
            raise ValueError("authenticated calibration verification is absent or revoked")
        with lock:
            record = registry.get(id(capability))
            if record is None or record[0]() is not capability:
                raise ValueError("authenticated calibration verification is absent or revoked")
        validated = trusted_read(trusted_bytes(artifact))
        state = record[1]
        if validated.artifact_sha256 != state.artifact_sha256:
            raise ValueError("authenticated calibration capability belongs to other evidence")
        rebuilt = trusted_observe(
            selected_model_ids=state.selected,
            benchmark_suite=state.suite,
            ground_truth=state.truth,
            inputs=state.inputs,
        )
        if rebuilt != validated:
            raise ValueError("authenticated calibration evidence changed after observation")
        pristine()
        with lock:
            if registry.get(id(capability)) is not record:
                raise ValueError("authenticated calibration was revoked during revalidation")

    def derive(
        *,
        calibration: AuthenticatedModelCalibrationArtifact,
        verification: VerifiedAuthenticatedModelCalibration,
    ) -> QualificationPolicy:
        """Derive the fixed P2 proposal; never issue successor-release or production authority."""

        require(verification, calibration)
        validated = trusted_read(trusted_bytes(calibration))
        policy = trusted_proposal(validated)
        require(verification, calibration)
        return policy

    def revoke(capability: VerifiedAuthenticatedModelCalibration) -> None:
        # Retire the owned lease even if drift must subsequently be reported.
        # A child PID must never acquire the inherited parent registry lock.
        if trusted_pid() != owner_pid:
            raise ValueError("authenticated calibration verifier is not pristine in this PID")
        if type(capability) is not trusted_capability_type:
            raise ValueError("authenticated calibration verification is absent or revoked")
        with lock:
            record = registry.get(id(capability))
            if record is None or record[0]() is not capability:
                raise ValueError("authenticated calibration verification is absent or revoked")
            registry.pop(id(capability))
        pristine()

    public.update(
        {
            "observe_authenticated_model_calibration": observe,
            "derive_authenticated_calibration_policy": derive,
            "_require_verified_authenticated_model_calibration": require,
            "revoke_verified_authenticated_model_calibration": revoke,
        }
    )
    public_codes.update({name: getattr(value, "__code__", None) for name, value in public.items()})
    return observe, derive, require, revoke


(
    observe_authenticated_model_calibration,
    derive_authenticated_calibration_policy,
    _require_verified_authenticated_model_calibration,
    revoke_verified_authenticated_model_calibration,
) = _build_calibration_authority()
del _build_calibration_authority
