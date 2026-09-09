"""Exact source-manifest development measurements, never inferred or authoritative ground truth."""

from __future__ import annotations

import hashlib
import re
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development import (
    _WEIGHTS,
    DevelopmentBenchmarkSummary,
    DevelopmentClaimMeasurement,
    DevelopmentMeasurementRatio,
    DevelopmentTruthControl,
    match_development_control,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusManifest,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusRootCauseReference,
    DevelopmentCorpusShardObservation,
)
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import _decode_json
from mmaudit.repository.redaction import detect_secrets

MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES = 2_000_000
MAX_DEVELOPMENT_CORPUS_SCORE_BYTES = 32_000_000
_SHA = r"^[0-9a-f]{64}$"
_CLAIM = r"^file-00(?:0[1-9]|[1-5][0-9]|6[0-4]):(?:0[1-9]|1[0-6])$"


class DevelopmentCorpusTruthControl(DevelopmentTruthControl):
    origin: DevelopmentCorpusRootCauseReference
    required_origin_line: int = Field(ge=1, le=10_000)
    claim_sites: tuple[DevelopmentCorpusRootCauseReference, ...] = Field(
        min_length=1, max_length=64
    )


class DevelopmentCorpusBenchmarkTruth(_AuditArtifact):
    """Caller-supplied labels; neither the declaration nor a hash proves external authorship."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_truth"] = "development_corpus_truth"
    truth_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    provenance: Literal[
        "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS", "OPERATOR_SUPPLIED_DEVELOPMENT_LABELS"
    ]
    truth_scope: Literal["DECLARED_LABELS_NOT_VERIFIED_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH"] = (
        "DECLARED_LABELS_NOT_VERIFIED_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH"
    )
    root_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    manifest: DevelopmentCorpusManifest
    controls: tuple[DevelopmentCorpusTruthControl, ...] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def controls_are_unique_and_inside_the_exact_source(self) -> Self:
        ids = tuple(c.control_id for c in self.controls)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("manifest truth control IDs must be unique and sorted")
        sources = {s.filename: s for s in self.manifest.sources}
        if any(
            ref.filename not in sources or ref.line_end > sources[ref.filename].line_count
            for control in self.controls
            for ref in (control.origin, *control.claim_sites)
        ):
            raise ValueError("manifest truth reference is outside the selected source")
        if detect_secrets(self.model_dump_json()):
            raise ValueError("manifest truth contains secret-like data")
        return self


def read_development_corpus_truth(
    content: bytes, *, expected_sha256: str
) -> DevelopmentCorpusBenchmarkTruth:
    """Require bounded exact selected bytes before parsing; never derive labels from responses."""

    if (
        type(content) is not bytes
        or not 0 < len(content) <= MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES
        or type(expected_sha256) is not str
        or re.fullmatch(_SHA, expected_sha256) is None
        or hashlib.sha256(content).hexdigest() != expected_sha256
    ):
        raise ValueError("manifest truth differs from its bounded selected bytes")
    content.decode("utf-8")
    try:
        decoded = _decode_json(content)
    except (RecursionError, OverflowError):
        raise ValueError("manifest truth JSON exceeds the parser's structural bound") from None
    if type(decoded) is not dict:
        raise ValueError("manifest truth must be an unambiguous JSON object")
    return DevelopmentCorpusBenchmarkTruth.model_validate_json(content, strict=True)


class DevelopmentCorpusBenchmarkBinding(_AuditArtifact):
    """Keep raw and typed labels together; retained pre-dispatch custody is not external authority."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_benchmark_binding"] = (
        "development_corpus_benchmark_binding"
    )
    scorer_version: Literal["manifest-structural-controls-v1"] = "manifest-structural-controls-v1"
    plan_sha256: str = Field(pattern=_SHA)
    truth_file_sha256: str = Field(pattern=_SHA)
    truth_file_content: str = Field(min_length=1, max_length=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES)
    truth: DevelopmentCorpusBenchmarkTruth

    @model_validator(mode="after")
    def original_label_bytes_and_typed_truth_agree(self) -> Self:
        if self.truth != read_development_corpus_truth(
            self.truth_file_content.encode("utf-8"), expected_sha256=self.truth_file_sha256
        ):
            raise ValueError("manifest benchmark changes its original label bytes")
        return self


def bind_development_corpus_benchmark(
    *, plan: DevelopmentCorpusPlan, truth_content: bytes, expected_truth_sha256: str
) -> DevelopmentCorpusBenchmarkBinding:
    """Bind the complete source plan before dispatch without inserting labels into requests."""

    if type(plan) is not DevelopmentCorpusPlan:
        raise ValueError("manifest benchmark requires its exact candidate plan")
    plan = DevelopmentCorpusPlan.model_validate_json(plan.model_dump_json(), strict=True)
    truth = read_development_corpus_truth(truth_content, expected_sha256=expected_truth_sha256)
    if plan.manifest != truth.manifest:
        raise ValueError("manifest benchmark labels and candidate source differ")
    return DevelopmentCorpusBenchmarkBinding(
        plan_sha256=plan.plan_sha256,
        truth_file_sha256=expected_truth_sha256,
        truth_file_content=truth_content.decode("utf-8"),
        truth=truth,
    )


class DevelopmentCorpusMeasurementRatio(DevelopmentMeasurementRatio):
    numerator: int = Field(ge=0, le=10_240)
    denominator: int = Field(ge=0, le=10_240)


def _ratio(
    numerator: int, denominator: int, *, complete: bool
) -> DevelopmentCorpusMeasurementRatio:
    return DevelopmentCorpusMeasurementRatio(
        numerator=numerator,
        denominator=denominator,
        state="INCOMPLETE_SCOPE"
        if not complete
        else "OBSERVED"
        if denominator
        else "EMPTY_DENOMINATOR",
        value=round(numerator / denominator, 6) if complete and denominator else None,
    )


class DevelopmentCorpusClaimMeasurement(DevelopmentClaimMeasurement):
    claim_id: str = Field(pattern=_CLAIM)


class DevelopmentCorpusBenchmarkSummary(DevelopmentBenchmarkSummary):
    total_claim_count: int = Field(ge=0, le=1024)
    invariant_claim_count: int = Field(ge=0, le=1024)
    advisory_claim_count: int = Field(ge=0, le=1024)
    advisories_at_planted_sites_count: int = Field(ge=0, le=1024)
    duplicate_claim_count: int = Field(ge=0, le=1024)
    unmatched_invariant_claim_count: int = Field(ge=0, le=1024)
    guarded_control_claim_count: int = Field(ge=0, le=1024)
    expected_root_ids: tuple[str, ...] = Field(max_length=1024)
    matched_root_ids: tuple[str, ...] = Field(max_length=1024)
    unmatched_expected_root_ids: tuple[str, ...] = Field(max_length=1024)
    observed_missed_root_ids: tuple[str, ...] = Field(max_length=1024)
    unobserved_root_ids: tuple[str, ...] = Field(max_length=1024)
    unique_root_recall: DevelopmentCorpusMeasurementRatio
    severity_weighted_root_recall: DevelopmentCorpusMeasurementRatio
    all_claim_unique_root_fraction: DevelopmentCorpusMeasurementRatio
    severity_weighted_structural_precision: DevelopmentCorpusMeasurementRatio
    first_attempt_shard_completion: DevelopmentCorpusMeasurementRatio
    unobserved_shard_ids: tuple[str, ...] = Field(max_length=64)
    missing_accounting_shard_ids: tuple[str, ...] = Field(max_length=64)
    unknown_actual_cost_shard_ids: tuple[str, ...] = Field(max_length=64)
    missing_shard_runtime_ids: tuple[str, ...] = Field(max_length=64)


class DevelopmentCorpusClaimSummary(_DevelopmentModel):
    """Shared structural measurements, independent of first-attempt or cumulative accounting."""

    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    total_claim_count: int = Field(ge=0, le=1024)
    invariant_claim_count: int = Field(ge=0, le=1024)
    advisory_claim_count: int = Field(ge=0, le=1024)
    advisories_at_planted_sites_count: int = Field(ge=0, le=1024)
    duplicate_claim_count: int = Field(ge=0, le=1024)
    unmatched_invariant_claim_count: int = Field(ge=0, le=1024)
    guarded_control_claim_count: int = Field(ge=0, le=1024)
    expected_root_ids: tuple[str, ...] = Field(max_length=1024)
    matched_root_ids: tuple[str, ...] = Field(max_length=1024)
    unmatched_expected_root_ids: tuple[str, ...] = Field(max_length=1024)
    observed_missed_root_ids: tuple[str, ...] = Field(max_length=1024)
    unobserved_root_ids: tuple[str, ...] = Field(max_length=1024)
    unique_root_recall: DevelopmentCorpusMeasurementRatio
    severity_weighted_root_recall: DevelopmentCorpusMeasurementRatio
    all_claim_unique_root_fraction: DevelopmentCorpusMeasurementRatio
    severity_weighted_structural_precision: DevelopmentCorpusMeasurementRatio


def _measure_corpus_claims(
    truth: DevelopmentCorpusBenchmarkTruth,
    observations: tuple[DevelopmentCorpusShardObservation, ...],
    *,
    complete: bool,
) -> tuple[tuple[DevelopmentCorpusClaimMeasurement, ...], DevelopmentCorpusClaimSummary]:
    """Keep one exact label-matching policy for original and cumulative measurements."""

    claims: list[DevelopmentCorpusClaimMeasurement] = []
    matched: set[str] = set()
    observed_files: set[str] = set()
    for shard in observations:
        if shard.status != "OBSERVED":
            continue
        observed_files.add(shard.source_filename)
        assert shard.response is not None
        for index, finding in enumerate(shard.response.findings, 1):
            control = match_development_control(truth.controls, shard.source_filename, finding)
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
                DevelopmentCorpusClaimMeasurement(
                    claim_id=f"{shard.shard_id}:{index:02d}",
                    disposition=disposition,
                    control_id=control.control_id if control is not None else None,
                    weight=_WEIGHTS[control.severity if control is not None else finding.severity],
                )
            )
    roots = tuple(c for c in truth.controls if c.expected == "PLANTED")
    misses = tuple(c for c in roots if c.control_id not in matched)
    matched_weight = sum(_WEIGHTS[c.severity] for c in roots if c.control_id in matched)
    advisories = sum(c.disposition in {"ADVISORY", "ADVISORY_AT_PLANTED_SITE"} for c in claims)
    summary = DevelopmentCorpusClaimSummary(
        quality_scope="COMPLETE_OBSERVATIONS" if complete else "INCOMPLETE_OBSERVATIONS",
        total_claim_count=len(claims),
        invariant_claim_count=len(claims) - advisories,
        advisory_claim_count=advisories,
        advisories_at_planted_sites_count=sum(
            c.disposition == "ADVISORY_AT_PLANTED_SITE" for c in claims
        ),
        duplicate_claim_count=sum(c.disposition == "DUPLICATE_OR_CONSEQUENCE" for c in claims),
        unmatched_invariant_claim_count=sum(
            c.disposition in {"UNMATCHED_INVARIANT", "GUARDED_CONTROL_CLAIM"} for c in claims
        ),
        guarded_control_claim_count=sum(c.disposition == "GUARDED_CONTROL_CLAIM" for c in claims),
        expected_root_ids=tuple(c.control_id for c in roots),
        matched_root_ids=tuple(c.control_id for c in roots if c.control_id in matched),
        unmatched_expected_root_ids=tuple(c.control_id for c in misses),
        observed_missed_root_ids=tuple(
            c.control_id for c in misses if all(s.filename in observed_files for s in c.claim_sites)
        ),
        unobserved_root_ids=tuple(
            c.control_id
            for c in misses
            if any(s.filename not in observed_files for s in c.claim_sites)
        ),
        unique_root_recall=_ratio(len(matched), len(roots), complete=complete),
        severity_weighted_root_recall=_ratio(
            matched_weight, sum(_WEIGHTS[c.severity] for c in roots), complete=complete
        ),
        all_claim_unique_root_fraction=_ratio(len(matched), len(claims), complete=complete),
        severity_weighted_structural_precision=_ratio(
            matched_weight, sum(c.weight for c in claims), complete=complete
        ),
    )
    return tuple(claims), summary


def _measure(
    binding: DevelopmentCorpusBenchmarkBinding, observation: DevelopmentCorpusObservation
) -> tuple[tuple[DevelopmentCorpusClaimMeasurement, ...], DevelopmentCorpusBenchmarkSummary]:
    if binding != bind_development_corpus_benchmark(
        plan=observation.plan,
        truth_content=binding.truth_file_content.encode("utf-8"),
        expected_truth_sha256=binding.truth_file_sha256,
    ):
        raise ValueError("manifest score differs from its pre-dispatch binding")
    claims, quality = _measure_corpus_claims(
        binding.truth,
        observation.observations,
        complete=observation.status == "OBSERVED_ALL_SHARDS",
    )
    expected = tuple(s.shard_id for s in observation.plan.shards)
    accounted = {a.shard_id for a in observation.accounting}
    timed = {s.shard_id for s in observation.observations}
    summary = DevelopmentCorpusBenchmarkSummary(
        **quality.model_dump(),
        first_attempt_shard_completion=_ratio(
            observation.completed_shard_count, len(expected), complete=True
        ),
        unobserved_shard_ids=observation.unobserved_shard_ids,
        missing_accounting_shard_ids=tuple(s for s in expected if s not in accounted),
        unknown_actual_cost_shard_ids=tuple(
            a.shard_id
            for a in observation.accounting
            if a.status is not CostEntryStatus.RELEASED and a.actual_cost_usd is None
        ),
        missing_shard_runtime_ids=tuple(s for s in expected if s not in timed),
        reported_actual_cost_usd=observation.reported_actual_cost_usd,
        accounted_cost_usd=observation.total_accounted_cost_usd,
        uncertain_accounted_cost_usd=observation.uncertain_accounted_cost_usd,
        active_reserved_usd=observation.active_reserved_usd,
        elapsed_seconds=observation.elapsed_seconds,
    )
    return tuple(claims), summary


class DevelopmentCorpusBenchmarkScore(_AuditArtifact):
    """Recomputed original-claim measurements, never filtered by model review opinions."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_benchmark_score"] = (
        "development_corpus_benchmark_score"
    )
    interpretation: Literal["STRUCTURAL_LABEL_MATCHES_NOT_VALIDATED_FINDINGS"] = (
        "STRUCTURAL_LABEL_MATCHES_NOT_VALIDATED_FINDINGS"
    )
    root_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    binding: DevelopmentCorpusBenchmarkBinding
    observation: DevelopmentCorpusObservation
    observation_sha256: str = Field(pattern=_SHA)
    claims: tuple[DevelopmentCorpusClaimMeasurement, ...] = Field(max_length=1024)
    summary: DevelopmentCorpusBenchmarkSummary

    @model_validator(mode="after")
    def exact_original_inputs_reproduce_every_measurement(self) -> Self:
        if self.observation_sha256 != canonical_sha256(self.observation.model_dump(mode="json")):
            raise ValueError("manifest score observation digest differs")
        material = self.observation.model_dump_json()
        if len(material.encode()) > MAX_DEVELOPMENT_CORPUS_RESULT_BYTES or detect_secrets(material):
            raise ValueError(
                "manifest score candidate exceeds its bound or contains secret-like data"
            )
        if (self.claims, self.summary) != _measure(self.binding, self.observation):
            raise ValueError("manifest score does not reproduce from its original inputs")
        return self


def score_development_corpus(
    *, binding: DevelopmentCorpusBenchmarkBinding, observation: DevelopmentCorpusObservation
) -> DevelopmentCorpusBenchmarkScore:
    """Measure the unchanged candidate once; no provider, semantic truth inference or audit pass."""

    if (
        type(binding) is not DevelopmentCorpusBenchmarkBinding
        or type(observation) is not DevelopmentCorpusObservation
    ):
        raise ValueError("manifest scoring requires exact binding and candidate types")
    material = observation.model_dump_json()
    if len(material.encode()) > MAX_DEVELOPMENT_CORPUS_RESULT_BYTES or detect_secrets(material):
        raise ValueError("manifest score candidate exceeds its bound or contains secret-like data")
    observation = DevelopmentCorpusObservation.model_validate_json(material, strict=True)
    binding = DevelopmentCorpusBenchmarkBinding.model_validate_json(
        binding.model_dump_json(), strict=True
    )
    claims, summary = _measure(binding, observation)
    return DevelopmentCorpusBenchmarkScore(
        binding=binding,
        observation=observation,
        observation_sha256=canonical_sha256(observation.model_dump(mode="json")),
        claims=claims,
        summary=summary,
    )
