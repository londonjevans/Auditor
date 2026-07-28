from pathlib import Path

from mmaudit.benchmark.models import ModelBenchmarkDimension
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    LineageReviewStatus,
    load_candidate_registry,
    load_qualification_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def test_committed_candidate_registry_is_exact_frozen_and_unqualified() -> None:
    registry = load_candidate_registry(ROOT / "config" / "models.candidates.toml")

    assert registry.registry_sha256 == (
        "c61f857cbe44206aede6608855b30c00d38e44f77f8767d7310564825d63d5e7"
    )
    assert registry.discovery_run_sha256 == (
        "b4401140169223fb4d16b89671e0ab63fb7f448aa456885b68e056dcf48f9dca"
    )
    assert len(registry.candidates) == 12
    assert all(
        candidate.lineage_review.status is LineageReviewStatus.PENDING
        and candidate.root_lineage is None
        and candidate.benchmark_status is CandidateBenchmarkStatus.PENDING
        and candidate.benchmark_artifact_sha256 is None
        and candidate.qualification_expires_at is None
        and candidate.structured_output_supported
        and candidate.zdr_eligible
        and candidate.data_collection_deny_eligible
        and len(candidate.approved_roles) >= 24
        for candidate in registry.candidates
    )


def test_committed_tier_a_policy_is_frozen_and_non_vacuous() -> None:
    policy = load_qualification_policy(ROOT / "config" / "models.maximum-assurance.toml")

    assert policy.policy_sha256 == (
        "f36e89643bb9c74c607222ac6690a5a2dc3d2ac98f0e36b941d3d1cccc293c83"
    )
    assert policy.tier_a_minimum_overall_score == 1.0
    assert policy.maximum_validity_days == 30
    assert policy.maximum_benchmark_evidence_age_days == 7
    assert {threshold.dimension for threshold in policy.thresholds} == set(ModelBenchmarkDimension)
    assert all(threshold.minimum_cases >= 2 for threshold in policy.thresholds)
    assert all(threshold.minimum_score == 1.0 for threshold in policy.thresholds)
    structured = next(
        threshold
        for threshold in policy.thresholds
        if threshold.dimension is ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE
    )
    assert structured.minimum_cases == 16
