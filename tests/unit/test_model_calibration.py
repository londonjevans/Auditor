from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkTarget,
    load_model_benchmark_corpus,
)
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    build_model_calibration_artifact,
    load_model_calibration_artifact,
    write_model_calibration_artifact,
)
from mmaudit.models.lineage_authority import (
    TrustedModelLineageReviewVerification,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.qualification import LineageReviewStatus
from tests.unit import test_model_lineage_authority as lineage_authority_fixtures
from tests.unit import test_model_lineage_review as lineage_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
NOW = datetime(2026, 7, 27, 14, 0, tzinfo=UTC)
EFFECTIVE_CONFIG_SHA256 = "3" * 64
LINEAGE_DISCOVERED_AT = datetime(2026, 7, 27, 8, 0, tzinfo=UTC)
LINEAGE_REFRESHED_AT = datetime(2026, 7, 27, 9, 0, tzinfo=UTC)
LINEAGE_REVIEWED_AT = datetime(2026, 7, 27, 9, 30, tzinfo=UTC)
LINEAGE_CREATED_AT = datetime(2026, 7, 27, 10, 0, tzinfo=UTC)
LINEAGE_EXPIRES_AT = datetime(2026, 8, 6, 10, 0, tzinfo=UTC)
LINEAGE_SIGNED_AT = datetime(2026, 7, 27, 10, 5, tzinfo=UTC)
LINEAGE_AUTHORITY_EXPIRES_AT = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)


def _signed_lineage_inputs(
    tmp_path: Path,
    *,
    label: str = "alpha",
    status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    reviewed_at: datetime = LINEAGE_REVIEWED_AT,
    created_at: datetime = LINEAGE_CREATED_AT,
) -> tuple[
    lineage_fixtures._Bundle,
    ModelLineageReviewArtifact,
    TrustedModelLineageReviewVerification,
]:
    with patch.multiple(
        lineage_fixtures,
        DISCOVERED_AT=LINEAGE_DISCOVERED_AT,
        REFRESHED_AT=LINEAGE_REFRESHED_AT,
        CREATED_AT=created_at,
        EXPIRES_AT=LINEAGE_EXPIRES_AT,
    ):
        bundle = lineage_fixtures._bundle((qualification_fixtures.MODEL_ID,))
        review = lineage_fixtures._review(
            (qualification_fixtures.MODEL_ID,),
            label=label,
            status=status,
            reviewed_at=reviewed_at,
        )
        artifact = lineage_fixtures._artifact(bundle, (review,))

    signing_root = tmp_path / f"lineage-signing-{label}-{status.value}"
    signing_root.mkdir(mode=0o700, parents=True)
    signed_at = max(LINEAGE_SIGNED_AT, created_at + timedelta(minutes=5))
    _anchor, _envelope, capability = lineage_authority_fixtures._signed_authority(
        root=signing_root,
        artifact=artifact,
        signed_at=signed_at,
        expires_at=LINEAGE_AUTHORITY_EXPIRES_AT,
    )
    return bundle, artifact, capability


async def _complete_inputs(
    tmp_path: Path,
    *,
    label: str = "alpha",
    status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    reviewed_at: datetime = LINEAGE_REVIEWED_AT,
    created_at: datetime = LINEAGE_CREATED_AT,
    schema_failure_case: str | None = None,
):
    bundle, lineage_artifact, lineage_capability = _signed_lineage_inputs(
        tmp_path,
        label=label,
        status=status,
        reviewed_at=reviewed_at,
        created_at=created_at,
    )
    candidate = bundle.registry.candidates[0]
    unverified_report = await qualification_fixtures._mock_report(
        target=ModelBenchmarkTarget(
            model_id=candidate.exact_model_id,
            root_lineage=None,
        ),
        schema_failure_case=schema_failure_case,
    )
    report = (
        qualification_fixtures._as_real_report(unverified_report, candidate=candidate)
        if schema_failure_case is None
        else unverified_report
    )
    portfolio, capability = qualification_fixtures._portfolio_evidence(
        registry=bundle.registry,
        report=report,
    )
    return (
        bundle.manifest,
        bundle.registry,
        report,
        portfolio,
        capability,
        lineage_artifact,
        lineage_capability,
    )


@pytest.mark.asyncio
async def test_calibration_is_non_dispositive_exact_and_canonical(tmp_path: Path) -> None:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await _complete_inputs(tmp_path)
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = qualification_fixtures._policy()

    artifact = build_model_calibration_artifact(
        created_at=NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )

    source_candidate = registry.candidates[0]
    lineage_binding = lineage_artifact.candidate_bindings[0]
    assert source_candidate.root_lineage is None
    assert source_candidate.lineage_review.status is LineageReviewStatus.PENDING
    assert artifact.candidate_registry_sha256 == registry.registry_sha256
    assert artifact.discovery_manifest_sha256 == manifest.manifest_sha256
    assert artifact.benchmark_portfolio_sha256 == portfolio.portfolio_sha256
    assert artifact.lineage_review_artifact_sha256 == lineage_artifact.artifact_sha256
    assert tuple(item.exact_model_id for item in artifact.candidates) == (
        source_candidate.exact_model_id,
    )
    assert artifact.candidates[0].included_in_distribution
    assert artifact.candidates[0].root_lineage == lineage_binding.root_lineage
    assert artifact.candidates[0].lineage_binding_sha256 == lineage_binding.binding_sha256
    assert artifact.candidates[0].exclusion_reasons == ()
    assert len(artifact.candidates[0].dimensions) == len(ModelBenchmarkDimension)
    assert portfolio.started_at is not None
    verified_lineage = lineage_capability.require_for(
        candidate_registry=registry,
        discovery_manifest=manifest,
        campaign_started_at=portfolio.started_at,
        observed_at=NOW,
    )
    assert artifact.lineage_authority_envelope_sha256 == verified_lineage.authority_envelope_sha256
    assert {item.dimension for item in artifact.distributions} == set(ModelBenchmarkDimension)
    assert all(
        distribution.candidate_count == 1
        and distribution.included_candidate_count == 1
        and distribution.excluded_candidate_count == 0
        and len(distribution.observations) == 1
        for distribution in artifact.distributions
    )
    assert "disposition" not in artifact.model_dump_json()

    output = tmp_path / "calibration.json"
    write_model_calibration_artifact(output, artifact)
    assert output.stat().st_mode & 0o777 == 0o600
    assert load_model_calibration_artifact(output) == artifact
    with pytest.raises(ValueError, match="fresh file"):
        write_model_calibration_artifact(output, artifact)


@pytest.mark.asyncio
async def test_failed_candidate_is_retained_but_never_enters_distributions(
    tmp_path: Path,
) -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = qualification_fixtures._policy()
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await _complete_inputs(
        tmp_path,
        label="failed-candidate",
        schema_failure_case=suite.cases[0].case_id,
    )

    artifact = build_model_calibration_artifact(
        created_at=NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )

    assert len(artifact.candidates) == 1
    assert not artifact.candidates[0].included_in_distribution
    assert artifact.candidates[0].dimensions == ()
    assert artifact.candidates[0].overall_score is None
    assert artifact.candidates[0].exclusion_reasons
    assert all(
        distribution.candidate_count == 1
        and distribution.included_candidate_count == 0
        and distribution.excluded_candidate_count == 1
        and distribution.observations == ()
        for distribution in artifact.distributions
    )


@pytest.mark.asyncio
async def test_calibration_rejects_capability_binding_drift_and_disposition_field(
    tmp_path: Path,
) -> None:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await _complete_inputs(tmp_path)
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = qualification_fixtures._policy()

    with pytest.raises(ValueError, match="trusted campaign verification"):
        build_model_calibration_artifact(
            created_at=NOW,
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            benchmark_suite=suite,
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            benchmark_policy_sha256=policy.policy_sha256,
            effective_config_sha256="4" * 64,
            trusted_campaign_verification=campaign_capability,
            lineage_review_artifact=lineage_artifact,
            trusted_lineage_verification=lineage_capability,
        )

    artifact = build_model_calibration_artifact(
        created_at=NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )
    payload = artifact.model_dump(mode="json")
    payload["disposition"] = "tier_a"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ModelCalibrationArtifact.model_validate(payload)

    payload = artifact.model_dump(mode="json")
    payload["effective_config_sha256"] = "4" * 64
    with pytest.raises(ValidationError, match="self-hash"):
        ModelCalibrationArtifact.model_validate(payload)


@pytest.mark.asyncio
async def test_self_sealed_candidate_root_cannot_receive_calibration_credit(
    tmp_path: Path,
) -> None:
    manifest, _evidence, registry = qualification_fixtures._candidate_inputs()
    candidate = registry.candidates[0]
    assert candidate.root_lineage is not None
    assert candidate.lineage_review.status is LineageReviewStatus.APPROVED
    report = qualification_fixtures._as_real_report(
        await qualification_fixtures._mock_report(),
        candidate=candidate,
    )
    policy = qualification_fixtures._policy()
    portfolio, campaign_capability = qualification_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
        policy=policy,
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    _bundle, lineage_artifact, lineage_capability = _signed_lineage_inputs(
        tmp_path,
        label="self-sealed-boundary",
    )

    with pytest.raises(ValueError, match="lineage review differs from the exact candidate"):
        build_model_calibration_artifact(
            created_at=NOW,
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            benchmark_suite=suite,
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            benchmark_policy_sha256=policy.policy_sha256,
            effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
            trusted_campaign_verification=campaign_capability,
            lineage_review_artifact=lineage_artifact,
            trusted_lineage_verification=lineage_capability,
        )


@pytest.mark.asyncio
async def test_authenticated_rejected_lineage_is_retained_without_credit(
    tmp_path: Path,
) -> None:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await _complete_inputs(
        tmp_path,
        label="rejected",
        status=LineageReviewStatus.REJECTED,
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = qualification_fixtures._policy()

    artifact = build_model_calibration_artifact(
        created_at=NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )

    observation = artifact.candidates[0]
    assert not observation.included_in_distribution
    assert observation.root_lineage is None
    assert "root_lineage_not_approved" in {reason.value for reason in observation.exclusion_reasons}
    assert artifact.included_root_lineage_count == 0


@pytest.mark.asyncio
async def test_authenticated_post_campaign_lineage_authority_is_rejected(
    tmp_path: Path,
) -> None:
    post_campaign_reviewed_at = datetime(2026, 7, 27, 12, 30, tzinfo=UTC)
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await _complete_inputs(
        tmp_path,
        label="post-campaign",
        reviewed_at=post_campaign_reviewed_at,
        created_at=datetime(2026, 7, 27, 13, 0, tzinfo=UTC),
    )
    assert portfolio.started_at is not None
    assert post_campaign_reviewed_at > portfolio.started_at

    with pytest.raises(ValueError, match="trusted lineage verification does not bind"):
        build_model_calibration_artifact(
            created_at=NOW,
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            benchmark_policy_sha256=qualification_fixtures._policy().policy_sha256,
            effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
            trusted_campaign_verification=campaign_capability,
            lineage_review_artifact=lineage_artifact,
            trusted_lineage_verification=lineage_capability,
        )


@pytest.mark.asyncio
async def test_calibration_rejects_mismatched_signed_lineage_authority(
    tmp_path: Path,
) -> None:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        _lineage_capability,
    ) = await _complete_inputs(tmp_path, label="original-authority")
    alternate_bundle, alternate_artifact, alternate_capability = _signed_lineage_inputs(
        tmp_path,
        label="alternate-authority",
    )
    assert alternate_bundle.registry == registry
    assert alternate_bundle.manifest == manifest
    assert alternate_artifact.artifact_sha256 != lineage_artifact.artifact_sha256

    with pytest.raises(ValueError, match="differs from the supplied artifact"):
        build_model_calibration_artifact(
            created_at=NOW,
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            benchmark_policy_sha256=qualification_fixtures._policy().policy_sha256,
            effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
            trusted_campaign_verification=campaign_capability,
            lineage_review_artifact=lineage_artifact,
            trusted_lineage_verification=alternate_capability,
        )


def test_published_calibration_schema_requires_authenticated_lineage_bindings() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "model_calibration.schema.json").read_text(encoding="utf-8")
    )

    assert schema["properties"]["schema_version"]["const"] == "2.0"
    assert {
        "lineage_review_artifact_sha256",
        "lineage_authority_envelope_sha256",
    } <= set(schema["required"])
    candidate = schema["$defs"]["ModelCalibrationCandidateObservation"]
    assert "lineage_binding_sha256" in candidate["required"]
