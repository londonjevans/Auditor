from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.model_portfolio import (
    create_candidate_benchmark_campaign,
    issue_trusted_candidate_benchmark_campaign_verification,
    seal_model_benchmark_portfolio_from_campaign,
)
from mmaudit.benchmark.models import ModelBenchmarkDimension, load_model_benchmark_corpus
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    build_model_calibration_artifact,
    load_model_calibration_artifact,
    write_model_calibration_artifact,
)
from mmaudit.models.candidate_benchmark import run_candidate_registry_benchmarks
from mmaudit.models.qualification import (
    CandidateModel,
    LineageReviewStatus,
    load_qualification_policy,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.usage import UsageLedger
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"
NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
EFFECTIVE_CONFIG_SHA256 = "3" * 64


async def _complete_inputs():
    manifest, _evidence, registry = qualification_fixtures._candidate_inputs()
    report = qualification_fixtures._as_real_report(
        await qualification_fixtures._mock_report(),
        candidate=registry.candidates[0],
    )
    portfolio, capability = qualification_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
    )
    return manifest, registry, report, portfolio, capability


@pytest.mark.asyncio
async def test_calibration_is_non_dispositive_exact_and_canonical(tmp_path: Path) -> None:
    manifest, registry, report, portfolio, capability = await _complete_inputs()
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
        trusted_campaign_verification=capability,
    )

    assert artifact.candidate_registry_sha256 == registry.registry_sha256
    assert artifact.discovery_manifest_sha256 == manifest.manifest_sha256
    assert artifact.benchmark_portfolio_sha256 == portfolio.portfolio_sha256
    assert tuple(item.exact_model_id for item in artifact.candidates) == (
        registry.candidates[0].exact_model_id,
    )
    assert artifact.candidates[0].included_in_distribution
    assert artifact.candidates[0].exclusion_reasons == ()
    assert len(artifact.candidates[0].dimensions) == len(ModelBenchmarkDimension)
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
    config_factory,
) -> None:
    config = candidate_fixtures._config(config_factory)
    model_id = "alpha/atlas-calibration"
    manifest, _evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model_id,
                provider_endpoint="provider-alpha",
                provider_name="Provider Alpha",
            ),
        ),
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    budget = candidate_fixtures._budget(tmp_path / "ledger", config)
    assert budget.atomic_ledger is not None
    journal = create_candidate_benchmark_campaign(
        tmp_path / "campaign",
        candidate_registry=registry,
        corpus=suite,
        effective_config_sha256=config.stable_hash(),
        qualification_policy_sha256=policy.policy_sha256,
        cost_ledger=budget.atomic_ledger,
    )
    factory = candidate_fixtures._MockClientFactory(failing_models={model_id})
    try:
        execution = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=manifest,
            discovery_evidence=_evidence,
            candidate_registry=registry,
            benchmark_suite=suite,
            budget=budget,
            usage=UsageLedger(),
            operator_api_key="synthetic-canary",
            explicitly_allow_synthetic_egress=True,
            client_factory=factory,
            evidence_sink=journal,
            qualification_policy=policy,
        )
    finally:
        await factory.close()
    portfolio = seal_model_benchmark_portfolio_from_campaign(
        tmp_path / "portfolio",
        campaign=journal,
    )
    capability = issue_trusted_candidate_benchmark_campaign_verification(
        campaign=journal,
        portfolio=portfolio,
        reports=execution.reports,
    )

    artifact = build_model_calibration_artifact(
        created_at=(
            NOW if portfolio.ended_at is None else portfolio.ended_at.replace(microsecond=0)
        ),
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=execution.reports,
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=config.stable_hash(),
        trusted_campaign_verification=capability,
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
async def test_calibration_rejects_capability_binding_drift_and_disposition_field() -> None:
    manifest, registry, report, portfolio, capability = await _complete_inputs()
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
            trusted_campaign_verification=capability,
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
        trusted_campaign_verification=capability,
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
async def test_future_lineage_review_is_retained_but_receives_no_calibration_credit() -> None:
    manifest, registry, report, _portfolio, _capability = await _complete_inputs()
    candidate = registry.candidates[0]
    assert candidate.root_lineage is not None
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(candidate.exact_model_id,),
        root_lineage=candidate.root_lineage,
        rationale="Synthetic future-dated lineage review for negative regression.",
        reviewed_by="test-operator",
        reviewed_at=datetime(2030, 1, 1, tzinfo=UTC),
        evidence_sha256="7" * 64,
    )
    future_candidate = CandidateModel.model_validate(
        candidate.model_copy(update={"lineage_review": review}).model_dump(mode="json")
    )
    future_registry = seal_candidate_registry(
        created_at=registry.created_at,
        discovery_run_sha256=registry.discovery_run_sha256,
        candidates=(future_candidate,),
    )
    policy = qualification_fixtures._policy()
    portfolio, capability = qualification_fixtures._portfolio_evidence(
        registry=future_registry,
        report=report,
        policy=policy,
    )
    suite = load_model_benchmark_corpus(CORPUS_PATH)

    artifact = build_model_calibration_artifact(
        created_at=NOW,
        candidate_registry=future_registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=policy.policy_sha256,
        effective_config_sha256=EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=capability,
    )

    observation = artifact.candidates[0]
    assert not observation.included_in_distribution
    assert "root_lineage_review_postdates_campaign" in {
        reason.value for reason in observation.exclusion_reasons
    }
    assert artifact.included_root_lineage_count == 0
