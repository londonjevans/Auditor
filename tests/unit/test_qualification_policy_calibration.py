from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.models.calibration as calibration_module
import mmaudit.models.qualification as qualification_module
from mmaudit.benchmark.models import ModelBenchmarkDimension, load_model_benchmark_corpus
from mmaudit.models.calibration import (
    TrustedModelCalibrationVerification,
    build_model_calibration_artifact,
    issue_trusted_model_calibration_verification,
    seal_calibrated_qualification_policy,
)
from mmaudit.models.qualification import (
    QualificationDimensionThreshold,
    QualificationRoleClass,
    QualificationThresholdBasis,
    RoleQualificationPolicy,
    load_qualification_policy,
    seal_qualification_policy,
    verify_model_qualification,
)
from tests.unit import test_model_calibration as calibration_fixtures
from tests.unit import test_model_qualification as qualification_fixtures
from tests.unit import test_qualification_workflow as workflow_fixtures

ROOT = Path(__file__).parents[2]
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
NOW = datetime(2026, 7, 30, 13, 0, tzinfo=UTC)
_DISTRIBUTION_SHA256 = "9" * 64
_DETERMINISTIC_DIMENSIONS = frozenset(
    {
        ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
        ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE,
        ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE,
    }
)
_ROLE_DIMENSIONS = {
    QualificationRoleClass.INVESTIGATOR: (
        ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
        ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION,
        ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING,
    ),
    QualificationRoleClass.VERIFIER: (ModelBenchmarkDimension.VERIFIER_QUALITY,),
    QualificationRoleClass.FALSIFIER: (ModelBenchmarkDimension.FALSIFIER_QUALITY,),
    QualificationRoleClass.JUDGE: (
        ModelBenchmarkDimension.FALSIFIER_QUALITY,
        ModelBenchmarkDimension.REPORT_QUALITY,
        ModelBenchmarkDimension.VERIFIER_QUALITY,
    ),
}


def _threshold(
    dimension: ModelBenchmarkDimension,
    *,
    minimum_cases: int | None = None,
    minimum_score: float | None = None,
) -> QualificationDimensionThreshold:
    deterministic = dimension in _DETERMINISTIC_DIMENSIONS
    return QualificationDimensionThreshold(
        dimension=dimension,
        minimum_cases=minimum_cases if minimum_cases is not None else (2 if deterministic else 4),
        minimum_score=minimum_score
        if minimum_score is not None
        else (1.0 if deterministic else 0.75),
        basis=(
            QualificationThresholdBasis.DETERMINISTIC_REQUIREMENT
            if deterministic
            else QualificationThresholdBasis.CALIBRATED_DISTRIBUTION
        ),
        rationale=f"Measured calibration rationale for {dimension.value}.",
        calibration_distribution_sha256=_DISTRIBUTION_SHA256,
    )


def _thresholds() -> tuple[QualificationDimensionThreshold, ...]:
    return tuple(
        _threshold(dimension)
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )


def _role_policies() -> tuple[RoleQualificationPolicy, ...]:
    return tuple(
        RoleQualificationPolicy(
            role_class=role_class,
            thresholds=tuple(_threshold(dimension) for dimension in _ROLE_DIMENSIONS[role_class]),
            minimum_overall_score=0.75,
            minimum_overall_rationale=(
                f"Measured aggregate calibration rationale for {role_class.value}."
            ),
        )
        for role_class in sorted(QualificationRoleClass, key=lambda item: item.value)
    )


def _seal_structural_v2(
    *,
    thresholds: tuple[QualificationDimensionThreshold, ...] | None = None,
    role_policies: tuple[RoleQualificationPolicy, ...] | None = None,
    included_root_lineages: int = 3,
):
    return seal_qualification_policy(
        created_at=NOW,
        thresholds=thresholds or _thresholds(),
        role_policies=role_policies or _role_policies(),
        calibration_artifact_sha256="8" * 64,
        calibration_included_candidate_count=3,
        calibration_included_root_lineage_count=included_root_lineages,
        tier_a_minimum_overall_score=0.75,
        tier_a_overall_rationale="Measured aggregate calibration rationale for global Tier A.",
        maximum_validity_days=30,
    )


def test_frozen_v1_policy_shape_and_hash_remain_exact() -> None:
    policy = load_qualification_policy(POLICY_PATH)
    payload = policy.model_dump(mode="json")

    assert policy.schema_version == "1.0"
    assert policy.policy_sha256 == (
        "f36e89643bb9c74c607222ac6690a5a2dc3d2ac98f0e36b941d3d1cccc293c83"
    )
    assert (
        not {
            "role_policies",
            "calibration_artifact_sha256",
            "calibration_included_candidate_count",
            "calibration_included_root_lineage_count",
            "tier_a_overall_rationale",
        }
        & payload.keys()
    )
    assert all("basis" not in threshold for threshold in payload["thresholds"])


def test_v2_policy_binds_rationales_distributions_roles_and_lineages() -> None:
    policy = _seal_structural_v2()

    assert policy.schema_version == "2.0"
    assert policy.calibration_included_candidate_count == 3
    assert policy.calibration_included_root_lineage_count == 3
    assert len(policy.role_policies) == len(QualificationRoleClass)
    assert all(threshold.rationale for threshold in policy.thresholds)
    assert all(role.minimum_overall_rationale and role.thresholds for role in policy.role_policies)


@pytest.mark.parametrize(
    ("dimension", "minimum_cases", "minimum_score", "message"),
    (
        (
            ModelBenchmarkDimension.ACCOUNTING_CONSERVATION,
            2,
            0.5,
            "judgment qualification",
        ),
        (
            ModelBenchmarkDimension.ACCOUNTING_CONSERVATION,
            4,
            1.0,
            "judgment qualification",
        ),
        (
            ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
            2,
            0.5,
            "deterministic qualification",
        ),
    ),
)
def test_v2_rejects_underfilled_absolute_or_weakened_thresholds(
    dimension: ModelBenchmarkDimension,
    minimum_cases: int,
    minimum_score: float,
    message: str,
) -> None:
    replacements = {item.dimension: item for item in _thresholds()}
    replacements[dimension] = _threshold(
        dimension,
        minimum_cases=minimum_cases,
        minimum_score=minimum_score,
    )

    with pytest.raises(ValidationError, match=message):
        _seal_structural_v2(
            thresholds=tuple(
                replacements[item] for item in sorted(replacements, key=lambda value: value.value)
            )
        )


def test_threshold_metadata_and_role_semantics_fail_closed() -> None:
    with pytest.raises(ValidationError, match="metadata must be complete"):
        QualificationDimensionThreshold(
            dimension=ModelBenchmarkDimension.ACCESS_CONTROL,
            minimum_cases=4,
            minimum_score=0.75,
            rationale="This rationale is long enough but has no evidence hash.",
        )

    with pytest.raises(ValidationError, match="mandatory semantic dimensions"):
        RoleQualificationPolicy(
            role_class=QualificationRoleClass.VERIFIER,
            thresholds=(_threshold(ModelBenchmarkDimension.EXACT_SOURCE_LOCATION),),
            minimum_overall_score=0.75,
            minimum_overall_rationale="Measured verifier aggregate threshold rationale.",
        )

    with pytest.raises(ValidationError):
        _seal_structural_v2(included_root_lineages=2)


@pytest.mark.asyncio
async def test_live_calibration_authority_is_opaque_and_underfilled_policy_is_refused() -> None:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
    ) = await calibration_fixtures._complete_inputs()
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    legacy_policy = workflow_fixtures._policy()
    artifact = build_model_calibration_artifact(
        created_at=calibration_fixtures.NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=legacy_policy.policy_sha256,
        effective_config_sha256=calibration_fixtures.EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
    )
    authority = issue_trusted_model_calibration_verification(
        artifact=artifact,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=suite,
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=legacy_policy.policy_sha256,
        effective_config_sha256=calibration_fixtures.EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
    )

    assert artifact.included_root_lineage_count == 1
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedModelCalibrationVerification()
    with pytest.raises(ValueError, match="at least three complete REAL candidates"):
        seal_calibrated_qualification_policy(
            calibration=artifact,
            trusted_calibration_verification=authority,
            created_at=NOW,
            thresholds=_thresholds(),
            role_policies=_role_policies(),
            tier_a_minimum_overall_score=0.75,
            tier_a_overall_rationale=(
                "Measured aggregate calibration rationale for global Tier A."
            ),
            maximum_validity_days=30,
        )


def test_v2_policy_without_live_authority_cannot_verify_or_resolve_production() -> None:
    bundle = qualification_fixtures._bundle()
    policy = _seal_structural_v2()

    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=policy,
        expected_bindings=bundle.bindings,
        trusted_benchmark_evidence=bundle.benchmark_evidence,
        now=qualification_fixtures._NOW,
    )

    assert not verification.valid
    assert any("lacks live verification authority" in error for error in verification.errors)
    with pytest.raises(ValueError, match="live calibrated policy authority"):
        qualification_fixtures._resolve_for_test(bundle, policy=policy)


def test_no_raw_calibration_or_policy_authority_issuer_is_module_reachable() -> None:
    assert not hasattr(calibration_module, "_issue_trusted_calibration_capability")
    assert not hasattr(qualification_module, "_issue_trusted_calibrated_policy")

    with pytest.raises(ValueError, match="typed artifact"):
        calibration_module.issue_trusted_model_calibration_verification(
            artifact=object(),  # type: ignore[arg-type]
            candidate_registry=object(),  # type: ignore[arg-type]
            discovery_run_manifest=object(),  # type: ignore[arg-type]
            benchmark_suite=object(),  # type: ignore[arg-type]
            benchmark_portfolio=object(),  # type: ignore[arg-type]
            benchmark_reports=(),
            benchmark_policy_sha256="1" * 64,
            effective_config_sha256="2" * 64,
            trusted_campaign_verification=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="typed artifact"):
        qualification_module.issue_trusted_calibrated_qualification_policy(
            policy=_seal_structural_v2(),
            calibration=object(),
            trusted_calibration_verification=object(),
        )
