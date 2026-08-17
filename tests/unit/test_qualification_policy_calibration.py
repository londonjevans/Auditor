from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.config as config_module
import mmaudit.models.calibration as calibration_module
import mmaudit.models.qualification as qualification_module
from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkDimensionScore,
    load_model_benchmark_corpus,
)
from mmaudit.config import AuditConfig
from mmaudit.models.calibration import (
    ModelCalibrationArtifact,
    ModelCalibrationCandidateObservation,
    ModelCalibrationDimensionDistribution,
    ModelCalibrationDimensionObservation,
    ModelCalibrationScoreFrequency,
    TrustedModelCalibrationVerification,
    build_model_calibration_artifact,
    calibrated_qualification_policy_bytes,
    calibration_distribution_sha256,
    derive_calibrated_qualification_policy,
    issue_trusted_model_calibration_verification,
    load_calibrated_qualification_policy,
    load_model_calibration_artifact,
    model_calibration_artifact_bytes,
    seal_calibrated_qualification_policy,
    verify_calibrated_qualification_policy_structure,
    write_calibrated_qualification_policy,
    write_model_calibration_artifact,
)
from mmaudit.models.candidate_benchmark import CandidateBenchmarkDiagnostic
from mmaudit.models.qualification import (
    CALIBRATION_ROLE_ROOT_SUPPORT,
    QualificationDimensionThreshold,
    QualificationPolicy,
    QualificationRoleClass,
    QualificationThresholdBasis,
    RoleQualificationPolicy,
    issue_release_pinned_trusted_calibrated_qualification_policy,
    load_qualification_policy,
    seal_qualification_policy,
    verify_model_qualification,
)
from mmaudit.models.qualification_workflow import (
    QualificationReleaseBindings,
    seal_qualification_release_bindings,
)
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.manifest import canonical_sha256
from tests.qualification_support import synthetic_release_observation
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


_ROLE_JUDGMENT_DIMENSIONS = frozenset(
    dimension
    for dimensions in _ROLE_DIMENSIONS.values()
    for dimension in dimensions
    if dimension not in _DETERMINISTIC_DIMENSIONS
)


def _expanded_artifact(
    template: ModelCalibrationArtifact,
    *,
    candidate_count: int = 8,
    root_indexes: tuple[int, ...] | None = None,
    pass_counts: dict[ModelBenchmarkDimension, tuple[int, ...]] | None = None,
) -> ModelCalibrationArtifact:
    roots = root_indexes or tuple(
        index if index < 6 else index - 6 for index in range(candidate_count)
    )
    if len(roots) != candidate_count:
        raise AssertionError("test root projection differs from candidate count")
    overrides = pass_counts or {}
    source = template.candidates[0]
    denominators = {item.dimension: item.evaluated for item in source.dimensions}
    candidates: list[ModelCalibrationCandidateObservation] = []
    for index in range(candidate_count):
        exact_model_id = f"calibration/model-{index:03d}"
        report_sha256 = f"{2_000 + index:064x}"
        diagnostic_payload = source.diagnostic.model_dump(mode="json")
        diagnostic_payload.update(
            exact_model_id=exact_model_id,
            report_sha256=report_sha256,
        )
        diagnostic = CandidateBenchmarkDiagnostic.model_validate(diagnostic_payload)
        dimensions: list[ModelBenchmarkDimensionScore] = []
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value):
            denominator = denominators[dimension]
            supplied = overrides.get(dimension)
            if supplied is not None:
                if len(supplied) != candidate_count:
                    raise AssertionError("test pass-count projection differs from candidates")
                passed = supplied[index]
            elif dimension in _DETERMINISTIC_DIMENSIONS or (dimension in _ROLE_JUDGMENT_DIMENSIONS):
                passed = denominator
            else:
                passed = 1
            dimensions.append(
                ModelBenchmarkDimensionScore(
                    dimension=dimension,
                    passed=passed,
                    evaluated=denominator,
                    score=round(passed / denominator, 6),
                )
            )
        ordered_dimensions = tuple(dimensions)
        candidates.append(
            ModelCalibrationCandidateObservation(
                exact_model_id=exact_model_id,
                root_lineage=f"sha256:{roots[index] + 1:064x}",
                lineage_binding_sha256=f"{1_000 + index:064x}",
                report_sha256=report_sha256,
                report_execution_evidence=source.report_execution_evidence,
                diagnostic=diagnostic,
                included_in_distribution=True,
                exclusion_reasons=(),
                dimensions=ordered_dimensions,
                overall_score=round(
                    sum(item.score for item in ordered_dimensions) / len(ordered_dimensions),
                    6,
                ),
            )
        )

    distributions: list[ModelCalibrationDimensionDistribution] = []
    for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value):
        observations = tuple(
            ModelCalibrationDimensionObservation(
                exact_model_id=candidate.exact_model_id,
                root_lineage=calibration_module._required_calibration_root_lineage(candidate),
                passed=next(
                    item.passed for item in candidate.dimensions if item.dimension is dimension
                ),
                evaluated=next(
                    item.evaluated for item in candidate.dimensions if item.dimension is dimension
                ),
                score=next(
                    item.score for item in candidate.dimensions if item.dimension is dimension
                ),
            )
            for candidate in candidates
        )
        frequencies: dict[float, int] = {}
        for observation in observations:
            frequencies[observation.score] = frequencies.get(observation.score, 0) + 1
        distributions.append(
            ModelCalibrationDimensionDistribution(
                dimension=dimension,
                candidate_count=candidate_count,
                included_candidate_count=candidate_count,
                excluded_candidate_count=0,
                observations=observations,
                score_frequencies=tuple(
                    ModelCalibrationScoreFrequency(score=score, candidate_count=count)
                    for score, count in sorted(frequencies.items())
                ),
                mean_score=round(
                    sum(item.score for item in observations) / len(observations),
                    6,
                ),
            )
        )

    payload = template.model_dump(mode="json")
    candidate_ids = [item.exact_model_id for item in candidates]
    payload.update(
        candidate_set_sha256=canonical_sha256(candidate_ids),
        included_root_lineage_count=len(set(roots)),
        candidates=[item.model_dump(mode="json") for item in candidates],
        distributions=[item.model_dump(mode="json") for item in distributions],
    )
    payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )
    return ModelCalibrationArtifact.model_validate(payload)


def _bound_threshold(
    artifact: ModelCalibrationArtifact,
    dimension: ModelBenchmarkDimension,
    minimum_score: float,
) -> QualificationDimensionThreshold:
    distribution = next(item for item in artifact.distributions if item.dimension is dimension)
    return QualificationDimensionThreshold(
        dimension=dimension,
        minimum_cases=distribution.observations[0].evaluated,
        minimum_score=minimum_score,
        basis=(
            QualificationThresholdBasis.DETERMINISTIC_REQUIREMENT
            if dimension in _DETERMINISTIC_DIMENSIONS
            else QualificationThresholdBasis.CALIBRATED_DISTRIBUTION
        ),
        rationale=(
            calibration_module._DETERMINISTIC_EMPIRICAL_SUPPORT_RATIONALE
            if dimension in _DETERMINISTIC_DIMENSIONS
            else calibration_module._JUDGMENT_EMPIRICAL_SUPPORT_RATIONALE
        ),
        calibration_distribution_sha256=calibration_distribution_sha256(distribution),
    )


def _baseline_policy_inputs(
    artifact: ModelCalibrationArtifact,
    *,
    global_score_overrides: dict[ModelBenchmarkDimension, float] | None = None,
) -> tuple[
    tuple[QualificationDimensionThreshold, ...],
    tuple[RoleQualificationPolicy, ...],
    float,
]:
    overrides = global_score_overrides or {}
    denominators = {
        item.dimension: item.observations[0].evaluated for item in artifact.distributions
    }
    global_scores = {
        dimension: (
            1.0
            if dimension in _DETERMINISTIC_DIMENSIONS
            else (
                round((denominators[dimension] - 1) / denominators[dimension], 6)
                if dimension in _ROLE_JUDGMENT_DIMENSIONS
                else round(1 / denominators[dimension], 6)
            )
        )
        for dimension in ModelBenchmarkDimension
    }
    global_scores.update(overrides)
    thresholds = tuple(
        _bound_threshold(artifact, dimension, global_scores[dimension])
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )
    role_policies = tuple(
        RoleQualificationPolicy(
            role_class=role_class,
            thresholds=tuple(
                _bound_threshold(
                    artifact,
                    dimension,
                    (
                        1.0
                        if dimension in _DETERMINISTIC_DIMENSIONS
                        else round(
                            (denominators[dimension] - 1) / denominators[dimension],
                            6,
                        )
                    ),
                )
                for dimension in _ROLE_DIMENSIONS[role_class]
            ),
            minimum_overall_score=round(
                1
                - 1
                / (
                    max(
                        denominators[dimension]
                        for dimension in _ROLE_DIMENSIONS[role_class]
                        if dimension not in _DETERMINISTIC_DIMENSIONS
                    )
                    * len(_ROLE_DIMENSIONS[role_class])
                ),
                6,
            ),
            minimum_overall_rationale=(calibration_module._AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE),
        )
        for role_class in sorted(QualificationRoleClass, key=lambda item: item.value)
    )
    return (
        thresholds,
        role_policies,
        min(
            item.overall_score
            for item in artifact.candidates
            if item.included_in_distribution and item.overall_score is not None
        ),
    )


def _seal_policy_for_artifact(artifact: ModelCalibrationArtifact) -> QualificationPolicy:
    thresholds, role_policies, global_overall = _baseline_policy_inputs(artifact)
    return seal_qualification_policy(
        created_at=artifact.created_at,
        thresholds=thresholds,
        role_policies=role_policies,
        calibration_artifact_sha256=artifact.artifact_sha256,
        calibration_included_candidate_count=sum(
            item.included_in_distribution for item in artifact.candidates
        ),
        calibration_included_root_lineage_count=artifact.included_root_lineage_count,
        tier_a_minimum_overall_score=global_overall,
        tier_a_overall_rationale=calibration_module._AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE,
        maximum_validity_days=30,
    )


def _rehashed_policy(
    policy: QualificationPolicy,
    **updates: object,
) -> QualificationPolicy:
    payload = policy.model_dump(mode="json")
    payload.update(updates)
    payload["policy_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "policy_sha256"}
    )
    return QualificationPolicy.model_validate(payload)


def _release_bindings_for_config(
    config: AuditConfig,
    *,
    effective_config_sha256: str | None = None,
) -> QualificationReleaseBindings:
    pins = config.maximum_assurance.qualification
    return seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256=effective_config_sha256 or config.stable_hash(),
        prompt_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        toolchain_sha256="5" * 64,
        isolation_sha256="6" * 64,
        benchmark_corpus_version=pins.corpus_version,
        benchmark_ground_truth_version=pins.ground_truth_version,
    )


def _successor_config(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy_sha256: str,
) -> AuditConfig:
    monkeypatch.setattr(
        config_module,
        "MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256",
        policy_sha256,
    )
    return config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={
            "allow_downgrade": False,
            "qualification": {
                "policy_sha256": policy_sha256,
                "corpus_version": config_module.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
                "corpus_sha256": config_module.MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
                "ground_truth_version": (
                    config_module.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION
                ),
                "ground_truth_sha256": (
                    config_module.MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256
                ),
            },
        },
    ).effective()


def _rehashed_calibration(
    artifact: ModelCalibrationArtifact,
    **updates: str,
) -> ModelCalibrationArtifact:
    payload = artifact.model_dump(mode="json")
    payload.update(updates)
    payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )
    return ModelCalibrationArtifact.model_validate(payload)


async def _calibration_template(tmp_path: Path) -> ModelCalibrationArtifact:
    (
        manifest,
        registry,
        report,
        portfolio,
        campaign_capability,
        lineage_artifact,
        lineage_capability,
    ) = await calibration_fixtures._complete_inputs(tmp_path)
    return build_model_calibration_artifact(
        created_at=calibration_fixtures.NOW,
        candidate_registry=registry,
        discovery_run_manifest=manifest,
        benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=workflow_fixtures._policy().policy_sha256,
        effective_config_sha256=calibration_fixtures.EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )


def _seal_structural_v2(
    *,
    thresholds: tuple[QualificationDimensionThreshold, ...] | None = None,
    role_policies: tuple[RoleQualificationPolicy, ...] | None = None,
    included_root_lineages: int = 6,
):
    return seal_qualification_policy(
        created_at=NOW,
        thresholds=thresholds or _thresholds(),
        role_policies=role_policies or _role_policies(),
        calibration_artifact_sha256="8" * 64,
        calibration_included_candidate_count=8,
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
        "1df14052e97a8ceb2cf3ec9fd25637f5f2f3a821818a54382a7c1f241059da8c"
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
    assert policy.calibration_included_candidate_count == 8
    assert policy.calibration_included_root_lineage_count == 6
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
async def test_live_calibration_authority_is_opaque_and_underfilled_policy_is_refused(
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
    ) = await calibration_fixtures._complete_inputs(tmp_path)
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
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
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
        lineage_review_artifact=lineage_artifact,
        trusted_lineage_verification=lineage_capability,
    )

    assert artifact.included_root_lineage_count == 1
    alternate_bundle, alternate_artifact, alternate_capability = (
        calibration_fixtures._signed_lineage_inputs(
            tmp_path,
            label="calibration-issuer-alternate",
        )
    )
    assert alternate_bundle.registry == registry
    assert alternate_artifact.artifact_sha256 != lineage_artifact.artifact_sha256
    with pytest.raises(ValueError, match="differs from live campaign evidence"):
        issue_trusted_model_calibration_verification(
            artifact=artifact,
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            benchmark_suite=suite,
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            benchmark_policy_sha256=legacy_policy.policy_sha256,
            effective_config_sha256=calibration_fixtures.EFFECTIVE_CONFIG_SHA256,
            trusted_campaign_verification=campaign_capability,
            lineage_review_artifact=alternate_artifact,
            trusted_lineage_verification=alternate_capability,
        )
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedModelCalibrationVerification()
    with pytest.raises(ValueError, match="at least 8 complete REAL candidates"):
        seal_calibrated_qualification_policy(
            calibration=artifact,
            trusted_calibration_verification=authority,
            created_at=artifact.created_at,
            thresholds=_thresholds(),
            role_policies=_role_policies(),
            tier_a_minimum_overall_score=0.75,
            tier_a_overall_rationale=(calibration_module._AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE),
            maximum_validity_days=30,
        )


@pytest.mark.asyncio
async def test_empirical_support_values_are_frozen_for_dimensions_and_aggregates(
    tmp_path: Path,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    thresholds, role_policies, global_overall = _baseline_policy_inputs(artifact)

    assert CALIBRATION_ROLE_ROOT_SUPPORT == {
        QualificationRoleClass.INVESTIGATOR: 4,
        QualificationRoleClass.VERIFIER: 2,
        QualificationRoleClass.FALSIFIER: 2,
        QualificationRoleClass.JUDGE: 2,
    }
    assert (
        next(
            item for item in role_policies if item.role_class is QualificationRoleClass.VERIFIER
        ).minimum_overall_score
        == 0.75
    )
    calibration_module._verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=thresholds,
        role_policies=role_policies,
        tier_a_minimum_overall_score=global_overall,
    )

    access_threshold = next(
        item for item in thresholds if item.dimension is ModelBenchmarkDimension.ACCESS_CONTROL
    )
    alternative = QualificationDimensionThreshold.model_validate(
        {**access_threshold.model_dump(mode="json"), "minimum_score": 0.5}
    )
    changed_thresholds = tuple(
        alternative if item.dimension is alternative.dimension else item for item in thresholds
    )
    with pytest.raises(ValueError, match=r"frozen empirical-support value 0\.25"):
        calibration_module._verify_policy_threshold_bindings(
            calibration=artifact,
            thresholds=changed_thresholds,
            role_policies=role_policies,
            tier_a_minimum_overall_score=global_overall,
        )
    with pytest.raises(ValueError, match="global aggregate threshold differs"):
        calibration_module._verify_policy_threshold_bindings(
            calibration=artifact,
            thresholds=thresholds,
            role_policies=role_policies,
            tier_a_minimum_overall_score=round(global_overall + 0.01, 6),
        )


def _mock_live_calibration_verification(
    monkeypatch: pytest.MonkeyPatch,
    artifact: ModelCalibrationArtifact,
) -> TrustedModelCalibrationVerification:
    authority = object.__new__(TrustedModelCalibrationVerification)

    def require(
        supplied: TrustedModelCalibrationVerification,
        artifact_sha256: str,
    ) -> None:
        assert supplied is authority
        assert artifact_sha256 == artifact.artifact_sha256

    monkeypatch.setattr(calibration_module, "_require_trusted_calibration_capability", require)
    return authority


@pytest.mark.asyncio
async def test_automatic_policy_derivation_freezes_exact_empirical_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    authority = _mock_live_calibration_verification(monkeypatch, artifact)
    derivation_parameters = inspect.signature(derive_calibrated_qualification_policy).parameters
    assert set(derivation_parameters) == {
        "calibration",
        "trusted_calibration_verification",
    }

    policy = derive_calibrated_qualification_policy(
        calibration=artifact,
        trusted_calibration_verification=authority,
    )

    expected_role_dimensions = {
        role: tuple(dimension.value for dimension in dimensions)
        for role, dimensions in _ROLE_DIMENSIONS.items()
    }
    assert policy.schema_version == "2.0"
    assert policy.calibration_artifact_sha256 == artifact.artifact_sha256
    assert policy.calibration_included_candidate_count == 8
    assert policy.calibration_included_root_lineage_count == 6
    assert policy.created_at == artifact.created_at
    assert policy.maximum_validity_days == 30
    assert policy.maximum_benchmark_evidence_age_days == 7
    assert all(
        "Non-statistical empirical-support" in (threshold.rationale or "")
        and "statistical-significance claim" in (threshold.rationale or "")
        for threshold in policy.thresholds
    )
    assert "Non-statistical empirical-support" in (policy.tier_a_overall_rationale or "")
    distributions = {item.dimension: item for item in artifact.distributions}
    for threshold in policy.thresholds:
        distribution = distributions[threshold.dimension]
        assert threshold.minimum_cases == distribution.observations[0].evaluated
        assert threshold.calibration_distribution_sha256 == calibration_distribution_sha256(
            distribution
        )
    assert {
        item.role_class: tuple(threshold.dimension.value for threshold in item.thresholds)
        for item in policy.role_policies
    } == expected_role_dimensions
    assert (
        verify_calibrated_qualification_policy_structure(
            calibration=artifact,
            policy=policy,
        )
        is None
    )

    output = tmp_path / "calibrated-policy.json"
    write_calibrated_qualification_policy(output, policy)
    assert output.read_bytes() == calibrated_qualification_policy_bytes(policy)
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_nlink == 1
    assert load_calibrated_qualification_policy(output) == policy
    with pytest.raises(ValueError, match="fresh file"):
        write_calibrated_qualification_policy(output, policy)


@pytest.mark.asyncio
async def test_automatic_policy_derivation_rejects_coordinate_only_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _expanded_artifact(
        await _calibration_template(tmp_path),
        candidate_count=10,
        root_indexes=tuple(range(10)),
        pass_counts={
            ModelBenchmarkDimension.ACCESS_CONTROL: (3,) * 8 + (2,) * 2,
            ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: (2,) * 2 + (3,) * 8,
        },
    )
    authority = _mock_live_calibration_verification(monkeypatch, artifact)

    with pytest.raises(ValueError, match="global calibrated policy is not jointly supported"):
        derive_calibrated_qualification_policy(
            calibration=artifact,
            trusted_calibration_verification=authority,
        )


@pytest.mark.asyncio
async def test_calibrated_policy_private_loader_rejects_unsafe_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    authority = _mock_live_calibration_verification(monkeypatch, artifact)
    policy = derive_calibrated_qualification_policy(
        calibration=artifact,
        trusted_calibration_verification=authority,
    )
    output = tmp_path / "calibrated-policy.json"
    write_calibrated_qualification_policy(output, policy)

    output.chmod(0o644)
    with pytest.raises(ValueError, match="private unshared regular file"):
        load_calibrated_qualification_policy(output)
    output.chmod(0o600)
    alias = tmp_path / "calibrated-policy-alias.json"
    alias.hardlink_to(output)
    with pytest.raises(ValueError, match="private unshared regular file"):
        load_calibrated_qualification_policy(output)
    alias.unlink()
    symbolic = tmp_path / "calibrated-policy-symbolic.json"
    symbolic.symlink_to(output)
    with pytest.raises(ValueError, match="unavailable"):
        load_calibrated_qualification_policy(symbolic)


@pytest.mark.asyncio
async def test_calibration_artifact_private_io_is_canonical_and_rejects_unsafe_files(
    tmp_path: Path,
) -> None:
    artifact = await _calibration_template(tmp_path / "inputs")
    output = tmp_path / "calibration.json"
    write_model_calibration_artifact(output, artifact)

    assert output.read_bytes() == model_calibration_artifact_bytes(artifact)
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_nlink == 1
    assert load_model_calibration_artifact(output) == artifact
    output.chmod(0o644)
    with pytest.raises(ValueError, match="private unshared regular file"):
        load_model_calibration_artifact(output)
    output.chmod(0o600)
    alias = tmp_path / "calibration-alias.json"
    alias.hardlink_to(output)
    with pytest.raises(ValueError, match="private unshared regular file"):
        load_model_calibration_artifact(output)
    alias.unlink()
    symbolic = tmp_path / "calibration-symbolic.json"
    symbolic.symlink_to(output)
    with pytest.raises(ValueError, match="unavailable"):
        load_model_calibration_artifact(symbolic)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["load", "write"])
async def test_calibration_artifact_io_rejects_an_ancestor_swapped_to_a_link(
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = await _calibration_template(tmp_path / "inputs")
    parent = tmp_path / "calibration-parent"
    parent.mkdir()
    output = parent / "calibration.json"
    if operation == "load":
        write_model_calibration_artifact(output, artifact)
    moved_parent = tmp_path / "calibration-parent-original"
    attacker_parent = tmp_path / "attacker-calibration-parent"
    attacker_parent.mkdir()
    actual_open = calibration_module.os.open
    swapped = False

    def racing_open(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == parent.name and dir_fd is not None and not swapped:
            parent.rename(moved_parent)
            parent.symlink_to(attacker_parent, target_is_directory=True)
            swapped = True
        return actual_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(calibration_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="unavailable or linked"):
        if operation == "load":
            load_model_calibration_artifact(output)
        else:
            write_model_calibration_artifact(output, artifact)
    assert swapped
    assert not (attacker_parent / output.name).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["load", "write"])
async def test_calibrated_policy_io_rejects_an_ancestor_swapped_to_a_link(
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path / "inputs"))
    authority = _mock_live_calibration_verification(monkeypatch, artifact)
    policy = derive_calibrated_qualification_policy(
        calibration=artifact,
        trusted_calibration_verification=authority,
    )
    parent = tmp_path / "policy-parent"
    parent.mkdir()
    output = parent / "policy.json"
    if operation == "load":
        write_calibrated_qualification_policy(output, policy)
    moved_parent = tmp_path / "policy-parent-original"
    attacker_parent = tmp_path / "attacker-parent"
    attacker_parent.mkdir()
    actual_open = calibration_module.os.open
    swapped = False

    def racing_open(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == parent.name and dir_fd is not None and not swapped:
            parent.rename(moved_parent)
            parent.symlink_to(attacker_parent, target_is_directory=True)
            swapped = True
        return actual_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(calibration_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="unavailable or linked"):
        if operation == "load":
            load_calibrated_qualification_policy(output)
        else:
            write_calibrated_qualification_policy(output, policy)
    assert swapped
    assert not (attacker_parent / output.name).exists()


@pytest.mark.asyncio
async def test_empirical_support_rejects_alias_inflation_and_zero_score_edges(
    tmp_path: Path,
) -> None:
    template = await _calibration_template(tmp_path)
    alias_artifact = _expanded_artifact(
        template,
        candidate_count=11,
        root_indexes=(0, 0, 0, 1, 1, 1, 2, 2, 3, 4, 5),
        pass_counts={
            ModelBenchmarkDimension.ACCESS_CONTROL: (3,) * 8 + (2,) * 3,
        },
    )
    alias_distribution = next(
        item
        for item in alias_artifact.distributions
        if item.dimension is ModelBenchmarkDimension.ACCESS_CONTROL
    )
    calibration_module._require_threshold_distribution_binding(
        threshold=_bound_threshold(
            alias_artifact,
            ModelBenchmarkDimension.ACCESS_CONTROL,
            0.5,
        ),
        distribution=alias_distribution,
        required_candidate_count=8,
        required_root_count=6,
    )
    with pytest.raises(ValueError, match=r"frozen empirical-support value 0\.5"):
        calibration_module._require_threshold_distribution_binding(
            threshold=_bound_threshold(
                alias_artifact,
                ModelBenchmarkDimension.ACCESS_CONTROL,
                0.75,
            ),
            distribution=alias_distribution,
            required_candidate_count=8,
            required_root_count=6,
        )

    perfect_distribution = next(
        item
        for item in alias_artifact.distributions
        if item.dimension is ModelBenchmarkDimension.FALSIFIER_QUALITY
    )
    calibration_module._require_threshold_distribution_binding(
        threshold=_bound_threshold(
            alias_artifact,
            ModelBenchmarkDimension.FALSIFIER_QUALITY,
            0.75,
        ),
        distribution=perfect_distribution,
        required_candidate_count=8,
        required_root_count=6,
    )

    zero_artifact = _expanded_artifact(
        template,
        pass_counts={ModelBenchmarkDimension.ACCESS_CONTROL: (0,) * 8},
    )
    zero_distribution = next(
        item
        for item in zero_artifact.distributions
        if item.dimension is ModelBenchmarkDimension.ACCESS_CONTROL
    )
    with pytest.raises(ValueError, match="lacks positive non-absolute empirical support"):
        calibration_module._require_threshold_distribution_binding(
            threshold=_bound_threshold(
                zero_artifact,
                ModelBenchmarkDimension.ACCESS_CONTROL,
                0.25,
            ),
            distribution=zero_distribution,
            required_candidate_count=8,
            required_root_count=6,
        )


@pytest.mark.asyncio
async def test_coordinate_wise_supported_policy_must_also_be_jointly_reachable(
    tmp_path: Path,
) -> None:
    artifact = _expanded_artifact(
        await _calibration_template(tmp_path),
        candidate_count=10,
        root_indexes=tuple(range(10)),
        pass_counts={
            ModelBenchmarkDimension.ACCESS_CONTROL: (3,) * 8 + (2,) * 2,
            ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: (2,) * 2 + (3,) * 8,
        },
    )
    thresholds, role_policies, global_overall = _baseline_policy_inputs(
        artifact,
        global_score_overrides={
            ModelBenchmarkDimension.ACCESS_CONTROL: 0.75,
            ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: 0.75,
        },
    )

    with pytest.raises(ValueError, match="global calibrated policy is not jointly supported"):
        calibration_module._verify_policy_threshold_bindings(
            calibration=artifact,
            thresholds=thresholds,
            role_policies=role_policies,
            tier_a_minimum_overall_score=global_overall,
        )


@pytest.mark.asyncio
async def test_structural_calibration_policy_verifier_grants_no_authority(
    tmp_path: Path,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    policy = _seal_policy_for_artifact(artifact)

    assert (
        verify_calibrated_qualification_policy_structure(
            calibration=artifact,
            policy=policy,
        )
        is None
    )
    with pytest.raises(ValueError, match="differs from its calibration artifact"):
        verify_calibrated_qualification_policy_structure(
            calibration=artifact,
            policy=_seal_structural_v2(),
        )


@pytest.mark.asyncio
async def test_structural_calibration_policy_verifier_rejects_every_noncanonical_field(
    tmp_path: Path,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    policy = _seal_policy_for_artifact(artifact)
    top_level_mutations = (
        {
            "created_at": (artifact.created_at + timedelta(seconds=1))
            .isoformat()
            .replace("+00:00", "Z")
        },
        {"maximum_validity_days": 31},
        {"maximum_benchmark_evidence_age_days": 8},
        {"tier_a_overall_rationale": "An arbitrary aggregate rationale that is long enough."},
    )
    for updates in top_level_mutations:
        with pytest.raises(ValueError, match="differs from its calibration artifact"):
            verify_calibrated_qualification_policy_structure(
                calibration=artifact,
                policy=_rehashed_policy(policy, **updates),
            )

    thresholds = [item.model_dump(mode="json") for item in policy.thresholds]
    thresholds[0]["rationale"] = "An arbitrary dimension rationale that is long enough."
    with pytest.raises(ValueError, match="threshold rationale differs"):
        verify_calibrated_qualification_policy_structure(
            calibration=artifact,
            policy=_rehashed_policy(policy, thresholds=thresholds),
        )

    role_policies = [item.model_dump(mode="json") for item in policy.role_policies]
    role_policies[0]["minimum_overall_rationale"] = (
        "An arbitrary role aggregate rationale that is long enough."
    )
    with pytest.raises(ValueError, match="aggregate rationale differs"):
        verify_calibrated_qualification_policy_structure(
            calibration=artifact,
            policy=_rehashed_policy(policy, role_policies=role_policies),
        )


@pytest.mark.asyncio
async def test_release_pinned_policy_reconstruction_rejects_current_v1_release(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    policy = _seal_policy_for_artifact(artifact)
    config = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE).effective()
    release_bindings = _release_bindings_for_config(config)

    with pytest.raises(ValueError, match="current maximum-assurance release pin"):
        issue_release_pinned_trusted_calibrated_qualification_policy(
            policy=policy,
            calibration=artifact,
            config=config,
            release_bindings=release_bindings,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=NOW,
            ),
        )


@pytest.mark.asyncio
async def test_mutating_runtime_pins_cannot_mint_successor_release_authority(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _expanded_artifact(await _calibration_template(tmp_path))
    policy = _seal_policy_for_artifact(artifact)
    config = _successor_config(
        config_factory,
        monkeypatch,
        policy_sha256=policy.policy_sha256,
    )
    monkeypatch.setattr(
        qualification_module,
        "MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256",
        policy.policy_sha256,
    )
    release_bindings = _release_bindings_for_config(config)
    with pytest.raises(ValueError, match="current source release"):
        issue_release_pinned_trusted_calibrated_qualification_policy(
            policy=policy,
            calibration=artifact,
            config=config,
            release_bindings=release_bindings,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=NOW,
            ),
        )


@pytest.mark.asyncio
async def test_release_pinned_policy_reconstruction_rejects_self_hashed_unpinned_corpus(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _rehashed_calibration(
        _expanded_artifact(await _calibration_template(tmp_path)),
        benchmark_corpus_sha256="b" * 64,
    )
    policy = _seal_policy_for_artifact(artifact)
    config = _successor_config(
        config_factory,
        monkeypatch,
        policy_sha256=policy.policy_sha256,
    )
    release_bindings = _release_bindings_for_config(config)

    with pytest.raises(ValueError, match="current source release"):
        issue_release_pinned_trusted_calibrated_qualification_policy(
            policy=policy,
            calibration=artifact,
            config=config,
            release_bindings=release_bindings,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=NOW,
            ),
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
        lineage_candidate_registry=bundle.lineage_registry,
    )

    assert not verification.valid
    assert any("lacks release-pinned successor authority" in error for error in verification.errors)
    with pytest.raises(ValueError, match="calibrated policy authority"):
        qualification_fixtures._resolve_for_test(bundle, policy=policy)


def test_live_calibration_authority_is_not_release_pinned_successor_authority() -> None:
    bundle = qualification_fixtures._bundle(policy_schema_version="1.0")
    policy, live_authority = qualification_fixtures._calibrated_policy_and_authority(
        bundle.registry
    )
    successor_bindings = bundle.bindings.model_copy(
        update={
            "lineage_candidate_registry_sha256": bundle.lineage_registry.registry_sha256,
            "calibration_release_transition_sha256": "d" * 64,
        }
    )

    with pytest.raises(ValueError, match="not release-pinned"):
        live_authority.require_release_pinned_for(
            policy=policy,
            calibration_artifact_sha256="a" * 64,
            release_bindings_sha256="b" * 64,
            candidate_registry_sha256="c" * 64,
            calibration_release_transition_sha256="d" * 64,
        )
    verification = verify_model_qualification(
        artifact=bundle.artifact,
        registry=bundle.registry,
        policy=policy,
        expected_bindings=successor_bindings,
        trusted_benchmark_evidence=bundle.benchmark_evidence,
        now=qualification_fixtures._NOW,
        trusted_calibrated_policy=live_authority,
        lineage_candidate_registry=bundle.lineage_registry,
    )
    assert any("release authority is mismatched" in error for error in verification.errors)
    assert verification.eligible_tier_a_model_ids == ()
    assert not verification.production_selection_ready
    with pytest.raises(ValueError, match="not release-pinned"):
        qualification_fixtures._resolve_for_test(
            bundle,
            policy=policy,
            expected_bindings=successor_bindings,
            trusted_calibrated_policy=live_authority,
        )


def test_no_raw_calibration_or_policy_authority_issuer_is_module_reachable() -> None:
    assert not hasattr(calibration_module, "_issue_trusted_calibration_capability")
    assert not hasattr(qualification_module, "_issue_trusted_calibrated_policy")
    assert not hasattr(qualification_module, "_build_trusted_calibrated_policy_authority")

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
            lineage_review_artifact=object(),  # type: ignore[arg-type]
            trusted_lineage_verification=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="typed artifact"):
        qualification_module.issue_trusted_calibrated_qualification_policy(
            policy=_seal_structural_v2(),
            calibration=object(),
            trusted_calibration_verification=object(),
        )
    with pytest.raises(ValueError, match="typed artifact"):
        qualification_module.issue_release_pinned_trusted_calibrated_qualification_policy(
            policy=_seal_structural_v2(),
            calibration=object(),
            config=object(),
            release_bindings=object(),
            trusted_release_observation=object(),
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        qualification_module.issue_release_pinned_trusted_calibrated_qualification_policy(
            policy=_seal_structural_v2(),
            calibration=object(),
            config=object(),
            release_bindings=object(),
            trusted_release_observation=object(),
            expected_policy_sha256="f" * 64,
        )
