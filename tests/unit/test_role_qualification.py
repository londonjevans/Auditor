from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.models import ModelBenchmarkDimension, load_model_benchmark_corpus
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    CandidateModel,
    ModelQualificationResult,
    QualificationDimensionResult,
    QualificationDimensionThreshold,
    QualificationDisposition,
    QualificationPolicy,
    QualificationRoleClass,
    QualificationThresholdBasis,
    RoleQualificationDisposition,
    RoleQualificationPolicy,
    RoleQualificationResult,
    derive_approved_roles_for_role_qualification,
    evaluate_role_qualification_results,
    seal_candidate_registry,
    seal_model_qualification_result,
    seal_qualification_policy,
)
from mmaudit.models.qualification_workflow import (
    run_qualification_workflow,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.qualification_support import synthetic_release_observation
from tests.unit import test_qualification_workflow as workflow_fixtures

_NOW = datetime(2026, 7, 30, tzinfo=UTC)


_DETERMINISTIC_DIMENSIONS = frozenset(
    {
        ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
        ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE,
        ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE,
    }
)


def _threshold(
    dimension: ModelBenchmarkDimension,
    *,
    calibrated: bool,
) -> QualificationDimensionThreshold:
    if not calibrated:
        return QualificationDimensionThreshold(
            dimension=dimension,
            minimum_cases=2,
            minimum_score=0.5,
        )
    deterministic = dimension in _DETERMINISTIC_DIMENSIONS
    return QualificationDimensionThreshold(
        dimension=dimension,
        minimum_cases=2 if deterministic else 4,
        minimum_score=1.0 if deterministic else 0.75,
        basis=(
            QualificationThresholdBasis.DETERMINISTIC_REQUIREMENT
            if deterministic
            else QualificationThresholdBasis.CALIBRATED_DISTRIBUTION
        ),
        rationale=f"Synthetic measured threshold rationale for {dimension.value}.",
        calibration_distribution_sha256="9" * 64,
    )


def _global_thresholds(
    *,
    calibrated: bool = False,
) -> tuple[QualificationDimensionThreshold, ...]:
    return tuple(
        _threshold(dimension, calibrated=calibrated)
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )


def _dimensions(
    *,
    reduced: frozenset[ModelBenchmarkDimension] = frozenset(
        {
            ModelBenchmarkDimension.FALSIFIER_QUALITY,
            ModelBenchmarkDimension.REPORT_QUALITY,
            ModelBenchmarkDimension.VERIFIER_QUALITY,
        }
    ),
) -> tuple[QualificationDimensionResult, ...]:
    return tuple(
        QualificationDimensionResult(
            dimension=dimension,
            passed=1 if dimension in reduced else 2,
            evaluated=2,
            score=0.5 if dimension in reduced else 1.0,
        )
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )


def _role_policies(
    *,
    calibrated: bool = False,
) -> tuple[RoleQualificationPolicy, ...]:
    dimensions = {
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
    return tuple(
        RoleQualificationPolicy(
            role_class=role_class,
            thresholds=tuple(
                _threshold(dimension, calibrated=calibrated)
                if calibrated
                else QualificationDimensionThreshold(
                    dimension=dimension,
                    minimum_cases=2,
                    minimum_score=1.0,
                    basis=QualificationThresholdBasis.CALIBRATED_DISTRIBUTION,
                    rationale=f"Synthetic role rationale for {dimension.value}.",
                    calibration_distribution_sha256="9" * 64,
                )
                for dimension in dimensions[role_class]
            ),
            minimum_overall_score=0.75 if calibrated else 1.0,
            minimum_overall_rationale=(
                f"Synthetic measured aggregate rationale for {role_class.value}."
            ),
        )
        for role_class in sorted(QualificationRoleClass, key=lambda item: item.value)
    )


def _sealed_result(
    *,
    disposition: QualificationDisposition,
    role_results: tuple[RoleQualificationResult, ...] = (),
    approved_roles: tuple[str, ...] = (),
    declared_roles: tuple[str, ...] = (),
) -> ModelQualificationResult:
    dimensions = _dimensions()
    return seal_model_qualification_result(
        exact_model_id="author/model",
        canonical_model_slug="author/model",
        root_lineage="sha256:" + "1" * 64,
        approved_provider_endpoint="provider/endpoint",
        approved_provider_name="Provider",
        endpoint_snapshot_sha256="2" * 64,
        output_capability_sha256="3" * 64,
        model_metadata_snapshot_sha256="4" * 64,
        pricing_snapshot_sha256="5" * 64,
        structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        benchmark_report_sha256="6" * 64,
        benchmark_verification_sha256="7" * 64,
        disposition=disposition,
        dimensions=dimensions,
        overall_score=round(sum(item.score for item in dimensions) / len(dimensions), 6),
        approved_roles=approved_roles,
        declared_roles=declared_roles,
        role_results=role_results,
        evaluated_at=_NOW,
        expires_at=_NOW + timedelta(days=7)
        if disposition is QualificationDisposition.TIER_A
        else None,
    )


def test_legacy_policy_keeps_v1_shape_and_hash_when_role_policies_are_absent() -> None:
    policy = seal_qualification_policy(
        created_at=_NOW,
        thresholds=_global_thresholds(),
        tier_a_minimum_overall_score=0.5,
        maximum_validity_days=30,
    )
    payload = policy.model_dump(mode="json")

    assert policy.schema_version == "1.0"
    assert "role_policies" not in payload
    assert policy.policy_sha256 == canonical_sha256(
        policy.model_dump(mode="json", exclude={"policy_sha256"})
    )


def test_v2_role_policy_is_complete_strict_and_self_hashed() -> None:
    policy = seal_qualification_policy(
        created_at=_NOW,
        thresholds=_global_thresholds(calibrated=True),
        role_policies=_role_policies(calibrated=True),
        calibration_artifact_sha256="8" * 64,
        calibration_included_candidate_count=3,
        calibration_included_root_lineage_count=3,
        tier_a_minimum_overall_score=0.75,
        tier_a_overall_rationale="Synthetic measured Tier A aggregate threshold rationale.",
        maximum_validity_days=30,
    )
    payload = policy.model_dump(mode="json")

    assert policy.schema_version == "2.0"
    assert len(policy.role_policies) == 4
    payload["role_policies"] = payload["role_policies"][:-1]
    payload["policy_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "policy_sha256"}
    )
    with pytest.raises(ValidationError, match="every role class"):
        QualificationPolicy.model_validate(payload)


def test_legacy_result_keeps_role_v2_fields_out_of_its_sealed_shape() -> None:
    result = _sealed_result(
        disposition=QualificationDisposition.TIER_A,
        approved_roles=("whole_protocol_review",),
    )
    payload = result.model_dump(mode="json")

    assert "declared_roles" not in payload
    assert "role_results" not in payload
    assert result.result_sha256 == canonical_sha256(
        result.model_dump(mode="json", exclude={"result_sha256"})
    )


def test_tier_a_can_be_investigator_only_without_authorizing_validator_roles() -> None:
    role_results = evaluate_role_qualification_results(
        global_disposition=QualificationDisposition.TIER_A,
        dimensions=_dimensions(),
        role_policies=_role_policies(),
    )
    declared = (
        "access_control",
        "falsifier",
        "judge",
        "verifier",
        "whole_protocol_review",
    )

    approved = derive_approved_roles_for_role_qualification(
        declared_roles=declared,
        global_disposition=QualificationDisposition.TIER_A,
        role_results=role_results,
    )

    assert {result.role_class: result.disposition for result in role_results} == {
        QualificationRoleClass.FALSIFIER: RoleQualificationDisposition.NOT_QUALIFIED,
        QualificationRoleClass.INVESTIGATOR: RoleQualificationDisposition.QUALIFIED,
        QualificationRoleClass.JUDGE: RoleQualificationDisposition.NOT_QUALIFIED,
        QualificationRoleClass.VERIFIER: RoleQualificationDisposition.NOT_QUALIFIED,
    }
    assert approved == ("access_control", "whole_protocol_review")
    assert {"verifier", "falsifier", "judge"}.isdisjoint(approved)


def test_role_failure_is_bound_by_result_seal_and_removes_only_affected_roles() -> None:
    role_results = evaluate_role_qualification_results(
        global_disposition=QualificationDisposition.TIER_A,
        dimensions=_dimensions(),
        role_policies=_role_policies(),
    )
    approved = derive_approved_roles_for_role_qualification(
        declared_roles=("access_control", "falsifier", "verifier"),
        global_disposition=QualificationDisposition.TIER_A,
        role_results=role_results,
    )
    result = _sealed_result(
        disposition=QualificationDisposition.TIER_A,
        role_results=role_results,
        approved_roles=approved,
        declared_roles=("access_control", "falsifier", "verifier"),
    )
    payload = result.model_dump(mode="json")
    payload["role_results"][0]["disposition"] = "qualified"

    with pytest.raises(ValidationError):
        ModelQualificationResult.model_validate(payload)

    with pytest.raises(ValidationError, match="undeclared"):
        _sealed_result(
            disposition=QualificationDisposition.TIER_A,
            role_results=role_results,
            approved_roles=("judge",),
            declared_roles=("access_control",),
        )


def test_one_validator_failure_removes_only_that_declared_role() -> None:
    role_results = evaluate_role_qualification_results(
        global_disposition=QualificationDisposition.TIER_A,
        dimensions=_dimensions(reduced=frozenset({ModelBenchmarkDimension.VERIFIER_QUALITY})),
        role_policies=_role_policies(),
    )

    approved = derive_approved_roles_for_role_qualification(
        declared_roles=("access_control", "falsifier", "judge", "verifier"),
        global_disposition=QualificationDisposition.TIER_A,
        role_results=role_results,
    )

    assert approved == ("access_control", "falsifier")


def test_role_approval_requires_global_tier_a_baseline() -> None:
    role_results = evaluate_role_qualification_results(
        global_disposition=QualificationDisposition.NOT_QUALIFIED,
        dimensions=_dimensions(),
        role_policies=_role_policies(),
    )

    assert all(
        result.disposition is RoleQualificationDisposition.NOT_QUALIFIED for result in role_results
    )
    assert (
        derive_approved_roles_for_role_qualification(
            declared_roles=("access_control", "whole_protocol_review"),
            global_disposition=QualificationDisposition.NOT_QUALIFIED,
            role_results=role_results,
        )
        == ()
    )


@pytest.mark.asyncio
async def test_workflow_refuses_role_policy_without_live_calibration_evidence() -> None:
    manifest, discovery_evidence, legacy_registry = workflow_fixtures._candidate_inputs()
    declared_roles = ("falsifier", "judge", "verifier", "whole_protocol_review")
    candidate = CandidateModel.model_validate(
        legacy_registry.candidates[0]
        .model_copy(update={"approved_roles": declared_roles})
        .model_dump(mode="json")
    )
    registry = seal_candidate_registry(
        created_at=legacy_registry.created_at,
        discovery_run_sha256=legacy_registry.discovery_run_sha256,
        candidates=(candidate,),
    )
    policy = seal_qualification_policy(
        created_at=workflow_fixtures.NOW,
        thresholds=_global_thresholds(calibrated=True),
        role_policies=_role_policies(calibrated=True),
        calibration_artifact_sha256="8" * 64,
        calibration_included_candidate_count=3,
        calibration_included_root_lineage_count=3,
        tier_a_minimum_overall_score=0.75,
        tier_a_overall_rationale="Synthetic measured Tier A aggregate threshold rationale.",
        maximum_validity_days=30,
    )
    report = workflow_fixtures._as_real_report(
        await workflow_fixtures._mock_report(),
        candidate=candidate,
    )
    portfolio, campaign_verification = workflow_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
        policy=policy,
    )
    release_bindings = workflow_fixtures._release_bindings(report)

    with pytest.raises(ValueError, match="live calibration evidence"):
        run_qualification_workflow(
            candidate_registry=registry,
            discovery_run_manifest=manifest,
            discovery_evidence=discovery_evidence,
            policy=policy,
            benchmark_suite=load_model_benchmark_corpus(workflow_fixtures.CORPUS_PATH),
            benchmark_portfolio=portfolio,
            benchmark_reports=(report,),
            release_bindings=release_bindings,
            trusted_campaign_verification=campaign_verification,
            trusted_generation_verification=None,
            trusted_release_observation=synthetic_release_observation(
                release_bindings,
                observed_at=workflow_fixtures.NOW + timedelta(hours=1),
            ),
            evaluated_at=workflow_fixtures.NOW + timedelta(hours=1),
            qualification_expires_at=workflow_fixtures.NOW + timedelta(days=6),
        )
