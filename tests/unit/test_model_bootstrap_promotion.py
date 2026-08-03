from __future__ import annotations

from datetime import timedelta

import pytest

from mmaudit.config import AuditConfig, ModelLineageConfig
from mmaudit.models.qualification_workflow import promote_qualified_model_lineages
from mmaudit.models.registry import ModelRegistry
from tests.conftest import MODEL_IDS, base_config_data
from tests.unit import test_model_qualification as qualification_fixtures


def _identity_records() -> tuple[
    qualification_fixtures._Bundle,
    tuple[ModelLineageConfig, ...],
]:
    bundle = qualification_fixtures._bundle()
    candidates = {candidate.exact_model_id: candidate for candidate in bundle.registry.candidates}
    identities: list[ModelLineageConfig] = []
    for model_id in bundle.verification.eligible_tier_a_model_ids:
        candidate = candidates[model_id]
        assert candidate.root_lineage is not None
        identities.append(
            ModelLineageConfig(
                root_lineage=candidate.root_lineage,
                canonical_model_id=model_id,
                aliases=(),
                retention_policy="zero",
            )
        )
    return bundle, tuple(identities)


def test_promotion_attaches_only_exact_benchmark_derived_quality() -> None:
    bundle, identities = _identity_records()
    results = {result.exact_model_id: result for result in bundle.artifact.results}

    promoted = promote_qualified_model_lineages(
        declared_identities=identities,
        candidate_registry=bundle.registry,
        qualification_artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        promoted_at=qualification_fixtures._NOW + timedelta(hours=3),
    )

    assert tuple(item.canonical_model_id for item in promoted) == tuple(sorted(results))
    assert all(identity.measured_quality is None for identity in identities)
    for identity in promoted:
        result = results[identity.canonical_model_id]
        assert identity.aliases == ()
        assert identity.measured_quality is not None
        assert identity.measured_quality.score == result.overall_score
        assert identity.measured_quality.tier == "highest"
        assert identity.measured_quality.measurement == (
            f"sha256:{result.quality_measurement_sha256}"
        )


def test_promotion_preserves_aliases_and_rejects_already_measured_records() -> None:
    bundle, identities = _identity_records()
    promoted_at = qualification_fixtures._NOW + timedelta(hours=3)
    alias_bearing = (
        identities[0].model_copy(update={"aliases": ("synthetic/alias-model",)}),
        *identities[1:],
    )

    promoted = promote_qualified_model_lineages(
        declared_identities=alias_bearing,
        candidate_registry=bundle.registry,
        qualification_artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        promoted_at=promoted_at,
    )
    assert promoted[0].aliases == ("synthetic/alias-model",)
    with pytest.raises(ValueError, match="unmeasured"):
        promote_qualified_model_lineages(
            declared_identities=promoted,
            candidate_registry=bundle.registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=promoted_at,
        )


def test_promoted_alias_identity_passes_exact_current_production_validation() -> None:
    bundle, identities = _identity_records()
    identities = (
        identities[0].model_copy(update={"aliases": ("synthetic/measurement-alias",)}),
        *identities[1:],
    )
    observed_at = qualification_fixtures._NOW + timedelta(hours=4)
    promoted = promote_qualified_model_lineages(
        declared_identities=identities,
        candidate_registry=bundle.registry,
        qualification_artifact=bundle.artifact,
        qualification_verification=bundle.verification,
        promoted_at=qualification_fixtures._NOW + timedelta(hours=3),
    )
    results = bundle.artifact.results
    role_models = {
        role: {"primary": results[index].exact_model_id, "fallbacks": []}
        for index, role in enumerate(MODEL_IDS)
    }
    role_models["specialists"] = {
        "access_control": {"primary": results[6].exact_model_id, "fallbacks": []},
        "report_quality": {"primary": results[7].exact_model_id, "fallbacks": []},
    }
    data = base_config_data()
    data["privacy"]["approved_model_lineages"] = sorted(
        {identity.root_lineage for identity in promoted}
    )
    data["models"].update(
        {
            "provider_policy": {
                "only": sorted({result.approved_provider_endpoint for result in results}),
                "allow_fallbacks": False,
            },
            "registry": [identity.model_dump(mode="json") for identity in promoted],
            **role_models,
        }
    )
    config = AuditConfig.model_validate(data)
    qualification = qualification_fixtures._resolve_for_test(
        bundle,
        production_effective_config_sha256=config.stable_hash(),
    )

    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    metadata = [
        {"id": result.exact_model_id, "supported_parameters": ["response_format"]}
        for result in results
    ]
    errors = ModelRegistry.validate(
        config,
        metadata,
        require_verified_qualification=True,
        production_qualification=qualification,
        qualification_now=observed_at,
    )

    assert validation.valid
    assert not errors
    assert config.models.registry[0].aliases == ("synthetic/measurement-alias",)


def test_promotion_rejects_identity_set_root_and_evidence_mismatches() -> None:
    bundle, identities = _identity_records()
    promoted_at = qualification_fixtures._NOW + timedelta(hours=3)

    with pytest.raises(ValueError, match="eligible Tier A models"):
        promote_qualified_model_lineages(
            declared_identities=identities[:-1],
            candidate_registry=bundle.registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=promoted_at,
        )

    wrong_root = (
        identities[0].model_copy(update={"root_lineage": "sha256:" + ("f" * 64)}),
        *identities[1:],
    )
    with pytest.raises(ValueError, match="evidence differs"):
        promote_qualified_model_lineages(
            declared_identities=wrong_root,
            candidate_registry=bundle.registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=promoted_at,
        )

    different_registry = qualification_fixtures._bundle(root_count=7).registry
    with pytest.raises(ValueError, match="bindings are inconsistent"):
        promote_qualified_model_lineages(
            declared_identities=identities,
            candidate_registry=different_registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=promoted_at,
        )


def test_promotion_rejects_pending_invalid_stale_and_ambiguous_time() -> None:
    bundle, identities = _identity_records()

    with pytest.raises(ValueError, match="whole-second UTC"):
        promote_qualified_model_lineages(
            declared_identities=identities,
            candidate_registry=bundle.registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=(qualification_fixtures._NOW + timedelta(hours=3, microseconds=1)),
        )

    with pytest.raises(ValueError, match="evidence differs"):
        promote_qualified_model_lineages(
            declared_identities=identities,
            candidate_registry=bundle.registry,
            qualification_artifact=bundle.artifact,
            qualification_verification=bundle.verification,
            promoted_at=qualification_fixtures._NOW + timedelta(days=7),
        )

    pending = qualification_fixtures._bundle(
        review_status=qualification_fixtures.LineageReviewStatus.PENDING
    )
    with pytest.raises(ValueError, match="production-ready"):
        promote_qualified_model_lineages(
            declared_identities=identities,
            candidate_registry=pending.registry,
            qualification_artifact=pending.artifact,
            qualification_verification=pending.verification,
            promoted_at=qualification_fixtures._NOW + timedelta(hours=3),
        )

    mock_only = qualification_fixtures._bundle(
        benchmark_execution=qualification_fixtures.ExecutionEvidenceKind.MOCK
    )
    with pytest.raises(ValueError, match="valid qualification verification"):
        promote_qualified_model_lineages(
            declared_identities=identities,
            candidate_registry=mock_only.registry,
            qualification_artifact=mock_only.artifact,
            qualification_verification=mock_only.verification,
            promoted_at=qualification_fixtures._NOW + timedelta(hours=3),
        )
