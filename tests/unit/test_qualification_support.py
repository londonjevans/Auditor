from __future__ import annotations

import hashlib
from datetime import timedelta

from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from tests.qualification_support import synthetic_production_qualification
from tests.unit.test_model_registry import _verified_production_config_and_capability


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def test_synthetic_qualification_projects_exact_candidate_registry_routes() -> None:
    config, seed, observed_at = _verified_production_config_and_capability()
    model_ids_by_root: dict[str, list[str]] = {}
    for model in seed.models:
        model_ids_by_root.setdefault(model.root_lineage, []).append(model.exact_model_id)
    reviews = {
        root_lineage: seal_operator_lineage_review(
            status=LineageReviewStatus.APPROVED,
            reviewed_model_ids=tuple(sorted(model_ids)),
            rationale="Synthetic approved lineage for refresh-runtime fixture coverage.",
            root_lineage=root_lineage,
            reviewed_by="synthetic-refresh-runtime-test",
            reviewed_at=observed_at,
            evidence_sha256=_sha(f"lineage-review:{root_lineage}"),
        )
        for root_lineage, model_ids in model_ids_by_root.items()
    }
    candidates = []
    for index, model in enumerate(seed.models):
        candidates.append(
            CandidateModel(
                exact_model_id=model.exact_model_id,
                canonical_model_slug=model.canonical_model_slug,
                root_lineage=model.root_lineage,
                lineage_review=reviews[model.root_lineage],
                discovery_evidence_sha256=_sha(f"discovery:{model.exact_model_id}"),
                approved_provider_endpoint=f"refresh-provider-{index}/fp8",
                approved_provider_name=f"Refresh Provider {index}",
                endpoint_snapshot_sha256=_sha(f"refresh-endpoint:{model.exact_model_id}"),
                output_capability_sha256=_sha(f"refresh-output:{model.exact_model_id}"),
                model_metadata_snapshot_sha256=_sha(f"refresh-metadata:{model.exact_model_id}"),
                pricing_snapshot_sha256=_sha(f"refresh-pricing:{model.exact_model_id}"),
                context_size=100_000,
                max_prompt_tokens=90_000,
                max_prompt_tokens_source="metadata",
                output_limit=8_192,
                output_limit_source="metadata",
                structured_output_supported=True,
                structured_output_mode=StructuredOutputMode.JSON_OBJECT,
                reasoning_supported=True,
                zdr_eligible=True,
                data_collection_deny_eligible=True,
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PASSED,
                benchmark_artifact_sha256=_sha(f"report:{model.exact_model_id}"),
                qualification_expires_at=observed_at + timedelta(days=30),
                approved_roles=model.approved_roles,
            )
        )
    registry = seal_candidate_registry(
        created_at=observed_at,
        discovery_run_sha256=_sha("refresh-discovery-run"),
        candidates=tuple(candidates),
    )

    qualification = synthetic_production_qualification(
        config,
        observed_at,
        candidate_registry=registry,
    )

    assert qualification.candidate_registry_sha256 == registry.registry_sha256
    assert qualification.bindings.candidate_registry_sha256 == registry.registry_sha256
    by_model = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    for model in qualification.models:
        candidate = by_model[model.exact_model_id]
        assert model.canonical_model_slug == candidate.canonical_model_slug
        assert model.root_lineage == candidate.root_lineage
        assert model.approved_provider_endpoint == candidate.approved_provider_endpoint
        assert model.approved_provider_name == candidate.approved_provider_name
        assert model.endpoint_snapshot_sha256 == candidate.endpoint_snapshot_sha256
        assert model.output_capability_sha256 == candidate.output_capability_sha256
        assert model.model_metadata_snapshot_sha256 == candidate.model_metadata_snapshot_sha256
        assert model.pricing_snapshot_sha256 == candidate.pricing_snapshot_sha256
        assert model.structured_output_mode is candidate.structured_output_mode
        assert all(
            binding.approved_provider_endpoint == candidate.approved_provider_endpoint
            and binding.approved_provider_name == candidate.approved_provider_name
            for binding in model.reasoning_bindings
        )
