from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mmaudit.benchmark.models import ModelBenchmarkTarget, load_model_benchmark_corpus
from mmaudit.models.calibration import ModelCalibrationArtifact, build_model_calibration_artifact
from mmaudit.models.discovery import OpenRouterModelDiscoveryRunManifest
from mmaudit.models.lineage_authority import (
    ModelLineageAuthorityEnvelope,
    ModelLineageAuthorityStatement,
    TrustedModelLineageReviewVerification,
    build_model_lineage_authority_envelope,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.lineage_transition import (
    ModelLineageRegistryTransitionError,
    build_identity_reviewed_candidate_registry,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateRegistry,
    LineageReviewStatus,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit import test_model_calibration as calibration_fixtures
from tests.unit import test_model_lineage_authority as authority_fixtures
from tests.unit import test_model_lineage_review as lineage_fixtures
from tests.unit import test_qualification_workflow as workflow_fixtures


@dataclass(frozen=True)
class _TransitionInputs:
    registry: CandidateRegistry
    manifest: OpenRouterModelDiscoveryRunManifest
    review: ModelLineageReviewArtifact
    envelope: ModelLineageAuthorityEnvelope
    calibration: ModelCalibrationArtifact
    lineage_capability: TrustedModelLineageReviewVerification
    campaign_started_at: datetime | None


async def _transition_inputs(
    tmp_path: Path,
    *,
    status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    label: str = "transition",
    approved_roles: tuple[str, ...] = (),
) -> _TransitionInputs:
    with patch.multiple(
        lineage_fixtures,
        DISCOVERED_AT=calibration_fixtures.LINEAGE_DISCOVERED_AT,
        REFRESHED_AT=calibration_fixtures.LINEAGE_REFRESHED_AT,
        CREATED_AT=calibration_fixtures.LINEAGE_CREATED_AT,
        EXPIRES_AT=calibration_fixtures.LINEAGE_EXPIRES_AT,
    ):
        bundle = lineage_fixtures._bundle(
            (workflow_fixtures.MODEL_ID,),
            approved_roles=approved_roles,
        )
        decision = lineage_fixtures._review(
            (workflow_fixtures.MODEL_ID,),
            label=label,
            status=status,
            reviewed_at=calibration_fixtures.LINEAGE_REVIEWED_AT,
        )
        review = lineage_fixtures._artifact(bundle, (decision,))

    signing_root = tmp_path / f"lineage-transition-{label}-{status.value}"
    signing_root.mkdir(mode=0o700)
    _anchor, envelope, lineage_capability = authority_fixtures._signed_authority(
        root=signing_root,
        artifact=review,
        signed_at=calibration_fixtures.LINEAGE_SIGNED_AT,
        expires_at=calibration_fixtures.LINEAGE_AUTHORITY_EXPIRES_AT,
    )
    candidate = bundle.registry.candidates[0]
    report = workflow_fixtures._as_real_report(
        await workflow_fixtures._mock_report(
            target=ModelBenchmarkTarget(
                model_id=candidate.exact_model_id,
                root_lineage=None,
            )
        ),
        candidate=candidate,
    )
    portfolio, campaign_capability = workflow_fixtures._portfolio_evidence(
        registry=bundle.registry,
        report=report,
    )
    calibration = build_model_calibration_artifact(
        created_at=calibration_fixtures.NOW,
        candidate_registry=bundle.registry,
        discovery_run_manifest=bundle.manifest,
        benchmark_suite=load_model_benchmark_corpus(calibration_fixtures.CORPUS_PATH),
        benchmark_portfolio=portfolio,
        benchmark_reports=(report,),
        benchmark_policy_sha256=workflow_fixtures._policy().policy_sha256,
        effective_config_sha256=calibration_fixtures.EFFECTIVE_CONFIG_SHA256,
        trusted_campaign_verification=campaign_capability,
        lineage_review_artifact=review,
        trusted_lineage_verification=lineage_capability,
    )
    assert calibration.lineage_authority_envelope_sha256 == envelope.authority_envelope_sha256
    return _TransitionInputs(
        registry=bundle.registry,
        manifest=bundle.manifest,
        review=review,
        envelope=envelope,
        calibration=calibration,
        lineage_capability=lineage_capability,
        campaign_started_at=portfolio.started_at,
    )


def _reseal_calibration(payload: dict[str, Any]) -> ModelCalibrationArtifact:
    payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )
    return ModelCalibrationArtifact.model_validate(payload)


def _transition(inputs: _TransitionInputs) -> CandidateRegistry:
    return build_identity_reviewed_candidate_registry(
        candidate_registry=inputs.registry,
        lineage_review_artifact=inputs.review,
        lineage_authority_envelope=inputs.envelope,
        calibration_artifact=inputs.calibration,
        **_authority_arguments(inputs),
    )


def _authority_arguments(inputs: _TransitionInputs) -> dict[str, Any]:
    assert inputs.campaign_started_at is not None
    return {
        "discovery_run_manifest": inputs.manifest,
        "trusted_lineage_verification": inputs.lineage_capability,
        "campaign_started_at": inputs.campaign_started_at,
        "observed_at": calibration_fixtures.NOW,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    [LineageReviewStatus.APPROVED, LineageReviewStatus.REJECTED],
)
async def test_transition_applies_complete_decisions_without_quality_or_selection_authority(
    tmp_path: Path,
    status: LineageReviewStatus,
) -> None:
    inputs = await _transition_inputs(tmp_path, status=status, label=status.value)
    source_before = inputs.registry.model_dump(mode="json")

    reviewed = _transition(inputs)

    source_candidate = inputs.registry.candidates[0]
    reviewed_candidate = reviewed.candidates[0]
    binding = inputs.review.candidate_bindings[0]
    assert inputs.registry.model_dump(mode="json") == source_before
    assert reviewed.registry_sha256 != inputs.registry.registry_sha256
    assert reviewed.created_at == inputs.registry.created_at
    assert reviewed.discovery_run_sha256 == inputs.registry.discovery_run_sha256
    assert reviewed_candidate.lineage_review.model_dump(mode="json") == (
        inputs.review.reviews[0].model_dump(mode="json")
    )
    assert reviewed_candidate.lineage_review.status is status
    assert reviewed_candidate.root_lineage == binding.root_lineage
    assert (reviewed_candidate.root_lineage is not None) is (status is LineageReviewStatus.APPROVED)
    assert reviewed_candidate.benchmark_status is CandidateBenchmarkStatus.PENDING
    assert reviewed_candidate.benchmark_artifact_sha256 is None
    assert reviewed_candidate.qualification_expires_at is None
    assert reviewed_candidate.approved_roles == ()
    assert not hasattr(reviewed, "source_egress_authorized")
    assert not hasattr(reviewed, "production_selection_authorized")
    assert source_candidate.model_dump(
        mode="json", exclude={"root_lineage", "lineage_review"}
    ) == reviewed_candidate.model_dump(mode="json", exclude={"root_lineage", "lineage_review"})


@pytest.mark.asyncio
async def test_transition_preserves_conditional_role_declarations(tmp_path: Path) -> None:
    roles = ("falsifier", "judge", "verifier", "whole_protocol_review")
    inputs = await _transition_inputs(
        tmp_path,
        label="conditional-roles",
        approved_roles=roles,
    )

    reviewed = _transition(inputs)

    assert inputs.registry.candidates[0].approved_roles == roles
    assert reviewed.candidates[0].approved_roles == roles
    assert reviewed.candidates[0].benchmark_status is CandidateBenchmarkStatus.PENDING
    assert reviewed.candidates[0].benchmark_artifact_sha256 is None
    assert reviewed.candidates[0].qualification_expires_at is None


@pytest.mark.asyncio
async def test_transition_rejects_wrong_registry_review_calibration_and_envelope(
    tmp_path: Path,
) -> None:
    inputs = await _transition_inputs(tmp_path)

    candidate_payload = inputs.registry.candidates[0].model_dump(mode="json")
    candidate_payload["output_limit"] = inputs.registry.candidates[0].output_limit - 1
    changed_candidate = CandidateModel.model_validate(candidate_payload)
    changed_registry = seal_candidate_registry(
        created_at=inputs.registry.created_at,
        discovery_run_sha256=inputs.registry.discovery_run_sha256,
        candidates=(changed_candidate,),
    )
    with pytest.raises(ModelLineageRegistryTransitionError, match="exact R0"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=changed_registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=inputs.calibration,
            **_authority_arguments(inputs),
        )

    review_payload = inputs.review.model_dump(mode="json")
    review_payload["candidate_registry_sha256"] = "f" * 64
    review_payload["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in review_payload.items() if key != "artifact_sha256"}
    )
    wrong_review = ModelLineageReviewArtifact.model_validate(review_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="exact R0"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=wrong_review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=inputs.calibration,
            **_authority_arguments(inputs),
        )

    calibration_payload = inputs.calibration.model_dump(mode="json")
    calibration_payload["candidate_registry_sha256"] = "e" * 64
    wrong_calibration = _reseal_calibration(calibration_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="calibration artifact differs"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=wrong_calibration,
            **_authority_arguments(inputs),
        )

    other_signing_root = tmp_path / "other-lineage-envelope"
    other_signing_root.mkdir(mode=0o700)
    _anchor, wrong_envelope, _capability = authority_fixtures._signed_authority(
        root=other_signing_root,
        artifact=inputs.review,
        signed_at=calibration_fixtures.LINEAGE_SIGNED_AT,
        expires_at=calibration_fixtures.LINEAGE_AUTHORITY_EXPIRES_AT,
    )
    with pytest.raises(ModelLineageRegistryTransitionError, match="calibration artifact differs"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=wrong_envelope,
            calibration_artifact=inputs.calibration,
            **_authority_arguments(inputs),
        )

    statement_payload = inputs.envelope.statement.model_dump(mode="json")
    mistimed_signed_at = inputs.review.created_at - timedelta(seconds=1)
    statement_payload["signed_at"] = mistimed_signed_at.isoformat().replace("+00:00", "Z")
    statement_payload["statement_sha256"] = canonical_sha256(
        {key: value for key, value in statement_payload.items() if key != "statement_sha256"}
    )
    mistimed_statement = ModelLineageAuthorityStatement.model_validate_json(
        json.dumps(statement_payload),
        strict=True,
    )
    mistimed_envelope = build_model_lineage_authority_envelope(
        statement=mistimed_statement,
        detached_signature=inputs.envelope.detached_signature,
    )
    mistimed_calibration_payload = inputs.calibration.model_dump(mode="json")
    mistimed_calibration_payload["lineage_authority_envelope_sha256"] = (
        mistimed_envelope.authority_envelope_sha256
    )
    mistimed_calibration = _reseal_calibration(mistimed_calibration_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="envelope differs"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=mistimed_envelope,
            calibration_artifact=mistimed_calibration,
            **_authority_arguments(inputs),
        )


@pytest.mark.asyncio
async def test_transition_rejects_calibration_root_and_binding_splices(tmp_path: Path) -> None:
    inputs = await _transition_inputs(tmp_path)

    binding_payload = inputs.calibration.model_dump(mode="json")
    binding_payload["candidates"][0]["lineage_binding_sha256"] = "d" * 64
    wrong_binding = _reseal_calibration(binding_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="lineage projection"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=wrong_binding,
            **_authority_arguments(inputs),
        )

    wrong_root_value = "sha256:" + ("c" * 64)
    root_payload = inputs.calibration.model_dump(mode="json")
    root_payload["candidates"][0]["root_lineage"] = wrong_root_value
    for distribution in root_payload["distributions"]:
        distribution["observations"][0]["root_lineage"] = wrong_root_value
    wrong_root = _reseal_calibration(root_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="lineage projection"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=wrong_root,
            **_authority_arguments(inputs),
        )


@pytest.mark.asyncio
async def test_transition_rejects_junk_signature_and_wrong_or_forged_authority(
    tmp_path: Path,
) -> None:
    inputs = await _transition_inputs(tmp_path, label="authenticated-transition")
    signature = inputs.envelope.detached_signature
    replacement = "A" if signature[40] != "A" else "B"
    junk_envelope = build_model_lineage_authority_envelope(
        statement=inputs.envelope.statement,
        detached_signature=signature[:40] + replacement + signature[41:],
    )
    junk_payload = inputs.calibration.model_dump(mode="json")
    junk_payload["lineage_authority_envelope_sha256"] = junk_envelope.authority_envelope_sha256
    junk_calibration = _reseal_calibration(junk_payload)
    with pytest.raises(ModelLineageRegistryTransitionError, match="trusted lineage projection"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=junk_envelope,
            calibration_artifact=junk_calibration,
            **_authority_arguments(inputs),
        )

    other_root = tmp_path / "wrong-live-lineage-authority"
    other_root.mkdir(mode=0o700)
    _anchor, _envelope, wrong_capability = authority_fixtures._signed_authority(
        root=other_root,
        artifact=inputs.review,
        signed_at=calibration_fixtures.LINEAGE_SIGNED_AT,
        expires_at=calibration_fixtures.LINEAGE_AUTHORITY_EXPIRES_AT,
    )
    assert inputs.campaign_started_at is not None
    with pytest.raises(ModelLineageRegistryTransitionError, match="trusted lineage projection"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=inputs.calibration,
            discovery_run_manifest=inputs.manifest,
            trusted_lineage_verification=wrong_capability,
            campaign_started_at=inputs.campaign_started_at,
            observed_at=calibration_fixtures.NOW,
        )
    with pytest.raises(ModelLineageRegistryTransitionError, match="fresh trusted lineage"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=inputs.calibration,
            discovery_run_manifest=inputs.manifest,
            trusted_lineage_verification=object(),  # type: ignore[arg-type]
            campaign_started_at=inputs.campaign_started_at,
            observed_at=calibration_fixtures.NOW,
        )


@pytest.mark.asyncio
async def test_transition_rejects_missing_reordered_spliced_or_pending_inputs(
    tmp_path: Path,
) -> None:
    inputs = await _transition_inputs(tmp_path)
    source = inputs.registry.candidates[0]
    second_payload = source.model_dump(mode="json")
    second_payload["exact_model_id"] = "alpha/model-zero"
    second_payload["canonical_model_slug"] = "alpha/model-zero"
    second_payload["lineage_review"] = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=("alpha/model-zero",),
        rationale="Synthetic candidate remains pending exact lineage review.",
    ).model_dump(mode="json")
    second = CandidateModel.model_validate(second_payload)

    malformed_registries = (
        CandidateRegistry.model_construct(
            schema_version="1.0",
            created_at=inputs.registry.created_at,
            discovery_run_sha256=inputs.registry.discovery_run_sha256,
            candidates=(source, second),
            registry_sha256=inputs.registry.registry_sha256,
        ),
        CandidateRegistry.model_construct(
            schema_version="1.0",
            created_at=inputs.registry.created_at,
            discovery_run_sha256=inputs.registry.discovery_run_sha256,
            candidates=(second, source),
            registry_sha256=inputs.registry.registry_sha256,
        ),
    )
    for malformed in malformed_registries:
        with pytest.raises(ModelLineageRegistryTransitionError, match="R0 candidate registry"):
            build_identity_reviewed_candidate_registry(
                candidate_registry=malformed,
                lineage_review_artifact=inputs.review,
                lineage_authority_envelope=inputs.envelope,
                calibration_artifact=inputs.calibration,
                **_authority_arguments(inputs),
            )

    missing_calibration = ModelCalibrationArtifact.model_construct(
        **{
            **inputs.calibration.__dict__,
            "candidates": (),
        }
    )
    with pytest.raises(ModelLineageRegistryTransitionError, match="calibration artifact"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=inputs.review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=missing_calibration,
            **_authority_arguments(inputs),
        )

    pending_binding = inputs.review.candidate_bindings[0].model_copy(
        update={"decision": LineageReviewStatus.PENDING, "root_lineage": None}
    )
    pending_review = ModelLineageReviewArtifact.model_construct(
        **{
            **inputs.review.__dict__,
            "candidate_bindings": (pending_binding,),
        }
    )
    with pytest.raises(ModelLineageRegistryTransitionError, match="lineage review artifact"):
        build_identity_reviewed_candidate_registry(
            candidate_registry=inputs.registry,
            lineage_review_artifact=pending_review,
            lineage_authority_envelope=inputs.envelope,
            calibration_artifact=inputs.calibration,
            **_authority_arguments(inputs),
        )
