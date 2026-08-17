from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.policy_eligibility import (
    ModelPolicyEligibilityArtifact,
    PolicyCriterionDisposition,
    PolicyEligibilityDecision,
    PolicyEligibilityRoute,
    PolicyEvidenceKind,
    PolicyLegalCriterion,
    PolicyReviewReason,
    PolicyUsePurpose,
    build_model_policy_eligibility_artifact,
    build_model_policy_eligibility_determination,
    build_official_policy_evidence_reference,
    build_policy_criterion_assessment,
    build_policy_eligibility_route,
    build_policy_eligibility_source_reference_observation,
    policy_review_signal,
)
from mmaudit.models.policy_eligibility_authority import (
    PolicyEligibilitySourceObservation,
    build_policy_eligibility_source_commitment,
    build_policy_eligibility_source_observation,
)
from mmaudit.models.policy_eligibility_refresh import (
    POLICY_ELIGIBILITY_REFRESH_FILENAME,
    ModelPolicyEligibilityRefreshArtifact,
    ModelPolicyEligibilityRefreshError,
    PolicyEligibilityRefreshRouteDisposition,
    build_model_policy_eligibility_refresh_artifact,
    load_model_policy_eligibility_artifact,
    load_model_policy_eligibility_refresh_artifact,
    load_policy_eligibility_checked_routes,
    load_policy_eligibility_source_observation,
    verify_model_policy_eligibility_refresh_artifact,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.refresh import ModelRefreshSnapshot, build_model_refresh_snapshot
from mmaudit.reporting.json_report import stable_json

OBSERVED_AT = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
EVIDENCE_RETRIEVED_AT = datetime(2026, 8, 1, 8, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 8, 2, 8, 0, tzinfo=UTC)
EFFECTIVE_AT = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)
CURRENT_EXPIRES_AT = datetime(2026, 8, 25, 8, 0, tzinfo=UTC)
SOURCE_OBSERVATION_EXPIRES_AT = OBSERVED_AT + timedelta(hours=12)
PARAMETERS = ["max_tokens", "reasoning", "response_format", "temperature"]


@dataclass(frozen=True)
class _RefreshPolicyBundle:
    snapshot: ModelRefreshSnapshot
    artifact: ModelPolicyEligibilityArtifact
    observation: PolicyEligibilitySourceObservation
    routes: tuple[PolicyEligibilityRoute, ...]


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _route(
    exact_model_id: str,
    provider_name: str,
    provider_endpoint: str,
) -> PolicyEligibilityRoute:
    return build_policy_eligibility_route(
        exact_model_id=exact_model_id,
        provider_name=provider_name,
        provider_endpoint=provider_endpoint,
    )


def _routes() -> tuple[PolicyEligibilityRoute, ...]:
    return tuple(
        sorted(
            (
                _route("alpha/current-1", "Provider Alpha", "provider-alpha/current"),
                _route("beta/expired-1", "Provider Beta", "provider-beta/expired"),
                _route("delta/changed-1", "Provider Delta", "provider-delta/changed"),
                _route("epsilon/review-1", "Provider Epsilon", "provider-epsilon/review"),
                _route("zeta/missing-1", "Provider Zeta", "provider-zeta/missing"),
            ),
            key=lambda route: route.identity,
        )
    )


def _assessment_dispositions(
    decision: PolicyEligibilityDecision,
) -> dict[PolicyLegalCriterion, PolicyCriterionDisposition]:
    if decision is PolicyEligibilityDecision.REVIEW_REQUIRED:
        return {PolicyLegalCriterion.SOURCE_CODE_ANALYSIS: PolicyCriterionDisposition.AMBIGUOUS}
    return {}


def _policy_artifact(
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    evidence_tag: str = "base",
    include_second_reference: bool = False,
) -> ModelPolicyEligibilityArtifact:
    first_evidence = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.COMMERCIAL_TERMS,
        publisher="Synthetic Policy Publisher",
        official_source_url=f"https://example.invalid/policy/{evidence_tag}",
        retrieved_at=EVIDENCE_RETRIEVED_AT,
        content_sha256=_hash(f"policy-content:{evidence_tag}"),
        byte_count=512,
        source_version="synthetic-v1",
    )
    evidence = [first_evidence]
    if include_second_reference:
        evidence.append(
            build_official_policy_evidence_reference(
                kind=PolicyEvidenceKind.ROUTING_PROVIDER_TERMS,
                publisher="Synthetic Routing Policy Publisher",
                official_source_url=f"https://example.invalid/routing-policy/{evidence_tag}",
                retrieved_at=EVIDENCE_RETRIEVED_AT,
                content_sha256=_hash(f"routing-policy-content:{evidence_tag}"),
                byte_count=384,
                source_version="synthetic-v1",
            )
        )
    official_evidence = tuple(sorted(evidence, key=lambda item: item.reference_sha256))
    reference_sha256s = tuple(item.reference_sha256 for item in official_evidence)
    determinations = []
    for route in routes:
        if route.exact_model_id == "zeta/missing-1":
            continue
        decision = (
            PolicyEligibilityDecision.REVIEW_REQUIRED
            if route.exact_model_id == "epsilon/review-1"
            else PolicyEligibilityDecision.ELIGIBLE
        )
        overrides = _assessment_dispositions(decision)
        assessments = tuple(
            build_policy_criterion_assessment(
                criterion=criterion,
                disposition=overrides.get(
                    criterion,
                    PolicyCriterionDisposition.PERMITTED,
                ),
                evidence_reference_sha256s=reference_sha256s,
                assessment_record_sha256=_hash(
                    f"assessment:{route.exact_model_id}:{criterion.value}:{evidence_tag}"
                ),
            )
            for criterion in sorted(PolicyLegalCriterion, key=lambda item: item.value)
        )
        expires_at = OBSERVED_AT if route.exact_model_id == "beta/expired-1" else CURRENT_EXPIRES_AT
        determinations.append(
            build_model_policy_eligibility_determination(
                route=route,
                decision=decision,
                intended_use=PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
                applicable_client_entity_sha256s=(_hash("client-entity"),),
                applicable_client_jurisdictions=("GB",),
                applicable_operator_entity_sha256s=(_hash("operator-entity"),),
                applicable_operator_jurisdictions=("GB",),
                assessments=assessments,
                reviewed_by="synthetic-legal-reviewer",
                reviewed_at=REVIEWED_AT,
                effective_at=EFFECTIVE_AT,
                expires_at=expires_at,
                review_record_sha256=_hash(f"review:{route.exact_model_id}:{evidence_tag}"),
            )
        )
    return build_model_policy_eligibility_artifact(
        created_at=REVIEWED_AT + timedelta(hours=2),
        official_evidence=official_evidence,
        determinations=tuple(determinations),
    )


def _candidate(route: PolicyEligibilityRoute, *, snapshot_tag: str) -> CandidateModel:
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=(route.exact_model_id,),
        rationale="Synthetic lineage intentionally remains pending.",
    )
    return CandidateModel(
        exact_model_id=route.exact_model_id,
        canonical_model_slug=route.exact_model_id,
        root_lineage=None,
        lineage_review=review,
        discovery_evidence_sha256=_hash(f"discovery:{snapshot_tag}:{route.exact_model_id}"),
        approved_provider_endpoint=route.provider_endpoint,
        approved_provider_name=route.provider_name,
        endpoint_snapshot_sha256=_hash(f"endpoint:{snapshot_tag}:{route.exact_model_id}"),
        output_capability_sha256=_hash(f"output:{snapshot_tag}:{route.exact_model_id}"),
        model_metadata_snapshot_sha256=_hash(f"metadata:{snapshot_tag}:{route.exact_model_id}"),
        pricing_snapshot_sha256=_hash(f"pricing:{snapshot_tag}:{route.exact_model_id}"),
        context_size=100_000,
        max_prompt_tokens=91_808,
        max_prompt_tokens_source="metadata",
        output_limit=8_192,
        output_limit_source="metadata",
        structured_output_supported=True,
        structured_output_mode=StructuredOutputMode.JSON_OBJECT,
        reasoning_supported=True,
        zdr_eligible=True,
        data_collection_deny_eligible=True,
        operational_status=CandidateOperationalStatus.AVAILABLE,
        benchmark_status=CandidateBenchmarkStatus.PENDING,
    )


def _raw_model(route: PolicyEligibilityRoute) -> dict[str, Any]:
    return {
        "id": route.exact_model_id,
        "canonical_slug": route.exact_model_id,
        "context_length": 100_000,
        "top_provider": {
            "context_length": 100_000,
            "max_completion_tokens": 8_192,
        },
        "supported_parameters": list(PARAMETERS),
    }


def _raw_endpoint(
    route: PolicyEligibilityRoute,
    *,
    snapshot_tag: str,
) -> dict[str, Any]:
    prompt_price = "0.000001" if snapshot_tag == "base" else "0.000003"
    return {
        "model_id": route.exact_model_id,
        "slug": route.provider_endpoint,
        "provider_name": route.provider_name,
        "status": 0,
        "context_length": 100_000,
        "max_prompt_tokens": 91_808,
        "max_completion_tokens": 8_192,
        "supported_parameters": list(PARAMETERS),
        "pricing": {"completion": "0.000002", "prompt": prompt_price},
    }


def _endpoint_envelope(
    route: PolicyEligibilityRoute,
    *,
    snapshot_tag: str,
) -> dict[str, Any]:
    endpoint = _raw_endpoint(route, snapshot_tag=snapshot_tag)
    return {
        "data": {
            "id": route.exact_model_id,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }


def _snapshot(
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    snapshot_tag: str = "base",
    retrieved_at: datetime = OBSERVED_AT,
) -> ModelRefreshSnapshot:
    registry = seal_candidate_registry(
        created_at=retrieved_at,
        discovery_run_sha256=_hash(f"discovery-run:{snapshot_tag}"),
        candidates=tuple(_candidate(route, snapshot_tag=snapshot_tag) for route in routes),
    )
    endpoints = [_raw_endpoint(route, snapshot_tag=snapshot_tag) for route in routes]
    return build_model_refresh_snapshot(
        retrieved_at=retrieved_at,
        catalog_payload={"data": [_raw_model(route) for route in routes]},
        zdr_payload={"data": endpoints},
        candidate_registry=registry,
        candidate_endpoint_payloads={
            route.exact_model_id: _endpoint_envelope(
                route,
                snapshot_tag=snapshot_tag,
            )
            for route in routes
        },
        authenticated_metadata=True,
    )


def _observation(
    artifact: ModelPolicyEligibilityArtifact,
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    observed_at: datetime = OBSERVED_AT,
    expires_at: datetime = SOURCE_OBSERVATION_EXPIRES_AT,
    included_route_ids: frozenset[str] | None = None,
    current_content_by_reference: dict[str, str] | None = None,
) -> PolicyEligibilitySourceObservation:
    evidence_by_reference = {item.reference_sha256: item for item in artifact.official_evidence}
    determinations_by_route = {item.route.identity: item for item in artifact.determinations}
    determination_ids = {
        determination.route.exact_model_id for determination in artifact.determinations
    }
    included = determination_ids if included_route_ids is None else included_route_ids
    commitments = []
    for route in routes:
        if route.exact_model_id not in included:
            continue
        determination = determinations_by_route[route.identity]
        cited_references = tuple(
            sorted(
                {
                    reference_sha256
                    for assessment in determination.assessments
                    for reference_sha256 in assessment.evidence_reference_sha256s
                }
            )
        )
        reference_observations = tuple(
            build_policy_eligibility_source_reference_observation(
                reference=evidence_by_reference[reference_sha256],
                current_content_sha256=(
                    current_content_by_reference.get(
                        reference_sha256,
                        evidence_by_reference[reference_sha256].content_sha256,
                    )
                    if current_content_by_reference is not None
                    else (
                        _hash("changed-policy-content")
                        if route.exact_model_id == "delta/changed-1" and index == 0
                        else evidence_by_reference[reference_sha256].content_sha256
                    )
                ),
            )
            for index, reference_sha256 in enumerate(cited_references)
        )
        commitments.append(
            build_policy_eligibility_source_commitment(
                artifact=artifact,
                route=route,
                source_reference_observations=reference_observations,
            )
        )
    return build_policy_eligibility_source_observation(
        artifact=artifact,
        observed_at=observed_at,
        expires_at=expires_at,
        source_commitments=tuple(commitments),
    )


def _bundle() -> _RefreshPolicyBundle:
    routes = _routes()
    artifact = _policy_artifact(routes)
    return _RefreshPolicyBundle(
        snapshot=_snapshot(routes),
        artifact=artifact,
        observation=_observation(artifact, routes),
        routes=routes,
    )


def _projection(bundle: _RefreshPolicyBundle) -> ModelPolicyEligibilityRefreshArtifact:
    return build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=bundle.snapshot,
        policy_artifact=bundle.artifact,
        source_observation=bundle.observation,
        checked_routes=bundle.routes,
    )


def _write_canonical(path: Path, value: Any) -> None:
    path.write_text(stable_json(value), encoding="utf-8")
    path.chmod(0o600)


def test_daily_projection_classifies_every_route_without_positive_authority() -> None:
    bundle = _bundle()
    projection = _projection(bundle)

    records = {record.route.exact_model_id: record for record in projection.route_records}
    assert tuple(record.route for record in projection.route_records) == bundle.routes
    assert records["alpha/current-1"].disposition is (
        PolicyEligibilityRefreshRouteDisposition.NO_REVIEW_SIGNAL
    )
    assert records["alpha/current-1"].review_reasons == ()
    assert records["beta/expired-1"].review_reasons == (PolicyReviewReason.EXPIRED,)
    assert records["delta/changed-1"].review_reasons == (PolicyReviewReason.SOURCE_CHANGED,)
    assert records["epsilon/review-1"].review_reasons == (PolicyReviewReason.REVIEW_REQUIRED,)
    assert records["zeta/missing-1"].review_reasons == (PolicyReviewReason.MISSING,)
    assert all(
        record.disposition is PolicyEligibilityRefreshRouteDisposition.REDETERMINATION_REQUIRED
        for model_id, record in records.items()
        if model_id != "alpha/current-1"
    )
    assert projection.redetermination_required is True
    assert projection.refresh_snapshot_sha256 == bundle.snapshot.snapshot_sha256
    assert projection.refresh_source_evidence_sha256 == bundle.snapshot.source_evidence_sha256
    assert projection.refresh_semantic_sha256 == bundle.snapshot.semantic_sha256
    assert projection.policy_artifact_sha256 == bundle.artifact.artifact_sha256
    assert projection.source_observation == bundle.observation
    assert projection.observed_at == OBSERVED_AT
    assert projection.evidence_fresh_until == SOURCE_OBSERVATION_EXPIRES_AT
    assert projection.automated_eligibility_inference is False
    assert projection.policy_selection_authorized is False
    assert projection.qualification_authorized is False
    assert projection.source_egress_authorized is False
    assert projection.production_selection_authorized is False
    assert all(record.automated_eligibility_inference is False for record in records.values())
    assert "ELIGIBLE" not in {item.value for item in PolicyEligibilityRefreshRouteDisposition}

    commitments = {
        commitment.route.identity: commitment
        for commitment in bundle.observation.source_commitments
    }
    expected_signals = tuple(
        signal
        for route in bundle.routes
        if (
            signal := policy_review_signal(
                artifact=bundle.artifact,
                route=route,
                observed_at=bundle.snapshot.retrieved_at,
                source_reference_observations=(
                    None
                    if (commitment := commitments.get(route.identity)) is None
                    else commitment.source_reference_observations
                ),
            )
        )
        is not None
    )
    assert projection.review_signals == expected_signals

    verify_model_policy_eligibility_refresh_artifact(
        artifact=projection,
        refresh_snapshot=bundle.snapshot,
        policy_artifact=bundle.artifact,
        source_observation=bundle.observation,
        checked_routes=bundle.routes,
        used_at=OBSERVED_AT + timedelta(hours=1),
    )


def test_daily_projection_surfaces_per_reference_content_swap_for_review() -> None:
    route = _routes()[0]
    routes = (route,)
    artifact = _policy_artifact(routes, include_second_reference=True)
    evidence = artifact.official_evidence
    assert len(evidence) == 2
    assert evidence[0].content_sha256 != evidence[1].content_sha256
    observation = _observation(
        artifact,
        routes,
        current_content_by_reference={
            evidence[0].reference_sha256: evidence[1].content_sha256,
            evidence[1].reference_sha256: evidence[0].content_sha256,
        },
    )

    projection = build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=_snapshot(routes),
        policy_artifact=artifact,
        source_observation=observation,
        checked_routes=routes,
    )

    assert projection.redetermination_required is True
    assert projection.route_records[0].disposition is (
        PolicyEligibilityRefreshRouteDisposition.REDETERMINATION_REQUIRED
    )
    assert projection.route_records[0].review_reasons == (PolicyReviewReason.SOURCE_CHANGED,)
    assert projection.review_signals[0].reasons == (PolicyReviewReason.SOURCE_CHANGED,)
    assert projection.review_signals[0].source_reference_observations == (
        observation.source_commitments[0].source_reference_observations
    )
    assert len(projection.review_signals[0].source_reference_observations or ()) == 2


def test_no_signal_projection_remains_non_authorizing_and_has_no_eligible_state() -> None:
    route = _routes()[0]
    routes = (route,)
    artifact = _policy_artifact(routes)
    observation = _observation(artifact, routes)
    projection = build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=_snapshot(routes),
        policy_artifact=artifact,
        source_observation=observation,
        checked_routes=routes,
    )

    assert projection.review_signals == ()
    assert projection.redetermination_required is False
    assert projection.route_records[0].disposition is (
        PolicyEligibilityRefreshRouteDisposition.NO_REVIEW_SIGNAL
    )
    assert projection.route_records[0].redetermination_required is False
    assert projection.policy_selection_authorized is False
    assert projection.production_selection_authorized is False


@pytest.mark.parametrize(
    "included_route_ids",
    [
        frozenset({"alpha/current-1", "beta/expired-1", "delta/changed-1"}),
        frozenset(
            {
                "alpha/current-1",
                "beta/expired-1",
                "delta/changed-1",
                "epsilon/review-1",
            }
        ),
    ],
)
def test_projection_rejects_omitted_or_extra_source_observation_routes(
    included_route_ids: frozenset[str],
) -> None:
    bundle = _bundle()
    observation = _observation(
        bundle.artifact,
        bundle.routes,
        included_route_ids=included_route_ids,
    )
    checked_routes = bundle.routes if len(included_route_ids) == 3 else bundle.routes[:3]

    with pytest.raises(
        ModelPolicyEligibilityRefreshError,
        match="exactly cover determined checked routes",
    ):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=observation,
            checked_routes=checked_routes,
        )


def test_projection_rejects_reordered_observation_and_checked_routes() -> None:
    bundle = _bundle()
    observation_payload = bundle.observation.model_dump(mode="python")
    observation_payload["source_commitments"] = tuple(
        reversed(bundle.observation.source_commitments)
    )
    forged_observation = PolicyEligibilitySourceObservation.model_construct(**observation_payload)

    with pytest.raises(ModelPolicyEligibilityRefreshError, match="source observation is invalid"):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=forged_observation,
            checked_routes=bundle.routes,
        )
    with pytest.raises(ModelPolicyEligibilityRefreshError, match="unique, and sorted"):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=tuple(reversed(bundle.routes)),
        )


@pytest.mark.parametrize("route_change", ["omitted", "extra", "reordered"])
def test_exact_verifier_rejects_changed_route_inventory(route_change: str) -> None:
    bundle = _bundle()
    projection = _projection(bundle)
    if route_change == "omitted":
        routes = bundle.routes[:-1]
    elif route_change == "extra":
        routes = (*bundle.routes, bundle.routes[-1])
    else:
        routes = tuple(reversed(bundle.routes))

    with pytest.raises(ModelPolicyEligibilityRefreshError):
        verify_model_policy_eligibility_refresh_artifact(
            artifact=projection,
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=routes,
            used_at=OBSERVED_AT + timedelta(hours=1),
        )


@pytest.mark.parametrize("record_change", ["omitted", "extra", "reordered"])
def test_artifact_rejects_changed_route_record_inventory(record_change: str) -> None:
    projection = _projection(_bundle())
    payload = projection.model_dump(mode="python")
    records = projection.route_records
    if record_change == "omitted":
        payload["route_records"] = records[:-1]
    elif record_change == "extra":
        payload["route_records"] = (*records, records[-1])
    else:
        payload["route_records"] = tuple(reversed(records))

    with pytest.raises(ValidationError, match="classify every checked route"):
        ModelPolicyEligibilityRefreshArtifact.model_validate(payload)


def test_exact_verifier_rejects_spliced_snapshot_policy_and_observation() -> None:
    bundle = _bundle()
    projection = _projection(bundle)
    spliced_snapshot = _snapshot(bundle.routes, snapshot_tag="spliced")
    spliced_policy = _policy_artifact(bundle.routes, evidence_tag="spliced")
    spliced_observation = _observation(spliced_policy, bundle.routes)

    with pytest.raises(ModelPolicyEligibilityRefreshError, match="exact source evidence"):
        verify_model_policy_eligibility_refresh_artifact(
            artifact=projection,
            refresh_snapshot=spliced_snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=bundle.routes,
            used_at=OBSERVED_AT + timedelta(hours=1),
        )
    with pytest.raises(ModelPolicyEligibilityRefreshError):
        verify_model_policy_eligibility_refresh_artifact(
            artifact=projection,
            refresh_snapshot=bundle.snapshot,
            policy_artifact=spliced_policy,
            source_observation=spliced_observation,
            checked_routes=bundle.routes,
            used_at=OBSERVED_AT + timedelta(hours=1),
        )
    with pytest.raises(ModelPolicyEligibilityRefreshError, match="policy artifact"):
        verify_model_policy_eligibility_refresh_artifact(
            artifact=projection,
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=spliced_observation,
            checked_routes=bundle.routes,
            used_at=OBSERVED_AT + timedelta(hours=1),
        )


def test_projection_rejects_snapshot_route_absence_and_invalid_observation_time() -> None:
    bundle = _bundle()
    missing_snapshot = _snapshot(bundle.routes[:-1])
    with pytest.raises(ModelPolicyEligibilityRefreshError, match="absent from the exact"):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=missing_snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=bundle.routes,
        )

    future_observation_snapshot = _snapshot(
        bundle.routes,
        retrieved_at=OBSERVED_AT - timedelta(seconds=1),
    )
    with pytest.raises(ModelPolicyEligibilityRefreshError, match="future-dated"):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=future_observation_snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=bundle.routes,
        )


def test_projection_accepts_a_current_prior_source_observation_and_uses_refresh_time() -> None:
    routes = _routes()
    artifact = _policy_artifact(routes)
    observation = _observation(
        artifact,
        routes,
        observed_at=OBSERVED_AT - timedelta(hours=12),
        expires_at=OBSERVED_AT + timedelta(hours=12),
    )
    snapshot = _snapshot(routes, retrieved_at=OBSERVED_AT)

    projection = build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=snapshot,
        policy_artifact=artifact,
        source_observation=observation,
        checked_routes=routes,
    )

    assert projection.observed_at == snapshot.retrieved_at
    assert projection.refresh_retrieved_at == snapshot.retrieved_at
    assert projection.source_observation.observed_at == observation.observed_at
    assert all(signal.observed_at == snapshot.retrieved_at for signal in projection.review_signals)
    assert projection.evidence_fresh_until == observation.expires_at


def test_projection_detects_expiry_between_source_observation_and_refresh() -> None:
    routes = _routes()
    artifact = _policy_artifact(routes)
    observation = _observation(
        artifact,
        routes,
        observed_at=OBSERVED_AT - timedelta(hours=1),
        expires_at=OBSERVED_AT + timedelta(hours=12),
    )
    snapshot = _snapshot(routes, retrieved_at=OBSERVED_AT + timedelta(hours=1))

    projection = build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=snapshot,
        policy_artifact=artifact,
        source_observation=observation,
        checked_routes=routes,
    )

    expired_record = next(
        record
        for record in projection.route_records
        if record.route.exact_model_id == "beta/expired-1"
    )
    assert expired_record.review_reasons == (PolicyReviewReason.EXPIRED,)
    expired_signal = next(
        signal
        for signal in projection.review_signals
        if signal.route.exact_model_id == "beta/expired-1"
    )
    assert expired_signal.observed_at == snapshot.retrieved_at


@pytest.mark.parametrize(
    ("observed_at", "expires_at"),
    [
        (OBSERVED_AT - timedelta(hours=24, seconds=1), OBSERVED_AT - timedelta(seconds=1)),
        (OBSERVED_AT - timedelta(hours=1), OBSERVED_AT),
    ],
)
def test_projection_rejects_stale_or_expired_source_observation(
    observed_at: datetime,
    expires_at: datetime,
) -> None:
    routes = _routes()
    artifact = _policy_artifact(routes)
    observation = _observation(
        artifact,
        routes,
        observed_at=observed_at,
        expires_at=expires_at,
    )

    with pytest.raises(ModelPolicyEligibilityRefreshError, match="stale, or expired"):
        build_model_policy_eligibility_refresh_artifact(
            refresh_snapshot=_snapshot(routes),
            policy_artifact=artifact,
            source_observation=observation,
            checked_routes=routes,
        )


def test_verifier_binds_freshness_boundaries_and_whole_second_use_time() -> None:
    bundle = _bundle()
    projection = _projection(bundle)
    verify_model_policy_eligibility_refresh_artifact(
        artifact=projection,
        refresh_snapshot=bundle.snapshot,
        policy_artifact=bundle.artifact,
        source_observation=bundle.observation,
        checked_routes=bundle.routes,
        used_at=projection.evidence_fresh_until - timedelta(seconds=1),
    )

    for used_at in (
        projection.observed_at - timedelta(seconds=1),
        projection.evidence_fresh_until,
        projection.evidence_fresh_until + timedelta(seconds=1),
    ):
        with pytest.raises(ModelPolicyEligibilityRefreshError, match="future-dated or stale"):
            verify_model_policy_eligibility_refresh_artifact(
                artifact=projection,
                refresh_snapshot=bundle.snapshot,
                policy_artifact=bundle.artifact,
                source_observation=bundle.observation,
                checked_routes=bundle.routes,
                used_at=used_at,
            )
    with pytest.raises(ModelPolicyEligibilityRefreshError, match="whole-second UTC"):
        verify_model_policy_eligibility_refresh_artifact(
            artifact=projection,
            refresh_snapshot=bundle.snapshot,
            policy_artifact=bundle.artifact,
            source_observation=bundle.observation,
            checked_routes=bundle.routes,
            used_at=projection.observed_at + timedelta(microseconds=1),
        )


def test_projection_models_are_strict_frozen_self_hashed_and_fail_closed() -> None:
    bundle = _bundle()
    projection = _projection(bundle)
    payload = projection.model_dump(mode="python")
    payload["artifact_sha256"] = _hash("tampered")
    with pytest.raises(ValidationError, match="self-hash"):
        ModelPolicyEligibilityRefreshArtifact.model_validate(payload)

    payload = projection.model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="extra"):
        ModelPolicyEligibilityRefreshArtifact.model_validate(payload)

    payload = projection.model_dump(mode="python")
    payload["production_selection_authorized"] = 0
    with pytest.raises(ValidationError):
        ModelPolicyEligibilityRefreshArtifact.model_validate(payload)

    with pytest.raises(ValidationError, match="frozen"):
        projection.redetermination_required = False  # type: ignore[misc]
    assert ModelPolicyEligibilityRefreshArtifact.model_config["frozen"] is True
    assert ModelPolicyEligibilityRefreshArtifact.model_config["strict"] is True


def test_explicit_policy_refresh_inputs_and_projection_round_trip_canonically(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    projection = _projection(bundle)
    artifact_path = tmp_path / "policy-artifact.json"
    observation_path = tmp_path / "source-observation.json"
    routes_path = tmp_path / "checked-routes.json"
    projection_path = tmp_path / POLICY_ELIGIBILITY_REFRESH_FILENAME
    _write_canonical(artifact_path, bundle.artifact)
    _write_canonical(observation_path, bundle.observation)
    _write_canonical(
        routes_path,
        [route.model_dump(mode="json") for route in bundle.routes],
    )
    _write_canonical(projection_path, projection)

    assert load_model_policy_eligibility_artifact(artifact_path) == bundle.artifact
    assert load_policy_eligibility_source_observation(observation_path) == bundle.observation
    assert load_policy_eligibility_checked_routes(routes_path) == bundle.routes
    assert load_model_policy_eligibility_refresh_artifact(projection_path) == projection


def test_explicit_policy_refresh_input_loader_rejects_noncanonical_or_linked_routes(
    tmp_path: Path,
) -> None:
    routes = _routes()
    noncanonical = tmp_path / "noncanonical-routes.json"
    noncanonical.write_text(
        json.dumps([route.model_dump(mode="json") for route in routes]),
        encoding="utf-8",
    )
    noncanonical.chmod(0o600)
    with pytest.raises(ModelPolicyEligibilityRefreshError, match=r"checked.*invalid"):
        load_policy_eligibility_checked_routes(noncanonical)

    canonical = tmp_path / "canonical-routes.json"
    _write_canonical(canonical, [route.model_dump(mode="json") for route in routes])
    linked = tmp_path / "linked-routes.json"
    linked.symlink_to(canonical)
    with pytest.raises(ModelPolicyEligibilityRefreshError, match=r"checked.*invalid"):
        load_policy_eligibility_checked_routes(linked)
