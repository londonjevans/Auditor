from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    ModelDiscoveryArtifactBinding,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    _issue_real_openrouter_discovery_run,
    openrouter_endpoint_query,
    openrouter_model_query,
    seal_model_discovery_run_manifest,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.lineage_review import (
    LINEAGE_REVIEW_FILENAME,
    ModelLineageReviewArtifact,
    ModelLineageReviewError,
    build_model_lineage_review_artifact,
    load_model_lineage_review_artifact,
    validate_model_lineage_review_artifact,
    write_model_lineage_review_artifact,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    LineageReviewStatus,
    OperatorLineageReview,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.refresh import (
    ModelRefreshFreshness,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
    build_model_refresh_snapshot_from_source,
    build_model_refresh_source_evidence,
    evaluate_model_refresh_freshness,
)
from mmaudit.release_io import write_json_evidence

DISCOVERED_AT = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)
REFRESHED_AT = datetime(2026, 7, 30, 9, 0, tzinfo=UTC)
CREATED_AT = datetime(2026, 7, 30, 10, 0, tzinfo=UTC)
EXPIRES_AT = datetime(2026, 8, 6, 10, 0, tzinfo=UTC)
PARAMETERS = [
    "max_tokens",
    "reasoning",
    "response_format",
    "structured_outputs",
    "temperature",
]


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _root(label: str) -> str:
    return "sha256:" + hashlib.sha256(f"root:{label}".encode()).hexdigest()


def _catalog_model(model_id: str, *, canonical_slug: str | None = None) -> dict[str, Any]:
    return {
        "id": model_id,
        "canonical_slug": canonical_slug or model_id,
        "context_length": 100_000,
        "top_provider": {
            "context_length": 100_000,
            "max_completion_tokens": 8_192,
            "is_moderated": False,
        },
        "supported_parameters": list(PARAMETERS),
    }


def _endpoint(model_id: str, index: int, *, price: str = "0.000001") -> dict[str, Any]:
    return {
        "model_id": model_id,
        "tag": f"provider-{index}/exact",
        "slug": f"provider-{index}/exact",
        "provider_name": f"Approved Provider {index}",
        "status": 0,
        "context_length": 100_000,
        "max_prompt_tokens": 91_808,
        "max_completion_tokens": 8_192,
        "supported_parameters": list(PARAMETERS),
        "pricing": {"completion": "0.000002", "prompt": price},
    }


@dataclass(frozen=True)
class _Bundle:
    registry: CandidateRegistry
    manifest: OpenRouterModelDiscoveryRunManifest
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    source: ModelRefreshSourceEvidence
    snapshot: ModelRefreshSnapshot
    freshness: ModelRefreshFreshness
    catalogs: tuple[dict[str, Any], ...]
    endpoints: tuple[dict[str, Any], ...]


def _bundle(
    model_ids: tuple[str, ...] = ("alpha/atlas",),
    *,
    canonical_slugs: dict[str, str] | None = None,
) -> _Bundle:
    canonical_slugs = canonical_slugs or {}
    catalogs = tuple(
        _catalog_model(model_id, canonical_slug=canonical_slugs.get(model_id))
        for model_id in model_ids
    )
    endpoints = tuple(_endpoint(model_id, index) for index, model_id in enumerate(model_ids))
    payloads = []
    routes = []
    endpoint_bindings = []
    model_bindings = []
    for model_id, catalog, endpoint in zip(model_ids, catalogs, endpoints, strict=True):
        provider_endpoint = str(endpoint["slug"])
        endpoint_snapshot = validate_openrouter_endpoint_snapshot(
            exact_model_id=model_id,
            configured_provider_endpoints=(provider_endpoint,),
            provider_policy_mode="only",
            endpoint_payload={
                "data": {
                    "id": model_id,
                    "endpoints": [
                        {key: value for key, value in endpoint.items() if key != "model_id"}
                    ],
                }
            },
            require_zdr=True,
            zdr_payload={"data": [endpoint]},
            reasoning_requested=False,
        )
        payload = validate_openrouter_model_discovery(
            exact_model_id=model_id,
            models_payload={"data": list(catalogs)},
            single_model_payload={"data": catalog},
            endpoint_snapshot=endpoint_snapshot,
        )
        payloads.append(payload)
        routes.append(
            DiscoveryCandidateRoute(
                exact_model_id=model_id,
                approved_provider_endpoint=provider_endpoint,
            )
        )
        endpoint_bindings.append(
            DiscoveryEndpointMetadataBinding(
                exact_model_id=model_id,
                api_query=openrouter_endpoint_query(model_id),
                response_snapshot_sha256=_sha(["endpoint-response", model_id]),
            )
        )
        model_bindings.append(
            DiscoveryModelMetadataBinding(
                exact_model_id=model_id,
                canonical_slug=payload.canonical_slug,
                api_query=openrouter_model_query(model_id),
                response_snapshot_sha256=_sha(["model-response", model_id]),
                model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
            )
        )
    provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=DISCOVERED_AT,
        client_fingerprint_sha256=_sha("client"),
        provider_fingerprint_sha256=_sha("provider"),
        catalog_snapshot_sha256=_sha(catalogs),
        zdr_snapshot_sha256=_sha(endpoints),
        candidate_routes=tuple(routes),
        model_metadata_bindings=tuple(model_bindings),
        endpoint_metadata_bindings=tuple(endpoint_bindings),
        payloads=tuple(payloads),
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    artifacts = tuple(
        ModelDiscoveryArtifactBinding(
            exact_model_id=item.exact_model_id,
            approved_provider_endpoint=item.approved_provider_endpoint,
            filename=(f"candidate-{hashlib.sha256(item.exact_model_id.encode()).hexdigest()}.json"),
            artifact_sha256=_sha(["artifact", item.exact_model_id]),
            discovery_evidence_sha256=item.discovery_evidence_sha256,
        )
        for item in evidence
    )
    manifest = seal_model_discovery_run_manifest(
        provenance=provenance,
        artifacts=artifacts,
    )
    candidates = tuple(
        _pending_candidate(item) for item in sorted(evidence, key=lambda item: item.exact_model_id)
    )
    registry = seal_candidate_registry(
        created_at=DISCOVERED_AT,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=candidates,
    )
    source = build_model_refresh_source_evidence(
        retrieved_at=REFRESHED_AT,
        catalog_payload={"data": list(catalogs)},
        zdr_payload={"data": list(endpoints)},
        candidate_registry=registry,
        candidate_endpoint_payloads={
            model_id: {
                "data": {
                    "id": model_id,
                    "endpoints": [
                        {key: value for key, value in endpoint.items() if key != "model_id"}
                    ],
                }
            }
            for model_id, endpoint in zip(model_ids, endpoints, strict=True)
        },
        authenticated_metadata=True,
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=CREATED_AT,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    return _Bundle(
        registry=registry,
        manifest=manifest,
        discovery_evidence=evidence,
        source=source,
        snapshot=snapshot,
        freshness=freshness,
        catalogs=catalogs,
        endpoints=endpoints,
    )


def _pending_candidate(evidence: OpenRouterModelDiscoveryEvidence) -> CandidateModel:
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=(evidence.exact_model_id,),
        rationale="Synthetic candidate remains pending independent lineage review.",
    )
    return CandidateModel(
        exact_model_id=evidence.exact_model_id,
        canonical_model_slug=evidence.canonical_slug,
        root_lineage=None,
        lineage_review=review,
        discovery_evidence_sha256=evidence.discovery_evidence_sha256,
        approved_provider_endpoint=evidence.approved_provider_endpoint,
        approved_provider_name=evidence.provider_name,
        endpoint_snapshot_sha256=evidence.endpoint_snapshot_sha256,
        output_capability_sha256=evidence.output_capability_sha256,
        model_metadata_snapshot_sha256=evidence.model_metadata_snapshot_sha256,
        pricing_snapshot_sha256=evidence.pricing_snapshot_sha256,
        context_size=evidence.context_size,
        max_prompt_tokens=endpoint.max_prompt_tokens,
        max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
        output_limit=evidence.output_limit,
        output_limit_source=endpoint.max_completion_tokens_source,
        structured_output_supported=evidence.structured_output_supported,
        structured_output_mode=evidence.structured_output_mode,
        reasoning_supported=evidence.reasoning_supported,
        zdr_eligible=evidence.zdr_eligible is True,
        data_collection_deny_eligible=evidence.data_collection_deny_eligible,
        data_collection_deny_request_policy_enforced=(
            evidence.data_collection_deny_request_policy_enforced
        ),
        data_collection_deny_evidence_source=evidence.data_collection_deny_evidence_source,
        data_collection_deny_evidence_sha256=evidence.data_collection_deny_evidence_sha256,
        data_collection_deny_evidence_expires_at=(
            evidence.data_collection_deny_evidence_expires_at
        ),
        operational_status=CandidateOperationalStatus.AVAILABLE,
        benchmark_status=CandidateBenchmarkStatus.PENDING,
    )


def _review(
    model_ids: tuple[str, ...],
    *,
    label: str = "alpha",
    status: LineageReviewStatus = LineageReviewStatus.APPROVED,
    reviewed_at: datetime = CREATED_AT,
) -> tuple[OperatorLineageReview, bytes]:
    evidence = f"synthetic lineage evidence:{label}".encode()
    return (
        seal_operator_lineage_review(
            status=status,
            reviewed_model_ids=tuple(sorted(model_ids)),
            root_lineage=_root(label) if status is LineageReviewStatus.APPROVED else None,
            rationale="Operator reviewed the synthetic root-model identity evidence.",
            reviewed_by="test-operator",
            reviewed_at=reviewed_at,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        ),
        evidence,
    )


def _artifact(
    bundle: _Bundle,
    reviews: tuple[tuple[OperatorLineageReview, bytes], ...] | None = None,
    *,
    freshness: ModelRefreshFreshness | None = None,
    source: ModelRefreshSourceEvidence | None = None,
    snapshot: ModelRefreshSnapshot | None = None,
) -> ModelLineageReviewArtifact:
    selected = reviews or (
        _review(tuple(item.exact_model_id for item in bundle.registry.candidates)),
    )
    decisions = tuple(review for review, _evidence in selected)
    evidence_by_hash = {
        review.evidence_sha256: evidence
        for review, evidence in selected
        if review.evidence_sha256 is not None
    }
    return build_model_lineage_review_artifact(
        created_at=CREATED_AT,
        expires_at=EXPIRES_AT,
        candidate_registry=bundle.registry,
        discovery_manifest=bundle.manifest,
        discovery_evidence=bundle.discovery_evidence,
        refresh_source_evidence=source or bundle.source,
        refresh_snapshot=snapshot or bundle.snapshot,
        refresh_freshness=freshness or bundle.freshness,
        expected_soft_max_age_hours=30,
        expected_hard_max_age_hours=72,
        reviews=decisions,
        review_evidence_by_sha256=evidence_by_hash,
    )


def test_lineage_overlay_is_exact_serializable_and_non_authorizing(tmp_path: Path) -> None:
    bundle = _bundle()
    review, evidence = _review(("alpha/atlas",))
    artifact = _artifact(bundle, ((review, evidence),))

    assert artifact.source_scope == "PUBLIC_OPEN_SOURCE_ONLY"
    assert artifact.purpose == "LINEAGE_IDENTITY_ONLY"
    assert artifact.quality_status == "NOT_EVALUATED"
    assert artifact.evidence_class == "PROVIDER_FREE_STRUCTURAL"
    assert artifact.source_egress_authorized is False
    assert artifact.production_selection_authorized is False
    assert artifact.approved_root_lineages == (_root("alpha"),)
    assert artifact.candidate_registry_sha256 == bundle.registry.registry_sha256
    assert artifact.refresh_snapshot_sha256 == bundle.snapshot.snapshot_sha256
    assert artifact.refresh_semantic_sha256 == bundle.snapshot.semantic_sha256

    with pytest.raises(ValidationError, match="frozen"):
        artifact.reviews[0].rationale = "mutated after hashing"

    validate_model_lineage_review_artifact(
        artifact=artifact,
        observed_at=CREATED_AT + timedelta(hours=1),
        candidate_registry=bundle.registry,
        discovery_manifest=bundle.manifest,
        discovery_evidence=bundle.discovery_evidence,
        refresh_source_evidence=bundle.source,
        refresh_snapshot=bundle.snapshot,
        refresh_freshness=bundle.freshness,
        expected_soft_max_age_hours=30,
        expected_hard_max_age_hours=72,
        review_evidence_by_sha256={hashlib.sha256(evidence).hexdigest(): evidence},
    )
    write_model_lineage_review_artifact(tmp_path, artifact)
    assert load_model_lineage_review_artifact(tmp_path) == artifact


def test_lineage_overlay_accepts_a_decided_rejection_without_approving_a_root() -> None:
    bundle = _bundle()
    review, evidence = _review(
        ("alpha/atlas",),
        status=LineageReviewStatus.REJECTED,
    )

    artifact = _artifact(bundle, ((review, evidence),))

    assert artifact.approved_root_lineages == ()
    assert artifact.candidate_bindings[0].root_lineage is None


@pytest.mark.parametrize("review_state", ["pending", "missing", "pre_refresh"])
def test_lineage_overlay_rejects_incomplete_or_mistimed_decisions(review_state: str) -> None:
    bundle = _bundle()
    if review_state == "pending":
        review = seal_operator_lineage_review(
            status=LineageReviewStatus.PENDING,
            reviewed_model_ids=("alpha/atlas",),
            rationale="Synthetic lineage review remains pending.",
        )
        reviews: tuple[OperatorLineageReview, ...] = (review,)
        evidence_by_hash: dict[str, bytes] = {}
    elif review_state == "missing":
        reviews = ()
        evidence_by_hash = {}
    else:
        review, evidence = _review(
            ("alpha/atlas",),
            reviewed_at=REFRESHED_AT - timedelta(seconds=1),
        )
        reviews = (review,)
        evidence_by_hash = {hashlib.sha256(evidence).hexdigest(): evidence}

    with pytest.raises(ModelLineageReviewError):
        build_model_lineage_review_artifact(
            created_at=CREATED_AT,
            expires_at=EXPIRES_AT,
            candidate_registry=bundle.registry,
            discovery_manifest=bundle.manifest,
            discovery_evidence=bundle.discovery_evidence,
            refresh_source_evidence=bundle.source,
            refresh_snapshot=bundle.snapshot,
            refresh_freshness=bundle.freshness,
            expected_soft_max_age_hours=30,
            expected_hard_max_age_hours=72,
            reviews=reviews,
            review_evidence_by_sha256=evidence_by_hash,
        )


def test_lineage_overlay_rejects_wrong_or_extra_evidence_bytes() -> None:
    bundle = _bundle()
    review, evidence = _review(("alpha/atlas",))
    evidence_hash = hashlib.sha256(evidence).hexdigest()
    common = {
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "candidate_registry": bundle.registry,
        "discovery_manifest": bundle.manifest,
        "discovery_evidence": bundle.discovery_evidence,
        "refresh_source_evidence": bundle.source,
        "refresh_snapshot": bundle.snapshot,
        "refresh_freshness": bundle.freshness,
        "expected_soft_max_age_hours": 30,
        "expected_hard_max_age_hours": 72,
        "reviews": (review,),
    }

    with pytest.raises(ModelLineageReviewError, match="hash is inconsistent"):
        build_model_lineage_review_artifact(
            **common,
            review_evidence_by_sha256={evidence_hash: b"wrong"},
        )
    with pytest.raises(ModelLineageReviewError, match="exactly cover"):
        build_model_lineage_review_artifact(
            **common,
            review_evidence_by_sha256={
                evidence_hash: evidence,
                "f" * 64: b"extra",
            },
        )


def test_lineage_overlay_rejects_stale_refresh_and_expired_runtime_use() -> None:
    bundle = _bundle()
    stale_at = REFRESHED_AT + timedelta(hours=31)
    stale = evaluate_model_refresh_freshness(
        observed_at=stale_at,
        snapshot=bundle.snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    review, evidence = _review(("alpha/atlas",), reviewed_at=stale_at)

    with pytest.raises(ModelLineageReviewError, match="requires current"):
        build_model_lineage_review_artifact(
            created_at=stale_at,
            expires_at=stale_at + timedelta(days=1),
            candidate_registry=bundle.registry,
            discovery_manifest=bundle.manifest,
            discovery_evidence=bundle.discovery_evidence,
            refresh_source_evidence=bundle.source,
            refresh_snapshot=bundle.snapshot,
            refresh_freshness=stale,
            expected_soft_max_age_hours=30,
            expected_hard_max_age_hours=72,
            reviews=(review,),
            review_evidence_by_sha256={
                hashlib.sha256(evidence).hexdigest(): evidence,
            },
        )

    artifact = _artifact(bundle)
    with pytest.raises(ModelLineageReviewError, match="expired"):
        validate_model_lineage_review_artifact(
            artifact=artifact,
            observed_at=EXPIRES_AT,
            candidate_registry=bundle.registry,
            discovery_manifest=bundle.manifest,
            discovery_evidence=bundle.discovery_evidence,
            refresh_source_evidence=bundle.source,
            refresh_snapshot=bundle.snapshot,
            refresh_freshness=bundle.freshness,
            expected_soft_max_age_hours=30,
            expected_hard_max_age_hours=72,
            review_evidence_by_sha256={
                artifact.reviews[0].evidence_sha256: b"synthetic lineage evidence:alpha"
            },
        )


def test_lineage_overlay_rejects_caller_inflated_freshness_policy() -> None:
    bundle = _bundle()
    inflated = evaluate_model_refresh_freshness(
        observed_at=CREATED_AT,
        snapshot=bundle.snapshot,
        soft_max_age_hours=720,
        hard_max_age_hours=2_160,
        production_selection_present=False,
    )

    with pytest.raises(ModelLineageReviewError, match="trusted age policy"):
        _artifact(bundle, freshness=inflated)


def test_lineage_overlay_replays_source_and_rejects_current_identity_drift() -> None:
    bundle = _bundle()
    changed_catalog = _catalog_model(
        "alpha/atlas",
        canonical_slug="alpha/atlas-revision",
    )
    changed_source = build_model_refresh_source_evidence(
        retrieved_at=REFRESHED_AT,
        catalog_payload={"data": [changed_catalog]},
        zdr_payload={"data": list(bundle.endpoints)},
        candidate_registry=bundle.registry,
        candidate_endpoint_payloads={
            "alpha/atlas": {
                "data": {
                    "id": "alpha/atlas",
                    "endpoints": [
                        {
                            key: value
                            for key, value in bundle.endpoints[0].items()
                            if key != "model_id"
                        }
                    ],
                }
            }
        },
        authenticated_metadata=True,
    )
    changed_snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=changed_source,
        candidate_registry=bundle.registry,
    )
    changed_freshness = evaluate_model_refresh_freshness(
        observed_at=CREATED_AT,
        snapshot=changed_snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )

    with pytest.raises(ModelLineageReviewError, match="does not replay"):
        _artifact(bundle, source=bundle.source, snapshot=changed_snapshot)
    with pytest.raises(ModelLineageReviewError, match="canonical identity drifted"):
        _artifact(
            bundle,
            source=changed_source,
            snapshot=changed_snapshot,
            freshness=changed_freshness,
        )


def test_lineage_overlay_rejects_a_route_when_the_current_model_is_ineligible() -> None:
    bundle = _bundle()
    changed_source = build_model_refresh_source_evidence(
        retrieved_at=REFRESHED_AT,
        catalog_payload={"data": list(bundle.catalogs)},
        zdr_payload={"data": []},
        candidate_registry=bundle.registry,
        candidate_endpoint_payloads={
            "alpha/atlas": {
                "data": {
                    "id": "alpha/atlas",
                    "endpoints": [
                        {
                            key: value
                            for key, value in bundle.endpoints[0].items()
                            if key != "model_id"
                        }
                    ],
                }
            }
        },
        authenticated_metadata=True,
    )
    changed_snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=changed_source,
        candidate_registry=bundle.registry,
    )
    changed_freshness = evaluate_model_refresh_freshness(
        observed_at=CREATED_AT,
        snapshot=changed_snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )

    with pytest.raises(ModelLineageReviewError, match="not current and eligible"):
        _artifact(
            bundle,
            source=changed_source,
            snapshot=changed_snapshot,
            freshness=changed_freshness,
        )


def test_lineage_overlay_rejects_variant_splitting_and_one_root_split_across_reviews() -> None:
    variants = _bundle(("alpha/atlas", "alpha/atlas-fast"))
    first, first_evidence = _review(("alpha/atlas",), label="first")
    second, second_evidence = _review(("alpha/atlas-fast",), label="second")

    with pytest.raises(ModelLineageReviewError, match="variant family"):
        _artifact(
            variants,
            ((first, first_evidence), (second, second_evidence)),
        )

    distinct = _bundle(("alpha/atlas", "beta/borealis"))
    first, first_evidence = _review(("alpha/atlas",), label="shared")
    second_evidence = b"synthetic lineage evidence:shared-second"
    second = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=("beta/borealis",),
        root_lineage=_root("shared"),
        rationale="Operator reviewed the second synthetic model identity.",
        reviewed_by="test-operator",
        reviewed_at=CREATED_AT,
        evidence_sha256=hashlib.sha256(second_evidence).hexdigest(),
    )
    with pytest.raises(ModelLineageReviewError, match="split across"):
        _artifact(
            distinct,
            ((first, first_evidence), (second, second_evidence)),
        )


def test_lineage_overlay_rejects_mixed_discovery_and_authority_tampering() -> None:
    bundle = _bundle()
    other = _bundle(("beta/borealis",))
    review, evidence = _review(("alpha/atlas",))

    with pytest.raises(ModelLineageReviewError, match="exact discovery evidence"):
        build_model_lineage_review_artifact(
            created_at=CREATED_AT,
            expires_at=EXPIRES_AT,
            candidate_registry=bundle.registry,
            discovery_manifest=other.manifest,
            discovery_evidence=other.discovery_evidence,
            refresh_source_evidence=bundle.source,
            refresh_snapshot=bundle.snapshot,
            refresh_freshness=bundle.freshness,
            expected_soft_max_age_hours=30,
            expected_hard_max_age_hours=72,
            reviews=(review,),
            review_evidence_by_sha256={
                hashlib.sha256(evidence).hexdigest(): evidence,
            },
        )

    payload = _artifact(bundle).as_dict()
    payload["source_egress_authorized"] = True
    with pytest.raises(ValidationError):
        ModelLineageReviewArtifact.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "coerced"),
    [
        ("soft_max_age_hours", "30"),
        ("source_egress_authorized", 0),
    ],
)
def test_lineage_overlay_loader_rejects_schema_invalid_coercions(
    tmp_path: Path,
    field: str,
    coerced: object,
) -> None:
    payload = _artifact(_bundle()).as_dict()
    payload[field] = coerced
    evidence_root = tmp_path / field
    evidence_root.mkdir(mode=0o700)
    evidence_root.chmod(0o700)
    write_json_evidence(
        evidence_root=evidence_root,
        relative_path=LINEAGE_REVIEW_FILENAME,
        value=payload,
    )

    with pytest.raises(ModelLineageReviewError, match="invalid"):
        load_model_lineage_review_artifact(evidence_root)


def test_published_lineage_review_schema_is_strict_bounded_and_non_authorizing() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / "model_lineage_review.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["properties"]["source_scope"]["const"] == "PUBLIC_OPEN_SOURCE_ONLY"
    assert schema["properties"]["purpose"]["const"] == "LINEAGE_IDENTITY_ONLY"
    assert schema["properties"]["quality_status"]["const"] == "NOT_EVALUATED"
    assert schema["properties"]["evidence_class"]["const"] == "PROVIDER_FREE_STRUCTURAL"
    assert (
        schema["properties"]["provider_observation_authenticity"]["const"]
        == "NOT_INDEPENDENTLY_PROVEN"
    )
    assert (
        schema["properties"]["operator_decision_authenticity"]["const"]
        == "NOT_INDEPENDENTLY_PROVEN"
    )
    assert schema["properties"]["source_egress_authorized"]["const"] is False
    assert schema["properties"]["production_selection_authorized"]["const"] is False
    assert schema["properties"]["refresh_retrieved_at"]["format"] == "date-time"
    assert schema["properties"]["candidate_bindings"]["maxItems"] == 128
    assert schema["properties"]["evidence_bindings"]["maxItems"] == 128
    assert (
        schema["$defs"]["ModelLineageReviewEvidenceBinding"]["properties"]["byte_count"]["maximum"]
        == 2_000_000
    )
