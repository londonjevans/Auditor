from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    CoverageMetric,
    CoverageProvenance,
    InvariantSuite,
    KnownIssueApplicability,
    KnownIssueDisposition,
    KnownIssueTaxonomy,
    KnownIssueTaxonomyCoverage,
    Location,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    ProtocolProfileAssessment,
    ProtocolProfileDetectionRule,
    ProtocolProfileEvidence,
    ProtocolProfileKind,
    ProtocolProfileStatus,
)
from mmaudit.solidity.economics import ECONOMIC_TEMPLATE_REGISTRY
from mmaudit.solidity.taxonomy import (
    KNOWN_ISSUE_TAXONOMY_CORPUS_SHA256,
    KNOWN_ISSUE_TAXONOMY_RAW_SHA256,
    build_known_issue_taxonomy_coverage,
    load_known_issue_taxonomy,
    validate_known_issue_taxonomy_coverage_provenance,
)


def _profile_assessment() -> ProtocolProfileAssessment:
    classifications: list[ProtocolProfileEvidence] = []
    for profile in sorted(ProtocolProfileKind, key=lambda item: item.value):
        detected = profile is ProtocolProfileKind.SOLIDITY_GENERAL
        evidence_payload = {
            "profile": profile.value,
            "status": (
                ProtocolProfileStatus.DETECTED.value
                if detected
                else ProtocolProfileStatus.NOT_DETECTED.value
            ),
            "rule": ProtocolProfileDetectionRule.INDEXED_SYMBOL.value,
            "matched_facts": (
                ["indexed Solidity contract is in audit scope"]
                if detected
                else [f"no deterministic {profile.value} profile facts were detected"]
            ),
            "entity_ids": ["contract:src/Minimal.sol:Minimal"] if detected else [],
            "locations": (
                [
                    Location(
                        path="src/Minimal.sol",
                        start_line=1,
                        end_line=3,
                        symbol="Minimal",
                        content_hash="a" * 64,
                    ).model_dump(mode="json")
                ]
                if detected
                else []
            ),
        }
        evidence_payload["evidence_sha256"] = ProtocolProfileEvidence.calculate_evidence_sha256(
            evidence_payload
        )
        classifications.append(ProtocolProfileEvidence.model_validate(evidence_payload))
    assessment_payload = {
        "schema_version": "1.0",
        "input_sha256": "b" * 64,
        "classification_complete": True,
        "classifications": [item.model_dump(mode="json") for item in classifications],
        "limitations": [],
    }
    assessment_payload["assessment_sha256"] = ProtocolProfileAssessment.calculate_assessment_sha256(
        assessment_payload
    )
    return ProtocolProfileAssessment.model_validate(assessment_payload)


def _model_metric(numerator: int, denominator: int, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=[] if denominator else ["No surface of this kind exists."],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=["A synthetic review surface lacks required credit."]
        if numerator < denominator
        else [],
        state=AnalysisState.MODEL_ONLY if numerator else AnalysisState.NOT_ANALYZED,
        detail=detail,
    )


def _surface_coverage(*surfaces: ModelReviewSurface) -> ModelReviewCoverage:
    ordered = sorted(surfaces, key=lambda surface: surface.surface_id)
    critical_denominator = sum(surface.critical for surface in ordered)
    return ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        surfaces=ordered,
        overall=_model_metric(
            len(ordered),
            len(ordered),
            "Synthetic exact surface review.",
        ),
        by_kind={
            kind: _model_metric(
                sum(surface.kind is kind for surface in ordered),
                sum(surface.kind is kind for surface in ordered),
                f"Synthetic {kind.value} surface review.",
            )
            for kind in ModelReviewSurfaceKind
        },
        critical=_model_metric(
            0,
            critical_denominator,
            "Synthetic critical surface review with fewer than three root lineages.",
        ),
        critical_gate_passed=False,
    )


def _reviewed_surface(
    *,
    item_id: str,
    subject_id: str,
    kind: ModelReviewSurfaceKind,
    critical: bool,
    surface_id: str | None = None,
) -> ModelReviewSurface:
    retained_id = surface_id or ModelSurfaceReviewRequest.calculate_surface_id(kind, subject_id)
    return ModelReviewSurface(
        surface_id=retained_id,
        kind=kind,
        subject_id=subject_id,
        label=f"Synthetic review for {item_id}",
        critical=critical,
        evidence_references=[
            ModelReviewEvidenceReference(
                surface_id=retained_id,
                request_id="synthetic-taxonomy-review",
                artifact_sha256="c" * 64,
                requested_model="vendor/model",
                model="vendor/model",
                review_role="source_audit",
                status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                root_lineage=f"sha256:{'d' * 64}",
                credited=True,
                reason="Exact retained synthetic review evidence.",
            )
        ],
    )


def test_committed_taxonomy_is_hash_pinned_and_maps_every_economic_template() -> None:
    resource = load_known_issue_taxonomy()

    assert resource.raw_sha256 == KNOWN_ISSUE_TAXONOMY_RAW_SHA256
    assert resource.corpus.corpus_sha256 == KNOWN_ISSUE_TAXONOMY_CORPUS_SHA256
    assert resource.corpus.finding_authority is False
    assert {
        item.economic_template
        for item in resource.corpus.items
        if item.economic_template is not None
    } == set(ECONOMIC_TEMPLATE_REGISTRY)
    assert "attacker_capabilities" not in type(resource.corpus.items[0]).model_fields


def test_raw_or_semantic_taxonomy_tampering_is_rejected(tmp_path: Path) -> None:
    resource = load_known_issue_taxonomy()
    tampered_path = tmp_path / "taxonomy.json"
    tampered = resource.raw_bytes.replace(b"AMM reserve-dependent", b"AMM changed-dependent")
    tampered_path.write_bytes(tampered)

    with pytest.raises(ValueError, match="raw SHA-256"):
        load_known_issue_taxonomy(tampered_path)

    payload = resource.corpus.model_dump(mode="json")
    payload["items"][0]["defensive_question"] = "Changed question."
    with pytest.raises(ValidationError, match="semantic hash"):
        KnownIssueTaxonomy.model_validate(payload)


def test_missing_profile_or_review_evidence_expands_to_explicit_gaps() -> None:
    resource = load_known_issue_taxonomy()

    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=None,
        model_review_coverage=None,
    )

    assert coverage.finding_authority is False
    assert coverage.overall.population == len(resource.corpus.items)
    assert coverage.overall.denominator == len(resource.corpus.items)
    assert coverage.overall.numerator == 0
    assert all(
        item.applicability is KnownIssueApplicability.UNKNOWN
        and item.disposition is KnownIssueDisposition.GAP
        for item in coverage.dispositions
    )
    assert coverage.critical_gap_ids
    assert coverage.critical_gate_passed is False


def test_complete_negative_profiles_become_cited_exclusions_not_implicit_passes() -> None:
    resource = load_known_issue_taxonomy()
    assessment = _profile_assessment()

    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=InvariantSuite(
            protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
            protocol_profile_assessment=assessment,
        ),
        model_review_coverage=None,
    )

    applicable = [
        item
        for item in coverage.dispositions
        if item.applicability is KnownIssueApplicability.APPLICABLE
    ]
    not_applicable = [
        item
        for item in coverage.dispositions
        if item.applicability is KnownIssueApplicability.NOT_APPLICABLE
    ]
    assert {item.item_id for item in applicable} == {
        "KI-AUTHORIZATION-BOUNDARIES",
        "KI-EXTERNAL-CALL-STATE-CONSISTENCY",
    }
    assert all(item.disposition is KnownIssueDisposition.GAP for item in applicable)
    assert len(not_applicable) == len(resource.corpus.items) - 2
    assert all(item.disposition is KnownIssueDisposition.NOT_APPLICABLE for item in not_applicable)
    assert coverage.overall.denominator == 2
    assert coverage.overall.population == len(resource.corpus.items)
    assert len(coverage.overall.exclusions) == len(not_applicable)


def test_coverage_rejects_an_omitted_corpus_disposition() -> None:
    resource = load_known_issue_taxonomy()
    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=None,
        model_review_coverage=None,
    )
    payload = json.loads(coverage.model_dump_json())
    payload["dispositions"] = payload["dispositions"][1:]
    payload["coverage_sha256"] = KnownIssueTaxonomyCoverage.calculate_coverage_sha256(payload)

    with pytest.raises(ValidationError, match="every taxonomy corpus item"):
        KnownIssueTaxonomyCoverage.model_validate(payload)


def test_coverage_provenance_recomputes_the_retained_profile_projection() -> None:
    resource = load_known_issue_taxonomy()
    no_profile_coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=None,
        model_review_coverage=None,
    )
    validate_known_issue_taxonomy_coverage_provenance(
        no_profile_coverage,
        invariants=None,
        model_review_coverage=None,
    )
    assessment = _profile_assessment()
    invariants = InvariantSuite(
        protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
        protocol_profile_assessment=assessment,
    )

    with pytest.raises(ValueError, match="retained profile and model-review evidence"):
        validate_known_issue_taxonomy_coverage_provenance(
            no_profile_coverage,
            invariants=invariants,
            model_review_coverage=None,
        )

    profile_coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=invariants,
        model_review_coverage=None,
    )
    with pytest.raises(ValueError, match="retained profile and model-review evidence"):
        validate_known_issue_taxonomy_coverage_provenance(
            profile_coverage,
            invariants=None,
            model_review_coverage=None,
        )


@pytest.mark.parametrize(
    ("kind", "critical", "surface_id"),
    [
        (ModelReviewSurfaceKind.CONTRACT, True, None),
        (ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS, False, None),
        (ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS, True, f"model-surface:{'e' * 64}"),
    ],
)
def test_wrong_kind_identity_or_tier_cannot_forge_taxonomy_review_credit(
    kind: ModelReviewSurfaceKind,
    critical: bool,
    surface_id: str | None,
) -> None:
    resource = load_known_issue_taxonomy()
    assessment = _profile_assessment()
    invariants = InvariantSuite(
        protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
        protocol_profile_assessment=assessment,
    )
    item = next(
        item for item in resource.corpus.items if item.item_id == "KI-AUTHORIZATION-BOUNDARIES"
    )
    surface = _reviewed_surface(
        item_id=item.item_id,
        subject_id=item.review_surface_subject_id,
        kind=kind,
        critical=critical,
        surface_id=surface_id,
    )

    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=invariants,
        model_review_coverage=_surface_coverage(surface),
    )
    disposition = next(
        disposition for disposition in coverage.dispositions if disposition.item_id == item.item_id
    )

    assert disposition.disposition is KnownIssueDisposition.GAP
    assert disposition.reviewed_surface_ids == []


def test_duplicate_known_issue_subjects_are_rejected_before_review_credit() -> None:
    resource = load_known_issue_taxonomy()
    assessment = _profile_assessment()
    invariants = InvariantSuite(
        protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
        protocol_profile_assessment=assessment,
    )
    item = next(
        item for item in resource.corpus.items if item.item_id == "KI-AUTHORIZATION-BOUNDARIES"
    )
    exact = _reviewed_surface(
        item_id=item.item_id,
        subject_id=item.review_surface_subject_id,
        kind=ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS,
        critical=True,
    )
    duplicate = _reviewed_surface(
        item_id=item.item_id,
        subject_id=item.review_surface_subject_id,
        kind=ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS,
        critical=True,
        surface_id=f"model-surface:{'f' * 64}",
    )

    with pytest.raises(ValueError, match="duplicate known-issue subjects"):
        build_known_issue_taxonomy_coverage(
            resource,
            invariants=invariants,
            model_review_coverage=_surface_coverage(exact, duplicate),
        )
