"""Pinned defensive known-issue taxonomy loading and disposition coverage."""

from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path

from mmaudit.models.schemas import (
    AnalysisState,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    InvariantSuite,
    KnownIssueApplicability,
    KnownIssueCitation,
    KnownIssueCitationKind,
    KnownIssueCriticality,
    KnownIssueDisposition,
    KnownIssueItemDisposition,
    KnownIssueTaxonomy,
    KnownIssueTaxonomyCoverage,
    ModelReviewCoverage,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    ProtocolProfileAssessment,
    ProtocolProfileEvidence,
    ProtocolProfileKind,
    ProtocolProfileStatus,
    QualityGateResult,
)
from mmaudit.solidity.economics import ECONOMIC_TEMPLATE_REGISTRY

KNOWN_ISSUE_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[1] / "resources" / "known_issue_taxonomy.v1.json"
)
KNOWN_ISSUE_TAXONOMY_VERSION = "1.0"
KNOWN_ISSUE_TAXONOMY_RAW_SHA256 = "c7b9fba9daa31c343662553464d4b2c6ef177639fceb26c908514a21d6efac48"
KNOWN_ISSUE_TAXONOMY_CORPUS_SHA256 = (
    "3899b1934399f999717b452dc953af99ab0e4441099063e11f004e8135626f33"
)
_MAX_TAXONOMY_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class LoadedKnownIssueTaxonomy:
    """Exact committed bytes and their validated semantic corpus."""

    corpus: KnownIssueTaxonomy
    raw_bytes: bytes
    raw_sha256: str


def load_known_issue_taxonomy(
    path: Path = KNOWN_ISSUE_TAXONOMY_PATH,
    *,
    expected_raw_sha256: str = KNOWN_ISSUE_TAXONOMY_RAW_SHA256,
) -> LoadedKnownIssueTaxonomy:
    """Load a bounded regular file only when its raw and semantic pins match."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("known-issue taxonomy must be an unshared regular file")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_TAXONOMY_BYTES:
        raise ValueError("known-issue taxonomy exceeds its bounded artifact size")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError("known-issue taxonomy changed while it was read")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if raw_sha256 != expected_raw_sha256:
        raise ValueError("known-issue taxonomy raw SHA-256 differs from the compiled pin")
    corpus = KnownIssueTaxonomy.model_validate_json(raw, strict=True)
    if (
        corpus.taxonomy_version != KNOWN_ISSUE_TAXONOMY_VERSION
        or corpus.corpus_sha256 != KNOWN_ISSUE_TAXONOMY_CORPUS_SHA256
    ):
        raise ValueError("known-issue taxonomy semantic identity differs from the compiled pin")
    mapped = {
        item.economic_template: item for item in corpus.items if item.economic_template is not None
    }
    if set(mapped) != set(ECONOMIC_TEMPLATE_REGISTRY):
        raise ValueError("known-issue taxonomy must map every economic template exactly once")
    for kind, template in ECONOMIC_TEMPLATE_REGISTRY.items():
        item = mapped[kind]
        if [profile.value for profile in item.applicable_protocol_profiles] != sorted(
            template.protocol_profiles
        ):
            raise ValueError(f"taxonomy profiles drifted from economic template {kind.value}")
    return LoadedKnownIssueTaxonomy(
        corpus=corpus,
        raw_bytes=raw,
        raw_sha256=raw_sha256,
    )


def write_pinned_known_issue_taxonomy(
    path: Path,
    resource: LoadedKnownIssueTaxonomy,
) -> None:
    """Publish the exact compiled corpus bytes and verify the resulting leaf."""

    path.parent.mkdir(parents=True, exist_ok=True)
    written = path.write_bytes(resource.raw_bytes)
    if written != len(resource.raw_bytes) or hashlib.sha256(path.read_bytes()).hexdigest() != (
        resource.raw_sha256
    ):
        raise ValueError("published known-issue taxonomy differs from the compiled raw pin")


def build_known_issue_taxonomy_coverage(
    resource: LoadedKnownIssueTaxonomy,
    *,
    invariants: InvariantSuite | None,
    model_review_coverage: ModelReviewCoverage | None,
) -> KnownIssueTaxonomyCoverage:
    """Materialize every taxonomy item; missing or invalid review credit becomes GAP."""

    validated_invariants = (
        InvariantSuite.model_validate(invariants.model_dump(mode="python"))
        if invariants is not None
        else None
    )
    validated_model_review = (
        ModelReviewCoverage.model_validate(model_review_coverage.model_dump(mode="python"))
        if model_review_coverage is not None
        else None
    )
    profile_assessment = (
        validated_invariants.protocol_profile_assessment
        if validated_invariants is not None
        else None
    )
    profile_evidence = _profile_evidence_by_kind(profile_assessment)
    taxonomy_surfaces = [
        surface
        for surface in (validated_model_review.surfaces if validated_model_review else [])
        if surface.kind is ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS
    ]
    taxonomy_subjects = [surface.subject_id for surface in taxonomy_surfaces]
    if len(taxonomy_subjects) != len(set(taxonomy_subjects)):
        raise ValueError("model-review coverage contains duplicate known-issue subjects")
    surfaces_by_subject = {surface.subject_id: surface for surface in taxonomy_surfaces}
    dispositions: list[KnownIssueItemDisposition] = []
    for item in resource.corpus.items:
        relevant = [profile_evidence.get(profile) for profile in item.applicable_protocol_profiles]
        matched = sorted(
            (
                evidence.profile
                for evidence in relevant
                if evidence is not None and evidence.status is ProtocolProfileStatus.DETECTED
            ),
            key=lambda profile: profile.value,
        )
        if matched:
            applicability = KnownIssueApplicability.APPLICABLE
        elif not profile_evidence or any(
            evidence is None or evidence.status is ProtocolProfileStatus.INDETERMINATE
            for evidence in relevant
        ):
            applicability = KnownIssueApplicability.UNKNOWN
        else:
            applicability = KnownIssueApplicability.NOT_APPLICABLE
        citations = [_corpus_citation(resource, item.item_id, item.item_sha256)]
        citations.extend(
            _profile_citations(
                profile_assessment,
                [evidence for evidence in relevant if evidence is not None],
            )
        )
        surface = surfaces_by_subject.get(item.review_surface_subject_id)
        expected_surface_id = ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS,
            item.review_surface_subject_id,
        )
        reviewed = bool(
            applicability is KnownIssueApplicability.APPLICABLE
            and surface is not None
            and surface.surface_id == expected_surface_id
            and surface.critical
            and surface.reviewed
        )
        if reviewed:
            assert surface is not None
            citations.extend(_model_review_citations(surface))
            disposition = KnownIssueDisposition.REVIEWED
            reviewed_surface_ids = [surface.surface_id]
            rationale = (
                "Applicable failure mode received exact credited review on its content-bound "
                "host-generated surface; REVIEWED is consideration evidence, not a safety result."
            )
        elif applicability is KnownIssueApplicability.NOT_APPLICABLE:
            disposition = KnownIssueDisposition.NOT_APPLICABLE
            reviewed_surface_ids = []
            rationale = "Every relevant closed protocol profile was deterministically NOT_DETECTED."
        elif applicability is KnownIssueApplicability.UNKNOWN:
            disposition = KnownIssueDisposition.GAP
            reviewed_surface_ids = []
            rationale = (
                "Applicability could not be established or excluded from complete deterministic "
                "profile evidence, so the item fails closed as a GAP."
            )
        else:
            disposition = KnownIssueDisposition.GAP
            reviewed_surface_ids = []
            rationale = (
                "The failure mode is applicable but lacks exact credited review evidence on its "
                "content-bound host-generated surface."
            )
        dispositions.append(
            KnownIssueItemDisposition(
                item_id=item.item_id,
                applicability=applicability,
                disposition=disposition,
                matched_profiles=matched,
                reviewed_surface_ids=reviewed_surface_ids,
                citations=sorted(
                    citations,
                    key=lambda citation: (
                        citation.kind.value,
                        citation.reference,
                        citation.evidence_sha256,
                    ),
                ),
                rationale=rationale,
            )
        )
    overall = _taxonomy_metric(
        resource.corpus,
        dispositions,
        critical_only=False,
    )
    critical = _taxonomy_metric(
        resource.corpus,
        dispositions,
        critical_only=True,
    )
    critical_ids = {
        item.item_id
        for item in resource.corpus.items
        if item.criticality is KnownIssueCriticality.CRITICAL
    }
    critical_gaps = sorted(
        disposition.item_id
        for disposition in dispositions
        if disposition.item_id in critical_ids
        and disposition.applicability is not KnownIssueApplicability.NOT_APPLICABLE
        and disposition.disposition is KnownIssueDisposition.GAP
    )
    limitations = sorted(
        {
            *(
                profile_assessment.limitations
                if profile_assessment is not None
                else ["typed deterministic protocol-profile assessment was unavailable"]
            ),
            *(
                [
                    f"{sum(item.disposition is KnownIssueDisposition.GAP for item in dispositions)} "
                    "known-issue class(es) remain explicit coverage GAPs"
                ]
                if any(item.disposition is KnownIssueDisposition.GAP for item in dispositions)
                else []
            ),
        }
    )
    payload = {
        "schema_version": "1.0",
        "finding_authority": False,
        "corpus": resource.corpus.model_dump(mode="json"),
        "corpus_raw_sha256": resource.raw_sha256,
        "profile_assessment": (
            profile_assessment.model_dump(mode="json") if profile_assessment is not None else None
        ),
        "dispositions": [item.model_dump(mode="json") for item in dispositions],
        "overall": overall.model_dump(mode="json"),
        "critical": critical.model_dump(mode="json"),
        "critical_gap_ids": critical_gaps,
        "critical_gate_passed": bool(critical.denominator) and not critical_gaps,
        "limitations": limitations,
    }
    payload["coverage_sha256"] = KnownIssueTaxonomyCoverage.calculate_coverage_sha256(payload)
    return KnownIssueTaxonomyCoverage.model_validate(payload)


def validate_known_issue_taxonomy_coverage_provenance(
    coverage: KnownIssueTaxonomyCoverage,
    *,
    invariants: InvariantSuite | None,
    model_review_coverage: ModelReviewCoverage | None,
) -> None:
    """Require the exact pinned corpus and recomputed host/model evidence projection."""

    if (
        coverage.corpus.corpus_sha256 != KNOWN_ISSUE_TAXONOMY_CORPUS_SHA256
        or coverage.corpus_raw_sha256 != KNOWN_ISSUE_TAXONOMY_RAW_SHA256
    ):
        raise ValueError("taxonomy coverage differs from the compiled corpus identity")
    resource = LoadedKnownIssueTaxonomy(
        corpus=coverage.corpus,
        raw_bytes=b"",
        raw_sha256=coverage.corpus_raw_sha256,
    )
    expected = build_known_issue_taxonomy_coverage(
        resource,
        invariants=invariants,
        model_review_coverage=model_review_coverage,
    )
    if coverage != expected:
        raise ValueError(
            "taxonomy coverage differs from retained profile and model-review evidence"
        )


def known_issue_taxonomy_quality_gate(
    coverage: KnownIssueTaxonomyCoverage | None,
    *,
    required: bool,
) -> QualityGateResult:
    """Project the critical-GAP rule without granting findings or review credit."""

    passed = coverage is not None and coverage.critical_gate_passed
    return QualityGateResult(
        gate="known_issue_taxonomy_critical_disposition",
        required=required,
        passed=passed,
        detail=(
            f"{coverage.critical.numerator}/{coverage.critical.denominator} applicable critical "
            "known-issue classes reviewed; critical gaps="
            f"{','.join(coverage.critical_gap_ids) or 'none'}"
            if coverage is not None
            else "known-issue taxonomy coverage was not produced"
        ),
        state=AnalysisState.MODEL_ONLY if coverage is not None else AnalysisState.NOT_ANALYZED,
        artifacts=["known-issue-taxonomy-coverage.json", "known-issue-taxonomy.json"],
    )


def _profile_evidence_by_kind(
    assessment: ProtocolProfileAssessment | None,
) -> dict[ProtocolProfileKind, ProtocolProfileEvidence]:
    if assessment is None:
        return {}
    return {item.profile: item for item in assessment.classifications}


def _corpus_citation(
    resource: LoadedKnownIssueTaxonomy,
    item_id: str,
    item_sha256: str,
) -> KnownIssueCitation:
    return KnownIssueCitation(
        kind=KnownIssueCitationKind.CORPUS,
        reference=f"known-issue-taxonomy:{item_id}",
        evidence_sha256=item_sha256,
        detail=(
            f"Pinned taxonomy item from raw corpus {resource.raw_sha256}; this classification "
            "has no finding authority."
        ),
    )


def _profile_citations(
    assessment: ProtocolProfileAssessment | None,
    evidence_items: list[ProtocolProfileEvidence],
) -> list[KnownIssueCitation]:
    if assessment is None:
        missing_sha256 = hashlib.sha256(b"protocol-profile-assessment:missing").hexdigest()
        return [
            KnownIssueCitation(
                kind=KnownIssueCitationKind.PROFILE_ASSESSMENT,
                reference="protocol-profile-assessment:missing",
                evidence_sha256=missing_sha256,
                detail="No typed deterministic protocol-profile assessment was retained.",
            )
        ]
    citations = [
        KnownIssueCitation(
            kind=KnownIssueCitationKind.PROFILE_ASSESSMENT,
            reference="protocol-profile-assessment:1.0",
            evidence_sha256=assessment.assessment_sha256,
            detail="Self-hashed complete closed-profile assessment used for applicability.",
        )
    ]
    citations.extend(
        KnownIssueCitation(
            kind=KnownIssueCitationKind.PROFILE_EVIDENCE,
            reference=f"protocol-profile:{item.profile.value}:{item.status.value}",
            evidence_sha256=item.evidence_sha256,
            locations=item.locations,
            detail=(
                f"Host rule {item.rule.value} classified {item.profile.value} as "
                f"{item.status.value}."
            ),
        )
        for item in evidence_items
    )
    return citations


def _model_review_citations(surface: ModelReviewSurface) -> list[KnownIssueCitation]:
    return [
        KnownIssueCitation(
            kind=KnownIssueCitationKind.MODEL_REVIEW,
            reference=f"{surface.surface_id}:{reference.request_id}",
            evidence_sha256=reference.artifact_sha256,
            locations=surface.locations,
            detail=(
                f"Credited {reference.status.value} response from {reference.review_role}; "
                "this proves consideration only."
            ),
        )
        for reference in surface.evidence_references
        if reference.credited
    ]


def _taxonomy_metric(
    corpus: KnownIssueTaxonomy,
    dispositions: list[KnownIssueItemDisposition],
    *,
    critical_only: bool,
) -> CoverageMetric:
    item_by_id = {item.item_id: item for item in corpus.items}
    population = [
        disposition
        for disposition in dispositions
        if not critical_only
        or item_by_id[disposition.item_id].criticality is KnownIssueCriticality.CRITICAL
    ]
    included = [
        item
        for item in population
        if item.applicability is not KnownIssueApplicability.NOT_APPLICABLE
    ]
    reviewed = [item for item in included if item.disposition is KnownIssueDisposition.REVIEWED]
    exclusions = [
        CoverageExclusion(
            subject=item.item_id,
            reason="all applicable closed protocol profiles were deterministically not detected",
            provenance=CoverageProvenance.SYMBOL_INDEX,
        )
        for item in population
        if item.applicability is KnownIssueApplicability.NOT_APPLICABLE
    ]
    gaps = sorted(
        item.item_id for item in included if item.disposition is KnownIssueDisposition.GAP
    )
    denominator = len(included)
    numerator = len(reviewed)
    label = "critical known-issue classes" if critical_only else "known-issue classes"
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=len(population),
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=exclusions,
        not_applicable_evidence=(
            [f"all {label} were excluded by complete per-profile negative evidence"]
            if not denominator
            else []
        ),
        confidence=1,
        provenance=[CoverageProvenance.SYMBOL_INDEX, CoverageProvenance.MODEL_REVIEW],
        failures=[f"{item_id} is an explicit GAP" for item_id in gaps],
        state=AnalysisState.MODEL_ONLY if denominator else AnalysisState.DETERMINISTIC,
        detail=(
            f"{label} with exact credited review on content-bound host-generated surfaces; "
            "REVIEWED does not mean no vulnerability exists"
        ),
    )
