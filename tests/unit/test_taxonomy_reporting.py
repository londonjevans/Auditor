from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
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
    KnownIssueTaxonomyItem,
    ProtocolProfileKind,
    QualityGateResult,
)
from mmaudit.reporting.bundle import CoverageArtifact, build_coverage_artifact
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.solidity.taxonomy import (
    build_known_issue_taxonomy_coverage,
    load_known_issue_taxonomy,
)
from tests.unit import test_actor_model_integration as actor_support
from tests.unit import test_known_issue_taxonomy as taxonomy_support


def _taxonomy_coverage() -> KnownIssueTaxonomyCoverage:
    item_values = {
        "item_id": "KI-ESCAPED-REPORTING",
        "title": "Escaped <script>| [link](javascript:bad)",
        "category": "reporting",
        "criticality": KnownIssueCriticality.CRITICAL,
        "applicable_protocol_profiles": [ProtocolProfileKind.SOLIDITY_GENERAL],
        "defensive_question": "Review whether retained evidence is rendered safely.",
        "economic_template": None,
    }
    item_sha256 = KnownIssueTaxonomyItem.calculate_item_sha256(item_values)
    item = KnownIssueTaxonomyItem(
        **item_values,
        item_sha256=item_sha256,
        review_surface_subject_id=f"known-issue:KI-ESCAPED-REPORTING:{item_sha256}",
    )
    corpus_values = {
        "schema_version": "1.0",
        "taxonomy_version": "1.0",
        "purpose": "defensive_failure_mode_coverage",
        "finding_authority": False,
        "items": [item.model_dump(mode="json")],
    }
    corpus = KnownIssueTaxonomy(
        **corpus_values,
        corpus_sha256=KnownIssueTaxonomy.calculate_corpus_sha256(corpus_values),
    )
    disposition = KnownIssueItemDisposition(
        item_id=item.item_id,
        applicability=KnownIssueApplicability.UNKNOWN,
        disposition=KnownIssueDisposition.GAP,
        citations=[
            KnownIssueCitation(
                kind=KnownIssueCitationKind.CORPUS,
                reference="[corpus](javascript:bad)|<svg>",
                evidence_sha256="b" * 64,
                detail="Untrusted <detail>| must stay text.",
            )
        ],
        rationale="Untrusted <rationale>| must stay text.",
    )
    overall = CoverageMetric(
        numerator=0,
        denominator=1,
        population=1,
        percentage=0.0,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1.0,
        provenance=[CoverageProvenance.CONFIGURATION],
        failures=["KI-ESCAPED-REPORTING is a GAP"],
        state=AnalysisState.NOT_ANALYZED,
        detail="Explicit known-issue taxonomy dispositions.",
    )
    coverage_values = {
        "schema_version": "1.0",
        "finding_authority": False,
        "corpus": corpus.model_dump(mode="json"),
        "corpus_raw_sha256": "b" * 64,
        "profile_assessment": None,
        "dispositions": [disposition.model_dump(mode="json")],
        "overall": overall.model_dump(mode="json"),
        "critical": overall.model_dump(mode="json"),
        "critical_gap_ids": [item.item_id],
        "critical_gate_passed": False,
        "limitations": ["Protocol profile classification is unavailable."],
    }
    return KnownIssueTaxonomyCoverage(
        **coverage_values,
        coverage_sha256=KnownIssueTaxonomyCoverage.calculate_coverage_sha256(coverage_values),
    )


def _committed_taxonomy_coverage() -> KnownIssueTaxonomyCoverage:
    return build_known_issue_taxonomy_coverage(
        load_known_issue_taxonomy(),
        invariants=None,
        model_review_coverage=None,
    )


def _coverage_artifact_payload(
    coverage: KnownIssueTaxonomyCoverage,
) -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "run_id": "synthetic-taxonomy-reporting",
        "scanner_only": False,
        "run_status": AuditRunStatus.INCOMPLETE,
        "quality_status": AuditQualityStatus.INCOMPLETE,
        "completed": False,
        "quality_gates": [
            QualityGateResult(
                gate="minimum_analysis_floor",
                required=True,
                passed=False,
                detail="Synthetic minimum floor is incomplete.",
                state=AnalysisState.NOT_ANALYZED,
            )
        ],
        "limitations": ["Synthetic minimum floor is incomplete."],
        "language_capability": None,
        "scope_assessment": None,
        "solidity_coverage": None,
        "model_review_coverage": None,
        "taxonomy_coverage": coverage,
        "generic_source_coverage": None,
    }


def _report_with_taxonomy(coverage: KnownIssueTaxonomyCoverage) -> AuditReport:
    finding, _, evaluation = actor_support._calibrated_finding()
    payload = actor_support._report_payload(finding, evaluation)
    quality_gates = payload["quality_gates"]
    assert isinstance(quality_gates, list)
    payload.update(
        {
            "schema_version": "1.4",
            "taxonomy_coverage": coverage,
            "quality_gates": [
                *quality_gates,
                QualityGateResult(
                    gate="known_issue_taxonomy_critical_disposition",
                    required=False,
                    passed=False,
                    detail="A critical known-issue taxonomy class is a GAP.",
                    state=AnalysisState.NOT_ANALYZED,
                    artifacts=[
                        "known-issue-taxonomy-coverage.json",
                        "known-issue-taxonomy.json",
                    ],
                ),
            ],
        }
    )
    return AuditReport.model_validate(payload)


def test_coverage_artifact_uses_exact_taxonomy_version_boundary() -> None:
    coverage = _taxonomy_coverage()
    current = CoverageArtifact.model_validate(_coverage_artifact_payload(coverage))

    assert current.schema_version == "1.2"
    assert current.taxonomy_coverage == coverage
    current_payload = current.model_dump(mode="python")
    current_payload.pop("taxonomy_coverage")
    with pytest.raises(ValidationError, match=r"schema 1\.2 requires taxonomy coverage"):
        CoverageArtifact.model_validate(current_payload)
    current_payload["taxonomy_coverage"] = None
    with pytest.raises(ValidationError, match=r"schema 1\.2 requires taxonomy coverage"):
        CoverageArtifact.model_validate(current_payload)

    legacy_payload = current.model_dump(mode="python")
    legacy_payload["schema_version"] = "1.1"
    legacy_payload.pop("taxonomy_coverage")
    legacy = CoverageArtifact.model_validate(legacy_payload)
    assert "taxonomy_coverage" not in legacy.model_dump(mode="json")

    legacy_payload["taxonomy_coverage"] = coverage
    with pytest.raises(ValidationError, match=r"schema 1\.1 cannot carry taxonomy coverage"):
        CoverageArtifact.model_validate(legacy_payload)


def test_report_projections_render_taxonomy_as_non_finding_coverage() -> None:
    coverage = _committed_taxonomy_coverage()
    report = _report_with_taxonomy(coverage)

    artifact = build_coverage_artifact(report)
    markdown = render_markdown(report)
    forensic = render_forensic_markdown(report)
    client = render_client_markdown(
        report,
        {actor_support._SOURCE_PATH: actor_support._SOURCE},
    )

    assert artifact.schema_version == "1.2"
    assert artifact.taxonomy_coverage == coverage
    for rendered in (markdown, forensic):
        assert "Known-issue taxonomy coverage — not vulnerability findings" in rendered
        assert f"0/{len(coverage.corpus.items)} (0%)" in rendered
        assert "CRITICAL TAXONOMY GAP" in rendered
        assert "GAP" in rendered
    assert "This is defensive review coverage, not a finding inventory." in client
    assert "known-issue-taxonomy.json" in client
    assert "known-issue-taxonomy-coverage.json" in client


def test_sarif_taxonomy_projection_adds_no_rule_or_result() -> None:
    coverage = _taxonomy_coverage()
    finding, _, _ = actor_support._calibrated_finding()
    baseline = generate_sarif([finding])["runs"][0]

    run = generate_sarif([finding], taxonomy_coverage=coverage)["runs"][0]

    assert run["tool"]["driver"]["rules"] == baseline["tool"]["driver"]["rules"]
    assert run["results"] == baseline["results"]
    properties = run["properties"]["knownIssueTaxonomyCoverage"]
    assert properties["findingAuthority"] is False
    assert properties["overall"] == {
        "numerator": 0,
        "denominator": 1,
        "population": 1,
        "percentage": 0.0,
    }
    assert properties["criticalGapIds"] == ["KI-ESCAPED-REPORTING"]
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notifications) == 1
    assert notifications[0]["level"] == "warning"
    assert "not findings" in notifications[0]["message"]["text"]


def test_report_rejects_taxonomy_profile_projection_drift() -> None:
    report = _report_with_taxonomy(_committed_taxonomy_coverage())
    payload = report.model_dump(mode="python")
    assessment = taxonomy_support._profile_assessment()
    payload["invariants"] = InvariantSuite(
        protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
        protocol_profile_assessment=assessment,
    )

    with pytest.raises(ValidationError, match="retained profile and model-review evidence"):
        AuditReport.model_validate(payload)


def test_report_rejects_self_hashed_but_unpinned_taxonomy_corpus() -> None:
    with pytest.raises(ValidationError, match="compiled corpus identity"):
        _report_with_taxonomy(_taxonomy_coverage())
