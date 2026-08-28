"""Synthetic provider-free tests for terminal learning orchestration projection."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

import mmaudit.orchestration.learning as learning_orchestration
from mmaudit.config import AuditRunOptions, LearningCaptureScope
from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.learning import (
    TerminalAuditLearningRecord,
    learning_canonical_sha256,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditReport,
    CandidateFindingArtifact,
    CoverageMetric,
    CoverageProvenance,
    FalsificationDecision,
    FalsificationVerdict,
    FindingStatus,
    Location,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewStatus,
    ModelVote,
)
from mmaudit.orchestration.learning import (
    TERMINAL_AUDIT_LEARNING_ARTIFACT_PATH,
    build_terminal_learning_capture,
    persist_terminal_learning_capture,
    terminal_learning_capture_is_eligible,
)
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    _validate_terminal_learning_capture,
)
from mmaudit.orchestration.pipeline import _refresh_latest_artifacts
from mmaudit.privacy import PrivacySourceClassification
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.run_authority import (
    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    RunTerminalReportAuthority,
)
from tests.unit.test_client_forensic_reporting import _candidate, _finding
from tests.unit.test_run_status import (
    _assessment,
    _coverage,
    _real_scanner,
    _typed_report_payload,
    _usage,
)

_TENANT_SCOPE = LearningCaptureScope(tenant_scope_id=f"tenant-scope-{'a' * 64}")


def _metric(numerator: int, denominator: int, *, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=(100.0 if denominator else None),
        exclusions=[],
        not_applicable_evidence=[] if denominator else ["No surface of this kind was present."],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=[],
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _model_review_coverage() -> ModelReviewCoverage:
    surface_id = f"model-surface:{'1' * 64}"
    surface = ModelReviewSurface(
        surface_id=surface_id,
        kind=ModelReviewSurfaceKind.SOURCE_FILE,
        subject_id="src/SyntheticVault.sol",
        label="src/SyntheticVault.sol",
        critical=False,
        locations=[
            Location(
                path="src/SyntheticVault.sol",
                start_line=5,
                end_line=7,
                symbol="withdraw",
            )
        ],
        evidence_references=[
            ModelReviewEvidenceReference(
                surface_id=surface_id,
                request_id="request-source_audit",
                artifact_sha256="2" * 64,
                requested_model="alpha/atlas-secure",
                model="alpha/atlas-secure",
                review_role="source_audit",
                status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                root_lineage=f"sha256:{'3' * 64}",
                credited=True,
                reason="Synthetic source surface was reviewed without a candidate.",
            )
        ],
    )
    by_kind = {
        kind: _metric(
            1 if kind is ModelReviewSurfaceKind.SOURCE_FILE else 0,
            1 if kind is ModelReviewSurfaceKind.SOURCE_FILE else 0,
            detail=f"Synthetic {kind.value} terminal coverage.",
        )
        for kind in ModelReviewSurfaceKind
    }
    return ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        surfaces=[surface],
        overall=_metric(1, 1, detail="Synthetic overall terminal coverage."),
        by_kind=by_kind,
        critical=_metric(0, 0, detail="No critical synthetic surface was present."),
        critical_gate_passed=False,
    )


def _complete_report(*, extra_usage_roles: tuple[str, ...] = ()) -> AuditReport:
    scanner = _real_scanner()
    usage = [_usage(role) for role in (*ANALYSIS_ROLES, *extra_usage_roles)]
    floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        required_model_roles=ANALYSIS_ROLES,
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[scanner],
        usage=usage,
        coverage=_coverage(),
    )
    exact_cost = sum(
        (Decimal(record.accounted_cost_usd_exact or "0") for record in payload["usage"]),
        start=Decimal(0),
    )
    payload["accounted_cost_usd"] = float(exact_cost)
    payload["accounted_cost_usd_exact"] = format(exact_cost, "f")
    payload["model_review_coverage"] = _model_review_coverage()
    return AuditReport.model_validate(payload)


def test_terminal_projection_binds_completed_report_surfaces_and_role_resources() -> None:
    report = _complete_report()
    authority = RunTerminalReportAuthority.build(report)

    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(),
        terminal_report_authority=authority,
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )

    assert record.tenant_id == _TENANT_SCOPE.tenant_scope_id
    assert record.audit_id == report.run_id
    assert record.terminal_report_authority_sha256 == authority.authority_sha256
    assert record.report_payload_sha256 == authority.report_payload_sha256
    assert record.completed_at == report.generated_at
    assert len(record.reviewed_surfaces) == 1
    assert record.reviewed_surfaces[0].descriptor_excerpt == "src/SyntheticVault.sol"
    assert {item.role_id for item in record.role_usage} == set(ANALYSIS_ROLES)
    assert sum(item.request_count for item in record.role_usage) == len(report.usage)
    assert record.external_misses == ()
    assert record.authority == "NONAUTHORIZING"


def test_terminal_projection_ceil_capture_prevents_same_second_precision_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed_at = datetime(2026, 8, 1, 12, 0, 0, 750_000, tzinfo=UTC)
    observed_at = completed_at - timedelta(microseconds=250_000)
    report = AuditReport.model_validate(
        {**_complete_report().model_dump(mode="python"), "generated_at": completed_at}
    )

    class FrozenDateTime:
        @classmethod
        def now(cls, tz: object) -> datetime:
            assert tz is UTC
            return observed_at

    monkeypatch.setattr(learning_orchestration, "datetime", FrozenDateTime)
    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
    )

    assert record.completed_at == completed_at
    assert record.captured_at == datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC)


def test_terminal_projection_retains_confirmed_rejected_proposed_and_missed_outcomes() -> None:
    base = _complete_report(extra_usage_roles=("specialist:falsifier",))
    confirmed = _finding(FindingStatus.CONFIRMED)
    rejected = _finding(
        FindingStatus.REJECTED,
        finding_id="MMA-SYNTHETIC-REJECTED",
    ).model_copy(
        update={
            "contributing_candidate_ids": ["candidate-synthetic-rejected"],
            "disagreement": "Independent synthetic review falsified the candidate.",
        }
    )
    report = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "findings": [confirmed],
            "rejected_findings": [rejected],
            "falsification_decisions": [
                FalsificationDecision(
                    candidate_id="candidate-synthetic-rejected",
                    test_name="test_synthetic_rejection",
                    verdict=FalsificationVerdict.FALSIFIED,
                    test_matches_claim=True,
                    assumptions_validated=True,
                    rationale="Synthetic local falsifier rejected the retained test claim.",
                    contradictions=["Synthetic state transition remained unreachable."],
                )
            ],
        }
    )
    confirmed_candidate = _candidate(confirmed).model_copy(
        update={
            "model_votes": [
                ModelVote(
                    role="source_audit",
                    requested_model="alpha/proposer",
                    returned_model="alpha/proposer",
                    family="alpha/proposer",
                    verdict="proposed",
                    rationale="Synthetic proposer raised the retained candidate.",
                ),
                ModelVote(
                    role="verifier",
                    requested_model="beta/verifier",
                    returned_model="beta/verifier",
                    family="beta/verifier",
                    verdict="verified",
                    rationale="Synthetic verifier supported the retained candidate.",
                ),
                ModelVote(
                    role="candidate_falsifier:1",
                    requested_model="gamma/falsifier",
                    returned_model="gamma/falsifier",
                    family="gamma/falsifier",
                    verdict="inconclusive",
                    rationale="Synthetic reviewer reached no conclusion.",
                ),
            ]
        }
    )
    rejected_candidate = _candidate(
        rejected,
        candidate_id="candidate-synthetic-rejected",
    ).model_copy(
        update={
            "model_votes": [
                ModelVote(
                    role="source_audit",
                    requested_model="delta/proposer",
                    returned_model="delta/proposer",
                    family="delta/proposer",
                    verdict="proposed",
                    rationale="Synthetic proposer raised the rejected candidate.",
                ),
                ModelVote(
                    role="candidate_falsifier:2",
                    requested_model="epsilon/falsifier",
                    returned_model="epsilon/falsifier",
                    family="epsilon/falsifier",
                    verdict="rejected",
                    rationale="Synthetic reviewer rejected the candidate.",
                ),
            ]
        }
    )
    candidates = (confirmed_candidate, rejected_candidate)
    authority = RunTerminalReportAuthority.build(report)

    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=candidates,
        terminal_report_authority=authority,
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )

    assert [item.finding_id for item in record.confirmed_findings] == [confirmed.id]
    assert [item.candidate_id for item in record.rejected_candidates] == [
        "candidate-synthetic-rejected"
    ]
    assert record.rejected_candidates[0].reason_excerpt == rejected.disagreement
    attributions = {
        (item.model_id, item.outcome.value, item.target_id) for item in record.reviewer_attributions
    }
    assert (
        "alpha/proposer",
        "PROPOSED",
        confirmed.id,
    ) in attributions
    assert ("beta/verifier", "VERIFIED", confirmed.id) in attributions
    assert (
        "delta/proposer",
        "PROPOSED",
        "candidate-synthetic-rejected",
    ) in attributions
    assert (
        "alpha/atlas-secure",
        "FALSIFIED",
        "candidate-synthetic-rejected",
    ) in attributions
    falsifier = next(
        item for item in record.reviewer_attributions if item.outcome.value == "FALSIFIED"
    )
    assert falsifier.actor_kind.value == "SPECIALIST"
    assert falsifier.specialist_role == "falsifier"
    assert not any(model == "gamma/falsifier" for model, _, _ in attributions)
    assert not any(model == "epsilon/falsifier" for model, _, _ in attributions)
    assert not any(
        model == "beta/verifier" and target == "candidate-synthetic-rejected"
        for model, _, target in attributions
    )
    assert any(outcome == "MISSED" for _, outcome, _ in attributions)
    assert record.reviewed_surfaces[0].outcome.value == "MIXED"


def test_terminal_capture_scope_is_precommitted_and_contaminating_inputs_are_ineligible() -> None:
    report = _complete_report()
    options = AuditRunOptions(learning_capture_scope=_TENANT_SCOPE)

    assert options.model_dump(mode="json")["learning_capture_scope"] == {
        "schema_version": "1.0",
        "tenant_scope_id": _TENANT_SCOPE.tenant_scope_id,
        "input_kind": "TENANT_AUDIT",
    }
    assert terminal_learning_capture_is_eligible(
        report=report,
        scanner_only=False,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        tenant_scope_id=_TENANT_SCOPE.tenant_scope_id,
    )
    for source_classification in (
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    ):
        assert not terminal_learning_capture_is_eligible(
            report=report,
            scanner_only=False,
            privacy_source_classification=source_classification,
            tenant_scope_id=_TENANT_SCOPE.tenant_scope_id,
        )
    assert not terminal_learning_capture_is_eligible(
        report=report,
        scanner_only=True,
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        tenant_scope_id=None,
    )

    with pytest.raises(ValidationError, match="frozen"):
        _TENANT_SCOPE.tenant_scope_id = f"tenant-scope-{'b' * 64}"


def test_terminal_learning_persistence_is_private_bounded_and_link_resistant(tmp_path) -> None:
    report = _complete_report()
    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )
    run_dir = tmp_path / "run"
    (run_dir / "private").mkdir(parents=True)

    destination = persist_terminal_learning_capture(run_dir=run_dir, record=record)

    assert destination == run_dir / TERMINAL_AUDIT_LEARNING_ARTIFACT_PATH
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert json.loads(destination.read_text(encoding="utf-8"))["record_sha256"] == (
        record.record_sha256
    )
    with pytest.raises(ValueError, match="already exists"):
        persist_terminal_learning_capture(run_dir=run_dir, record=record)

    escaped_run = tmp_path / "escaped-run"
    escaped_run.mkdir()
    escaped_private = tmp_path / "escaped-private"
    escaped_private.mkdir()
    (escaped_run / "private").symlink_to(escaped_private, target_is_directory=True)
    with pytest.raises(ValueError, match="private directory is unsafe"):
        persist_terminal_learning_capture(run_dir=escaped_run, record=record)


def test_manifest_revalidates_exact_private_learning_projection(tmp_path) -> None:
    report = _complete_report()
    authority = RunTerminalReportAuthority.build(report)
    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(),
        terminal_report_authority=authority,
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )
    run_dir = tmp_path / "run"
    (run_dir / "private").mkdir(parents=True)
    write_json(run_dir / RUN_TERMINAL_REPORT_AUTHORITY_PATH, authority)
    write_json(
        run_dir / "candidate-findings.json",
        CandidateFindingArtifact(schema_version="1.1", findings=[]),
    )
    destination = persist_terminal_learning_capture(run_dir=run_dir, record=record)
    run_options = AuditRunOptions(
        privacy_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        learning_capture_scope=_TENANT_SCOPE,
    )

    def binding() -> ManifestFileBinding:
        payload = destination.read_bytes()
        return ManifestFileBinding(
            path=TERMINAL_AUDIT_LEARNING_ARTIFACT_PATH,
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
        )

    _validate_terminal_learning_capture(
        run_dir,
        report,
        scheduler_artifact=None,
        run_options=run_options,
        expected_binding=binding(),
    )
    with pytest.raises(ValueError, match="presence differs from capture eligibility"):
        _validate_terminal_learning_capture(
            run_dir,
            report,
            scheduler_artifact=None,
            run_options=run_options,
            expected_binding=None,
        )

    tampered = record.model_dump(mode="json")
    tampered["role_usage"][0]["cost_usd_exact"] = "9"
    tampered["record_sha256"] = learning_canonical_sha256(
        {key: value for key, value in tampered.items() if key != "record_sha256"}
    )
    resealed = TerminalAuditLearningRecord.model_validate_json(
        json.dumps(tampered, sort_keys=True),
        strict=True,
    )
    write_json(destination, resealed)
    with pytest.raises(ValueError, match="differs from deterministic projection"):
        _validate_terminal_learning_capture(
            run_dir,
            report,
            scheduler_artifact=None,
            run_options=run_options,
            expected_binding=binding(),
        )


def test_latest_projection_excludes_and_purges_private_learning_payload(tmp_path) -> None:
    report = _complete_report()
    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )
    run_dir = tmp_path / "run"
    latest = tmp_path / "latest"
    (run_dir / "private").mkdir(parents=True)
    (latest / "private").mkdir(parents=True)
    retained = persist_terminal_learning_capture(run_dir=run_dir, record=record)
    persist_terminal_learning_capture(run_dir=latest, record=record)
    (run_dir / "audit-report.md").write_text("synthetic report\n", encoding="utf-8")

    _refresh_latest_artifacts(run_dir=run_dir, latest=latest)

    assert retained.is_file()
    assert (latest / "audit-report.md").read_text(encoding="utf-8") == ("synthetic report\n")
    assert not (latest / "private").exists()


def test_terminal_learning_rejects_rejection_without_exact_reason() -> None:
    base = _complete_report()
    rejected = _finding(
        FindingStatus.REJECTED,
        finding_id="MMA-SYNTHETIC-REJECTED-NO-REASON",
    ).model_copy(
        update={
            "contributing_candidate_ids": ["candidate-synthetic-rejected-no-reason"],
            "disagreement": "",
            "model_votes": [],
        }
    )
    report = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "rejected_findings": [rejected],
        }
    )
    with pytest.raises(ValueError, match="explicit rejection reason"):
        build_terminal_learning_capture(
            tenant_id=_TENANT_SCOPE.tenant_scope_id,
            report=report,
            candidate_projection=(
                _candidate(
                    rejected,
                    candidate_id="candidate-synthetic-rejected-no-reason",
                ),
            ),
            terminal_report_authority=RunTerminalReportAuthority.build(report),
            scheduler_artifact=None,
            captured_at=report.generated_at,
        )


def test_terminal_learning_requires_exact_confirmed_candidate_and_surface_inventory() -> None:
    base = _complete_report()
    confirmed = _finding(FindingStatus.CONFIRMED)
    report = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "findings": [confirmed],
        }
    )
    with pytest.raises(ValueError, match="absent candidate payload"):
        build_terminal_learning_capture(
            tenant_id=_TENANT_SCOPE.tenant_scope_id,
            report=report,
            candidate_projection=(),
            terminal_report_authority=RunTerminalReportAuthority.build(report),
            scheduler_artifact=None,
            captured_at=report.generated_at,
        )

    report_without_surfaces = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "model_review_coverage": None,
        }
    )
    with pytest.raises(ValueError, match="non-empty surface inventory"):
        build_terminal_learning_capture(
            tenant_id=_TENANT_SCOPE.tenant_scope_id,
            report=report_without_surfaces,
            candidate_projection=(),
            terminal_report_authority=RunTerminalReportAuthority.build(report_without_surfaces),
            scheduler_artifact=None,
            captured_at=report_without_surfaces.generated_at,
        )


def test_terminal_learning_marks_unresolved_candidate_surface_inconclusive() -> None:
    base = _complete_report()
    unresolved = _finding(FindingStatus.STRONGLY_SUPPORTED)
    coverage_payload = _model_review_coverage().model_dump(mode="python")
    coverage_payload["surfaces"][0]["evidence_references"][0]["status"] = (
        ModelSurfaceReviewStatus.CANDIDATE
    )
    report = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "findings": [unresolved],
            "model_review_coverage": ModelReviewCoverage.model_validate(coverage_payload),
        }
    )

    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(_candidate(unresolved),),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )

    assert record.confirmed_findings == ()
    assert record.reviewed_surfaces[0].outcome.value == "INCONCLUSIVE"


def test_terminal_learning_emits_bounded_explicit_excerpts_for_valid_long_text() -> None:
    base = _complete_report()
    confirmed = _finding(FindingStatus.CONFIRMED).model_copy(
        update={
            "title": "Synthetic title\n" + "t" * 1_000,
            "summary": "Synthetic summary\n" + "s" * 10_000,
        }
    )
    report = AuditReport.model_validate(
        {
            **base.model_dump(mode="python"),
            "findings": [confirmed],
        }
    )
    candidate = _candidate(confirmed).model_copy(
        update={
            "model_votes": [
                ModelVote(
                    role="source_audit",
                    requested_model="alpha/proposer",
                    returned_model="alpha/proposer",
                    family="alpha/proposer",
                    verdict="proposed",
                    rationale="Synthetic proposer produced the long candidate.",
                )
            ]
        }
    )

    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(candidate,),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )

    retained = record.confirmed_findings[0]
    assert len(retained.title_excerpt) <= 512
    assert len(retained.summary_excerpt) <= 4_096
    assert retained.title_excerpt.endswith("…[truncated]")
    assert retained.summary_excerpt.endswith("…[truncated]")
    assert "\n" not in retained.title_excerpt


def test_terminal_learning_normalizes_edge_and_empty_excerpt_whitespace() -> None:
    base = _complete_report()
    confirmed = _finding(FindingStatus.CONFIRMED).model_copy(
        update={"title": "  Synthetic edge title  ", "summary": " \t "}
    )
    report = AuditReport.model_validate({**base.model_dump(mode="python"), "findings": [confirmed]})
    candidate = _candidate(confirmed).model_copy(
        update={
            "model_votes": [
                ModelVote(
                    role="source_audit",
                    requested_model="alpha/proposer",
                    returned_model="alpha/proposer",
                    family="alpha/proposer",
                    verdict="proposed",
                    rationale="Synthetic proposer produced the whitespace candidate.",
                )
            ]
        }
    )

    record = build_terminal_learning_capture(
        tenant_id=_TENANT_SCOPE.tenant_scope_id,
        report=report,
        candidate_projection=(candidate,),
        terminal_report_authority=RunTerminalReportAuthority.build(report),
        scheduler_artifact=None,
        captured_at=report.generated_at,
    )

    retained = record.confirmed_findings[0]
    assert retained.title_excerpt == "Synthetic edge title"
    assert retained.summary_excerpt == "[empty]"
