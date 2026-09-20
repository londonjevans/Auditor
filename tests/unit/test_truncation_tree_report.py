"""Original candidate-to-report custody on a disposable synthetic seven-pass campaign."""

from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import AuditReport, CandidateFindingArtifact
from mmaudit.orchestration import manifest
from tests.integration.test_truncation_tree_manifest_files import _write_model
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_assurance_support import CompleteTreeAssuranceFixture
from tests.unit.test_truncation_tree_assurance import complete_tree as complete_tree
from tests.unit.test_truncation_tree_manifest import complete_manifest as complete_manifest


def test_original_seven_pass_report_replays_all_retained_and_ordinary_findings(
    original_candidate_report: tuple[AuditConfig, CompleteTreeAssuranceFixture, AuditReport],
) -> None:
    config, fixture, report = original_candidate_report
    root = fixture.privacy.run_directory
    state = fixture.candidate_report
    candidates = CandidateFindingArtifact.model_validate(
        {
            "schema_version": "1.1",
            "findings": [item.model_dump(mode="json") for item in state.candidates],
        }
    )
    _write_model(root / "candidate-findings.json", candidates)
    _write_model(
        root / "reproduction-results.json",
        manifest._ManifestReproductionArtifact(
            schema_version="1.0",
            test_specifications=[],
            results=[],
            candidate_resolutions=state.resolutions,
        ),
    )
    _write_model(root / "report.json", report)
    decoded = AuditReport.model_validate_json((root / "report.json").read_bytes())
    assert decoded == report and len(candidates.findings) == 9
    assert not decoded.completed and not decoded.scanner_runs and not decoded.reproductions
    assert len(fixture.journal.pass_results) == 7
    # Named invariant: every original retained or ordinary finding survives all seven passes.
    manifest._validate_scheduler_report_authority(
        root=root,
        report=decoded,
        snapshot=manifest._scheduler_report_authority_snapshot(fixture.journal),
        config=config,
        run_options=fixture.source.analysis_arguments["run_options"],
    )


def test_coverage_only_campaign_refuses_a_report_with_unbound_host_candidates(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]],
) -> None:
    fixture, arguments = complete_manifest
    root = fixture.privacy.run_directory
    candidates = sorted(
        (
            candidate
            for output in fixture.journal.outputs
            for candidate in output.accepted_candidates
        ),
        key=lambda candidate: candidate.candidate_id,
    )
    _write_model(
        root / "candidate-findings.json",
        CandidateFindingArtifact(schema_version="1.1", findings=candidates),
    )
    _write_model(
        root / "reproduction-results.json",
        manifest._ManifestReproductionArtifact(
            schema_version="1.0", test_specifications=[], results=[]
        ),
    )
    # The coverage-only fixture's placeholder host IDs are not actual accepted findings.
    # Named invariant: passing coverage checks cannot authorize an unbound candidate report.
    with pytest.raises(ValueError, match="pass-three differs from accepted blind candidates"):
        manifest._validate_scheduler_report_authority(
            root=root,
            report=arguments["report"],
            snapshot=arguments["snapshot"],
            config=arguments["config"],
            run_options=None,
        )
    assert not arguments["report"].completed
