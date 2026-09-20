"""Original report/cost joins and honest full-manifest refusals on synthetic evidence."""

from pathlib import Path

import pytest

from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryChildActivation
from mmaudit.orchestration import manifest
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_assurance_support import build_complete_tree_assurance_fixture
from tests.truncation_tree_report_support import candidate_report_config
from tests.truncation_tree_run_artifacts import write_original_run_artifacts
from tests.truncation_tree_run_support import OriginalRunAccounting


def test_original_full_tree_bundle_keeps_costs_and_manifest_refusals(tmp_path: Path) -> None:
    config = candidate_report_config()
    root = tmp_path / "original-run"
    fixture = build_complete_tree_assurance_fixture(
        config,
        root / "private" / "scheduler-journal",
        candidate_report=True,
        run_manifest=True,
    )
    try:
        report = write_original_run_artifacts(
            config, fixture, fixture.candidate_report.final_report(fixture.runtime)
        )
        original = fixture.journal.artifact()
        accounting = fixture.run_accounting
        assert accounting is not None
        assert len(report.findings) == 9 and not report.completed
        assert not report.scanner_runs and not report.reproductions and not report.formal_runs
        assert not report.invariant_executions and not accounting.pending
        assert set(accounting.dispatched_requests) == {record.request_id for record in report.usage}
        assert len(accounting.ledger.snapshot().entries) == len(report.usage)
        arguments = dict(
            run_dir=root,
            report=report,
            config=config,
            run_options=fixture.source.analysis_arguments["run_options"],
            production_qualification=fixture.authorities.qualification,
            scheduler_runtime_journal=fixture.journal,
            protocol_profile_replay_discovery=fixture.source.discovery,
        )
        # Named invariant: original report projections preserve every finding and charged request.
        manifest._validate_report_artifact_consistency(root, report, report_bundle_required=True)
        manifest._validate_model_execution_cost_ledger_custody(
            root, report, original, current_model_execution_required=True
        )
        manifest._validate_run_terminal_report_authority(
            root, report, scheduler_artifact=original, achieved_profile=None
        )
        context = manifest._validated_context_manifest(root, report, scheduler_artifact=original)
        assert context is not None
        assert fixture.journal.artifact() == original
        # These unfinished original inputs are refusals, never full-manifest acceptance.
        with pytest.raises(ValueError, match="selected split retry policy"):
            manifest.build_run_evidence_manifest(**arguments)
        with pytest.raises(ValueError, match="differs from effective token configuration"):
            manifest._validate_context_manifest_configuration(context, config)
        assert all(
            candidate.output_limit < config.effective_reserved_output_tokens
            for candidate in fixture.authorities.refresh_runtime.history.candidate_registry.candidates
        )
        activation = next(
            entry
            for entry in fixture.journal.truncation_recovery_entries
            if isinstance(entry, SchedulerTruncationRecoveryChildActivation)
        )
        child_usage = next(
            usage
            for usage in report.usage
            if usage.request_id == activation.child_logical_request_id
        )
        for index, substituted in enumerate(
            (
                None,
                activation.model_copy(update={"child_logical_request_id": "different-child"}),
                activation.model_copy(update={"request_limit_id": "different-root"}),
                activation.model_copy(
                    update={
                        "request_limit_count_before_child": (
                            activation.request_limit_count_before_child + 1
                        )
                    }
                ),
            )
        ):
            ledger = OriginalRunAccounting(tmp_path / f"recovery-refusal-{index}")
            # Named invariant: wrong or absent original recovery coordinates reserve no cost.
            with pytest.raises(ValueError):
                ledger.prepare(
                    child_usage,
                    fixture.authorities.refresh_runtime,
                    recovery_activation=substituted,
                )
            assert not ledger.ledger.snapshot().entries and not ledger.pending
        for name in ("metadata.json", "model-execution.json", "client-report.md"):
            path = root / name
            saved = path.read_bytes()
            path.write_bytes(b"{}\n")
            try:
                # Named invariant: a present substitute never inherits original report custody.
                with pytest.raises(ValueError):
                    manifest._validate_report_artifact_consistency(
                        root, report, report_bundle_required=True
                    )
            finally:
                path.write_bytes(saved)
        assert fixture.journal.artifact() == original
    finally:
        fixture.close()
