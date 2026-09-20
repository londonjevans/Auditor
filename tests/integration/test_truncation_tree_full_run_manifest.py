"""A full original synthetic manifest, with configuration and missing engines preserved."""

from pathlib import Path

import pytest

from mmaudit.orchestration import manifest
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_assurance_support import build_complete_tree_assurance_fixture
from tests.truncation_tree_report_support import candidate_report_config
from tests.truncation_tree_run_artifacts import write_original_run_artifacts


def test_original_configured_tree_issues_full_manifest_without_engine_credit(
    tmp_path: Path,
) -> None:
    config = candidate_report_config()
    root = tmp_path / "original-configured-run"
    fixture = build_complete_tree_assurance_fixture(
        config,
        root / "private" / "scheduler-journal",
        candidate_report=True,
        run_manifest=True,
        configured_requests=True,
    )
    try:
        report = write_original_run_artifacts(
            config, fixture, fixture.candidate_report.final_report(fixture.runtime)
        )
        original = fixture.journal.artifact()
        accounting = fixture.run_accounting
        assert accounting is not None
        assert len(report.findings) == 9 and len(report.usage) == 63
        assert not report.completed
        assert not report.scanner_runs and not report.reproductions and not report.formal_runs
        assert not report.invariant_executions and not accounting.pending
        assert len(accounting.ledger.snapshot().entries) == 63
        assert set(accounting.dispatched_requests) == {usage.request_id for usage in report.usage}
        assert accounting.spent_input_tokens == sum(usage.prompt_tokens for usage in report.usage)
        assert accounting.spent_output_tokens == sum(
            usage.completion_tokens for usage in report.usage
        )
        by_request = {usage.request_id: usage for usage in report.usage}
        spent_input = spent_output = 0
        for request_id in accounting.dispatched_requests:
            usage = by_request[request_id]
            before = usage.routing["atomic_token_reservation"]["before"]
            assert before["spent_input_tokens"] == spent_input
            assert before["spent_output_tokens"] == spent_output
            assert before["reserved_input_tokens"] == 0
            assert before["reserved_output_tokens"] == 0
            spent_input += usage.prompt_tokens
            spent_output += usage.completion_tokens
        arguments = dict(
            run_dir=root,
            report=report,
            config=config,
            run_options=fixture.source.analysis_arguments["run_options"],
            production_qualification=fixture.authorities.qualification,
            scheduler_runtime_journal=fixture.journal,
            protocol_profile_replay_discovery=fixture.source.discovery,
        )
        # Named invariant: complete evidence custody does not invent completed engine assurance.
        result = manifest.build_run_evidence_manifest(**arguments)
        assert result.schema_version == "1.4"
        assert result.run_configuration.achieved_profile is None
        assert result.run_configuration.requested_profile == config.profile
        assert fixture.journal.artifact() == original
        with pytest.raises(ValueError, match="live runtime journal authority"):
            manifest.build_run_evidence_manifest(
                **(arguments | {"scheduler_runtime_journal": None})
            )
        for name in ("metadata.json", "model-execution.json", "client-report.md"):
            path = root / name
            saved = path.read_bytes()
            path.write_bytes(b"{}\n")
            try:
                # Named invariant: substituted public files cannot inherit the original manifest.
                with pytest.raises(ValueError):
                    manifest.build_run_evidence_manifest(**arguments)
            finally:
                path.write_bytes(saved)
        assert fixture.journal.artifact() == original
    finally:
        fixture.close()
