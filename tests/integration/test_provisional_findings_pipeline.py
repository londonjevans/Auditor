"""Actual pipeline reports retain provisional records without granting model or audit credit."""

from __future__ import annotations

import copy
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import tests.fake_openrouter as fake_module
from mmaudit.constants import ExitCode
from mmaudit.models.provisional_findings import (
    PROVISIONAL_FINDINGS_METADATA_KEY,
    provisional_findings_from_metadata,
)
from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.truncation import CandidateReviewChannelState, frame_candidate_review_batch
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_pipeline import _run
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _one_whole_protocol_config,
    _recovery_entries,
    _truncated_parent_attempt,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
@pytest.mark.parametrize("target", ["parent", "child"])
async def test_original_pipeline_reports_provisional_records_and_resumes_without_new_work(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
    state: CandidateReviewChannelState,
    target: str,
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch)
    ledger_path = tmp_path / "synthetic-provisional-ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    original_wire = fake_module._truncated_candidate_review_wire
    valid_ids = (f"provisional-{target}-first", f"provisional-{target}-second")

    def selected_channel_wire(
        content: dict[str, Any],
        *,
        retained_surface_count: int | None = None,
        retained_finding_count: int | None = None,
    ) -> str:
        child = not content["findings"]
        if child != (target == "child"):
            return original_wire(
                content,
                retained_surface_count=retained_surface_count,
                retained_finding_count=retained_finding_count,
            )
        material = copy.deepcopy(content)
        template = (
            material["findings"][0]
            if material["findings"]
            else fake_module._candidate(
                candidate_id="synthetic-template",
                role=material["surface_reviews"][0]["review_role"],
            )
        )
        material["findings"] = [
            {**copy.deepcopy(template), "candidate_id": identity}
            for identity in (*valid_ids, "synthetic-discarded-record")
        ]
        frames = frame_candidate_review_batch(
            CandidateReviewBatch.model_validate(material)
        ).model_dump(mode="json")["frames"]
        if state is CandidateReviewChannelState.INVALID:
            frames[3]["record"]["confidence"] = "synthetic-invalid-confidence"
            count, phase, tail = 5, "SURFACE_REVIEW", '"surface_id":"synthetic-private-tail'
        else:
            count, phase, tail = 3, "FINDING", '"candidate_id":"synthetic-private-tail'
        prefix = ",".join(
            json.dumps(
                frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            )
            for frame in frames[:count]
        )
        return (
            '{"frames":['
            + prefix
            + f',{{"schema_version":"1.0","sequence":{count},"phase":"{phase}","record":{{'
            + tail
        )

    monkeypatch.setattr(fake_module, "_truncated_candidate_review_wire", selected_channel_wire)
    mode = "truncation_recovery" if target == "parent" else "truncation_recovery_recursive"
    fake = FakeOpenRouter(mode=mode)
    output = tmp_path / "provisional-output"
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output)
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == 2
    inventory = provisional_findings_from_metadata(first.report.metadata)
    assert inventory is not None
    assert inventory.retained_finding_count == (2 if target == "parent" else 3)
    selected = [
        source
        for source in inventory.sources
        if source.source_kind == ("scheduler_parent" if target == "parent" else "recovery_child")
    ]
    assert len(selected) == 1
    source = selected[0]
    assert source.findings_state is state
    assert tuple(record.candidate.candidate_id for record in source.records) == valid_ids
    parent = _truncated_parent_attempt(first.run_dir)
    entries = _recovery_entries(first.run_dir)
    original = (
        parent
        if target == "parent"
        else next(
            entry
            for entry in entries
            if entry.get("child_logical_request_id") == source.request_id
            and entry.get("entry_kind") == "CHILD_TERMINAL"
        )
    )
    assert (
        source.truncation_projection_sha256 == original["truncation_projection"]["evidence_sha256"]
    )
    assert [record.candidate.model_dump(mode="json") for record in source.records] == original[
        "truncation_projection"
    ]["findings"]
    assert not any(entry.get("entry_kind") == "FAMILY_PROMOTED" for entry in entries)
    assert all(
        not set(valid_ids).intersection(finding.contributing_candidate_ids)
        for finding in (
            *first.report.findings,
            *first.report.rejected_findings,
            *first.report.filtered_findings,
        )
    )
    candidates_and_coverage = _candidate_and_surface_inventory(first.run_dir)
    assert all(identity.encode() not in candidates_and_coverage[0] for identity in valid_ids)
    persisted = json.loads((first.run_dir / "final-findings.json").read_bytes())
    assert persisted["metadata"][PROVISIONAL_FINDINGS_METADATA_KEY] == inventory.model_dump(
        mode="json"
    )
    assert "synthetic-private-tail" not in json.dumps(persisted)
    assert "synthetic-invalid-confidence" not in json.dumps(persisted)
    for name in ("client-report.md", "forensic-report.md", "audit-report.md"):
        rendered = (first.run_dir / name).read_text(encoding="utf-8")
        assert all(identity in rendered for identity in valid_ids)
        assert "Retained provisional findings — not validated" in rendered
        assert "not accepted or confirmed findings" in rendered
    original_files = _journal_private_file_snapshot(first.run_dir / "private" / "scheduler-journal")
    original_ledger = ledger.snapshot()
    original_ledger_bytes = ledger_path.read_bytes()
    resumed_fake = FakeOpenRouter(mode=mode)
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        output=output,
        resume_run_dir=first.run_dir,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE
    assert not resumed.report.completed
    assert (
        resumed_fake.chat_calls
        == resumed_fake.truncated_parent_calls
        == resumed_fake.recovery_child_calls
        == 0
    )
    replayed = provisional_findings_from_metadata(resumed.report.metadata)
    assert replayed is not None
    assert replayed.model_dump_json() == inventory.model_dump_json()
    assert _candidate_and_surface_inventory(resumed.run_dir) == candidates_and_coverage
    assert ledger.snapshot() == original_ledger
    assert ledger_path.read_bytes() == original_ledger_bytes
    assert (
        _journal_private_file_snapshot(first.run_dir / "private" / "scheduler-journal")
        == original_files
    )
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)
