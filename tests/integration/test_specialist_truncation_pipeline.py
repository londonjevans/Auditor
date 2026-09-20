"""MockTransport-only automatic specialist recursion; no provider or audit credit."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.constants import ExitCode
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_generic_truncation_tree_pipeline import _extend_synthetic_scope
from tests.integration.test_pipeline import _run
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _one_whole_protocol_config,
    _recovery_entries,
    _truncated_parent_attempt,
)


def _original_journal_json_bytes(run_dir: Path) -> tuple[tuple[str, bytes], ...]:
    directory = run_dir / "private" / "scheduler-journal"
    assert directory.is_dir()
    retained = tuple(
        (path.relative_to(directory).as_posix(), path.read_bytes())
        for path in sorted(directory.rglob("*.json"))
    )
    assert retained
    return retained


def _assert_original_specialist_terminals(
    entries: tuple[dict[str, Any], ...], *, role: str
) -> tuple[dict[str, Any], ...]:
    results = tuple(entry for entry in entries if entry["entry_kind"] == "CHILD_TERMINAL")
    request_role = f"specialist:{role}"
    for result in results:
        usage = result["runtime_usage_record"]
        activation = result["runtime_activation"]
        context = usage["routing"]["context_request_evidence"]
        assert activation["request_role"] == usage["role"] == request_role
        assert context["request_role"] == context["context_role"] == request_role
        assert usage["execution_evidence"] == ExecutionEvidenceKind.MOCK.value
        assert Decimal(result["accounted_cost_usd_exact"]) == Decimal("0.001")
        assert Decimal(result["accounted_cost_usd_exact"]) == Decimal(
            usage["accounted_cost_usd_exact"]
        )
        assert Decimal(result["accounted_cost_usd_exact"]) <= Decimal(result["reserved_usd_exact"])
        assert usage["attempts"] == 1 and usage["retry_count"] == 0
        if result["terminal_status"] == "TRUNCATED":
            assert result["schema_version"] == "1.1"
            assert result["completed_surface_ids"] == []
            assert result.get("runtime_output_artifact") is None
            assert result.get("runtime_specialist_accepted_outcome") is None
            assert result.get("runtime_specialist_accepted_outcome_sha256") is None
            continue
        assert result["terminal_status"] == "SUCCEEDED"
        assert result["schema_version"] == "1.2"
        outcome = SpecialistAcceptedOutcome.model_validate_json(
            json.dumps(result["runtime_specialist_accepted_outcome"]), strict=True
        )
        assert outcome.outcome_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
        assert outcome.specialist_role == role
        assert outcome.request_role == request_role
        assert outcome.request_id == usage["request_id"] == result["child_logical_request_id"]
        assert outcome.validated_response_sha256 == usage["validated_response_sha256"]
        assert outcome.context_request_evidence_sha256 == context["evidence_sha256"]
        assert (
            outcome.surface_review_artifact_sha256
            == result["runtime_output_artifact_sha256"]
            == result["runtime_output_artifact"]["artifact_sha256"]
        )
        assert outcome.requested_surface_count == len(result["child_surface_ids"])
        assert outcome.requested_surface_count == len(result["runtime_requested_surface_requests"])
        assert outcome.evidence_sha256 == result["runtime_specialist_accepted_outcome_sha256"]
    return results


@pytest.mark.parametrize(
    ("sources", "mode", "children", "depth", "role", "root_schema"),
    (
        (5, "truncation_recovery_specialist_recursive", 4, 2, "access_control", "1.2"),
        (9, "truncation_recovery_specialist_tree", 14, 3, "access_control", "1.3"),
        (17, "truncation_recovery_specialist_tree", 30, 4, "access_control", "1.3"),
        (
            17,
            "truncation_recovery_specialist_tree_retained",
            14,
            3,
            "false_negative_hunter",
            "1.3",
        ),
    ),
    ids=("legacy", "full-tree", "depth-four", "retained-second-role"),
)
@pytest.mark.asyncio
async def test_specialist_descendants_preserve_original_outcomes_limits_and_resume(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
    sources: int,
    mode: str,
    children: int,
    depth: int,
    role: str,
    root_schema: str,
) -> None:
    _extend_synthetic_scope(vulnerable_repo, sources=sources)
    config = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        specialist=True,
        specialist_role=role,
        max_requests_per_agent=children + 1,
    )
    ledger_path = tmp_path / "ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path, cap_usd=Decimal(str(config.execution.budget_usd))
    )
    output = tmp_path / "output"
    fake = FakeOpenRouter(mode=mode)
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output)

    assert first.exit_code is ExitCode.INCOMPLETE and not first.report.completed
    assert fake.specialist_truncation_calls == 1
    # Invariant: the actual pipeline dispatches every required descendant exactly once.
    assert fake.recovery_child_calls == children
    assert fake.truncated_parent_calls == 0
    entries = _recovery_entries(first.run_dir)
    families = tuple(entry for entry in entries if entry["entry_kind"] == "FAMILY_ROOT")
    closures = tuple(entry for entry in entries if entry["entry_kind"] == "FAMILY_CLOSED")
    results = _assert_original_specialist_terminals(entries, role=role)
    parent = _truncated_parent_attempt(first.run_dir)
    parent_id = parent["usage_record"]["request_id"]
    assert parent["usage_record"]["role"] == f"specialist:{role}"
    assert len(families) == len(closures) == children // 2
    assert len(results) == children
    assert max(c["depth"] for f in families for c in f["recovery_plan"]["children"]) == depth
    assert families[-1]["request_count_after_family"] == children
    assert families[-1]["request_limit_count_after_family"] == children + 1
    assert [result["global_request_ordinal"] for result in results] == list(range(1, children + 1))
    assert closures[-1]["family_id"] == families[0]["family_id"]
    assert closures[-1]["schema_version"] == root_schema
    assert closures[-1]["closure_status"] == "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING"
    assert not any(entry["entry_kind"] == "FAMILY_PROMOTED" for entry in entries)
    for family in families:
        binding = family["request_limit_binding"]["parent_request_limit_reservation"]
        assert binding["role"] == f"specialist:{role}"
        assert family["request_limit_id"] == parent_id
        plan_parent = family["recovery_plan"]["parent"]
        unfinished = [
            surface
            for child in family["recovery_plan"]["children"]
            for surface in child["surface_ids"]
        ]
        assert sorted(unfinished) == plan_parent["unfinished_surface_ids"]
        assert len(unfinished) == len(set(unfinished))
        assert set(plan_parent["retained_surface_ids"]).isdisjoint(unfinished)
    retained_bridges = [result for result in results if result["retained_surface_ids"]]
    assert bool(retained_bridges) == mode.endswith("tree_retained")
    request_ids = {parent_id, *(result["child_logical_request_id"] for result in results)}
    snapshot = ledger.snapshot()
    charges = tuple(entry for entry in snapshot.entries if entry.request_id in request_ids)
    assert len(charges) == children + 1
    assert sum((entry.accounted_cost_usd for entry in charges), Decimal("0")) == Decimal(
        "0.001"
    ) * (children + 1)
    assert all(entry.actual_cost_usd == entry.accounted_cost_usd for entry in charges)
    inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-specialist-retained" not in inventory[0]
    assert b"scheduler-recovery-request-" not in inventory[1]
    specialist_bytes = (first.run_dir / "specialist-execution.json").read_bytes()
    record = next(
        record for record in json.loads(specialist_bytes)["records"] if record["role"] == role
    )
    assert record["status"] == "failed"
    assert record["successful_requests"] == record["source_review_creditable_requests"] == 0
    assert record["accepted_outcomes"] == []
    assert set(record["failed_request_ids"]) == request_ids
    ledger_bytes = ledger_path.read_bytes()
    journal_bytes = _original_journal_json_bytes(first.run_dir)

    resumed_fake = FakeOpenRouter(mode=mode)
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE and not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert resumed_fake.specialist_truncation_calls == 0
    assert _recovery_entries(first.run_dir) == entries
    assert _original_journal_json_bytes(first.run_dir) == journal_bytes
    assert _candidate_and_surface_inventory(resumed.run_dir) == inventory
    assert (resumed.run_dir / "specialist-execution.json").read_bytes() == specialist_bytes
    assert ledger.snapshot() == snapshot and ledger_path.read_bytes() == ledger_bytes
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)


@pytest.mark.asyncio
async def test_specialist_descendants_cannot_expand_original_shared_request_limit(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    _extend_synthetic_scope(vulnerable_repo, sources=17)
    config = _one_whole_protocol_config(
        config_factory, monkeypatch, specialist=True, max_requests_per_agent=5
    )
    ledger_path = tmp_path / "limited-ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path, cap_usd=Decimal(str(config.execution.budget_usd))
    )
    mode = "truncation_recovery_specialist_tree"
    fake = FakeOpenRouter(mode=mode)
    output = tmp_path / "limited-output"
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output)
    assert first.exit_code is ExitCode.INCOMPLETE and not first.report.completed
    assert fake.recovery_child_calls == 4
    entries = _recovery_entries(first.run_dir)
    results = _assert_original_specialist_terminals(entries, role="access_control")
    families = tuple(entry for entry in entries if entry["entry_kind"] == "FAMILY_ROOT")
    assert len(families) == 2
    assert families[-1]["request_limit_count_after_family"] == 5
    assert entries[-1]["closure_status"] == "INCOMPLETE"
    assert not any(entry["entry_kind"] == "FAMILY_PROMOTED" for entry in entries)
    request_ids = {result["child_logical_request_id"] for result in results}
    snapshot = ledger.snapshot()
    charges = tuple(entry for entry in snapshot.entries if entry.request_id in request_ids)
    assert len(charges) == 4
    assert sum((entry.accounted_cost_usd for entry in charges), Decimal("0")) == Decimal("0.004")
    ledger_bytes = ledger_path.read_bytes()
    specialist_bytes = (first.run_dir / "specialist-execution.json").read_bytes()
    journal_bytes = _original_journal_json_bytes(first.run_dir)
    resumed_fake = FakeOpenRouter(mode=mode)
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE and not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert _recovery_entries(first.run_dir) == entries
    assert _original_journal_json_bytes(first.run_dir) == journal_bytes
    assert ledger.snapshot() == snapshot and ledger_path.read_bytes() == ledger_bytes
    assert (resumed.run_dir / "specialist-execution.json").read_bytes() == specialist_bytes
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)
