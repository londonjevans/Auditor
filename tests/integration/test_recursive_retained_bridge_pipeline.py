"""Mock-only retained-bridge dispatch, shared accounting and zero-transport resume."""

from __future__ import annotations

import shutil
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.constants import ExitCode
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_pipeline import _run
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _one_whole_protocol_config,
    _recovery_entries,
)


@pytest.fixture
def retained_bridge_repo(vulnerable_repo: Path) -> Path:
    """Keep two unfinished bridge surfaces after retaining a complete record."""

    source = Path(__file__).resolve().parents[1] / "fixtures" / "retained_bridge"
    for name in ("retained_counter.py", "retained_validation.py"):
        shutil.copyfile(source / name, vulnerable_repo / name)
    return vulnerable_repo


@pytest.mark.asyncio
async def test_retained_mock_bridge_recovers_only_unfinished_surfaces_without_credit(
    config_factory: Any, monkeypatch: pytest.MonkeyPatch, retained_bridge_repo: Path, tmp_path: Path
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch, max_requests_per_agent=5)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    fake = FakeOpenRouter(mode="truncation_recovery_recursive_retained")
    output = tmp_path / "output"
    first = await _run(
        config, retained_bridge_repo, tmp_path, fake, cost_ledger=ledger, output=output
    )
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == 4
    entries = _recovery_entries(first.run_dir)
    families = [entry for entry in entries if entry["entry_kind"] == "FAMILY_ROOT"]
    closures = [entry for entry in entries if entry["entry_kind"] == "FAMILY_CLOSED"]
    results = [entry for entry in entries if entry["entry_kind"] == "CHILD_TERMINAL"]
    assert len(families) == len(closures) == 2
    root, nested = families
    bridge = next(result for result in results if result["terminal_status"] == "TRUNCATED")
    retained = bridge["retained_surface_ids"]
    assert len(retained) == 1
    assert retained == [r["surface_id"] for r in bridge["truncation_projection"]["surface_reviews"]]
    assert bridge.get("runtime_output_artifact") is bridge.get("runtime_normalized_batch") is None
    assert bridge["completed_surface_ids"] == []
    parent = nested["recovery_plan"]["parent"]
    children = nested["recovery_plan"]["children"]
    unfinished = [surface for child in children for surface in child["surface_ids"]]
    assert parent["retained_surface_ids"] == retained
    assert sorted(unfinished) == parent["unfinished_surface_ids"]
    assert len(unfinished) == len(set(unfinished))
    assert set(unfinished).isdisjoint(retained)
    assert sorted([*unfinished, *retained]) == bridge["child_surface_ids"]
    assert nested["parent_terminal_result_sha256"] == bridge["entry_sha256"]
    assert nested["request_count_after_family"] == 4
    assert nested["request_limit_count_after_family"] == 5
    assert closures[0]["covered_unfinished_surface_ids"] == parent["unfinished_surface_ids"]
    assert (
        closures[1]["covered_unfinished_surface_ids"]
        == (root["recovery_plan"]["parent"]["unfinished_surface_ids"])
    )
    assert closures[1]["closure_status"] == "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING"
    assert not any(entry["entry_kind"] == "FAMILY_PROMOTED" for entry in entries)
    snapshot = ledger.snapshot()
    request_ids = {result["child_logical_request_id"] for result in results}
    billed = [entry for entry in snapshot.entries if entry.request_id in request_ids]
    assert len(billed) == 4
    assert all(
        entry.actual_cost_usd == entry.accounted_cost_usd == Decimal("0.001") for entry in billed
    )
    assert all(entry.accounted_cost_usd <= entry.reserved_usd for entry in billed)
    inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"scheduler-recovery-request-" not in inventory[1]
    resumed_fake = FakeOpenRouter(mode="truncation_recovery_recursive_retained")
    resumed = await _run(
        config,
        retained_bridge_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE
    assert not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert ledger.snapshot() == snapshot
    assert _recovery_entries(first.run_dir) == entries
    assert _candidate_and_surface_inventory(resumed.run_dir) == inventory
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)


@pytest.mark.asyncio
async def test_retained_bridge_cannot_exceed_the_original_shared_request_limit(
    config_factory: Any, monkeypatch: pytest.MonkeyPatch, retained_bridge_repo: Path, tmp_path: Path
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch, max_requests_per_agent=4)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "limited-ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    fake = FakeOpenRouter(mode="truncation_recovery_recursive_retained")
    first = await _run(config, retained_bridge_repo, tmp_path, fake, cost_ledger=ledger)
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == 2
    entries = _recovery_entries(first.run_dir)
    assert sum(entry["entry_kind"] == "FAMILY_ROOT" for entry in entries) == 1
    bridge = next(entry for entry in entries if entry.get("terminal_status") == "TRUNCATED")
    assert len(bridge["retained_surface_ids"]) == 1
    assert entries[-1]["closure_status"] == "INCOMPLETE"
    assert not any(entry["entry_kind"] == "FAMILY_PROMOTED" for entry in entries)
    assert b"scheduler-recovery-request-" not in _candidate_and_surface_inventory(first.run_dir)[1]
    results = [entry for entry in entries if entry["entry_kind"] == "CHILD_TERMINAL"]
    ids = {entry["child_logical_request_id"] for entry in results}
    billed = [entry for entry in ledger.snapshot().entries if entry.request_id in ids]
    assert len(billed) == 2
    assert sum((entry.accounted_cost_usd for entry in billed), Decimal("0")) == Decimal("0.002")
