"""MockTransport-only bounded generic recovery trees; no live API or chain access."""

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


def _extend_synthetic_scope(repo: Path, *, sources: int) -> None:
    fixture = (
        Path(__file__).resolve().parents[1] / "fixtures" / "retained_bridge" / "retained_counter.py"
    )
    for index in range(sources - 4):
        shutil.copyfile(fixture, repo / f"generic_recovery_surface_{index:02d}.py")


@pytest.mark.parametrize(
    ("sources", "mode", "expected_children", "expected_depth"),
    (
        (9, "truncation_recovery_tree", 14, 3),
        (17, "truncation_recovery_tree", 30, 4),
        (17, "truncation_recovery_tree_retained", 14, 3),
    ),
)
@pytest.mark.asyncio
async def test_generic_tree_dispatch_and_resume_preserve_scope_and_all_liabilities(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
    sources: int,
    mode: str,
    expected_children: int,
    expected_depth: int,
) -> None:
    _extend_synthetic_scope(vulnerable_repo, sources=sources)
    config = _one_whole_protocol_config(
        config_factory, monkeypatch, max_requests_per_agent=expected_children + 1
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    fake = FakeOpenRouter(mode=mode)
    output = tmp_path / "output"
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output)
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == expected_children
    entries = _recovery_entries(first.run_dir)
    families = [e for e in entries if e["entry_kind"] == "FAMILY_ROOT"]
    results = [e for e in entries if e["entry_kind"] == "CHILD_TERMINAL"]
    closures = [e for e in entries if e["entry_kind"] == "FAMILY_CLOSED"]
    assert len(families) == len(closures) == expected_children // 2
    assert len(results) == expected_children
    assert len(families[0]["recovery_plan"]["parent"]["requested_surface_ids"]) == sources
    assert (
        max(child["depth"] for f in families for child in f["recovery_plan"]["children"])
        == expected_depth
    )
    assert families[-1]["request_count_after_family"] == expected_children
    assert families[-1]["request_limit_count_after_family"] == expected_children + 1
    assert [e["global_request_ordinal"] for e in results] == list(range(1, expected_children + 1))
    assert closures[-1]["family_id"] == families[0]["family_id"]
    assert closures[-1]["schema_version"] == "1.3"
    assert closures[-1]["closure_status"] == "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING"
    assert len(closures[-1]["nested_family_closure_sha256s"]) == 2
    assert not any(e["entry_kind"] == "FAMILY_PROMOTED" for e in entries)
    for family in families:
        parent = family["recovery_plan"]["parent"]
        unfinished = [
            surface
            for child in family["recovery_plan"]["children"]
            for surface in child["surface_ids"]
        ]
        assert sorted(unfinished) == parent["unfinished_surface_ids"]
        assert len(unfinished) == len(set(unfinished))
        assert set(parent["retained_surface_ids"]).isdisjoint(unfinished)
    for result in results:
        if result["terminal_status"] == "TRUNCATED":
            assert result["completed_surface_ids"] == []
            assert result.get("runtime_output_artifact") is None
    request_ids = {result["child_logical_request_id"] for result in results}
    snapshot = ledger.snapshot()
    charges = [e for e in snapshot.entries if e.request_id in request_ids]
    assert len(charges) == expected_children
    assert (
        sum((e.accounted_cost_usd for e in charges), Decimal("0"))
        == Decimal("0.001") * expected_children
    )
    assert all(e.actual_cost_usd == e.accounted_cost_usd for e in charges)
    inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"scheduler-recovery-request-" not in inventory[1]

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
    assert resumed.exit_code is ExitCode.INCOMPLETE
    assert not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert ledger.snapshot() == snapshot
    assert _recovery_entries(first.run_dir) == entries
    assert _candidate_and_surface_inventory(resumed.run_dir) == inventory
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)


@pytest.mark.asyncio
async def test_generic_descendants_cannot_expand_the_original_shared_request_ceiling(
    config_factory: Any, monkeypatch: pytest.MonkeyPatch, vulnerable_repo: Path, tmp_path: Path
) -> None:
    _extend_synthetic_scope(vulnerable_repo, sources=17)
    config = _one_whole_protocol_config(config_factory, monkeypatch, max_requests_per_agent=5)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "limited-ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    fake = FakeOpenRouter(mode="truncation_recovery_tree")
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger)
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.recovery_child_calls == 4
    entries = _recovery_entries(first.run_dir)
    assert sum(e["entry_kind"] == "FAMILY_ROOT" for e in entries) == 2
    assert entries[-1]["closure_status"] == "INCOMPLETE"
    assert not any(e["entry_kind"] == "FAMILY_PROMOTED" for e in entries)
    request_ids = {
        e["child_logical_request_id"] for e in entries if e["entry_kind"] == "CHILD_TERMINAL"
    }
    charges = [e for e in ledger.snapshot().entries if e.request_id in request_ids]
    assert len(charges) == 4
    assert sum((e.accounted_cost_usd for e in charges), Decimal("0")) == Decimal("0.004")
