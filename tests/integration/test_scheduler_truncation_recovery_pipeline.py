"""Focused local-provider coverage for the pipeline truncation-recovery boundary."""

from __future__ import annotations

import json
from decimal import ROUND_DOWN, Decimal, Inexact, localcontext
from pathlib import Path
from typing import Any, cast

import pytest

import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryEntryKind,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.pipeline import _canonical_recovery_usd_total
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_pipeline import _run


def _one_whole_protocol_config(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    whole_protocol_count: int = 1,
    specialist: bool = False,
) -> Any:
    sections: dict[str, Any] = {
        "privacy": {"fail_on_detected_secret": False},
        "execution": {"max_requests_per_agent": 4},
    }
    if specialist:
        sections["profile"] = "deep"
        sections["models"] = {
            "allow_non_independent_models": True,
            "specialists": {
                "access_control": {
                    "primary": "bravo/borealis-secure",
                    "fallbacks": [],
                }
            },
        }
    config = config_factory(**sections).effective()
    model_ids = (
        config.models.source_audit.primary,
        config.models.business_logic.primary,
    )
    if whole_protocol_count not in {1, 2}:
        raise AssertionError("focused recovery fixture supports one or two blind parents")

    def one_whole_protocol_review(
        _config: Any,
        _qualification: Any,
        *,
        selected_model_ids: frozenset[str] | None = None,
        now: Any = None,
    ) -> tuple[tuple[str, str], ...]:
        del selected_model_ids, now
        return tuple(
            (
                model_id,
                pipeline_module._scheduler_root_lineage(config, model_id),
            )
            for model_id in model_ids[:whole_protocol_count]
        )

    monkeypatch.setattr(
        pipeline_module,
        "_whole_protocol_review_models",
        one_whole_protocol_review,
    )
    return config


def _recovery_entries(run_dir: Path) -> tuple[dict[str, Any], ...]:
    directory = run_dir / "private" / "scheduler-journal" / "truncation-recovery"
    return tuple(
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))
    )


def _truncated_parent_attempts(run_dir: Path) -> tuple[dict[str, Any], ...]:
    directory = run_dir / "private" / "scheduler-journal" / "provider-attempts"
    matches = tuple(
        payload
        for path in sorted(directory.glob("*.json"))
        if (payload := json.loads(path.read_text(encoding="utf-8"))).get("truncation_projection")
        is not None
    )
    return cast(tuple[dict[str, Any], ...], matches)


def _truncated_parent_attempt(run_dir: Path) -> dict[str, Any]:
    matches = _truncated_parent_attempts(run_dir)
    assert len(matches) == 1
    return matches[0]


def _candidate_and_surface_inventory(run_dir: Path) -> tuple[bytes, bytes]:
    return (
        (run_dir / "candidate-findings.json").read_bytes(),
        (run_dir / "private" / "model-review-artifacts.json").read_bytes(),
    )


def test_recovery_cost_sum_ignores_hostile_decimal_context() -> None:
    with localcontext() as ambient:
        ambient.prec = 2
        ambient.rounding = ROUND_DOWN
        ambient.traps[Inexact] = True
        actual = _canonical_recovery_usd_total(
            (
                "9999999999999",
                "0.123456789012345678901234567890123456",
                "0.000000000000000000000000000000000001",
            )
        )

    assert actual == "9999999999999.123456789012345678901234567890123457"


def test_recovery_cost_sum_rejects_a_lying_over_limit_iterable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    yielded = 0

    class LyingCosts:
        def __len__(self) -> int:
            return 0

        def __iter__(self) -> Any:
            nonlocal yielded
            for _index in range(4):
                yielded += 1
                yield "0.000000000000000001"

    monkeypatch.setattr(
        pipeline_module,
        "_TRUNCATION_RECOVERY_COST_COMPONENT_LIMIT",
        3,
    )
    with pytest.raises(ValueError, match="exceeds its compiled bound"):
        _canonical_recovery_usd_total(LyingCosts())

    assert yielded == 4


@pytest.mark.asyncio
async def test_mock_direct_recovery_is_noncrediting_and_resume_dispatches_nothing(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "truncation-recovery-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "output"
    fake = FakeOpenRouter(mode="truncation_recovery")

    first = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        cost_ledger=ledger,
        output=output,
    )

    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == 2
    parent = _truncated_parent_attempt(first.run_dir)
    projection = parent["truncation_projection"]
    assert [item["candidate_id"] for item in projection["findings"]] == ["raw-truncated-parent"]
    assert projection["surface_reviews"] == []
    assert parent["usage_record"]["status"] == "rejected_truncated_response"
    entries = _recovery_entries(first.run_dir)
    child_results = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value
    )
    closures = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value
    )
    assert len(child_results) == 2
    assert {entry["terminal_status"] for entry in child_results} == {
        SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value,
        SchedulerTruncationRecoveryTerminalStatus.TRUNCATED.value,
    }
    assert [
        (
            entry["runtime_usage_record"]["attempts"],
            entry["runtime_usage_record"]["retry_count"],
            entry["runtime_request_limit_reservation"]["request_limit_count_before"],
            entry["runtime_request_limit_reservation"]["request_limit_count_after"],
        )
        for entry in child_results
    ] == [(1, 0, 1, 2), (1, 0, 2, 3)]
    assert {
        entry["runtime_request_limit_reservation"]["request_limit_scope"] for entry in child_results
    } == {parent["usage_record"]["request_id"]}
    successful_child = next(
        entry
        for entry in child_results
        if entry["terminal_status"] == SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value
    )
    assert successful_child["runtime_usage_record"]["execution_evidence"] == (
        ExecutionEvidenceKind.MOCK.value
    )
    assert len(closures) == 1
    assert closures[0]["closure_status"] == (
        SchedulerTruncationRecoveryClosureStatus.INCOMPLETE.value
    )
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-truncated-parent" not in first_inventory[0]
    assert all(
        not str(artifact["request_id"]).startswith("scheduler-recovery-request-")
        for artifact in json.loads(first_inventory[1])["artifacts"]
    )

    resumed_fake = FakeOpenRouter(mode="truncation_recovery")
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
    assert resumed_fake.chat_calls == 0
    assert resumed_fake.truncated_parent_calls == 0
    assert resumed_fake.recovery_child_calls == 0
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory


@pytest.mark.asyncio
async def test_multiple_truncated_parents_recover_sequentially_without_resume_dispatch(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        whole_protocol_count=2,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "multiple-recovery-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "multiple-recovery-output"
    fake = FakeOpenRouter(mode="truncation_recovery_multiple")

    first = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        cost_ledger=ledger,
        output=output,
    )

    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 2
    assert fake.recovery_child_calls == 4
    parents = _truncated_parent_attempts(first.run_dir)
    assert len(parents) == 2
    assert {
        finding["candidate_id"]
        for parent in parents
        for finding in parent["truncation_projection"]["findings"]
    } == {"raw-truncated-parent-0", "raw-truncated-parent-1"}
    assert all(not parent["truncation_projection"]["surface_reviews"] for parent in parents)

    entries = _recovery_entries(first.run_dir)
    family_roots = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value
    )
    child_results = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value
    )
    closures = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value
    )
    assert len(family_roots) == len(closures) == 2
    assert len(child_results) == 4
    assert all(
        closure["closure_status"] == SchedulerTruncationRecoveryClosureStatus.INCOMPLETE.value
        for closure in closures
    )
    for family in family_roots:
        family_results = tuple(
            result for result in child_results if result["family_id"] == family["family_id"]
        )
        assert [result["terminal_status"] for result in family_results] == [
            SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value,
            SchedulerTruncationRecoveryTerminalStatus.TRUNCATED.value,
        ]
        assert [
            result["runtime_request_limit_reservation"]["request_limit_count_before"]
            for result in family_results
        ] == [1, 2]
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-truncated-parent-0" not in first_inventory[0]
    assert b"raw-truncated-parent-1" not in first_inventory[0]

    resumed_fake = FakeOpenRouter(mode="truncation_recovery_multiple")
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
    assert resumed_fake.chat_calls == 0
    assert resumed_fake.truncated_parent_calls == 0
    assert resumed_fake.recovery_child_calls == 0
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory


@pytest.mark.asyncio
async def test_retained_parent_surface_closes_incomplete_mock_family_without_credit(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "retained-surface-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "retained-surface-output"
    fake = FakeOpenRouter(mode="truncation_recovery_retained_surface")

    first = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        cost_ledger=ledger,
        output=output,
    )

    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == 2
    projection = _truncated_parent_attempt(first.run_dir)["truncation_projection"]
    assert [item["candidate_id"] for item in projection["findings"]] == ["raw-truncated-parent"]
    assert len(projection["surface_reviews"]) == 1
    retained_surface_ids = tuple(
        sorted(item["surface_id"] for item in projection["surface_reviews"])
    )
    entries = _recovery_entries(first.run_dir)
    family_roots = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value
    )
    child_results = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value
    )
    closures = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value
    )
    assert len(family_roots) == len(closures) == 1
    assert len(child_results) == 2
    family = family_roots[0]
    parent = family["recovery_plan"]["parent"]
    assert tuple(parent["retained_surface_ids"]) == retained_surface_ids
    assert set(parent["unfinished_surface_ids"]) == (
        set(parent["requested_surface_ids"]) - set(retained_surface_ids)
    )
    child_surface_ids = tuple(
        surface_id
        for child in family["recovery_plan"]["children"]
        for surface_id in child["surface_ids"]
    )
    assert len(child_surface_ids) == len(set(child_surface_ids))
    assert set(child_surface_ids) == set(parent["unfinished_surface_ids"])
    assert not set(child_surface_ids).intersection(retained_surface_ids)
    assert {entry["terminal_status"] for entry in child_results} == {
        SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value,
        SchedulerTruncationRecoveryTerminalStatus.TRUNCATED.value,
    }
    assert {entry["runtime_usage_record"]["execution_evidence"] for entry in child_results} == {
        ExecutionEvidenceKind.MOCK.value
    }
    assert closures[0]["closure_status"] == (
        SchedulerTruncationRecoveryClosureStatus.INCOMPLETE.value
    )
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-truncated-parent" not in first_inventory[0]
    artifacts = json.loads(first_inventory[1])["artifacts"]
    assert all(
        not str(artifact["review_role"]).startswith("whole_protocol_review:")
        and not str(artifact["request_id"]).startswith("scheduler-recovery-request-")
        for artifact in artifacts
    )

    resumed_fake = FakeOpenRouter(mode="truncation_recovery_retained_surface")
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
    assert resumed_fake.chat_calls == 0
    assert resumed_fake.truncated_parent_calls == 0
    assert resumed_fake.recovery_child_calls == 0
    assert _recovery_entries(first.run_dir) == entries
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory


@pytest.mark.asyncio
async def test_specialist_truncation_never_opens_recovery_family(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        specialist=True,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "specialist-truncation-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "specialist-truncation-output"
    fake = FakeOpenRouter(mode="truncation_recovery_specialist")

    first = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        cost_ledger=ledger,
        output=output,
    )

    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.specialist_truncation_calls == 1
    assert fake.recovery_child_calls == 0
    parent = _truncated_parent_attempt(first.run_dir)
    assert parent["usage_record"]["role"] == "specialist:access_control"
    assert [finding["candidate_id"] for finding in parent["truncation_projection"]["findings"]] == [
        "raw-specialist-retained"
    ]
    assert _recovery_entries(first.run_dir) == ()
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-specialist-retained" not in first_inventory[0]

    resumed_fake = FakeOpenRouter(mode="truncation_recovery_specialist")
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
    assert resumed_fake.chat_calls == 0
    assert resumed_fake.specialist_truncation_calls == 0
    assert resumed_fake.recovery_child_calls == 0
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory
