"""Focused local-provider coverage for the pipeline truncation-recovery boundary."""

from __future__ import annotations

import json
from decimal import ROUND_DOWN, Decimal, Inexact, localcontext
from pathlib import Path
from typing import Any, cast

import pytest

import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
)
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
    max_requests_per_agent: int = 4,
) -> Any:
    sections: dict[str, Any] = {
        "privacy": {"fail_on_detected_secret": False},
        "execution": {"max_requests_per_agent": max_requests_per_agent},
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


def _assert_resume_retains_exact_scheduler_journal(*, owner: Path, consumer: Path) -> None:
    assert not (consumer / "private" / "scheduler-journal").exists()
    owner_artifact_bytes = (owner / "scheduler-state.json").read_bytes()
    assert (consumer / "scheduler-state.json").read_bytes() == owner_artifact_bytes
    owner_artifact = json.loads(owner_artifact_bytes)
    reference = json.loads(
        (consumer / "private" / "scheduler-journal-reference.json").read_text(encoding="utf-8")
    )
    assert reference["owner_run_id"] == owner.name
    assert reference["consumer_run_id"] == consumer.name
    assert reference["relative_journal_path"] == f"{owner.name}/private/scheduler-journal"
    assert reference["scheduler_artifact_sha256"] == owner_artifact["artifact_sha256"]
    assert (
        reference["scheduler_journal_evidence_sha256"]
        == (owner_artifact["journal_evidence"]["evidence_sha256"])
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
async def test_mock_recursive_child_recovery_is_bounded_noncrediting_and_resumes_zero_transport(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        max_requests_per_agent=5,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "recursive-truncation-recovery-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "recursive-truncation-recovery-output"
    fake = FakeOpenRouter(mode="truncation_recovery_recursive")

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
    assert fake.recovery_child_calls == 4
    parent_attempt = _truncated_parent_attempt(first.run_dir)
    parent_request_id = parent_attempt["usage_record"]["request_id"]
    assert Decimal(parent_attempt["usage_record"]["accounted_cost_usd_exact"]) == Decimal("0.001")
    assert parent_attempt["truncation_projection"]["findings_state"] == "COMPLETE"

    entries = _recovery_entries(first.run_dir)
    assert [entry["entry_kind"] for entry in entries] == [
        SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value,
        SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value,
    ]
    family_roots = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value
    )
    activations = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value
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
    assert len(activations) == len(child_results) == 4
    root, nested = family_roots
    nested_closure, root_closure = closures
    assert root["family_index"] == 0
    assert root["parent_kind"] == "SCHEDULER_TASK"
    assert root["parent_family_id"] is None
    assert root["request_count_before_family"] == 0
    assert root["request_count_after_family"] == 2
    assert root["request_limit_count_before_family"] == 1
    assert root["request_limit_count_after_family"] == 3
    assert nested["family_index"] == 1
    assert nested["parent_kind"] == "RECOVERY_CHILD"
    assert nested["parent_family_id"] == root["family_id"]
    assert nested["request_count_before_family"] == 2
    assert nested["request_count_after_family"] == 4
    assert nested["request_limit_count_before_family"] == 3
    assert nested["request_limit_count_after_family"] == 5
    assert nested["request_limit_binding"] == root["request_limit_binding"]
    assert nested["requested_surface_manifest"] == root["requested_surface_manifest"]

    root_results = tuple(
        result for result in child_results if result["family_id"] == root["family_id"]
    )
    nested_results = tuple(
        result for result in child_results if result["family_id"] == nested["family_id"]
    )
    assert [result["terminal_status"] for result in root_results] == [
        SchedulerTruncationRecoveryTerminalStatus.TRUNCATED.value,
        SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value,
    ]
    assert all(
        result["terminal_status"] == SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value
        for result in nested_results
    )
    truncated_child_result = root_results[0]
    root_children = root["recovery_plan"]["children"]
    nested_children = nested["recovery_plan"]["children"]
    truncated_child = next(
        child
        for child in root_children
        if child["child_task_id"] == truncated_child_result["child_task_id"]
    )
    successful_root_child = next(
        child
        for child in root_children
        if child["child_task_id"] != truncated_child["child_task_id"]
    )
    assert truncated_child["depth"] == 1
    assert truncated_child["path"] == "0"
    assert truncated_child_result["retained_surface_ids"] == []
    assert truncated_child_result["truncation_projection"]["findings_state"] == "COMPLETE"
    assert truncated_child_result["truncation_projection"]["surface_reviews"] == []
    nested_parent = nested["recovery_plan"]["parent"]
    assert nested_parent["parent_task_id"] == truncated_child["child_task_id"]
    assert nested_parent["parent_logical_request_id"] == truncated_child["child_logical_request_id"]
    assert nested_parent["parent_task_plan_sha256"] == truncated_child["child_plan_sha256"]
    assert nested_parent["current_depth"] == 1
    assert nested_parent["parent_path"] == "0"
    assert nested_parent["requested_surface_ids"] == truncated_child["surface_ids"]
    assert nested_parent["unfinished_surface_ids"] == truncated_child["surface_ids"]
    assert nested["parent_terminal_result_sha256"] == truncated_child_result["entry_sha256"]
    assert [(child["depth"], child["path"]) for child in nested_children] == [
        (2, "00"),
        (2, "01"),
    ]
    grandchild_surfaces = tuple(
        surface_id for child in nested_children for surface_id in child["surface_ids"]
    )
    assert len(grandchild_surfaces) == len(set(grandchild_surfaces))
    assert set(grandchild_surfaces) == set(truncated_child["surface_ids"])
    assert not set(grandchild_surfaces).intersection(successful_root_child["surface_ids"])
    leaf_surfaces = (*successful_root_child["surface_ids"], *grandchild_surfaces)
    assert len(leaf_surfaces) == len(set(leaf_surfaces))
    assert set(leaf_surfaces) == set(root["recovery_plan"]["parent"]["unfinished_surface_ids"])

    assert [entry["global_request_ordinal"] for entry in activations] == [1, 2, 3, 4]
    assert [
        (
            entry["request_limit_count_before_child"],
            entry["request_limit_count_after_child"],
        )
        for entry in activations
    ] == [(1, 2), (2, 3), (3, 4), (4, 5)]
    assert {entry["request_limit_id"] for entry in activations} == {parent_request_id}
    assert [entry["global_request_ordinal"] for entry in child_results] == [1, 2, 3, 4]
    assert all(
        entry["runtime_usage_record"]["attempts"] == 1
        and entry["runtime_usage_record"]["retry_count"] == 0
        and entry["runtime_usage_record"]["completion_tokens"] == 50
        and entry["runtime_usage_record"]["execution_evidence"] == ExecutionEvidenceKind.MOCK.value
        and Decimal(entry["accounted_cost_usd_exact"])
        == Decimal(entry["runtime_usage_record"]["accounted_cost_usd_exact"])
        == Decimal("0.001")
        and Decimal(entry["accounted_cost_usd_exact"]) <= Decimal(entry["reserved_usd_exact"])
        for entry in child_results
    )
    assert [
        (
            entry["runtime_request_limit_reservation"]["request_limit_count_before"],
            entry["runtime_request_limit_reservation"]["request_limit_count_after"],
        )
        for entry in child_results
    ] == [(1, 2), (2, 3), (3, 4), (4, 5)]

    recovery_transport_ids = tuple(
        logical_request_id
        for request in fake.requests
        if isinstance(metadata := request.get("metadata"), dict)
        and isinstance(logical_request_id := metadata.get("mmaudit_request_id"), str)
        and logical_request_id.startswith("scheduler-recovery-request-")
    )
    assert recovery_transport_ids == tuple(
        activation["child_logical_request_id"] for activation in activations
    )
    assert recovery_transport_ids == tuple(
        result["child_logical_request_id"] for result in child_results
    )
    assert nested_closure["family_id"] == nested["family_id"]
    assert nested_closure["schema_version"] == "1.1"
    assert nested_closure["closure_status"] == (
        SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED.value
    )
    assert nested_closure["child_result_sha256s"] == [
        result["entry_sha256"] for result in nested_results
    ]
    assert nested_closure["nested_family_closure_sha256s"] == []
    assert root_closure["family_id"] == root["family_id"]
    assert root_closure["schema_version"] == "1.2"
    assert root_closure["closure_status"] == (
        SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING.value
    )
    assert root_closure["child_result_sha256s"] == [
        result["entry_sha256"] for result in root_results
    ]
    assert root_closure["nested_family_closure_sha256s"] == [nested_closure["entry_sha256"]]
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )

    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-truncated-parent" not in first_inventory[0]
    assert b"scheduler-recovery-request-" not in first_inventory[1]
    first_ledger = ledger.snapshot()
    recovery_ledger_entries = tuple(
        entry for entry in first_ledger.entries if entry.request_id in set(recovery_transport_ids)
    )
    assert len(recovery_ledger_entries) == 4
    assert {entry.request_id for entry in recovery_ledger_entries} == set(recovery_transport_ids)
    assert all(
        entry.actual_cost_usd == entry.accounted_cost_usd == Decimal("0.001")
        and entry.accounted_cost_usd <= entry.reserved_usd
        for entry in recovery_ledger_entries
    )

    resumed_fake = FakeOpenRouter(mode="truncation_recovery_recursive")
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
    _assert_resume_retains_exact_scheduler_journal(
        owner=first.run_dir,
        consumer=resumed.run_dir,
    )
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory
    assert ledger.snapshot() == first_ledger


@pytest.mark.asyncio
async def test_mock_recursive_recovery_refuses_grandchildren_beyond_shared_request_limit(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        max_requests_per_agent=4,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "recursive-request-limit-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    output = tmp_path / "recursive-request-limit-output"
    fake = FakeOpenRouter(mode="truncation_recovery_recursive")

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
    entries = _recovery_entries(first.run_dir)
    assert [entry["entry_kind"] for entry in entries] == [
        SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED.value,
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL.value,
        SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED.value,
    ]
    family_roots = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value
    )
    activations = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value
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
    assert len(activations) == len(child_results) == 2
    root = family_roots[0]
    closure = closures[0]
    assert root["parent_kind"] == "SCHEDULER_TASK"
    assert root["parent_family_id"] is None
    assert root["request_limit_count_before_family"] == 1
    assert root["request_limit_count_after_family"] == 3
    assert [(child["depth"], child["path"]) for child in root["recovery_plan"]["children"]] == [
        (1, "0"),
        (1, "1"),
    ]
    assert [result["terminal_status"] for result in child_results] == [
        SchedulerTruncationRecoveryTerminalStatus.TRUNCATED.value,
        SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value,
    ]
    assert [entry["global_request_ordinal"] for entry in activations] == [1, 2]
    assert [
        (
            entry["request_limit_count_before_child"],
            entry["request_limit_count_after_child"],
        )
        for entry in activations
    ] == [(1, 2), (2, 3)]
    assert closure["family_id"] == root["family_id"]
    assert closure["schema_version"] == "1.0"
    assert closure["closure_status"] == SchedulerTruncationRecoveryClosureStatus.INCOMPLETE.value
    assert closure["child_result_sha256s"] == [result["entry_sha256"] for result in child_results]
    assert closure["nested_family_closure_sha256s"] == []
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )

    recovery_transport_ids = tuple(
        logical_request_id
        for request in fake.requests
        if isinstance(metadata := request.get("metadata"), dict)
        and isinstance(logical_request_id := metadata.get("mmaudit_request_id"), str)
        and logical_request_id.startswith("scheduler-recovery-request-")
    )
    assert recovery_transport_ids == tuple(
        child["child_logical_request_id"] for child in root["recovery_plan"]["children"]
    )
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-truncated-parent" not in first_inventory[0]
    assert b"scheduler-recovery-request-" not in first_inventory[1]
    first_ledger = ledger.snapshot()
    recovery_ledger_entries = tuple(
        entry for entry in first_ledger.entries if entry.request_id in set(recovery_transport_ids)
    )
    assert len(recovery_ledger_entries) == 2
    assert all(
        entry.actual_cost_usd == entry.accounted_cost_usd == Decimal("0.001")
        and entry.accounted_cost_usd <= entry.reserved_usd
        for entry in recovery_ledger_entries
    )

    resumed_fake = FakeOpenRouter(mode="truncation_recovery_recursive")
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
    _assert_resume_retains_exact_scheduler_journal(
        owner=first.run_dir,
        consumer=resumed.run_dir,
    )
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory
    assert ledger.snapshot() == first_ledger


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
async def test_mock_specialist_truncation_recovers_without_credit_and_resumes_zero_transport(
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
    assert fake.recovery_child_calls == 2
    parent = _truncated_parent_attempt(first.run_dir)
    assert parent["usage_record"]["role"] == "specialist:access_control"
    assert [finding["candidate_id"] for finding in parent["truncation_projection"]["findings"]] == [
        "raw-specialist-retained"
    ]
    entries = _recovery_entries(first.run_dir)
    family_roots = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT.value
    )
    activations = tuple(
        entry
        for entry in entries
        if entry["entry_kind"] == SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED.value
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
    assert len(activations) == len(child_results) == 2
    assert closures[0]["closure_status"] == (
        SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED.value
    )
    assert all(
        entry["entry_kind"] != SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED.value
        for entry in entries
    )
    assert {
        family_roots[0]["request_limit_binding"]["parent_request_limit_reservation"]["role"],
        *(entry["request_role"] for entry in activations),
        *(entry["runtime_usage_record"]["role"] for entry in child_results),
        *(
            entry["runtime_usage_record"]["routing"]["context_request_evidence"]["request_role"]
            for entry in child_results
        ),
        *(
            entry["runtime_usage_record"]["routing"]["context_request_evidence"]["context_role"]
            for entry in child_results
        ),
    } == {"specialist:access_control"}
    assert all(
        entry["child_logical_request_id"].startswith("scheduler-recovery-request-")
        for entry in activations
    )
    assert [
        (
            entry["runtime_usage_record"]["attempts"],
            entry["runtime_usage_record"]["retry_count"],
            entry["runtime_request_limit_reservation"]["request_limit_count_before"],
            entry["runtime_request_limit_reservation"]["request_limit_count_after"],
        )
        for entry in child_results
    ] == [(1, 0, 1, 2), (1, 0, 2, 3)]
    parent_request_id = parent["usage_record"]["request_id"]
    assert {
        entry["runtime_request_limit_reservation"]["request_limit_scope"] for entry in child_results
    } == {parent_request_id}
    assert all(
        Decimal(entry["accounted_cost_usd_exact"])
        == Decimal(entry["runtime_usage_record"]["accounted_cost_usd_exact"])
        == Decimal("0.001")
        and Decimal(entry["accounted_cost_usd_exact"]) <= Decimal(entry["reserved_usd_exact"])
        for entry in child_results
    )
    assert all(
        entry["terminal_status"] == SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED.value
        and entry["runtime_usage_record"]["execution_evidence"] == ExecutionEvidenceKind.MOCK.value
        for entry in child_results
    )
    for entry in child_results:
        usage = entry["runtime_usage_record"]
        context_evidence = usage["routing"]["context_request_evidence"]
        output_artifact = entry["runtime_output_artifact"]
        outcome = SpecialistAcceptedOutcome.model_validate_json(
            json.dumps(entry["runtime_specialist_accepted_outcome"]),
            strict=True,
        )
        assert entry["schema_version"] == "1.2"
        assert outcome.outcome_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
        assert outcome.request_id == entry["child_logical_request_id"] == usage["request_id"]
        assert outcome.request_role == entry["runtime_activation"]["request_role"] == usage["role"]
        assert outcome.specialist_role == "access_control"
        assert outcome.context_request_evidence_sha256 == context_evidence["evidence_sha256"]
        assert (
            outcome.context_request_evidence_sha256
            == usage["routing"]["context_request_evidence_sha256"]
        )
        assert outcome.validated_response_sha256 == usage["validated_response_sha256"]
        assert (
            outcome.surface_review_artifact_sha256
            == entry["runtime_output_artifact_sha256"]
            == output_artifact["artifact_sha256"]
        )
        assert (
            outcome.requested_surface_count
            == len(entry["runtime_requested_surface_requests"])
            == len(entry["child_surface_ids"])
        )
        assert entry["runtime_specialist_accepted_outcome_sha256"] == outcome.evidence_sha256
    first_inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"raw-specialist-retained" not in first_inventory[0]
    assert b"scheduler-recovery-request-" not in first_inventory[1]
    specialist_execution = (first.run_dir / "specialist-execution.json").read_bytes()
    access_control = next(
        record
        for record in json.loads(specialist_execution)["records"]
        if record["role"] == "access_control"
    )
    assert access_control["status"] == "failed"
    assert access_control["successful_requests"] == 0
    assert access_control["source_review_creditable_requests"] == 0
    assert access_control["accepted_outcomes"] == []
    assert set(access_control["failed_request_ids"]) == {
        parent_request_id,
        *(entry["child_logical_request_id"] for entry in activations),
    }
    first_ledger = ledger.snapshot()

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
    assert _recovery_entries(first.run_dir) == entries
    assert _candidate_and_surface_inventory(resumed.run_dir) == first_inventory
    assert (resumed.run_dir / "specialist-execution.json").read_bytes() == specialist_execution
    assert ledger.snapshot() == first_ledger
