"""Durable original-tree progress and checkpoint custody through real MockTransport consumers."""

from __future__ import annotations

import asyncio
import json
import os
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_tree_execution import DevelopmentTreeExecutionProgress
from mmaudit.orchestration import development_tree as module
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


def progress(arguments, count):
    return DevelopmentTreeExecutionProgress.model_validate_json(
        (arguments["output_dir"] / f"progress-{count:04d}.json").read_bytes(), strict=True
    )


@pytest.mark.asyncio
async def test_initial_progress_exists_before_the_first_request(tmp_path):
    _, arguments, calls = execution(tmp_path)
    original = arguments["mock_transport"]

    def handler(request):
        checkpoint = progress(arguments, 0)
        assert len(checkpoint.primary_statuses) == 5
        assert all(row.status == "PENDING" for row in checkpoint.primary_statuses)
        assert checkpoint.completed_attempt_count == checkpoint.total_accounted_cost_usd == 0
        assert not checkpoint.audit_complete
        return original.handle_request(request)

    arguments["mock_transport"] = httpx.MockTransport(handler)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert len(calls) == progress(arguments, 1).completed_attempt_count == 1


@pytest.mark.asyncio
async def test_cancel_after_durable_child_persists_closed_tree_progress(tmp_path, monkeypatch):
    _, arguments, calls = execution(tmp_path)
    original = module.run_development_corpus

    async def cancel_after_result(**kwargs):
        await original(**kwargs)
        raise asyncio.CancelledError

    monkeypatch.setattr(module, "run_development_corpus", cancel_after_result)
    with pytest.raises(asyncio.CancelledError):
        await module.run_development_tree_plan(**arguments)
    checkpoint = progress(arguments, 1)
    assert len(calls) == checkpoint.completed_attempt_count == 1
    assert checkpoint.primary_statuses[0].status == "REVIEW_INCOMPLETE"
    assert all(row.status == "PENDING" for row in checkpoint.primary_statuses[1:])
    assert checkpoint.total_accounted_cost_usd == Decimal("0.01")
    assert checkpoint.reported_actual_cost_usd == Decimal("0.01")
    assert checkpoint.status == "INCOMPLETE" and not checkpoint.audit_complete
    assert (arguments["output_dir"] / "coverage-0001.json").is_file()


@pytest.mark.asyncio
async def test_uncertain_billing_stop_keeps_full_tree_progress_and_original_charge(tmp_path):
    _, arguments, _ = execution(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, json={"error": {"message": "synthetic rejection"}})

    arguments["mock_transport"] = httpx.MockTransport(handler)
    with pytest.raises(ValueError, match="uncertain billing"):
        await module.run_development_tree_plan(**arguments)
    checkpoint = progress(arguments, 1)
    row = arguments["ledger"].snapshot().entries[0]
    assert len(calls) == checkpoint.completed_attempt_count == 1
    assert row.status is CostEntryStatus.UNCERTAIN_ACCOUNTED and row.actual_cost_usd is None
    assert checkpoint.uncertain_accounted_cost_usd == row.accounted_cost_usd == row.reserved_usd
    assert checkpoint.reported_actual_cost_usd == 0 and checkpoint.status == "INCOMPLETE"
    assert checkpoint.primary_statuses[0].status == "CANDIDATE_INCOMPLETE"
    assert all(p.status == "PENDING" for p in checkpoint.primary_statuses[1:])
    assert not (arguments["output_dir"] / "cases/case-0002").exists()


@pytest.mark.asyncio
async def test_source_drift_cannot_advance_the_last_closed_checkpoint(tmp_path, monkeypatch):
    _, arguments, calls = execution(tmp_path)
    original = module.run_development_corpus
    plan_file = arguments["loaded"].directory.path / "plan.json"

    async def change_after_result(**kwargs):
        record = await original(**kwargs)
        plan_file.write_bytes(plan_file.read_bytes() + b"\n")
        return record

    monkeypatch.setattr(module, "run_development_corpus", change_after_result)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(**arguments)
    assert progress(arguments, 0).completed_attempt_count == 0
    assert not (arguments["output_dir"] / "progress-0001.json").exists()
    assert len(calls) == len(arguments["ledger"].snapshot().entries) == 1
    assert arguments["ledger"].snapshot().entries[0].actual_cost_usd == Decimal("0.01")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["later_prefix", "wrong_plan", "cost", "elapsed", "bool_count", "coverage"]
)
async def test_older_checkpoint_tampering_refuses_before_new_dispatch(tmp_path, change):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    arguments["loaded"] = reopen(inputs)
    await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=1
    )
    root = arguments["output_dir"]
    path = root / ("coverage-0001.json" if change == "coverage" else "progress-0001.json")
    value = json.loads(path.read_bytes())
    if change == "later_prefix":
        value = json.loads((root / "progress-0002.json").read_bytes())
    elif change == "wrong_plan":
        value["tree_plan_sha256"] = "f" * 64
    elif change == "cost":
        value["total_accounted_cost_usd"] = value["reported_actual_cost_usd"] = "0.02"
    elif change == "elapsed":
        value["elapsed_active_seconds"] += 1.0
        value["primary_statuses"][0]["elapsed_seconds"] += 1.0
    elif change == "bool_count":
        value["completed_attempt_count"] = True
        value["primary_statuses"][0]["completed_attempt_count"] = True
    else:
        value["coverage_sha256"] = "f" * 64
    path.write_text(json.dumps(value))
    snapshot = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    assert len(calls) == 2 and arguments["ledger"].snapshot() == snapshot


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["content", "same_bytes_inode", "deletion", "future_entry"])
async def test_checkpoint_custody_lives_through_a_later_request(tmp_path, change):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    root = arguments["output_dir"]
    path = root / "progress-0001.json"
    original = arguments["mock_transport"]
    retained = path.read_bytes()

    def handler(request):
        if change == "content":
            path.write_bytes(retained + b"\n")
        elif change == "future_entry":
            (root / "progress-0123.json").write_text("{}")
        else:
            path.rename(tmp_path / "retained-original-checkpoint.json")
            if change == "same_bytes_inode":
                path.write_bytes(retained)
                path.chmod(0o600)
        return original.handle_request(request)

    before = arguments["ledger"].snapshot().entries
    arguments["mock_transport"] = httpx.MockTransport(handler)
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    entries = arguments["ledger"].snapshot().entries
    assert len(calls) == len(entries) == 2
    assert all(entry in entries for entry in before)
    assert not (root / "progress-0002.json").exists()
    assert not (root / "cases/case-0001/run/review-01-end.json").exists()


@pytest.mark.asyncio
async def test_sparse_legacy_checkpoints_preserve_retained_bytes_and_original_charges(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    arguments["loaded"] = reopen(inputs)
    await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=2
    )
    root = arguments["output_dir"]
    retained = {
        name: (root / name).read_bytes()
        for name in (
            "progress-0001.json",
            "coverage-0001.json",
            "progress-0003.json",
            "coverage-0003.json",
        )
    }
    for count in (0, 2):
        path = root / f"progress-{count:04d}.json"
        if path.exists():
            path.rename(tmp_path / f"removed-checkpoint-{count}.json")
    before = arguments["ledger"].snapshot().entries
    arguments["loaded"] = reopen(inputs)
    await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=1
    )
    assert len(calls) == 4
    assert all((root / name).read_bytes() == content for name, content in retained.items())
    assert all(entry in arguments["ledger"].snapshot().entries for entry in before)
    assert progress(arguments, 4).completed_attempt_count == 4


@pytest.mark.asyncio
async def test_successful_stages_do_not_duplicate_full_source_coverage(tmp_path):
    _, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=3)
    root = arguments["output_dir"]
    assert len(calls) == 3
    assert all((root / f"progress-{count:04d}.json").is_file() for count in range(4))
    assert (root / "coverage-0003.json").is_file()
    assert not any((root / f"coverage-{count:04d}.json").exists() for count in range(3))


@pytest.mark.asyncio
async def test_future_closed_prefix_refuses_before_resumed_dispatch(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    root = arguments["output_dir"]
    (root / "progress-0123.json").write_bytes((root / "progress-0001.json").read_bytes())
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="prefix"):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
async def test_checkpoint_requires_original_unshared_regular_file_custody(tmp_path, kind):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    path = arguments["output_dir"] / "progress-0001.json"
    original = tmp_path / "retained-checkpoint.json"
    path.rename(original)
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, path)
    else:
        path.mkdir(mode=0o700)
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
async def test_actual_checkpoint_namespace_bound_refuses_before_resumed_dispatch(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    monkeypatch.setattr(module, "_MAX_CHECKPOINT_ROOT_ENTRIES", 4)
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="checkpoint namespace exceeds"):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
async def test_checkpoint_write_failure_recovers_closed_work_without_repeating_it(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    original = module._model_file
    injected = False

    def fail_once(root, name, model, *, create):
        nonlocal injected
        if name == "progress-0001.json" and create and not injected:
            injected = True
            raise OSError("synthetic checkpoint write failure")
        return original(root, name, model, create=create)

    monkeypatch.setattr(module, "_model_file", fail_once)
    with pytest.raises(OSError, match="synthetic checkpoint"):
        await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    root = arguments["output_dir"]
    before = arguments["ledger"].snapshot().entries
    candidate = (root / "cases/case-0001/run/candidate/result.json").read_bytes()
    arguments["loaded"] = reopen(inputs)
    await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=1
    )
    assert len(calls) == 2 and progress(arguments, 1).completed_attempt_count == 1
    assert (root / "cases/case-0001/run/candidate/result.json").read_bytes() == candidate
    assert all(entry in arguments["ledger"].snapshot().entries for entry in before)
