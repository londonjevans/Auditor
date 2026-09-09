"""Whole-run and custody regressions using only synthetic local transports and disposable controls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import socket
import subprocess
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.orchestration.development_corpus as candidate_runner
import mmaudit.orchestration.development_corpus_ensemble as parent_runner
import mmaudit.orchestration.development_corpus_judgment as review_runner
from mmaudit.benchmark.development_corpus_ensemble import DevelopmentCorpusEnsembleScore
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import selected_policy
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    retained,
)

STAGES = ("candidate", "review-01", "review-02")


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble boundary control attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def wrap_children(monkeypatch, wrapper):
    """Wrap the real child entrypoints, never replace response validation or accounting."""

    for name in ("run_development_corpus", "run_development_corpus_judgment"):
        original = getattr(parent_runner, name)

        async def execute_child(_original=original, **kwargs):
            return await wrapper(_original, kwargs)

        monkeypatch.setattr(parent_runner, name, execute_child)


def offset_clock(monkeypatch):
    """Advance only orchestration clocks; preserve real elapsed time and the event-loop clock."""

    advance = [0.0]
    clock = SimpleNamespace(monotonic=lambda: time.monotonic() + advance[0])
    for module in (parent_runner, candidate_runner, review_runner):
        monkeypatch.setattr(module, "time", clock)
    return advance


@pytest.mark.asyncio
async def test_all_child_stages_receive_the_same_absolute_deadline_and_remaining_plan_budget(
    tmp_path, monkeypatch
):
    case = execution_case(tmp_path)
    advance = offset_clock(monkeypatch)
    captured = []

    async def wrapper(original, kwargs):
        captured.append((kwargs["parent_deadline"], kwargs["prepared"].plan.maximum_run_seconds))
        result = await original(**kwargs)
        advance[0] += 100.0
        return result

    wrap_children(monkeypatch, wrapper)
    result = await execute(case)
    assert result.status == "OBSERVED_ALL_STAGES" and case.counts == [6, 3, 3]
    assert len(captured) == 3 and len({deadline for deadline, _ in captured}) == 1
    assert captured[0][1] == case.prepared.plan.maximum_run_seconds == 600
    assert 0 < captured[2][1] < captured[1][1] < 500
    assert result.elapsed_seconds >= 300
    assert result.total_accounted_cost_usd == Decimal("0.12")


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
async def test_actual_whole_run_timeout_preserves_the_unreturned_stage_charge(tmp_path, stage):
    case = execution_case(tmp_path, prepared=manifest_ensemble_case(maximum_run_seconds=2.0))

    async def stalled(role, ordinal, _request):
        if role == stage and ordinal == 1:
            await asyncio.Event().wait()

    result = await asyncio.wait_for(execute(case, custom=stalled), timeout=8)
    assert case.counts == ([1, 0, 0], [6, 1, 0], [6, 3, 1])[stage]
    assert result == retained(case) and result.status == "INCOMPLETE"
    assert result.stop_reason == "LOCAL_FAILURE"
    assert result.accounting[-1].entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert result.elapsed_seconds >= 2 and not result.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
async def test_expiry_after_durable_child_stops_before_any_next_stage(tmp_path, monkeypatch, stage):
    case = execution_case(tmp_path)
    advance = offset_clock(monkeypatch)

    async def wrapper(original, kwargs):
        child = await original(**kwargs)
        if kwargs["output_dir"].name == STAGES[stage]:
            advance[0] += 601.0
        return child

    wrap_children(monkeypatch, wrapper)
    result = await execute(case)
    assert case.counts == ([6, 0, 0], [6, 3, 0], [6, 3, 3])[stage]
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert result.candidate.completed_shard_count == 6 and len(result.judgments) == stage
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd


@pytest.mark.asyncio
async def test_review_preparation_cannot_reset_an_expired_parent_deadline(tmp_path, monkeypatch):
    case = execution_case(tmp_path)
    advance = offset_clock(monkeypatch)
    prepare = parent_runner.prepare_development_corpus_judgment

    def delayed_preparation(**kwargs):
        prepared = prepare(**kwargs)
        advance[0] += 601.0
        return prepared

    monkeypatch.setattr(parent_runner, "prepare_development_corpus_judgment", delayed_preparation)
    result = await execute(case)
    assert case.counts == [6, 0, 0]
    assert result.status == "INCOMPLETE" and len(result.judgments) == 1
    assert result.judgments[0].observations == () and result.completed_judgment_count == 0
    assert result.total_accounted_cost_usd == Decimal("0.06")


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("deadline", [False, 0.0, -1.0, float("nan"), float("inf"), 600, 1.0])
async def test_invalid_or_expired_absolute_deadline_handoff_cannot_dispatch(
    tmp_path, monkeypatch, stage, deadline
):
    case = execution_case(tmp_path)

    async def wrapper(original, kwargs):
        if kwargs["output_dir"].name == STAGES[stage]:
            kwargs["parent_deadline"] = deadline
        return await original(**kwargs)

    wrap_children(monkeypatch, wrapper)
    result = await execute(case)
    assert case.counts == ([0, 0, 0], [6, 0, 0], [6, 3, 0])[stage]
    assert (
        result.status == "INCOMPLETE"
        and result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    )
    assert not result.audit_complete


@pytest.mark.asyncio
async def test_candidate_score_write_failure_keeps_durable_original_candidate_and_parent_measurement(
    tmp_path, monkeypatch
):
    case = execution_case(tmp_path)

    def refuse_score(_root, _score):
        raise ValueError("synthetic derivative write refusal")

    monkeypatch.setattr(candidate_runner, "_write_score", refuse_score)
    result = await execute(case)
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert result.candidate.completed_shard_count == 6 and case.counts == [6, 0, 0]
    assert not (case.root / "candidate/score.json").exists()
    score = DevelopmentCorpusEnsembleScore.model_validate_json(
        (case.root / "score.json").read_bytes(), strict=True
    )
    assert score.candidate_score.observation == result.candidate
    assert result.total_accounted_cost_usd == Decimal("0.06")


@pytest.mark.asyncio
async def test_parent_score_write_failure_is_not_returned_as_a_success(tmp_path, monkeypatch):
    case = execution_case(tmp_path)
    original_write = parent_runner._write

    def refuse_score(root, name, model, **kwargs):
        if name == "score.json":
            raise ValueError("synthetic composed score write refusal")
        return original_write(root, name, model, **kwargs)

    monkeypatch.setattr(parent_runner, "_write", refuse_score)
    with pytest.raises(ValueError, match="could not be finalized"):
        await execute(case)
    observation = retained(case)
    assert case.counts == [6, 3, 3] and observation.total_accounted_cost_usd == Decimal("0.12")
    assert not (case.root / "score.json").exists() and not observation.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("kind", ["short_upstream", "reordered_upstream", "short_output"])
async def test_child_custody_requires_the_complete_ordered_ancestor_chain(
    tmp_path, monkeypatch, stage, kind
):
    case = execution_case(tmp_path)

    def weaken(directory):
        components = directory.component_identities
        changed = (
            components[-1:]
            if kind != "reordered_upstream"
            else (*reversed(components[:-1]), components[-1])
        )
        return replace(directory, component_identities=changed)

    async def wrapper(original, kwargs):
        if kwargs["output_dir"].name == STAGES[stage]:
            if kind == "short_output":
                kwargs["output_custody"] = weaken(kwargs["output_custody"])
            elif stage == 0:
                bundle = kwargs["upstream"]
                kwargs["upstream"] = replace(bundle, directory=weaken(bundle.directory))
            else:
                bundle = kwargs["upstream"]
                kwargs["upstream"] = replace(
                    bundle, directories=tuple(weaken(d) for d in bundle.directories)
                )
        return await original(**kwargs)

    wrap_children(monkeypatch, wrapper)
    result = await execute(case)
    assert case.counts == ([0, 0, 0], [6, 0, 0], [6, 3, 0])[stage]
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("kind", ["replacement", "link", "permissions"])
async def test_active_child_directory_drift_stops_without_adopting_a_replacement(
    tmp_path, stage, kind
):
    case = execution_case(tmp_path)

    def drift(role, ordinal, _request):
        if role != stage or ordinal != 1:
            return None
        original = case.root / STAGES[stage]
        if kind == "permissions":
            original.chmod(0o755)
        else:
            preserved = case.root / (STAGES[stage] + "-preserved")
            original.rename(preserved)
            if kind == "link":
                original.symlink_to(preserved, target_is_directory=True)
            else:
                shutil.copytree(preserved, original)

    with pytest.raises(ValueError):
        await execute(case, custom=drift)
    assert case.counts == ([1, 0, 0], [6, 1, 0], [6, 3, 1])[stage]
    assert not (case.root / "result.json").exists()
    assert len(case.ledger.snapshot().entries) == sum(case.counts)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("when", ["before_execution", "after_result", "missing_result"])
async def test_local_child_failure_recovers_only_the_durable_original_result(
    tmp_path, monkeypatch, stage, when
):
    case = execution_case(tmp_path)
    original_child = []

    async def wrapper(original, kwargs):
        selected = kwargs["output_dir"].name == STAGES[stage]
        if selected and when == "before_execution":
            raise ValueError("synthetic pre-dispatch local failure")
        child = await original(**kwargs)
        if selected:
            original_child.append(child)
            if when == "missing_result":
                (kwargs["output_dir"] / "result.json").unlink()
            raise ValueError("synthetic post-observation local failure")
        return child

    wrap_children(monkeypatch, wrapper)
    result = await execute(case)
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert (
        case.counts
        == (
            ([0, 0, 0], [6, 0, 0], [6, 3, 0])
            if when == "before_execution"
            else ([6, 0, 0], [6, 3, 0], [6, 3, 3])
        )[stage]
    )
    recovered = (
        result.candidate
        if stage == 0
        else result.judgments[stage - 1]
        if len(result.judgments) >= stage
        else None
    )
    assert recovered == (original_child[0] if when == "after_result" else None)
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    if stage == 0 and when != "after_result":
        assert result.claims == () and len(result.unobserved_candidate_shard_ids) == 6
    score = DevelopmentCorpusEnsembleScore.model_validate_json(
        (case.root / "score.json").read_bytes(), strict=True
    )
    assert score.observation == result and not score.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("per_attempt", ["4", "5"])
async def test_realistic_19_file_source_snapshot_executes_all_three_stages_without_truth_invention(
    tmp_path,
    per_attempt,
):
    root = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    manifest = json.loads((root / "fixture-manifest.json").read_bytes())
    records = tuple(row for row in manifest["files"] if row["path"].endswith(".sol"))
    expected_names = tuple(
        sorted(
            (
                *(
                    "src/core/" + name
                    for name in (
                        "Interfaces.sol",
                        "ProtocolRegistry.sol",
                        "SyntheticFixtureOnly.sol",
                        "SyntheticProxies.sol",
                    )
                ),
                *(f"src/markets/SyntheticMarket{index:03d}.sol" for index in range(15)),
            )
        )
    )
    assert tuple(row["path"] for row in records) == expected_names
    sources = tuple((row["path"], (root / row["path"]).read_bytes()) for row in records)
    assert len(sources) == 19 and sum(len(raw) for _, raw in sources) == 175158
    assert sum(len(raw.decode().splitlines()) for _, raw in sources) == 4952
    assert all(
        hashlib.sha256(raw).hexdigest() == row["sha256"]
        for (_, raw), row in zip(sources, records, strict=True)
    )
    if per_attempt == "5":
        with pytest.raises(ValueError, match="250"):
            manifest_ensemble_case(
                source_files=sources, policy=selected_policy(total="250", per_attempt=per_attempt)
            )
        assert not (tmp_path / "run").exists()
        return
    case = execution_case(
        tmp_path,
        prepared=manifest_ensemble_case(
            source_files=sources, policy=selected_policy(total="250", per_attempt=per_attempt)
        ),
        scored=False,
    )
    result = await execute(case)
    assert result.status == "OBSERVED_ALL_STAGES" and case.counts == [19, 19, 19]
    assert len(result.claims) == 19 and result.completed_judgment_count == 38
    assert len(result.accounting) == 57 and result.total_accounted_cost_usd == Decimal("0.57")
    for stage in ("", *STAGES):
        material = DevelopmentCorpusMaterial.model_validate_json(
            (case.root / stage / "sources.json").read_bytes()
        )
        assert material.source_files == sources
    assert not (case.root / "benchmark-plan.json").exists()
    assert not (case.root / "score.json").exists()
    assert not result.audit_complete and not result.qualification_eligible
