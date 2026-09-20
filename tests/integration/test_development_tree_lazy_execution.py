"""Every original slot remains scheduled while only needed bundles are materialized."""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest

from mmaudit.orchestration import development_tree as module
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
async def test_stage_pause_does_not_prepare_future_bundles_or_drop_their_coverage(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    first = await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    cases = arguments["output_dir"] / "cases"
    assert {p.name for p in cases.iterdir()} == {"case-0001"}
    assert len(first.primary_statuses) == len(arguments["loaded"].plan.primaries) == 5
    assert all(p.status == "PENDING" for p in first.primary_statuses[1:])
    assert len(first.coverage.unselected_paths) == 4
    original = (cases / "case-0001/run/candidate/result.json").read_bytes()
    arguments["loaded"] = reopen(inputs)
    resumed = await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=3
    )
    assert {p.name for p in cases.iterdir()} == {"case-0001", "case-0002"}
    assert [role for _, role, _ in calls] == [0, 1, 2, 0]
    assert len(resumed.primary_statuses) == 5
    assert resumed.primary_statuses[0].status == "OBSERVED_ALL_STAGES"
    assert resumed.primary_statuses[1].status == "REVIEW_INCOMPLETE"
    assert all(p.status == "PENDING" for p in resumed.primary_statuses[2:])
    assert (cases / "case-0001/run/candidate/result.json").read_bytes() == original
    assert resumed.completed_attempt_count == 4
    assert arguments["ledger"].snapshot().spent_usd == Decimal("0.04")
    assert not resumed.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("drift", [False, True])
async def test_eager_legacy_bundles_are_all_replayed_before_any_resumed_call(tmp_path, drift):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    root = arguments["output_dir"]
    # The predecessor prepared all five bundles before the first candidate. Reproduce that
    # exact existing bundle/run format using the original materializer and preparer.
    for index in range(2, 6):
        module._prepare_case(arguments["loaded"], root, index, resume=False, mock=True)
    before = arguments["ledger"].snapshot()
    if drift:
        path = root / "cases/case-0005/bundle/manifest.json"
        path.write_bytes(path.read_bytes() + b"\n")
        # Whitespace alone has no serialized binding before reopening; change a source byte too.
        primary = arguments["loaded"].plan.primaries[4].primary_filename
        source = root / "cases/case-0005/bundle/source" / primary
        source.write_bytes(source.read_bytes() + b"\n")
    arguments["loaded"] = reopen(inputs)
    if drift:
        with pytest.raises(ValueError):
            await module.run_development_tree_plan(
                **arguments, resume=True, maximum_stages_per_invocation=1
            )
        assert len(calls) == 1 and arguments["ledger"].snapshot() == before
    else:
        progress = await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=2
        )
        assert len(calls) == progress.completed_attempt_count == 3
        assert all(row in arguments["ledger"].snapshot().entries for row in before.entries)
        assert len(progress.primary_statuses) == 5 and progress.status == "INCOMPLETE"


@pytest.mark.asyncio
async def test_unexpected_future_bundle_during_a_request_cannot_be_silently_adopted(tmp_path):
    _, arguments, calls = execution(tmp_path)
    original = arguments["mock_transport"]

    def introduce_future_output(request):
        response = original.handle_request(request)
        (arguments["output_dir"] / "cases/case-0002").mkdir(mode=0o700)
        return response

    arguments["mock_transport"] = httpx.MockTransport(introduce_future_output)
    with pytest.raises(ValueError, match="unstarted case"):
        await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    snapshot = arguments["ledger"].snapshot()
    assert len(calls) == len(snapshot.entries) == 1
    assert snapshot.entries[0].status is CostEntryStatus.RECONCILED
    assert snapshot.spent_usd == Decimal("0.01")
    assert not (arguments["output_dir"] / "cases/case-0001/run/candidate-end.json").exists()


@pytest.mark.asyncio
async def test_each_reviewer_marker_binds_one_actual_preparation_not_a_second_rebuild(
    tmp_path, monkeypatch
):
    _, arguments, calls = execution(tmp_path)
    original_review = module._review
    prepared = []

    def review(case, index):
        result = original_review(case, index)
        prepared.append((case.index, index, result.plan))
        return result

    monkeypatch.setattr(module, "_review", review)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=3)
    assert [role for _, role, _ in calls] == [0, 1, 2]
    assert [(case, index) for case, index, _ in prepared] == [(1, 1), (1, 2)]
    for _, index, plan in prepared:
        root = arguments["output_dir"] / "cases/case-0001/run"
        from mmaudit.models.development_tree_execution import DevelopmentTreeStageStart

        start = DevelopmentTreeStageStart.model_validate_json(
            (root / f"review-0{index}-start.json").read_bytes(), strict=True
        )
        assert start.child_plan_sha256 == plan.plan_sha256
        assert start.request_id == plan.shards[0].estimate.request_id


@pytest.mark.asyncio
async def test_uncertain_billing_stops_before_materializing_a_future_bundle(tmp_path):
    _, arguments, _ = execution(tmp_path)
    calls = []

    def rejected(request):
        calls.append(request)
        return httpx.Response(429, json={"error": {"code": 429, "message": "synthetic refusal"}})

    arguments["mock_transport"] = httpx.MockTransport(rejected)
    with pytest.raises(ValueError, match="uncertain billing"):
        await module.run_development_tree_plan(**arguments)
    snapshot = arguments["ledger"].snapshot()
    assert len(calls) == len(snapshot.entries) == 1
    assert snapshot.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert snapshot.entries[0].actual_cost_usd is None
    assert snapshot.entries[0].accounted_cost_usd == snapshot.entries[0].reserved_usd
    assert {p.name for p in (arguments["output_dir"] / "cases").iterdir()} == {"case-0001"}
