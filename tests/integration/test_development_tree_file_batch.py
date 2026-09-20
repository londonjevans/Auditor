"""Real mock controller/restart retains file custody and all known billing liabilities."""

from __future__ import annotations

import os
from decimal import Decimal

import httpx
import pytest

from mmaudit.orchestration import development_tree as controller
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
async def test_batch_custody_reaches_every_primary_and_reviewer_across_cold_restart(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    original = controller.require_regular_file_custody_batch_unchanged
    batches = []

    def checked(files, **kwargs):
        batches.append(tuple((file.root, file.binding.path) for file in files))
        return original(files, **kwargs)

    monkeypatch.setattr(controller, "require_regular_file_custody_batch_unchanged", checked)
    paused = await controller.run_development_tree_plan(
        **arguments, maximum_stages_per_invocation=3
    )
    assert paused.completed_attempt_count == len(calls) == 3
    root = arguments["output_dir"]
    names = (
        "plan.json",
        "progress-0001.json",
        "coverage-0003.json",
        "cases/case-0001/run/candidate/result.json",
    )
    retained = {name: (root / name).read_bytes() for name in names}
    charged = arguments["ledger"].snapshot().entries
    prior_batches = len(batches)
    arguments["loaded"] = reopen(inputs)
    final = await controller.run_development_tree_plan(**arguments, resume=True)
    assert len(batches) > prior_batches and max(map(len, batches)) == 22
    assert final.completed_attempt_count == len(calls) == 15
    assert all(row.status == "OBSERVED_ALL_STAGES" for row in final.primary_statuses)
    assert final.coverage.successful_primary_paths == tuple(
        primary.primary_filename for primary in arguments["loaded"].plan.primaries
    )
    assert final.coverage.not_successfully_observed_paths == ()
    assert retained == {name: (root / name).read_bytes() for name in names}
    snapshot = arguments["ledger"].snapshot()
    assert all(row in snapshot.entries for row in charged)
    assert len(snapshot.entries) == len({row.request_id for row in snapshot.entries}) == 15
    assert snapshot.spent_usd == final.reported_actual_cost_usd == Decimal("0.15")
    assert snapshot.active_reserved_usd == final.active_reserved_usd == 0
    assert not final.audit_complete and not final.qualification_eligible
    assert not final.release_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["bytes", "inode", "symlink", "hardlink"])
async def test_batch_refuses_retained_candidate_drift_during_reviewer_and_keeps_charges(
    tmp_path, monkeypatch, change
):
    _, arguments, calls = execution(tmp_path)
    path = arguments["output_dir"] / "cases/case-0001/run/candidate/result.json"
    transport = arguments["mock_transport"]
    original = controller.require_regular_file_custody_batch_unchanged
    refused = []

    def checked(files, **kwargs):
        try:
            return original(files, **kwargs)
        except ValueError:
            refused.extend(file.root / file.binding.path for file in files)
            raise

    def handler(request):
        if len(calls) == 1:
            content = path.read_bytes()
            if change == "bytes":
                path.write_bytes(content + b"\n")
            elif change == "hardlink":
                os.link(path, path.with_suffix(".synthetic-linked"))
            else:
                retained = path.with_suffix(".synthetic-retained")
                path.rename(retained)
                if change == "inode":
                    path.write_bytes(content)
                else:
                    path.symlink_to(retained)
        return transport.handle_request(request)

    monkeypatch.setattr(controller, "require_regular_file_custody_batch_unchanged", checked)
    arguments["mock_transport"] = httpx.MockTransport(handler)
    with pytest.raises(ValueError):
        await controller.run_development_tree_plan(**arguments, maximum_stages_per_invocation=3)
    assert path in refused
    assert len(calls) == 2
    snapshot = arguments["ledger"].snapshot()
    assert len(snapshot.entries) == 2 and snapshot.spent_usd == Decimal("0.02")
    assert snapshot.active_reserved_usd == 0
    assert not (arguments["output_dir"] / "progress-0002.json").exists()
