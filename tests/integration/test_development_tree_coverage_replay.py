"""Repeated review checkpoints reuse pure coverage, never live source or ledger guards."""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_corpus_coverage import read_development_corpus_coverage
from mmaudit.orchestration import development_tree as module
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
async def test_review_checkpoints_share_only_exact_pure_coverage_within_one_invocation(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    compute = module.compute_development_corpus_coverage
    populations = []

    def counted(**kwargs):
        populations.append(len(kwargs["records"]))
        return compute(**kwargs)

    monkeypatch.setattr(module, "compute_development_corpus_coverage", counted)
    first = await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=3)
    assert populations == [0, 1]
    assert len(calls) == first.completed_attempt_count == 3
    assert first.primary_statuses[0].status == "OBSERVED_ALL_STAGES"
    assert all(p.status == "PENDING" for p in first.primary_statuses[1:])
    coverage_path = arguments["output_dir"] / "coverage-0003.json"
    retained = coverage_path.read_bytes()
    coverage = read_development_corpus_coverage(retained)
    assert (
        compute(
            reference=coverage.reference,
            records=coverage.records,
            partitions=coverage.partitions,
        ).model_dump_json()
        == coverage.model_dump_json()
    )
    assert coverage.summary == first.coverage
    charged = arguments["ledger"].snapshot().entries
    populations.clear()
    arguments["loaded"] = reopen(inputs)
    second = await module.run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=1
    )
    assert populations == [0, 1, 2]
    assert len(calls) == second.completed_attempt_count == 4
    assert coverage_path.read_bytes() == retained
    snapshot = arguments["ledger"].snapshot()
    assert all(row in snapshot.entries for row in charged)
    assert snapshot.spent_usd == Decimal("0.04")
    assert snapshot.active_reserved_usd == 0
    assert not second.audit_complete and not second.qualification_eligible
    assert not second.release_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["source", "checkpoint"])
async def test_warm_pure_coverage_never_replaces_live_custody_during_review(
    tmp_path, monkeypatch, changed
):
    _, arguments, calls = execution(tmp_path)
    compute = module.compute_development_corpus_coverage
    populations = []

    def counted(**kwargs):
        populations.append(len(kwargs["records"]))
        return compute(**kwargs)

    monkeypatch.setattr(module, "compute_development_corpus_coverage", counted)
    transport = arguments["mock_transport"]

    def handler(request):
        if len(calls) == 1:
            assert populations == [0, 1]
            path = (
                arguments["loaded"].reference.corpus_root
                / arguments["loaded"].plan.reference.manifest.sources[0].filename
                if changed == "source"
                else arguments["output_dir"] / "progress-0001.json"
            )
            path.write_bytes(path.read_bytes() + b"\n")
        return transport.handle_request(request)

    arguments["mock_transport"] = httpx.MockTransport(handler)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=3)
    assert len(calls) == 2 and populations == [0, 1]
    snapshot = arguments["ledger"].snapshot()
    assert len(snapshot.entries) == 2
    assert snapshot.spent_usd == Decimal("0.02")
    assert snapshot.active_reserved_usd == 0
    assert not (arguments["output_dir"] / "progress-0002.json").exists()
