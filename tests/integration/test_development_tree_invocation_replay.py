"""Actual tree execution reuses pure parsing, not source, request or charge custody."""

from __future__ import annotations

from decimal import Decimal

import pytest

from mmaudit.models import development_corpus as models
from mmaudit.models import development_corpus_replay as replay_module
from mmaudit.orchestration.development_tree import run_development_tree_plan
from tests.integration import test_development_corpus_replay_custody as custody_controls
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
async def test_actual_candidate_and_cold_review_resume_each_replay_original_material_once(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    content = arguments["loaded"].reference.material.model_dump_json()
    original = models.DevelopmentCorpusMaterial.model_validate_json
    parses = []

    def parse(value, **kwargs):
        if value == content:
            parses.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(models.DevelopmentCorpusMaterial, "model_validate_json", parse)
    first = await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert first.completed_attempt_count == len(calls) == 1
    assert parses == [content]
    before = arguments["ledger"].snapshot().entries
    candidate = arguments["output_dir"] / "cases/case-0001/run/candidate/result.json"
    candidate_bytes = candidate.read_bytes()
    arguments["loaded"] = reopen(inputs)
    parses.clear()
    final = await run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=2
    )
    assert final.completed_attempt_count == len(calls) == 3
    assert parses == [content]
    assert candidate.read_bytes() == candidate_bytes
    entries = arguments["ledger"].snapshot().entries
    assert all(entry in entries for entry in before)
    assert arguments["ledger"].snapshot().spent_usd == Decimal("0.03")
    assert len(final.primary_statuses) == 5
    assert (
        not final.audit_complete and not final.qualification_eligible and not final.release_eligible
    )


@pytest.mark.parametrize("hit", [1, 2, 3, 4])
@pytest.mark.parametrize("changed", ["manifest", "source_bytes", "source_inode", "manifest_memory"])
def test_warm_invocation_replay_preserves_each_original_live_boundary(
    tmp_path, monkeypatch, hit, changed
):
    # Reuse every exact mutation/assertion from the existing guard-local controls, now with
    # pure results surviving the earlier bundle construction and validation calls as well.
    with replay_module.development_corpus_replay_scope():
        custody_controls.test_pure_manifest_reuse_preserves_every_original_live_boundary(
            tmp_path, monkeypatch, hit, changed
        )


@pytest.mark.parametrize("hit", [2, 3, 5, 6])
@pytest.mark.parametrize(
    "changed", ["original_bytes", "original_inode", "manifest", "recipe", "reference_material"]
)
def test_warm_invocation_replay_preserves_each_late_original_and_recipe_check(
    tmp_path, monkeypatch, hit, changed
):
    with replay_module.development_corpus_replay_scope():
        custody_controls.test_reused_material_never_caches_a_live_original_or_recipe_verdict(
            tmp_path, monkeypatch, hit, changed
        )
