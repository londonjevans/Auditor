"""Maximum count/claim fixtures preserve actual production limits, without independent-truth credit."""

import json
from decimal import Decimal

import pytest
from pydantic import ValidationError

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import DevelopmentCorpusResponse
from tests.development_corpus_repeats_scale_support import maximum_repeat_case


def test_maximum_repeat_fixture_freezes_512_requests_and_1024_structural_controls():
    prepared, responses = maximum_repeat_case(capacity_quote=True)
    assert prepared.plan.trial_count == len(prepared.trials) == 8
    assert all(len(t.shards) == 64 for t in prepared.trials)
    assert len(prepared.plan.benchmark.truth.controls) == 1024
    assert prepared.plan.benchmark.truth.provenance == "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS"
    assert (
        len(
            {
                development_ledger_request_id(s.estimate.request_id)
                for t in prepared.trials
                for s in t.shards
            }
        )
        == 512
    )
    first = prepared.trials[0]
    assert all(
        tuple(s.request_content for s in t.shards) == tuple(s.request_content for s in first.shards)
        for t in prepared.trials
    )
    assert 0 < prepared.plan.estimated_total_cost_usd <= Decimal("250")
    assert prepared.plan.estimated_total_cost_usd == first.plan.estimated_total_cost_usd * 8
    assert prepared.plan.maximum_run_seconds == 1800
    assert all(t.plan.maximum_run_seconds == 1800 for t in prepared.trials)
    for shard, response in zip(first.shards, responses, strict=True):
        observed = DevelopmentCorpusResponse.model_validate_json(json.dumps(response), strict=True)
        assert len(observed.findings) == 16
        assert all(f.root_cause_ref.filename == shard.source_filename for f in observed.findings)
    assert not prepared.plan.audit_complete and not prepared.plan.qualification_eligible


def test_original_maximum_width_quote_is_refused_above_the_unchanged_250_budget():
    with pytest.raises(ValidationError) as refused:
        maximum_repeat_case(capacity_quote=False)
    errors = refused.value.errors()
    assert errors[0]["loc"] == ("estimated_total_cost_usd",)
    assert errors[0]["input"] == Decimal("1706.079232000000000000")
    assert errors[0]["type"] == "less_than_equal"
