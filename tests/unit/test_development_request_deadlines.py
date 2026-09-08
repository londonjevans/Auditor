"""Selected development deadlines remain bounded policy, not provider cost/quality authority."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_audit import prepare_development_audit
from mmaudit.models.development_costs import DevelopmentCostPolicy, estimate_development_request
from mmaudit.models.development_transport import development_request_timeout_seconds
from tests.development_audit_support import audit_case
from tests.development_benchmark_support import scored_audit_case
from tests.development_corpus_support import corpus_case
from tests.development_cost_support import development_case
from tests.development_ensemble_support import ensemble_case
from tests.development_judgment_support import judgment_case


def deadline_policy(value=None):
    return DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("20"),
        per_attempt_budget_usd=Decimal("1"),
        request_timeout_seconds=value,
    )


def scored_deadline_case(*, policy):
    base = scored_audit_case()
    return prepare_development_audit(
        policy=policy,
        endpoint_snapshot=base.shards[0].endpoint_snapshot,
        corpus_id=base.plan.corpus_id,
        source_files=base.shards[0].source_files,
        run_id=base.plan.run_id,
        schema_version="2.0",
    )


@pytest.mark.parametrize("value", [None, 1, 180, 360, 1800])
def test_selected_deadline_is_retained_or_legacy_default_is_omitted(value):
    policy = deadline_policy(value)
    assert development_request_timeout_seconds(policy) == (180 if value is None else value)
    data = json.loads(policy.model_dump_json())
    if value is None:
        assert "request_timeout_seconds" not in data
    else:
        assert data["request_timeout_seconds"] == value
    assert DevelopmentCostPolicy.model_validate_json(json.dumps(data), strict=True) == policy
    assert policy.maximum_attempts == 1 and policy.uncertain_cost_policy == "STOP"


@pytest.mark.parametrize(
    "value", [True, False, 0, -1, 1801, 1.0, 1.5, "30", "", [], {}, float("inf"), float("nan")]
)
def test_deadline_requires_an_exact_bounded_integer(value):
    with pytest.raises(ValueError):
        deadline_policy(value)


@pytest.mark.parametrize("value", [1, 180, 360, 1800])
def test_deadline_does_not_change_provider_bytes_or_numeric_cost_estimates(value):
    metadata, body = development_case()
    before = json.dumps(body, sort_keys=True)
    original = estimate_development_request(
        policy=deadline_policy(),
        endpoint_snapshot=metadata,
        request_id="synthetic",
        request_body=body,
    )
    selected = estimate_development_request(
        policy=deadline_policy(value),
        endpoint_snapshot=metadata,
        request_id="synthetic",
        request_body=body,
    )
    assert original.model_dump(exclude={"policy"}) == selected.model_dump(exclude={"policy"})
    assert json.dumps(body, sort_keys=True) == before
    assert not selected.provider_enforced_ceiling and not selected.qualification_eligible
    assert not selected.release_eligible


@pytest.mark.parametrize(
    "factory", [audit_case, scored_deadline_case, corpus_case, judgment_case, ensemble_case]
)
def test_every_prepared_run_retains_the_selected_timeout_and_preserves_wire_requests(factory):
    original = factory(policy=deadline_policy())
    selected = factory(policy=deadline_policy(360))
    assert original.plan.model_dump_json() != selected.plan.model_dump_json()
    assert '"request_timeout_seconds":360' in selected.plan.model_dump_json()
    original_shards = original.candidate.shards if factory is ensemble_case else original.shards
    selected_shards = selected.candidate.shards if factory is ensemble_case else selected.shards
    assert tuple(s.request_content for s in original_shards) == tuple(
        s.request_content for s in selected_shards
    )
    assert all(s.estimate.policy.request_timeout_seconds == 360 for s in selected_shards)
    assert not selected.plan.audit_complete and not selected.plan.qualification_eligible


@pytest.mark.parametrize("value", [0, -1, 1801])
def test_forged_frozen_policy_is_revalidated_before_selecting_a_deadline(value):
    forged = deadline_policy().model_copy(update={"request_timeout_seconds": value})
    with pytest.raises(ValueError):
        development_request_timeout_seconds(forged)


def test_deadline_resolver_refuses_policy_subclasses_and_untyped_values():
    class ForeignPolicy(DevelopmentCostPolicy):
        pass

    for value in (None, {}, ForeignPolicy.model_validate(deadline_policy().model_dump())):
        with pytest.raises(ValueError, match="exact policy"):
            development_request_timeout_seconds(value)


@pytest.mark.parametrize("value", [None, 1, 1800, 0, 1801, True, "180"])
def test_public_policy_schema_exposes_the_selected_deadline_bound(value):
    data = json.loads(deadline_policy().model_dump_json())
    data["request_timeout_seconds"] = value
    root = Path(__file__).parents[2]
    committed = json.loads((root / "schemas/development_cost_policy.schema.json").read_bytes())
    for schema in (DevelopmentCostPolicy.model_json_schema(), committed):
        validator = Draft202012Validator(schema)
        assert validator.is_valid(data) is (
            value is None or (type(value) is int and 1 <= value <= 1800)
        )


def test_selected_deadline_and_explicit_carry_are_retained_independently():
    policy = DevelopmentCostPolicy.model_validate(
        {**deadline_policy(360).model_dump(), "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"}
    )
    encoded = policy.model_dump_json()
    assert '"request_timeout_seconds":360' in encoded
    assert '"uncertain_cost_policy":"CARRY_RESERVED_ESTIMATE"' in encoded
    assert DevelopmentCostPolicy.model_validate_json(encoded, strict=True) == policy
    assert policy.maximum_attempts == 1
