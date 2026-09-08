from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.development_audit import (
    DEVELOPMENT_AUDIT_SOURCE_PINS,
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    DevelopmentAuditShardObservation,
    prepare_development_audit,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_review import DevelopmentReviewObservation
from mmaudit.orchestration.development_audit import _rebuild
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_audit_support import (
    audit_case,
    complete_audit_observation,
    corpus_sources,
    shard_observation,
)
from tests.development_cost_support import development_case


@pytest.mark.parametrize(
    "filename",
    [
        "development_audit_plan.schema.json",
        "development_audit_shard_observation.schema.json",
        "development_audit_observation.schema.json",
    ],
)
def test_development_audit_schemas_are_canonical_and_cannot_promote_authority(filename):
    content = (Path(__file__).resolve().parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    for field in (
        "audit_complete",
        "findings_validated",
        "qualification_eligible",
        "release_eligible",
    ):
        assert schema["properties"][field]["const"] is False


def test_guarded_counterpart_changes_only_the_declared_gateway_authorization():
    a = dict(corpus_sources("a"))
    b = dict(corpus_sources("b"))
    assert a["UnitStore.sol"] == b["UnitStore.sol"]
    assert a["UnitRouter.sol"] == b["UnitRouter.sol"]
    assert (
        a["RoutePolicy.sol"].replace(
            b"function setGateway(address nextGateway) external {",
            b"function setGateway(address nextGateway) external onlyAdministrator {",
        )
        == b["RoutePolicy.sol"]
    )
    for sources in (a, b):
        assert all(b"abstract contract" in content for content in sources.values())
        assert b"internal virtual;" in sources["UnitRouter.sol"]


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("discovery", [False, True])
def test_complete_primary_partition_uses_exact_shared_context_and_single_identity(
    variant, discovery
):
    prepared = audit_case(variant=variant, discovery=discovery)
    assert prepared == audit_case(variant=variant, discovery=discovery) == _rebuild(prepared)
    assert prepared.plan == DevelopmentAuditPlan.model_validate_json(
        prepared.plan.model_dump_json()
    )
    assert len(prepared.shards) == len(prepared.plan.sources) == 3
    assert len({shard.estimate.request_id for shard in prepared.shards}) == 3
    assert len({shard.estimate.request_sha256 for shard in prepared.shards}) == 3
    for source, shard in zip(prepared.plan.sources, prepared.shards, strict=True):
        body = json.loads(shard.request_content)
        assert shard.source_filename == source.filename
        assert hashlib.sha256(shard.source_content).hexdigest() == source.sha256
        assert hashlib.sha256(shard.request_content).hexdigest() == shard.estimate.request_sha256
        assert body["messages"][1]["content"].startswith("Primary file: " + source.filename)
        for name, digest, _size, _lines in DEVELOPMENT_AUDIT_SOURCE_PINS[prepared.plan.corpus_id]:
            assert "Source file: " + name in body["messages"][1]["content"]
            assert "Source SHA-256: " + digest in body["messages"][1]["content"]
        assert body["provider"]["allow_fallbacks"] is False
        assert body["provider"]["zdr"] is True
        assert body["reasoning"] == {"effort": "high"}
        assert body["response_format"]["json_schema"]["strict"] is True
        assert "tools" not in body and "tool_choice" not in body
        assert "abstract contract" not in prepared.plan.model_dump_json()
    assert prepared.plan.estimated_total_cost_usd == sum(
        shard.estimate.estimated_cost_per_attempt_usd for shard in prepared.shards
    )
    assert prepared.plan.audit_complete is prepared.plan.qualification_eligible is False


@pytest.mark.parametrize(
    "change", ["missing", "order", "extra", "bytes", "name", "list", "mutable", "other_variant"]
)
def test_any_non_exact_corpus_refuses_before_transport(change):
    sources = corpus_sources()
    if change == "missing":
        sources = sources[:-1]
    elif change == "order":
        sources = tuple(reversed(sources))
    elif change == "extra":
        sources += (("extra.sol", b"inert"),)
    elif change == "bytes":
        sources = ((sources[0][0], sources[0][1] + b" "), *sources[1:])
    elif change == "name":
        sources = (("../RoutePolicy.sol", sources[0][1]), *sources[1:])
    elif change == "list":
        sources = list(sources)
    elif change == "mutable":
        sources = ((sources[0][0], bytearray(sources[0][1])), *sources[1:])
    else:
        sources = corpus_sources("b")
    with pytest.raises(ValueError):
        prepare_development_audit(
            policy=audit_case().plan.shards[0].estimate.policy,
            endpoint_snapshot=development_case()[0],
            corpus_id="unit-ledger-a-v1",
            source_files=sources,
            run_id="local-refusal",
        )


@pytest.mark.parametrize("run_id", ["", "x" * 65, "../outside", "\x01", True])
def test_run_ids_are_explicit_bounded_and_request_bound(run_id):
    with pytest.raises(ValueError):
        audit_case(run_id=run_id)


def test_aggregate_estimate_and_attempt_policy_are_checked_before_a_run():
    for policy in (
        DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("0.5"),
            per_attempt_budget_usd=Decimal("0.5"),
        ),
        DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("5"),
            maximum_attempts=2,
        ),
    ):
        with pytest.raises(ValueError):
            audit_case(policy=policy)


@pytest.mark.parametrize("change", ["request", "primary", "context", "plan", "shards", "metadata"])
def test_prepared_plan_is_rebuilt_not_trusted_by_its_dataclass_label(change):
    prepared = audit_case()
    first = prepared.shards[0]
    if change == "request":
        first = replace(first, request_content=b"{}")
    elif change == "primary":
        first = replace(first, source_filename="UnitStore.sol")
    elif change == "context":
        first = replace(first, source_files=corpus_sources("b"))
    elif change == "metadata":
        first = replace(
            first,
            discovery=None,
            endpoint_snapshot=audit_case(discovery=True).shards[0].endpoint_snapshot,
        )
    elif change == "plan":
        prepared = replace(
            prepared, plan=prepared.plan.model_copy(update={"plan_sha256": "0" * 64})
        )
    else:
        prepared = replace(prepared, shards=prepared.shards[:-1])
    if change in {"request", "primary", "context", "metadata"}:
        prepared = replace(prepared, shards=(first, *prepared.shards[1:]))
    with pytest.raises(ValueError):
        _rebuild(prepared)


def test_aggregate_retains_per_file_hypotheses_and_costs_without_qualification():
    report = complete_audit_observation()
    assert DevelopmentAuditObservation.model_validate_json(report.model_dump_json()) == report
    assert report.completed_shard_count == 3 and report.unobserved_shard_ids == ()
    assert report.total_accounted_cost_usd == Decimal("0.03")
    assert all(item.response is not None for item in report.observations)
    assert {item.source_filename for item in report.observations} == {
        source.filename for source in report.plan.sources
    }
    assert (
        report.audit_complete
        is report.findings_validated
        is report.qualification_eligible
        is report.release_eligible
        is False
    )
    with pytest.raises(ValidationError):
        DevelopmentReviewObservation.model_validate_json(report.observations[0].model_dump_json())


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "corpus",
        "estimate",
        "coverage",
        "cost",
        "active",
        "generation",
        "order",
        "accounting",
        "status",
    ],
)
def test_forged_aggregate_scope_coverage_identity_or_accounting_refuses(change):
    data = complete_audit_observation().model_dump(mode="json")
    if change == "source":
        data["observations"][0]["source_sha256"] = "0" * 64
    elif change == "corpus":
        data["observations"][0]["corpus_id"] = "unit-ledger-b-v1"
    elif change == "estimate":
        data["observations"][0]["estimate"]["request_id"] = "changed"
    elif change == "coverage":
        data["completed_shard_count"] = 2
    elif change == "cost":
        data["total_accounted_cost_usd"] = "0"
    elif change == "active":
        data["active_reserved_usd"] = "1"
    elif change == "generation":
        data["observations"][1]["generation_id"] = data["observations"][0]["generation_id"]
    elif change == "order":
        data["observations"].reverse()
    elif change == "accounting":
        data["accounting"][0]["accounted_cost_usd"] = "0"
    else:
        data["status"] = "INCOMPLETE"
    with pytest.raises(ValidationError):
        DevelopmentAuditObservation.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "field", ["audit_complete", "findings_validated", "qualification_eligible", "release_eligible"]
)
@pytest.mark.parametrize("value", [True, 1, "false"])
def test_every_development_artifact_refuses_promoted_assurance(field, value):
    plan = audit_case().plan
    observation = shard_observation(audit_case().shards[0])
    for model in (plan, observation, complete_audit_observation()):
        data = model.model_dump(mode="json")
        data[field] = value
        with pytest.raises(ValidationError):
            type(model).model_validate_json(json.dumps(data))


def test_primary_line_numbers_cannot_point_only_into_shared_context():
    shard = audit_case().shards[1]
    data = shard_observation(shard).model_dump(mode="json")
    data["response"]["findings"][0]["line_end"] = 65
    with pytest.raises(ValidationError):
        DevelopmentAuditShardObservation.model_validate_json(json.dumps(data))
