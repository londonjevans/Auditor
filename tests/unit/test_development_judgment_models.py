"""Exact candidate coverage, source scope and non-authorizing review schemas."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mmaudit.models.development_judgment import (
    DevelopmentJudgmentPlan,
    development_judgment_request_id,
    prepare_development_judgment_shard,
    validate_development_candidate_accounting,
    validate_development_judgment_response,
)
from mmaudit.models.development_review import DevelopmentJudgmentResponse
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_audit_support import complete_audit_observation, corpus_sources
from tests.development_benchmark_support import scored_file_response, scored_observation
from tests.development_judgment_support import judgment_case, judgment_metadata, judgment_response


@pytest.mark.parametrize("variant", ["a", "b"])
def test_plan_preserves_every_candidate_and_compiles_only_source_and_claim_data(variant):
    prepared = judgment_case(variant=variant)
    assert prepared.plan.candidate == scored_observation(variant=variant)
    assert prepared.plan.lineage_independence == "NOT_ESTABLISHED"
    assert prepared.plan.findings_validated is prepared.plan.qualification_eligible is False
    assert prepared.plan.audit_complete is prepared.plan.release_eligible is False
    assert (
        DevelopmentJudgmentPlan.model_validate_json(prepared.plan.model_dump_json())
        == prepared.plan
    )
    assert len(prepared.shards) == 3 and not prepared.plan.empty_candidate_shard_ids
    for item, shard in zip(prepared.shards, prepared.plan.candidate.observations, strict=True):
        assert item.claims[0].finding == shard.response.findings[0]
        body = json.loads(item.request_content)
        assert (
            body["response_format"]["json_schema"]["name"]
            == "mmaudit_development_candidate_judgment"
        )
        assert body["provider"]["allow_fallbacks"] is False and body["provider"]["zdr"] is True
        assert body["reasoning"] == {"effort": "high"}
        assert "decisions" in body["response_format"]["json_schema"]["schema"]["properties"]
        messages = json.dumps(body["messages"])
        assert prepared.plan.candidate.plan.shards[0].estimate.exact_model_id not in messages
        assert "MATCHED_ROOT" not in messages and "truth-" not in messages
        for name, source in corpus_sources(variant):
            assert (
                name in messages
                and source.decode().splitlines()[4] in body["messages"][1]["content"]
            )
        assert item.estimate.request_id.startswith("dvj-") and len(item.estimate.request_id) == 64


@pytest.mark.parametrize("empty_ids", [(1,), (2,), (1, 3), (1, 2, 3)])
def test_empty_shards_have_explicit_scope_but_no_planned_request_or_estimate(empty_ids):
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for i in empty_ids:
        responses[i - 1]["findings"] = []
    prepared = judgment_case(responses=responses)
    assert prepared.plan.empty_candidate_shard_ids == tuple(f"file-{i:02d}" for i in empty_ids)
    assert len(prepared.shards) == 3 - len(empty_ids)
    assert bool(prepared.plan.estimated_total_cost_usd) is bool(prepared.shards)
    with pytest.raises(ValueError, match="empty"):
        prepare_development_judgment_shard(
            candidate=prepared.plan.candidate,
            policy=prepared.plan.policy,
            endpoint_snapshot=prepared.endpoint_snapshot,
            source_files=prepared.source_files,
            shard_id=f"file-{empty_ids[0]:02d}",
            run_id="refused-empty",
        )


@pytest.mark.parametrize("kind", ["same_id", "known_alias"])
def test_same_producer_or_supplied_canonical_alias_cannot_judge(kind):
    metadata = (
        judgment_metadata(model_id="synthetic/development-auditor")
        if kind == "same_id"
        else (judgment_metadata(canonical="synthetic/development-auditor"))
    )
    with pytest.raises(ValueError, match=r"producer|alias"):
        judgment_case(endpoint_snapshot=metadata)


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_sha256", "b" * 64),
        ("run_id", "changed-run"),
        ("estimated_total_cost_usd", "0"),
        ("empty_candidate_shard_ids", ["file-01"]),
        ("lineage_independence", "VERIFIED"),
        ("qualification_eligible", True),
        ("findings_validated", True),
        ("audit_complete", True),
        ("release_eligible", True),
    ],
)
def test_resealed_plan_cannot_change_bindings_or_grant_authority(field, value):
    data = judgment_case().plan.model_dump(mode="json")
    data[field] = value
    data["plan_sha256"] = canonical_sha256(
        {key: item for key, item in data.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentJudgmentPlan.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "change", ["missing", "changed", "reorder", "path", "byte_type", "tuple_type"]
)
def test_judgment_reuses_exact_frozen_source_boundary(change):
    sources = corpus_sources("a")
    if change == "missing":
        sources = sources[:-1]
    elif change == "changed":
        sources = ((sources[0][0], sources[0][1] + b"\n"), *sources[1:])
    elif change == "reorder":
        sources = tuple(reversed(sources))
    elif change == "path":
        sources = (("../RoutePolicy.sol", sources[0][1]), *sources[1:])
    elif change == "byte_type":
        sources = ((sources[0][0], bytearray(sources[0][1])), *sources[1:])
    else:
        sources = list(sources)
    with pytest.raises(ValueError):
        judgment_case(source_files=sources)


def test_legacy_candidates_are_not_reinterpreted():
    with pytest.raises(ValueError, match="v2"):
        judgment_case(candidate=complete_audit_observation())


@pytest.mark.parametrize("verdict", ["SUPPORTED", "REFUTED", "INCONCLUSIVE"])
def test_source_grounded_decisions_cover_the_exact_input_claims(verdict):
    prepared = judgment_case()
    response = DevelopmentJudgmentResponse.model_validate_json(
        json.dumps(judgment_response(verdict=verdict))
    )
    validate_development_judgment_response(
        response, corpus_id="unit-ledger-a-v1", claims=prepared.shards[0].claims
    )


@pytest.mark.parametrize(
    "change", ["empty", "extra", "unknown", "duplicate", "outside_file", "outside_line"]
)
def test_missing_new_duplicate_or_out_of_scope_decisions_cannot_be_observed(change):
    prepared = judgment_case()
    value = judgment_response()
    if change == "empty":
        value["decisions"] = []
    elif change in {"extra", "duplicate"}:
        value["decisions"].append(
            {
                **value["decisions"][0],
                "claim_id": "file-01:02" if change == "extra" else "file-01:01",
            }
        )
    elif change == "unknown":
        value["decisions"][0]["claim_id"] = "file-02:01"
    else:
        value["decisions"][0]["source_refs"][0].update(
            {"filename": "Unknown.sol"} if change == "outside_file" else {"line_end": 66}
        )
    with pytest.raises(ValueError):
        response = DevelopmentJudgmentResponse.model_validate_json(json.dumps(value))
        validate_development_judgment_response(
            response, corpus_id="unit-ledger-a-v1", claims=prepared.shards[0].claims
        )


@pytest.mark.parametrize(
    "change",
    [
        "unsupported_verdict",
        "no_refs",
        "duplicate_ref",
        "bool_line",
        "reversed",
        "extra_field",
        "new_finding",
    ],
)
def test_response_rejects_ambiguous_or_unsubstantiated_conclusive_structure(change):
    value = judgment_response()
    decision = value["decisions"][0]
    if change == "unsupported_verdict":
        decision["verdict"] = "VERIFIED"
    elif change == "no_refs":
        decision["source_refs"] = []
    elif change == "duplicate_ref":
        decision["source_refs"] *= 2
    elif change in {"bool_line", "reversed"}:
        decision["source_refs"][0]["line_start"] = True if change == "bool_line" else 47
    elif change == "extra_field":
        decision["qualification_eligible"] = True
    else:
        decision["finding"] = scored_file_response(1)["findings"][0]
    with pytest.raises(ValidationError):
        DevelopmentJudgmentResponse.model_validate_json(json.dumps(value))


def test_a_fresh_or_changed_ledger_cannot_erase_candidate_costs(tmp_path):
    candidate = scored_observation()
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    with pytest.raises(ValueError, match="accounting"):
        validate_development_candidate_accounting(candidate, ledger.snapshot())


@pytest.mark.parametrize("run_id", ["", "../outside", True, "x" * 65])
def test_run_identity_is_bounded_before_requests(run_id):
    with pytest.raises(ValueError):
        development_judgment_request_id(run_id, "a" * 64, "file-01")


@pytest.mark.parametrize(
    "filename",
    [
        "development_judgment_response.schema.json",
        "development_judgment_plan.schema.json",
        "development_judgment_shard_observation.schema.json",
        "development_judgment_observation.schema.json",
        "development_judgment_impact_score.schema.json",
    ],
)
def test_judgment_schemas_are_canonical_and_cannot_confer_authority(filename):
    content = (Path(__file__).resolve().parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    Draft202012Validator.check_schema(schema)
    if filename != "development_judgment_response.schema.json":
        for name in (
            "findings_validated",
            "audit_complete",
            "qualification_eligible",
            "release_eligible",
        ):
            assert schema["properties"][name]["const"] is False
        assert schema["properties"]["lineage_independence"]["const"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("verdict", ["SUPPORTED", "REFUTED", "INCONCLUSIVE"])
@pytest.mark.parametrize("wire", [False, True])
def test_public_and_wire_schema_both_require_source_refs_for_conclusive_opinions(verdict, wire):
    schema = (
        json.loads(judgment_case().shards[0].request_content)["response_format"]["json_schema"][
            "schema"
        ]
        if wire
        else DevelopmentJudgmentResponse.model_json_schema()
    )
    validator = Draft202012Validator(schema)
    value = judgment_response(verdict=verdict)
    assert validator.is_valid(value)
    value["decisions"][0]["source_refs"] = []
    assert validator.is_valid(value) is (verdict == "INCONCLUSIVE")


def test_complete_candidate_is_required_even_when_a_partial_audit_is_structurally_valid():
    from mmaudit.models.development_audit import DevelopmentAuditObservation

    data = scored_observation().model_dump(mode="json")
    data.update(
        status="INCOMPLETE",
        stop_reason="INTERRUPTED",
        observations=data["observations"][:1],
        accounting=data["accounting"][:1],
        unobserved_shard_ids=["file-02", "file-03"],
        completed_shard_count=1,
        total_accounted_cost_usd="0.01",
    )
    partial = DevelopmentAuditObservation.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="complete"):
        judgment_case(candidate=partial)
