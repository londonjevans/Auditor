"""The sent schema must reject the same synthetic kind/nullability defects as the client."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mmaudit.models.development_review import (
    DevelopmentScoredFinding,
    DevelopmentScoredReviewResponse,
    _scored_finding_schema,
)
from mmaudit.models.openrouter import strict_json_schema
from tests.development_benchmark_support import scored_audit_case, scored_response


@pytest.mark.parametrize("schema_view", ["model", "wire", "public"])
@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("present_mask", range(8))
def test_every_kind_and_null_combination_has_the_same_contract(schema_view, advisory, present_mask):
    response = scored_response(advisory=advisory)
    non_null = scored_response()["findings"][0]
    for index, field in enumerate(("vulnerability_class", "violated_invariant", "root_cause_ref")):
        response["findings"][0][field] = non_null[field] if present_mask & (1 << index) else None
    expected = present_mask == (0 if advisory else 7)
    try:
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)
    except ValidationError:
        client_accepts = False
    else:
        client_accepts = True
    assert client_accepts is expected
    if schema_view == "model":
        schema = DevelopmentScoredReviewResponse.model_json_schema()
    elif schema_view == "wire":
        request = json.loads(scored_audit_case().shards[0].request_content)
        schema = request["response_format"]["json_schema"]["schema"]
    else:
        schema = json.loads(
            (
                Path(__file__).parents[2] / "schemas/development_scored_review_response.schema.json"
            ).read_bytes()
        )
    assert Draft202012Validator(schema).is_valid(response) is client_accepts


@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("field", tuple(DevelopmentScoredFinding.model_fields))
def test_every_field_remains_required_in_each_closed_branch(advisory, field):
    response = scored_response(advisory=advisory)
    schema = strict_json_schema(DevelopmentScoredReviewResponse)
    assert Draft202012Validator(schema).is_valid(response)
    del response["findings"][0][field]
    assert not Draft202012Validator(schema).is_valid(response)
    with pytest.raises(ValidationError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("location", ["root", "finding", "origin"])
def test_branches_keep_unknown_fields_closed(advisory, location):
    response = scored_response(advisory=advisory)
    if location == "root":
        response["untrusted_authority"] = True
    elif location == "finding":
        response["findings"][0]["untrusted_authority"] = True
    else:
        response["findings"][0]["root_cause_ref"] = {
            **scored_response()["findings"][0]["root_cause_ref"],
            "untrusted_authority": True,
        }
    assert not Draft202012Validator(strict_json_schema(DevelopmentScoredReviewResponse)).is_valid(
        response
    )
    with pytest.raises(ValidationError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


def test_model_request_and_public_contracts_share_the_same_complete_alternatives():
    schemas = [
        DevelopmentScoredReviewResponse.model_json_schema(),
        strict_json_schema(DevelopmentScoredReviewResponse),
        json.loads(
            (
                Path(__file__).parents[2] / "schemas/development_scored_review_response.schema.json"
            ).read_bytes()
        ),
    ]
    definitions = [schema["$defs"]["DevelopmentScoredFinding"] for schema in schemas]
    assert definitions[0] == definitions[1] == definitions[2]
    assert set(definitions[0]) == {"title", "description", "anyOf"}
    for branch, kind in zip(
        definitions[0]["anyOf"], ("advisory", "invariant_violation"), strict=True
    ):
        assert branch["type"] == "object" and branch["additionalProperties"] is False
        assert (
            set(branch["properties"])
            == set(branch["required"])
            == set(DevelopmentScoredFinding.model_fields)
        )
        assert branch["properties"]["kind"]["enum"] == [kind]
        validator = Draft202012Validator({**branch, "$defs": schemas[0]["$defs"]})
        assert validator.is_valid(scored_response(advisory=kind == "advisory")["findings"][0])
        assert not validator.is_valid(scored_response(advisory=kind != "advisory")["findings"][0])


def test_nested_schema_cache_values_are_mutation_isolated():
    before = strict_json_schema(DevelopmentScoredReviewResponse)
    changed = strict_json_schema(DevelopmentScoredReviewResponse)
    changed["$defs"]["DevelopmentScoredFinding"]["anyOf"][0]["properties"]["root_cause_ref"] = {}
    changed["$defs"]["DevelopmentScoredFinding"]["anyOf"][1]["required"].clear()
    assert strict_json_schema(DevelopmentScoredReviewResponse) == before
    for shard in scored_audit_case().shards:
        assert (
            json.loads(shard.request_content)["response_format"]["json_schema"]["schema"] == before
        )


def test_actual_v2_prompt_names_both_sides_of_the_existing_contract():
    for shard in scored_audit_case().shards:
        prompt = json.loads(shard.request_content)["messages"][0]["content"]
        assert "When kind is advisory" in prompt
        assert (
            "vulnerability_class, violated_invariant and root_cause_ref must all be JSON null"
            in prompt
        )
        assert "When kind is invariant_violation, all three fields must be non-null" in prompt
        assert (
            "Do not label an advisory as an invariant violation just to supply origin fields"
            in prompt
        )


@pytest.mark.parametrize(
    "change", ["kind", "closure", "required", "conditional", "missing", "one_option", "two_nulls"]
)
def test_schema_shape_drift_fails_before_a_weaker_schema_can_be_emitted(change):
    # Recreate the source model's pre-export nullable object from its complete non-null branch.
    source = deepcopy(
        DevelopmentScoredReviewResponse.model_json_schema()["$defs"]["DevelopmentScoredFinding"][
            "anyOf"
        ][1]
    )
    properties = source["properties"]
    properties["kind"]["enum"] = ["invariant_violation", "advisory"]
    for name in ("vulnerability_class", "violated_invariant", "root_cause_ref"):
        properties[name] = {"anyOf": [deepcopy(properties[name]), {"type": "null"}]}
    if change == "kind":
        properties["kind"] = []
    elif change == "closure":
        source["additionalProperties"] = True
    elif change == "required":
        source["required"].remove("root_cause_ref")
    elif change == "conditional":
        source["allOf"] = []
    elif change == "missing":
        del properties["root_cause_ref"]
    elif change == "one_option":
        properties["root_cause_ref"]["anyOf"] = [{"type": "null"}]
    else:
        properties["root_cause_ref"]["anyOf"] = [{"type": "null"}, {"type": "null"}]
    with pytest.raises(ValueError, match="development finding schema"):
        _scored_finding_schema(source)
