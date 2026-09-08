"""Bounded provider metadata is diagnostic evidence, never repaired or verified usage."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import mmaudit.models.development_diagnostics as diagnostics
from mmaudit.models.development_audit import DevelopmentScoredAuditShardObservation
from tests.development_audit_support import complete_audit_observation
from tests.development_benchmark_support import scored_observation


def payload():
    return {
        "choices": [{"index": 0, "finish_reason": "length", "native_finish_reason": "MAX_TOKENS"}],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 4096,
            "total_tokens": 4196,
            "completion_tokens_details": {"reasoning_tokens": 4000},
        },
    }


def project(value=None):
    return diagnostics.project_development_completion_telemetry(
        payload() if value is None else value, response_sha256="a" * 64
    )


def test_reported_finish_and_counts_are_retained_without_inventing_a_success():
    result = project()
    assert result.finish_reason == "length" and result.finish_reason_state == "REPORTED"
    assert result.native_finish_reason == "max_tokens"
    assert result.native_finish_reason_state == "REPORTED"
    assert result.prompt_tokens.value == 100
    assert result.completion_tokens.value == 4096
    assert result.total_tokens.value == 4196
    assert result.reasoning_tokens.value == 4000
    assert result.token_sum_consistency == result.reasoning_subset_consistency == "CONSISTENT"
    assert result.interpretation == "REPORTED_METADATA_NOT_VERIFIED_USAGE"
    assert result.response_sha256 == "a" * 64
    assert result == type(result).model_validate_json(result.model_dump_json())


@pytest.mark.parametrize(
    "field", ["prompt_tokens", "completion_tokens", "total_tokens", "reasoning_tokens"]
)
@pytest.mark.parametrize("value", [True, "7", 7.0, Decimal("7"), -1, 4_000_001, {}, []])
def test_invalid_counts_are_not_coerced_or_serialized(field, value):
    data = payload()
    target = (
        data["usage"]["completion_tokens_details"] if field == "reasoning_tokens" else data["usage"]
    )
    target[field] = value
    result = project(data)
    observed = getattr(result, field)
    assert observed.state == "INVALID" and observed.value is None
    assert result.completion_tokens.value == (None if field == "completion_tokens" else 4096)


@pytest.mark.parametrize("value", [0, 4_000_000])
def test_exact_bounded_counts_including_zero_are_retained(value):
    data = payload()
    data["usage"]["completion_tokens_details"]["reasoning_tokens"] = value
    result = project(data)
    assert result.reasoning_tokens.state == "REPORTED" and result.reasoning_tokens.value == value


@pytest.mark.parametrize("value", [None, {}, [], "private-canary"])
def test_absent_and_invalid_usage_containers_are_distinguished(value):
    data = payload()
    data["usage"] = value
    result = project(data)
    expected = "NOT_REPORTED" if value is None or value == {} else "INVALID"
    assert all(
        getattr(result, name).state == expected
        for name in ("prompt_tokens", "completion_tokens", "total_tokens", "reasoning_tokens")
    )
    assert result.token_sum_consistency == result.reasoning_subset_consistency == "NOT_OBSERVED"
    assert "private-canary" not in result.model_dump_json()


@pytest.mark.parametrize("field", ["finish_reason", "native_finish_reason"])
@pytest.mark.parametrize(
    "value,state",
    [
        (None, "NOT_REPORTED"),
        (True, "INVALID"),
        ({}, "INVALID"),
        ("private-canary", "UNRECOGNIZED"),
    ],
)
def test_unrecognized_or_invalid_finish_values_cannot_escape(field, value, state):
    data = payload()
    data["choices"][0][field] = value
    result = project(data)
    assert getattr(result, field) is None
    assert getattr(result, field + "_state") == state
    assert "private-canary" not in result.model_dump_json()


@pytest.mark.parametrize(
    "choices,state",
    [
        (None, "NOT_REPORTED"),
        ({}, "INVALID"),
        ([], "AMBIGUOUS"),
        ([{}, {}], "AMBIGUOUS"),
        ([{}], "INVALID"),
        ([{"index": True}], "INVALID"),
        ([{"index": 1}], "INVALID"),
    ],
)
def test_ambiguous_choice_is_never_silently_selected(choices, state):
    data = payload()
    data["choices"] = choices
    result = project(data)
    assert result.finish_reason_state == result.native_finish_reason_state == state
    assert result.finish_reason is result.native_finish_reason is None
    assert result.completion_tokens.value == 4096


def test_inconsistent_reported_counts_remain_exact_with_recomputable_labels():
    data = payload()
    data["usage"]["total_tokens"] = 1
    data["usage"]["completion_tokens_details"]["reasoning_tokens"] = 4097
    result = project(data)
    assert result.total_tokens.value == 1 and result.reasoning_tokens.value == 4097
    assert result.token_sum_consistency == result.reasoning_subset_consistency == "INCONSISTENT"


@pytest.mark.parametrize("finish", ["stop", "length", "tool_calls", "content_filter", "error"])
def test_every_documented_normalized_finish_reason_is_retained(finish):
    data = payload()
    data["choices"][0]["finish_reason"] = finish
    assert project(data).finish_reason == finish


@pytest.mark.parametrize("details", [None, {}, [], "synthetic-private-details"])
def test_nested_reasoning_metadata_does_not_erase_top_level_counts(details):
    data = payload()
    data["usage"]["completion_tokens_details"] = details
    result = project(data)
    assert result.prompt_tokens.value == 100 and result.completion_tokens.value == 4096
    assert result.reasoning_tokens.state == (
        "NOT_REPORTED" if details is None or details == {} else "INVALID"
    )
    assert result.reasoning_tokens.value is None
    assert "synthetic-private-details" not in result.model_dump_json()


@pytest.mark.parametrize(
    "change", ["sum", "subset", "count_state", "finish_state", "raw", "authority", "hash"]
)
def test_tampered_telemetry_cannot_claim_consistency_or_retain_raw_values(change):
    value = project().model_dump(mode="json")
    if change == "sum":
        value["token_sum_consistency"] = "INCONSISTENT"
    elif change == "subset":
        value["reasoning_subset_consistency"] = "NOT_OBSERVED"
    elif change == "count_state":
        value["prompt_tokens"]["state"] = "INVALID"
    elif change == "finish_state":
        value["finish_reason_state"] = "NOT_REPORTED"
    elif change == "raw":
        value["native_finish_reason"] = "private-canary"
    elif change == "authority":
        value["interpretation"] = "VERIFIED_USAGE"
    else:
        value["response_sha256"] = None
    with pytest.raises(ValidationError):
        type(project()).model_validate_json(json.dumps(value))


@pytest.mark.parametrize("change", ["no_http", "no_hash", "wrong_hash", "unread_json"])
def test_parent_requires_exact_whole_body_custody(change):
    value = scored_observation().observations[0].model_dump(mode="json")
    telemetry = project().model_dump(mode="json")
    telemetry["response_sha256"] = value["response_sha256"]
    value.update(
        status="INCOMPLETE",
        diagnostics=["INCOMPLETE_OUTPUT"],
        response=None,
        completion_telemetry=telemetry,
    )
    assert (
        DevelopmentScoredAuditShardObservation.model_validate_json(
            json.dumps(value)
        ).completion_telemetry
        is not None
    )
    if change == "no_http":
        value["http_status"] = None
    elif change == "no_hash":
        value["response_sha256"] = None
    elif change == "wrong_hash":
        telemetry["response_sha256"] = "b" * 64
    else:
        value["diagnostics"] = ["INVALID_RESPONSE"]
        value["rejection_evidence"] = {
            "stage": "HTTP_BODY",
            "reason": "RESPONSE_JSON",
            "response_sha256": value["response_sha256"],
        }
    with pytest.raises(ValidationError):
        DevelopmentScoredAuditShardObservation.model_validate_json(json.dumps(value))


def test_absent_telemetry_preserves_legacy_observation_bytes():
    observation = complete_audit_observation()
    content = observation.model_dump_json()
    assert "completion_telemetry" not in content
    assert (
        hashlib.sha256(content.encode()).hexdigest()
        == "b07c014f29ce36f215444fafaaad3e8dae46e0635e89df9a05d70bdf76bf810b"
    )
    assert observation == type(observation).model_validate_json(content)


@pytest.mark.parametrize("change", ["raw", "count", "count_type", "finish", "interpretation"])
def test_public_telemetry_schema_is_canonical_closed_and_bounded(change):
    from scripts.generate_release_schemas import MODELS, rendered_schema

    filename = "development_completion_telemetry.schema.json"
    content = (Path(__file__).parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    value = project().model_dump(mode="json")
    assert validator.is_valid(value)
    if change == "raw":
        value["raw_completion"] = "private-canary"
    elif change == "count":
        value["prompt_tokens"]["value"] = 4_000_001
    elif change == "count_type":
        value["prompt_tokens"]["value"] = True
    elif change == "finish":
        value["finish_reason"] = "private-canary"
    else:
        value["interpretation"] = "VERIFIED_USAGE"
    assert not validator.is_valid(value)
