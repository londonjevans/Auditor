"""Constant-only refusal evidence for synthetic invalid data; no network or provider use."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

import mmaudit.models.development_transport as transport_module
from mmaudit.models.development_audit import DevelopmentScoredAuditShardObservation
from mmaudit.models.development_diagnostics import (
    MAX_DEVELOPMENT_SCHEMA_ISSUES,
    DevelopmentResponseRejection,
    DevelopmentSchemaIssue,
    project_development_schema_failure,
)
from mmaudit.models.development_review import (
    DevelopmentScoredFinding,
    DevelopmentScoredReviewResponse,
)
from mmaudit.models.structured_output import (
    StructuredOutputDecodeError,
    StructuredOutputFailureCode,
)
from tests.development_audit_support import complete_audit_observation
from tests.development_benchmark_support import scored_observation, scored_response

FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures/model_responses/development_invalid_advisory_response.json"
)


def rejection(content: str, model: type[BaseModel] = DevelopmentScoredReviewResponse):
    with pytest.raises(ValueError, match=r"^INVALID_RESPONSE$") as caught:
        transport_module._decode_development_review(content, model)
    detail = caught.value.rejection
    assert type(detail) is DevelopmentResponseRejection
    assert "Synthetic" not in str(caught.value)
    return detail


@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("field", ["vulnerability_class", "violated_invariant", "root_cause_ref"])
def test_nullability_reports_the_actual_constant_field_and_claim_index(advisory, field):
    response = scored_response(advisory=advisory)
    response["findings"].insert(0, scored_response(advisory=advisory)["findings"][0])
    response["findings"][1][field] = scored_response()["findings"][0][field] if advisory else None
    detail = rejection(json.dumps(response))
    assert detail.stage == "STRUCTURED_OUTPUT"
    assert detail.structured_failure == "SCHEMA_VALIDATION_FAILED"
    assert len(detail.schema_issues) == 1
    issue = detail.schema_issues[0]
    assert issue.constraint == (
        "ADVISORY_FIELD_MUST_BE_NULL" if advisory else "INVARIANT_FIELD_MUST_BE_SET"
    )
    assert issue.field == field and issue.finding_index == 1
    assert detail.schema_issues_truncated is False


def test_intentionally_invalid_fixture_has_a_safe_paired_repair():
    content = FIXTURE.read_text()
    detail = rejection(content)
    assert detail.schema_issues[0].constraint == "ADVISORY_FIELD_MUST_BE_NULL"
    assert detail.schema_issues[0].field == "vulnerability_class"
    repaired = json.loads(content)
    repaired["findings"][0]["vulnerability_class"] = None
    result = transport_module._decode_development_review(
        json.dumps(repaired), DevelopmentScoredReviewResponse
    )
    assert result.findings[0].kind == "advisory"
    assert result.findings[0].violated_invariant is None


def test_named_error_codes_preserve_the_existing_nonadvisory_guard():
    finding = DevelopmentScoredFinding.model_validate_json(
        json.dumps(scored_response()["findings"][0])
    )
    forged = finding.model_copy(update={"kind": "untrusted-kind", "violated_invariant": None})
    with pytest.raises(ValueError, match="require a class"):
        forged.kind_and_origin_are_consistent()


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        ("line_start", True, "FIELD_TYPE"),
        ("line_end", 0, "FIELD_BOUND"),
        ("title", "", "FIELD_BOUND"),
        ("severity", "secret-unrecognized-value", "ENUM_VALUE"),
        ("kind", "secret-unrecognized-value", "ENUM_VALUE"),
        ("root_cause_ref", "secret-unrecognized-value", "FIELD_TYPE"),
    ],
)
def test_strict_schema_errors_do_not_copy_rejected_values(field, value, constraint):
    response = scored_response()
    response["findings"][0][field] = value
    detail = rejection(json.dumps(response))
    assert detail.schema_issues[0].constraint == constraint
    assert detail.schema_issues[0].field == field
    assert detail.schema_issues[0].finding_index == 0
    assert "secret-unrecognized-value" not in detail.model_dump_json()


@pytest.mark.parametrize("field", ["schema_version", "summary", "findings"])
def test_missing_root_fields_are_named_without_inventing_a_claim_index(field):
    response = scored_response()
    del response[field]
    issue = rejection(json.dumps(response)).schema_issues[0]
    assert issue.constraint == "REQUIRED_FIELD"
    assert issue.field == field and issue.finding_index is None


@pytest.mark.parametrize("field", ["kind", "violated_invariant", "root_cause_ref"])
def test_missing_nullable_fields_remain_required(field):
    response = scored_response(advisory=True)
    del response["findings"][0][field]
    issue = rejection(json.dumps(response)).schema_issues[0]
    assert issue.constraint == "REQUIRED_FIELD"
    assert issue.field == field and issue.finding_index == 0


@pytest.mark.parametrize("origin", [False, True])
def test_reversed_lines_are_not_repaired(origin):
    response = scored_response()
    location = response["findings"][0]
    if origin:
        location = location["root_cause_ref"]
    location["line_start"] = 47
    issue = rejection(json.dumps(response)).schema_issues[0]
    assert issue.constraint == "LINE_ORDER"
    assert issue.field == ("root_cause_ref" if origin else "finding")
    assert issue.finding_index == 0


@pytest.mark.parametrize("field", ["filename", "line_start", "line_end"])
def test_origin_schema_coordinates_are_fixed_names(field):
    response = scored_response()
    response["findings"][0]["root_cause_ref"][field] = (
        "../synthetic-private-name.sol" if field == "filename" else False
    )
    detail = rejection(json.dumps(response))
    assert detail.schema_issues[0].field == "root_cause_ref." + field
    assert "synthetic-private-name" not in detail.model_dump_json()


@pytest.mark.parametrize("location", ["root", "finding", "origin"])
@pytest.mark.parametrize("key", ["unexpected-private-field", "root_cause_ref.filename", "input"])
def test_unknown_field_names_never_escape_the_projection(location, key):
    response = scored_response()
    destination = response
    expected, index = "response", None
    if location in {"finding", "origin"}:
        destination = response["findings"][0]
        expected, index = "finding", 0
    if location == "origin":
        destination = destination["root_cause_ref"]
        expected = "root_cause_ref"
    destination[key] = "synthetic-sensitive-value"
    detail = rejection(json.dumps(response))
    issue = detail.schema_issues[0]
    assert issue.constraint == "EXTRA_FIELD"
    assert issue.field == expected and issue.finding_index == index
    assert "synthetic-sensitive-value" not in detail.model_dump_json()
    assert "unexpected-private-field" not in detail.model_dump_json()


@pytest.mark.parametrize("count", [8, 9, 40])
def test_diagnostics_retain_only_a_bounded_prefix_and_truthful_truncation(count):
    response = scored_response()
    for index in range(count):
        response["unknown-private-key-" + str(index)] = "ignored-sensitive-value"
    detail = rejection(json.dumps(response))
    assert len(detail.schema_issues) == min(count, MAX_DEVELOPMENT_SCHEMA_ISSUES)
    assert detail.schema_issues_truncated is (count > MAX_DEVELOPMENT_SCHEMA_ISSUES)
    assert len(detail.model_dump_json()) < 1800
    assert "private-key" not in detail.model_dump_json()


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("{", "INVALID_JSON_SYNTAX"),
        ('{"summary":"one","summary":"two"}', "DUPLICATE_OBJECT_KEY"),
        ('{"summary":NaN}', "NON_FINITE_NUMBER"),
        ('{"summary":1e999}', "NON_FINITE_NUMBER"),
        ("```json\n{}\n```", "INVALID_JSON_SYNTAX"),
    ],
)
def test_syntax_failures_remain_distinct_without_a_schema_revalidation(content, code):
    detail = rejection(content)
    assert detail.structured_failure == code
    assert detail.schema_issues == () and detail.schema_issues_truncated is False


def test_successful_diagnostic_revalidation_never_overrides_original_refusal(monkeypatch):
    def original_refusal(*_args, **_kwargs):
        raise StructuredOutputDecodeError(StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED)

    monkeypatch.setattr(transport_module, "decode_structured_output", original_refusal)
    detail = rejection(json.dumps(scored_response()))
    assert detail.structured_failure == "SCHEMA_VALIDATION_FAILED"
    assert detail.schema_issues == ()


def test_schema_generation_drift_leaves_detail_unknown(monkeypatch):
    model = DevelopmentScoredReviewResponse

    def changed_generation(*_args, **_kwargs):
        monkeypatch.setattr(model, "__pydantic_core_schema__", {})
        raise StructuredOutputDecodeError(StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED)

    monkeypatch.setattr(transport_module, "decode_structured_output", changed_generation)
    detail = rejection("{}")
    assert detail.structured_failure == "SCHEMA_VALIDATION_FAILED"
    assert detail.schema_issues == ()


def test_unknown_model_validation_code_is_generic_and_never_copies_context():
    class SyntheticModel(BaseModel):
        field: int

    with pytest.raises(ValidationError) as caught:
        SyntheticModel.model_validate({"field": "sensitive-non-integer"})
    issues, truncated = project_development_schema_failure(caught.value)
    assert issues[0].constraint == "SCHEMA_CONSTRAINT"
    assert issues[0].field == "response"
    assert issues[0].finding_index is None and truncated is False
    assert "sensitive" not in issues[0].model_dump_json()


@pytest.mark.parametrize("index", [-1, 16, True, "0"])
def test_schema_coordinate_rejects_unbounded_or_coerced_indexes(index):
    with pytest.raises(ValidationError):
        DevelopmentSchemaIssue.model_validate_json(
            json.dumps({"constraint": "FIELD_TYPE", "field": "line_end", "finding_index": index})
        )


@pytest.mark.parametrize(
    "change",
    ["stage", "reason", "structured", "truncation", "issue_count", "index", "field", "extra"],
)
def test_forged_rejection_details_fail_closed(change):
    values: dict[str, Any] = rejection("{}").model_dump(mode="json")
    if change == "stage":
        values["stage"] = "SOURCE_SCOPE"
    elif change == "reason":
        values["reason"] = "untrusted-provider-reason"
    elif change == "structured":
        values["structured_failure"] = "INVALID_JSON_SYNTAX"
    elif change == "truncation":
        values["schema_issues_truncated"] = True
    elif change == "issue_count":
        values["schema_issues"] *= 9
    elif change == "index":
        values["finding_index"] = 0
    elif change == "field":
        values["schema_issues"][0]["field"] = "untrusted-private-field"
    else:
        values["raw_response"] = "sensitive-prose"
    with pytest.raises(ValidationError):
        DevelopmentResponseRejection.model_validate_json(json.dumps(values))


def test_legacy_successful_observation_keeps_its_prechange_serialized_bytes():
    observation = complete_audit_observation()
    raw = observation.model_dump_json()
    assert "rejection_evidence" not in raw
    assert hashlib.sha256(raw.encode()).hexdigest() == (
        "b07c014f29ce36f215444fafaaad3e8dae46e0635e89df9a05d70bdf76bf810b"
    )
    assert type(observation).model_validate_json(raw) == observation


@pytest.mark.parametrize("change", ["extra", "field", "count", "index"])
def test_canonical_rejection_schema_is_closed_and_bounded(change):
    from scripts.generate_release_schemas import MODELS, rendered_schema

    filename = "development_response_rejection.schema.json"
    content = (Path(__file__).parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    value = rejection("{}").model_dump(mode="json")
    assert validator.is_valid(value)
    if change == "extra":
        value["raw_output"] = "private-canary"
    elif change == "field":
        value["schema_issues"][0]["field"] = "unknown-private-field"
    elif change == "count":
        value["schema_issues"] *= 9
    else:
        value["schema_issues"][0]["finding_index"] = 16
    assert not validator.is_valid(value)


@pytest.mark.parametrize(
    "change", ["observed", "diagnostic", "http", "no_hash", "hash_mismatch", "json_without_hash"]
)
def test_parent_observation_cannot_misbind_or_promote_rejection_detail(change):
    value = scored_observation().observations[0].model_dump(mode="json")
    detail = rejection("{}").model_dump(mode="json")
    detail["response_sha256"] = value["response_sha256"]
    value.update(
        status="INCOMPLETE",
        diagnostics=["INVALID_RESPONSE"],
        response=None,
        rejection_evidence=detail,
    )
    assert (
        DevelopmentScoredAuditShardObservation.model_validate_json(json.dumps(value)).status
        == "INCOMPLETE"
    )
    if change == "observed":
        value["status"] = "OBSERVED"
    elif change == "diagnostic":
        value["diagnostics"] = ["TIMEOUT"]
    elif change == "http":
        value["http_status"] = 500
    elif change == "hash_mismatch":
        detail["response_sha256"] = "a" * 64
    else:
        detail["response_sha256"] = value["response_sha256"] = None
        if change == "json_without_hash":
            detail.update(
                stage="HTTP_BODY", reason="RESPONSE_JSON", structured_failure=None, schema_issues=[]
            )
    with pytest.raises(ValidationError):
        DevelopmentScoredAuditShardObservation.model_validate_json(json.dumps(value))
