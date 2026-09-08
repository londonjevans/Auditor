"""V2 representation must not change v1 meaning or confer correctness by declaration."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from pydantic import ValidationError

from mmaudit.models.development_audit import DevelopmentAuditPlan, development_shard_request_id
from mmaudit.models.development_review import (
    DevelopmentReviewResponse,
    DevelopmentScoredReviewResponse,
)
from tests.development_audit_support import audit_case
from tests.development_benchmark_support import scored_audit_case, scored_response


@pytest.mark.parametrize("advisory", [False, True])
def test_v2_represents_advisories_without_asserting_a_violation(advisory: bool) -> None:
    response = DevelopmentScoredReviewResponse.model_validate_json(
        json.dumps(scored_response(advisory=advisory)), strict=True
    )
    finding = response.findings[0]
    assert (finding.violated_invariant is None) is advisory
    assert (finding.root_cause_ref is None) is advisory
    assert (finding.vulnerability_class is None) is advisory
    with pytest.raises(ValidationError):
        DevelopmentReviewResponse.model_validate_json(response.model_dump_json(), strict=True)


@pytest.mark.parametrize("field", ["violated_invariant", "root_cause_ref", "vulnerability_class"])
@pytest.mark.parametrize("advisory", [False, True])
def test_kind_and_nullable_fields_cannot_disagree(field: str, advisory: bool) -> None:
    response = scored_response(advisory=advisory)
    response["findings"][0][field] = scored_response()["findings"][0][field] if advisory else None
    with pytest.raises(ValidationError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize(
    "change",
    ["missing_version", "legacy_version", "wrong_kind", "reversed", "bool_line", "authority"],
)
def test_v2_rejects_ambiguous_version_lines_and_extra_authority(change: str) -> None:
    response = scored_response()
    finding = response["findings"][0]
    if change == "missing_version":
        del response["schema_version"]
    elif change == "legacy_version":
        response["schema_version"] = "1.0"
    elif change == "wrong_kind":
        finding["kind"] = "verified"
    elif change == "reversed":
        finding["root_cause_ref"]["line_start"] = 47
    elif change == "bool_line":
        finding["line_start"] = True
    else:
        finding["findings_validated"] = True
    with pytest.raises(ValidationError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize("filename", ["../RoutePolicy.sol", "/RoutePolicy.sol", "nested/File.sol"])
def test_origin_reference_cannot_select_a_filesystem_path(filename: str) -> None:
    response = scored_response()
    response["findings"][0]["root_cause_ref"]["filename"] = filename
    with pytest.raises(ValidationError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


def test_v2_plan_and_requests_are_explicit_and_distinct_from_v1() -> None:
    legacy = audit_case(run_id="local-scored-review")
    scored = scored_audit_case()
    assert legacy.plan.schema_version == "1.0"
    assert scored.plan.schema_version == "2.0"
    assert legacy.plan.plan_sha256 != scored.plan.plan_sha256
    for old, new in zip(legacy.shards, scored.shards, strict=True):
        assert new.schema_version == "2.0"
        assert old.source_files == new.source_files
        assert old.estimate.request_id != new.estimate.request_id
        assert old.request_content != new.request_content
        body = json.loads(new.request_content)
        assert body["response_format"]["json_schema"]["name"].endswith("_v2")
        assert body["provider"] == json.loads(old.request_content)["provider"]
        assert body["reasoning"] == {"effort": "high"}
    assert DevelopmentAuditPlan.model_validate_json(scored.plan.model_dump_json()) == scored.plan


def test_plan_cannot_relabel_a_legacy_estimate_as_a_v2_request() -> None:
    legacy = audit_case()
    values = legacy.plan.model_dump(mode="json")
    values["schema_version"] = "2.0"
    with pytest.raises(ValidationError):
        DevelopmentAuditPlan.model_validate_json(json.dumps(values), strict=True)


def test_prepared_version_participates_in_exact_rebuild_equality() -> None:
    scored = scored_audit_case()
    assert replace(scored.shards[0], schema_version="1.0") != scored.shards[0]
    with pytest.raises(ValueError, match="version"):
        development_shard_request_id("local", "unit-ledger-a-v1", "RoutePolicy.sol", "3.0")  # type: ignore[arg-type]
