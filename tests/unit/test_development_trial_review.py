"""Non-authorizing review consistency and characterization of the existing v1 schema.

These checks do not authenticate private requests or validate reported findings. A
versioned successor should replace the v1 limitation, not rewrite this trial history.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.development_audit import DevelopmentAuditObservation
from mmaudit.models.development_review import (
    DEVELOPMENT_FIXTURE_PINS,
    DevelopmentReviewObservation,
    DevelopmentReviewResponse,
)
from scripts.validate_governance_state import AUTHORITY_FIELDS

ROOT = Path(__file__).resolve().parents[2]
REVIEW_PATH = ROOT / "docs/remediation/v3/development_trial_review.json"
HEADINGS = re.compile(r"^## (\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?Z) ", re.MULTILINE)
CHARACTERIZATION_PATH = "tests/fixtures/model_responses/development_advisory_characterization.json"


def _review() -> dict[str, Any]:
    result = json.loads(REVIEW_PATH.read_text())
    assert type(result) is dict
    return result


def test_review_remains_documentation_only_with_no_promoted_authority() -> None:
    review = _review()
    assert review["artifact_kind"] == "documentation_only_development_trial_review"
    assert review["evidence_class"] == "OPERATOR_REPORTED_NOT_INDEPENDENTLY_AUTHENTICATED"
    assert review["review_status"] == "PARTIAL"
    assert review["completed_real_audits"] == 0
    for field in (
        *AUTHORITY_FIELDS,
        "remote_request_bytes_inspected",
        "private_response_bytes_inspected",
        "private_ledger_bytes_inspected",
        "findings_validated",
        "audit_complete",
        "qualification_eligible",
        "release_eligible",
    ):
        assert review[field] is False
    assert review["reported_accounting"]["private_ledger_authenticated"] is False
    assert review["schema_characterization"]["characterization_is_quality_evidence"] is False


def test_review_binds_historical_report_and_dated_sections() -> None:
    report = _review()["operator_report"]
    assert report["path"] == "docs/remediation/v3/operator_results.md"
    current = (ROOT / report["path"]).read_text()
    headings = list(HEADINGS.finditer(current))
    by_timestamp = {match[1]: index for index, match in enumerate(headings)}
    assert len(by_timestamp) == len(headings), "duplicate report timestamps are ambiguous"
    start = headings[by_timestamp[report["sections"][0]["timestamp"]]].start()
    retained = (current[: headings[0].start()] + current[start:]).encode()
    assert hashlib.sha256(retained).hexdigest() == report["raw_sha256_at_review"]
    assert len(retained) == report["bytes_at_review"]
    assert len(retained.splitlines()) == report["lines_at_review"]
    for section in report["sections"]:
        index = by_timestamp[section["timestamp"]]
        end = headings[index + 1].start() if index + 1 < len(headings) else len(current)
        content = current[headings[index].start() : end].encode()
        assert hashlib.sha256(content).hexdigest() == section["sha256"]
        assert len(content) == section["bytes"]


@pytest.mark.parametrize("filename,lines", [("ControlA.sol", 17), ("ControlB.sol", 18)])
def test_review_checks_local_fixture_bytes_without_claiming_remote_request_custody(
    filename: str, lines: int
) -> None:
    matches = [
        item for item in _review()["local_fixture_pins"] if Path(item["path"]).name == filename
    ]
    assert len(matches) == 1
    pin = matches[0]
    assert pin["path"] == f"tests/fixtures/solidity/development_review/{filename}"
    content = (ROOT / pin["path"]).read_bytes()
    assert (filename, pin["sha256"]) in DEVELOPMENT_FIXTURE_PINS
    assert hashlib.sha256(content).hexdigest() == pin["sha256"]
    assert len(content) == pin["bytes"]
    assert len(content.splitlines()) == pin["lines"] == lines
    assert b"abstract contract" in content


def test_rejected_paid_attempt_is_retained_in_reported_accounting() -> None:
    review = _review()
    attempts = review["fixture_attempts"]
    accounting = review["reported_accounting"]
    assert len({attempt["request_id"] for attempt in attempts}) == len(attempts) == 3
    rejected = [attempt for attempt in attempts if attempt["reported_status"] == "INCOMPLETE"]
    assert len(rejected) == 1
    assert rejected[0]["reported_diagnostic"] == "IDENTITY_MISMATCH"
    assert rejected[0]["reported_findings"] is None
    assert Decimal(rejected[0]["reported_cost_usd"]) == Decimal("0.0110142")
    fixture_total = sum(Decimal(attempt["reported_cost_usd"]) for attempt in attempts)
    assert fixture_total == Decimal(accounting["fixture_used_usd"]) == Decimal("0.0340674")
    corpora = review["reported_corpus_observations"]
    corpus_total = sum(Decimal(corpus["reported_cost_usd"]) for corpus in corpora)
    assert fixture_total + corpus_total == Decimal(accounting["development_used_usd"])
    assert accounting["development_used_usd"] == "0.2606400"
    assert len(attempts) + sum(corpus["reported_shards"] for corpus in corpora) == 9
    assert accounting["development_entries"] == 9
    assert accounting["cumulative_entries"] == 57
    assert accounting["cumulative_used_usd"] == "0.68118684"
    assert accounting["arithmetic_is_execution_or_spend_authority"] is False


def test_missing_fixture_runtime_cannot_borrow_corpus_runtime_or_generation_ids() -> None:
    review = _review()
    for attempt in review["fixture_attempts"]:
        assert attempt["elapsed_seconds"] is None
        assert attempt["runtime_status"] == "INCONCLUSIVE"
    assert review["acceptance"]["fixture_runtime"] == "INCONCLUSIVE_ABSENT"
    assert "elapsed_seconds" not in DevelopmentReviewObservation.model_fields
    assert "elapsed_seconds" in DevelopmentAuditObservation.model_fields
    assert [
        corpus["reported_elapsed_seconds"] for corpus in review["reported_corpus_observations"]
    ] == [
        "86.5",
        "102.7",
    ]


def test_guarded_advisories_and_cross_file_duplicates_are_not_a_quality_pass() -> None:
    review = _review()
    scoring = review["reported_fixture_scoring"]
    assert scoring["strict_invariant_false_positives"] == scoring["guarded_advisories"] == 2
    assert scoring["guarded_medium_or_higher"] == 0
    assert scoring["severity_filter_is_not_a_replacement_score"] is True
    assert scoring["independently_validated_findings"] == 0
    for corpus in review["reported_corpus_observations"]:
        assert corpus["aggregate_unique_root_causes"] is None
        assert corpus["quality_score"] is None


def test_existing_v1_decoder_accepts_structural_advisory_with_forced_invariant_field() -> None:
    """Characterize the gap: structural decoding does not validate the stated invariant."""

    assert _review()["schema_characterization"]["fixture"] == CHARACTERIZATION_PATH
    path = ROOT / CHARACTERIZATION_PATH
    decoded = DevelopmentReviewResponse.model_validate_json(path.read_bytes(), strict=True)
    assert len(decoded.findings) == 1
    assert "not a demonstrated authorization violation" in decoded.findings[0].explanation
    assert decoded.findings[0].violated_invariant
    assert "kind" not in type(decoded.findings[0]).model_fields
    assert "root_cause_ref" not in type(decoded.findings[0]).model_fields


@pytest.mark.parametrize("change", ["missing", "null"])
def test_existing_v1_schema_cannot_represent_an_advisory_without_a_violation(change: str) -> None:
    assert _review()["schema_characterization"]["fixture"] == CHARACTERIZATION_PATH
    path = ROOT / CHARACTERIZATION_PATH
    data = json.loads(path.read_text())
    if change == "missing":
        del data["findings"][0]["violated_invariant"]
    else:
        data["findings"][0]["violated_invariant"] = None
    with pytest.raises(ValidationError, match="violated_invariant"):
        DevelopmentReviewResponse.model_validate_json(json.dumps(data), strict=True)
