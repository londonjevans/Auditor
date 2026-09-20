"""Retained truncated proposals remain exact, bounded and outside all finding credit."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

import mmaudit.models.provisional_findings as model_module
import mmaudit.reporting.markdown as markdown_module
from mmaudit.models.provisional_findings import (
    PROVISIONAL_FINDINGS_METADATA_KEY,
    ProvisionalFindingInventory,
    provisional_findings_from_metadata,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    CandidateReviewTruncationProjection,
    _canonical_sha256,
)
from mmaudit.reporting.bundle import build_coverage_artifact, build_findings_artifact
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.run_authority import RunTerminalReportAuthority
from mmaudit.reporting.status import effective_report_status
from tests.channel_retention_support import VALID_FINDING_IDS, channel_projection
from tests.unit.test_client_forensic_reporting import _report
from tests.unit.test_truncation import _candidate
from tests.unit.test_truncation_recovery_journal import _projection, _requested_surfaces


def _inventory_payload(
    *,
    state: CandidateReviewChannelState = CandidateReviewChannelState.OPEN,
    child: bool = False,
    projection: CandidateReviewTruncationProjection | None = None,
) -> dict[str, Any]:
    """Build comparison-only synthetic data; this helper never claims original custody."""

    if projection is None:
        _, surfaces = _requested_surfaces(7)
        projection = channel_projection(surfaces, state=state, retained_count=1)
    frames = {
        frame.record_id: frame
        for frame in projection.accepted_frames
        if frame.phase is CandidateReviewFramePhase.FINDING
    }
    prefix = "scheduler-recovery-" if child else "scheduler-"
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_authority": "comparison_required",
        "campaign_id": "scheduler-campaign-" + "a" * 64,
        "manifest_sha256": "b" * 64,
        "journal_evidence_sha256": "c" * 64,
        "scheduler_artifact_sha256": "d" * 64,
        "sources": [
            {
                "source_kind": "recovery_child" if child else "scheduler_parent",
                "source_entry_sha256": "e" * 64,
                "task_id": prefix + "task-" + "f" * 64,
                "request_id": prefix + "request-" + "1" * 64,
                "request_role": "source_audit",
                "usage_record_sha256": "2" * 64,
                "original_response_sha256": projection.original_response_sha256,
                "truncation_projection_sha256": projection.evidence_sha256,
                "algorithm_version": "mmaudit.seven-pass-scheduler.v2",
                "findings_state": projection.findings_state.value,
                "surface_reviews_state": projection.surface_reviews_state.value,
                "summary_state": projection.summary_state.value,
                "declared_finding_count": projection.declared_finding_count,
                "records": [
                    {
                        "candidate": finding.model_dump(mode="json"),
                        "retained_frame": frames[finding.candidate_id].model_dump(mode="json"),
                    }
                    for finding in projection.findings
                ],
            }
        ],
        "retained_finding_count": len(projection.findings),
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "validated_finding_authorized": False,
        "completion_authorized": False,
    }
    _rehash(payload)
    return payload


def _rehash(payload: dict[str, Any]) -> None:
    payload["inventory_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "inventory_sha256"}
    )


def _metadata(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        PROVISIONAL_FINDINGS_METADATA_KEY: payload,
        "scheduler": {
            key: payload[key]
            for key in (
                "campaign_id",
                "manifest_sha256",
                "journal_evidence_sha256",
                "scheduler_artifact_sha256",
            )
        },
    }


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
@pytest.mark.parametrize("child", [False, True])
def test_provisional_inventory_retains_exact_records_without_credit(
    state: CandidateReviewChannelState, child: bool
) -> None:
    payload = _inventory_payload(state=state, child=child)
    inventory = provisional_findings_from_metadata(_metadata(payload))
    assert inventory is not None
    assert inventory.model_dump(mode="json") == payload
    assert inventory.retained_finding_count == 2
    assert (
        tuple(record.candidate.candidate_id for record in inventory.sources[0].records)
        == VALID_FINDING_IDS
    )
    assert inventory.sources[0].findings_state is state
    assert not inventory.review_credit_authorized
    assert not inventory.coverage_credit_authorized
    assert not inventory.validated_finding_authorized
    assert not inventory.completion_authorized
    encoded = inventory.model_dump_json()
    assert (
        ProvisionalFindingInventory.model_validate_json(encoded, strict=True).model_dump_json()
        == encoded
    )
    assert "synthetic-partial" not in encoded
    assert "synthetic-invalid-confidence" not in encoded


@pytest.mark.parametrize(
    "field",
    [
        "review_credit_authorized",
        "coverage_credit_authorized",
        "validated_finding_authorized",
        "completion_authorized",
    ],
)
@pytest.mark.parametrize("value", [True, 0, "false", None])
def test_provisional_inventory_refuses_rehashed_authority(field: str, value: object) -> None:
    payload = _inventory_payload()
    payload[field] = value
    _rehash(payload)
    with pytest.raises(ValueError, match="cannot authorize credit"):
        provisional_findings_from_metadata(_metadata(payload))


@pytest.mark.parametrize(
    "field",
    [
        "review_credit_authorized",
        "coverage_credit_authorized",
        "validated_finding_authorized",
        "completion_authorized",
    ],
)
def test_provisional_inventory_requires_explicit_noncrediting_fields(field: str) -> None:
    payload = _inventory_payload()
    del payload[field]
    with pytest.raises(ValueError):
        provisional_findings_from_metadata(_metadata(payload))


def test_terminal_report_binding_rejects_coherently_rehashed_provisional_substitution() -> None:
    report = _report(completed=False)
    payload = _inventory_payload()
    report.metadata.update(_metadata(payload))
    authority = RunTerminalReportAuthority.build(report)
    changed = report.model_copy(deep=True)
    substituted = changed.metadata[PROVISIONAL_FINDINGS_METADATA_KEY]
    substituted["sources"][0]["original_response_sha256"] = "0" * 64
    _rehash(substituted)
    assert provisional_findings_from_metadata(changed.metadata) is not None
    with pytest.raises(
        ValueError, match="public report differs from private terminal report authority"
    ):
        authority.require_exact_report(changed)


@pytest.mark.parametrize(
    "change",
    [
        "finding",
        "frame_identity",
        "frame_phase",
        "duplicate_record",
        "record_order",
        "declared_count",
        "retained_count",
        "boolean_count",
        "source_kind",
        "unstarted",
        "duplicate_source",
        "source_entry",
        "unknown_field",
        "hash",
    ],
)
def test_provisional_inventory_refuses_inconsistent_records_after_rehash(change: str) -> None:
    payload = _inventory_payload()
    source = payload["sources"][0]
    if change == "finding":
        source["records"][0]["candidate"]["confidence"] = 0.7
    elif change == "frame_identity":
        source["records"][0]["retained_frame"]["record_id"] = "other-record"
    elif change == "frame_phase":
        source["records"][0]["retained_frame"].update(phase="SUMMARY", record_id=None)
    elif change == "duplicate_record":
        source["records"].append(copy.deepcopy(source["records"][0]))
        payload["retained_finding_count"] = 3
    elif change == "record_order":
        source["records"].reverse()
    elif change == "declared_count":
        source["declared_finding_count"] = 1
    elif change == "retained_count":
        payload["retained_finding_count"] = 3
    elif change == "boolean_count":
        source["declared_finding_count"] = True
    elif change == "source_kind":
        source["source_kind"] = "recovery_child"
    elif change == "unstarted":
        source["findings_state"] = "NOT_STARTED"
    elif change in {"duplicate_source", "source_entry"}:
        duplicate = copy.deepcopy(source)
        if change == "source_entry":
            duplicate["request_id"] = "scheduler-request-" + "3" * 64
        payload["sources"].append(duplicate)
        payload["retained_finding_count"] = 4
    elif change == "unknown_field":
        source["validated"] = True
    _rehash(payload)
    if change == "hash":
        payload["inventory_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        provisional_findings_from_metadata(_metadata(payload))


@pytest.mark.parametrize(
    "field",
    ["campaign_id", "manifest_sha256", "journal_evidence_sha256", "scheduler_artifact_sha256"],
)
def test_provisional_metadata_requires_exact_report_scheduler_join(field: str) -> None:
    metadata = _metadata(_inventory_payload())
    metadata["scheduler"][field] = "0" * 64
    with pytest.raises(ValueError, match="report scheduler binding"):
        provisional_findings_from_metadata(metadata)


@pytest.mark.parametrize("value", [None, [], "{}", 0])
def test_provisional_metadata_cannot_hide_an_invalid_explicit_inventory(value: object) -> None:
    assert provisional_findings_from_metadata({}) is None
    with pytest.raises(ValueError, match="explicit object"):
        provisional_findings_from_metadata({PROVISIONAL_FINDINGS_METADATA_KEY: value})


def test_provisional_metadata_enforces_its_exact_byte_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _inventory_payload()
    size = len(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )
    monkeypatch.setattr(model_module, "MAX_JSON_ARTIFACT_BYTES", size)
    assert provisional_findings_from_metadata(_metadata(payload)) is not None
    monkeypatch.setattr(model_module, "MAX_JSON_ARTIFACT_BYTES", size - 1)
    with pytest.raises(ValueError, match="byte bound"):
        provisional_findings_from_metadata(_metadata(payload))


def test_provisional_report_visibility_does_not_change_candidates_coverage_or_status() -> None:
    report = _report(completed=False)
    original = report.model_copy(deep=True)
    report.metadata.update(_metadata(_inventory_payload()))
    assert report.findings == report.rejected_findings == report.filtered_findings == []
    assert not build_findings_artifact(report).candidate_findings
    assert build_coverage_artifact(report) == build_coverage_artifact(original)
    assert effective_report_status(report) == effective_report_status(original)
    for rendered in (
        render_markdown(report),
        render_forensic_markdown(report),
        render_client_markdown(report, {}),
    ):
        assert "Retained provisional findings — not validated" in rendered
        assert "2 complete proposed finding record(s)" in rendered
        assert all(identity in rendered for identity in VALID_FINDING_IDS)
        assert "not accepted or confirmed findings" in rendered
        assert "metadata.provisional_truncated_findings" in rendered


def test_provisional_rendering_escapes_untrusted_text_without_losing_json_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, surfaces = _requested_surfaces(7)
    findings = tuple(
        _candidate(f"bounded-provisional-{index:02}").model_copy(
            update={"title": "<script>fixture()</script> [link](javascript:fixture)\x1b"}
        )
        for index in range(3)
    )
    projection = _projection(surfaces, findings=findings, retained_count=1)
    payload = _inventory_payload(projection=projection)
    report = _report(completed=False)
    report.metadata.update(_metadata(payload))
    monkeypatch.setattr(markdown_module, "_MAX_PROVISIONAL_FINDING_ROWS", 2)
    for rendered in (
        render_markdown(report),
        render_forensic_markdown(report),
        render_client_markdown(report, {}),
    ):
        assert "<script>" not in rendered
        assert "\x1b" not in rendered
        assert "&lt;script&gt;" in rendered
        assert "bounded-provisional-00" in rendered
        assert "bounded-provisional-01" in rendered
        assert "bounded-provisional-02" not in rendered
        assert "1 further provisional record(s)" in rendered
    assert provisional_findings_from_metadata(report.metadata).retained_finding_count == 3
    assert report.metadata[PROVISIONAL_FINDINGS_METADATA_KEY] == payload
