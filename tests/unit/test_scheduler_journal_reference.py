"""Fail-closed identity tests for detached retained scheduler journals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.scheduler import SchedulerRetainedJournalReference
from scripts.generate_release_schemas import rendered_schema
from tests.scheduler_support import build_complete_scheduler_artifact

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_FILENAME = "scheduler_retained_journal_reference.schema.json"


def _reference() -> SchedulerRetainedJournalReference:
    return SchedulerRetainedJournalReference.from_artifact(
        owner_run_id="20260802T100000Z-aabbccdd",
        consumer_run_id="20260802T110000Z-11223344",
        artifact=build_complete_scheduler_artifact(seed="retained-journal-reference"),
    )


def test_retained_journal_reference_binds_one_exact_physical_owner() -> None:
    artifact = build_complete_scheduler_artifact(seed="retained-journal-reference")
    reference = _reference()

    assert reference.ownership_mode == "physical_private_journal"
    assert reference.relative_journal_path == "20260802T100000Z-aabbccdd/private/scheduler-journal"
    reference.require_exact(
        owner_run_id="20260802T100000Z-aabbccdd",
        consumer_run_id="20260802T110000Z-11223344",
        artifact=artifact,
    )

    different_artifact = build_complete_scheduler_artifact(seed="different-owner-artifact")
    with pytest.raises(ValueError, match="differs from its owner and artifact"):
        reference.require_exact(
            owner_run_id="20260802T100000Z-aabbccdd",
            consumer_run_id="20260802T110000Z-11223344",
            artifact=different_artifact,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("owner_run_id", "latest", "safe basenames"),
        ("owner_run_id", "../owner", "safe basenames"),
        ("consumer_run_id", "consumer/run", "safe basenames"),
        (
            "relative_journal_path",
            "other/private/scheduler-journal",
            "one prior physical journal",
        ),
        (
            "relative_journal_path",
            "20260802T100000Z-aabbccdd/private/../scheduler-journal",
            "one prior physical journal",
        ),
    ),
)
def test_retained_journal_reference_rejects_basename_and_path_substitution(
    field: str,
    value: str,
    message: str,
) -> None:
    payload = _reference().model_dump(mode="python")
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        SchedulerRetainedJournalReference.model_validate(payload)


def test_retained_journal_reference_rejects_self_reference_chain_and_tamper() -> None:
    payload = _reference().model_dump(mode="python")
    payload["consumer_run_id"] = payload["owner_run_id"]
    with pytest.raises(ValidationError, match="cannot target its own run"):
        SchedulerRetainedJournalReference.model_validate(payload)

    payload = _reference().model_dump(mode="python")
    payload["scheduler_artifact_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        SchedulerRetainedJournalReference.model_validate(payload)

    payload = _reference().model_dump(mode="python")
    payload["owner_reference_sha256"] = "e" * 64
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SchedulerRetainedJournalReference.model_validate(payload)


def test_retained_journal_reference_schema_is_exact_and_strict() -> None:
    schema_path = ROOT / "schemas" / SCHEMA_FILENAME
    observed = schema_path.read_text(encoding="utf-8")
    assert observed == rendered_schema(SCHEMA_FILENAME, SchedulerRetainedJournalReference)

    schema = json.loads(observed)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["ownership_mode"]["const"] == "physical_private_journal"
    assert schema["properties"]["evidence_authority"]["const"] == "comparison_required"
    assert schema["properties"]["schema_version"]["const"] == "1.0"
