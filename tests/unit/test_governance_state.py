"""Development coordination must not replace history or confer audit authority."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.validate_governance_state import (
    AUTHORITY_FIELDS,
    CURRENT_STATE_KEY,
    HISTORICAL_PAYLOAD_SHA256S,
    EngineeringState,
    OperatorObservation,
    combined_queue_statuses,
    validate_governance_documents,
    validate_governance_state,
    validate_operator_observation,
)
from tests.governance_state_support import (
    FIXTURES,
    HISTORICAL_TIMESTAMP,
    LATEST_TIMESTAMP,
    prepend_report,
    synthetic_operator_history,
    synthetic_operator_observation,
)

ROOT = Path(__file__).parents[2]


def test_make_check_runs_read_only_governance_before_the_full_suite() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    check = next(line for line in makefile.splitlines() if line.startswith("check:")).split()[1:]
    assert check.index("governance") < check.index("test")
    assert "test: governance\n\t$(PYTHON) -m pytest" in makefile
    assert "governance:\n\t$(PYTHON) scripts/validate_governance_state.py" in makefile


def _documents() -> dict[str, dict]:
    return {name: json.loads((ROOT / name).read_bytes()) for name in HISTORICAL_PAYLOAD_SHA256S}


def test_current_governance_record_matches_queues_artifacts_and_headers() -> None:
    result = validate_governance_state(ROOT)
    assert result.provider_call_authorized is False
    assert result.release_authorized is False
    assert result.operator.completed_real_audits == 0


@pytest.mark.parametrize(
    "mutation", ("count", "queue_hash", "artifact_hash", "header", "selection")
)
def test_governance_validation_rejects_current_state_drift(mutation: str) -> None:
    documents = _documents()
    first = next(iter(documents.values()))[CURRENT_STATE_KEY]
    if mutation == "count":
        first["unfinished_ticket_count"] += 1
    elif mutation == "queue_hash":
        first["queue_statuses_sha256"] = "0" * 64
    elif mutation == "artifact_hash":
        first["artifact_sha256s"]["config/models.selection-plan.json"] = "0" * 64
    elif mutation == "header":
        first["updated_at"] = "2026-09-07T00:00:00Z"
    else:
        first["current_ticket"] = "V3-SINGLE-AUDIT-001"
        first["current_ticket_status"] = "IN_PROGRESS"
    for document in documents.values():
        document[CURRENT_STATE_KEY] = copy.deepcopy(first)
    expected = (
        "artifact binding"
        if mutation == "artifact_hash"
        else "worklog header"
        if mutation == "header"
        else "differs from the queues"
    )
    with pytest.raises(ValueError, match=expected):
        validate_governance_documents(ROOT, documents)


@pytest.mark.parametrize("target", tuple(HISTORICAL_PAYLOAD_SHA256S))
@pytest.mark.parametrize("mutation", ("history", "coherent_reseal", "missing_scope", "mirror"))
def test_governance_validation_preserves_historical_payloads_and_exact_mirrors(
    target: str, mutation: str
) -> None:
    documents = _documents()
    changed = documents[target]
    if mutation in {"history", "coherent_reseal"}:
        changed["schema_version"] = "untrusted-history"
        if mutation == "coherent_reseal":
            from scripts.validate_governance_state import historical_payload_sha256

            changed["historical_payload_sha256"] = historical_payload_sha256(changed)
    elif mutation == "missing_scope":
        del changed["governance_state_scope"]
    else:
        changed[CURRENT_STATE_KEY]["unfinished_ticket_count"] += 1
    with pytest.raises(ValueError):
        validate_governance_documents(ROOT, documents)


@pytest.mark.parametrize("value", (True, 0, "false", None))
@pytest.mark.parametrize("field", AUTHORITY_FIELDS)
def test_governance_state_requires_literal_false_authority(field: str, value: object) -> None:
    payload = next(iter(_documents().values()))[CURRENT_STATE_KEY]
    payload[field] = value
    with pytest.raises(ValueError):
        EngineeringState.model_validate(payload)


@pytest.mark.parametrize(
    "mutation", ("extra", "boolean_count", "missing", "false_real_audit", "unexpected_path")
)
def test_governance_state_rejects_malformed_or_promoted_records(mutation: str) -> None:
    payload = next(iter(_documents().values()))[CURRENT_STATE_KEY]
    if mutation == "extra":
        payload["unreviewed_override"] = True
    elif mutation == "boolean_count":
        payload["unfinished_ticket_count"] = True
    elif mutation == "missing":
        del payload["artifact_sha256s"]
    elif mutation == "false_real_audit":
        payload["operator"]["completed_real_audits"] = 1
    else:
        payload["artifact_sha256s"]["outside-the-fixed-scope.json"] = "0" * 64
    with pytest.raises(ValueError):
        EngineeringState.model_validate(payload)


@pytest.mark.parametrize("status", ("PARTIAL", "BLOCKED_TECHNICAL", "QUEUED", "IN_PROGRESS"))
def test_queue_parser_never_counts_incomplete_status_as_complete(status: str) -> None:
    first = f"### V3-SYNTHETIC-001 — Local fixture\n\n- **Status:** `{status}`\n"
    parsed = combined_queue_statuses([first, first])
    assert parsed == {"V3-SYNTHETIC-001": status}


@pytest.mark.parametrize("mutation", ("conflict", "duplicate", "missing_status", "unknown_status"))
def test_queue_parser_rejects_ambiguous_or_unclassified_tickets(mutation: str) -> None:
    first = "### V3-SYNTHETIC-001 — Local fixture\n\n- **Status:** `QUEUED`\n"
    second = first
    if mutation == "conflict":
        second = first.replace("QUEUED", "COMPLETE")
    elif mutation == "duplicate":
        second += first
    elif mutation == "missing_status":
        second = "### V3-SYNTHETIC-001 — Local fixture\n"
    else:
        second = first.replace("QUEUED", "NOT_A_STATUS")
    with pytest.raises(ValueError):
        combined_queue_statuses([first, second])


@pytest.mark.parametrize("report_count", (0, 1, 2))
def test_operator_observation_accepts_preserved_history_and_explicit_new_facts(
    report_count: int,
) -> None:
    content, historical = synthetic_operator_history()
    original = content
    entry = (FIXTURES / "operator_new_entry.md").read_bytes()
    if report_count == 2:
        intermediate = entry.replace(b"2026-09-08T10:00:00Z", b"2026-09-07T09:25Z")
        content = prepend_report(content, intermediate)
    if report_count:
        content = prepend_report(content, entry)
        observation = synthetic_operator_observation(content)
        assert observation.raw_sha256 != historical["operator_results_sha256"]
        assert observation.reported_ledger_entries != historical["global_ledger_entry_count"]
    else:
        observation = synthetic_operator_observation(
            content, timestamp=HISTORICAL_TIMESTAMP, entries=3, amount="0.12500000"
        )
    validate_operator_observation(content, observation, historical)
    assert synthetic_operator_history()[0] == original
    assert observation.completed_real_audits == 0
    assert observation.evidence_class == "OPERATOR_REPORTED_NOT_INDEPENDENTLY_AUTHENTICATED"


@pytest.mark.parametrize(
    "layout",
    (
        "reported_shape",
        "same_line",
        "audit_on_next_line",
        "wrap_each_token",
        "wrap_with_trailing_spaces",
        "horizontal_tabs",
        "crlf",
        "following_sentence",
    ),
)
def test_operator_observation_accepts_wrapped_inline_explicit_sentences(layout: str) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_wrapped_entry.md").read_text(encoding="utf-8")
    if layout == "same_line":
        entry = entry.replace("at\n7", "at 7")
    elif layout == "audit_on_next_line":
        entry = entry.replace("USD. `completed", "USD.\n`completed")
    elif layout in {"wrap_each_token", "wrap_with_trailing_spaces", "horizontal_tabs"}:
        accounting = (
            "Ledger unchanged at 7 entries / `1.37500000` USD. `completed_real_audits` remains `0`."
        )
        separator = {
            "wrap_each_token": "\n",
            "wrap_with_trailing_spaces": "  \n  ",
            "horizontal_tabs": "\t ",
        }[layout]
        entry = entry.replace(
            accounting.replace("at 7", "at\n7"), separator.join(accounting.split())
        )
    elif layout == "crlf":
        entry = entry.replace("\n", "\r\n")
    elif layout == "following_sentence":
        entry = entry.replace("remains `0`.", "remains `0`. No external operation was performed.")
    content = prepend_report(original, entry.encode())
    observation = synthetic_operator_observation(content)
    validate_operator_observation(content, observation, historical)
    assert synthetic_operator_history()[0] == original
    assert observation.evidence_class == "OPERATOR_REPORTED_NOT_INDEPENDENTLY_AUTHENTICATED"


@pytest.mark.parametrize(
    "extra",
    (
        "Ledger now at 7 entries / `1.37500000` USD.",
        "Ledger\nnow at\n8 entries / `1.37500000` USD.",
        "Ledger now at 7 entries / `1.375e0` USD.",
        "Ledger\nnow\nat\n7 entries / `1.375e0` USD.",
        "`completed_real_audits` remains `0`.",
        "`completed_real_audits` is `1`.",
        "`completed_real_audits`\nis\n`1`.",
        "`completed_real_audits` is unknown.",
        "`completed_real_audits`\nis\nunknown.",
    ),
)
def test_operator_observation_refuses_extra_inline_or_wrapped_accounting(extra: str) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_wrapped_entry.md").read_text(encoding="utf-8")
    entry = entry.replace("remains `0`.", "remains `0`. " + extra)
    content = prepend_report(original, entry.encode())
    with pytest.raises(ValueError, match="accounting is absent or ambiguous"):
        validate_operator_observation(content, synthetic_operator_observation(content), historical)


@pytest.mark.parametrize("field", ("ledger", "audits"))
@pytest.mark.parametrize(
    "barrier",
    (
        "\n\n",
        "\n  \n",
        "\r\n\r\n",
        " <!-- omitted example --> ",
        "\n<!-- omitted example -->\n",
        "\n> Quoted example only.\n",
        "\n```text\nExample only.\n```\n",
        "\n    Indented example only.\n",
        "\n### Another section\n",
    ),
)
def test_operator_observation_never_assembles_a_fact_across_a_prose_barrier(
    field: str, barrier: str
) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_new_entry.md").read_text(encoding="utf-8")
    before, after = ("/ ", "/" + barrier) if field == "ledger" else ("is ", "is" + barrier)
    entry = entry.replace(before, after, 1)
    content = prepend_report(original, entry.encode())
    with pytest.raises(ValueError, match="accounting is absent or ambiguous"):
        validate_operator_observation(content, synthetic_operator_observation(content), historical)


@pytest.mark.parametrize(
    "mutation",
    ("prefix", "anchor_body", "older_body", "missing_anchor", "duplicate_anchor", "append_tail"),
)
def test_operator_observation_rejects_history_edits_even_after_current_digest_rebinding(
    mutation: str,
) -> None:
    content, historical = synthetic_operator_history()
    if mutation == "prefix":
        content = content.replace(b"local regression only", b"changed regression header")
    elif mutation == "anchor_body":
        content = content.replace(b"0.12500000", b"0.62500000", 1)
    elif mutation == "older_body":
        content = content.replace(b"Synthetic older report", b"Altered older report")
    elif mutation == "missing_anchor":
        content = content.replace(HISTORICAL_TIMESTAMP.encode(), b"2026-09-04T03:40Z")
    elif mutation == "duplicate_anchor":
        content += b"\n## " + HISTORICAL_TIMESTAMP.encode() + b"\n"
    else:
        content += b"\nHistorical tail changed.\n"
    content = prepend_report(content, (FIXTURES / "operator_new_entry.md").read_bytes())
    with pytest.raises(ValueError, match="historical"):
        validate_operator_observation(content, synthetic_operator_observation(content), historical)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        ("raw_sha256", "0" * 64, "current evidence binding"),
        ("byte_count", 1, "current evidence binding"),
        ("line_count", 1, "current evidence binding"),
        ("latest_entry_timestamp", HISTORICAL_TIMESTAMP, "latest identity"),
        ("reported_ledger_entries", 3, "latest reported facts"),
        ("reported_ledger_used_usd", "0.12500000", "latest reported facts"),
        ("reported_ledger_used_usd", "1.375", "latest reported facts"),
    ),
)
def test_operator_observation_rejects_stale_bindings_and_invented_summaries(
    field: str, value: object, error: str
) -> None:
    original, historical = synthetic_operator_history()
    content = prepend_report(original, (FIXTURES / "operator_new_entry.md").read_bytes())
    payload = synthetic_operator_observation(content).model_dump()
    payload[field] = value
    with pytest.raises(ValueError, match=error):
        validate_operator_observation(
            content, OperatorObservation.model_validate(payload), historical
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_ledger",
        "missing_audits",
        "duplicate_ledger",
        "duplicate_audits",
        "contradictory_ledger",
        "contradictory_audits",
        "nonzero_audits",
        "negative_amount",
        "exponent_amount",
        "unsupported_prose",
        "malformed_extra_ledger",
        "malformed_extra_audits",
        "overlong_count",
        "overlong_decimal",
    ),
)
def test_operator_observation_requires_unambiguous_latest_explicit_accounting(
    mutation: str,
) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_new_entry.md").read_bytes()
    ledger = b"Ledger now at 7 entries / `1.37500000` USD.\n"
    audits = b"`completed_real_audits` is `0`.\n"
    if mutation == "missing_ledger":
        entry = entry.replace(ledger, b"")
    elif mutation == "missing_audits":
        entry = entry.replace(audits, b"")
    elif mutation == "duplicate_ledger":
        entry += ledger
    elif mutation == "duplicate_audits":
        entry += audits
    elif mutation == "contradictory_ledger":
        entry += ledger.replace(b"7 entries", b"8 entries")
    elif mutation == "contradictory_audits":
        entry += audits.replace(b"`0`", b"`1`")
    elif mutation == "nonzero_audits":
        entry = entry.replace(audits, audits.replace(b"`0`", b"`1`"))
    elif mutation == "negative_amount":
        entry = entry.replace(b"1.37500000", b"-1.37500000")
    elif mutation == "exponent_amount":
        entry = entry.replace(b"1.37500000", b"1.375e0")
    elif mutation == "malformed_extra_ledger":
        entry += ledger.replace(b"1.37500000", b"1.375e0")
    elif mutation == "malformed_extra_audits":
        entry += audits.replace(b"`0`", b"unknown")
    elif mutation == "overlong_count":
        entry = entry.replace(b"7 entries", b"7" * 13 + b" entries")
    elif mutation == "overlong_decimal":
        entry = entry.replace(b"1.37500000", b"1." + b"3" * 19)
    else:
        entry = entry.replace(ledger, b"Same ledger as before.\n")
    content = prepend_report(original, entry)
    with pytest.raises(ValueError, match=r"accounting|reported facts"):
        validate_operator_observation(content, synthetic_operator_observation(content), historical)


@pytest.mark.parametrize(
    ("prefix", "suffix"),
    (("```text\n", "```\n"), ("~~~~\n", "~~~~\n"), ("<!--\n", "-->\n"), ("> ", ""), ("    ", "")),
)
@pytest.mark.parametrize("visible_facts", (True, False))
def test_operator_observation_never_borrows_accounting_from_examples(
    prefix: str, suffix: str, visible_facts: bool
) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_new_entry.md").read_text(encoding="utf-8")
    ledger = "Ledger now at 7 entries / `1.37500000` USD.\n"
    audits = "`completed_real_audits` is `0`.\n"
    sample = prefix + ledger + suffix + prefix + audits + suffix
    sample += prefix + f"## {HISTORICAL_TIMESTAMP} — Example only\n" + suffix
    if not visible_facts:
        entry = entry.replace(ledger, "").replace(audits, "")
    content = prepend_report(original, (entry + sample).encode())
    observation = synthetic_operator_observation(content)
    if visible_facts:
        validate_operator_observation(content, observation, historical)
    else:
        with pytest.raises(ValueError, match="accounting is absent"):
            validate_operator_observation(content, observation, historical)


@pytest.mark.parametrize(
    "mutation",
    ("invalid_calendar", "old_timestamp", "duplicate_timestamp", "wrong_order", "undated_heading"),
)
def test_operator_observation_rejects_ambiguous_new_report_identity(mutation: str) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_new_entry.md").read_bytes()
    timestamp = LATEST_TIMESTAMP
    if mutation == "invalid_calendar":
        timestamp = "2026-09-32T10:00:00Z"
        entry = entry.replace(LATEST_TIMESTAMP.encode(), timestamp.encode())
    elif mutation == "old_timestamp":
        timestamp = "2026-09-02T10:00:00Z"
        entry = entry.replace(LATEST_TIMESTAMP.encode(), timestamp.encode())
    elif mutation == "duplicate_timestamp":
        original = prepend_report(original, entry)
    elif mutation == "wrong_order":
        original = prepend_report(original, entry.replace(b"2026-09-08", b"2026-09-09"))
    else:
        entry += b"\n## Undated ambiguous report\n"
    content = prepend_report(original, entry)
    with pytest.raises(ValueError):
        validate_operator_observation(
            content, synthetic_operator_observation(content, timestamp=timestamp), historical
        )


def test_operator_observation_enforces_bounded_inputs_and_revalidates_constructed_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, historical = synthetic_operator_history()
    content = prepend_report(original, (FIXTURES / "operator_new_entry.md").read_bytes())
    observation = synthetic_operator_observation(content)
    invalid = observation.model_copy(update={"completed_real_audits": True})
    with pytest.raises(ValueError):
        validate_operator_observation(content, invalid, historical)
    monkeypatch.setattr("scripts.validate_governance_state._MAX_DOCUMENT_BYTES", len(content) - 1)
    with pytest.raises(ValueError, match="bounded byte scope"):
        validate_operator_observation(content, observation, historical)


@pytest.mark.parametrize("new_report_count", (1023, 1024))
def test_operator_observation_bounds_entries_including_the_original_anchor(
    new_report_count: int,
) -> None:
    original, historical = synthetic_operator_history()
    entry = (FIXTURES / "operator_new_entry.md").read_bytes()
    start = datetime(2026, 9, 8, tzinfo=UTC)
    timestamps = [
        (start + timedelta(minutes=index)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for index in reversed(range(new_report_count))
    ]
    entries = b"\n".join(
        entry.replace(LATEST_TIMESTAMP.encode(), timestamp.encode()) for timestamp in timestamps
    )
    content = prepend_report(original, entries)
    observation = synthetic_operator_observation(content, timestamp=timestamps[0])
    if new_report_count == 1023:
        validate_operator_observation(content, observation, historical)
    else:
        with pytest.raises(ValueError, match="ordering or latest identity"):
            validate_operator_observation(content, observation, historical)
