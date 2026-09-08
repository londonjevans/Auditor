"""Read-only development coordination checks; never audit or release authority."""

from __future__ import annotations

import argparse
import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.models.route_constraints import ProviderPriceCapAlgorithm
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_file_evidence, read_json_evidence

CURRENT_STATE_KEY = "current_engineering_state"
GOVERNANCE_SCOPE = "CURRENT_ENGINEERING_STATE_ONLY_OTHER_FIELDS_ARE_HISTORICAL_NONAUTHORIZING"
HISTORICAL_PAYLOAD_SHA256S = {
    "docs/remediation/v3/runtime_status.json": (
        "c3807ea619539b5b5ef0b3cf30dcc7b670e4e8fb458d50e296f8d467605bea70"
    ),
    "docs/remediation/v3/review_traceability.json": (
        "da70b13abaa1e486a98c333c902c7124e4bd232eb62038de0583e3e1d2c78036"
    ),
}
COORDINATION_KEYS = frozenset(
    {CURRENT_STATE_KEY, "governance_state_scope", "historical_payload_sha256"}
)
QUEUE_PATHS = ("docs/codex_work_queue.md", "docs/remediation/v3/work_queue.md")
WORKLOG_PATHS = ("docs/codex_worklog.md", "docs/remediation/v3/worklog.md")
OPERATOR_RESULTS_PATH = "docs/remediation/v3/operator_results.md"
ARTIFACT_PATHS = frozenset(
    {
        "config/models.selection-plan.json",
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "docs/remediation/v3/product_completion_goal.txt",
        "schemas/candidate_selection_plan.schema.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "schemas/managed_provisioning_receipt.schema.json",
        "schemas/managed_provisioning_state.schema.json",
    }
)
ALLOWED_STATUSES = frozenset(
    {
        "QUEUED",
        "IN_PROGRESS",
        "COMPLETE",
        "PARTIAL",
        "BLOCKED_TECHNICAL",
        "BLOCKED_SAFETY",
        "WITHDRAWN_OPERATOR_ERROR",
    }
)
TERMINAL_STATUSES = frozenset({"COMPLETE", "WITHDRAWN_OPERATOR_ERROR"})
AUTHORITY_FIELDS = (
    "provider_call_authorized",
    "source_egress_authorized",
    "production_selection_authorized",
    "qualification_authorized",
    "runner_authority_authorized",
    "audit_authorized",
    "benchmark_authorized",
    "release_authorized",
    "serialized_authority",
)
_MAX_DOCUMENT_BYTES = 16_000_000
_HEADING = re.compile(r"^#{2,3} (?P<title>[^\n]+)$", re.MULTILINE)
_TICKET = re.compile(r"^(?P<ticket>[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\b")
_STATUS = re.compile(r"^- \*\*Status:\*\* `(?P<status>[A-Z_]+)`\s*$", re.MULTILINE)
_OPERATOR_TIMESTAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2})?Z"
_OPERATOR_HEADING = re.compile(rf"^## ({_OPERATOR_TIMESTAMP})(?:[ \t]+[^\r\n]*)?\r?$", re.MULTILINE)
# Allow a single prose wrap, never join paragraphs or masked examples into a fact.
_REPORT_SPACE = r"(?:[ \t]*\r?\n[ \t]*|[ \t]+)"
_LEDGER_PREFIX = re.compile(
    rf"\bLedger{_REPORT_SPACE}(?:unchanged|now){_REPORT_SPACE}at\b", re.ASCII
)
_AUDIT_PREFIX = re.compile(r"`completed_real_audits`")
_LEDGER_REPORT = re.compile(
    _LEDGER_PREFIX.pattern
    + rf"{_REPORT_SPACE}([0-9]{{1,12}}){_REPORT_SPACE}entries{_REPORT_SPACE}/"
    + rf"(?:{_REPORT_SPACE})?`([0-9]{{1,12}}\.[0-9]{{1,18}})`{_REPORT_SPACE}USD\."
    + r"(?=[ \t\r\n]|\Z)",
    re.ASCII,
)
_AUDIT_REPORT = re.compile(
    rf"(?:^ {{0,3}}|(?<=[.!?]){_REPORT_SPACE})"
    + _AUDIT_PREFIX.pattern
    + rf"{_REPORT_SPACE}(?:remains|is){_REPORT_SPACE}`([0-9]{{1,12}})`\."
    + r"(?=[ \t\r\n]|\Z)",
    re.MULTILINE | re.ASCII,
)
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
TicketId = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")]


class _StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InventorySummary(_StrictRecord):
    inventory_sha256: Sha256
    source_discovery_semantics_sha256: Sha256
    source_universe_sha256: Sha256
    source_count: int = Field(ge=1)
    source_occurrence_count: int = Field(ge=1)
    gate_source_count: int = Field(ge=0)
    logical_gate_count: int = Field(ge=1)
    unsatisfied_gate_count: int = Field(ge=0)
    current_manual_gate_count: int = Field(ge=0)
    completion_entrypoint_parameter_count: int = Field(ge=0)


class OperatorObservation(_StrictRecord):
    raw_sha256: Sha256
    byte_count: int = Field(ge=1)
    line_count: int = Field(ge=1)
    latest_entry_timestamp: str
    reported_ledger_entries: int = Field(ge=0)
    reported_ledger_used_usd: str = Field(pattern=r"^\d+\.\d+$")
    completed_real_audits: int = Field(ge=0, le=0)
    evidence_class: Literal["OPERATOR_REPORTED_NOT_INDEPENDENTLY_AUTHENTICATED"]


class EngineeringState(_StrictRecord):
    """Current coordination only; no serialized permission or audit-completion claim."""

    schema_version: Literal["1.0"]
    status: Literal["NONAUTHORIZING_COORDINATION"]
    updated_at: str
    current_ticket: TicketId | None
    current_ticket_status: Literal["IN_PROGRESS"] | None
    last_completed_ticket: TicketId
    last_partial_ticket: TicketId
    next_ticket: TicketId | None
    unfinished_ticket_count: int = Field(ge=0)
    queue_statuses_sha256: Sha256
    artifact_sha256s: dict[str, Sha256]
    inventory: InventorySummary
    operator: OperatorObservation
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    qualification_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    audit_authorized: Literal[False]
    benchmark_authorized: Literal[False]
    release_authorized: Literal[False]
    serialized_authority: Literal[False]

    @field_validator(*AUTHORITY_FIELDS, mode="before")
    @classmethod
    def authority_must_be_literal_false(cls, value: object) -> object:
        if value is not False:
            raise ValueError("coordination cannot grant authority")
        return value

    @field_validator("updated_at")
    @classmethod
    def timestamp_is_utc(cls, value: str) -> str:
        if not value.endswith("Z"):
            raise ValueError("coordination timestamp must be UTC")
        datetime.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def state_is_closed(self) -> Self:
        if (self.current_ticket is None) != (self.current_ticket_status is None):
            raise ValueError("coordination selection and status disagree")
        if set(self.artifact_sha256s) != ARTIFACT_PATHS:
            raise ValueError("coordination artifact scope differs from the fixed read-only scope")
        return self


def historical_payload_sha256(document: Mapping[str, Any]) -> str:
    """Exclude only the three explicitly introduced coordination fields."""

    return canonical_sha256(
        {key: value for key, value in document.items() if key not in COORDINATION_KEYS}
    )


def combined_queue_statuses(documents: Sequence[str]) -> dict[str, str]:
    """Reject missing/duplicate statuses and cross-queue disagreement before counting."""

    combined: dict[str, str] = {}
    for document in documents:
        headings = list(_HEADING.finditer(document))
        local: dict[str, str] = {}
        for index, heading in enumerate(headings):
            ticket_match = _TICKET.match(heading.group("title"))
            if ticket_match is None:
                continue
            ticket = ticket_match.group("ticket")
            end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
            matches = list(_STATUS.finditer(document[heading.end() : end]))
            if ticket in local or len(matches) != 1:
                raise ValueError("queue ticket has missing or duplicate status")
            status = matches[0].group("status")
            if status not in ALLOWED_STATUSES:
                raise ValueError("queue ticket has unsupported status")
            if ticket in combined and combined[ticket] != status:
                raise ValueError("queue ticket status conflicts across records")
            local[ticket] = status
            combined[ticket] = status
        if not local:
            raise ValueError("queue has no classified tickets")
    if not combined:
        raise ValueError("no queues were supplied")
    return combined


def _read_bytes(root: Path, path: str) -> bytes:
    return read_file_evidence(
        evidence_root=root, relative_path=path, max_bytes=_MAX_DOCUMENT_BYTES
    ).content


def _read_object(root: Path, path: str) -> dict[str, Any]:
    value = read_json_evidence(
        evidence_root=root, relative_path=path, max_bytes=_MAX_DOCUMENT_BYTES
    ).value
    if type(value) is not dict:
        raise ValueError("governance document must be a JSON object")
    return cast(dict[str, Any], value)


def validate_worklog_header(header: str, state: EngineeringState) -> None:
    """Machine fields must occur once in the current header, not in history."""

    expected = {
        "GOVERNANCE_STATE_SOURCE": "docs/remediation/v3/runtime_status.json#current_engineering_state",
        "CURRENT_ENGINEERING_STATE_SHA256": canonical_sha256(state.model_dump(mode="json")),
        "CURRENT_TICKET": state.current_ticket or "UNSELECTED",
        "CURRENT_TICKET_IMPLEMENTATION_STARTED": "true"
        if state.current_ticket is not None
        else "false",
        "LAST_COMPLETED_TICKET": state.last_completed_ticket,
        "LAST_PARTIAL_TICKET": state.last_partial_ticket,
    }
    for key, value in expected.items():
        occurrences = re.findall(rf"^{key}: (.+)$", header, flags=re.MULTILINE)
        if occurrences != [value]:
            raise ValueError("current worklog header differs from engineering coordination")
    count = re.findall(
        r"^REMAINING_ACTIONABLE_TICKETS: The combined queues contain (\d+) unfinished tickets\b",
        header,
        flags=re.MULTILINE,
    )
    if count != [str(state.unfinished_ticket_count)]:
        raise ValueError("current worklog unfinished count differs from the queues")
    for token in ("PROVIDER_FREE", "NONAUTHORIZING", state.operator.raw_sha256):
        if token not in header:
            raise ValueError("current worklog lacks its nonauthorizing evidence scope")


def _visible_operator_text(text: str) -> str:
    """Mask quoted/code/comment examples without moving report offsets."""

    visible: list[str] = []
    fence_character = ""
    fence_length = 0
    text = re.sub(r"<!--.*?(?:-->|\Z)", lambda match: _mask_report_text(match[0]), text, flags=re.S)
    for line in text.splitlines(keepends=True):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})([^\r\n]*)", line)
        hidden = (
            bool(fence_character)
            or line.startswith(("    ", "\t"))
            or line.lstrip().startswith(">")
        )
        if fence is not None:
            marker, suffix = fence.groups()
            if not fence_character:
                fence_character, fence_length = marker[0], len(marker)
            elif (
                marker[0] == fence_character and len(marker) >= fence_length and not suffix.strip()
            ):
                fence_character = ""
            hidden = True
        visible.append(_mask_report_text(line) if hidden else line)
    return "".join(visible)


def _mask_report_text(text: str) -> str:
    # A non-whitespace barrier preserves offsets without making hidden text a prose wrap.
    return "".join(character if character in "\r\n" else "\x00" for character in text)


def validate_operator_observation(
    content: bytes, observation: OperatorObservation, historical: Mapping[str, Any]
) -> None:
    """Bind current reported facts and separately preserve the frozen original document.

    This checks local report consistency, not ledger authenticity or permissions.
    The caller authenticates ``historical`` against the compiled historical JSON
    digest before using its original timestamp, byte count and hash as the anchor.
    """

    if type(content) is not bytes or not content or len(content) > _MAX_DOCUMENT_BYTES:
        raise ValueError("operator document exceeds its bounded byte scope")
    if type(observation) is not OperatorObservation:
        raise ValueError("operator observation requires the exact current record type")
    observation = OperatorObservation.model_validate(observation.model_dump(), strict=True)
    text = content.decode("utf-8")
    if (
        hashlib.sha256(content).hexdigest() != observation.raw_sha256
        or len(content) != observation.byte_count
        or len(text.splitlines()) != observation.line_count
    ):
        raise ValueError("operator current evidence binding changed")
    visible = _visible_operator_text(text)
    headings = list(_OPERATOR_HEADING.finditer(visible))
    anchors = [item for item in headings if item[1] == historical["latest_entry_timestamp"]]
    if not headings or len(anchors) != 1:
        raise ValueError("operator historical report anchor is absent or ambiguous")
    anchor = anchors[0]
    original = (text[: headings[0].start()] + text[anchor.start() :]).encode("utf-8")
    if (
        hashlib.sha256(original).hexdigest() != historical["operator_results_sha256"]
        or len(original) != historical["operator_results_bytes"]
        or len(original.decode("utf-8").splitlines()) != historical["operator_results_lines"]
    ):
        raise ValueError("operator historical evidence changed")
    current_headings = [item for item in headings if item.start() <= anchor.start()]
    timestamps = [datetime.fromisoformat(item[1]) for item in current_headings]
    if (
        len(current_headings) > 1024
        or any(a <= b for a, b in pairwise(timestamps))
        or len(re.findall(r"^## ", visible[: anchor.start()], re.MULTILINE))
        != len(current_headings) - 1
        or headings[0][1] != observation.latest_entry_timestamp
    ):
        raise ValueError("operator report ordering or latest identity is ambiguous")
    end = headings[1].start() if len(headings) > 1 else len(visible)
    latest = visible[headings[0].end() : end]
    ledgers = _LEDGER_REPORT.findall(latest)
    audits = _AUDIT_REPORT.findall(latest)
    ledger_prefixes = _LEDGER_PREFIX.findall(latest)
    audit_prefixes = _AUDIT_PREFIX.findall(latest)
    if (
        len(ledgers) != 1
        or len(audits) != 1
        or len(ledger_prefixes) != 1
        or len(audit_prefixes) != 1
    ):
        raise ValueError("operator latest report accounting is absent or ambiguous")
    if (
        int(ledgers[0][0]) != observation.reported_ledger_entries
        or ledgers[0][1] != observation.reported_ledger_used_usd
        or int(audits[0]) != observation.completed_real_audits
    ):
        raise ValueError("operator current summary differs from latest reported facts")


def validate_governance_documents(
    repository_root: Path, documents: Mapping[str, Mapping[str, Any]]
) -> EngineeringState:
    """Validate local engineering state independently of its preserved operator history."""

    if set(documents) != set(HISTORICAL_PAYLOAD_SHA256S):
        raise ValueError("governance document set differs from the closed scope")
    states: list[EngineeringState] = []
    for path, document in documents.items():
        expected_history = HISTORICAL_PAYLOAD_SHA256S[path]
        if (
            document.get("governance_state_scope") != GOVERNANCE_SCOPE
            or document.get("historical_payload_sha256") != expected_history
            or historical_payload_sha256(document) != expected_history
        ):
            raise ValueError("historical governance payload or its scope changed")
        states.append(EngineeringState.model_validate(document.get(CURRENT_STATE_KEY)))
    state = states[0]
    if any(other != state for other in states[1:]):
        raise ValueError("current engineering mirrors disagree")

    statuses = combined_queue_statuses(
        [_read_bytes(repository_root, path).decode("utf-8") for path in QUEUE_PATHS]
    )
    unfinished = sum(status not in TERMINAL_STATUSES for status in statuses.values())
    active = {ticket for ticket, status in statuses.items() if status == "IN_PROGRESS"}
    if (
        unfinished != state.unfinished_ticket_count
        or canonical_sha256(statuses) != state.queue_statuses_sha256
        or active != ({state.current_ticket} if state.current_ticket is not None else set())
        or statuses.get(state.last_completed_ticket) != "COMPLETE"
        or statuses.get(state.last_partial_ticket) != "PARTIAL"
        or (
            state.next_ticket is not None
            and statuses.get(state.next_ticket) not in {"QUEUED", "PARTIAL"}
        )
    ):
        raise ValueError("current engineering status differs from the queues")
    artifact_contents: dict[str, bytes] = {}
    artifact_values: dict[str, dict[str, Any]] = {}
    for path, expected in state.artifact_sha256s.items():
        if path.endswith(".json"):
            observed = read_json_evidence(
                evidence_root=repository_root, relative_path=path, max_bytes=_MAX_DOCUMENT_BYTES
            )
            if type(observed.value) is not dict:
                raise ValueError("governance artifact must be a JSON object")
            artifact_values[path] = cast(dict[str, Any], observed.value)
            content = observed.content
        else:
            content = _read_bytes(repository_root, path)
        artifact_contents[path] = content
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("current engineering artifact binding changed")
    inventory = artifact_values["docs/remediation/v3/autonomy_gate_inventory.json"]
    if (
        state.inventory
        != InventorySummary.model_validate(
            {key: inventory.get(key) for key in InventorySummary.model_fields}
        )
        or inventory.get("runtime_authority") is not False
        or inventory.get("managed_run_ready") is not False
    ):
        raise ValueError("current inventory projection changed or promoted authority")
    plan = CandidateSelectionPlan.model_validate_json(
        artifact_contents["config/models.selection-plan.json"], strict=True
    )
    unavailable = plan.authenticated_runner_unavailability
    if (
        plan.schema_version != "1.7"
        or plan.authenticated_runner_selection is not None
        or unavailable is None
        or unavailable.route_predicate_profile.schema_version != "1.0"
        or unavailable.route_predicate_profile.price_cap_algorithm
        is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    ):
        raise ValueError("active plan no longer matches retained nonauthorizing V1 custody")
    operator_bytes = _read_bytes(repository_root, OPERATOR_RESULTS_PATH)
    historical_operator = documents["docs/remediation/v3/runtime_status.json"][
        "current_operator_result_reconciliation"
    ]
    validate_operator_observation(operator_bytes, state.operator, historical_operator)
    for path in WORKLOG_PATHS:
        header = _read_bytes(repository_root, path).decode("utf-8").split("\n## ", 1)[0]
        validate_worklog_header(header, state)
    return state


def validate_governance_state(repository_root: Path) -> EngineeringState:
    documents = {path: _read_object(repository_root, path) for path in HISTORICAL_PAYLOAD_SHA256S}
    return validate_governance_documents(repository_root, documents)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        state = validate_governance_state(args.repository_root)
    except (OSError, TypeError, ValueError, KeyError):
        print("Governance coordination INVALID; no authority granted.")
        return 1
    print(
        f"Governance coordination valid: {state.unfinished_ticket_count} unfinished tickets; NONAUTHORIZING."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
