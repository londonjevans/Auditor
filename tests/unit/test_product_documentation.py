from __future__ import annotations

import ast
import hashlib
import json
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_PATH = ROOT / "AGENTS.md"
QUEUE_PATH = ROOT / "docs/remediation/v3/work_queue.md"
TRACEABILITY_PATH = ROOT / "docs/remediation/v3/review_traceability.json"
RUNTIME_STATUS_PATH = ROOT / "docs/remediation/v3/runtime_status.json"
OPERATOR_RESULTS_PATH = ROOT / "docs/remediation/v3/operator_results.md"
README_PATH = ROOT / "README.md"
MODEL_SELECTION_PATH = ROOT / "docs/models/model_selection.md"
PRODUCT_VISION_PATH = ROOT / "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
CONFIG_PATH = ROOT / "src/mmaudit/config.py"

OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
PRODUCT_VISION_RELATIVE_PATH = "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
PRODUCT_VISION_SHA256 = "8b878b665e636b3b48500fefe2967394b2abdd69ce2ebfa0033d04542d2965e1"
OPERATOR_RESULTS_SHA256 = "41932dfe7cfa2a0dbc7f0f68d01c2fbf8bec2ad0276ac16a9837b6b9e66f2b69"
PRODUCT_VISION_GIT_ATTRIBUTES = f"{PRODUCT_VISION_RELATIVE_PATH} -text"
POLICY_ELIGIBILITY_TICKET = "V3-POLICYELIG-001"
POLICY_ELIGIBILITY_QUEUE_HEADING = (
    "## V3-POLICYELIG-001 — Provider terms and jurisdictional eligibility for model use"
)

ALLOWED_TICKET_STATUSES = frozenset(
    {
        "QUEUED",
        "IN_PROGRESS",
        "COMPLETE",
        "PARTIAL",
        "BLOCKED_TECHNICAL",
        "BLOCKED_SAFETY",
    }
)
README_CAPABILITY_TICKETS = frozenset(
    {
        "V3-SHARD-001",
        "V3-SCHEDULER-001",
        "V3-EXECORIGIN-001",
        "V3-FORKSUITE-001",
        "V3-TESTQUALITY-001",
        "V3-TOKENS-001",
        "V3-OMISSION-001",
        "V3-GRAPHBOUND-001",
    }
)
MODEL_WORK_TICKETS = frozenset(
    {
        "V3-MODELREFRESH-001",
        "V3-LINEAGE-001",
        "V3-CALIBRATE-001",
        "V3-QUALIFY-001",
        "V3-POLICYELIG-001",
    }
)
EXPECTED_REQUIREMENT_IDS = tuple("ABCDEFGHIJKLMNOPQRSTUV")

_LEVEL_TWO_HEADING = re.compile(r"^## (?P<title>[^\n]+)$", re.MULTILINE)
_TICKET_TITLE = re.compile(r"^(?P<ticket>V3-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b")
_TICKET_STATUS = re.compile(
    r"^- \*\*Status:\*\* `(?P<status>[A-Z_]+)`\s*$",
    re.MULTILINE,
)
_STATUS_TABLE_ROW = re.compile(
    r"^\|\s*(?P<label>[^|\n]+?)\s*\|\s*"
    r"`(?P<ticket>V3-[A-Z0-9]+(?:-[A-Z0-9]+)*)`\s*\|\s*"
    r"`(?P<status>[A-Z_]+)`\s*\|(?:\s*[^|\n]+\s*\|)*\s*$",
    re.MULTILINE,
)


def _parse_queue_ticket_statuses(document: str) -> dict[str, str]:
    headings = list(_LEVEL_TWO_HEADING.finditer(document))
    statuses: dict[str, str] = {}
    for index, heading in enumerate(headings):
        ticket_match = _TICKET_TITLE.match(heading.group("title"))
        if ticket_match is None:
            continue
        ticket = ticket_match.group("ticket")
        assert ticket not in statuses, f"duplicate queue ticket heading: {ticket}"
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
        body = document[heading.end() : body_end]
        status_matches = list(_TICKET_STATUS.finditer(body))
        assert len(status_matches) == 1, (
            f"queue ticket {ticket} must have exactly one anchored Status line; "
            f"found {len(status_matches)}"
        )
        status = status_matches[0].group("status")
        assert status in ALLOWED_TICKET_STATUSES, (
            f"queue ticket {ticket} has unsupported status {status}"
        )
        statuses[ticket] = status
    assert statuses, "queue contains no parseable V3 ticket blocks"
    return statuses


def _isolated_level_two_section(document: str, heading: str) -> str:
    marker = f"{heading}\n"
    assert document.count(marker) == 1, f"expected exactly one {heading!r} section"
    _, _, remainder = document.partition(marker)
    next_heading = _LEVEL_TWO_HEADING.search(remainder)
    return remainder if next_heading is None else remainder[: next_heading.start()]


def _parse_status_table(document: str, heading: str) -> dict[str, str]:
    section = _isolated_level_two_section(document, heading)
    statuses: dict[str, str] = {}
    for match in _STATUS_TABLE_ROW.finditer(section):
        ticket = match.group("ticket")
        status = match.group("status")
        assert ticket not in statuses, f"duplicate status-table row for {ticket}"
        assert status in ALLOWED_TICKET_STATUSES, (
            f"status-table row for {ticket} has unsupported status {status}"
        )
        assert match.group("label").strip(), f"status-table row for {ticket} has no label"
        statuses[ticket] = status
    assert statuses, f"{heading!r} has no parseable capability rows"
    return statuses


def _derive_requirement_status(
    tickets: Sequence[str],
    queue_statuses: Mapping[str, str],
) -> str:
    assert tickets, "traceability requirement must reference at least one ticket"
    assert len(tickets) == len(set(tickets)), "traceability requirement repeats a ticket"
    if list(tickets) == ["ALL"]:
        assert queue_statuses, "ALL cannot derive from an empty queue"
        return (
            "COMPLETE"
            if all(status == "COMPLETE" for status in queue_statuses.values())
            else "IN_PROGRESS"
        )
    assert "ALL" not in tickets, "ALL cannot be combined with individual ticket IDs"
    unknown = sorted(set(tickets) - set(queue_statuses))
    assert not unknown, f"traceability requirement references unknown tickets: {unknown}"
    mapped = [queue_statuses[ticket] for ticket in tickets]
    if all(status == "COMPLETE" for status in mapped):
        return "COMPLETE"
    if "IN_PROGRESS" in mapped:
        return "IN_PROGRESS"
    if any(status in {"COMPLETE", "PARTIAL"} for status in mapped):
        return "PARTIAL"
    if "BLOCKED_SAFETY" in mapped:
        return "BLOCKED_SAFETY"
    if "BLOCKED_TECHNICAL" in mapped:
        return "BLOCKED_TECHNICAL"
    return "QUEUED"


def _field_default(class_name: str, field_name: str) -> int:
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"), filename=str(CONFIG_PATH))
    class_nodes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    assert len(class_nodes) == 1, f"expected one {class_name} declaration"
    assignments = [
        node
        for node in class_nodes[0].body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == field_name
    ]
    assert len(assignments) == 1, f"expected one {class_name}.{field_name} declaration"
    value = assignments[0].value
    assert isinstance(value, ast.Call), f"{class_name}.{field_name} must use Field(default=...)"
    default_keywords = [keyword for keyword in value.keywords if keyword.arg == "default"]
    assert len(default_keywords) == 1, (
        f"{class_name}.{field_name} must have exactly one explicit Field default"
    )
    default = ast.literal_eval(default_keywords[0].value)
    assert isinstance(default, int) and not isinstance(default, bool), (
        f"{class_name}.{field_name} default must be an integer"
    )
    return default


def _field_default_factory(class_name: str, field_name: str) -> str:
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"), filename=str(CONFIG_PATH))
    class_nodes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    assert len(class_nodes) == 1, f"expected one {class_name} declaration"
    assignments = [
        node
        for node in class_nodes[0].body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == field_name
    ]
    assert len(assignments) == 1, f"expected one {class_name}.{field_name} declaration"
    value = assignments[0].value
    assert isinstance(value, ast.Call), (
        f"{class_name}.{field_name} must use Field(default_factory=...)"
    )
    factory_keywords = [keyword for keyword in value.keywords if keyword.arg == "default_factory"]
    assert len(factory_keywords) == 1 and isinstance(factory_keywords[0].value, ast.Name), (
        f"{class_name}.{field_name} must have one named Field default_factory"
    )
    return factory_keywords[0].value.id


def _assert_fails(expected: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except AssertionError as exc:
        assert expected in str(exc)
    else:
        raise AssertionError(f"operation did not fail with {expected!r}")


def test_queue_parser_rejects_duplicate_missing_and_invalid_statuses() -> None:
    duplicate_heading = """
## V3-ONE-001 — first

- **Status:** `QUEUED`

## V3-ONE-001 — duplicate

- **Status:** `COMPLETE`
"""
    duplicate_status = """
## V3-ONE-001 — duplicate status

- **Status:** `QUEUED`
- **Status:** `COMPLETE`
"""
    missing_status = """
## V3-ONE-001 — missing status

- **Objective:** synthetic parser fixture.
"""
    invalid_status = """
## V3-ONE-001 — invalid status

- **Status:** `DONE`
"""

    _assert_fails(
        "duplicate queue ticket heading",
        lambda: _parse_queue_ticket_statuses(duplicate_heading),
    )
    _assert_fails(
        "exactly one anchored Status line",
        lambda: _parse_queue_ticket_statuses(duplicate_status),
    )
    _assert_fails(
        "exactly one anchored Status line",
        lambda: _parse_queue_ticket_statuses(missing_status),
    )
    _assert_fails(
        "unsupported status",
        lambda: _parse_queue_ticket_statuses(invalid_status),
    )


def test_status_reducer_is_derived_and_rejects_unknown_ticket_ids() -> None:
    statuses = {
        "V3-COMPLETE-001": "COMPLETE",
        "V3-ACTIVE-001": "IN_PROGRESS",
        "V3-PARTIAL-001": "PARTIAL",
        "V3-SAFETY-001": "BLOCKED_SAFETY",
        "V3-TECHNICAL-001": "BLOCKED_TECHNICAL",
        "V3-QUEUED-001": "QUEUED",
    }

    assert _derive_requirement_status(["V3-COMPLETE-001"], statuses) == "COMPLETE"
    assert (
        _derive_requirement_status(["V3-COMPLETE-001", "V3-ACTIVE-001"], statuses) == "IN_PROGRESS"
    )
    assert _derive_requirement_status(["V3-COMPLETE-001", "V3-QUEUED-001"], statuses) == "PARTIAL"
    assert _derive_requirement_status(["V3-SAFETY-001"], statuses) == "BLOCKED_SAFETY"
    assert _derive_requirement_status(["V3-TECHNICAL-001"], statuses) == "BLOCKED_TECHNICAL"
    assert _derive_requirement_status(["V3-QUEUED-001"], statuses) == "QUEUED"
    assert _derive_requirement_status(["ALL"], statuses) == "IN_PROGRESS"
    assert _derive_requirement_status(["ALL"], {"V3-ONE-001": "COMPLETE"}) == "COMPLETE"

    _assert_fails(
        "unknown tickets",
        lambda: _derive_requirement_status(["V3-UNKNOWN-001"], statuses),
    )
    _assert_fails(
        "ALL cannot be combined",
        lambda: _derive_requirement_status(["ALL", "V3-QUEUED-001"], statuses),
    )
    _assert_fails(
        "repeats a ticket",
        lambda: _derive_requirement_status(["V3-QUEUED-001", "V3-QUEUED-001"], statuses),
    )


def test_status_table_parser_rejects_duplicate_rows() -> None:
    document = """
## Queue-derived capability status

| Capability | Ticket | Queue status |
| --- | --- | --- |
| One | `V3-ONE-001` | `QUEUED` |
| Duplicate | `V3-ONE-001` | `COMPLETE` |
"""

    _assert_fails(
        "duplicate status-table row",
        lambda: _parse_status_table(document, "## Queue-derived capability status"),
    )


def test_review_traceability_statuses_derive_from_queue_ticket_statuses() -> None:
    queue_statuses = _parse_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    traceability = json.loads(TRACEABILITY_PATH.read_text(encoding="utf-8"))
    requirements = traceability["requirements"]
    requirement_ids = [requirement["id"] for requirement in requirements]

    assert requirement_ids == list(EXPECTED_REQUIREMENT_IDS), (
        "review traceability must contain the canonical complete A-V requirement sequence"
    )
    for requirement in requirements:
        tickets = requirement["tickets"]
        assert isinstance(tickets, list) and all(isinstance(ticket, str) for ticket in tickets)
        expected = _derive_requirement_status(tickets, queue_statuses)
        assert requirement["status"] == expected, (
            f"traceability requirement {requirement['id']} status must derive from queue tickets "
            f"{tickets}: expected {expected}, found {requirement['status']}"
        )


def test_readme_and_model_work_markings_derive_from_queue_ticket_statuses() -> None:
    queue_statuses = _parse_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    readme = README_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    readme_markings = _parse_status_table(readme, "## Queue-derived capability status")
    model_markings = _parse_status_table(
        model_selection,
        "## Queue-derived model-work status",
    )

    assert set(readme_markings) == README_CAPABILITY_TICKETS
    assert set(model_markings) == MODEL_WORK_TICKETS
    for document_name, markings in (
        ("README", readme_markings),
        ("model-selection guide", model_markings),
    ):
        for ticket, marked_status in markings.items():
            assert ticket in queue_statuses, f"{document_name} marks unknown ticket {ticket}"
            assert marked_status == queue_statuses[ticket], (
                f"{document_name} marks {ticket} as {marked_status}, but the queue status is "
                f"{queue_statuses[ticket]}"
            )

    release_matches = re.findall(
        r"^\*\*Repository release status:\*\* `(?P<status>[A-Z_]+)`\s*$",
        _isolated_level_two_section(readme, "## Queue-derived capability status"),
        re.MULTILINE,
    )
    assert len(release_matches) == 1, (
        "README capability section must carry one repository release-status marking"
    )
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    assert release_matches[0] == runtime_status["release_status"]


def test_operator_command_results_have_a_persistent_reconciliation_contract() -> None:
    agents = AGENTS_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    operator_result_bytes = OPERATOR_RESULTS_PATH.read_bytes()
    operator_results = operator_result_bytes.decode("utf-8")
    queues = (
        (ROOT / "docs/codex_work_queue.md").read_text(encoding="utf-8"),
        QUEUE_PATH.read_text(encoding="utf-8"),
    )
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    preflight_status = runtime_status["authrunner_provider_free_preflight"]
    local_contract = preflight_status["local_preflight_contract"]

    assert "docs/remediation/v3/operator_results.md" in agents
    assert "Before ending any turn that issued, reissued, or depended on an operator command" in (
        agents
    )
    assert "../remediation/v3/operator_results.md" in model_selection
    assert hashlib.sha256(operator_result_bytes).hexdigest() == OPERATOR_RESULTS_SHA256
    assert OPERATOR_RESULTS_SHA256 in model_selection
    assert all(OPERATOR_RESULTS_SHA256 in queue for queue in queues)
    assert "--primary-judge-registry" in model_selection
    assert "primary-judge-registry-r4.json" in model_selection
    assert "--candidate anthropic/claude-opus-5=amazon-bedrock" not in model_selection
    assert "PRIMARY r4 (`minimax/minimax-m3=coreweave/fp4`) — SUCCESS" in operator_results
    assert "runner public lineage does not prove three distinct roots" in operator_results
    assert "LINEAGE CAPTURE — SUCCESS, one coherent 15-source bundle" in operator_results
    assert "AUTHRUNNER PREFLIGHT — **VALID**" in operator_results
    assert "VALID / NONAUTHORIZING / NO PROVIDER EGRESS" in operator_results
    assert "f0ff2d76017dfcd075c6758f0da7256c98dd45ca749a42b81ca1ce8c95a93f9e" in (operator_results)
    assert "848b1dfda5b60c6793089ed3916073d86e3a734da9dbc5a824302bec7f4b37da" in (operator_results)
    assert "capture_public_model_lineage.py --output-dir" in model_selection
    assert "6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4" in (model_selection)
    assert "primary-judge-registry-r4.json" in model_selection
    assert "replay-judge-registry-r2.json" in model_selection
    assert "Written by the monitoring session; treat as operator-supplied evidence." in (
        operator_results
    )
    assert preflight_status["operator_reported_no_provider_egress"] is True
    assert preflight_status["operator_reported_ledger_unchanged"] is True
    assert preflight_status["operator_reported_provider_completion_calls"] == 0
    assert local_contract == {
        "source": "LOCALLY_VERIFIED_PREFLIGHT_CODE",
        "secret_selection_reached": False,
        "provider_dispatch_reached": False,
        "durable_output_publication_reached": False,
        "transient_private_write_probes_are_created_and_removed": True,
    }
    assert "ledger_unchanged" not in preflight_status
    assert "artifacts_created" not in preflight_status
    assert "secret_selected" not in preflight_status
    assert "provider_egress" not in preflight_status
    assert "provider_completion_calls" not in preflight_status


def test_policy_eligibility_status_and_vision_boundary_are_documented_exactly() -> None:
    queue = QUEUE_PATH.read_text(encoding="utf-8")
    model_selection = MODEL_SELECTION_PATH.read_text(encoding="utf-8")
    vision = PRODUCT_VISION_PATH.read_text(encoding="utf-8")
    queue_statuses = _parse_queue_ticket_statuses(queue)
    model_statuses = _parse_status_table(
        model_selection,
        "## Queue-derived model-work status",
    )

    assert model_statuses[POLICY_ELIGIBILITY_TICKET] == queue_statuses[POLICY_ELIGIBILITY_TICKET]
    queue_section = _isolated_level_two_section(queue, POLICY_ELIGIBILITY_QUEUE_HEADING)
    assert "Section 9.2 of the product vision" in queue_section
    assert "must not be inferred from catalogue" in queue_section
    assert "per exact model and provider endpoint" in queue_section

    vision_marker = "### 9.2 Policy eligibility\n"
    next_marker = "### 9.3 Capability eligibility\n"
    assert vision.count(vision_marker) == 1
    _, _, vision_remainder = vision.partition(vision_marker)
    vision_section, separator, _ = vision_remainder.partition(next_marker)
    assert separator, "policy-eligibility vision section has no capability boundary"
    assert "`ModelPolicyEligibility`" in vision_section
    assert "Unknown or ambiguous policy status must default to exclusion." in vision_section
    assert "A daily automated policy check may flag changes" in vision_section

    normalized_model_selection = " ".join(model_selection.split())
    assert (
        f"policy gate is queued under `{POLICY_ELIGIBILITY_TICKET}`"
        not in normalized_model_selection
    )
    assert "policy eligibility remain queued" not in normalized_model_selection
    assert "distinct commercial-policy mechanism is implemented" in (normalized_model_selection)
    assert "`ELIGIBLE` in this state machine remains technical only" in (normalized_model_selection)
    assert "independently authenticated per-audit policy authority" in (normalized_model_selection)
    assert "No current independently approved determination covers any provider" in (
        normalized_model_selection
    )


def test_vision_and_traceability_bind_current_document_authority() -> None:
    traceability = json.loads(TRACEABILITY_PATH.read_text(encoding="utf-8"))
    queue = QUEUE_PATH.read_text(encoding="utf-8")
    metadata = PRODUCT_VISION_PATH.lstat()
    vision_bytes = PRODUCT_VISION_PATH.read_bytes()

    assert not stat.S_ISLNK(metadata.st_mode)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1
    assert traceability["product_vision_path"] == PRODUCT_VISION_RELATIVE_PATH
    assert traceability["product_vision_sha256"] == PRODUCT_VISION_SHA256
    assert hashlib.sha256(vision_bytes).hexdigest() == PRODUCT_VISION_SHA256
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert PRODUCT_VISION_GIT_ATTRIBUTES in attributes

    authority_section = _isolated_level_two_section(
        queue,
        "## Governing documents and precedence",
    )
    for path, digest in (
        (OBJECTIVE_RELATIVE_PATH, OBJECTIVE_SHA256),
        (PRODUCT_VISION_RELATIVE_PATH, PRODUCT_VISION_SHA256),
    ):
        authority_rows = re.findall(
            rf"^\|\s*`{re.escape(path)}`\s*\|\s*`{digest}`\s*\|",
            authority_section,
            re.MULTILINE,
        )
        assert len(authority_rows) == 1, (
            f"governing-documents table must bind {path} to its exact current digest"
        )

    vision = vision_bytes.decode("utf-8")
    preamble, separator, _ = vision.partition("## 2. Mission")
    assert separator, "product vision lacks its numbered mission section"
    assert f"`{OBJECTIVE_RELATIVE_PATH}`" in preamble
    assert f"`{OBJECTIVE_SHA256}`" in preamble
    normalized_preamble = " ".join(preamble.casefold().split())
    assert "current remediation phase" in normalized_preamble
    assert "objective governs" in normalized_preamble
    assert "vision governs" in normalized_preamble
    assert "target state" in normalized_preamble


def test_readme_context_and_token_limits_match_configuration_defaults() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    capability_section = _isolated_level_two_section(
        readme,
        "## Queue-derived capability status",
    )
    assert "total role-context allocations to 2 MB" not in readme
    assert _field_default_factory("AuditConfig", "repository") == "RepositoryConfig"
    assert _field_default_factory("AuditConfig", "token_budgets") == "TokenBudgetConfig"

    defaults = {
        "repository.max_total_context_bytes": _field_default(
            "RepositoryConfig", "max_total_context_bytes"
        ),
        "token_budgets.maximum_source_tokens_per_request": _field_default(
            "TokenBudgetConfig", "maximum_source_tokens_per_request"
        ),
        "token_budgets.global_input_token_budget": _field_default(
            "TokenBudgetConfig", "global_input_token_budget"
        ),
        "token_budgets.global_output_token_budget": _field_default(
            "TokenBudgetConfig", "global_output_token_budget"
        ),
    }
    for field, expected in defaults.items():
        match = re.search(
            rf"`{re.escape(field)}\s*=\s*(?P<value>[0-9][0-9_,]*)`",
            capability_section,
        )
        assert match is not None, f"README capability section does not name the {field} default"
        documented = int(match.group("value").replace(",", "").replace("_", ""))
        assert documented == expected, (
            f"README documents {field}={documented}, but AuditConfig defines {expected}"
        )
