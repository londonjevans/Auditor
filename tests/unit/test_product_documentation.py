from __future__ import annotations

import ast
import hashlib
import json
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS_PATH = ROOT / "AGENTS.md"
QUEUE_PATH = ROOT / "docs/remediation/v3/work_queue.md"
CODEX_QUEUE_PATH = ROOT / "docs/codex_work_queue.md"
CODEX_WORKLOG_PATH = ROOT / "docs/codex_worklog.md"
TRACEABILITY_PATH = ROOT / "docs/remediation/v3/review_traceability.json"
RUNTIME_STATUS_PATH = ROOT / "docs/remediation/v3/runtime_status.json"
OPERATOR_RESULTS_PATH = ROOT / "docs/remediation/v3/operator_results.md"
README_PATH = ROOT / "README.md"
MODEL_SELECTION_PATH = ROOT / "docs/models/model_selection.md"
SELECTION_PLAN_PATH = ROOT / "config/models.selection-plan.json"
PRODUCT_VISION_PATH = ROOT / "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
CONFIG_PATH = ROOT / "src/mmaudit/config.py"
AUTONOMY_INVENTORY_PATH = ROOT / "docs/remediation/v3/autonomy_gate_inventory.json"
AUTONOMY_INVENTORY_SCHEMA_PATH = ROOT / "schemas/autonomy_gate_inventory.schema.json"
MANAGED_TOOLCHAIN_BUNDLE_PATH = ROOT / "src/mmaudit/resources/managed_toolchain_bundle.json"
MANAGED_TOOLCHAIN_SCHEMA_PATH = ROOT / "schemas/managed_toolchain_bundle.schema.json"

OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
PRODUCT_VISION_RELATIVE_PATH = "product/CORROVERA_SECURITY_AUDITOR_PRODUCT_VISION.md"
PRODUCT_VISION_SHA256 = "8b878b665e636b3b48500fefe2967394b2abdd69ce2ebfa0033d04542d2965e1"
OPERATOR_RESULTS_SHA256 = "25ee5395a7e2360637f89d89cc0e89084a530c8921d0af395b06bc9b700b01e5"
HISTORICAL_R7_OPERATOR_RESULTS_SHA256 = (
    "00de61717cb6d61c003682abca12ae2c7e59613db03ef99558133b972c123516"
)
HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 = (
    "f0c87e608633dc8ae940a977c8207d9e371b2bf683d0a91f415316273d5ac0dc"
)
HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT = "3989e7592de6e1c355365443c10e00c2083829d8"
CURRENT_LINEAGE_RESEAL_CHECKPOINT = "331bde27c7085d4da34c7b8ec1f688f2ce1e52b3"
HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT = "3975d2e12fd81a214b9faa1c3031c94506ab696d"
CURRENT_SELECTION_SUCCESSOR_CHECKPOINT = "dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d"
CURRENT_AUTHRUNNER_SUCCESSOR_CHECKPOINT = CURRENT_SELECTION_SUCCESSOR_CHECKPOINT
HISTORICAL_PHASE_ZERO_CHECKPOINT = "d0402d1c68f0f82d9ee4f8757f7967abda372ac6"
HISTORICAL_PHASE_ZERO_INVENTORY_RAW_SHA256 = (
    "6a3c54258dd1f0c25fc8861c8298cf51d187b33bd5528ec25b1549c0e0021980"
)
AUTONOMY_INVENTORY_RAW_SHA256 = "363a6f0a59b357d250b04412c55ef21a28c4cb98c80b9d598de9d33c18ee7faa"
AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "c762122d00d6655dec1091d4a01188b835801f1ef13cd042d222be6a122184ae"
)
AUTONOMY_INVENTORY_SHA256 = "81d12a36dc0a80f54682e54811b86139985468bb8a026ca74e1be09fa182ef32"
AUTONOMY_SOURCE_UNIVERSE_SHA256 = "b573bae0b27f7f92db65d0475ff183a6c3a89c444d6adce158693f61758557dc"
AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "9d82596b3bfc2cac3bc31882787b1bfe4818c5c0c36b963b6c5ecf4b251e8483"
)
MANAGED_TOOLCHAIN_RAW_SHA256 = "6d427e698d1074be2d20747211bcdd53816509e0e71b4225dff0401c32d6561a"
MANAGED_TOOLCHAIN_SHA256 = "55c412fdb2dd56a2541c0e737d953b5d0e770ece42b4c1c11ebfb7e1c233498d"
MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256 = (
    "068d3daa7a0c661e6ad6781d4184ce27e53edbc3c8867989d5dc0c877b73c785"
)
AUTONOMY_PHASE_ZERO_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_release_schemas.py",
    }
)
HISTORICAL_INELIGIBLE_GEMMA_PLAN_SHA256 = (
    "41b5af9ae4def5ef535ae25a13c7c38b95d5819a878a5eef1c1c5bfb8386bf58"
)
HISTORICAL_INELIGIBLE_GEMMA_ROLE_SHA256 = (
    "f1c80252e94bf789d1b78f424a8b9c142f7e750e8ee0ba3bacfaae2a3330aa25"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256 = (
    "ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256 = (
    "93a2487fceec4771749aa8c33d0870fba70941293bf57a2dd48e6c065e172421"
)
CURRENT_NONAUTHORIZING_ZAI_ENTRY_SHA256 = (
    "45f0a3f416a806932e2596ca4f6381e12bbc4901d15c301b22fd5d607a7f55ef"
)
CURRENT_NONAUTHORIZING_DEEPSEEK_ENTRY_SHA256 = (
    "da576e8d1835b41be94ea4dab6cd6329ae8c1483b830214d9e05acef44e8617b"
)
CURRENT_NONAUTHORIZING_KIMI_ENTRY_SHA256 = (
    "77217b6dca94bc292a13cc5a5ce84c48c68a6bb2e055462db51048013abd3f11"
)
CURRENT_LINEAGE_MANIFEST_SHA256 = "b097a65613a07930f5c256c63065202a8998d5212a0021312a0e315ff6557b53"
CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256 = (
    "815fc0e376682f83f994ac5c21962c5f43556a78f5e736045f93a6ee81e5de0d"
)
NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT = "68d774b2cee5fa69476b1cfea2f8172731a365c8"
HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT = "b4134c70641e33cbbff2b430b135910df903733b"
HISTORICAL_R6_R6_R2_OPERATOR_RESULTS_SHA256 = (
    "e7e631be16b5502f6e16b1d2aeae9ac226d8d79050263f27555f5ff8f812b0fd"
)
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
_QUEUE_TICKET_HEADING = re.compile(r"^#{2,3} (?P<title>[^\n]+)$", re.MULTILINE)
_TICKET_TITLE = re.compile(r"^(?P<ticket>V3-[A-Z0-9]+(?:-[A-Z0-9]+)*)\b")
_ANY_TICKET_TITLE = re.compile(r"^(?P<ticket>[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\b")
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


def _parse_all_queue_ticket_statuses(document: str) -> dict[str, str]:
    headings = list(_QUEUE_TICKET_HEADING.finditer(document))
    statuses: dict[str, str] = {}
    for index, heading in enumerate(headings):
        ticket_match = _ANY_TICKET_TITLE.match(heading.group("title"))
        if ticket_match is None:
            continue
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
        body = document[heading.end() : body_end]
        status_matches = list(_TICKET_STATUS.finditer(body))
        if not status_matches:
            continue
        ticket = ticket_match.group("ticket")
        assert ticket not in statuses, f"duplicate queue ticket heading: {ticket}"
        assert len(status_matches) == 1, (
            f"queue ticket {ticket} must have exactly one anchored Status line; "
            f"found {len(status_matches)}"
        )
        status = status_matches[0].group("status")
        assert status in ALLOWED_TICKET_STATUSES, (
            f"queue ticket {ticket} has unsupported status {status}"
        )
        statuses[ticket] = status
    assert statuses, "queue contains no parseable ticket blocks"
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


def test_phase_zero_checkpoint_resolves_and_owns_exact_inventory_paths() -> None:
    resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_PHASE_ZERO_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_PHASE_ZERO_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    source_tree = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            HISTORICAL_PHASE_ZERO_CHECKPOINT,
            "src",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    historical_inventory = subprocess.run(
        [
            "git",
            "show",
            f"{HISTORICAL_PHASE_ZERO_CHECKPOINT}:docs/remediation/v3/autonomy_gate_inventory.json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )

    assert resolved.stdout.strip() == HISTORICAL_PHASE_ZERO_CHECKPOINT
    assert frozenset(changed.stdout.splitlines()) == AUTONOMY_PHASE_ZERO_PATHS
    assert sum(path.endswith(".py") for path in source_tree.stdout.splitlines()) == 207
    assert (
        hashlib.sha256(historical_inventory.stdout).hexdigest()
        == HISTORICAL_PHASE_ZERO_INVENTORY_RAW_SHA256
    )


def test_combined_queue_unfinished_count_is_derived() -> None:
    canonical = _parse_all_queue_ticket_statuses(QUEUE_PATH.read_text(encoding="utf-8"))
    codex = _parse_all_queue_ticket_statuses(CODEX_QUEUE_PATH.read_text(encoding="utf-8"))
    for ticket in canonical.keys() & codex.keys():
        assert canonical[ticket] == codex[ticket], f"queue status disagreement for {ticket}"
    combined = codex | canonical
    unfinished = sum(status != "COMPLETE" for status in combined.values())

    assert unfinished == 43
    assert (
        "REMAINING_ACTIONABLE_TICKETS: The combined queues contain "
        f"{unfinished} unfinished tickets."
    ) in CODEX_WORKLOG_PATH.read_text(encoding="utf-8")


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
    normalized_model_selection = " ".join(model_selection.split())
    selection_plan = json.loads(SELECTION_PLAN_PATH.read_text(encoding="utf-8"))
    operator_result_bytes = OPERATOR_RESULTS_PATH.read_bytes()
    operator_results = operator_result_bytes.decode("utf-8")
    queues = (
        (ROOT / "docs/codex_work_queue.md").read_text(encoding="utf-8"),
        QUEUE_PATH.read_text(encoding="utf-8"),
    )
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    autonomy_inventory_bytes = AUTONOMY_INVENTORY_PATH.read_bytes()
    autonomy_inventory = json.loads(autonomy_inventory_bytes)
    autonomy_schema_bytes = AUTONOMY_INVENTORY_SCHEMA_PATH.read_bytes()
    autonomy_schema = json.loads(autonomy_schema_bytes)
    managed_toolchain_bytes = MANAGED_TOOLCHAIN_BUNDLE_PATH.read_bytes()
    managed_toolchain = json.loads(managed_toolchain_bytes)
    managed_toolchain_schema_bytes = MANAGED_TOOLCHAIN_SCHEMA_PATH.read_bytes()
    managed_toolchain_schema = json.loads(managed_toolchain_schema_bytes)
    assert runtime_status["real_model_calls"] == {
        "attempted": 12,
        "succeeded": 2,
        "rejected": 10,
    }
    assert runtime_status["openrouter_budget_usd"] == {
        "cap": "250.00000000",
        "used": "0.01680888",
        "reserved": "0.00000000",
        "remaining": "249.98319112",
    }
    assert runtime_status["historical_governed_ledger_evidence"] == {
        "entry_count": 11,
        "used_usd": "0.0034764325",
        "reserved_usd": "0.00000000",
        "remaining_usd": "249.9965235675",
        "is_current_live_campaign_ledger": False,
    }
    assert runtime_status["live_authrunner_campaign_ledger"] == {
        "entry_count": 1,
        "used_usd": "0.01680888",
        "reserved_usd": "0.00000000",
        "remaining_usd": "249.98319112",
        "entry_status": "reconciled",
        "is_authority": False,
    }
    preflight_status = runtime_status["historical_authrunner_provider_free_r2_r5_r2_preflight"]
    assert preflight_status["status"] == (
        "VALID_NONAUTHORIZING_NO_PROVIDER_EGRESS_HISTORICAL_R2_R5_R2"
    )
    assert preflight_status["scope"] == "HISTORICAL_R2_R5_R2_AFTER_A1ACE778_DO_NOT_RERUN"
    smoke_status = runtime_status["authrunner_noncrediting_smoke"]
    exact_status = runtime_status["authrunner_exact_cost_admission"]
    local_contract = preflight_status["local_preflight_contract"]
    lineage_r2_command = (
        ".venv/bin/python scripts/capture_public_model_lineage.py --output-dir "
        "/private/tmp/mmaudit-public-lineage-20260821-r2"
    )
    tencent_r5_command = (
        'MMAUDIT_SECRETS_ENV_FILE="$HOME/.mmaudit/secrets.env" MMAUDIT_BUDGET_USD=250 '
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models discover --candidate tencent/hy3=tencent/fp8 "
        "--config config/openrouter-qualification.toml --secrets-env-file "
        '"$HOME/.mmaudit/secrets.env" --output-dir '
        '"$HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r5" '
        "--candidate-selection-plan config/models.selection-plan.json "
        "--candidate-selection-ranking-source "
        "/Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/"
        "model-ranking.py --candidate-selection-lineage-review-source "
        "/Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/"
        "V3-LINEAGE-001-operator-review.md --candidate-registry-output "
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r5.json" --no-color'
    )
    smoke_real_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE MMAUDIT_BUDGET_USD=250 "
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models authenticated-runner-smoke --candidate-registry "
        '"$HOME/.mmaudit/private/authrunner/candidate-registry-r6.json" '
        '--candidate-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-candidate-20260821-r6" --primary-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r6.json" '
        '--primary-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-primary-judge-20260821-r6" --replay-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/replay-judge-registry-r2.json" '
        '--replay-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-replay-judge-20260820-r2" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        '--output "$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260821-s1.json" '
        "--candidate-cost-cap-usd-per-attempt 1.00 "
        "--primary-judge-cost-cap-usd-per-attempt 1.00 "
        "--replay-judge-cost-cap-usd-per-attempt 1.00 "
        "--config config/openrouter-qualification.toml "
        "--corpus benchmarks/model_corpus/manifest.json "
        '--cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        '--secrets-env-file "$HOME/.mmaudit/secrets.env" '
        "--allow-code-egress --no-color"
    )
    smoke_preflight_command = smoke_real_command.replace(
        "--allow-code-egress --no-color",
        "--allow-code-egress --preflight-only --no-color",
    )
    smoke_live_route_command = smoke_real_command.replace(
        "--allow-code-egress --no-color",
        "--allow-metadata-egress --live-route-preflight-only --no-color",
    )
    smoke_verify_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE MMAUDIT_BUDGET_USD=250 "
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        ".venv/bin/mmaudit models verify-authenticated-runner-smoke --bundle "
        '"$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260821-s1.json" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        "--corpus benchmarks/model_corpus/manifest.json "
        "--config config/openrouter-qualification.toml --no-color"
    )
    smoke_file_sha256s = {
        "manifest.json": "aa453f655a4d09adf19498387c9cd2b48939119f1494e9517182dbb2b3ee685c",
        "ground_truth.json": "e5e2baef1b986c77ae448fad1eb96052f061a8db1daae1b6f4122f61cbce8765",
        "provenance.json": "d3f9e13733949f660ae4f3eeac8c3576a8b8b620e37adb4f1fc268e45163d46c",
        "verdict_policy.json": "79b1aee6b28fc90f64887fff189b9f404114bd7671a7363bdb437e19d258d68f",
    }
    assert "docs/remediation/v3/operator_results.md" in agents
    assert "Before ending any turn that issued, reissued, or depended on an operator command" in (
        agents
    )
    assert "../remediation/v3/operator_results.md" in model_selection
    assert hashlib.sha256(operator_result_bytes).hexdigest() == OPERATOR_RESULTS_SHA256
    assert HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in model_selection
    assert all(HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in queue for queue in queues)
    for filename, expected_sha256 in smoke_file_sha256s.items():
        artifact_bytes = (ROOT / "benchmarks/model_corpus_smoke" / filename).read_bytes()
        assert hashlib.sha256(artifact_bytes).hexdigest() == expected_sha256
        assert expected_sha256 in model_selection
    assert "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497" in (model_selection)
    assert selection_plan["plan_sha256"] == CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    assert selection_plan["plan_sha256"] in model_selection
    assert selection_plan["schema_version"] == "1.3"
    assert selection_plan["authenticated_runner_selection"]["required_reasoning_effort"] == "high"
    assert (
        selection_plan["authenticated_runner_selection"]["required_completion_limit_source"]
        == "metadata"
    )
    assert '`effort = "high"`' in model_selection
    assert "4,096-token atomic reasoning reserve" in normalized_model_selection
    assert "falls back to the exact frozen model-catalog inventory only when" in (
        normalized_model_selection
    )
    assert "MiniMax M3" in model_selection
    assert "It is no longer selected." in model_selection
    assert model_selection.count(lineage_r2_command) == 1
    assert model_selection.count(tencent_r5_command) == 1
    assert "historical command records and must not be rerun" in normalized_model_selection
    assert "9075ca7635c861194cc732e67d9ebb92e6ffa0af" in model_selection
    assert smoke_live_route_command not in model_selection
    assert smoke_real_command not in model_selection
    assert (
        smoke_live_route_command.replace(
            "--allow-metadata-egress --live-route-preflight-only --no-color",
            "--allow-code-egress --no-color",
        )
        == smoke_real_command
    )
    assert smoke_preflight_command not in model_selection
    assert smoke_verify_command not in model_selection
    assert ".venv/bin/mmaudit models authenticated-runner-smoke" not in model_selection
    assert ".venv/bin/mmaudit models verify-authenticated-runner-smoke" not in model_selection
    assert ".venv/bin/mmaudit models authenticated-runner --" not in model_selection
    assert "--live-route-preflight-only" not in model_selection
    assert "--allow-metadata-egress" not in model_selection
    assert "--allow-code-egress" not in model_selection
    assert "--preflight-only" not in model_selection
    assert "PENDING_TENCENT_LINEAGE_RESEAL_CHECKPOINT" not in model_selection
    assert "a1ace778afcf308b57fe436271cdc16a2bb8e156" in model_selection
    assert "af70559ddaf84178efffee1ec1bf7b99bf0b12df" in model_selection
    assert "Add noncrediting provider smoke path" in normalized_model_selection
    assert "7e9db03145b4afc1834dd47e9f4f97800e1edffb" in model_selection
    assert "Fix smoke null lineage projection" in normalized_model_selection
    assert "f0a0f39ee275bc774709bd0fbff411cfa7ecac04" in model_selection
    assert "Document provider-free smoke preflight" in normalized_model_selection
    assert "provider-free r2/r5/r2 preflight" in normalized_model_selection
    assert "has now completed and is historical; do not rerun it" in (normalized_model_selection)
    assert "Post-origin fixes, failed one-case REAL attempt, and token-budget parity repair" in (
        model_selection
    )
    assert "smoke public lineage returned a non-independent projection" in (
        normalized_model_selection
    )
    assert "root_lineage = None" in model_selection
    assert "The operator ran it verbatim. It is now historical and must not be rerun." in (
        normalized_model_selection
    )
    assert "f5afb2bff074254ee5c4a484386ee4c416b17a88" in model_selection
    assert "historical and unsafe to execute" in normalized_model_selection
    assert "accepted only `RELEASE_PINNED_MODEL_BENCHMARK`" in normalized_model_selection
    assert "`RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION`" in model_selection
    assert "`PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK`" in model_selection
    assert "`PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION`" in model_selection
    assert "after a provider response had been charged and bound" in normalized_model_selection
    assert "REAL bound usage lacks AUTHRUNNER transport-origin custody" in (
        normalized_model_selection
    )
    assert "first paid candidate completion could therefore have spent money and then failed" in (
        normalized_model_selection
    )
    assert "Provider-free preflight cannot exercise that post-response issuer boundary" in (
        normalized_model_selection
    )
    assert "Both the paid smoke and its conditional offline verifier are withdrawn" in (
        normalized_model_selection
    )
    assert "request and atomic global input token budgets differ" in normalized_model_selection
    assert "no bundle was published" in normalized_model_selection
    assert "no paid smoke attempt, provider completion, or spend occurred" in (
        normalized_model_selection
    )
    assert "only for a `PENDING` review with a null registry root" in (normalized_model_selection)
    assert "33 focused and 81 bounded smoke/neighbor tests" in normalized_model_selection
    assert "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6" in model_selection
    assert "c9a8923064ef1bb606a67b14641c4c8df55bc9ea" in model_selection
    assert "Bind smoke REAL origin custody" in normalized_model_selection
    assert "four closed proof kinds to its disjoint request namespace" in normalized_model_selection
    assert "release candidate and cross-lineage requests retain only" in normalized_model_selection
    assert "smoke candidate and judge namespaces admit only" in normalized_model_selection
    assert (
        "Missing, malformed, cross-kind, release-to-smoke, smoke-to-release, and forged namespace "
        "mappings reject." in normalized_model_selection
    )
    assert "admitting a smoke proof kind grants no release" in normalized_model_selection
    assert "Implementer validation passed 584 provider-free tests" in normalized_model_selection
    assert "Independent validation passed 371 usage/OpenRouter tests" in normalized_model_selection
    assert "83 runner/smoke/cross-lineage tests" in normalized_model_selection
    assert "123 generation/candidate tests" in normalized_model_selection
    assert "577 broad tests total" in normalized_model_selection
    assert (
        "final focused checks passed 22 usage-scope and three OpenRouter transport-path tests"
        in (normalized_model_selection)
    )
    assert "red-team verdict was clean with no blocker/HIGH" in normalized_model_selection
    assert "repository-wide Ruff passed" in normalized_model_selection
    assert "full 206-source tree" in normalized_model_selection
    assert "whole-repository format check is intentionally not credited" in (
        normalized_model_selection
    )
    assert "59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb" in model_selection
    assert "Bind AUTHRUNNER token budgets" in normalized_model_selection
    assert "136-test five-file AUTHRUNNER matrix" in normalized_model_selection
    assert "Independent paid-readiness review" in normalized_model_selection
    assert "no blocker/HIGH" in normalized_model_selection
    assert "blocking lifecycle gap" in normalized_model_selection
    assert "retained candidate-campaign" in normalized_model_selection
    assert "Negative downstream consumer tests cover" in normalized_model_selection
    assert "Every previously emitted AUTHRUNNER command is now withdrawn" in (
        normalized_model_selection
    )
    assert "There is currently no runnable metadata, discovery, smoke, verifier" in (
        normalized_model_selection
    )
    assert "full AUTHRUNNER command" in normalized_model_selection
    assert "9f5c94d97b3d79d51c10e250b99244591461e959" in model_selection
    assert "3bcac02da30bdad2c7e584d35c091ea5cb75ea7d" in model_selection
    assert "Its first candidate completion reached the real transport" in normalized_model_selection
    assert "SCHEMA_VALIDATION_FAILED" in model_selection
    assert "$0.0547272` was reserved" in model_selection
    assert "$0.01680888` was charged and reconciled" in model_selection
    assert "provider-free `REVOCATION_CASCADE_FIX` is complete and clean" in (
        normalized_model_selection
    )
    assert "692eb173f002818b4434b746c8801b4cbeb852e2" in model_selection
    assert "exact PID-bound campaign and generation revokers" in normalized_model_selection
    assert "parent-to-child cascade" in normalized_model_selection
    assert "traceback-safe execution handoff guards" in normalized_model_selection
    assert "candidate and judge generation-capability revocation" in normalized_model_selection
    assert "229 focused and 266 adjacent tests" in normalized_model_selection
    assert "format over 510 tracked Python files" in normalized_model_selection
    assert "strict mypy over 206 source files" in normalized_model_selection
    assert "independent review reported `CLEAN` with no blocker/HIGH" in model_selection
    assert "no genuine owned-REAL parent capability" in normalized_model_selection
    assert "required_output_mode = NATIVE_JSON_SCHEMA" in model_selection
    assert "literal required provider parameter `structured_outputs`" in normalized_model_selection
    assert selection_plan["authenticated_runner_selection"]["role_assignment_sha256"] in (
        model_selection
    )
    assert "`max_json_repair_attempts = 0` is deliberate" in model_selection
    assert "noncreditable" in normalized_model_selection
    assert "route capability—not repair—is the correction" in normalized_model_selection
    assert "current r2/r5/r2 input composition" not in normalized_model_selection
    assert "candidate-registry-r6.json" in model_selection
    assert "authrunner-candidate-20260821-r6" in model_selection
    assert "primary-judge-registry-r6.json" in model_selection
    assert "authrunner-primary-judge-20260821-r6" in model_selection
    assert runtime_status["candidate_commit"] == HISTORICAL_PHASE_ZERO_CHECKPOINT
    assert runtime_status["candidate_commit_pushed"] is False
    assert runtime_status["candidate_commit_remote_resolved"] is False
    assert runtime_status["candidate_successor_commit"] == HISTORICAL_PHASE_ZERO_CHECKPOINT
    assert runtime_status["candidate_successor_status"] == (
        "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert runtime_status["historical_paid_diagnostic_base_commit"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert runtime_status["last_checkpoint_commit"] == HISTORICAL_PHASE_ZERO_CHECKPOINT
    assert runtime_status["autorun_status"] == "RUNNING_PROVIDER_FREE"
    assert runtime_status["current_ticket"] == "V3-AUTONOMY-001"
    assert runtime_status["active_provider_free_work"] == {
        "ticket": "V3-AUTONOMY-001",
        "slice": "PHASE_1_MANAGED_TOOLCHAIN_BUNDLE",
        "status": "COMPLETE_NONAUTHORIZING_WITHIN_IN_PROGRESS_TICKET",
        "next_slice": "PHASE_2_MANAGED_PROVISIONING_STATE",
        "provider_access_authorized": False,
        "secret_access_authorized": False,
        "private_operator_artifact_access_authorized": False,
        "runtime_authority_granted": False,
        "operator_metadata_egress_command_emitted": False,
        "operator_paid_smoke_command_emitted": False,
        "operator_command_execution_authorized": False,
        "parked_ticket": "V3-AUTHRUNNER-001",
        "parked_ticket_status": "PARTIAL_REAL_BLOCKED_SAFETY_NO_CURRENT_COMMAND",
    }
    phase_zero = runtime_status["autonomy_phase_zero_inventory"]
    assert phase_zero == {
        "status": "COMPLETE_NONAUTHORIZING",
        "implementation_commit": HISTORICAL_PHASE_ZERO_CHECKPOINT,
        "implementation_commit_pushed": False,
        "implementation_commit_remote_resolved": False,
        "artifact_path": "docs/remediation/v3/autonomy_gate_inventory.json",
        "schema_path": "schemas/autonomy_gate_inventory.schema.json",
        "artifact_reconciled_for_slice": "PHASE_1_MANAGED_TOOLCHAIN_BUNDLE",
        "artifact_raw_sha256": AUTONOMY_INVENTORY_RAW_SHA256,
        "schema_raw_sha256": AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256,
        "source_discovery_semantics_sha256": AUTONOMY_DISCOVERY_SEMANTICS_SHA256,
        "source_universe_sha256": AUTONOMY_SOURCE_UNIVERSE_SHA256,
        "inventory_sha256": AUTONOMY_INVENTORY_SHA256,
        "source_count": 3627,
        "source_occurrence_count": 3630,
        "gate_source_count": 3584,
        "non_gating_source_count": 43,
        "logical_gate_count": 35,
        "unsatisfied_gate_count": 29,
        "current_manual_gate_count": 15,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "next_slice": "PHASE_2_MANAGED_PROVISIONING_STATE",
    }
    assert runtime_status["managed_toolchain_phase_one"] == {
        "status": "COMPLETE_NONAUTHORIZING",
        "bundle_path": "src/mmaudit/resources/managed_toolchain_bundle.json",
        "schema_path": "schemas/managed_toolchain_bundle.schema.json",
        "bundle_raw_sha256": MANAGED_TOOLCHAIN_RAW_SHA256,
        "bundle_sha256": MANAGED_TOOLCHAIN_SHA256,
        "schema_raw_sha256": MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256,
        "first_class_role_count": 28,
        "pinned_role_count": 3,
        "unresolved_role_count": 25,
        "managed_gate_status": "PARTIAL",
        "independently_trusted": False,
        "provisioning_state_verified": False,
        "installed_members_verified": False,
        "transitive_dependency_closure_verified": False,
        "image_side_attestation_verified": False,
        "execution_evidence_verified": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "next_slice": "PHASE_2_MANAGED_PROVISIONING_STATE",
    }
    assert hashlib.sha256(autonomy_inventory_bytes).hexdigest() == AUTONOMY_INVENTORY_RAW_SHA256
    assert hashlib.sha256(autonomy_schema_bytes).hexdigest() == AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256
    assert hashlib.sha256(managed_toolchain_bytes).hexdigest() == MANAGED_TOOLCHAIN_RAW_SHA256
    assert (
        hashlib.sha256(managed_toolchain_schema_bytes).hexdigest()
        == MANAGED_TOOLCHAIN_SCHEMA_RAW_SHA256
    )
    assert autonomy_inventory["schema_version"] == "1.0"
    assert autonomy_inventory["phase"] == "PHASE_0_INVENTORY_ONLY"
    assert autonomy_inventory["status"] == "PARTIAL_NONAUTHORIZING"
    assert autonomy_inventory["source_discovery_semantics_sha256"] == (
        AUTONOMY_DISCOVERY_SEMANTICS_SHA256
    )
    assert autonomy_inventory["source_universe_sha256"] == AUTONOMY_SOURCE_UNIVERSE_SHA256
    assert autonomy_inventory["inventory_sha256"] == AUTONOMY_INVENTORY_SHA256
    assert autonomy_inventory["source_count"] == 3627
    assert autonomy_inventory["source_occurrence_count"] == 3630
    assert autonomy_inventory["gate_source_count"] == 3584
    assert autonomy_inventory["logical_gate_count"] == 35
    assert autonomy_inventory["unsatisfied_gate_count"] == 29
    assert autonomy_inventory["current_manual_gate_count"] == 15
    assert autonomy_inventory["provider_or_network_accessed"] is False
    assert autonomy_inventory["secret_material_read"] is False
    assert autonomy_inventory["runtime_authority"] is False
    assert autonomy_inventory["managed_run_ready"] is False
    assert autonomy_schema["properties"]["runtime_authority"]["const"] is False
    assert autonomy_schema["properties"]["managed_run_ready"]["const"] is False
    managed_gate = next(
        gate
        for gate in autonomy_inventory["logical_gates"]
        if gate["gate_id"] == "gate-managed-toolchain-bundle"
    )
    assert managed_gate["implementation_state"] == "PARTIAL"
    assert "28 first-class managed roles" in managed_gate["implementation_detail"]
    assert (
        "fixed operating-system probe helpers remain unmodeled"
        in (managed_gate["implementation_detail"])
    )
    assert managed_toolchain["schema_version"] == "1.0"
    assert managed_toolchain["status"] == "PARTIAL_NONAUTHORIZING"
    assert managed_toolchain["bundle_sha256"] == MANAGED_TOOLCHAIN_SHA256
    assert len(managed_toolchain["members"]) == 28
    assert sum(member["disposition"] == "PINNED" for member in managed_toolchain["members"]) == 3
    assert (
        sum(member["disposition"] == "UNRESOLVED" for member in managed_toolchain["members"]) == 25
    )
    assert managed_toolchain["limitations"] == [
        "Config projection is not installed or executed process identity evidence.",
        "Generic rootless execution is refused until every image-side executable is modeled.",
        "Image-side executable and relay identities remain unattested until provisioning.",
        "Fixed operating-system probe helpers remain unmodeled and lack exact identity verification.",
        "Single-file hashes do not verify transitive dependency closures.",
    ]
    for flag in (
        "independently_trusted",
        "provisioning_state_verified",
        "installed_members_verified",
        "transitive_dependency_closure_verified",
        "image_side_attestation_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert managed_toolchain[flag] is False
        assert managed_toolchain_schema["properties"][flag]["const"] is False
    assert runtime_status["last_validation"]["real_provider_accessed"] is False
    assert runtime_status["last_validation"]["operator_secret_accessed"] is False
    assert runtime_status["last_validation"]["operator_private_ledger_accessed_or_mutated"] is False
    resume_action = runtime_status["pause_state"]["resume_action_v3_authrunner"]
    assert "Park V3-AUTHRUNNER-001 PARTIAL" in resume_action
    assert "V3-AUTONOMY-001 Phase 0 and Phase 1 are complete nonauthorizing" in resume_action
    assert "Phase 2 managed provisioning state is the next provider-free slice" in resume_action
    assert smoke_status["implementation_checkpoint"] == ("692eb173f002818b4434b746c8801b4cbeb852e2")
    assert smoke_status["post_origin_fix_guide_checkpoint"] == (
        "c137f8bae9d27f5120e7e08eba2d9b5b384e1ca5"
    )
    assert smoke_status["paid_smoke_guide_checkpoint"] == (
        "7b2db061ceb7449674399d6133428b97b74b4b96"
    )
    assert "7b2db061ceb7449674399d6133428b97b74b4b96" in model_selection
    assert smoke_status["preflight_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_NO_PROVIDER_EGRESS_POST_TOKEN_BUDGET_FIX"
    )
    assert smoke_status["provider_free_preflight_command_emission_status"] == (
        "HISTORICAL_EXECUTED_VALID_DO_NOT_RERUN"
    )
    assert smoke_status["status"] == (
        "PARTIAL_R8_LIVE_ROUTE_VALID_LOCAL_CHECKPOINT_NOT_PUSHED_REAL_BLOCKED_SAFETY"
    )
    assert smoke_status["ticket_status"] == "PARTIAL"
    assert smoke_status["real_execution_status"] == (
        "FAILED_SAFE_AFTER_REAL_COMPLETION_SCHEMA_VALIDATION_FAILED_COST_RECONCILED_NO_BUNDLE"
    )
    assert smoke_status["real_command_emission_status"] == (
        "ABSENT_WITHDRAWN_AFTER_EXECUTED_FAILED_SAFE"
    )
    assert smoke_status["offline_verifier_command_emission_status"] == (
        "ABSENT_WITHHELD_NO_CURRENT_BUNDLE"
    )
    assert smoke_status["live_route_preflight_command_emission_status"] == (
        "ABSENT_WITHDRAWN_HISTORICAL_R6_R6_R2_RESULT_RETAINED"
    )
    assert smoke_status["full_24_case_real_command_status"] == "ABSENT_WITHHELD_BLOCKED_SAFETY"
    assert smoke_status["current_operator_results_sha256"] == OPERATOR_RESULTS_SHA256
    assert smoke_status["current_operator_results_bytes"] == 71_771
    assert smoke_status["current_operator_results_lines"] == 1_276
    historical_partial_metadata = smoke_status["historical_r7_partial_metadata_discovery"]
    assert historical_partial_metadata["implementation_checkpoint"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert historical_partial_metadata["candidate_status"] == "SUCCESS"
    historical_r7_gate = smoke_status["historical_r7_live_route_gate"]
    assert historical_r7_gate["composition"] == "r7/r7/r7"
    assert historical_r7_gate["metadata_discovery_status"] == "ALL_THREE_REGISTRIES_FROZEN"
    assert historical_r7_gate["live_route_gate_status"] == "FAILED_SAFE_BEFORE_PAID_TRANSPORT"
    assert historical_r7_gate["failure_role"] == "primary"
    assert historical_r7_gate["failure_model_id"] == "google/gemma-4-26b-a4b-it"
    assert historical_r7_gate["required_reasoning_effort"] == "high"
    assert historical_r7_gate["supported_reasoning_efforts"] == []
    assert historical_r7_gate["model_completions"] == 0
    assert historical_r7_gate["incremental_spend_usd"] == "0"
    assert historical_r7_gate["live_campaign_ledger_entry_count"] == 1
    assert historical_r7_gate["authority"] is False
    latest_capture = smoke_status["latest_glm_5_2_lineage_capture_and_reseal"]
    assert latest_capture["operator_results_sha256"] == OPERATOR_RESULTS_SHA256
    assert latest_capture["operator_results_bytes"] == 71_771
    assert latest_capture["operator_results_lines"] == 1_276
    assert latest_capture["reported_capture_source_count"] == 17
    assert latest_capture["capture_status"] == (
        "SUCCESS_ADOPTED_PROVIDER_FREE_DOCUMENTARY_IDENTITY_ONLY"
    )
    assert latest_capture["manifest_sha256"] == CURRENT_LINEAGE_MANIFEST_SHA256
    assert (
        latest_capture["manifest_semantic_bundle_sha256"] == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    )
    assert latest_capture["reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert latest_capture["model_completions"] == 0
    assert latest_capture["incremental_spend_usd"] == "0"
    assert latest_capture["output_authority"] is False
    assert latest_capture["current_operator_command_emitted"] is False
    current_lineage = runtime_status["authrunner_documentary_lineage_reseal"]
    assert current_lineage["manifest_sha256"] == CURRENT_LINEAGE_MANIFEST_SHA256
    assert current_lineage["manifest_size_bytes"] == 61_852
    assert current_lineage["semantic_bundle_sha256"] == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    assert current_lineage["source_count"] == 17
    assert current_lineage["alias_count"] == 16
    assert current_lineage["claim_count"] == 18
    assert current_lineage["decision_count"] == 16
    assert current_lineage["confirmed_identity_count"] == 12
    assert current_lineage["unconfirmed_identity_count"] == 4
    assert current_lineage["approved_root_count"] == 11
    assert current_lineage["constraint_count"] == 8
    assert current_lineage["active_runner_triple_directed_independence_pairs_passed"] == 6
    assert current_lineage["current_reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert current_lineage["current_reseal_checkpoint_pushed"] is False
    assert current_lineage["current_reseal_checkpoint_remote_resolved"] is False
    assert smoke_status["current_live_route_fields_status"] == (
        "HISTORICAL_R6_R6_R2_PREFLIGHT_EVIDENCE_NOT_A_CURRENT_COMMAND"
    )
    assert smoke_status["current_live_route_composition"] == "r6/r6/r2"
    assert smoke_status["current_live_route_preflight_succeeded"] is True
    assert smoke_status["current_live_route_preflight_logical_gets"] == 15
    assert smoke_status["current_live_route_preflight_maximum_provider_attempts"] == 30
    assert smoke_status["current_live_route_preflight_provider_completions"] == 0
    assert smoke_status["current_live_route_preflight_usage_records"] == 0
    assert smoke_status["current_live_route_preflight_budget_unchanged"] is True
    assert smoke_status["current_live_route_preflight_atomic_ledger_unchanged"] is True
    assert smoke_status["current_live_route_preflight_output_published"] is False
    assert smoke_status["zero_command_evidence_checkpoint"] == (
        "02ed5bef89d094e0d0c4852e1bf73914d9960c6b"
    )
    assert smoke_status["historical_command_guide_checkpoint"] == (
        "4bebab16bb2e36d54665918dec64429602b4f4e6"
    )
    assert smoke_status["historical_command_guide_checkpoint_pushed"] is True
    assert smoke_status["historical_command_guide_checkpoint_remote_resolved"] is True
    assert smoke_status["historical_adjacent_pair_emitted_then_paid_executed_and_withdrawn"] is True
    assert smoke_status["adjacent_sequence_required"] is True
    assert smoke_status["current_adjacent_command_count"] == 0
    assert smoke_status["current_adjacent_commands_emitted_not_run"] is False
    assert smoke_status["paid_execution_adjacency_status"] == (
        "UNPROVEN_NO_FRESH_IMMEDIATE_POST_B413_STEP_A_RESULT_RECORDED"
    )
    assert smoke_status["commands_must_not_be_chained"] is True
    assert smoke_status["pre_a_ledger_exactly_empty_inspection_required"] is True
    assert smoke_status["pre_a_output_absent_inspection_required"] is True
    assert smoke_status["pre_a_output_parent_mode_0700_inspection_required"] is True
    assert smoke_status["pre_a_exact_artifact_and_config_inspection_required"] is True
    assert smoke_status["step_a_exit_zero_required"] is True
    assert smoke_status["step_a_complete_exact_result_required"] is True
    assert smoke_status["step_b_separate_operator_authorization_required"] is True
    assert smoke_status["step_b_must_begin_immediately_after_step_a_review"] is True
    assert smoke_status["delay_or_interruption_requires_step_a_rerun"] is True
    assert (
        smoke_status[
            "intervening_source_config_artifact_ledger_output_secret_or_shell_env_change_allowed"
        ]
        is False
    )
    assert smoke_status["normal_provider_free_preflight_currently_emitted"] is False
    assert smoke_status["operator_paid_smoke_run"] is True
    assert smoke_status["operator_paid_smoke_succeeded"] is False
    assert smoke_status["operator_paid_smoke_model_completion_requests"] == 1
    assert smoke_status["operator_paid_smoke_provider_completions"] == 1
    assert smoke_status["operator_paid_smoke_authenticated_metadata_get_count"] is None
    assert smoke_status["operator_paid_smoke_reserved_usd"] == "0.0547272"
    assert smoke_status["operator_paid_smoke_spend_usd"] == "0.01680888"
    assert smoke_status["operator_paid_smoke_accounted_cost_usd"] == "0.01680888"
    assert smoke_status["operator_paid_smoke_ledger_entry_status"] == "reconciled"
    assert smoke_status["operator_paid_smoke_ledger_empty"] is False
    assert smoke_status["operator_paid_smoke_bundle_published"] is False
    assert smoke_status["operator_paid_smoke_verifier_run"] is False
    assert smoke_status["operator_paid_smoke_authenticated_metadata_egress"] is True
    assert smoke_status["operator_paid_smoke_failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert smoke_status["operator_paid_smoke_failure_phase"] == (
        "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    )
    assert smoke_status["operator_paid_smoke_failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert smoke_status["current_paid_smoke_authorization_status"] == (
        "ABSENT_WITHDRAWN_AFTER_EXECUTED_FAILED_SAFE"
    )
    assert smoke_status["maximum_assurance_json_repair_attempts"] == 0
    assert smoke_status["certification_model_output_repair_allowed"] is False
    assert smoke_status["repaired_output_creditable"] is False
    assert smoke_status["native_structured_output_eligibility_checkpoint"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert smoke_status["native_structured_output_eligibility_checkpoint_pushed"] is False
    assert smoke_status["native_structured_output_eligibility_checkpoint_remote_verified"] is False
    assert smoke_status["origin_custody_code_fix_status"] == (
        "IMPLEMENTED_CHECKPOINTED_PUSHED_REMOTE_VERIFIED_NONAUTHORIZING"
    )
    assert smoke_status["token_budget_parity_fix_checkpoint"] == (
        "59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb"
    )
    assert smoke_status["token_budget_parity_fix_validation"]["owner_five_file_tests_passed"] == 136
    assert smoke_status["token_budget_parity_fix_validation"]["root_five_file_tests_passed"] == 136
    assert smoke_status["token_budget_parity_fix_validation"]["independent_tests_passed"] == 122
    assert (
        smoke_status["token_budget_parity_fix_validation"]["focused_cli_ordering_tests_passed"] == 7
    )
    assert (
        smoke_status["origin_custody_fix_validation"][
            "terminal_full_suite_status_for_current_reconciliation"
        ]
        == "INTERRUPTED_CONCURRENT_OPERATOR_EVIDENCE_CHANGE_NO_CREDIT"
    )
    assert (
        smoke_status["origin_custody_fix_validation"][
            "terminal_full_suite_tests_passed_before_interruption"
        ]
        == 82
    )
    assert (
        smoke_status["origin_custody_fix_validation"][
            "terminal_full_suite_prerequisite_skips_before_interruption"
        ]
        == 13
    )
    cascade_validation = smoke_status["revocation_cascade_fix_validation"]
    assert cascade_validation["checkpoint"] == "692eb173f002818b4434b746c8801b4cbeb852e2"
    assert cascade_validation["root_focused_tests_passed"] == 229
    assert cascade_validation["root_adjacent_tests_passed"] == 266
    assert cascade_validation["campaign_revoker_pid_bound"] is True
    assert cascade_validation["generation_revoker_pid_bound"] is True
    assert cascade_validation["parent_cascade"] is True
    assert cascade_validation["traceback_safe_execution_handoff"] is True
    assert cascade_validation["smoke_candidate_generation_immediate_revoke"] is True
    assert cascade_validation["smoke_judge_generation_immediate_revoke"] is True
    assert cascade_validation["tracked_python_format_files_unchanged"] == 510
    assert cascade_validation["strict_mypy_source_files"] == 206
    assert cascade_validation["independent_review"] == "CLEAN_NO_BLOCKER_OR_HIGH"
    assert exact_status["status"] == (
        "PARTIAL_R8_LIVE_ROUTE_VALID_LOCAL_CHECKPOINT_NOT_PUSHED_REAL_BLOCKED_SAFETY"
    )
    assert exact_status["ticket_status"] == "PARTIAL"
    assert exact_status["autorun_status"] == (
        "BLOCKED_SAFETY_NO_CURRENT_OPERATOR_COMMANDS_REPLAY_ALLOWLIST_LOCAL_CHECKPOINT_NOT_PUSHED"
    )
    assert exact_status["paid_smoke_real_command_status"] == (
        "HISTORICAL_EXECUTED_FAILED_SAFE_SCHEMA_VALIDATION_COMMAND_WITHDRAWN"
    )
    assert exact_status["offline_smoke_verifier_command_status"] == (
        "ABSENT_WITHHELD_NO_CURRENT_BUNDLE"
    )
    assert exact_status["real_command_emission_authorized_for_operator_review"] is False
    revocation_fix = exact_status["revocation_cascade_fix"]
    assert revocation_fix["acceptance_requirement"] == (
        "REVOCATION_INVALIDATES_EVERY_DOWNSTREAM_CONSUMER"
    )
    assert revocation_fix["top_level_runner_lease_revoked"] is True
    assert revocation_fix["retained_campaign_capabilities_explicitly_revoked"] is True
    assert revocation_fix["retained_generation_capabilities_explicitly_revoked"] is True
    assert revocation_fix["current_gap"] is None
    assert revocation_fix["traceback_safe_execution_handoff"] is True
    assert revocation_fix["smoke_candidate_and_judge_generation_capabilities_immediately_revoked"]
    assert revocation_fix["root_focused_tests_passed"] == 229
    assert revocation_fix["root_adjacent_tests_passed"] == 266
    assert revocation_fix["independent_review"] == "CLEAN_NO_BLOCKER_OR_HIGH"
    assert revocation_fix["provider_or_private_execution_required"] is False
    assert revocation_fix["real_path_status"] == (
        "BLOCKED_SAFETY_POSITIVE_OWNED_REAL_PARENT_UNVALIDATED"
    )
    historical_selection = exact_status["historical_ineligible_gemma_selection_and_r7_capture"]
    assert historical_selection["selection_plan_sha256"] == (
        HISTORICAL_INELIGIBLE_GEMMA_PLAN_SHA256
    )
    assert historical_selection["selection_plan_checkpoint_commit"] == (
        HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT
    )
    assert historical_selection["selection_plan_checkpoint_status"] == (
        "HISTORICAL_INELIGIBLE_LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert historical_selection["selection_plan_schema_version"] == "1.1"
    assert historical_selection["required_output_mode"] == "NATIVE_JSON_SCHEMA"
    assert historical_selection["required_supported_parameters"] == ["structured_outputs"]
    assert historical_selection["candidate_endpoint_tag"] == "fireworks"
    assert historical_selection["primary_model_id"] == "google/gemma-4-26b-a4b-it"
    assert historical_selection["primary_endpoint_tag"] == "deepinfra/fp8"
    plan_entries = {entry["exact_model_id"]: entry for entry in selection_plan["entries"]}
    assert (
        historical_selection["primary_entry_sha256"]
        == plan_entries["google/gemma-4-26b-a4b-it"]["entry_sha256"]
    )
    assert historical_selection["primary_entry_priority_rank"] == 12
    assert plan_entries["tencent/hy3"]["priority_rank"] == 10
    assert historical_selection["role_assignment_sha256"] == HISTORICAL_INELIGIBLE_GEMMA_ROLE_SHA256
    assert historical_selection["operator_results_binding_status"] == (
        "UNRESOLVED_NONAUTHORIZING_CURRENT_RECORD"
    )
    assert historical_selection["replay_endpoint_tag"] == "together"
    assert historical_selection["candidate_registry_generation"] == "r7"
    assert historical_selection["candidate_registry"] == "candidate-registry-r7.json"
    assert historical_selection["candidate_discovery_run"] == "authrunner-candidate-20260821-r7"
    assert historical_selection["candidate_frozen_sha256"] == (
        "57b0e8fa7dfd4919fc720c25ba9dfa414a8e466605f8c0f8cbc286df5ea2b9db"
    )
    assert historical_selection["primary_registry_generation"] == "r7"
    assert historical_selection["replay_registry_generation"] == "r7"
    assert historical_selection["fresh_route_registries_present"] is True
    assert historical_selection["fresh_candidate_registry_present"] is True
    assert historical_selection["operationally_viable"] is False
    assert historical_selection["normal_provider_free_preflight_command_currently_emitted"] is False
    assert historical_selection["current_live_route_preflight_command_emitted"] is False
    assert historical_selection["current_paid_smoke_command_emitted"] is False
    current_successor = exact_status["current_selection_successor"]
    assert current_successor["status"] == (
        "PROVIDER_FREE_NONAUTHORIZING_REPLAY_ALLOWLIST_PLAN_CHECKPOINTED_LOCAL_NOT_PUSHED_"
        "OR_REMOTE_RESOLVED"
    )
    assert current_successor["selection_plan_sha256"] == selection_plan["plan_sha256"]
    assert current_successor["selection_plan_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    )
    assert current_successor["selection_plan_schema_version"] == "1.3"
    assert current_successor["checkpoint_commit"] == CURRENT_AUTHRUNNER_SUCCESSOR_CHECKPOINT
    assert current_successor["checkpoint_status"] == ("LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED")
    assert current_successor["checkpoint_pushed"] is False
    assert current_successor["checkpoint_remote_resolved"] is False
    assert current_successor["role_assignment_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256
    )
    assert (
        current_successor["role_assignment_sha256"]
        == (selection_plan["authenticated_runner_selection"]["role_assignment_sha256"])
    )
    assert current_successor["required_output_mode"] == "NATIVE_JSON_SCHEMA"
    assert current_successor["required_supported_parameters"] == ["structured_outputs"]
    assert current_successor["required_reasoning_effort"] == "high"
    assert current_successor["required_completion_limit_source"] == "metadata"
    assert current_successor["candidate_model_id"] == "deepseek/deepseek-v4-pro-0813"
    assert current_successor["candidate_endpoint_tag"] == "parasail/fp8"
    assert (
        current_successor["candidate_entry_sha256"] == CURRENT_NONAUTHORIZING_DEEPSEEK_ENTRY_SHA256
    )
    assert current_successor["primary_model_id"] == "z-ai/glm-5.2"
    assert current_successor["primary_endpoint_tag"] == "sail-research/fp8"
    assert current_successor["primary_entry_sha256"] == CURRENT_NONAUTHORIZING_ZAI_ENTRY_SHA256
    assert (
        current_successor["primary_entry_sha256"] == (plan_entries["z-ai/glm-5.2"]["entry_sha256"])
    )
    assert current_successor["replay_model_id"] == "moonshotai/kimi-k3"
    assert current_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert current_successor["replay_route_selection_mode"] == (
        "EXPLICIT_OPERATOR_CHOICE_NO_AUTOMATIC_FALLBACK"
    )
    assert current_successor["replay_entry_sha256"] == CURRENT_NONAUTHORIZING_KIMI_ENTRY_SHA256
    assert current_successor["operator_results_binding_status"] == (
        "BOUND_NONAUTHORIZING_CURRENT_RECORD"
    )
    assert current_successor["operator_results_binding_sha256"] == OPERATOR_RESULTS_SHA256
    assert current_successor["operator_recommendation_authority"] is False
    assert current_successor["documentary_lineage_status"] == "UNCONFIRMED"
    assert current_successor["documentary_lineage_status_scope"] == "SEALED_PLAN_LOCAL_ADVISORY"
    assert current_successor["selection_plan_distinct_root_lineages_verified"] is False
    assert current_successor["compiled_public_lineage_status"] == (
        "CONFIRMED_DOCUMENTARY_IDENTITY_ONLY"
    )
    assert (
        current_successor["compiled_public_lineage_manifest_sha256"]
        == CURRENT_LINEAGE_MANIFEST_SHA256
    )
    assert (
        current_successor["compiled_public_lineage_semantic_bundle_sha256"]
        == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    )
    assert current_successor["compiled_public_lineage_directed_independence_pairs_passed"] == 6
    assert current_successor["documentary_lineage_capture_required"] is False
    assert current_successor["documentary_lineage_capture_source_count"] == 17
    assert current_successor["fresh_documentary_lineage_capture_completed"] is True
    assert current_successor["current_lineage_reseal_completed"] is True
    assert current_successor["discovery_evidence_present"] is True
    assert current_successor["primary_r8_discovery_evidence_present"] is True
    assert current_successor["candidate_fresh_discovery_evidence_present"] is True
    assert current_successor["replay_fresh_discovery_evidence_present"] is True
    assert current_successor["fresh_route_discovery_required"] is False
    assert current_successor["operationally_viable"] is True
    assert current_successor["current_operator_command_emitted"] is False
    assert current_successor["authority"] is False
    assert "historical_full_r2_r5_r2_candidate_admission" in exact_status
    assert exact_status["zero_command_evidence_checkpoint"] == (
        "02ed5bef89d094e0d0c4852e1bf73914d9960c6b"
    )
    assert exact_status["last_durable_pushed_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_paid_diagnostic_base_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint"] == (
        HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_pushed"] is False
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_remote_verified"] is False
    assert exact_status["candidate_successor_checkpoint"] == CURRENT_AUTHRUNNER_SUCCESSOR_CHECKPOINT
    assert exact_status["candidate_successor_checkpoint_status"] == (
        "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert exact_status["historical_paid_diagnostic_guide_base_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_paid_diagnostic_guide_base_pushed"] is True
    assert exact_status["historical_paid_diagnostic_guide_base_remote_resolved"] is True
    assert (
        "ZERO_CURRENT_METADATA_DISCOVERY_SMOKE_VERIFIER"
        in exact_status["historical_paid_diagnostic_guide_base_scope"]
    )
    structured_output_eligibility = exact_status[
        "native_structured_output_eligibility_implementation"
    ]
    assert structured_output_eligibility["checkpoint_commit"] == (
        NATIVE_STRUCTURED_OUTPUT_GATE_CHECKPOINT
    )
    assert structured_output_eligibility["checkpoint_pushed"] is False
    assert structured_output_eligibility["checkpoint_remote_resolved"] is False
    assert structured_output_eligibility["fails_before_secret_selection"] is True
    assert structured_output_eligibility["fails_before_provider_dispatch"] is True
    assert structured_output_eligibility["fails_before_ledger_reservation"] is True
    assert structured_output_eligibility["authority"] is False
    completion_capacity = exact_status["current_completion_capacity_implementation"]
    assert completion_capacity["checkpoint_commit"] == HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT
    assert completion_capacity["lineage_reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert completion_capacity["selection_plan_schema_version"] == "1.3"
    assert completion_capacity["selection_plan_sha256"] == (
        "4e6c744559b1cc49c8ede590c868df103a10402d429d5e5d02cf4f429e0f3a66"
    )
    assert completion_capacity["selection_plan_required_completion_limit_source"] == "metadata"
    assert completion_capacity["candidate_endpoint_tag"] == "parasail/fp8"
    assert completion_capacity["primary_endpoint_tag"] == "sail-research/fp8"
    assert completion_capacity["replay_endpoint_tag"] == "wafer"
    assert completion_capacity["fails_before_secret_selection"] is True
    assert completion_capacity["fails_before_provider_dispatch"] is True
    assert completion_capacity["fails_before_ledger_reservation"] is True
    assert completion_capacity["current_operator_command_emitted"] is False
    assert completion_capacity["authority"] is False
    replay_successor = exact_status["current_replay_route_allowlist_successor"]
    assert replay_successor["checkpoint_commit"] == CURRENT_AUTHRUNNER_SUCCESSOR_CHECKPOINT
    assert replay_successor["selection_plan_sha256"] == CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    assert replay_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert replay_successor["explicit_operator_route_choice_required"] is True
    assert replay_successor["automatic_fallback_allowed"] is False
    assert replay_successor["fresh_exact_replay_discovery_required"] is False
    assert replay_successor["selected_replay_endpoint_tag"] == "modal/mxfp4"
    assert replay_successor["selected_replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert replay_successor["unselected_replay_seed_requiring_fresh_discovery_if_selected"] == (
        "phala"
    )
    assert replay_successor["r8_r8_r8_live_route_gate_valid"] is True
    assert replay_successor["current_operator_command_emitted"] is False
    assert replay_successor["authority"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_run"] is False
    supplementary_full_suite_attempt = runtime_status["last_validation"][
        "supplementary_full_suite_attempt"
    ]
    assert supplementary_full_suite_attempt == {
        "command": (
            ".venv/bin/pytest -q --ignore=tests/unit/test_product_documentation.py "
            "--ignore=tests/unit/test_product_objective.py"
        ),
        "status": "INTENTIONALLY_INTERRUPTED_NO_TERMINAL_PASS_CREDIT",
        "elapsed_seconds": 525.64,
        "displayed_progress_percent": 1,
        "passed_before_interrupt": 64,
        "skipped_before_interrupt": 13,
        "exit_code": 130,
        "terminal_full_suite_pass_credit": False,
    }
    historical_full_suite_attempt = exact_status["command_guide_successor_full_suite_attempt"]
    assert historical_full_suite_attempt["command"] == ".venv/bin/pytest -q"
    assert historical_full_suite_attempt["started_before_final_governance_bytes"] is True
    assert historical_full_suite_attempt["status"] == (
        "INTENTIONALLY_INTERRUPTED_NO_TERMINAL_PASS_CREDIT"
    )
    assert historical_full_suite_attempt["displayed_progress_percent"] == 2
    assert historical_full_suite_attempt["visible_skips"] == 6
    assert historical_full_suite_attempt["interrupted_during_test"] == (
        "test_scheduler_accepts_default_in_repository_private_output_exclusion"
    )
    assert historical_full_suite_attempt["exit_code"] == 130
    assert historical_full_suite_attempt["passed_test_count_printed"] is False
    assert historical_full_suite_attempt["terminal_full_suite_pass_credit"] is False
    assert "passed_test_count" not in historical_full_suite_attempt
    assert smoke_status["post_token_budget_fix_preflight_operator_results_sha256"] == (
        "76eff45c95116dea28cdaad78115d3926c6da3674a6b322784203335bfef7465"
    )
    assert smoke_status["post_token_budget_fix_preflight_operator_results_bytes"] == 41_806
    assert smoke_status["post_token_budget_fix_preflight_operator_results_lines"] == 756
    latest_paid_smoke = exact_status["latest_paid_smoke_attempt"]
    assert latest_paid_smoke["checkpoint_commit"] == HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    assert latest_paid_smoke["operator_results_sha256"] == (
        HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256
    )
    assert latest_paid_smoke["operator_results_bytes"] == 54_081
    assert latest_paid_smoke["operator_results_lines"] == 979
    assert latest_paid_smoke["authenticated_metadata_egress"] is True
    assert latest_paid_smoke["provider_completions"] == 1
    assert latest_paid_smoke["model_completion_requests"] == 1
    assert latest_paid_smoke["reserved_usd"] == "0.0547272"
    assert latest_paid_smoke["operator_reported_campaign_spend_usd"] == "0.01680888"
    assert latest_paid_smoke["accounted_cost_usd"] == "0.01680888"
    assert latest_paid_smoke["ledger_entry_status"] == "reconciled"
    assert latest_paid_smoke["operator_reported_campaign_ledger_empty"] is False
    assert latest_paid_smoke["bundle_published"] is False
    assert latest_paid_smoke["offline_verifier_run"] is False
    assert latest_paid_smoke["failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert latest_paid_smoke["failure_phase"] == "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    assert latest_paid_smoke["failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert latest_paid_smoke["adjacency_status"] == (
        "UNPROVEN_NO_FRESH_IMMEDIATE_POST_B413_STEP_A_RESULT_RECORDED"
    )
    assert latest_paid_smoke["authority"] is False
    historical_live_route = exact_status["historical_r6_r6_r2_live_route_preflight"]
    assert historical_live_route["operator_results_sha256"] == (
        HISTORICAL_R6_R6_R2_OPERATOR_RESULTS_SHA256
    )
    assert historical_live_route["composition"] == "r6/r6/r2"
    assert historical_live_route["all_three_routes_validated"] is True
    latest_exact_gate = exact_status["latest_r7_live_route_gate"]
    assert latest_exact_gate["operator_results_sha256"] == HISTORICAL_R7_OPERATOR_RESULTS_SHA256
    assert latest_exact_gate["composition"] == "r7/r7/r7"
    assert latest_exact_gate["status"] == (
        "FAILED_SAFE_PRIMARY_REASONING_PROFILE_INCOMPATIBLE_BEFORE_PAID_TRANSPORT"
    )
    assert latest_exact_gate["provider_completions"] == 0
    assert latest_exact_gate["incremental_spend_usd"] == "0"
    assert latest_exact_gate["authority"] is False
    latest_r8_gate = exact_status["latest_r8_completion_capacity_gate"]
    assert latest_r8_gate["operator_results_sha256"] == (
        "5faa33fe1bd5b332e8dffa0b29ed5718886d0c8b22c65cb1dc67b306eba8d00f"
    )
    assert latest_r8_gate["composition"] == "r7/r8/r7"
    assert latest_r8_gate["primary_endpoint_tag"] == "sail-research/fp8"
    assert latest_r8_gate["primary_registry"] == "primary-judge-registry-r8.json"
    assert latest_r8_gate["primary_frozen_sha256"] == (
        "8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26"
    )
    assert latest_r8_gate["primary_max_completion_tokens"] == 131_072
    assert latest_r8_gate["candidate_max_completion_tokens"] is None
    assert latest_r8_gate["replay_max_completion_tokens"] is None
    assert latest_r8_gate["status"] == (
        "FAILED_SAFE_EXPLICIT_COMPLETION_CAPACITY_REQUIRED_BEFORE_MODEL_COMPLETION"
    )
    assert latest_r8_gate["provider_completions"] == 0
    assert latest_r8_gate["incremental_spend_usd"] == "0"
    assert latest_r8_gate["bundle_published"] is False
    assert latest_r8_gate["authority"] is False
    current_r8_gate = smoke_status["latest_r8_r8_r8_live_route_gate"]
    assert current_r8_gate["operator_results_sha256"] == OPERATOR_RESULTS_SHA256
    assert current_r8_gate["operator_results_bytes"] == 71_771
    assert current_r8_gate["operator_results_lines"] == 1_276
    assert current_r8_gate["composition"] == "r8/r8/r8"
    assert current_r8_gate["replay_endpoint_tag"] == "modal/mxfp4"
    assert current_r8_gate["replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert current_r8_gate["logical_metadata_gets"] == 15
    assert current_r8_gate["maximum_metadata_provider_attempts"] == 30
    assert current_r8_gate["provider_completions"] == 0
    assert current_r8_gate["incremental_spend_usd"] == "0"
    assert current_r8_gate["output_published"] is False
    assert current_r8_gate["bundle_published"] is False
    assert current_r8_gate["authority"] is False
    assert "replay-judge-registry-r2.json" in model_selection
    assert "authrunner-replay-judge-20260820-r2" in model_selection
    assert "A stopped run is not resumable." in model_selection
    assert "Neither CLI has a resume flag" in normalized_model_selection
    assert "requires all five mutable output leaves to be fresh" in normalized_model_selection
    assert "Deterministic logical request IDs collide" in normalized_model_selection
    assert "process-local live custody cannot be recreated" in normalized_model_selection
    assert "neither one-shot runner can adopt that work and spend cannot be refunded" in (
        normalized_model_selection
    )
    assert "do not rerun the same command or reuse/overwrite" in normalized_model_selection
    assert "Changing only the smoke output path does not repair" in normalized_model_selection
    assert "repeats paid candidate work" in normalized_model_selection
    assert "after both candidates and before either judge POST" in normalized_model_selection
    assert "Actual candidate spend plus the aggregate maximum" in normalized_model_selection
    assert "strictly below the USD `250.00` ledger cap" in normalized_model_selection
    assert "fit its USD `1.00` role tripwire" in normalized_model_selection
    assert "reserves before every attempt" in normalized_model_selection
    assert "unknown actual charge is finalized at the reserved amount" in normalized_model_selection
    assert "no separate live USD `8.00` smoke or USD `192.00` full cumulative meter" in (
        normalized_model_selection
    )
    assert "each figure is attempt-count arithmetic" in normalized_model_selection
    assert "not deferred to an end-only interval check" in normalized_model_selection
    assert "checked again when the interval closes" in normalized_model_selection
    assert "Kimi's total judge plan" in normalized_model_selection
    assert "becomes exactly bounded before dispatch" in normalized_model_selection
    assert "Whole-inventory `provider_name` uniqueness remains enforced." in model_selection
    assert "end-to-end wire and evidence redesign" in normalized_model_selection
    assert "explicit selection-quality limitation" in normalized_model_selection
    assert "committed-byte provider-free gate" in normalized_model_selection
    assert "full 24-case REAL command is deliberately withheld" in normalized_model_selection
    assert "case-df79ea132113b863" in model_selection
    assert "synthetic/C0015.sol" in model_selection
    assert 'purpose = "NONCREDITING_SMOKE"' in model_selection
    assert "representative_for_calibration = false" in model_selection
    assert "semantic_scores_creditable = false" in model_selection
    assert "smoke_success_authorizes_full_launch = false" in model_selection
    assert "four logical requests" in normalized_model_selection
    assert "at most eight provider attempts" in normalized_model_selection
    assert "four generation refetches" in normalized_model_selection
    assert "--qualification-policy" not in smoke_real_command
    assert "--ground-truth-provenance" not in smoke_real_command
    assert "--primary-campaign-journal" not in smoke_real_command
    assert "--primary-portfolio" not in smoke_real_command
    assert "--replay-campaign-journal" not in smoke_real_command
    assert "--replay-portfolio" not in smoke_real_command
    assert "--candidate anthropic/claude-opus-5=amazon-bedrock" not in model_selection
    assert "PREFLIGHT r2/r5/r2 — **VALID**, with derived exact caps" in operator_results
    assert "PAID SMOKE LAUNCH ATTEMPTED — failed closed" in operator_results
    assert "PAID SMOKE LAUNCH #2 — failed closed" in operator_results
    assert "smoke current discovery differs from its frozen exact route" in operator_results
    assert "the token-budget mismatch from launch #1 is gone" in operator_results
    assert "no provider completion" in operator_results
    assert "no bundle produced" in operator_results
    assert "naive recursive field scan" in operator_results
    assert "cause was initially `INCONCLUSIVE`" in normalized_model_selection
    assert "naive, advisory, and nonauthorizing analysis" in normalized_model_selection
    assert "LIVE-ROUTE PREFLIGHT **VALID** on fresh r6/r6/r2 evidence" in operator_results
    assert "candidate=endpoint exact-model identity inventory" in operator_results
    assert "PRIMARY judge=endpoint exact-model identity inventory" in operator_results
    assert "Replay judge was unaffected" in operator_results
    assert "logical_gets=15; maximum_provider_attempts=30" in operator_results
    assert "SMOKE PREFLIGHT after token-budget fix `59f9f40` — VALID" in operator_results
    assert "The output is byte-identical to the pre-fix preflight" in operator_results
    assert "request and atomic global input token budgets differ" in operator_results
    assert "before any provider request" in operator_results
    assert "No bundle produced" in operator_results
    assert "SMOKE PREFLIGHT after `af70559`" in operator_results
    assert "SMOKE PREFLIGHT at checkpoint `f0a0f39` — **VALID**" in operator_results
    assert "VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS" in operator_results
    assert "944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19" in (model_selection)
    assert "b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d" in (model_selection)
    assert "0.21890352" in model_selection
    assert "33,621-byte operator record" in normalized_model_selection
    assert "35,771-byte operator record" in normalized_model_selection
    assert "withdrawn before execution" in normalized_model_selection
    assert "The smoke path fails for any real registry set." in operator_results
    assert "Not yet run:** the smoke REAL launch" in operator_results
    assert "f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57" in (model_selection)
    assert "3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436" in (model_selection)
    assert "5.27438208" in model_selection
    assert "BOTH r5 prerequisites RUN AND PASSED" in operator_results
    assert "PRIMARY r4 (`minimax/minimax-m3=coreweave/fp4`) — SUCCESS" in operator_results
    assert "runner public lineage does not prove three distinct roots" in operator_results
    assert "LINEAGE CAPTURE — SUCCESS, one coherent 15-source bundle" in operator_results
    assert "AUTHRUNNER PREFLIGHT — **VALID**" in operator_results
    assert "FAILED on unenforceable variable pricing" in operator_results
    assert "variable endpoint pricing component cannot be provider-capped" in operator_results
    assert "cache gate CLEARED; fails later on reasoning capability" in operator_results
    assert "Lineage prerequisites for BOTH replacement candidates" in operator_results
    assert "VALID / NONAUTHORIZING / NO PROVIDER EGRESS" in operator_results
    assert "f0ff2d76017dfcd075c6758f0da7256c98dd45ca749a42b81ca1ce8c95a93f9e" in (operator_results)
    assert "848b1dfda5b60c6793089ed3916073d86e3a734da9dbc5a824302bec7f4b37da" in (operator_results)
    assert "6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb" in (model_selection)
    assert "7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134" in (model_selection)
    assert "fe3e3daa21eeb370f35558c5eca5746c140f2b92e88a37233952ab77034dc07b" in (model_selection)
    assert "2d825234bfc1cf05fb9ec883c555bc007bd3a6033145507d629d5da7aa5619ad" in (model_selection)
    assert "90389d27f553d6f167a21aab364cebdb40ca5afbdbcc977d9127338ace4a3008" in (model_selection)
    assert "7c6dd26743733ae46aa94b7171ff2ca42f967ac8323b7f2d0aa95cf66f2dbc68" in (model_selection)
    assert "sha256:932e8cdba524bbf5280d368b0cb711bf0bf36b6fb57ea744bda2a86caea534fb" in (
        model_selection
    )
    assert "16 sources totaling 421,754 bytes" in normalized_model_selection
    assert "15 aliases, 17 exact nonoverlapping claims" in normalized_model_selection
    assert "11 confirmed identities across 10 roots" in normalized_model_selection
    assert "seven conservative negative-only constraints" in normalized_model_selection
    assert "All six ordered pair directions" in normalized_model_selection
    assert "capture_public_model_lineage.py --output-dir" in model_selection
    assert "6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4" in (model_selection)
    assert "did not exercise the current exact-cost admission implementation" in (
        normalized_model_selection
    )
    assert "Judge admission correctly remains `PENDING_REAL_CANDIDATE_OUTPUTS`" in (
        normalized_model_selection
    )
    assert "two exact retry-inclusive plans are derived" in normalized_model_selection
    assert "f6acf206f2c55eeb57b1a11fcf58cc4694a41208" in model_selection
    assert "That checkpoint is historical and must not be rerun" in normalized_model_selection
    assert "fd1459b519ea0ce28a2d123ddeb57653dd2f7918" in model_selection
    assert "Bound OpenRouter prompt-cache pricing" in model_selection
    assert "origin/agent/v3-wip-checkpoint" in model_selection
    assert "input_cache_read" in model_selection
    assert "provider.max_price.prompt" in model_selection
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
