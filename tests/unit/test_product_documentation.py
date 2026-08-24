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
LAST_RECONCILED_OPERATOR_RESULTS_SHA256 = (
    "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
)
PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256 = (
    "ed416745d3d0d957e05919e7cf10e14e75b4e9f3da800000e5789371520abbe2"
)
HISTORICAL_PRE_REPLAY_REPAIR_OPERATOR_RESULTS_SHA256 = (
    "a87ca7efaf4adf0af60479fa5b26fcbfe80ad6d3aa58a92c9e18fab1a70eabce"
)
HISTORICAL_POST_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 = (
    "dd6019db5bdf4e1c9b528b5f2949a81b9944336bef370be822ba52baf5a618fc"
)
PRE_RECEIPT_COMPOSITE_LIVE_OPERATOR_RESULTS_SHA256 = (
    "67b40784bce40a9369d721a922d5138a118d833105937219294778f4fc93ce98"
)
HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256 = (
    "25ee5395a7e2360637f89d89cc0e89084a530c8921d0af395b06bc9b700b01e5"
)
HISTORICAL_R7_OPERATOR_RESULTS_SHA256 = (
    "00de61717cb6d61c003682abca12ae2c7e59613db03ef99558133b972c123516"
)
HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 = (
    "f0c87e608633dc8ae940a977c8207d9e371b2bf683d0a91f415316273d5ac0dc"
)
HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT = "3989e7592de6e1c355365443c10e00c2083829d8"
CURRENT_LINEAGE_RESEAL_CHECKPOINT = "331bde27c7085d4da34c7b8ec1f688f2ce1e52b3"
HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT = "3975d2e12fd81a214b9faa1c3031c94506ab696d"
HISTORICAL_DCABE_SELECTION_CHECKPOINT = "dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d"
AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT = "531a9d822e9989bf2eda94530e88cf55f2dd2e0d"
AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT = "77fb4b9a0c03969a9776edf2091dc09d3b67daec"
HISTORICAL_AUTHRUNNER_RECEIPT_SCAFFOLD_CHECKPOINT = "8058e7bff88594b44aa42b8695ce5c25442ae73c"
HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT = "d2364f6b528f2e839fbef8b878552f95c4b92c9c"
AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT = "4e035a9d58b98284e7cceecf1fb844bc84e0dbe6"
HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT = "48ea635ab5a2fa778d6b5ce5c9a1592f0f27b375"
HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT = "68126e0fe438f853fb9b75582023f807a208bdae"
HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT = (
    "3a1246daf19ffa4a772be7806bd903199634ab0b"
)
HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT = (
    "03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc"
)
HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT = "c627f2debfa18df7d9567cd7c3300d19a9e9f5ce"
HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT = "7ef471744adfce557edf612a74b2847aafb3e8bc"
HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT = "85c06b07ccc3905af4e0231497276934f7ae142a"
PLANCONSTRAINTS_REPAIR_CHECKPOINT = "425502c5cbc173578053423d946ef24843f26285"
PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT = "390e9b29e748e38d511da9f0a54cfc4fa1a2c0a8"
CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT = "721d17a4ff08cc52ccdf0aa92ed04258e4137807"
CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT = "847e7180923e95768271c6fe7e8b06732a7d919a"
CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT = "dcd9ab2be15f4a0416372c110734b5079af1efe2"
CURRENT_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT = "d738f2760da047d15d4e53f87d6e0aeaf13d442a"
HISTORICAL_C627_AUTONOMY_INVENTORY_RAW_SHA256 = (
    "6fd2608825a5dff950f8c0a0239a446857c82783603ec81a15b060391c3d4778"
)
OPERATOR_INDEX_19_SOURCE_CHECKPOINT = "03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc"
HISTORICAL_PHASE_ZERO_CHECKPOINT = "d0402d1c68f0f82d9ee4f8757f7967abda372ac6"
PHASE_ONE_IMPLEMENTATION_CHECKPOINT = "084add8778ef36a2e4c86fdbdea4082eb3a1b332"
AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT = "9c61871502abbd19ff13278893f9c7785c5b28ba"
AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT = "3d4a43ac026547dd8652796b6186c48891fd7622"
HISTORICAL_PHASE_ZERO_INVENTORY_RAW_SHA256 = (
    "6a3c54258dd1f0c25fc8861c8298cf51d187b33bd5528ec25b1549c0e0021980"
)
AUTONOMY_INVENTORY_RAW_SHA256 = "c9452fb8bb504a743312264ccaddfbd47d7a11997bd04c0861709960153c985a"
AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256 = (
    "c302b155d7dd138adc150d9f398da279f130dd696a321fb9e0d287c089012bcf"
)
AUTONOMY_INVENTORY_SHA256 = "701ff7994152cc5a8fc0174341a3e8963573741f200e24f0ff3566720a069140"
AUTONOMY_SOURCE_UNIVERSE_SHA256 = "9fc20c8097d38f719169e360836806f8ffec0d175a1941aa942089163fed53e5"
AUTONOMY_DISCOVERY_SEMANTICS_SHA256 = (
    "4f1adb9e0bc8db7899fa4eb2928ee03f87d4d61d4113a0555fcdae750e260042"
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
PHASE_ONE_IMPLEMENTATION_PATHS = frozenset(
    {
        "docs/codex_work_queue.md",
        "docs/codex_worklog.md",
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "docs/remediation/v3/review_traceability.json",
        "docs/remediation/v3/runtime_status.json",
        "docs/remediation/v3/work_queue.md",
        "docs/remediation/v3/worklog.md",
        "schemas/managed_toolchain_bundle.schema.json",
        "scripts/generate_release_schemas.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "src/mmaudit/orchestration/managed_toolchain.py",
        "src/mmaudit/resources/managed_toolchain_bundle.json",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_managed_toolchain.py",
        "tests/unit/test_packaged_scanner_resources.py",
        "tests/unit/test_product_documentation.py",
        "tests/unit/test_product_objective.py",
        "tests/unit/test_release_schemas.py",
    }
)
PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS = frozenset(
    {
        "docs/codex_work_queue.md",
        "docs/codex_worklog.md",
        "docs/remediation/v3/review_traceability.json",
        "docs/remediation/v3/runtime_status.json",
        "docs/remediation/v3/work_queue.md",
        "docs/remediation/v3/worklog.md",
        "tests/unit/test_product_documentation.py",
        "tests/unit/test_product_objective.py",
    }
)
CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS = PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS | {
    "docs/models/model_selection.md"
}
PHASE_ONE_CORE_PATHS = PHASE_ONE_IMPLEMENTATION_PATHS - PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS
AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/authenticated_runner_smoke_evidence_bundle.schema.json",
        "schemas/autonomy_gate_inventory.schema.json",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/cli.py",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/authenticated_runner_smoke_openrouter.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_authenticated_runner_smoke_cli.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_usage.py",
    }
)
AUTONOMY_WORKTREE_INDEPENDENCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/unit/test_autonomy_gate_inventory.py",
    }
)
AUTHRUNNER_TOKEN_ENVELOPE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/authenticated_runner_durable_evidence_bundle.schema.json",
        "schemas/authenticated_runner_smoke_evidence_bundle.schema.json",
        "schemas/authenticated_runner_staged_cost_plan.schema.json",
        "schemas/context_manifest.schema.json",
        "schemas/cross_lineage_adjudication_report.schema.json",
        "schemas/model_execution_artifact.schema.json",
        "schemas/openrouter_structured_request_cost_preview.schema.json",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "src/mmaudit/models/generation_evidence.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/reasoning.py",
        "src/mmaudit/models/schemas.py",
        "src/mmaudit/models/token_planning.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/authenticated_runner_smoke_openrouter.py",
        "src/mmaudit/orchestration/budgets.py",
        "src/mmaudit/orchestration/context_manifest.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_authenticated_runner_smoke_cli.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_generation_evidence.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_openrouter_request_cost_preview.py",
        "tests/unit/test_reasoning.py",
        "tests/unit/test_token_planning.py",
    }
)
AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/benchmark/models.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_RECEIPT_COMPOSITE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "pyproject.toml",
        "src/mmaudit/benchmark/cross_lineage_adjudication.py",
        "src/mmaudit/benchmark/models.py",
        "src/mmaudit/models/generation_evidence.py",
        "src/mmaudit/models/openrouter.py",
        "src/mmaudit/models/usage.py",
        "src/mmaudit/orchestration/autonomy_gate_inventory.py",
        "tests/integration/test_openrouter_httpx_response_graph.py",
        "tests/unit/test_authenticated_runner.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_autonomy_gate_inventory.py",
        "tests/unit/test_cross_lineage_adjudication.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/openrouter.py",
        "tests/integration/test_openrouter_httpx_response_graph.py",
        "tests/unit/test_openrouter.py",
    }
)
AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_authenticated_runner_smoke_benchmark.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/usage.py",
        "tests/unit/test_openrouter.py",
        "tests/unit/test_openrouter_request_cost_preview.py",
        "tests/unit/test_usage.py",
    }
)
AUTHRUNNER_CANONICAL_REPLAY_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
    }
)
AUTHRUNNER_CANONICAL_REPLAY_STABLE_PATHS = frozenset(
    {"src/mmaudit/models/authenticated_runner_smoke.py"}
)
PLANCONSTRAINTS_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/route_constraints.py",
        "tests/unit/test_endpoint_snapshots.py",
        "tests/unit/test_model_discovery.py",
        "tests/unit/test_route_constraints.py",
    }
)
TRUNCATION_SPECIALIST_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "schemas/scheduler_state.schema.json",
        "src/mmaudit/agents/specialists.py",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/orchestration/assurance.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "src/mmaudit/orchestration/truncation_recovery_evidence.py",
        "tests/fake_openrouter.py",
        "tests/integration/test_pipeline.py",
        "tests/integration/test_scheduler_truncation_recovery_pipeline.py",
        "tests/unit/test_assurance.py",
        "tests/unit/test_model_coverage.py",
        "tests/unit/test_specialists.py",
        "tests/unit/test_truncation_recovery_journal.py",
    }
)
TRUNCATION_RECURSIVE_SOURCE_PATHS = frozenset(
    {
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/scheduler.py",
        "src/mmaudit/models/truncation_recovery_journal.py",
        "src/mmaudit/orchestration/pipeline.py",
        "src/mmaudit/orchestration/scheduler.py",
        "tests/fake_openrouter.py",
        "tests/integration/test_scheduler_truncation_recovery_pipeline.py",
        "tests/unit/test_truncation_recovery_journal.py",
    }
)
AUTHRUNNER_UNCHANGED_IMPLEMENTATION_PATHS = (
    AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS - AUTONOMY_WORKTREE_INDEPENDENCE_PATHS
)
PHASE_ONE_CORE_SUCCESSOR_PATHS = PHASE_ONE_CORE_PATHS & (
    AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS
)
PHASE_ONE_UNCHANGED_CORE_PATHS = PHASE_ONE_CORE_PATHS - PHASE_ONE_CORE_SUCCESSOR_PATHS
OPERATOR_RESULTS_RELATIVE_PATH = "docs/remediation/v3/operator_results.md"
HISTORICAL_INELIGIBLE_GEMMA_PLAN_SHA256 = (
    "41b5af9ae4def5ef535ae25a13c7c38b95d5819a878a5eef1c1c5bfb8386bf58"
)
HISTORICAL_INELIGIBLE_GEMMA_ROLE_SHA256 = (
    "f1c80252e94bf789d1b78f424a8b9c142f7e750e8ee0ba3bacfaae2a3330aa25"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256 = (
    "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
)
CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256 = (
    "7d67d43f98484890bf9f184a5bb89fbba25d0408dee65a7174eef5fdf1a75b14"
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


def test_autonomy_checkpoints_have_exact_historical_and_successor_custody() -> None:
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

    resolved = subprocess.run(
        ["git", "rev-parse", f"{PHASE_ONE_IMPLEMENTATION_CHECKPOINT}^{{commit}}"],
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
            PHASE_ONE_IMPLEMENTATION_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    core_match = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            PHASE_ONE_IMPLEMENTATION_CHECKPOINT,
            "--",
            *sorted(PHASE_ONE_UNCHANGED_CORE_PATHS),
        ],
        cwd=ROOT,
        check=False,
    )
    authrunner_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    authrunner_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    token_envelope_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    token_envelope_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    identity_diagnostic_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    identity_diagnostic_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    scope_cutoff_hotfix_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_composite_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    receipt_state_seal_hotfix_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_parent = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT}^",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    structured_output_diagnostic_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_parent = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT}^",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    required_provider_parameters_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_resolved = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_parent = subprocess.run(
        ["git", "rev-parse", f"{HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    canonical_replay_current_match = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT,
            "--",
            *sorted(AUTHRUNNER_CANONICAL_REPLAY_STABLE_PATHS),
        ],
        cwd=ROOT,
        check=False,
    )
    planconstraints_repair_resolved = subprocess.run(
        ["git", "rev-parse", f"{PLANCONSTRAINTS_REPAIR_CHECKPOINT}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    planconstraints_repair_parent = subprocess.run(
        ["git", "rev-parse", f"{PLANCONSTRAINTS_REPAIR_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    planconstraints_repair_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_specialist_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_parent = subprocess.run(
        ["git", "rev-parse", f"{CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT}^"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    truncation_recursive_current_match = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT,
            "--",
            *sorted(TRUNCATION_RECURSIVE_SOURCE_PATHS),
        ],
        cwd=ROOT,
        check=False,
    )
    worktree_independence_resolved = subprocess.run(
        [
            "git",
            "rev-parse",
            f"{AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT}^{{commit}}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    worktree_independence_changed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert resolved.stdout.strip() == PHASE_ONE_IMPLEMENTATION_CHECKPOINT
    assert len(PHASE_ONE_IMPLEMENTATION_PATHS) == 18
    assert len(PHASE_ONE_CORE_PATHS) == 10
    assert len(PHASE_ONE_CORE_SUCCESSOR_PATHS) == 3
    assert len(PHASE_ONE_UNCHANGED_CORE_PATHS) == 7
    assert len(PHASE_ONE_GOVERNANCE_SUCCESSOR_PATHS) == 8
    assert frozenset(changed.stdout.splitlines()) == PHASE_ONE_IMPLEMENTATION_PATHS
    assert OPERATOR_RESULTS_RELATIVE_PATH not in PHASE_ONE_IMPLEMENTATION_PATHS
    assert core_match.returncode == 0
    assert authrunner_resolved.stdout.strip() == AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT
    assert len(AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS) == 16
    assert len(AUTHRUNNER_UNCHANGED_IMPLEMENTATION_PATHS) == 13
    assert (
        frozenset(authrunner_changed.stdout.splitlines())
        == AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_PATHS
    )
    assert (
        worktree_independence_resolved.stdout.strip() == AUTONOMY_WORKTREE_INDEPENDENCE_CHECKPOINT
    )
    assert (
        frozenset(worktree_independence_changed.stdout.splitlines())
        == AUTONOMY_WORKTREE_INDEPENDENCE_PATHS
    )
    assert token_envelope_resolved.stdout.strip() == AUTHRUNNER_TOKEN_ENVELOPE_CHECKPOINT
    assert frozenset(token_envelope_changed.stdout.splitlines()) == AUTHRUNNER_TOKEN_ENVELOPE_PATHS
    assert len(AUTHRUNNER_TOKEN_ENVELOPE_PATHS) == 29
    assert identity_diagnostic_resolved.stdout.strip() == AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT
    assert (
        frozenset(identity_diagnostic_changed.stdout.splitlines())
        == AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS
    )
    assert len(AUTHRUNNER_IDENTITY_DIAGNOSTIC_PATHS) == 4
    assert (
        scope_cutoff_hotfix_resolved.stdout.strip() == HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert (
        scope_cutoff_hotfix_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_SCAFFOLD_CHECKPOINT
    )
    assert (
        frozenset(scope_cutoff_hotfix_changed.stdout.splitlines())
        == AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS
    )
    assert len(AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_PATHS) == 7
    assert (
        receipt_composite_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_composite_parent.stdout.strip() == AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    assert (
        frozenset(receipt_composite_changed.stdout.splitlines())
        == AUTHRUNNER_RECEIPT_COMPOSITE_PATHS
    )
    assert len(AUTHRUNNER_RECEIPT_COMPOSITE_PATHS) == 14
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_RECEIPT_COMPOSITE_PATHS
    assert not (AUTHRUNNER_RECEIPT_COMPOSITE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert (
        receipt_state_seal_hotfix_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        receipt_state_seal_hotfix_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert (
        frozenset(receipt_state_seal_hotfix_changed.stdout.splitlines())
        == AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS
    )
    assert len(AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS) == 4
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS
    assert not (
        AUTHRUNNER_RECEIPT_STATE_SEAL_HOTFIX_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert (
        structured_output_diagnostic_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        structured_output_diagnostic_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        frozenset(structured_output_diagnostic_changed.stdout.splitlines())
        == AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS
    )
    assert len(AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS
    assert not (
        AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert (
        required_provider_parameters_resolved.stdout.strip()
        == HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert (
        required_provider_parameters_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        frozenset(required_provider_parameters_changed.stdout.splitlines())
        == AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS
    )
    assert len(AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS
    assert not (
        AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS
    )
    assert canonical_replay_resolved.stdout.strip() == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert (
        canonical_replay_parent.stdout.strip()
        == HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert frozenset(canonical_replay_changed.stdout.splitlines()) == (
        AUTHRUNNER_CANONICAL_REPLAY_PATHS
    )
    assert len(AUTHRUNNER_CANONICAL_REPLAY_PATHS) == 3
    assert OPERATOR_RESULTS_RELATIVE_PATH not in AUTHRUNNER_CANONICAL_REPLAY_PATHS
    assert not (AUTHRUNNER_CANONICAL_REPLAY_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert canonical_replay_current_match.returncode == 0
    assert planconstraints_repair_resolved.stdout.strip() == PLANCONSTRAINTS_REPAIR_CHECKPOINT
    assert planconstraints_repair_parent.stdout.strip() == PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT
    assert (
        frozenset(planconstraints_repair_changed.stdout.splitlines())
        == PLANCONSTRAINTS_SOURCE_PATHS
    )
    assert len(PLANCONSTRAINTS_SOURCE_PATHS) == 5
    assert OPERATOR_RESULTS_RELATIVE_PATH not in PLANCONSTRAINTS_SOURCE_PATHS
    assert not (PLANCONSTRAINTS_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert truncation_specialist_resolved.stdout.strip() == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert (
        truncation_specialist_parent.stdout.strip()
        == CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
    )
    assert (
        frozenset(truncation_specialist_changed.stdout.splitlines())
        == TRUNCATION_SPECIALIST_SOURCE_PATHS
    )
    assert len(TRUNCATION_SPECIALIST_SOURCE_PATHS) == 16
    assert OPERATOR_RESULTS_RELATIVE_PATH not in TRUNCATION_SPECIALIST_SOURCE_PATHS
    assert not (TRUNCATION_SPECIALIST_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert truncation_recursive_resolved.stdout.strip() == CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT
    assert (
        truncation_recursive_parent.stdout.strip() == CURRENT_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT
    )
    assert (
        frozenset(truncation_recursive_changed.stdout.splitlines())
        == TRUNCATION_RECURSIVE_SOURCE_PATHS
    )
    assert len(TRUNCATION_RECURSIVE_SOURCE_PATHS) == 8
    assert OPERATOR_RESULTS_RELATIVE_PATH not in TRUNCATION_RECURSIVE_SOURCE_PATHS
    assert not (TRUNCATION_RECURSIVE_SOURCE_PATHS & CURRENT_COMMAND_GOVERNANCE_SUCCESSOR_PATHS)
    assert truncation_recursive_current_match.returncode == 0


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


def test_truncation_resumes_after_planconstraints_regression_repair() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-TRUNCATION-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "**Status:** `PARTIAL`" in section
        assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in section
        assert CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT in section
        assert "specialist" in section and "v1.2" in section
        assert "MOCK recovery remains unpromoted" in section
        assert "one generic zero-retained truncated child" in section
        assert "v1.1 `COVERAGE_CLOSED`" in section
        assert "v1.2 `RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING`" in section
        assert "neither closure creates promotion, coverage, specialist, or assurance credit" in (
            section
        )
        assert "max-cap refusal" in section
        assert "zero-transport resume" in section
        assert (
            "Add only full-tree live opaque capability and promotion for the exact one-level "
            "generic zero-retained tree" in section
        )
        assert "Deeper recursion, retained-surface recursion, specialist-role recursion" in section
        assert "Resume only the bounded provider-free specialist-role recovery gap" not in section
        assert "Pause this ticket while" not in section


def test_recursive_truncation_checkpoint_is_current_without_external_authority() -> None:
    worklogs = (
        CODEX_WORKLOG_PATH.read_text(encoding="utf-8"),
        (ROOT / "docs/remediation/v3/worklog.md").read_text(encoding="utf-8"),
    )
    for worklog in worklogs:
        assert (
            "AUTORUN_STATUS: V3_TRUNCATION_001_ONE_LEVEL_GENERIC_RECURSIVE_RECOVERY_"
            "CHECKPOINTED_PROVIDER_FREE_NONAUTHORIZING_FULL_TREE_LIVE_PROMOTION_NEXT"
        ) in worklog
        assert (
            "CURRENT_LOCAL_SLICE_STATUS: ONE_LEVEL_GENERIC_RECURSIVE_RECOVERY_COMPLETE_"
            "TICKET_PARTIAL_PROVIDER_FREE_NONAUTHORIZING"
        ) in worklog
        assert CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT in worklog
        assert CURRENT_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT in worklog
        assert "owns exactly 8" in worklog
        assert "`66` journal" in worklog
        assert "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING" in worklog
        assert "Recursive promotion, coverage, specialist, and assurance credit remain absent" in (
            worklog
        )
        assert "full-tree live opaque capability and promotion" in worklog
        assert "No provider, network, credential, private-ledger" in worklog


def test_planconstraints_ticket_is_mirrored_and_fail_closed() -> None:
    def ticket_section(document: str) -> str:
        match = re.search(
            r"^#{2,3} V3-PLANCONSTRAINTS-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        return " ".join(match.group().split())

    canonical = ticket_section(QUEUE_PATH.read_text(encoding="utf-8"))
    codex = ticket_section(CODEX_QUEUE_PATH.read_text(encoding="utf-8"))

    for section in (canonical, codex):
        assert "**Status:** `COMPLETE`" in section
        assert (
            "operator-reported, nonauthorizing `c627f2d` offline-valid sealed one-case" in section
        )
        assert "satisfies only this provider-free prerequisite" in section
        assert "not independent bundle authentication or campaign authority" in section
        assert "successfully sealed and offline-verified" not in section
        assert "mandatory before the 24-case campaign" in section.lower()
        assert "typed, self-hashed route-predicate profile" in section
        assert "same typed predicate implementations" in section or (
            "same typed predicate" in section and "runtime" in section
        )
        assert "exact-model" in section and "selected-endpoint" in section
        assert "`structured_outputs`" in section
        assert "endpoint-first" in section
        assert "exact-model catalog fallback only under the validated" in section
        assert "exact operational accepted state" in section
        assert "provider cap is expressible" in section
        assert "closed" in section and "disposition/reason" in section
        assert "lacks a selection representation" in section
        assert "typed `UNAVAILABLE`" in section
        assert "24-case campaign" in section and "fail" in section.lower()
        assert "wholly runtime-only" in section
        assert "absence of one complete shared predicate profile" in section
        assert "necessary but never proves behavioral schema reliability" in section
        assert "Runtime schema conformance remains a separate empirical" in section
        assert "Item 5" in section and "`ADOPTED_NONAUTHORIZING / IMPLEMENTED`" in section
        assert PLANCONSTRAINTS_REPAIR_CHECKPOINT in section
        assert "five-path checkpoint" in section
        assert "case-insensitive `display_count == 1` selected-name rule" in section
        assert "unrelated Fireworks/Alibaba/Morph collisions" in section
        assert HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT in section
        assert "exact 33-path provider-free implementation" in section
        assert (
            "No operator action, provider access, inferred index, command, or campaign" in section
        )
        assert "Keep queued until AUTHRUNNER produces a successful smoke bundle" not in section
        assert "Keep queued until the AUTHRUNNER smoke succeeds" not in section
        assert "Item 3's REPLAY allowlist is historical" in section
        assert "candidate/PRIMARY extension remains advisory" in section
        assert "Items 2, 3, 4, and 6 remain" in section
        assert "`OPERATOR_SUPPLIED_NONAUTHORIZING_ANALYSIS`" in section


def test_modelrefresh_next_action_is_historicalized_behind_current_provider_free_priority() -> None:
    for document in (
        QUEUE_PATH.read_text(encoding="utf-8"),
        CODEX_QUEUE_PATH.read_text(encoding="utf-8"),
    ):
        match = re.search(
            r"^#{2,3} V3-MODELREFRESH-001\b.*?(?=^#{2,3} V3-[A-Z0-9-]+\b|\Z)",
            document,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert match is not None
        section = " ".join(match.group().split())
        assert "No provider or operator action is current" in section
        assert "`V3-PLANCONSTRAINTS-001` is complete after repair checkpoint `425502c`" in section
        assert "`7ef4717` retained as its historical implementation base" in section
        assert "separate future authorization" in section
        assert "do not emit or rerun an authenticated refresh command" in section
        assert "operator-run authenticated metadata discovery" not in section


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
    traceability_text = TRACEABILITY_PATH.read_text(encoding="utf-8")
    traceability = json.loads(traceability_text)
    requirements = traceability["requirements"]
    requirement_ids = [requirement["id"] for requirement in requirements]

    assert requirement_ids == list(EXPECTED_REQUIREMENT_IDS), (
        "review traceability must contain the canonical complete A-V requirement sequence"
    )
    assert "The current 29375-byte operator log" not in traceability_text
    assert "The current 35771-byte operator record" not in traceability_text
    assert "the current one-entry AUTHRUNNER campaign ledger" not in traceability_text
    assert "the then-current one-entry AUTHRUNNER campaign ledger" in traceability_text
    assert "then-current 29375-byte operator log" in traceability_text
    assert "then-current 35771-byte operator record" in traceability_text
    assert "global 25-entry ledger / 0.396223 USD" in traceability_text
    requirements_by_id = {requirement["id"]: requirement for requirement in requirements}
    truncation_evidence = " ".join(requirements_by_id["J"]["evidence"])
    assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in truncation_evidence
    assert CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT in truncation_evidence
    assert CURRENT_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT in truncation_evidence
    assert "one depth-two generic family" in truncation_evidence
    assert "nested family closes at typed v1.1 COVERAGE_CLOSED" in truncation_evidence
    assert "root at typed v1.2 RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING" in (
        truncation_evidence
    )
    assert "66 full truncation-recovery journal tests" in truncation_evidence
    assert "2 recursive positive/shared-cap integrations" in truncation_evidence
    assert "1 direct compatibility integration" in truncation_evidence
    assert "1 specialist compatibility integration" in truncation_evidence
    assert "independent no-blocker/HIGH review passed" in truncation_evidence
    assert (
        "full-tree opaque live capability and promotion"
        in (requirements_by_id["J"]["remaining_proof"])
    )
    autonomy_evidence = " ".join(requirements_by_id["U"]["evidence"])
    assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in autonomy_evidence
    assert CURRENT_TRUNCATION_RECURSIVE_CHECKPOINT in autonomy_evidence
    assert CURRENT_TRUNCATION_RECURSIVE_PARENT_CHECKPOINT in autonomy_evidence
    assert AUTONOMY_INVENTORY_RAW_SHA256 in autonomy_evidence
    assert AUTONOMY_INVENTORY_SHA256 in autonomy_evidence
    assert AUTONOMY_DISCOVERY_SEMANTICS_SHA256 in autonomy_evidence
    assert AUTONOMY_SOURCE_UNIVERSE_SHA256 in autonomy_evidence
    assert "Full-tree opaque promotion" in autonomy_evidence
    assert "REAL provider execution remain absent" in autonomy_evidence
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
    operator_result_bytes = subprocess.run(
        [
            "git",
            "show",
            f"{PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT}:{OPERATOR_RESULTS_RELATIVE_PATH}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    operator_results = operator_result_bytes.decode("utf-8")
    queues = (
        (ROOT / "docs/codex_work_queue.md").read_text(encoding="utf-8"),
        QUEUE_PATH.read_text(encoding="utf-8"),
    )
    worklogs = (
        CODEX_WORKLOG_PATH.read_text(encoding="utf-8"),
        (ROOT / "docs/remediation/v3/worklog.md").read_text(encoding="utf-8"),
    )
    for worklog in worklogs:
        assert (
            "AUTORUN_STATUS: V3_TRUNCATION_001_SPECIALIST_ROLE_RECOVERY_CHECKPOINTED_"
            "PROVIDER_FREE_NONAUTHORIZING_RECURSIVE_CHILD_RECOVERY_NEXT"
        ) in worklog
        assert "CURRENT_TICKET: V3-TRUNCATION-001" in worklog
        assert (
            "CURRENT_LOCAL_SLICE_STATUS: SPECIALIST_ROLE_RECOVERY_COMPLETE_PROVIDER_FREE_"
            "NONAUTHORIZING_RECURSIVE_CHILD_RECOVERY_PENDING"
        ) in worklog
        assert CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT in worklog
        assert "recursive recovery of one truncated recovery child" in worklog
        assert (
            "OPERATOR_RESULTS_CURRENT_WORKTREE_STATUS: USER_OWNED_DRIFT_DETECTED_NOT_OPENED_"
            "OR_RECONCILED_FOR_CURRENT_PROVIDER_FREE_SOURCE_TICKET"
        ) in worklog
        assert (
            f"LAST_RECONCILED_OPERATOR_RESULTS: `{LAST_RECONCILED_OPERATOR_RESULTS_SHA256}` / "
            "115171 bytes / 2111 lines"
        ) in worklog
    normalized_queues = tuple(" ".join(queue.split()) for queue in queues)
    runtime_status = json.loads(RUNTIME_STATUS_PATH.read_text(encoding="utf-8"))
    assert runtime_status["operator_results_current_worktree_status"] == (
        "USER_OWNED_DRIFT_DETECTED_NOT_OPENED_OR_RECONCILED_FOR_CURRENT_PROVIDER_FREE_SOURCE_TICKET"
    )
    assert runtime_status["operator_results_current_worktree_required_for_ticket"] is False
    assert (
        runtime_status["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert runtime_status["last_reconciled_operator_results_bytes"] == 115_171
    assert runtime_status["last_reconciled_operator_results_lines"] == 2_111
    autonomy_inventory_bytes = AUTONOMY_INVENTORY_PATH.read_bytes()
    autonomy_inventory = json.loads(autonomy_inventory_bytes)
    autonomy_schema_bytes = AUTONOMY_INVENTORY_SCHEMA_PATH.read_bytes()
    autonomy_schema = json.loads(autonomy_schema_bytes)
    managed_toolchain_bytes = MANAGED_TOOLCHAIN_BUNDLE_PATH.read_bytes()
    managed_toolchain = json.loads(managed_toolchain_bytes)
    managed_toolchain_schema_bytes = MANAGED_TOOLCHAIN_SCHEMA_PATH.read_bytes()
    managed_toolchain_schema = json.loads(managed_toolchain_schema_bytes)
    assert runtime_status["real_model_calls"] == {
        "attempted": None,
        "succeeded": None,
        "rejected": None,
        "current_aggregate_counts_reported": False,
    }
    assert runtime_status["historical_real_model_calls_through_r9"] == {
        "attempted": 20,
        "succeeded": 2,
        "rejected": 18,
        "is_current_aggregate": False,
    }
    assert runtime_status["openrouter_budget_usd"] == {
        "projection_scope": "LAST_RECONCILED_OPERATOR_RECORD_NOT_CURRENT_USER_OWNED_WORKTREE_STATE",
        "used_value_provenance": (
            "LAST_RECONCILED_OPERATOR_RESULTS_"
            "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
        ),
        "used_value_operator_reported": True,
        "independently_authenticated_by_codex": False,
        "codex_private_ledger_accessed": False,
        "cap": "250.00000000",
        "used": "0.396223",
        "reserved": None,
        "remaining": None,
        "last_reconciled_reserved_and_remaining_reported": False,
        "is_authority": False,
    }
    assert runtime_status["historical_governed_ledger_evidence"] == {
        "entry_count": 11,
        "used_usd": "0.0034764325",
        "reserved_usd": "0.00000000",
        "remaining_usd": "249.9965235675",
        "is_current_live_campaign_ledger": False,
    }
    assert "live_authrunner_campaign_ledger" not in runtime_status
    assert runtime_status["last_reconciled_authrunner_campaign_ledger"] == {
        "projection_scope": "LAST_RECONCILED_OPERATOR_RECORD_NOT_CURRENT_USER_OWNED_WORKTREE_STATE",
        "projection_provenance": (
            "LAST_RECONCILED_OPERATOR_RESULTS_"
            "4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251"
        ),
        "operator_reported": True,
        "independently_authenticated_by_codex": False,
        "codex_private_ledger_accessed": False,
        "entry_count": 25,
        "used_usd": "0.396223",
        "reserved_usd": None,
        "remaining_usd": None,
        "terminal_entry_count": None,
        "last_reconciled_reserved_remaining_and_terminal_count_reported": False,
        "reported_occupied_run_indexes": [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
        ],
        "next_unused_run_index": None,
        "next_unused_run_index_stated": False,
        "entry_statuses": {
            "smoke_r1": "reconciled",
            "smoke_r2": "uncertain_accounted",
            "smoke_r3": "reconciled",
            "smoke_r4": "reconciled",
            "smoke_r5": "reconciled",
            "smoke_r6": "reconciled",
            "smoke_r7": "reconciled",
            "smoke_r8": "reconciled",
            "smoke_r9": "reconciled",
            "smoke_r10": "reconciled",
            "smoke_r11": "reconciled",
            "smoke_r12": "reconciled",
            "smoke_r13": "reconciled",
            "smoke_r14": "charged_terminal_status_not_stated",
            "smoke_r15": "charged_terminal_status_not_stated",
            "smoke_r16": "charged_terminal_status_not_stated",
            "smoke_r17": "operator_timeout_one_uncertain_accounted_judge_entry",
            "smoke_r18": "schema_validation_failed_candidate",
            "smoke_r19": "complete_noncrediting_nonauthorizing_closed_four_entry_run",
        },
        "smoke_r1_actual_cost_usd": "0.01680888",
        "smoke_r1_accounted_cost_usd": "0.01680888",
        "smoke_r2_actual_cost_usd": None,
        "smoke_r2_accounted_cost_usd": "0.05225616",
        "smoke_r3_actual_cost_usd": "0.00554796",
        "smoke_r3_accounted_cost_usd": "0.00554796",
        "smoke_r4_actual_cost_usd": "0.00537768",
        "smoke_r4_accounted_cost_usd": "0.00537768",
        "smoke_r5_r6_r7_r8_r9_per_index_cost_mapping_available": False,
        "smoke_r5_through_r9_all_reconciled": True,
        "smoke_r10_r11_r12_r13_per_index_cost_mapping_available": False,
        "smoke_r10_through_r13_all_reconciled": True,
        "smoke_r14_actual_cost_usd": "0.004044",
        "smoke_r15_actual_cost_usd": "0.008478",
        "smoke_r16_actual_cost_usd": "0.006281",
        "smoke_r14_r15_terminal_statuses_stated": False,
        "smoke_r16_terminal_status_stated": False,
        "smoke_r19_bundle_sha256": (
            "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
        ),
        "smoke_r19_bundle_bytes": 282_802,
        "smoke_r19_closed_run_ledger_entry_count": 4,
        "smoke_r19_closed_run_ledger_final_spent_usd": "0.39622262",
        "smoke_r19_canonical_replay_status": (
            "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED_AT_C627F2D"
        ),
        "smoke_r2_releasable_or_reusable": False,
        "every_terminal_entry_releasable_or_reusable": False,
        "is_authority": False,
    }
    preflight_status = runtime_status["historical_authrunner_provider_free_r2_r5_r2_preflight"]
    assert preflight_status["status"] == (
        "VALID_NONAUTHORIZING_NO_PROVIDER_EGRESS_HISTORICAL_R2_R5_R2"
    )
    assert preflight_status["scope"] == "HISTORICAL_R2_R5_R2_AFTER_A1ACE778_DO_NOT_RERUN"
    smoke_status = runtime_status["authrunner_noncrediting_smoke"]
    exact_status = runtime_status["authrunner_exact_cost_admission"]
    assert exact_status["historical_committed_byte_preflight_scope"] == (
        "HISTORICAL_F6ACF206_AND_FD1459B_MECHANISM_EVENTS_NOT_CURRENT_7EF4717_"
        "PREFLIGHT_ROUTE_COMMAND_OR_AUTHORITY"
    )
    assert (
        exact_status["historical_failed_committed_byte_preflight"]["operator_results_sha256"]
        == "3c8fc79c24615fae4f80dbbed6c86a9ddbb4b61cd0b1441ac83d2b020a1b60fd"
    )
    assert (
        exact_status["historical_post_cache_fix_committed_byte_preflight"][
            "operator_results_sha256"
        ]
        == "3af4473feac473c3ef5b7ecd553ed67dc141d6f174647e29bd2c1dc485bc609e"
    )
    assert exact_status["historical_exact_cost_base_checkpoint_commit"] == (
        "f6acf206f2c55eeb57b1a11fcf58cc4694a41208"
    )
    assert exact_status["historical_cache_dominance_fix_checkpoint_commit"] == (
        "fd1459b519ea0ce28a2d123ddeb57653dd2f7918"
    )
    assert exact_status["historical_post_cache_fix_committed_byte_preflight_status"] == (
        "FAILED_SAFE_REASONING_CAPABILITY_AFTER_CACHE_GATE_CLEARED"
    )
    assert exact_status["historical_post_origin_fix_provider_free_smoke_preflight_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_NO_PROVIDER_EGRESS_POST_TOKEN_BUDGET_FIX"
    )
    for former_unscoped_preflight_key in (
        "failed_committed_byte_preflight",
        "post_cache_fix_committed_byte_preflight",
        "base_checkpoint_status",
        "base_checkpoint_commit",
        "base_checkpoint_subject",
        "cache_dominance_fix_checkpoint_status",
        "cache_dominance_fix_checkpoint_commit",
        "cache_dominance_fix_checkpoint_subject",
        "post_fix_committed_byte_preflight_status",
        "origin_custody_fix_checkpoint_status",
        "origin_custody_fix_checkpoint_commit",
        "origin_custody_fix_checkpoint_subject",
        "post_origin_fix_provider_free_smoke_preflight_status",
    ):
        assert former_unscoped_preflight_key not in exact_status
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
    current_r9_r8_r8_smoke_real_command = (
        "env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE "
        'PYTHONPATH="$PWD/src" MMAUDIT_BUDGET_USD=250 '
        'MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        "/Users/generalcuster/Documents/dev/Auditor/.venv/bin/mmaudit models "
        "authenticated-runner-smoke --candidate-registry "
        '"$HOME/.mmaudit/private/authrunner/candidate-registry-r9.json" '
        '--candidate-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-candidate-20260822-r9" --primary-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/primary-judge-registry-r8.json" '
        '--primary-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-primary-judge-20260821-r8" --replay-judge-registry '
        '"$HOME/.mmaudit/private/authrunner/replay-judge-registry-r8.json" '
        '--replay-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/'
        'authrunner-replay-judge-20260822-r8" '
        "--smoke-corpus benchmarks/model_corpus_smoke "
        "--smoke-run-index 2 "
        '--output "$HOME/.mmaudit/private/authrunner/'
        'authenticated-runner-smoke-evidence-20260822-s3.json" '
        "--candidate-cost-cap-usd-per-attempt 1.00 "
        "--primary-judge-cost-cap-usd-per-attempt 1.00 "
        "--replay-judge-cost-cap-usd-per-attempt 1.00 "
        "--config config/openrouter-qualification.toml "
        "--corpus benchmarks/model_corpus/manifest.json "
        '--cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" '
        '--secrets-env-file "$HOME/.mmaudit/secrets.env" '
        "--allow-code-egress --no-color"
    )
    current_r9_r8_r8_smoke_live_route_command = current_r9_r8_r8_smoke_real_command.replace(
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
    assert "Before ending any turn" in agents
    assert "issued, reissued, or depended on an operator command" in agents
    assert "read `docs/remediation/v3/operator_results.md`" in agents
    assert "reconcile its latest result" in agents
    assert "../remediation/v3/operator_results.md" in model_selection
    assert (
        hashlib.sha256(operator_result_bytes).hexdigest()
        == PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256
    )
    assert PLANCONSTRAINTS_PARENT_OPERATOR_RESULTS_SHA256 != LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    assert HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT in normalized_model_selection
    assert (
        "activates receipt preparation, dispatch, all-or-none completion-plus-metadata composition"
        in normalized_model_selection
    )
    assert "`INCOMPLETE`, not a pass" in normalized_model_selection
    assert AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT in normalized_model_selection
    assert "fails on untouched parent" in normalized_model_selection
    assert "closure-owned live authority-registry dicts or cells" in normalized_model_selection
    assert "coordinated mutation of the outermost checker" in normalized_model_selection
    assert "tracing, profiling, native-memory, or equivalent runtime compromise" in (
        normalized_model_selection
    )
    assert "provider transport receipt cannot seal owned request state" in (
        normalized_model_selection
    )
    assert "positively traverses the repaired receipt-seal boundary" in normalized_model_selection
    assert (
        "`usage_diagnostics=STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS`"
        in normalized_model_selection
    )
    assert "25-entry global ledger totaling `$0.396223`" in normalized_model_selection
    assert "next unused index is not stated" in normalized_model_selection
    assert "explicitly retracts its prior requested-mode hypothesis" in normalized_model_selection
    assert "accounting and canonical-replay boundary" in model_selection
    assert "The current r6/r6/r2 input composition" not in model_selection
    assert "not a current plan, command, or reusable output target" in normalized_model_selection
    assert "same bundle bytes offline" in normalized_model_selection
    assert "without another provider run or new spend" in normalized_model_selection
    assert "operator-supplied verification" in normalized_model_selection
    assert "not independent private-artifact authentication by Codex" in (
        normalized_model_selection
    )
    assert "No AUTHRUNNER command is current" in normalized_model_selection
    for worklog_path in (CODEX_WORKLOG_PATH, ROOT / "docs/remediation/v3/worklog.md"):
        worklog = " ".join(worklog_path.read_text(encoding="utf-8").split())
        assert "boundary-local historical snapshot" in worklog
        assert "not present authority or current action" in worklog
        assert "No next unused index is stated; no current command exists." in worklog
        assert "No next unused index or current command exists." not in worklog
    assert HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in model_selection
    assert all(HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256 in queue for queue in queues)
    assert all(
        f"Historical selection-plan checkpoint `{HISTORICAL_DCABE_SELECTION_CHECKPOINT}`" in queue
        for queue in normalized_queues
    )
    assert all(PLANCONSTRAINTS_REPAIR_CHECKPOINT in queue for queue in normalized_queues)
    assert all(
        f"Current selection-plan checkpoint `{HISTORICAL_DCABE_SELECTION_CHECKPOINT}`" not in queue
        for queue in normalized_queues
    )
    assert all("Historical exact-cost admission slice 2026-08-21" in queue for queue in queues)
    assert all("Exact-cost admission WIP 2026-08-21" not in queue for queue in queues)
    assert all(
        "Last reconciled operator-reported offline result / limitation" in queue for queue in queues
    )
    assert all(
        "Current operator-reported offline result / limitation" not in queue for queue in queues
    )
    assert all("Current live result / limitation" not in queue for queue in queues)
    assert all("independently verifies the same 282,802-byte" not in queue for queue in queues)
    assert all("No post-`c627f2d` provider call" in queue for queue in normalized_queues)
    assert all("The current 29,375-byte operator-supplied log" not in queue for queue in queues)
    assert all("The then-current 29,375-byte operator-supplied log" in queue for queue in queues)
    assert all("independently confirms the source mismatch" not in queue for queue in queues)
    assert all("The current 44,808-byte" not in queue for queue in queues)
    assert all("The current 50,211-byte" not in queue for queue in queues)
    assert "The current 57,621-byte canonical manifest" not in model_selection
    for filename, expected_sha256 in smoke_file_sha256s.items():
        artifact_bytes = (ROOT / "benchmarks/model_corpus_smoke" / filename).read_bytes()
        assert hashlib.sha256(artifact_bytes).hexdigest() == expected_sha256
        assert expected_sha256 in model_selection
    assert "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497" in (model_selection)
    assert selection_plan["plan_sha256"] == CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    assert selection_plan["plan_sha256"] in model_selection
    assert selection_plan["schema_version"] == "1.4"
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
    assert current_r9_r8_r8_smoke_live_route_command not in model_selection
    assert current_r9_r8_r8_smoke_real_command not in model_selection
    assert (
        current_r9_r8_r8_smoke_live_route_command.replace(
            "--allow-metadata-egress --live-route-preflight-only --no-color",
            "--allow-code-egress --no-color",
        )
        == current_r9_r8_r8_smoke_real_command
    )
    assert model_selection.count(".venv/bin/mmaudit models authenticated-runner-smoke") == 0
    assert ".venv/bin/mmaudit models verify-authenticated-runner-smoke" not in model_selection
    assert ".venv/bin/mmaudit models authenticated-runner --" not in model_selection
    assert model_selection.count("--live-route-preflight-only") == 0
    assert model_selection.count("--allow-metadata-egress") == 0
    assert model_selection.count("--allow-code-egress") == 0
    assert " --preflight-only " not in model_selection
    assert "authrunner-candidate-20260822-r9" in model_selection
    assert "primary-judge-registry-r14.json" in model_selection
    assert "replay r8" in model_selection
    assert model_selection.count("--smoke-run-index 2") == 0
    assert AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT in model_selection
    assert "385-test implementer matrix" in normalized_model_selection
    assert "independent 363-test review" in normalized_model_selection
    assert 'PYTHONPATH="$PWD/src"' not in model_selection
    assert "no current command or campaign authority exists" in normalized_model_selection
    assert "`V3-AUTONOMY-001` Phase 2 remains paused" in model_selection
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
    assert "both the paid smoke and its conditional offline verifier were withdrawn" in (
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
    assert "every previously emitted AUTHRUNNER command was withdrawn" in (
        normalized_model_selection
    )
    assert "no runnable metadata, discovery, smoke, verifier" in (normalized_model_selection)
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
    assert "`NATIVE_JSON_SCHEMA` plus literal `structured_outputs`" in model_selection
    assert "self-hashed selection plan" in normalized_model_selection
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
    assert runtime_status["updated_at"] == "2026-08-24T14:43:31Z"
    assert runtime_status["candidate_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert (
        runtime_status["candidate_commit_parent"] == CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
    )
    assert runtime_status["candidate_commit_pushed"] is False
    assert runtime_status["candidate_commit_remote_resolved"] is False
    assert runtime_status["candidate_successor_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert runtime_status["candidate_successor_status"] == (
        "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    )
    assert (
        "Exact 16-path provider-free V3-TRUNCATION-001 specialist-role recovery slice"
        in runtime_status["candidate_commit_scope"]
    )
    assert (
        "private successful specialist recovery children"
        in runtime_status["candidate_commit_scope"]
    )
    assert "public v1.1 evidence" in runtime_status["candidate_commit_scope"]
    assert "live REAL promotion" in runtime_status["candidate_commit_scope"]
    assert "byte-stable zero-transport resume" in runtime_status["candidate_commit_scope"]
    assert "recursive recovery-child consumption" in runtime_status["candidate_commit_scope"]
    assert "operator_results" in runtime_status["candidate_commit_scope"]
    assert "operator action are excluded" in runtime_status["candidate_commit_scope"]
    assert (
        "conditionally preauthorized" not in runtime_status["blocked_tickets"]["V3-AUTHRUNNER-001"]
    )
    assert runtime_status["historical_paid_diagnostic_base_commit"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert runtime_status["last_checkpoint_commit"] == CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT
    assert "exact 16-path" in runtime_status["last_checkpoint_commit_scope"]
    assert (
        "V3_TRUNCATION_001_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_"
        "PROVIDER_FREE_NONAUTHORIZING" in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        "private v1.2 successful specialist children"
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert (
        "public v1.1 evidence exposes only the outcome hash"
        in runtime_status["last_checkpoint_commit_scope"]
    )
    assert "recursive child consumption" in runtime_status["last_checkpoint_commit_scope"]
    assert "425502c PLANCONSTRAINTS repair" in runtime_status["last_checkpoint_commit_scope"]
    assert "operator_results" in runtime_status["last_checkpoint_commit_scope"]
    assert "provider/network execution" in runtime_status["last_checkpoint_commit_scope"]
    assert "operator action are excluded" in runtime_status["last_checkpoint_commit_scope"]
    planconstraints_status = runtime_status["planconstraints_provider_free_route_admission"]
    assert planconstraints_status == {
        "ticket": "V3-PLANCONSTRAINTS-001",
        "status": "HISTORICAL_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_REGRESSION_REPAIRED",
        "source_checkpoint_commit": PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        "source_checkpoint_parent": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "source_checkpoint_subject": "Restore selected endpoint name parity",
        "source_checkpoint_exact_path_count": 5,
        "historical_base_source_checkpoint_commit": HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT,
        "historical_base_source_checkpoint_parent": (
            HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT
        ),
        "historical_base_source_checkpoint_exact_path_count": 33,
        "source_checkpoint_pushed": False,
        "source_checkpoint_remote_resolved": False,
        "selection_plan_schema_version": "1.4",
        "selection_plan_raw_sha256": hashlib.sha256(SELECTION_PLAN_PATH.read_bytes()).hexdigest(),
        "selection_plan_sha256": CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256,
        "candidate_selection_plan_schema_raw_sha256": (
            "d271ed3ce6ccde084653b9daaf4d56e5573c6f64a7a62f9bf198ce9cdf16b3b5"
        ),
        "authenticated_runner_smoke_evidence_bundle_schema_raw_sha256": (
            "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404"
        ),
        "shared_route_constraint_profile_count": 1,
        "shared_route_constraint_predicate_count": 29,
        "shared_route_constraint_profile_sha256": (
            "00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82"
        ),
        "selected_provider_display_name_uniqueness_retained": True,
        "unrelated_provider_display_name_duplicates_allowed": True,
        "complete_provider_identity_inventory_retained": True,
        "display_name_casefolding_retained": True,
        "selection_discovery_registry_candidate_judge_and_runtime_parity_bound": True,
        "runtime_required_output_tokens_bound_to_serialized_max_tokens": True,
        "full_admission_status": "BLOCKED_FAIL_CLOSED_TYPED_UNAVAILABLE_EVIDENCE",
        "typed_unavailable_requirements": [
            "EMPIRICAL_SCHEMA_VALIDATION",
            "RUNTIME_TOKEN_DETAIL_CONVENTION",
        ],
        "adjacent_runner_matrix_tests_passed": 921,
        "focused_route_snapshot_discovery_admission_tests_passed_overlapping": 250,
        "canonical_inventory_tests_passed": 32,
        "ruff_check": "PASS",
        "ruff_format_check": "PASS_FOCUSED_FILES_ALREADY_FORMATTED",
        "strict_mypy_source_files": 1,
        "strict_mypy": "PASS",
        "canonical_generator_write_and_verify": "PASS",
        "pip_check": "PASS_NO_BROKEN_REQUIREMENTS",
        "diff_integrity": "PASS",
        "historical_7ef_independent_mutation_probe_count": 1012,
        "historical_7ef_independent_import_order_count": 6,
        "independent_review": "PASS_NO_BLOCKER_OR_HIGH",
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "operator_private_ledger_accessed_or_mutated": False,
        "campaign_or_operator_action_executed": False,
        "runtime_authority": False,
        "historical_repository_full_suite_status": "INCOMPLETE_NO_PASS_CREDIT",
        "historical_repository_full_suite_passed": 1492,
        "historical_repository_full_suite_skipped": 25,
        "historical_repository_full_suite_failed": 1,
    }
    assert runtime_status["truncation_provider_free_recovery"] == {
        "ticket": "V3-TRUNCATION-001",
        "status": "PARTIAL_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_PROVIDER_FREE_NONAUTHORIZING",
        "source_checkpoint_commit": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "source_checkpoint_parent": CURRENT_TRUNCATION_SPECIALIST_PARENT_CHECKPOINT,
        "source_checkpoint_subject": "Add specialist truncation recovery custody",
        "source_checkpoint_exact_path_count": 16,
        "prior_retained_parent_recovery_checkpoint": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "historical_planconstraints_repair_checkpoint": PLANCONSTRAINTS_REPAIR_CHECKPOINT,
        "historical_planconstraints_base_checkpoint": HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT,
        "historical_authrunner_replay_checkpoint": HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT,
        "private_successful_child_schema_version": "1.2",
        "private_specialist_accepted_outcome_required_for_exact_specialist_child": True,
        "private_specialist_accepted_outcome_sha256_bound": True,
        "public_recovery_request_evidence_schema_version": "1.1",
        "public_specialist_outcome_projection": "SHA256_ONLY",
        "public_specialist_outcome_body_exposed": False,
        "specialist_credit_requires_live_real_promotion": True,
        "specialist_credit_requires_exact_revalidated_usage": True,
        "selected_parent_remains_truncated": True,
        "serialized_child_is_authority": False,
        "mock_child_is_creditable": False,
        "mock_pipeline_specialist_child_count": 2,
        "mock_pipeline_promotion_count": 0,
        "mock_pipeline_specialist_credit_count": 0,
        "mock_resume_provider_transport_count": 0,
        "mock_resume_journal_byte_stable": True,
        "recursive_child_recovery_complete": False,
        "positive_nonempty_full_pipeline_real_promotion_available": False,
        "final_schema_inventory_specialist_tests_passed": 92,
        "promoted_specialist_assurance_tests_passed": 4,
        "journal_resume_tests_passed": 2,
        "mock_pipeline_integration_tests_passed": 1,
        "earlier_adjacent_tests_passed": 162,
        "ruff_check": "PASS",
        "ruff_format_check": "PASS",
        "strict_mypy": "PASS",
        "canonical_generator_write_and_verify": "PASS",
        "diff_integrity": "PASS",
        "independent_review": "PASS_NO_BLOCKER_OR_HIGH",
        "maximum_assurance_attempt_status": "INCONCLUSIVE_NO_TERMINAL_RESULT_NO_PASS_CREDIT",
        "maximum_assurance_attempt_elapsed_seconds": 602.86,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "operator_private_ledger_accessed_or_mutated": False,
        "campaign_or_operator_action_executed": False,
        "runtime_authority": False,
        "next_provider_free_slice": "BOUNDED_RECURSIVE_RECOVERY_CHILD_CONSUMPTION",
    }
    assert runtime_status["autorun_status"] == (
        "V3_TRUNCATION_001_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
        "NONAUTHORIZING_NEXT_RECURSIVE_CHILD_RECOVERY_ZERO_CURRENT_EXTERNAL_COMMANDS"
    )
    assert runtime_status["autorun_status_evidence_scope"] == (
        "LOCAL_PROVIDER_FREE_TRUNCATION_SPECIALIST_RECOVERY_CHECKPOINT_721D17A_PLUS_PRIOR_"
        "RETAINED_PARENT_RECOVERY_CHECKPOINT_390E9B2_PLUS_HISTORICAL_PLANCONSTRAINTS_REPAIR_"
        "CHECKPOINT_425502C_AND_BASE_7EF4717_PLUS_HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT_"
        "C627F2D; LAST_RECONCILED_OPERATOR_EVIDENCE_REMAINS_NONAUTHORIZING_AND_NOT_"
        "INDEPENDENTLY_AUTHENTICATED_BY_CODEX; CURRENT_USER_OWNED_OPERATOR_FILE_DRIFTED_AND_"
        "WAS_NOT_OPENED_OR_RECONCILED_FOR_CURRENT_PROVIDER_FREE_SOURCE_TICKET"
    )
    assert (
        runtime_status["autorun_status_operator_evidence_independently_authenticated_by_codex"]
        is False
    )
    assert runtime_status["autorun_status"] != (
        "PAUSED_AFTER_C627F2D_INDEX_19_VALID_NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_"
        "ZERO_CURRENT_COMMANDS_NEXT_INDEX_NOT_STATED"
    )
    assert runtime_status["current_ticket"] == "V3-TRUNCATION-001"
    assert runtime_status["last_completed_provider_free_work"] == {
        "ticket": "V3-TRUNCATION-001",
        "slice": "SPECIALIST_ROLE_RECOVERY_COMPLETE_AT_721D17A_WITHIN_PARTIAL_TICKET",
        "status": (
            "PARTIAL_PROVIDER_FREE_NONAUTHORIZING; SPECIALIST_CHILD_PRIVATE_V1_2_AND_PUBLIC_"
            "HASH_ONLY_V1_1_CUSTODY_COMPLETE; CREDIT_REQUIRES_LIVE_REAL_PROMOTION; MOCK_AND_"
            "SERIALIZED_EVIDENCE_NONCREDITING"
        ),
        "next_slice": (
            "IMPLEMENT_BOUNDED_PROVIDER_FREE_RECURSIVE_RECOVERY_CHILD_CONSUMPTION_THEN_RECORD_"
            "BEFORE_POSITIVE_NONEMPTY_FULL_PIPELINE_REAL_PROMOTION"
        ),
        "provider_access_authorized": False,
        "secret_access_authorized": False,
        "private_operator_artifact_access_authorized": False,
        "runtime_authority_granted": False,
        "operator_metadata_egress_command_emitted": False,
        "operator_paid_smoke_command_emitted": False,
        "operator_command_execution_authorized": False,
        "parked_ticket": "V3-AUTONOMY-001",
        "parked_ticket_status": (
            "PARTIAL_PHASE_2_PAUSED_PENDING_SEPARATE_AUTHRUNNER_AUTHORITATIVE_"
            "EVIDENCE_NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX_AUTHORIZED"
        ),
        "historical_park_reason": "TIME_SENSITIVE_INDEXED_EXTERNAL_SEQUENCE_ENDED",
    }
    assert runtime_status["prior_provider_free_work"] == {
        "ticket": "V3-TRUNCATION-001",
        "source_checkpoint_commit": PLANCONSTRAINTS_REPAIR_PARENT_CHECKPOINT,
        "source_checkpoint_parent": "b1f8ba9eba7efef94388ab185529f1248fb608c3",
        "source_checkpoint_exact_path_count": 14,
        "completed_slice": "RETAINED_PARENT_SURFACE_RECOVERY",
        "ticket_status": "PARTIAL",
        "specialist_role_recovery_complete": True,
        "specialist_role_recovery_checkpoint": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "recursive_child_recovery_complete": False,
        "positive_nonempty_full_pipeline_real_promotion_available": False,
        "provider_or_network_accessed": False,
        "runtime_authority": False,
    }
    phase_zero = runtime_status["autonomy_phase_zero_inventory"]
    assert phase_zero == {
        "status": "COMPLETE_NONAUTHORIZING",
        "implementation_commit": HISTORICAL_PHASE_ZERO_CHECKPOINT,
        "implementation_commit_pushed": False,
        "implementation_commit_remote_resolved": False,
        "current_reconciliation_commit": CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT,
        "current_reconciliation_commit_pushed": False,
        "current_reconciliation_commit_remote_resolved": False,
        "historical_c627_authrunner_entrypoint_successor_path_count": 3,
        "current_reconciliation_exact_path_count": 16,
        "artifact_path": "docs/remediation/v3/autonomy_gate_inventory.json",
        "schema_path": "schemas/autonomy_gate_inventory.schema.json",
        "artifact_reconciled_for_slice": "V3_TRUNCATION_SPECIALIST_ROLE_RECOVERY",
        "artifact_raw_sha256": AUTONOMY_INVENTORY_RAW_SHA256,
        "schema_raw_sha256": AUTONOMY_INVENTORY_SCHEMA_RAW_SHA256,
        "source_discovery_semantics_sha256": AUTONOMY_DISCOVERY_SEMANTICS_SHA256,
        "source_universe_sha256": AUTONOMY_SOURCE_UNIVERSE_SHA256,
        "source_semantics_sha256": None,
        "source_semantics_sha256_reported": False,
        "historical_03d_source_semantics_sha256": (
            "67f1ff32913327913ab19adbe60ff54263bf0fcb347304b151bd009311cfe1b0"
        ),
        "inventory_sha256": AUTONOMY_INVENTORY_SHA256,
        "source_count": 3657,
        "source_occurrence_count": 3660,
        "gate_source_count": 3614,
        "non_gating_source_count": 43,
        "source_kind_count": 13,
        "logical_gate_count": 35,
        "unsatisfied_gate_count": 29,
        "current_manual_gate_count": 15,
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "historical_structural_successor": "PHASE_2_MANAGED_PROVISIONING_STATE",
        "historical_structural_successor_scope": (
            "COMPONENT_LOCAL_ARCHITECTURAL_SUCCESSOR_NONAUTHORIZING_NOT_CURRENT_"
            "EXECUTION_NEXT_ACTION"
        ),
        "current_execution_status": (
            "TRUNCATION_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
            "NONAUTHORIZING; AUTONOMY_PHASE_2_PAUSED; NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX"
        ),
        "current_execution_next_action": (
            "IMPLEMENT_PROVIDER_FREE_V3_TRUNCATION_001_RECURSIVE_CHILD_RECOVERY; KEEP_AUTHRUNNER_"
            "PARTIAL_BLOCKED_SAFETY; NO_CURRENT_COMMAND_OR_INDEX_INFERENCE"
        ),
    }
    assert runtime_status["managed_toolchain_phase_one"] == {
        "status": "COMPLETE_NONAUTHORIZING",
        "implementation_commit": PHASE_ONE_IMPLEMENTATION_CHECKPOINT,
        "implementation_commit_pushed": False,
        "implementation_commit_remote_resolved": False,
        "implementation_path_count": 18,
        "implementation_core_path_count": 10,
        "post_checkpoint_governance_successor_path_count": 8,
        "operator_results_in_implementation_checkpoint": False,
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
        "historical_structural_successor": "PHASE_2_MANAGED_PROVISIONING_STATE",
        "historical_structural_successor_scope": (
            "COMPONENT_LOCAL_ARCHITECTURAL_SUCCESSOR_NONAUTHORIZING_NOT_CURRENT_"
            "EXECUTION_NEXT_ACTION"
        ),
        "current_execution_status": (
            "TRUNCATION_SPECIALIST_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
            "NONAUTHORIZING; AUTONOMY_PHASE_2_PAUSED; NO_EXTERNAL_SEQUENCE_COMMAND_OR_INDEX"
        ),
        "current_execution_next_action": (
            "IMPLEMENT_PROVIDER_FREE_V3_TRUNCATION_001_RECURSIVE_CHILD_RECOVERY; KEEP_AUTHRUNNER_"
            "PARTIAL_BLOCKED_SAFETY; NO_CURRENT_COMMAND_OR_INDEX_INFERENCE"
        ),
    }
    assert "next_slice" not in phase_zero
    assert "next_slice" not in runtime_status["managed_toolchain_phase_one"]
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
    assert autonomy_inventory["source_count"] == 3657
    assert autonomy_inventory["source_occurrence_count"] == 3660
    assert autonomy_inventory["gate_source_count"] == 3614
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
    assert runtime_status["last_validation"]["historical_03d_generation_real_provider_accessed"]
    assert runtime_status["last_validation"]["historical_03d_generation_operator_secret_accessed"]
    assert runtime_status["last_validation"][
        "historical_03d_generation_operator_private_ledger_accessed_or_mutated"
    ]
    assert runtime_status["last_validation"]["post_c627_real_provider_accessed"] is False
    assert runtime_status["last_validation"]["post_c627_operator_secret_accessed"] is False
    assert (
        runtime_status["last_validation"]["post_c627_operator_private_ledger_accessed_or_mutated"]
        is False
    )
    assert runtime_status["last_validation"]["post_c627_new_spend"] is False
    pause_state = runtime_status["pause_state"]
    current_action = pause_state["next_action_after_v3_truncation_specialist_recovery"]
    resume_action = pause_state["resume_action_v3_truncation_recursive_child_recovery"]
    assert "bounded provider-free recursive recovery-child consumption" in current_action
    assert "original TRUNCATED parent" in current_action
    assert "live-REAL-only promotion credit" in current_action
    assert PLANCONSTRAINTS_REPAIR_CHECKPOINT in current_action
    assert HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT in current_action
    assert HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT in current_action
    assert "Do not infer or issue any operator/provider command" in current_action
    assert "bounded provider-free recursive recovery-child consumption only" in resume_action
    assert "keep the ticket PARTIAL" in resume_action
    assert "positive nonempty full-pipeline REAL promotion evidence" in resume_action
    assert "No operator/provider authority exists" in resume_action
    assert pause_state["non_allowlisted_pause_journal_fields_are_historical"] is True
    assert pause_state["non_allowlisted_pause_journal_fields_are_current_actions"] is False
    assert pause_state["current_semantic_field_allowlist"] == [
        "next_action_after_v3_truncation_specialist_recovery",
        "resume_action_v3_truncation_recursive_child_recovery",
    ]
    assert "Every field in this object" in pause_state["historical_pause_journal_scope"]
    assert "validation*" in pause_state["historical_pause_journal_scope"]
    assert "checkpoint*" in pause_state["historical_pause_journal_scope"]
    assert "timestamped_pause_journal_scope" not in pause_state
    assert "timestamped_pause_journal_entries_are_current_actions" not in pause_state
    assert pause_state["current_action_field"] == (
        "next_action_after_v3_truncation_specialist_recovery"
    )
    assert pause_state["current_resume_field"] == (
        "resume_action_v3_truncation_recursive_child_recovery"
    )
    assert "result_v3_authrunner_current_r2_r5_r2_preflight" not in pause_state
    assert "result_v3_authrunner_historical_r2_r5_r2_preflight" in pause_state
    assert (
        "terminal full unit gate 5989 passed"
        in pause_state["validation_v3_authrunner_exact_cost_admission"]
    )
    assert (
        "validation_v3_authrunner_exact_cost_admission"
        not in pause_state["current_semantic_field_allowlist"]
    )
    identity_reconciliation = smoke_status["initial_identity_binding_reconciliation"]
    assert identity_reconciliation["checkpoint_commit"] == (
        HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert identity_reconciliation["historical_unsafe_checkpoint_commit"] == (
        "8058e7bff88594b44aa42b8695ce5c25442ae73c"
    )
    assert identity_reconciliation["full_structural_validation_used_as_scope_classifier"] is False
    assert (
        identity_reconciliation[
            "exact_candidate_and_judge_smoke_scope_classifier_independent_of_validity"
        ]
        is True
    )
    assert (
        identity_reconciliation["intrinsic_invalid_exact_v3_smoke_bypassed_receipt_guard"] is False
    )
    assert identity_reconciliation["exact_smoke_cutoff_precedes_generation_metadata_get"] is True
    assert identity_reconciliation["exact_smoke_cutoff_precedes_usage_ledger_replacement"] is True
    assert identity_reconciliation["exact_smoke_cutoff_precedes_origin_marking"] is True
    assert (
        identity_reconciliation["exact_smoke_cutoff_precedes_generation_verification_capability"]
        is True
    )
    assert identity_reconciliation["strict_usage_diagnostic_maximum_code_count"] == 1
    assert identity_reconciliation["strict_usage_diagnostic_vocabulary_closed"] is True
    assert identity_reconciliation["generic_and_release_behavior_parity_retained"] is True
    assert (
        identity_reconciliation["operator_exact_strict_usage_rejecting_clause_available"] is False
    )
    assert identity_reconciliation["provider_free_strict_usage_diagnostic_clause_available"] is True
    receipt_scaffold = smoke_status["immutable_transport_receipt_scaffold"]
    assert receipt_scaffold["checkpoint_commit"] == ("8058e7bff88594b44aa42b8695ce5c25442ae73c")
    assert receipt_scaffold["scope_cutoff_hotfix_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_SCOPE_CUTOFF_CHECKPOINT
    )
    assert (
        receipt_scaffold["receipt_composite_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["receipt_composite_parent_checkpoint"] == (
        AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    )
    assert receipt_scaffold["receipt_composite_owned_path_count"] == 14
    assert (
        receipt_scaffold["receipt_state_seal_hotfix_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert (
        receipt_scaffold["receipt_state_seal_hotfix_parent_checkpoint"]
        == HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["receipt_state_seal_hotfix_owned_path_count"] == 4
    assert (
        receipt_scaffold[
            "candidate_receipt_cutoff_bypassed_by_intrinsic_invalid_scope_classification"
        ]
        is False
    )
    assert receipt_scaffold["production_receipt_dispatch_active"] is True
    assert receipt_scaffold["production_receipt_dispatch_dormant"] is False
    assert receipt_scaffold["production_receipt_dispatch_scope"] == (
        "EXACT_CANONICAL_CANDIDATE_OR_JUDGE_V3_NONCREDITING_SMOKE_ONLY"
    )
    assert receipt_scaffold["generic_and_release_use_historical_path"] is True
    assert receipt_scaffold["completion_receipt_composite_complete"] is True
    assert receipt_scaffold["metadata_receipt_composite_complete"] is True
    assert receipt_scaffold["production_in_flight_transport_proof_complete"] is False
    assert receipt_scaffold["production_in_flight_transport_lifecycle_proved_locally"] is True
    assert receipt_scaffold["historical_pre_hotfix_receipt_state_seal_executed"] is True
    assert receipt_scaffold["historical_pre_hotfix_receipt_state_seal_succeeded"] is False
    assert receipt_scaffold["historical_pre_hotfix_failure"] == (
        "provider transport receipt cannot seal owned request state"
    )
    assert receipt_scaffold["historical_pre_hotfix_failure_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert receipt_scaffold["historical_pre_hotfix_provider_completion_or_charge"] is False
    assert receipt_scaffold["historical_pre_hotfix_index_14_consumed"] is False
    assert (
        receipt_scaffold["historical_pre_hotfix_operator_diagnosis_independently_proven"] is False
    )
    assert receipt_scaffold["operator_record_predates_receipt_state_seal_hotfix"] is False
    assert receipt_scaffold["provider_free_receipt_state_seal_hotfix_validated"] is True
    assert receipt_scaffold["historical_live_evidence_scope"] == (
        "HISTORICAL_POST_68126E0_THROUGH_03D6E8A_GENERATION_NOT_POST_C627_PROVIDER_EXECUTION"
    )
    assert receipt_scaffold["historical_post_68126e0_provider_call_executed"] is True
    assert receipt_scaffold["historical_post_68126e0_receipt_state_seal_cleared_live"] is True
    assert receipt_scaffold["historical_3a_structured_output_routing_negative_executed"] is True
    for former_unscoped_live_key in (
        "post_hotfix_provider_call_executed",
        "post_hotfix_receipt_state_seal_cleared_live",
        "post_hotfix_structured_output_routing_negative_executed",
        "production_strong_origin_candidate_or_judge_positive_operator_reported",
        "actual_provider_tls_private_response_graph_operator_reported",
    ):
        assert former_unscoped_live_key not in receipt_scaffold
    assert (
        receipt_scaffold["clause_level_diagnostic_source_checkpoint"]
        == HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert receipt_scaffold["clause_level_diagnostic_owned_path_count"] == 5
    assert receipt_scaffold["clause_level_diagnostic_live_code"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert receipt_scaffold["clause_level_diagnostic_historical_guard_root_count"] == 47
    assert (
        receipt_scaffold["clause_level_diagnostic_historical_reachable_function_state_count"]
        == 1072
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_owned_path_count"] == 5
    assert (
        receipt_scaffold["historical_required_provider_parameters_join_exact_matrix_tests_passed"]
        == 789
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_request_cost_preview_tests_passed"
        ]
        == 19
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_model_benchmark_tests_passed"
        ]
        == 26
    )
    assert receipt_scaffold["historical_required_provider_parameters_join_guard_root_count"] == 47
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_reachable_function_state_count"
        ]
        == 1073
    )
    assert (
        receipt_scaffold[
            "historical_required_provider_parameters_join_post_fix_provider_call_executed"
        ]
        is True
    )
    assert receipt_scaffold["historical_c627_canonical_replay_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    )
    assert receipt_scaffold["historical_c627_canonical_replay_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert receipt_scaffold["historical_c627_canonical_replay_owned_path_count"] == 3
    assert receipt_scaffold["historical_c627_canonical_replay_runtime_tests_passed"] == 95
    assert receipt_scaffold["historical_c627_canonical_replay_adjacent_tests_passed"] == 111
    assert (
        receipt_scaffold["historical_c627_canonical_replay_retained_authrunner_tests_passed"] == 789
    )
    assert receipt_scaffold["historical_c627_canonical_replay_operator_reported_valid"] is True
    assert receipt_scaffold["historical_c627_canonical_replay_provider_rerun_executed"] is False
    assert receipt_scaffold["historical_c627_canonical_replay_new_spend_incurred"] is False
    assert receipt_scaffold["all_or_none_composite_consumption"] is True
    assert receipt_scaffold["same_client_transport_task_thread_pid_and_ledger_custody"] is True
    assert receipt_scaffold[
        "historical_03d_production_strong_origin_candidate_or_judge_positive_operator_reported"
    ]
    assert receipt_scaffold[
        "historical_03d_actual_provider_tls_private_response_graph_operator_reported"
    ]
    assert (
        receipt_scaffold[
            "operator_reported_production_evidence_independently_authenticated_by_codex"
        ]
        is False
    )
    assert receipt_scaffold["complete_provider_compatibility_proven"] is False
    assert receipt_scaffold["candidate_origin_issuance_source_reachable_and_receipt_gated"] is True
    assert receipt_scaffold["judge_capability_issuance_reachable"] is True
    assert receipt_scaffold["judge_capability_issuance_receipt_gated"] is True
    assert receipt_scaffold["judge_capability_live_positive_executed"] is False
    assert receipt_scaffold["usage_publication_full_rollback_join_behaviorally_executed"] is False
    assert (
        receipt_scaffold["generation_capability_full_rollback_join_behaviorally_executed"] is False
    )
    assert receipt_scaffold["focused_tests_passed"] == 785
    assert receipt_scaffold["local_numeric_loopback_httpx_lifecycle_tests_passed"] == 1
    assert receipt_scaffold["independent_guard_root_count"] == 47
    assert receipt_scaffold["independent_reachable_function_state_count"] == 1071
    assert "REACHABLE_MUTATION_OR_REPLACEMENT" in receipt_scaffold["threat_model_covered"]
    assert "DELIBERATE_INTROSPECTIVE_WRITES" in receipt_scaffold["threat_model_excluded"]
    assert "TRACING_PROFILING_NATIVE_MEMORY" in receipt_scaffold["threat_model_excluded"]
    assert receipt_scaffold["runtime_authority"] is False
    historical_c627_receipt = exact_status["historical_c627_receipt_composite_checkpoint"]
    assert historical_c627_receipt["checkpoint_commit"] == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert historical_c627_receipt["parent_commit"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert historical_c627_receipt["owned_path_count"] == 3
    assert historical_c627_receipt["owned_paths"] == [
        "docs/remediation/v3/autonomy_gate_inventory.json",
        "src/mmaudit/models/authenticated_runner_smoke.py",
        "tests/unit/test_authenticated_runner_smoke_runtime.py",
    ]
    assert historical_c627_receipt["path_sha256"] == {
        "docs/remediation/v3/autonomy_gate_inventory.json": (
            HISTORICAL_C627_AUTONOMY_INVENTORY_RAW_SHA256
        ),
        "src/mmaudit/models/authenticated_runner_smoke.py": (
            "27e70a3c17ef5f03c503e594bca2c3e433fb2c4193de772eb7be829592c3555a"
        ),
        "tests/unit/test_authenticated_runner_smoke_runtime.py": (
            "58eab4a75a0a944a2290789570aa410f26b2e0471b215cce45622076ad892d0f"
        ),
    }
    assert historical_c627_receipt["receipt_state_seal_hotfix_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_STATE_SEAL_CHECKPOINT
    )
    assert historical_c627_receipt["receipt_state_seal_hotfix_parent_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert historical_c627_receipt["receipt_state_seal_hotfix_owned_path_count"] == 4
    assert historical_c627_receipt["base_receipt_composite_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_RECEIPT_COMPOSITE_CHECKPOINT
    )
    assert historical_c627_receipt["base_receipt_composite_parent_checkpoint"] == (
        AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
    )
    assert historical_c627_receipt["base_receipt_composite_owned_path_count"] == 14
    assert historical_c627_receipt["operator_result_predates_checkpoint"] is False
    assert historical_c627_receipt["operator_result_postdates_checkpoint"] is True
    assert (
        historical_c627_receipt["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert historical_c627_receipt["last_reconciled_operator_results_bytes"] == 115_171
    assert historical_c627_receipt["last_reconciled_operator_results_lines"] == 2_111
    assert historical_c627_receipt["operator_results_in_checkpoint"] is False
    assert historical_c627_receipt["generic_and_release_parity"] is True
    assert historical_c627_receipt["historical_receipt_state_seal_focused_tests_passed"] == 785
    assert (
        historical_c627_receipt[
            "historical_receipt_state_seal_local_numeric_loopback_httpx_tests_passed"
        ]
        == 1
    )
    assert (
        historical_c627_receipt["historical_receipt_state_seal_independent_guard_root_count"] == 47
    )
    assert (
        historical_c627_receipt[
            "historical_receipt_state_seal_independent_reachable_function_state_count"
        ]
        == 1071
    )
    assert (
        historical_c627_receipt["historical_c627_authenticated_runner_smoke_runtime_tests_passed"]
        == 95
    )
    assert (
        historical_c627_receipt[
            "historical_c627_adjacent_cli_durable_inventory_release_schema_tests_passed"
        ]
        == 111
    )
    assert (
        historical_c627_receipt["historical_c627_retained_exact_authrunner_matrix_tests_passed"]
        == 789
    )
    assert (
        historical_c627_receipt[
            "historical_c627_retained_exact_authrunner_matrix_known_deprecation_warnings"
        ]
        == 2
    )
    assert historical_c627_receipt["full_suite_status"] == (
        "INCOMPLETE_PREEXISTING_DETERMINISTIC_FAILURE_NO_PASS_CREDIT"
    )
    assert historical_c627_receipt["full_suite_passed_before_failure"] == 1492
    assert historical_c627_receipt["full_suite_skipped_before_failure"] == 25
    assert historical_c627_receipt["full_suite_failed"] == 1
    assert historical_c627_receipt["full_suite_failure_reproduced_on_untouched_parent"] is True
    assert historical_c627_receipt[
        "historical_index_14_metadata_gate_status_at_base_checkpoint"
    ] == ("VALID_OPERATOR_REPORTED_NONAUTHORIZING_AFTER_R15_JUDGE_REFREEZES")
    assert historical_c627_receipt["historical_paid_launch_status_at_base_checkpoint"] == (
        "FAILED_SAFE_PRETRANSPORT_PROVIDER_RECEIPT_STATE_SEAL"
    )
    assert historical_c627_receipt["historical_paid_launch_failure_at_base_checkpoint"] == (
        "provider transport receipt cannot seal owned request state"
    )
    assert (
        historical_c627_receipt["historical_provider_completion_or_charge_at_base_checkpoint"]
        is False
    )
    assert historical_c627_receipt["historical_ledger_changed_at_base_checkpoint"] is False
    assert historical_c627_receipt["historical_index_14_consumed_at_base_checkpoint"] is False
    assert historical_c627_receipt["historical_bundle_published_at_base_checkpoint"] is False
    assert historical_c627_receipt["provider_free_receipt_state_seal_hotfix_validated"] is True
    assert historical_c627_receipt["historical_live_evidence_scope"] == (
        "HISTORICAL_POST_68126E0_THROUGH_03D6E8A_GENERATION_NOT_POST_C627_PROVIDER_EXECUTION"
    )
    assert historical_c627_receipt["historical_post_68126e0_provider_call_executed"] is True
    assert (
        historical_c627_receipt["historical_post_68126e0_receipt_state_seal_cleared_live"] is True
    )
    assert (
        historical_c627_receipt["historical_3a_structured_output_routing_negative_executed"] is True
    )
    for former_unscoped_live_key in (
        "post_hotfix_provider_call_executed",
        "post_hotfix_receipt_state_seal_cleared_live",
        "post_hotfix_structured_output_routing_negative_executed",
        "live_clause_specific_negative_executed",
        "live_clause_specific_diagnostic",
        "production_strong_origin_positive_operator_reported",
        "actual_provider_tls_private_response_graph_operator_reported",
    ):
        assert former_unscoped_live_key not in historical_c627_receipt
    assert historical_c627_receipt["clause_level_diagnostic_source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert historical_c627_receipt["clause_level_diagnostic_owned_path_count"] == 5
    assert historical_c627_receipt["clause_level_diagnostic_exact_matrix_tests_passed"] == 789
    assert (
        historical_c627_receipt["clause_level_diagnostic_adjacent_model_benchmark_tests_passed"]
        == 26
    )
    assert historical_c627_receipt["clause_level_diagnostic_independent_tests_passed"] == 564
    assert historical_c627_receipt["clause_level_diagnostic_independent_guard_root_count"] == 47
    assert (
        historical_c627_receipt[
            "clause_level_diagnostic_independent_reachable_function_state_count"
        ]
        == 1072
    )
    assert historical_c627_receipt["historical_required_provider_parameters_join_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert historical_c627_receipt[
        "historical_required_provider_parameters_join_parent_checkpoint"
    ] == (HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT)
    assert (
        historical_c627_receipt["historical_required_provider_parameters_join_owned_path_count"]
        == 5
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_exact_authrunner_matrix_tests_passed"
        ]
        == 789
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_request_cost_preview_tests_passed"
        ]
        == 19
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_model_benchmark_tests_passed"
        ]
        == 26
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_overlapping_usage_plus_preview_tests_passed"
        ]
        == 185
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_overlapping_usage_plus_preview_is_additive"
        ]
        is False
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_independent_guard_root_count"
        ]
        == 47
    )
    assert (
        historical_c627_receipt[
            "historical_required_provider_parameters_join_independent_reachable_function_state_count"
        ]
        == 1073
    )
    assert historical_c627_receipt["historical_generation_provider_call_executed"] is True
    assert historical_c627_receipt["post_c627_provider_call_executed"] is False
    assert historical_c627_receipt["last_reconciled_complete_smoke_run_index"] == 19
    assert historical_c627_receipt["last_reconciled_complete_smoke_status"] == (
        "COMPLETE_NONCREDITING_NONAUTHORIZING"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert historical_c627_receipt["last_reconciled_complete_smoke_bundle_bytes"] == 282_802
    assert historical_c627_receipt["last_reconciled_complete_smoke_canonical_replay_passed"] is True
    assert historical_c627_receipt["last_reconciled_complete_smoke_canonical_replay_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert historical_c627_receipt[
        "historical_pre_c627_complete_smoke_canonical_replay_failure"
    ] == ("authenticated runner smoke bundle failed canonical replay")
    assert historical_c627_receipt[
        "historical_pre_c627_complete_smoke_canonical_replay_underlying_error"
    ] == ("AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate")
    assert historical_c627_receipt["historical_c627_offline_replay_caused_provider_rerun"] is False
    assert historical_c627_receipt["historical_c627_offline_replay_caused_new_spend"] is False
    assert (
        historical_c627_receipt[
            "historical_c627_offline_replay_independently_authenticated_by_codex"
        ]
        is False
    )
    assert historical_c627_receipt["last_reconciled_next_unused_run_index"] is None
    assert historical_c627_receipt["last_reconciled_next_unused_run_index_stated"] is False
    assert historical_c627_receipt["historical_3a_live_clause_specific_negative_executed"] is True
    assert historical_c627_receipt["historical_3a_live_clause_specific_diagnostic"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert historical_c627_receipt[
        "historical_03d_production_strong_origin_positive_operator_reported"
    ]
    assert historical_c627_receipt[
        "historical_03d_actual_provider_tls_private_response_graph_operator_reported"
    ]
    assert (
        historical_c627_receipt[
            "operator_reported_production_evidence_independently_authenticated_by_codex"
        ]
        is False
    )
    assert historical_c627_receipt["complete_provider_compatibility_proven"] is False
    assert historical_c627_receipt["full_publication_rollback_joins_behaviorally_executed"] is False
    assert historical_c627_receipt["provider_access_authorized"] is False
    assert historical_c627_receipt["paid_authority"] is False
    assert historical_c627_receipt["runtime_authority"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_run"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_attempt_started"] is False
    operator_reconciliation = runtime_status["last_validation"]["last_reconciled_operator_evidence"]
    assert (
        operator_reconciliation["operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert operator_reconciliation["operator_results_bytes"] == 115_171
    assert operator_reconciliation["operator_results_lines"] == 2_111
    assert operator_reconciliation["generation_source_checkpoint"] == (
        OPERATOR_INDEX_19_SOURCE_CHECKPOINT
    )
    assert operator_reconciliation["offline_replay_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    )
    assert operator_reconciliation["smoke_run_index"] == 19
    assert operator_reconciliation["smoke_status"] == (
        "COMPLETE_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert operator_reconciliation["historical_pre_c627_failure_phase"] == (
        "POST_RUN_CANONICAL_REPLAY"
    )
    assert operator_reconciliation["historical_pre_c627_failure"] == (
        "authenticated runner smoke bundle failed canonical replay"
    )
    assert operator_reconciliation["historical_pre_c627_underlying_failure"] == (
        "AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate"
    )
    assert operator_reconciliation["historical_03d_generation_provider_completion_or_charge"]
    assert operator_reconciliation["post_c627_provider_completion_or_charge"] is False
    assert operator_reconciliation["ledger_entry_count"] == 25
    assert operator_reconciliation["ledger_total_usd"] == "0.396223"
    assert operator_reconciliation["index_19_closed_run_ledger_entry_count"] == 4
    assert operator_reconciliation["index_19_closed_run_ledger_total_usd"] == "0.39622262"
    assert operator_reconciliation["next_unused_run_index"] is None
    assert operator_reconciliation["next_unused_run_index_stated"] is False
    assert operator_reconciliation["bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert operator_reconciliation["bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert operator_reconciliation["bundle_bytes"] == 282_802
    assert operator_reconciliation["bundle_offline_verified"] is True
    assert operator_reconciliation["bundle_offline_verification_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert (
        operator_reconciliation["bundle_offline_verification_independently_authenticated_by_codex"]
        is False
    )
    assert operator_reconciliation["replay_caused_provider_rerun"] is False
    assert operator_reconciliation["replay_caused_new_spend"] is False
    assert operator_reconciliation["operator_full_bundle_diagnosis_independently_proven"] is False
    assert (
        operator_reconciliation["narrow_report_level_datetime_defect_reproduced_provider_free"]
        is True
    )
    assert operator_reconciliation["authority"] is False
    assert smoke_status["implementation_checkpoint"] == ("692eb173f002818b4434b746c8801b4cbeb852e2")
    assert smoke_status["historical_post_origin_fix_guide_checkpoint"] == (
        "c137f8bae9d27f5120e7e08eba2d9b5b384e1ca5"
    )
    assert smoke_status["historical_post_origin_fix_guide_state"] == (
        "CHECKPOINTED_PUSHED_REMOTE_VERIFIED_PREFLIGHT_VALID_NONAUTHORIZING"
    )
    assert "post_origin_fix_guide_checkpoint" not in smoke_status
    assert "post_origin_fix_guide_state" not in smoke_status
    assert smoke_status["paid_smoke_guide_checkpoint"] == (
        "7b2db061ceb7449674399d6133428b97b74b4b96"
    )
    assert smoke_status["historical_safety_withdrawal_checkpoint"] == (
        "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6"
    )
    assert "safety_withdrawal_checkpoint" not in smoke_status
    assert "safety_withdrawal_checkpoint_subject" not in smoke_status
    assert "7b2db061ceb7449674399d6133428b97b74b4b96" in model_selection
    historical_preflights = smoke_status["historical_provider_free_preflight_snapshots"]
    assert historical_preflights["scope"] == (
        "HISTORICAL_PRE_C627_PROVIDER_FREE_PREFLIGHTS_NOT_CURRENT_ROUTE_FRESHNESS_"
        "COMMAND_OR_AUTHORITY"
    )
    post_token_budget_preflight = historical_preflights["post_token_budget_fix"]
    assert post_token_budget_preflight["status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_NO_PROVIDER_EGRESS"
    )
    assert "preflight_status" not in smoke_status
    assert not any(
        key.startswith(
            (
                "post_token_budget_fix_preflight_",
                "successful_preflight_",
                "post_origin_fix_successful_preflight_",
                "failed_preflight_",
            )
        )
        for key in smoke_status
    )
    assert smoke_status["provider_free_preflight_command_emission_status"] == (
        "HISTORICAL_EXECUTED_VALID_DO_NOT_RERUN"
    )
    assert smoke_status["status"] == (
        "PARTIAL_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_"
        "ZERO_CURRENT_COMMANDS_REAL_BLOCKED_SAFETY"
    )
    assert smoke_status["ticket_status"] == "PARTIAL"
    assert smoke_status["smoke_run_index_contract"] == {
        "status": "IMPLEMENTED_CHECKPOINTED_NONAUTHORIZING",
        "checkpoint_commit": AUTHRUNNER_SMOKE_INDEX_IMPLEMENTATION_CHECKPOINT,
        "checkpoint_pushed": False,
        "checkpoint_remote_resolved": False,
        "durable_schema_version": "1.2",
        "durable_schema_raw_sha256": (
            "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404"
        ),
        "historical_pre_planconstraints_durable_schema_raw_sha256": (
            "2163642df1d0b7adf463eb04887e2027e462acdd716ec83451d76c49d80db78d"
        ),
        "required_cli_argument": True,
        "required_in_metadata_only_and_paid_modes": True,
        "canonical_minimum": 1,
        "canonical_maximum": 999_999_999,
        "current_emitted_run_index": None,
        "occupied_run_indexes": [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            19,
        ],
        "next_unused_run_index": None,
        "next_unused_run_index_stated": False,
        "cumulative_ledger_namespace_reuse_rejected_provider_free": True,
        "attempt_suffixed_namespace_reuse_rejected": True,
        "rejection_precedes_secret_selection": True,
        "rejection_precedes_provider_dispatch": True,
        "rejection_precedes_ledger_mutation": True,
        "historical_reconciled_entry_retained": True,
        "release_namespaces_unchanged_and_disjoint": True,
        "autonomy_entrypoint_source_id": (
            "completion-entrypoint:models_authenticated_runner_smoke:smoke_run_index"
        ),
        "autonomy_entrypoint_logical_gate_id": "gate-authenticated-real-campaign",
        "implementer_focused_tests_passed": 385,
        "independent_focused_tests_passed": 360,
        "independent_adjacent_openrouter_tests_passed": 3,
        "provider_free_contract_access_scope": (
            "LOCAL_PROVIDER_FREE_RUN_INDEX_CONTRACT_IMPLEMENTATION_ONLY_NOT_HISTORICAL_"
            "03D_GENERATION_OR_PRIVATE_LEDGER_PROJECTION"
        ),
        "codex_provider_or_network_accessed_during_provider_free_contract_implementation": (False),
        "codex_operator_secret_accessed_during_provider_free_contract_implementation": False,
        (
            "codex_operator_private_ledger_accessed_or_mutated_during_provider_free_"
            "contract_implementation"
        ): False,
        "runtime_authority": False,
    }
    for former_unscoped_access_key in (
        "provider_or_network_accessed",
        "operator_secret_accessed",
        "operator_private_ledger_accessed_or_mutated",
    ):
        assert former_unscoped_access_key not in smoke_status["smoke_run_index_contract"]
    assert smoke_status["real_execution_status"] == (
        "HISTORICAL_03D6E8A_INDEX_19_COMPLETE_NONCREDITING_NONAUTHORIZING_SEALED_BUNDLE_"
        "HISTORICAL_C627F2D_OFFLINE_REPLAY_OPERATOR_REPORTED_VALID_NO_RERUN_NO_NEW_SPEND"
    )
    assert smoke_status["real_command_emission_status"] == (
        "ZERO_CURRENT_AUTHRUNNER_COMMANDS_NEXT_UNUSED_INDEX_NOT_STATED_PAID_NAMESPACE_NOT_AUTHORITY"
    )
    assert smoke_status["offline_verifier_command_emission_status"] == (
        "HISTORICAL_OPERATOR_EXECUTED_LAST_RECONCILED_RESULT_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_ZERO_CURRENT_COMMANDS"
    )
    assert smoke_status["live_route_preflight_command_emission_status"] == (
        "ZERO_CURRENT_ROUTE_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_"
        "NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_UNUSED_INDEX_NOT_STATED"
    )
    assert smoke_status["full_24_case_real_command_status"] == "ABSENT_WITHHELD_BLOCKED_SAFETY"
    assert (
        smoke_status["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert smoke_status["last_reconciled_operator_results_bytes"] == 115_171
    assert smoke_status["last_reconciled_operator_results_lines"] == 2_111
    complete_smoke = smoke_status["last_reconciled_complete_smoke_offline_replay"]
    assert complete_smoke["generation_source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_REQUIRED_PROVIDER_PARAMETERS_CHECKPOINT
    )
    assert complete_smoke["offline_replay_checkpoint"] == HISTORICAL_AUTHRUNNER_REPLAY_CHECKPOINT
    assert complete_smoke["operator_results_sha256"] == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    assert complete_smoke["operator_results_bytes"] == 115_171
    assert complete_smoke["operator_results_lines"] == 2_111
    assert complete_smoke["smoke_run_index"] == 19
    assert complete_smoke["status"] == "COMPLETE_NONCREDITING_NONAUTHORIZING"
    assert complete_smoke["bundle_path"] == (
        "$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json"
    )
    assert complete_smoke["bundle_sha256"] == (
        "e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703"
    )
    assert complete_smoke["bundle_bytes"] == 282_802
    assert complete_smoke["closed_run_ledger_entry_count"] == 4
    assert complete_smoke["closed_run_ledger_final_spent_usd"] == "0.39622262"
    assert complete_smoke["global_ledger_entry_count"] == 25
    assert complete_smoke["global_ledger_total_usd"] == "0.396223"
    assert complete_smoke["canonical_replay_status"] == (
        "VALID_NONCREDITING_NONAUTHORIZING_OPERATOR_REPORTED"
    )
    assert complete_smoke["historical_pre_c627_canonical_replay_failure"] == (
        "authenticated runner smoke bundle failed canonical replay"
    )
    assert complete_smoke["historical_pre_c627_canonical_replay_underlying_error"] == (
        "AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate"
    )
    assert (
        complete_smoke["historical_operator_reported_strict_datetime_validation_error_count"] == 15
    )
    assert (
        complete_smoke["operator_full_bundle_evidence_independently_authenticated_by_codex"]
        is False
    )
    assert complete_smoke["narrow_report_level_datetime_defect_reproduced_provider_free"] is True
    assert complete_smoke["narrow_report_level_datetime_failure_count"] == 3
    assert complete_smoke["index_17_status"] == (
        "OPERATOR_TIMEOUT_ONE_UNCERTAIN_ACCOUNTED_JUDGE_ENTRY"
    )
    assert complete_smoke["index_18_status"] == "SCHEMA_VALIDATION_FAILED_CANDIDATE"
    assert complete_smoke["index_19_status"] == "COMPLETE_NONCREDITING_NONAUTHORIZING"
    assert complete_smoke["next_unused_run_index"] is None
    assert complete_smoke["next_unused_run_index_stated"] is False
    assert complete_smoke["offline_verified"] is True
    assert complete_smoke["offline_verification_operator_reported"] is True
    assert complete_smoke["replay_caused_provider_rerun"] is False
    assert complete_smoke["replay_caused_new_spend"] is False
    assert complete_smoke["current_command"] is False
    assert complete_smoke["authority"] is False
    live_negative = smoke_status[
        "historical_post_diagnostic_structured_output_routing_live_negative"
    ]
    assert live_negative["source_checkpoint"] == (
        HISTORICAL_AUTHRUNNER_STRUCTURED_OUTPUT_DIAGNOSTIC_CHECKPOINT
    )
    assert (
        live_negative["operator_results_sha256"]
        == HISTORICAL_POST_DIAGNOSTIC_OPERATOR_RESULTS_SHA256
    )
    assert live_negative["operator_results_bytes"] == 108_633
    assert live_negative["operator_results_lines"] == 1_980
    assert live_negative["metadata_gate_run_index"] == 16
    assert live_negative["metadata_gate_status"] == (
        "GREEN_OPERATOR_REPORTED_NONAUTHORIZING_DETAILS_UNSTATED"
    )
    assert live_negative["followup_instrumented_run_index"] is None
    assert live_negative["failure"] == (
        "NONCREDITING_SMOKE identity binding lacks immutable receipt custody"
    )
    assert live_negative["usage_diagnostics"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert live_negative["failure_phase"] == (
        "POSTTRANSPORT_STRICT_STRUCTURED_OUTPUT_ROUTING_IDENTITY_REQUIRED_PROVIDER_PARAMETERS_"
        "BEFORE_IMMUTABLE_IDENTITY_CUSTODY"
    )
    assert live_negative["receipt_state_seal_cleared_live"] is True
    assert live_negative["provider_transport_dispatched"] is True
    assert live_negative["provider_completion_or_charge"] is True
    assert live_negative["ledger_entry_count"] == 16
    assert live_negative["ledger_total_usd"] == "0.151976"
    assert live_negative["index_16_cost_usd"] == "0.006281"
    assert live_negative["ledger_changed"] is True
    assert live_negative["run_index_consumed"] is True
    assert live_negative["next_unused_run_index"] == 17
    assert live_negative["bundle_published"] is None
    assert live_negative["requested_mode_mismatch_hypothesis_retracted_as_wrong"] is True
    assert live_negative["exact_route_artifact_identities_stated_in_new_entry"] is False
    assert live_negative["run_16_terminal_status_stated"] is False
    assert (
        live_negative[
            "reserved_remaining_aggregate_call_counts_metadata_get_count_stated_at_that_boundary"
        ]
        is False
    )
    assert live_negative["operator_diagnosis_independently_proven"] is False
    assert live_negative["current_command"] is False
    assert live_negative["authority"] is False
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
    historical_capture = smoke_status["historical_glm_5_2_lineage_capture_and_reseal"]
    assert historical_capture["operator_results_sha256"] == (
        HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256
    )
    assert historical_capture["operator_results_bytes"] == 71_771
    assert historical_capture["operator_results_lines"] == 1_276
    assert historical_capture["reported_capture_source_count"] == 17
    assert historical_capture["capture_status"] == (
        "SUCCESS_ADOPTED_PROVIDER_FREE_DOCUMENTARY_IDENTITY_ONLY"
    )
    assert historical_capture["manifest_sha256"] == CURRENT_LINEAGE_MANIFEST_SHA256
    assert (
        historical_capture["manifest_semantic_bundle_sha256"]
        == CURRENT_LINEAGE_SEMANTIC_BUNDLE_SHA256
    )
    assert historical_capture["reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert historical_capture["model_completions"] == 0
    assert historical_capture["incremental_spend_usd"] == "0"
    assert historical_capture["output_authority"] is False
    assert historical_capture["current_operator_command_emitted"] is False
    historical_r4_selection = runtime_status[
        "historical_authrunner_primary_r4_candidate_selection_validation"
    ]
    assert historical_r4_selection["scope"] == (
        "HISTORICAL_CB3FC341_MINIMAX_R4_SELECTION_NOT_CURRENT_ECB8_ZAI_PLAN_CUSTODY"
    )
    assert historical_r4_selection["commit"] == "cb3fc34174e028c2d2ff208c50c23a90a4b29d72"
    assert "authrunner_candidate_selection_validation" not in runtime_status
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
        "ABSENT_ZERO_CURRENT_COMMANDS_INDEX_10_GATE_WITH_PRIMARY_R14_WAS_OPERATOR_"
        "REPORTED_VALID_IMMEDIATELY_BEFORE_PAID_RUN_BUT_IS_NOW_HISTORICAL_"
        "NONAUTHORIZING"
    )
    assert smoke_status["current_live_route_composition"] is None
    assert smoke_status["current_live_route_preflight_run"] is False
    assert smoke_status["current_live_route_preflight_succeeded"] is False
    assert smoke_status["current_live_route_preflight_logical_gets"] is None
    assert smoke_status["current_live_route_preflight_maximum_provider_attempts"] is None
    assert smoke_status["current_live_route_preflight_provider_completions"] is None
    assert smoke_status["current_live_route_preflight_usage_records"] is None
    assert smoke_status["current_live_route_preflight_budget_unchanged"] is None
    assert smoke_status["current_live_route_preflight_atomic_ledger_unchanged"] is None
    assert smoke_status["current_live_route_preflight_output_published"] is None
    assert smoke_status["historical_operator_live_route_preflight_evidence_scope"] == (
        "HISTORICAL_FIRST_LIVE_ROUTE_PREFLIGHT_EVENT_NOT_CURRENT_ROUTE_STATE"
    )
    assert smoke_status["historical_operator_live_route_preflight_frozen_endpoint_count"] == 12
    assert smoke_status["historical_operator_live_route_preflight_observed_endpoint_count"] == 13
    assert smoke_status["historical_observed_primary_discovery_drift_under_hours"] == 7
    assert "live_route_preflight_checkpoint" not in smoke_status
    assert "observed_primary_discovery_drift_under_hours" not in smoke_status
    assert not any(key.startswith("operator_live_route_preflight_") for key in smoke_status)
    assert "operator_live_route_preflight_current_endpoint_count" not in smoke_status
    assert smoke_status["historical_aggregate_live_route_preflight_scope"] == (
        "HISTORICAL_R6_R6_R2_AGGREGATE_EVENT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert smoke_status["historical_aggregate_candidate_registry"] == "candidate-registry-r6.json"
    assert smoke_status["historical_aggregate_primary_judge_registry"] == (
        "primary-judge-registry-r6.json"
    )
    assert smoke_status["historical_aggregate_replay_judge_registry"] == (
        "replay-judge-registry-r2.json"
    )
    for stale_key in (
        "aggregate_live_route_preflight_checkpoint",
        "operator_aggregate_live_route_preflight_run",
        "fresh_candidate_registry",
        "fresh_candidate_discovery_run",
        "fresh_primary_judge_registry",
        "fresh_primary_judge_discovery_run",
        "fresh_replay_judge_registry",
        "fresh_replay_judge_discovery_run",
    ):
        assert stale_key not in smoke_status
    index_ten_gate = smoke_status["historical_index_10_metadata_only_gate"]
    assert index_ten_gate == {
        "status": (
            "OPERATOR_REPORTED_VALID_IMMEDIATELY_BEFORE_INDEX_10_PAID_RUN_NONAUTHORIZING_HISTORICAL"
        ),
        "candidate_registry": None,
        "candidate_discovery_run": None,
        "primary_registry": "primary-judge-registry-r14.json",
        "primary_discovery_run": "authrunner-primary-judge-20260823-r14",
        "replay_registry": None,
        "replay_discovery_run": None,
        "composition": None,
        "logical_metadata_gets": None,
        "maximum_metadata_provider_attempts": None,
        "usage_records": None,
        "budget_unchanged": None,
        "atomic_cost_ledger_unchanged": None,
        "output_published": None,
        "effective_config_sha256": None,
        "primary_sub_hour_drift_observation_count_that_day": 5,
        "paid_index_10_run_occurred": True,
        "current_command": False,
        "authority": False,
    }
    assert "34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404" in (model_selection)
    assert "Historical AUTHRUNNER replay checkpoint `c627f2d" in model_selection
    assert "Current checkpoint `c627f2d" not in model_selection
    assert "Current `c627f2d`" not in model_selection
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
    assert smoke_status["current_adjacent_composition"] is None
    assert smoke_status["current_smoke_run_index"] is None
    assert smoke_status["current_candidate_registry"] is None
    assert smoke_status["current_candidate_discovery_run"] is None
    assert smoke_status["current_primary_judge_registry"] is None
    assert smoke_status["current_primary_judge_discovery_run"] is None
    assert smoke_status["current_replay_judge_registry"] is None
    assert smoke_status["current_replay_judge_discovery_run"] is None
    assert smoke_status["current_smoke_output"] is None
    assert smoke_status["paused_phase2_working_bytes_may_be_used"] is False
    assert smoke_status["executable_bytes_must_remain_unchanged_between_a_and_b"] is True
    assert smoke_status["paid_execution_adjacency_status"] == (
        "HISTORICAL_INDEX_19_EXECUTION_AND_HISTORICAL_C627F2D_OFFLINE_REPLAY_RECORDED_"
        "NONAUTHORIZING; NO_POST_C627_PROVIDER_RUN; CURRENT_ROUTE_ADJACENCY_NOT_"
        "ESTABLISHED; ZERO_CURRENT_COMMANDS; NEXT_UNUSED_INDEX_NOT_STATED"
    )
    assert smoke_status["paid_path_blocker"] == (
        "HISTORICAL_C627F2D_OFFLINE_REPLAY_IS_OPERATOR_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_BUT_GRANTS_NO_CAMPAIGN_AUTHORITY; COMPLETED_REAL_AUDITS_ZERO; "
        "ONE_CASE_NOT_24; V3_PLANCONSTRAINTS_001_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_"
        "AFTER_425502C_REPAIR_WITH_HISTORICAL_7EF4717_IMPLEMENTATION_BASE; FULL_BLOCKED_"
        "TYPED_UNAVAILABLE_EMPIRICAL_SCHEMA_AND_TOKEN_DETAIL_EVIDENCE; ZERO_CURRENT_"
        "COMMANDS; NEXT_UNUSED_INDEX_NOT_STATED; ANY_FUTURE_OPERATOR_ACTION_REQUIRES_"
        "SEPARATE_AUTHORIZATION"
    )
    assert smoke_status["commands_must_not_be_chained"] is True
    assert smoke_status["pre_a_ledger_exactly_empty_inspection_required"] is False
    assert smoke_status["pre_a_ledger_exactly_one_reconciled_entry_inspection_required"] is False
    assert smoke_status["pre_a_ledger_expected_used_usd"] is None
    assert smoke_status["pre_a_ledger_expected_reserved_usd"] is None
    assert smoke_status["pre_a_ledger_expected_remaining_usd"] is None
    assert smoke_status["pre_a_smoke_run_index_namespace_must_be_unused"] is False
    assert smoke_status["pre_a_smoke_run_index"] is None
    assert smoke_status["pre_a_output_absent_inspection_required"] is False
    assert smoke_status["pre_a_output_parent_mode_0700_inspection_required"] is False
    assert smoke_status["pre_a_exact_artifact_and_config_inspection_required"] is False
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
    assert smoke_status["historical_operator_paid_smoke_run"] is True
    assert smoke_status["historical_operator_paid_smoke_succeeded"] is False
    assert smoke_status["historical_operator_paid_smoke_model_completion_requests"] == 1
    assert smoke_status["historical_operator_paid_smoke_provider_completions"] == 1
    assert smoke_status["historical_operator_paid_smoke_authenticated_metadata_get_count"] is None
    assert smoke_status["historical_operator_paid_smoke_reserved_usd"] == "0.0547272"
    assert smoke_status["historical_operator_paid_smoke_spend_usd"] == "0.01680888"
    assert smoke_status["historical_operator_paid_smoke_accounted_cost_usd"] == "0.01680888"
    assert smoke_status["historical_operator_paid_smoke_ledger_entry_status"] == "reconciled"
    assert smoke_status["historical_operator_paid_smoke_ledger_empty"] is False
    assert smoke_status["historical_operator_paid_smoke_bundle_published"] is False
    assert smoke_status["historical_operator_paid_smoke_verifier_run"] is False
    assert smoke_status["historical_operator_paid_smoke_authenticated_metadata_egress"] is True
    assert smoke_status["historical_operator_paid_smoke_failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert smoke_status["historical_operator_paid_smoke_failure_phase"] == (
        "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    )
    assert smoke_status["historical_operator_paid_smoke_failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert smoke_status["historical_operator_paid_smoke_fields_scope"] == (
        "HISTORICAL_FIRST_CHARGED_PAID_ATTEMPT_RETAINED_UNCHANGED"
    )
    assert not any(key.startswith("operator_paid_smoke_") for key in smoke_status)
    assert smoke_status["current_paid_smoke_authorization_status"] == (
        "NOT_AUTHORIZED_ZERO_CURRENT_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_"
        "VALID_NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_INDEX_NOT_STATED"
    )
    assert smoke_status["last_reconciled_offline_verifier_status"] == (
        "OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_POST_C627F2D_NO_RERUN_NO_NEW_SPEND"
    )
    assert (
        smoke_status["last_reconciled_offline_verifier_result_independently_authenticated_by_codex"]
        is False
    )
    assert smoke_status["historical_pre_c627_offline_verifier_status"] == (
        "ATTEMPTED_FAILED_SAFE_CANONICAL_REPLAY_NO_PASS_CREDIT"
    )
    assert smoke_status["post_c627_offline_replay_provider_calls"] == 0
    assert smoke_status["post_c627_offline_replay_ledger_mutated"] is False
    assert "provider_calls" not in smoke_status
    assert "ledger_mutated" not in smoke_status
    assert smoke_status["historical_paid_smoke_attempt_9_status"] == (
        "FAILED_SAFE_AFTER_CANDIDATE_TRANSPORT_GENERATION_METADATA_INVALID_AND_MISSING_"
        "USAGE_VALIDATION_R9_RECONCILED_NO_BUNDLE"
    )
    assert smoke_status["historical_paid_smoke_attempt_9_run_index"] == 9
    assert smoke_status["historical_paid_smoke_attempt_9_request_id"] == (
        "authrunner.smoke.r9.candidate.primary:"
        "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
    )
    assert smoke_status["historical_operator_paid_smoke_group_run_indexes"] == [14, 15, 16]
    assert smoke_status["historical_operator_paid_smoke_group_status"] == (
        "POST_3A1246D_INDEX_16_CHARGED_FAILED_SAFE_AT_IDENTITY_REQUIRED_PROVIDER_"
        "PARAMETERS_BEFORE_IMMUTABLE_IDENTITY_CUSTODY"
    )
    assert (
        smoke_status["historical_operator_paid_smoke_group_per_run_cost_mapping_available"] is True
    )
    assert smoke_status["historical_operator_paid_smoke_group_run_status"] == (
        "charged_terminal_statuses_not_stated"
    )
    assert smoke_status["historical_operator_paid_smoke_group_usage_diagnostics"] == (
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    )
    assert smoke_status["historical_operator_paid_smoke_group_index_14_cost_usd"] == "0.004044"
    assert smoke_status["historical_operator_paid_smoke_group_index_15_cost_usd"] == "0.008478"
    assert smoke_status["historical_operator_paid_smoke_group_index_16_cost_usd"] == "0.006281"
    assert smoke_status["historical_operator_paid_smoke_group_ledger_entry_count"] == 16
    assert smoke_status["historical_operator_paid_smoke_group_ledger_total_usd"] == "0.151976"
    assert smoke_status["historical_operator_paid_smoke_group_ledger_reserved_usd"] is None
    assert smoke_status["historical_operator_paid_smoke_group_ledger_remaining_usd"] is None
    assert smoke_status["historical_operator_paid_smoke_group_bundle_published"] is None
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
    assert smoke_status["historical_component_validation_scope"] == (
        "HISTORICAL_CHECKPOINT_LOCAL_VALIDATIONS_NOT_CURRENT_7EF4717_VALIDATION_OR_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"][
            "owner_five_file_tests_passed"
        ]
        == 136
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"]["root_five_file_tests_passed"]
        == 136
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"]["independent_tests_passed"]
        == 122
    )
    assert (
        smoke_status["historical_token_budget_parity_fix_validation"][
            "focused_cli_ordering_tests_passed"
        ]
        == 7
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_status_for_current_reconciliation"
        ]
        == "INTERRUPTED_CONCURRENT_OPERATOR_EVIDENCE_CHANGE_NO_CREDIT"
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_tests_passed_before_interruption"
        ]
        == 82
    )
    assert (
        smoke_status["historical_origin_custody_fix_validation"][
            "terminal_full_suite_prerequisite_skips_before_interruption"
        ]
        == 13
    )
    cascade_validation = smoke_status["historical_revocation_cascade_fix_validation"]
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
    for former_unscoped_validation_key in (
        "origin_custody_fix_validation",
        "token_budget_parity_fix_validation",
        "live_route_preflight_validation",
        "revocation_cascade_fix_validation",
        "validation",
    ):
        assert former_unscoped_validation_key not in smoke_status
    assert exact_status["status"] == (
        "PARTIAL_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_NONAUTHORIZING_"
        "ZERO_CURRENT_COMMANDS_REAL_BLOCKED_SAFETY"
    )
    assert exact_status["ticket_status"] == "PARTIAL"
    assert exact_status["autorun_status"] == (
        "PAUSED_AFTER_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_OFFLINE_REPLAY_ZERO_CURRENT_COMMANDS_NEXT_INDEX_NOT_STATED"
    )
    assert exact_status["historical_component_validation_scope"] == (
        "HISTORICAL_CHECKPOINT_LOCAL_VALIDATIONS_NOT_CURRENT_7EF4717_VALIDATION_OR_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert (
        exact_status["historical_reasoning_selection_checkpoint_validation"][
            "final_combined_affected_tests_passed"
        ]
        == 433
    )
    assert (
        exact_status["historical_tencent_lineage_reseal_validation"][
            "current_root_affected_tests_passed"
        ]
        == 120
    )
    assert (
        exact_status["historical_origin_custody_fix_checkpoint_validation"][
            "implementer_tests_passed"
        ]
        == 584
    )
    assert (
        exact_status["historical_token_budget_parity_fix_checkpoint_validation"][
            "owner_five_file_tests_passed"
        ]
        == 136
    )
    assert (
        exact_status["historical_live_route_preflight_checkpoint_validation"]["owner_tests_passed"]
        == 164
    )
    assert exact_status["historical_post_origin_fix_guide_state"] == (
        "CHECKPOINTED_PUSHED_REMOTE_VERIFIED_PREFLIGHT_VALID_NONAUTHORIZING"
    )
    for former_unscoped_validation_key in (
        "reasoning_selection_checkpoint_validation",
        "tencent_lineage_reseal_validation",
        "origin_custody_fix_checkpoint_validation",
        "token_budget_parity_fix_checkpoint_validation",
        "live_route_preflight_checkpoint_validation",
        "post_origin_fix_guide_state",
    ):
        assert former_unscoped_validation_key not in exact_status
    assert exact_status["paid_smoke_real_command_status"] == (
        "ABSENT_ZERO_CURRENT_COMMANDS_POST_C627F2D_INDEX_19_OPERATOR_REPORTED_VALID_"
        "NONCREDITING_NONAUTHORIZING_OFFLINE_REPLAY_NEXT_INDEX_NOT_STATED_NO_PAID_AUTHORITY"
    )
    assert exact_status["offline_smoke_verifier_command_status"] == (
        "HISTORICAL_OPERATOR_EXECUTED_LAST_RECONCILED_RESULT_REPORTED_VALID_NONCREDITING_"
        "NONAUTHORIZING_ZERO_CURRENT_COMMANDS"
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
        "UNRESOLVED_NONAUTHORIZING_LAST_RECONCILED_RECORD"
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
    historical_dcabe = exact_status["historical_dcabe_selection_plan_checkpoint"]
    assert historical_dcabe["status"] == (
        "HISTORICAL_NONAUTHORIZING_SELECTION_PLAN_CUSTODY_WITH_HISTORICAL_DCABE_ROUTE_EVIDENCE_ONLY"
    )
    assert historical_dcabe["route_evidence_scope"] == (
        "HISTORICAL_DCABE_PLAN_BOUND_SNAPSHOT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert historical_dcabe["selection_plan_sha256"] == (
        "ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f"
    )
    assert historical_dcabe["selection_plan_schema_version"] == "1.3"
    assert historical_dcabe["checkpoint_commit"] == HISTORICAL_DCABE_SELECTION_CHECKPOINT
    assert historical_dcabe["checkpoint_status"] == ("LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED")
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_registry"] == (
        "candidate-registry-r9.json"
    )
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_discovery_run"] == (
        "authrunner-candidate-20260822-r9"
    )
    assert historical_dcabe["historical_dcabe_plan_bound_candidate_frozen_sha256"] == (
        "cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad"
    )
    assert historical_dcabe["replay_route_selection_mode"] == (
        "EXPLICIT_OPERATOR_CHOICE_NO_AUTOMATIC_FALLBACK"
    )
    assert historical_dcabe["operator_results_binding_status"] == (
        "BOUND_NONAUTHORIZING_HISTORICAL_PLAN_RECORD"
    )
    assert historical_dcabe["operator_results_binding_sha256"] == (
        "302679f3e8e9281cdf9e0ec3d6d1d566d172cb54b389fbac607180d1f0911940"
    )
    assert (
        historical_dcabe["last_reconciled_operator_results_sha256"]
        == LAST_RECONCILED_OPERATOR_RESULTS_SHA256
    )
    assert historical_dcabe["historical_dcabe_plan_bound_live_route_status"] == (
        "ABSENT_AT_DCABE_PLAN_BOUNDARY_R10_R8_R8_GATE_NOT_CURRENT_FRESHNESS"
    )
    assert historical_dcabe["operator_command_emitted_by_dcabe_plan_checkpoint"] is False
    assert historical_dcabe["authority"] is False

    current_successor = exact_status["current_selection_plan_checkpoint"]
    assert current_successor["status"] == "CURRENT_V1_4_NONAUTHORIZING_PLANCONSTRAINTS_CUSTODY"
    assert current_successor["route_evidence_scope"] == (
        "PROVIDER_FREE_STATIC_AND_REPLAY_CUSTODY_NOT_CURRENT_PROVIDER_ROUTE_FRESHNESS_"
        "COMMAND_OR_AUTHORITY"
    )
    assert (
        current_successor["selection_plan_raw_sha256"]
        == hashlib.sha256(SELECTION_PLAN_PATH.read_bytes()).hexdigest()
    )
    assert current_successor["selection_plan_sha256"] == selection_plan["plan_sha256"]
    assert current_successor["selection_plan_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_PLAN_SHA256
    )
    assert current_successor["selection_plan_schema_version"] == "1.4"
    assert current_successor["checkpoint_commit"] == HISTORICAL_PLANCONSTRAINTS_BASE_CHECKPOINT
    assert current_successor["checkpoint_parent"] == (
        HISTORICAL_PLANCONSTRAINTS_BASE_PARENT_CHECKPOINT
    )
    assert current_successor["checkpoint_status"] == "LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED"
    assert current_successor["checkpoint_pushed"] is False
    assert current_successor["checkpoint_remote_resolved"] is False
    assert current_successor["role_assignment_sha256"] == (
        CURRENT_NONAUTHORIZING_SUCCESSOR_ROLE_SHA256
    )
    assert (
        current_successor["role_assignment_sha256"]
        == (selection_plan["authenticated_runner_selection"]["role_assignment_sha256"])
    )
    assert (
        current_successor["route_predicate_profile_sha256"]
        == (
            selection_plan["authenticated_runner_selection"]["route_predicate_profile"][
                "profile_sha256"
            ]
        )
    )
    assert current_successor["route_predicate_count"] == 29
    assert current_successor["required_output_mode"] == "NATIVE_JSON_SCHEMA"
    assert current_successor["required_supported_parameters"] == ["structured_outputs"]
    assert current_successor["required_reasoning_effort"] == "high"
    assert current_successor["required_completion_limit_source"] == "metadata"
    assert current_successor["required_completion_tokens"] == 8192
    assert current_successor["required_output_tokens"] == 4096
    assert current_successor["reserved_reasoning_tokens"] == 4096
    assert current_successor["candidate_model_id"] == "deepseek/deepseek-v4-pro-0813"
    assert current_successor["candidate_endpoint_tag"] == "parasail/fp8"
    assert current_successor["primary_model_id"] == "z-ai/glm-5.2"
    assert current_successor["primary_endpoint_tag"] == "sail-research/fp8"
    assert current_successor["replay_model_id"] == "moonshotai/kimi-k3"
    assert current_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert current_successor["replay_route_selection_mode"] == (
        "EXPLICIT_EXACT_ROUTE_NO_AUTOMATIC_FALLBACK"
    )
    assert current_successor["empirical_schema_conformance_disposition"] == "UNAVAILABLE"
    assert current_successor["token_detail_convention_disposition"] == "UNAVAILABLE"
    assert current_successor["full_admission_authorized"] is False
    assert current_successor["operator_command_emitted_by_checkpoint"] is False
    assert current_successor["authority"] is False
    assert "historical_full_r2_r5_r2_candidate_admission" in exact_status
    assert exact_status["zero_command_evidence_checkpoint"] == (
        "02ed5bef89d094e0d0c4852e1bf73914d9960c6b"
    )
    assert exact_status["historical_paid_diagnostic_last_durable_pushed_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert "last_durable_pushed_checkpoint" not in exact_status
    assert exact_status["historical_paid_diagnostic_base_checkpoint"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint"] == (
        HISTORICAL_INELIGIBLE_GEMMA_CHECKPOINT
    )
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_pushed"] is False
    assert exact_status["historical_ineligible_gemma_plan_checkpoint_remote_verified"] is False
    assert exact_status["historical_dcabe_selection_plan_candidate_successor_checkpoint"] == (
        HISTORICAL_DCABE_SELECTION_CHECKPOINT
    )
    assert exact_status[
        "historical_dcabe_selection_plan_candidate_successor_checkpoint_status"
    ] == ("LOCAL_COMMIT_NOT_PUSHED_OR_REMOTE_RESOLVED")
    assert "candidate_successor_checkpoint" not in exact_status
    assert "candidate_successor_checkpoint_status" not in exact_status
    assert exact_status["historical_revocation_cascade_validation_status"] == (
        "PASS_PROVIDER_FREE_REVOCATION_CASCADE_FIX_CLEAN_REAL_BLOCKED_SAFETY"
    )
    assert "validation_status" not in exact_status
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
    completion_capacity = exact_status["historical_completion_capacity_invariant_origin"]
    assert completion_capacity["current_invariant_status"] == (
        "ACTIVE_FAIL_CLOSED_EXPLICIT_METADATA_COMPLETION_CAPACITY_REQUIRED"
    )
    assert completion_capacity["route_evidence_scope"] == (
        "HISTORICAL_3975_ORIGIN_PLAN_ROUTES_NOT_CURRENT_SELECTION"
    )
    assert completion_capacity["checkpoint_commit"] == HISTORICAL_COMPLETION_CAPACITY_CHECKPOINT
    assert completion_capacity["lineage_reseal_checkpoint"] == CURRENT_LINEAGE_RESEAL_CHECKPOINT
    assert completion_capacity["selection_plan_schema_version"] == "1.3"
    assert completion_capacity["selection_plan_sha256"] == (
        "4e6c744559b1cc49c8ede590c868df103a10402d429d5e5d02cf4f429e0f3a66"
    )
    assert completion_capacity["selection_plan_required_completion_limit_source"] == "metadata"
    assert completion_capacity["historical_origin_plan_candidate_endpoint_tag"] == "parasail/fp8"
    assert completion_capacity["historical_origin_plan_primary_endpoint_tag"] == (
        "sail-research/fp8"
    )
    assert completion_capacity["historical_origin_plan_replay_endpoint_tag"] == "wafer"
    assert completion_capacity["fails_before_secret_selection"] is True
    assert completion_capacity["fails_before_provider_dispatch"] is True
    assert completion_capacity["fails_before_ledger_reservation"] is True
    assert completion_capacity["operator_command_emitted_by_origin_checkpoint"] is False
    assert completion_capacity["authority"] is False
    replay_successor = exact_status["historical_dcabe_selection_plan_replay_allowlist"]
    assert replay_successor["route_evidence_scope"] == (
        "HISTORICAL_PRE_C627_PLAN_BOUND_NO_POST_C627_METADATA_OR_PROVIDER_PROOF"
    )
    assert replay_successor["checkpoint_commit"] == HISTORICAL_DCABE_SELECTION_CHECKPOINT
    assert replay_successor["selection_plan_sha256"] == (
        "ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f"
    )
    assert replay_successor["replay_allowed_endpoint_tags"] == ["modal/mxfp4", "phala"]
    assert replay_successor["explicit_operator_route_choice_required"] is True
    assert replay_successor["automatic_fallback_allowed"] is False
    assert replay_successor["historical_dcabe_selected_replay_required_additional_discovery"] is (
        False
    )
    assert replay_successor["historical_dcabe_operator_selected_replay_endpoint_tag"] == (
        "modal/mxfp4"
    )
    assert replay_successor["historical_dcabe_operator_selection_operator_reported"] is True
    assert (
        replay_successor["historical_dcabe_operator_selection_independently_authenticated_by_codex"]
        is False
    )
    assert replay_successor["historical_dcabe_operator_selection_is_current_route_freshness"] is (
        False
    )
    assert "plan_selected_replay_endpoint_tag" not in replay_successor
    assert replay_successor["historical_dcabe_plan_bound_replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert replay_successor["historical_pre_c627_r8_r8_r8_live_route_gate_valid"] is True
    assert replay_successor["operator_command_emitted_by_selection_plan_checkpoint"] is False
    assert "r8_r8_r8_live_route_gate_valid" not in replay_successor
    assert replay_successor["unselected_replay_seed_requiring_fresh_discovery_if_selected"] == (
        "phala"
    )
    assert replay_successor["authority"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_run"] is False
    assert runtime_status["last_validation"]["terminal_full_suite_attempt_started"] is False
    assert runtime_status["last_validation"]["status"] == (
        "V3_TRUNCATION_001_SPECIALIST_ROLE_RECOVERY_SLICE_COMPLETE_TICKET_PARTIAL_PROVIDER_FREE_"
        "NONAUTHORIZING_RECURSIVE_CHILD_RECOVERY_PENDING_MAXIMUM_ASSURANCE_INCONCLUSIVE"
    )
    assert "92 PASS" in runtime_status["last_validation"]["command"]
    assert "4 PASS" in runtime_status["last_validation"]["command"]
    assert "2 PASS" in runtime_status["last_validation"]["command"]
    assert "1 PASS" in runtime_status["last_validation"]["command"]
    assert "162 PASS" in runtime_status["last_validation"]["command"]
    assert "INCONCLUSIVE after 602.86 seconds" in runtime_status["last_validation"]["command"]
    assert (
        "V3-TRUNCATION-001 remains PARTIAL after exact 16-path provider-free specialist recovery "
        f"checkpoint {CURRENT_TRUNCATION_SPECIALIST_CHECKPOINT}"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "Private successful specialist children use schema v1.2"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "public recovery request evidence uses v1.1 and exposes only that hash"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "only live REAL promotion with exact revalidated usage can produce specialist credit"
        in runtime_status["last_validation"]["result"]
    )
    assert (
        "two successful child terminals remain unpromoted and noncrediting"
        in runtime_status["last_validation"]["result"]
    )
    assert "resume performs zero transport" in runtime_status["last_validation"]["result"]
    assert (
        "Recursive recovery-child consumption and positive nonempty full-pipeline REAL promotion "
        "remain absent" in runtime_status["last_validation"]["result"]
    )
    assert (
        "Historical 425502c PLANCONSTRAINTS repair" in runtime_status["last_validation"]["result"]
    )
    assert "7ef4717 implementation base" in runtime_status["last_validation"]["result"]
    assert "c627f2d AUTHRUNNER replay" in runtime_status["last_validation"]["result"]
    assert runtime_status["last_validation"]["maximum_assurance_attempt"] == {
        "status": "INCONCLUSIVE_NO_TERMINAL_RESULT_NO_PASS_CREDIT",
        "elapsed_seconds": 602.86,
        "terminal_result_available": False,
        "pass_credit": False,
    }
    terminal_full_suite_attempt = runtime_status["last_validation"][
        "historical_planconstraints_terminal_full_suite_attempt"
    ]
    assert terminal_full_suite_attempt == {
        "command": ".venv/bin/pytest -q",
        "status": "INCOMPLETE_PREEXISTING_DETERMINISTIC_FAILURE_NO_PASS_CREDIT",
        "elapsed_seconds": 3878.41,
        "passed_before_failure": 1492,
        "skipped_before_failure": 25,
        "failed": 1,
        "failure": (
            "tests/unit/test_candidate_benchmark.py::"
            "test_authenticated_runner_candidate_consumes_exact_cost_preview_inventory"
        ),
        "failure_message": "candidate benchmark request accounting is inconsistent",
        "underlying_context": (
            "benchmark cases reported ReasoningPolicyError with zero observed usage"
        ),
        "same_failure_reproduced_on_untouched_parent": (
            AUTHRUNNER_RECEIPT_COMPOSITE_PARENT_CHECKPOINT
        ),
        "introduced_by_receipt_composite_checkpoint": False,
        "terminal_full_suite_pass_credit": False,
    }
    historical_scheduler_recovery = runtime_status["historical_scheduler_full_suite_recovery"]
    assert historical_scheduler_recovery["scope"] == (
        "HISTORICAL_SCHEDULER_RECOVERY_COMPONENT_EVIDENCE_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_scheduler_recovery["status"] == "HISTORICAL_COMPLETE_COMPONENT"
    assert "exact normalized tree passed 4401 tests" in historical_scheduler_recovery["remaining"]
    assert "scheduler_full_suite_recovery" not in runtime_status
    historical_policy_validation = runtime_status["historical_policy_eligibility_core_validation"]
    assert historical_policy_validation["scope"] == (
        "HISTORICAL_POLICY_ELIGIBILITY_COMPONENT_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_policy_validation["status"] == ("HISTORICAL_COMPLETE_PROVIDER_FREE_MECHANISM")
    assert "5155 tests passed" in historical_policy_validation["result"]
    assert "policy_eligibility_core_validation" not in runtime_status
    assert terminal_full_suite_attempt["terminal_full_suite_pass_credit"] is False
    historical_base_validation = exact_status["historical_base_checkpoint_validation"]
    assert historical_base_validation["scope"] == (
        "HISTORICAL_F6ACF206_CHECKPOINT_LOCAL_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_base_validation["terminal_full_unit_tests_passed"] == 5989
    historical_cache_validation = exact_status["historical_cache_dominance_checkpoint_validation"]
    assert historical_cache_validation["scope"] == (
        "HISTORICAL_FD1459B_CHECKPOINT_LOCAL_VALIDATION_NOT_CURRENT_7EF4717_REPOSITORY_"
        "FULL_SUITE_CREDIT"
    )
    assert historical_cache_validation["terminal_full_suite_tests_passed"] == 6230
    assert historical_cache_validation["terminal_full_suite_exit_code"] == 0
    assert "base_checkpoint_validation" not in exact_status
    assert "cache_dominance_checkpoint_validation" not in exact_status
    historical_full_suite_attempt = exact_status[
        "historical_command_guide_successor_full_suite_attempt"
    ]
    assert historical_full_suite_attempt["scope"] == (
        "HISTORICAL_COMMAND_GUIDE_SUCCESSOR_ATTEMPT_NOT_CURRENT_7EF4717_REPOSITORY_FULL_SUITE_CREDIT"
    )
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
    assert "command_guide_successor_full_suite_attempt" not in exact_status
    assert post_token_budget_preflight["operator_results_sha256"] == (
        "76eff45c95116dea28cdaad78115d3926c6da3674a6b322784203335bfef7465"
    )
    assert post_token_budget_preflight["operator_results_bytes"] == 41_806
    assert post_token_budget_preflight["operator_results_lines"] == 756
    historical_charged_smoke = exact_status["historical_first_charged_paid_smoke_attempt"]
    assert historical_charged_smoke["checkpoint_commit"] == (
        HISTORICAL_PAID_DIAGNOSTIC_BASE_CHECKPOINT
    )
    assert historical_charged_smoke["operator_results_sha256"] == (
        HISTORICAL_PAID_DIAGNOSTIC_OPERATOR_RESULTS_SHA256
    )
    assert historical_charged_smoke["operator_results_bytes"] == 54_081
    assert historical_charged_smoke["operator_results_lines"] == 979
    assert historical_charged_smoke["authenticated_metadata_egress"] is True
    assert historical_charged_smoke["provider_completions"] == 1
    assert historical_charged_smoke["model_completion_requests"] == 1
    assert historical_charged_smoke["reserved_usd"] == "0.0547272"
    assert historical_charged_smoke["operator_reported_campaign_spend_usd"] == "0.01680888"
    assert historical_charged_smoke["accounted_cost_usd"] == "0.01680888"
    assert historical_charged_smoke["ledger_entry_status"] == "reconciled"
    assert historical_charged_smoke["operator_reported_campaign_ledger_empty"] is False
    assert historical_charged_smoke["bundle_published"] is False
    assert historical_charged_smoke["offline_verifier_run"] is False
    assert historical_charged_smoke["failure"] == (
        "model returned invalid structured data (SCHEMA_VALIDATION_FAILED)"
    )
    assert historical_charged_smoke["failure_phase"] == (
        "STRICT_STRUCTURED_OUTPUT_SCHEMA_VALIDATION"
    )
    assert historical_charged_smoke["failure_cause"] == (
        "SELECTED_CANDIDATE_ROUTE_LACKS_NATIVE_STRUCTURED_OUTPUTS"
    )
    assert historical_charged_smoke["adjacency_status"] == (
        "UNPROVEN_NO_FRESH_IMMEDIATE_POST_B413_STEP_A_RESULT_RECORDED"
    )
    assert historical_charged_smoke["authority"] is False
    historical_paid_smoke_9 = exact_status["historical_paid_smoke_attempt_9"]
    assert historical_paid_smoke_9["checkpoint_commit"] == AUTHRUNNER_IDENTITY_DIAGNOSTIC_CHECKPOINT
    assert historical_paid_smoke_9["operator_results_sha256"] == (
        "efab7ac219c7a4bea4c2cd513f0d3455fff021483d28af1d958b6dd0eb59413d"
    )
    assert historical_paid_smoke_9["operator_results_bytes"] == 95_945
    assert historical_paid_smoke_9["operator_results_lines"] == 1_728
    assert historical_paid_smoke_9["composition"] is None
    assert historical_paid_smoke_9["smoke_run_index"] == 9
    assert (
        "GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING"
        in (historical_paid_smoke_9["failure"])
    )
    assert historical_paid_smoke_9["failure_phase"] == ("GENERATION_METADATA_IDENTITY_BINDING")
    assert historical_paid_smoke_9["provisional_identity_strength"] == (
        "CANONICAL_MODEL_AND_ENDPOINT_BOUND"
    )
    assert historical_paid_smoke_9["final_identity_strength"] == "UNBOUND"
    assert historical_paid_smoke_9["identity_binding_status"] == "generation_metadata_unbound"
    assert historical_paid_smoke_9["candidate_transport_reached"] is True
    assert historical_paid_smoke_9["per_index_cost_mapping_available"] is False
    assert historical_paid_smoke_9["ledger_entry_status"] == "reconciled"
    assert historical_paid_smoke_9["ledger_entry_count"] == 9
    assert historical_paid_smoke_9["ledger_used_usd"] == "0.10457436"
    assert historical_paid_smoke_9["ledger_reserved_usd"] == "0"
    assert historical_paid_smoke_9["ledger_remaining_usd"] == "249.89542564"
    assert historical_paid_smoke_9["ledger_entry_released_or_reusable"] is False
    assert historical_paid_smoke_9["bundle_published"] is False
    assert historical_paid_smoke_9["authority"] is False
    latest_paid_smoke = exact_status["historical_index_10_paid_smoke_group"]
    assert latest_paid_smoke["operator_results_sha256"] == (
        PRE_RECEIPT_COMPOSITE_LIVE_OPERATOR_RESULTS_SHA256
    )
    assert latest_paid_smoke["reported_run_indexes"] == [10]
    assert latest_paid_smoke["per_run_cost_mapping_available"] is False
    assert latest_paid_smoke["run_status"] == "reconciled"
    assert latest_paid_smoke["usage_diagnostics"] == "NONE"
    assert latest_paid_smoke["exceptional_smoke_diagnostic_code_count"] == 0
    assert latest_paid_smoke["generic_creditability_proven"] is False
    assert latest_paid_smoke["candidate_completion_receipt_cutoff_reached"] is True
    assert latest_paid_smoke["judge_metadata_receipt_cutoff_live_proven"] is False
    assert latest_paid_smoke["candidate_cutoff_precedes_generation_metadata_get"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_usage_ledger_replacement"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_origin_marking"] is True
    assert latest_paid_smoke["candidate_cutoff_precedes_generation_verification_capability"] is True
    assert latest_paid_smoke["ledger_entry_count"] == 13
    assert latest_paid_smoke["ledger_total_usd"] == "0.133173"
    assert latest_paid_smoke["ledger_reserved_usd"] is None
    assert latest_paid_smoke["ledger_remaining_usd"] is None
    assert latest_paid_smoke["bundle_published"] is False
    assert latest_paid_smoke["next_unused_run_index"] == 14
    assert latest_paid_smoke["authority"] is False
    historical_aggregate_route = exact_status[
        "historical_aggregate_live_route_preflight_mismatch_event"
    ]
    assert historical_aggregate_route["scope"] == (
        "HISTORICAL_9F5C94D_R6_R6_R2_MISMATCH_EVENT_NOT_CURRENT_ROUTE_FRESHNESS_OR_COMMAND"
    )
    assert historical_aggregate_route["checkpoint_commit"] == (
        "9f5c94d97b3d79d51c10e250b99244591461e959"
    )
    assert "aggregate_live_route_preflight" not in exact_status
    historical_live_route = exact_status["historical_r6_r6_r2_live_route_preflight"]
    assert historical_live_route["operator_results_sha256"] == (
        HISTORICAL_R6_R6_R2_OPERATOR_RESULTS_SHA256
    )
    assert historical_live_route["composition"] == "r6/r6/r2"
    assert historical_live_route["all_three_routes_validated"] is True
    latest_exact_gate = exact_status["historical_r7_live_route_gate"]
    assert latest_exact_gate["operator_results_sha256"] == HISTORICAL_R7_OPERATOR_RESULTS_SHA256
    assert latest_exact_gate["composition"] == "r7/r7/r7"
    assert latest_exact_gate["status"] == (
        "FAILED_SAFE_PRIMARY_REASONING_PROFILE_INCOMPATIBLE_BEFORE_PAID_TRANSPORT"
    )
    assert latest_exact_gate["provider_completions"] == 0
    assert latest_exact_gate["incremental_spend_usd"] == "0"
    assert latest_exact_gate["authority"] is False
    latest_r8_gate = exact_status["historical_r8_completion_capacity_gate"]
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
    historical_r8_gate = smoke_status["historical_r8_r8_r8_live_route_gate"]
    assert historical_r8_gate["operator_results_sha256"] == (
        HISTORICAL_R8_GATE_OPERATOR_RESULTS_SHA256
    )
    assert historical_r8_gate["operator_results_bytes"] == 71_771
    assert historical_r8_gate["operator_results_lines"] == 1_276
    assert historical_r8_gate["composition"] == "r8/r8/r8"
    assert historical_r8_gate["replay_endpoint_tag"] == "modal/mxfp4"
    assert historical_r8_gate["replay_frozen_sha256"] == (
        "75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8"
    )
    assert historical_r8_gate["logical_metadata_gets"] == 15
    assert historical_r8_gate["maximum_metadata_provider_attempts"] == 30
    assert historical_r8_gate["provider_completions"] == 0
    assert historical_r8_gate["incremental_spend_usd"] == "0"
    assert historical_r8_gate["output_published"] is False
    assert historical_r8_gate["bundle_published"] is False
    assert historical_r8_gate["authority"] is False
    historical_r9_sequence = smoke_status["historical_r9_r8_r8_smoke_sequence"]
    assert historical_r9_sequence["operator_results_sha256"] == (
        "302679f3e8e9281cdf9e0ec3d6d1d566d172cb54b389fbac607180d1f0911940"
    )
    assert historical_r9_sequence["operator_results_bytes"] == 74_562
    assert historical_r9_sequence["operator_results_lines"] == 1_330
    assert historical_r9_sequence["candidate_registry"] == "candidate-registry-r9.json"
    assert historical_r9_sequence["candidate_frozen_sha256"] == (
        "cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad"
    )
    assert historical_r9_sequence["composition"] == "r9/r8/r8"
    assert historical_r9_sequence["logical_metadata_gets"] == 15
    assert historical_r9_sequence["paid_smoke_status"] == (
        "FAILED_SAFE_BEFORE_PROVIDER_COMPLETION_REQUEST_ID_ALREADY_RECORDED"
    )
    assert historical_r9_sequence["provider_completions_during_paid_attempt"] == 0
    assert historical_r9_sequence["incremental_spend_usd"] == "0"
    assert historical_r9_sequence["live_ledger_entry_count"] == 1
    assert historical_r9_sequence["existing_entry_released_or_superseded"] is False
    assert historical_r9_sequence["bundle_published"] is False
    assert historical_r9_sequence["authority"] is False
    assert not any(key.startswith("latest_") for key in smoke_status)
    assert {key for key in smoke_status if key.startswith("last_reconciled_")} == {
        "last_reconciled_operator_results_sha256",
        "last_reconciled_operator_results_bytes",
        "last_reconciled_operator_results_lines",
        "last_reconciled_operator_results_status",
        "last_reconciled_complete_smoke_offline_replay",
        "last_reconciled_offline_verifier_status",
        "last_reconciled_offline_verifier_result_independently_authenticated_by_codex",
    }
    assert not any(key.startswith("latest_") for key in exact_status)
    assert exact_status["historical_safety_withdrawal_checkpoint"] == (
        "ca63b924f244cc9bcee2d2405d20b000ce0bb9d6"
    )
    assert "current_safety_withdrawal_checkpoint" not in exact_status
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
    assert "The selected endpoint's `provider_name` must be unique" in model_selection
    assert "Duplicate names among unrelated, unselected endpoints" in normalized_model_selection
    assert "do not make the selected identity ambiguous" in normalized_model_selection
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
    assert operator_results.strip()
    assert "cause was initially `INCONCLUSIVE`" in normalized_model_selection
    assert "naive, advisory, and nonauthorizing analysis" in normalized_model_selection
    assert "944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19" in (model_selection)
    assert "b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d" in (model_selection)
    assert "0.21890352" in model_selection
    assert "33,621-byte operator record" in normalized_model_selection
    assert "35,771-byte operator record" in normalized_model_selection
    assert "withdrawn before execution" in normalized_model_selection
    assert "f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57" in (model_selection)
    assert "3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436" in (model_selection)
    assert "5.27438208" in model_selection
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
    assert "full current pre-transport metadata path" not in normalized_model_selection
    assert (
        "then-current r6/r6/r2 pre-transport metadata path at that historical boundary"
        in normalized_model_selection
    )
    assert "origin/agent/v3-wip-checkpoint" in model_selection
    assert "input_cache_read" in model_selection
    assert "provider.max_price.prompt" in model_selection
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
