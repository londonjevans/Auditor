from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
OBJECTIVE_BYTES = 2_892
OBJECTIVE_LOGICAL_LINES = 24
OBJECTIVE_GIT_ATTRIBUTES = f"{OBJECTIVE_RELATIVE_PATH} -text"


def test_product_objective_is_exact_regular_repository_file() -> None:
    objective = ROOT / OBJECTIVE_RELATIVE_PATH
    metadata = objective.lstat()

    assert not stat.S_ISLNK(metadata.st_mode)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1

    content = objective.read_bytes()
    assert len(content) == OBJECTIVE_BYTES
    assert len(content.splitlines()) == OBJECTIVE_LOGICAL_LINES
    assert hashlib.sha256(content).hexdigest() == OBJECTIVE_SHA256

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert OBJECTIVE_GIT_ATTRIBUTES in attributes


def test_product_objective_authorities_bind_exact_path_and_digest() -> None:
    traceability = json.loads(
        (ROOT / "docs/remediation/v3/review_traceability.json").read_text(encoding="utf-8")
    )
    queue_header = (
        (ROOT / "docs/remediation/v3/work_queue.md")
        .read_text(encoding="utf-8")
        .split("Statuses:", maxsplit=1)[0]
    )
    worklog_header = (
        (ROOT / "docs/remediation/v3/worklog.md")
        .read_text(encoding="utf-8")
        .split("AUTORUN_STATUS:", maxsplit=1)[0]
    )

    assert traceability["objective_path"] == OBJECTIVE_RELATIVE_PATH
    assert traceability["objective_sha256"] == OBJECTIVE_SHA256
    for header in (queue_header, worklog_header):
        assert f"`{OBJECTIVE_RELATIVE_PATH}`" in header
        assert f"`{OBJECTIVE_SHA256}`" in header


def test_product_objective_records_explicit_supersession_and_integrity_backstops() -> None:
    objective = (ROOT / OBJECTIVE_RELATIVE_PATH).read_text(encoding="utf-8")
    traceability = json.loads(
        (ROOT / "docs/remediation/v3/review_traceability.json").read_text(encoding="utf-8")
    )
    runtime_status = json.loads(
        (ROOT / "docs/remediation/v3/runtime_status.json").read_text(encoding="utf-8")
    )
    supersession = traceability["objective_supersession"]

    assert supersession == {
        "prior_path": OBJECTIVE_RELATIVE_PATH,
        "prior_sha256": "f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43",
        "prior_git_blob": "360944d9a44cadfbb7134b23175aa04749994be6",
        "prior_introduced_commit": "517559e5c9526f78e516374ebc194933d01eac7f",
        "successor_path": OBJECTIVE_RELATIVE_PATH,
        "successor_sha256": OBJECTIVE_SHA256,
        "authorized_at": "2026-08-17T20:06:41Z",
        "decision": "EXPLICIT_OPERATOR_TARGET_CHANGE",
    }
    assert runtime_status["objective_path"] == OBJECTIVE_RELATIVE_PATH
    assert runtime_status["objective_sha256"] == OBJECTIVE_SHA256
    assert runtime_status["objective_supersession"] == supersession
    for required_text in (
        "hash alone is never enough",
        "External frozen ground-truth",
        "Cross-lineage independence",
        "append-only transparency log",
        "same-root judgement voids it",
        "real, non-model-generated corpus ground-truth",
    ):
        assert required_text in objective


def test_current_completion_authority_has_no_legacy_human_gate() -> None:
    queue = (ROOT / "docs/remediation/v3/work_queue.md").read_text(encoding="utf-8")
    traceability = json.loads(
        (ROOT / "docs/remediation/v3/review_traceability.json").read_text(encoding="utf-8")
    )
    runtime_status = json.loads(
        (ROOT / "docs/remediation/v3/runtime_status.json").read_text(encoding="utf-8")
    )

    autonomy = queue.split("## V3-AUTONOMY-001", maxsplit=1)[1].split(
        "## Historical 46-step execution order", maxsplit=1
    )[0]
    normalized_autonomy = " ".join(autonomy.split())
    assert "Phase 0 has no dependency and must not wait" in normalized_autonomy
    assert "V3-AUTHLINEAGE-PUBLIC-001" in normalized_autonomy
    assert "The legacy signed `V3-LINEAGE-001` path is objective-out-of-scope" in (
        normalized_autonomy
    )
    assert "Phase 0 completed at `d0402d1c68f0f82d9ee4f8757f7967abda372ac6`" in (
        normalized_autonomy
    )
    assert "Phase 1 is complete nonauthorizing at local checkpoint" in normalized_autonomy
    assert "`084add8778ef36a2e4c86fdbdea4082eb3a1b332`" in normalized_autonomy
    assert "exact 28-role managed declaration" in normalized_autonomy
    assert "25 external roles unresolved" in normalized_autonomy
    assert "Phase 2's typed idempotent provisioning-state/refusal contract stays paused" in (
        normalized_autonomy
    )
    assert "`runtime_authority=false`" in normalized_autonomy
    assert "`managed_run_ready=false`" in normalized_autonomy

    requirements = {item["id"]: item for item in traceability["requirements"]}
    autonomy_evidence = " ".join(requirements["U"]["evidence"])
    consensus_evidence = {
        requirement_id: next(
            evidence
            for evidence in reversed(requirements[requirement_id]["evidence"])
            if "V3-CONSENSUS-001" in evidence
        )
        for requirement_id in ("A", "N", "U")
    }
    assert requirements["A"]["status"] == "PARTIAL"
    assert requirements["N"]["status"] == "PARTIAL"
    assert requirements["U"]["status"] == "IN_PROGRESS"
    for requirement_id in ("A", "N", "U"):
        assert "V3-CONSENSUS-001" in consensus_evidence[requirement_id]
    assert "one-verifier/two-falsifier quorum" in consensus_evidence["A"]
    assert "detached replay" in consensus_evidence["A"]
    assert "nonconfirming" in consensus_evidence["A"]
    assert "COMPLETE" in consensus_evidence["N"]
    assert "provider-free" in consensus_evidence["N"]
    assert "nonauthorizing" in consensus_evidence["N"]
    assert "one verifier and two lineage-distinct falsifiers" in consensus_evidence["N"]
    assert "all dissent" in consensus_evidence["N"]
    assert "Model agreement alone is nonconfirming" in consensus_evidence["N"]
    assert "no REAL provider run" in consensus_evidence["N"]
    assert "provider-free exact three-review quorum" in consensus_evidence["U"]
    assert "detached terminal-replay" in consensus_evidence["U"]
    assert "does not alter retry configuration" in consensus_evidence["U"]
    assert (
        "grants no provider, campaign, audit, runtime, qualification, or release authority"
        in (consensus_evidence["U"])
    )
    assert "Phase 1 is COMPLETE_NONAUTHORIZING" in autonomy_evidence
    assert "084add8778ef36a2e4c86fdbdea4082eb3a1b332" in autonomy_evidence
    assert "not pushed or remote-resolved" in autonomy_evidence
    assert "owns exactly 18 Phase-1 paths" in autonomy_evidence
    assert "excludes operator_results" in autonomy_evidence
    assert "827b3fb3153366efdd4f59ac30b439612c26523675d134cf502d6d36b3094fec" in (autonomy_evidence)
    assert "1cf5af44108c390eebd88f02b88cf0b8ae79c48a99c8a2f6b400400de3e14cda" in (autonomy_evidence)
    assert "4af6458862d94af02d77db5f25ff9bdb24ced56c665d2a7402111af795138e99" in (autonomy_evidence)
    assert "6fdfd55652cb8776263ef969f168b34ffd5c557aece263cd70a4b7b545888913" in (autonomy_evidence)
    assert "3667 unique completion inputs / 3670 occurrences" in autonomy_evidence
    assert "3624 gate sources" in autonomy_evidence
    assert "e61b7d7d168488bea8f27f40b31c4db4a0bf8386" in autonomy_evidence
    assert "ea85af3849db30c9832624c675594541a698ab06" in autonomy_evidence
    assert "dcd9ab2be15f4a0416372c110734b5079af1efe2" in autonomy_evidence
    assert "d738f2760da047d15d4e53f87d6e0aeaf13d442a" in autonomy_evidence
    assert "721d17a4ff08cc52ccdf0aa92ed04258e4137807" in autonomy_evidence
    assert "425502c5cbc173578053423d946ef24843f26285" in autonomy_evidence
    assert "108 evidence/journal/promotion" in autonomy_evidence
    assert "63 model-coverage" in autonomy_evidence
    assert "244 assurance" in autonomy_evidence
    assert "105 scheduler-journal" in autonomy_evidence
    assert "2 exact direct-and-recursive live synthetic" in autonomy_evidence
    assert "1 provider-free MOCK recursive integration" in autonomy_evidence
    assert "1 specialist compatibility" in autonomy_evidence
    assert "58 scheduler-model" in autonomy_evidence
    assert "9 scheduler-runtime" in autonomy_evidence
    assert "57 schema/inventory" in autonomy_evidence
    assert "4 focused original PLAN display-name regression" in autonomy_evidence
    assert "full-tree live promotion custody" in autonomy_evidence
    assert "all five live usage/context" in autonomy_evidence
    assert "one bridge and three leaves" in autonomy_evidence
    assert "universal direct and recursive parent plus child/leaf" in autonomy_evidence
    assert "Synthetic REAL attestations" in autonomy_evidence
    assert "not provider execution" in autonomy_evidence
    assert "independent no-blocker/HIGH review" in autonomy_evidence
    assert "repository-wide suite remains INCOMPLETE, not a pass" in autonomy_evidence
    assert "VALID / NONCREDITING / NONAUTHORIZING" in autonomy_evidence
    assert "without rerun or new spend" in autonomy_evidence
    assert "25-entry ledger / 0.396223 USD" in autonomy_evidence
    assert "next unused index is not stated" in autonomy_evidence
    assert "not independently authenticated by Codex" in autonomy_evidence
    assert "No current AUTHRUNNER/operator command" in autonomy_evidence
    assert "pins three package resources" in autonomy_evidence
    assert "leaves 25 external roles unresolved" in autonomy_evidence
    assert "paused V3-AUTONOMY-001" in requirements["U"]["remaining_proof"]
    assert "V3-RUNTIMEADMIT-001" in requirements["U"]["remaining_proof"]
    assert "replacement candidate" in requirements["U"]["remaining_proof"]
    assert "unbound generation identity" in requirements["U"]["remaining_proof"]
    assert "V3-RETRYCONT-001" in requirements["U"]["remaining_proof"]
    assert "provider-backed retry" in requirements["U"]["remaining_proof"]
    assert "V3-CALIBRATE-001" in requirements["U"]["remaining_proof"]
    assert "V3-CONSENSUS-001" in requirements["U"]["remaining_proof"]
    assert "COMPLETE" in requirements["U"]["remaining_proof"]
    assert "V3-CONSENSUS-001" in requirements["N"]["remaining_proof"]
    assert "Checkpoint the completed" not in requirements["U"]["remaining_proof"]
    assert runtime_status["candidate_commit"] == "4f666d05c79e550af4f5fc646c5e6ffabb60dcf0"
    assert runtime_status["candidate_commit_parent"] == ("9a902192cae14bb14144094b3a3b3bf6dafed9a9")
    assert runtime_status["current_ticket"] == "UNSELECTED"
    assert runtime_status["last_completed_ticket"] == "V3-SCHEMARETRY-001"
    assert runtime_status["operator_results_current_worktree_required_for_ticket"] is False
    last_completed_work = runtime_status["last_completed_provider_free_work"]
    assert last_completed_work["ticket"] == "V3-SCHEMARETRY-001"
    assert "COMPLETE_PROVIDER_FREE_NONAUTHORIZING" in last_completed_work["status"]
    assert (
        "V3_REVOKERECON_001_NEXT_DEPENDENCY_READY_QUEUED_NOT_SELECTED"
        in (last_completed_work["next_slice"])
    )
    assert "V3_MULTI_AUDIT_001_REMAINS_QUEUED" in last_completed_work["next_slice"]
    assert "V3_SINGLE_AUDIT_001" in last_completed_work["next_slice"]
    consensus = runtime_status["consensus_provider_free_adjudication"]
    assert consensus["ticket"] == "V3-CONSENSUS-001"
    assert consensus["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert consensus["reviewer_roles"] == ["VERIFIER", "FALSIFIER_1", "FALSIFIER_2"]
    assert consensus["single_reviewer_can_suppress_candidate_group"] is False
    assert consensus["model_agreement_receives_confirmation_credit"] is False
    assert consensus["all_dissent_retained"] is True
    assert consensus["complete_and_partial_terminal_replay_bound"] is True
    assert consensus["retry_behavior_changed"] is False
    learning = runtime_status["learning_provider_free_capture"]
    assert learning["ticket"] == "V3-LEARNING-001"
    assert learning["status"].startswith("PARTIAL_PHASE_1_COMPLETE_PROVIDER_FREE")
    assert learning["manifest_bound_and_deterministically_rebuilt"] is True
    assert learning["phase_2_application_enabled"] is False
    assert learning["retry_behavior_changed"] is False
    assert learning["retry_configuration_changed"] is False
    assert consensus["retry_configuration_changed"] is False
    assert consensus["successor_ticket_selected"] is False
    current_inventory = runtime_status["autonomy_phase_zero_inventory"]
    assert current_inventory["current_reconciliation_commit"] == (
        "f8960d92569cb9d8865ada9284981458699e4dab"
    )
    assert current_inventory["current_reconciliation_commit_pushed"] is False
    assert current_inventory["current_reconciliation_commit_remote_resolved"] is False
    assert current_inventory["current_reconciliation_uncommitted_worktree"] is False
    assert runtime_status["candidate_commit_pushed"] is True
    assert runtime_status["candidate_commit_remote_resolved"] is True
    assert "V3-LINEAGE-001" not in requirements["L"]["tickets"]
    assert "V3-AUTHLINEAGE-RECEIPT-001" not in requirements["L"]["tickets"]
    assert "V3-PLANCONSTRAINTS-001" in requirements["L"]["tickets"]
    assert "V3-RUNTIMEADMIT-001" in requirements["L"]["tickets"]
    assert "V3-HUMANCMP-001" not in requirements["R"]["tickets"]
    assert (
        "The optional human-comparison tier is not required"
        in (requirements["R"]["remaining_proof"])
    )
    assert "OBJECTIVE_OUT_OF_SCOPE" in runtime_status["blocked_tickets"]["V3-LINEAGE-001"]
    calibration_block = runtime_status["blocked_tickets"]["V3-CALIBRATE-001"]
    assert "V3-CALIBRATE-001 remains BLOCKED_TECHNICAL" in calibration_block
    assert "calibrated P2 plus successor C2" in calibration_block
    assert "FULL admission for one launch" in calibration_block
    assert "DeepSeek candidate is non-runnable" in calibration_block
    assert "57 entries / 0.68118684 USD" in calibration_block
    assert "completed real audits remain zero" in calibration_block
    assert "No current command or run index is authorized or inferred" in calibration_block

    def ticket(ticket_id: str) -> str:
        section = queue.split(f"## {ticket_id}", maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
        return " ".join(section.split())

    qualify = ticket("V3-QUALIFY-001")
    assert "V3-AUTHLINEAGE-PUBLIC-001" in qualify
    assert "V3-AUTHRUNNER-001" in qualify
    assert "legacy signed `V3-LINEAGE-001` path" in qualify
    assert "not qualification blockers" in qualify

    benchmark = ticket("V3-BENCHMARK-001")
    assert "No commissioned human baseline or human adjudicator is required" in benchmark
    assert "historical human-relative Tier 1/2 protocol remains an optional" in benchmark

    release = ticket("V3-RELEASE-001")
    assert "An optional blind human comparison is not a release prerequisite" in release

    model_refresh = ticket("V3-MODELREFRESH-001")
    assert "The legacy signed `V3-LINEAGE-001` path is not a current dependency" in model_refresh

    time_split = ticket("V3-TIMESPLIT-001")
    assert "private holdout optional" in time_split
    assert "objective-out-of-scope and not required for completion" in time_split

    policy = ticket("V3-POLICYELIG-001")
    assert "customer-facing commercial/legal determination is `OBJECTIVE_OUT_OF_SCOPE`" in policy

    human_comparison = ticket("V3-HUMANCMP-001")
    assert "**Frozen-objective disposition:** `OBJECTIVE_OUT_OF_SCOPE`" in human_comparison


def test_historical_execution_order_cannot_claim_complete_queue_authority() -> None:
    queue = (ROOT / "docs/remediation/v3/work_queue.md").read_text(encoding="utf-8")
    ticket_id_list = re.findall(r"^## (V3-[A-Z0-9-]+)\s", queue, flags=re.MULTILINE)
    ticket_ids = set(ticket_id_list)
    historical = queue.split("## Historical 46-step execution order", maxsplit=1)[1]
    historical_id_list = re.findall(r"^\d+\. `?(V3-[A-Z0-9-]+)", historical, flags=re.MULTILINE)
    historical_ids = set(historical_id_list)

    assert len(ticket_id_list) == len(ticket_ids) == 73
    assert len(historical_id_list) == len(historical_ids) == 46
    assert ticket_ids - historical_ids == {
        "V3-AUTHLINEAGE-001",
        "V3-AUTHLINEAGE-PUBLIC-001",
        "V3-AUTHLINEAGE-RECEIPT-001",
        "V3-AUTHRUNNER-001",
        "V3-AUTHSEAL-001",
        "V3-AUTHVERDICT-001",
        "V3-BASELINE-001",
        "V3-BENCHSCORE-001",
        "V3-EFFORT-001",
        "V3-EXECORIGIN-001",
        "V3-FLOOR-001",
        "V3-FORKDIFF-001",
        "V3-IDENTITY-001",
        "V3-OBJECTIVE-002",
        "V3-OMISSION-001",
        "V3-OUTPUT-001",
        "V3-PLANCONSTRAINTS-001",
        "V3-PRIVACY-001",
        "V3-RETRY-001",
        "V3-RETRYCONT-001",
        "V3-SCHEMARETRY-001",
        "V3-RUNTIMEADMIT-001",
        "V3-SHARD-001",
        "V3-SMOKE-001",
        "V3-TESTQUALITY-001",
        "V3-TOKENS-001",
        "V3-TOOLDIAG-001",
    }
    assert "not current completion authority" in queue
    assert "must not be used as completion authority" in " ".join(historical.split())
