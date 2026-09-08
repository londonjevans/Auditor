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
CURRENT_OPERATOR_RESULTS_SHA256 = "215ea0f2f312b9674fb51285f6fdf758b166a0a998e2d2d621ac2da42f9a5f19"
CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT = "810ed7f32a9f39df104a6959e84b71c59966fb44"
HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_SHA256 = (
    "63bfe90b281a6382b921c63669e817e65220c81b629fc75a7cb35b3f3e429d5b"
)
HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_REPOSITORY_COMMIT = (
    "c8a46b9b53a77fcdd4241d8fadeecbebc876346d"
)
HISTORICAL_V1_V2_CLARIFICATION_OPERATOR_RESULTS_SHA256 = (
    "d502c61a2525a2bdcc2e7efd79b115821af60f604e715d7be7ccd51b02983ab1"
)
HISTORICAL_V1_V2_CLARIFICATION_OPERATOR_RESULTS_REPOSITORY_COMMIT = (
    "dd141cd580c2a012a6efdef26213d3a727b68041"
)
HISTORICAL_POST_PRICECAPCOMP_RETEST_SHA256 = (
    "2da419f85a9f6b2d087c1f75dca4247ef91d8fcf23005c719644de5830238b21"
)
HISTORICAL_PRICEKEYORDER_CORRECTION_SHA256 = (
    "e446f2c23f3de0b6dd1352b8f4874f8f95bbb26a128638b2356af29a0850f596"
)
PRE_PRICEKEYORDER_OPERATOR_RESULTS_SHA256 = (
    "f37f46d56a544af4bef6e2ef662dc9a8e5b23a20f3789391c56aae1bb6968e5f"
)
PRE_PRICEKEYORDER_OPERATOR_RESULTS_REPOSITORY_COMMIT = "af16299f1612df656dbc5f25592230c812a62dc4"
PREVIOUS_PRICELEXEME_OPERATOR_RESULTS_SHA256 = (
    "775b7ead8a6fae6ee37dce3cd74a129cd5b3e03858c4818baa9a001ab2f79979"
)
PREVIOUS_PRICELEXEME_OPERATOR_RESULTS_REPOSITORY_COMMIT = "04ba42b1f35080ac8eb427e7b5003979c9104317"
PREVIOUS_OPERATOR_RESULTS_SHA256 = (
    "5d3de38f022b23bf426990659a892fe33cd6bcd164bda4aef7699f92ab01854e"
)
PREVIOUS_OPERATOR_RESULTS_REPOSITORY_COMMIT = "339ca7c8b29f8abfd81e8707c61566950e2739e7"
HISTORICAL_AF7_OPERATOR_RESULTS_SHA256 = (
    "af7a24e382b4f164c7bec0948816e6e6eb3f40e898b2f0688641c4475b697f1b"
)
ACTIVE_SELECTION_PLAN_SHA256 = "14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3"
ACTIVE_SELECTION_PLAN_RAW_SHA256 = (
    "4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695"
)
ACTIVE_SELECTION_PLAN_PREDECESSOR_SHA256 = (
    "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
)
ACTIVE_SELECTION_UNAVAILABLE_STATE_SHA256 = (
    "98941c3253ffe0f1aa88890b1c8b7fafb7d6575ee28ca31cb7724f14e784ceae"
)
ACTIVE_SELECTION_MATCHED_REVOCATION_SET_SHA256 = (
    "7c0118f5c170d46e6d2478bf92cbd83d1be6b426bda36dd57a6fc93e2ffd18c5"
)
CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256 = (
    # Exact September-4 operator/PLANADOPT snapshot, not the later local generator.
    "ab26b52af8a99cde03302afe553c4ee73f0474d3ff9d1014d929379feea8a005"
)
CURRENT_CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256 = (
    # PLANANCESTRY v1.8 requires an active assignment and the exact retained V1 profile.
    "001fa29df0ccd261fd7b2513cc322109a362498df027597c97d245c898439ba3"
)


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


def test_active_candidate_selection_plan_is_exactly_unavailable_and_nonauthorizing() -> None:
    plan_path = ROOT / "config/models.selection-plan.json"
    plan_bytes = plan_path.read_bytes()
    plan = json.loads(plan_bytes)

    def canonical_sha256(value: object) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    assert hashlib.sha256(plan_bytes).hexdigest() == ACTIVE_SELECTION_PLAN_RAW_SHA256
    assert (
        json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8") == plan_bytes
    assert plan["schema_version"] == "1.7"
    assert plan["plan_sha256"] == ACTIVE_SELECTION_PLAN_SHA256
    assert plan["plan_sha256"] == canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    assert plan["predecessor_plan_sha256"] == ACTIVE_SELECTION_PLAN_PREDECESSOR_SHA256
    assert plan["authenticated_runner_selection"] is None

    unavailable = plan["authenticated_runner_unavailability"]
    assert unavailable["disposition"] == "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
    assert unavailable["price_cap_profile_decision"] == ("PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION")
    assert unavailable["state_sha256"] == ACTIVE_SELECTION_UNAVAILABLE_STATE_SHA256
    assert unavailable["state_sha256"] == canonical_sha256(
        {key: value for key, value in unavailable.items() if key != "state_sha256"}
    )
    assert unavailable["matched_revocation_set_sha256"] == (
        ACTIVE_SELECTION_MATCHED_REVOCATION_SET_SHA256
    )
    assert unavailable["matched_revocation_set_sha256"] == canonical_sha256(
        {
            "schema_version": "1.0",
            "artifact_kind": "MATCHED_CANDIDATE_SELECTION_REVOCATIONS",
            "revocation_entry_sha256s": unavailable["revocation_entry_sha256s"],
        }
    )
    assert unavailable["candidate_selection_authorized"] is False
    profile = unavailable["route_predicate_profile"]
    assert profile["schema_version"] == "1.0"
    assert profile["profile_sha256"] == (
        "00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82"
    )
    assert profile["price_cap_algorithm"] == "MMAUDIT_OPENROUTER_MAX_PRICE_CEILING_V1"
    assert "price_component_unit_envelopes" not in profile
    assert [
        (
            constraint["role"],
            constraint["exact_model_id"],
            constraint["provider_endpoint"],
            constraint["constraint_sha256"],
        )
        for constraint in unavailable["judge_route_constraints"]
    ] == [
        (
            "primary_judge",
            "z-ai/glm-5.2",
            "sail-research/fp8",
            "f0177706981e7cc78994b8fc6d1ed34e170b6ee637e88ad12d1d94976d0ed6ad",
        ),
        (
            "replay_judge",
            "moonshotai/kimi-k3",
            "modal/mxfp4",
            "ffc54dc13eea0d92c06a1c6f29e0ae679eac5328d05ae8899e8cd7899b1eb199",
        ),
        (
            "replay_judge",
            "moonshotai/kimi-k3",
            "phala",
            "2a820c3b85936bc24cc1b0d007415d39e8e8bfd3b4eacb072a321e904e8a5912",
        ),
    ]
    for authority_field in (
        "ranking_executed",
        "cached_ranking_payload_present",
        "provider_metadata_present",
        "discovery_evidence_present",
        "documentary_lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "qualification_authorized",
        "production_selection_authorized",
        "runner_authority_authorized",
        "benchmark_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "serialized_authority",
    ):
        assert plan[authority_field] is False
    assert (
        hashlib.sha256(
            (ROOT / "schemas/candidate_selection_plan.schema.json").read_bytes()
        ).hexdigest()
        == CURRENT_CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256
    )


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
    assert "Phase 2's bounded provider-free provisioning contract is now implemented locally" in (
        normalized_autonomy
    )
    assert "A strict self-contained receipt embeds the exact provisioning plan" in (
        normalized_autonomy
    )
    assert "this ticket remains `PARTIAL`" in normalized_autonomy
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
    assert HISTORICAL_AF7_OPERATOR_RESULTS_SHA256 in autonomy_evidence
    assert "No current AUTHRUNNER/operator command" in autonomy_evidence
    assert "pins three package resources" in autonomy_evidence
    assert "leaves 25 external roles unresolved" in autonomy_evidence
    assert (
        "terminal provider-free PARTIAL V3-AUTONOMY-001" in (requirements["U"]["remaining_proof"])
    )
    assert "installed/transitive toolchain roles" in requirements["U"]["remaining_proof"]
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
    assert requirements["K"]["tickets"] == ["V3-COVERAGE-001", "V3-TAXONOMY-001"]
    assert requirements["K"]["status"] == "COMPLETE"
    assert "19-item defensive corpus" in requirements["K"]["evidence"][-1]
    historical_pricelexeme_selection = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if "V3-RETRIEVAL-001 is COMPLETE; after that closure" in evidence
    )
    assert "V3-PRICELEXEME-001 is the sole current and critical-path ticket" in (
        historical_pricelexeme_selection
    )
    assert "implementation_started=false" in historical_pricelexeme_selection
    pricelexeme_evidence = next(
        evidence
        for evidence in reversed(requirements["U"]["evidence"])
        if "V3-PRICELEXEME-001 is PARTIAL, not complete" in evidence
    )
    assert PREVIOUS_OPERATOR_RESULTS_SHA256 in pricelexeme_evidence
    assert "166648 bytes / 2964 lines" in pricelexeme_evidence
    assert PREVIOUS_OPERATOR_RESULTS_REPOSITORY_COMMIT in pricelexeme_evidence
    assert "joined provider-free raw-HTTP" in pricelexeme_evidence
    assert "affected matrix now passes 795 tests with two warnings" in pricelexeme_evidence
    assert "focused custody matrix 24" in pricelexeme_evidence
    assert "schema/inventory closure 126" in pricelexeme_evidence
    assert "fresh current-byte live admissibility remains unproven" in (pricelexeme_evidence)
    historical_priceform_evidence = next(
        evidence
        for evidence in reversed(requirements["U"]["evidence"])
        if "V3-PRICEFORM-001 is COMPLETE" in evidence
    )
    assert PREVIOUS_OPERATOR_RESULTS_SHA256 in historical_priceform_evidence
    assert "166648 bytes / 2964 lines" in historical_priceform_evidence
    assert "V3-PRICEFORM-001 is COMPLETE" in historical_priceform_evidence
    assert "decision-only, provider-free, nonauthorizing policy closure" in (
        historical_priceform_evidence
    )
    assert "795 passed tests and two warnings" in historical_priceform_evidence
    assert "ordinary uncaptured numeric prices remain refused" in historical_priceform_evidence
    assert "registered captured lexemes retain canonical exact-string storage" in (
        historical_priceform_evidence
    )
    assert "cost reserve, spend, and reconcile arithmetic remains identical" in (
        historical_priceform_evidence
    )
    assert "last partial is V3-PRICELEXEME-001" in historical_priceform_evidence
    assert "V3-PRICELEXEME-001 remains PARTIAL" in historical_priceform_evidence
    historical_testquality_evidence = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith("At 2026-09-02T22:13:00Z, V3-TESTQUALITY-001")
    )
    assert PREVIOUS_OPERATOR_RESULTS_SHA256 in historical_testquality_evidence
    assert "166648 bytes / 2964 lines" in historical_testquality_evidence
    assert "V3-TESTQUALITY-001 remains PARTIAL, provider-free, and nonauthorizing" in (
        historical_testquality_evidence
    )
    assert "one-shot same-invocation campaign cleanup handoff closure" in (
        historical_testquality_evidence
    )
    assert "preserves the exact live MutationSuiteObservation" in historical_testquality_evidence
    assert "binds the exact plan, mutation specification, source" in historical_testquality_evidence
    assert "Observed campaign invalidation or replay synchronously cascades" in (
        historical_testquality_evidence
    )
    assert "not an independent campaign receipt" in historical_testquality_evidence
    assert "lack a shared revocation lease" in historical_testquality_evidence
    assert "Production campaign authority remains hard-disabled" in historical_testquality_evidence
    assert "current REAL mutation campaign receipt" in historical_testquality_evidence
    assert "portable same-UID disposal" in historical_testquality_evidence
    assert "REAL mutation run and kill artifact" in historical_testquality_evidence
    assert "Current ticket is UNSELECTED" in historical_testquality_evidence
    assert "last completed is V3-PRICEFORM-001" in historical_testquality_evidence
    assert "last partial is V3-TESTQUALITY-001" in historical_testquality_evidence
    assert "combined unfinished count is 39" in historical_testquality_evidence
    assert "no next local ticket is selected" in historical_testquality_evidence
    assert "no provider, operator command" in historical_testquality_evidence
    historical_shared_lease_selection = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith("At 2026-09-03T05:40:39Z, V3-PRICELEXEME-001")
    )
    assert "V3-PRICELEXEME-001 is recorded PARTIAL terminal" in (historical_shared_lease_selection)
    assert "755 affected, 87 focused price/endpoint, 220 refresh-runtime" in (
        historical_shared_lease_selection
    )
    assert "5 detachment, 1 localhost integration, and 93 governance" in (
        historical_shared_lease_selection
    )
    assert "Fresh current-byte live admissibility remains unproven" in (
        historical_shared_lease_selection
    )
    assert "requires separate authorization" in historical_shared_lease_selection
    assert "V3-TESTQUALITY-001 becomes current and critical-path IN_PROGRESS" in (
        historical_shared_lease_selection
    )
    assert "implementation has not started" in historical_shared_lease_selection
    assert "shared lease and race-safe live dependency authority remain false" in (
        historical_shared_lease_selection
    )
    assert "production campaign authority remains disabled" in historical_shared_lease_selection
    assert "combined unfinished count remains 39" in historical_shared_lease_selection
    assert "no provider, network, command, candidate, route, plan, campaign" in (
        historical_shared_lease_selection
    )
    current_testquality_evidence = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith("At 2026-09-03T07:06:29Z, V3-TESTQUALITY-001 returns to PARTIAL")
    )
    assert "provider-free, comparison-only, and nonauthorizing" in current_testquality_evidence
    assert "PID-bound domain serializes run, observation, campaign, and score" in (
        current_testquality_evidence
    )
    assert "revalidate exact local seals after dependency release" in current_testquality_evidence
    assert "seal-SHA-matched immutable schema snapshots" in current_testquality_evidence
    assert "authenticated plan_sha256 equals the canonical score plan" in (
        current_testquality_evidence
    )
    assert "exact live sources are revalidated at registration" in current_testquality_evidence
    assert "callbacks defer beyond the outer lease" in current_testquality_evidence
    assert "BaseException and partial paths exact-remove" in current_testquality_evidence
    assert "forks refuse before inherited locks" in current_testquality_evidence
    assert "clean across 599 files" in current_testquality_evidence
    assert "clean across 233 source files" in current_testquality_evidence
    assert "focused chain passes 166 tests in 4.33s" in current_testquality_evidence
    assert "adjacent unit matrix passes 135 in 19.41s" in current_testquality_evidence
    assert "one unavailable-isolation skip" in current_testquality_evidence
    assert "broader 265-case attempt" in current_testquality_evidence
    assert "168 passes and one skip at 547.50s" in current_testquality_evidence
    assert "no terminal or full-suite credit" in current_testquality_evidence
    for current_inventory_digest in (
        "a895900aa48c2af60485e4a1a98035036dca2c6003d65db7a8f3df97182c6c9c",
        "22f351a283e023768de673cff786922845a7d8b4d3e71c69d7159ebacd21524a",
        "75a5dfc94f47d5d7873c661b46899ffd6939d74fd6a8052e0c86f0a1718ea692",
        "4c48cc0b8c13ba716b776749fee86530ea8de00b74aa119565d7d6de82fe24f8",
    ):
        assert current_inventory_digest in current_testquality_evidence
    assert "counts 3940/3943/3891/49" in current_testquality_evidence
    assert "Same-interpreter reflection, asynchronous-exception micro-gaps" in (
        current_testquality_evidence
    )
    assert "post-linearization return boundary remain explicit" in current_testquality_evidence
    assert "Current and next ticket are unselected" in current_testquality_evidence
    assert "V3-PRICEFORM-001 remains last complete" in current_testquality_evidence
    assert "V3-TESTQUALITY-001 is last partial" in current_testquality_evidence
    assert "V3-PRICELEXEME-001 and V3-CANDROUTE-001 remain PARTIAL" in (
        current_testquality_evidence
    )
    assert "combined unfinished count remains 39" in current_testquality_evidence
    assert PREVIOUS_OPERATOR_RESULTS_SHA256 in current_testquality_evidence
    assert "166648 bytes / 2964 lines" in current_testquality_evidence
    assert "57-entry / 0.68118684 USD ledger remain unchanged" in (current_testquality_evidence)
    assert "all provider, network, command, candidate, route, plan, campaign" in (
        current_testquality_evidence
    )
    historical_price_shape_evidence = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith("At 2026-09-03T09:05:00Z, current operator record")
    )
    normalized_historical_price_shape_evidence = historical_price_shape_evidence.lower()
    assert PRE_PRICEKEYORDER_OPERATOR_RESULTS_SHA256 in historical_price_shape_evidence
    assert "173635 bytes / 3084 lines" in historical_price_shape_evidence
    assert PRE_PRICEKEYORDER_OPERATOR_RESULTS_REPOSITORY_COMMIT in historical_price_shape_evidence
    assert "every direct and nested billable price leaf" in (
        normalized_historical_price_shape_evidence
    )
    assert "exact decimal string" in normalized_historical_price_shape_evidence
    assert "structured pricing.overrides list" in normalized_historical_price_shape_evidence
    assert "not lexeme loss" in normalized_historical_price_shape_evidence
    assert "v3-pricelexeme-001 remains partial terminal" in (
        normalized_historical_price_shape_evidence
    )
    assert "defense-in-depth" in normalized_historical_price_shape_evidence
    assert "v3-priceoverrides-001 is queued and unselected" in (
        normalized_historical_price_shape_evidence
    )
    assert "input_cache_write='0'" in normalized_historical_price_shape_evidence
    assert "web_search='0.01'" in normalized_historical_price_shape_evidence
    assert "sole blocker and route admissibility remain unproven" in (
        normalized_historical_price_shape_evidence
    )
    assert "current and next tickets remain unselected" in (
        normalized_historical_price_shape_evidence
    )
    assert "v3-priceform-001 is last complete" in normalized_historical_price_shape_evidence
    assert "v3-pricelexeme-001 is last partial" in normalized_historical_price_shape_evidence
    assert "unfinished count is 40" in normalized_historical_price_shape_evidence
    assert "57-entry / 0.68118684 usd ledger" in normalized_historical_price_shape_evidence
    assert "codex issued no command" in normalized_historical_price_shape_evidence
    historical_pricecaptier_evidence = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith(
            "At 2026-09-03T11:27:12Z, V3-PRICECAPTIER-001 is PARTIAL provider-free"
        )
    )
    assert historical_pricecaptier_evidence.startswith(
        "At 2026-09-03T11:27:12Z, V3-PRICECAPTIER-001 is PARTIAL provider-free"
    )
    for historical_pricecaptier_proof in (
        "Exact Decimal schedule-wide maxima",
        "partial-tier inheritance",
        "later applicable tiers winning",
        "per-state cache dominance",
        "complete schedule/proof hash binding",
        "Provider cap, request-cost, reserve, spend, and reconciliation consume",
        "flat-route bytes remain unchanged",
        "PRICE_CAP_NOT_EXPRESSIBLE and PRICE_CAP_PROOF_UNAVAILABLE",
        "nested numeric override lexemes fail closed",
        "prompt 0.0000044 and completion 0.0000132",
        "input_cache_write='0' and web_search='0.01'",
        "refresh and live preflight remain flat-only",
        "primary xAI/preflight acceptance is unmet",
        "Validation passed 280 focused tests",
        "1251 affected tests with two warnings",
        "241 adversarial focused tests",
        "no integration pass credit",
        "Current and next tickets are unselected",
        "V3-PRICEOVERRIDES-001 is last complete",
        "V3-PRICECAPTIER-001 is last partial",
        "unfinished count remains 40",
        "every external or production authority remain unchanged",
        "granted no authority",
    ):
        assert historical_pricecaptier_proof in historical_pricecaptier_evidence
    current_modelrefresh_evidence = next(
        evidence
        for evidence in reversed(requirements["U"]["evidence"])
        if evidence.startswith(
            "At 2026-09-03T13:58:58Z, V3-MODELREFRESH-001 closes a tier-schedule continuation"
        )
    )
    assert current_modelrefresh_evidence.startswith(
        "At 2026-09-03T13:58:58Z, V3-MODELREFRESH-001 closes a tier-schedule continuation"
    )
    for current_modelrefresh_proof in (
        "Exact ordered schedules and conservative maxima",
        "durable route and attempt pricing evidence",
        "live preflight",
        "Equal-maximum threshold drift is detected",
        "unavailable, mismatched, or tampered schedules fail closed",
        "flat-route bytes remain unchanged",
        "Validation passed 245 core tests",
        "262 schema/route/endpoint tests",
        "471 independently reviewed affected tests",
        "2 composed custody tests",
        "1064 passes and two known warnings",
        "all five passed under direct /private/tmp custody",
        "15 refresh-pricing assurance",
        "9 scheduler runtime/recovery passes",
        "no terminal full-suite credit",
        "input_cache_write='0' and web_search='0.01'",
        "Current and next tickets are UNSELECTED",
        "V3-PRICEOVERRIDES-001 is last complete",
        "V3-MODELREFRESH-001 is last partial",
        "unfinished count remains 41",
    ):
        assert current_modelrefresh_proof in current_modelrefresh_evidence
    current_operator_correction = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith(
            "At 2026-09-03T14:37:03Z, exact operator correction "
            f"{HISTORICAL_PRICEKEYORDER_CORRECTION_SHA256}"
        )
    )
    assert current_operator_correction.startswith(
        "At 2026-09-03T14:37:03Z, exact operator correction "
        f"{HISTORICAL_PRICEKEYORDER_CORRECTION_SHA256}"
    )
    for correction_proof in (
        "retracts the earlier key-order root-cause claim",
        "120-permutation assay yields one pricing hash and one snapshot hash",
        "V3-PRICEKEYORDER-001 is WITHDRAWN_OPERATOR_ERROR",
        "must not be implemented",
        "PRICE_CAP_NOT_EXPRESSIBLE and PRICE_CAP_PROOF_UNAVAILABLE",
        "tier-schedule projection is correct",
        "combined unfinished count is 40",
    ):
        assert correction_proof in current_operator_correction
    historical_operator_retest = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith(
            "At 2026-09-03T20:53:27Z, exact operator record "
            f"{HISTORICAL_POST_PRICECAPCOMP_RETEST_SHA256}"
        )
    )
    for reconciliation_proof in (
        "active repository plan remains V1",
        "no private plan or profile bytes",
        "nor proves opt-in V2 was selected or exercised",
        "constrained discovery canonicalizes tier schedules and evaluates schedule-aware facts",
        "quoted flat-pricing refusal is refresh-only",
        "aggregate public failure pair is nondiagnostic",
        "V3-PRICECAPCOMP-001 remains COMPLETE",
    ):
        assert reconciliation_proof in historical_operator_retest
    historical_selector_reconciliation = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith(
            "At 2026-09-03T21:41:10Z, exact current operator record "
            f"{HISTORICAL_V1_V2_CLARIFICATION_OPERATOR_RESULTS_SHA256}"
        )
    )
    for reconciliation_proof in (
        "every earlier retest used a V1-derived sp-grokF.json plan",
        "supported default-off successor CLI",
        "exact V1 predecessor",
        "same-route V1-to-V2 upgrade",
        "every candidate, primary-judge, and replay-judge constraint",
        "validates the exact immediate transition",
        "Omission preserves pinned V1 bytes",
        "repeat upgrade, downgrade, drift, tamper, revocation, non-boolean input",
        "stateful predecessor substitution fail closed",
        "No successor artifact was emitted, selected, or inspected",
        "120 focused selector/CLI tests",
        "1328 affected tests with two known warnings",
        "79 release/autonomy/schema tests",
        "counts are 3941/3944/3892/49 with 337 completion parameters",
    ):
        assert reconciliation_proof in historical_selector_reconciliation
    latest_autonomy_reconciliation = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith(
            "At 2026-09-03T23:38:22Z, V3-AUTONOMY-001 closes only its bounded Phase-2"
        )
    )
    assert latest_autonomy_reconciliation.startswith(
        "At 2026-09-03T23:38:22Z, V3-AUTONOMY-001 closes only its bounded Phase-2 "
        "provisioning slice PARTIAL"
    )
    for reconciliation_proof in (
        "strict self-contained receipt",
        "source set before the final receipt name is linked",
        "durable marker-bound no-reset cost-ledger",
        "25 external-role inputs remain explicit refusals",
        "affected local matrix passed 287 tests",
        "release-schema/autonomy contract passed 65",
        HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_SHA256,
        HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_REPOSITORY_COMMIT,
        "private V2 plan 96cc5301",
        "Current and next tickets are UNSELECTED",
        "Every provider, spend-admission, execution, qualification, runtime, audit, completion, "
        "release, and other authority remains false",
    ):
        assert reconciliation_proof in latest_autonomy_reconciliation
    latest_pricecapcache_reconciliation = next(
        evidence
        for evidence in requirements["U"]["evidence"]
        if evidence.startswith("At 2026-09-04T01:48:46Z, V3-PRICECAPCACHE-001 closes PARTIAL")
    )
    for reconciliation_proof in (
        "prompt, completion, request, and image ceilings",
        "no request-bound cache-write or total-cost cap",
        "non-atomic",
        "provider-enforced dominance remains unmet",
        "rejects reserved V3 unconditionally",
        "emit no V3 plan",
        "preview schema 1.3 and pricing-attempt schema 1.2 are removed",
        "understating both prompt and cache-write units",
        "neutralized because V3 publication and transport are unreachable",
        "Current and next tickets are UNSELECTED",
        "unfinished count is 42",
        "all authority remains false",
    ):
        assert reconciliation_proof in latest_pricecapcache_reconciliation
    assert "V3-PRICEOVERRIDES-001" in requirements["L"]["tickets"]
    assert "V3-PRICECAPTIER-001" in requirements["L"]["tickets"]
    assert "V3-PRICECAPCACHE-001" in requirements["L"]["tickets"]
    current_operator_reconciliation = traceability["operator_evidence_reconciliation"]
    assert current_operator_reconciliation["current_operator_results_sha256"] == (
        CURRENT_OPERATOR_RESULTS_SHA256
    )
    assert current_operator_reconciliation["current_operator_results_bytes"] == 190_177
    assert current_operator_reconciliation["current_operator_results_lines"] == 3_377
    assert current_operator_reconciliation["current_latest_entry_timestamp"] == (
        "2026-09-04T03:39Z"
    )
    assert current_operator_reconciliation["current_operator_results_repository_commit"] == (
        CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT
    )
    assert current_operator_reconciliation["prior_operator_results_sha256"] == (
        HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_SHA256
    )
    assert current_operator_reconciliation["prior_operator_results_bytes"] == 187_993
    assert current_operator_reconciliation["prior_operator_results_lines"] == 3_335
    assert current_operator_reconciliation["prior_operator_results_latest_entry_timestamp"] == (
        "2026-09-03T22:31Z"
    )
    assert current_operator_reconciliation["prior_operator_results_repository_commit"] == (
        HISTORICAL_PRE_PLANADOPT_OPERATOR_RESULTS_REPOSITORY_COMMIT
    )
    current_evidence_scope = current_operator_reconciliation[
        "historical_requirement_evidence_scope"
    ]
    assert "CURRENT OPERATOR FACTS_ARE_EXACTLY_215EA0F2_AT_2026_09_04T03_39Z" in (
        current_evidence_scope
    )
    assert "PRIOR_63BFE90B" in current_evidence_scope
    assert "NO_SUPPORTED_AUTHENTICATED_ANCESTRY_TRANSITION_EXISTS_TODAY" in (current_evidence_scope)
    assert "FUTURE_SEPARATELY_SELECTED_BOUNDED_TICKET" in current_evidence_scope
    assert "REMOTE_RESOLVED_HEAD_810ED7F_ADDS_ONLY_OPERATOR_PLANADOPT_VERIFICATION" in (
        current_evidence_scope
    )
    for current_operator_true_field in (
        "operator_supplied",
        "current_operator_verified_active_schema_1_7_no_candidate",
        "current_operator_verified_revoked_active_pin_removed",
        "current_operator_verified_v1_profile_retained_and_v2_not_adopted",
        "current_operator_observed_authenticated_ancestry_transition_gate",
        "current_authenticated_ancestry_transition_deferred_to_future_bounded_ticket",
        "current_operator_should_stop_probing_ancestry_transition",
    ):
        assert current_operator_reconciliation[current_operator_true_field] is True
    assert current_operator_reconciliation["independently_authenticated_by_codex"] is False
    assert (
        current_operator_reconciliation[
            "current_supported_authenticated_ancestry_transition_exists"
        ]
        is False
    )
    assert (
        current_operator_reconciliation["current_active_plan_to_v2_supported_path_available"]
        is False
    )
    assert current_operator_reconciliation["current_global_ledger_entry_count"] == 57
    assert current_operator_reconciliation["current_global_ledger_spent_usd_exact"] == "0.68118684"
    assert current_operator_reconciliation["completed_real_audits"] == 0
    assert current_operator_reconciliation["current_operator_v1_v2_clarification_accepted"] is True
    assert (
        current_operator_reconciliation[
            "current_operator_reported_all_retests_used_v1_derived_plan"
        ]
        is False
    )
    assert current_operator_reconciliation["current_operator_reported_private_v2_plan_sha256"] == (
        "96cc5301111c7b60cf9b8235870d8051e2ece737c80dc5321662a1f6adfa3aea"
    )
    assert (
        current_operator_reconciliation[
            "current_operator_reported_private_v2_plan_exercised_metadata_only"
        ]
        is True
    )
    assert (
        current_operator_reconciliation[
            "current_operator_reported_private_v2_plan_selected_as_active_repository_plan"
        ]
        is False
    )
    assert (
        current_operator_reconciliation[
            "current_operator_reported_private_v2_plan_adopted_by_repository"
        ]
        is False
    )
    assert current_operator_reconciliation["current_autonomy_ticket_status"].startswith(
        "PARTIAL_TERMINAL_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert current_operator_reconciliation["current_autonomy_closure_timestamp"] == (
        "2026-09-03T23:38:22Z"
    )
    assert current_operator_reconciliation[
        "current_autonomy_affected_local_matrix_tests_passed"
    ] == (287)
    assert current_operator_reconciliation[
        "current_autonomy_affected_local_matrix_duration_seconds"
    ] == (13.3)
    assert current_operator_reconciliation[
        "current_autonomy_release_schema_and_inventory_duration_seconds"
    ] == (51.43)
    assert current_operator_reconciliation["current_autonomy_product_governance_tests_passed"] == 27
    assert current_operator_reconciliation["current_autonomy_ruff_format_files_checked"] == 588
    assert current_operator_reconciliation[
        "autonomy_closure_affected_local_matrix_duration_seconds"
    ] == (8.38)
    assert current_operator_reconciliation[
        "autonomy_closure_release_schema_and_inventory_duration_seconds"
    ] == (51.99)
    assert current_operator_reconciliation["autonomy_closure_ruff_format_files_checked"] == 604
    assert current_operator_reconciliation["current_pricecapcomp_ticket_status"] == (
        "COMPLETE_TERMINAL_PROVIDER_FREE_ZERO_WEB_SEARCH_REQUEST_UNIT_CUSTODY_AND_DEFAULT_OFF_"
        "V1_TO_V2_SUCCESSOR_SELECTOR_NONAUTHORIZING"
    )
    assert (
        current_operator_reconciliation[
            "current_pricecapcomp_focused_selector_and_cli_tests_passed"
        ]
        == 120
    )
    assert (
        current_operator_reconciliation["current_pricecapcomp_broad_affected_tests_passed"] == 1328
    )
    assert current_operator_reconciliation["current_pricecapcomp_broad_affected_test_warnings"] == 2
    assert (
        current_operator_reconciliation["current_pricecapcomp_release_autonomy_schema_tests_passed"]
        == 79
    )
    assert current_operator_reconciliation[
        "current_pricecapcomp_successor_plan_schema_versions"
    ] == [
        "1.5",
        "1.6",
    ]
    for selector_fact in (
        "current_pricecapcomp_successor_selector_default_off",
        "current_pricecapcomp_successor_selector_exact_v1_to_v2_only",
        "current_pricecapcomp_successor_selector_same_route_upgrade_supported",
        "current_pricecapcomp_successor_selector_rebuilds_shared_profile_and_every_role_constraint",
        "current_pricecapcomp_successor_selector_validates_exact_immediate_transition",
        "current_pricecapcomp_successor_selector_rejects_repeat_upgrade_downgrade_drift_tamper_revocation_nonboolean_and_stateful_substitution",
        "historical_pricecapcomp_active_v1_plan_unchanged_at_boundary",
        "current_pricecapcomp_input_cache_write_remains_uncapped",
    ):
        assert current_operator_reconciliation[selector_fact] is True
    assert (
        current_operator_reconciliation[
            "current_pricecapcomp_successor_artifact_emitted_selected_or_inspected"
        ]
        is False
    )
    assert current_operator_reconciliation["queued_successor_ticket"] is None
    assert current_operator_reconciliation["queued_successor_ticket_status"] == "NONE"
    assert current_operator_reconciliation["withdrawn_successor_ticket"] == "V3-PRICEKEYORDER-001"
    assert current_operator_reconciliation["withdrawn_successor_ticket_status"] == (
        "WITHDRAWN_OPERATOR_ERROR"
    )
    assert current_operator_reconciliation["combined_unfinished_ticket_count"] == 41
    assert current_operator_reconciliation["last_completed_ticket"] == "V3-PLANADOPT-001"
    assert current_operator_reconciliation["last_partial_ticket"] == "V3-PRICECAPCACHE-001"
    assert current_operator_reconciliation["critical_path_ticket"] == "UNSELECTED"
    assert current_operator_reconciliation["next_safe_local_ticket"] is None
    assert current_operator_reconciliation["current_candidate_selection_plan_schema_version"] == (
        "1.7"
    )
    assert current_operator_reconciliation["current_candidate_selection_plan_sha256"] == (
        ACTIVE_SELECTION_PLAN_SHA256
    )
    assert current_operator_reconciliation["current_candidate_selection_plan_raw_sha256"] == (
        ACTIVE_SELECTION_PLAN_RAW_SHA256
    )
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_predecessor_sha256"
    ] == (ACTIVE_SELECTION_PLAN_PREDECESSOR_SHA256)
    assert (
        current_operator_reconciliation["current_candidate_selection_plan_has_active_selection"]
        is False
    )
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_unavailable_state_sha256"
    ] == (ACTIVE_SELECTION_UNAVAILABLE_STATE_SHA256)
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_matched_revocation_set_sha256"
    ] == (ACTIVE_SELECTION_MATCHED_REVOCATION_SET_SHA256)
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_unavailable_disposition"
    ] == ("NO_ACTIVE_CANDIDATE_AFTER_REVOCATION")
    assert current_operator_reconciliation["current_candidate_selection_plan_profile_decision"] == (
        "PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION"
    )
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_pins_revoked_route"
    ] is (False)
    assert current_operator_reconciliation[
        "current_candidate_selection_plan_schema_raw_sha256"
    ] == (CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256)
    assert current_operator_reconciliation["current_pricecapcache_closure_timestamp"] == (
        "2026-09-04T01:48:46Z"
    )
    assert current_operator_reconciliation[
        "current_pricecapcache_provider_max_price_supported_dimensions"
    ] == ["prompt", "completion", "request", "image"]
    for pricecapcache_trace_true_field in (
        "current_pricecapcache_trusted_project_provider_price_cap_rejects_v3_unconditionally",
        "current_pricecapcache_preview_schema_1_3_removed",
        "current_pricecapcache_pricing_attempt_schema_1_2_removed",
        "current_pricecapcache_old_schema_1_2_both_units_understatement_reproduced",
        "current_pricecapcache_old_schema_1_2_understatement_neutralized_by_unreachability",
        "current_pricecapcache_v1_and_v2_preserved",
        "current_pricecapcache_post_cutoff_static_and_generation_validation_passed",
    ):
        assert current_operator_reconciliation[pricecapcache_trace_true_field] is True
    for pricecapcache_trace_false_field in (
        "current_pricecapcache_v3_successor_derivation_available",
        "current_pricecapcache_v3_successor_cli_available",
        "current_pricecapcache_v3_plan_preview_attempt_or_transport_reachable",
        "current_pricecapcache_request_bound_cache_write_cap_available",
        "current_pricecapcache_request_bound_total_cost_cap_available",
        "current_pricecapcache_metadata_dominance_atomic",
        "current_pricecapcache_reconciliation_before_spend",
        "current_pricecapcache_provider_enforced_dominance_acceptance_met",
        "current_pricecapcache_post_cutoff_focused_validation_in_progress",
        "current_pricecapcache_provider_or_network_accessed_by_codex",
        "current_pricecapcache_operator_command_emitted_by_codex",
        "current_pricecapcache_ledger_accessed_or_mutated_by_codex",
        "current_pricecapcache_grants_authority",
    ):
        assert current_operator_reconciliation[pricecapcache_trace_false_field] is False
    assert (
        current_operator_reconciliation["current_pricecapcache_post_cutoff_affected_tests_passed"]
        == 1436
    )
    assert (
        current_operator_reconciliation["current_pricecapcache_post_cutoff_affected_test_warnings"]
        == 2
    )
    assert (
        current_operator_reconciliation[
            "current_pricecapcache_post_cutoff_affected_test_duration_seconds"
        ]
        == 245.19
    )
    assert (
        current_operator_reconciliation[
            "current_pricecapcache_post_cutoff_product_governance_tests_passed"
        ]
        == 27
    )
    assert current_operator_reconciliation["current_pricecapcache_independent_review"] == (
        "PASS_NO_BLOCKERS"
    )
    assert "V3-PRICEOVERRIDES-001" in requirements["U"]["remaining_proof"]
    assert "COMPLETE provider-free V3-PRICEOVERRIDES-001" in requirements["U"]["remaining_proof"]
    assert "typed tier validation and retention" in requirements["U"]["remaining_proof"]
    assert "schedule and endpoint hash binding" in requirements["U"]["remaining_proof"]
    assert "flat-evidence byte identity" in requirements["U"]["remaining_proof"]
    assert "unavailable conditional-cost projection" in requirements["U"]["remaining_proof"]
    assert "fail-closed refresh" in requirements["U"]["remaining_proof"]
    assert "full-CLI cap refusal" in requirements["U"]["remaining_proof"]
    assert "56 focused passes" in requirements["U"]["remaining_proof"]
    assert (
        "PRICEOVERRIDES requires no future implementation or live rerun"
        in (requirements["U"]["remaining_proof"])
    )
    assert "V3-PRICEOVERRIDES-001 remains QUEUED" not in requirements["U"]["remaining_proof"]
    assert requirements["U"]["status"] == "IN_PROGRESS"
    assert runtime_status["candidate_commit"] == "4f666d05c79e550af4f5fc646c5e6ffabb60dcf0"
    assert runtime_status["candidate_commit_parent"] == ("9a902192cae14bb14144094b3a3b3bf6dafed9a9")
    assert runtime_status["updated_at"] == "2026-09-04T04:05:31Z"
    assert runtime_status["current_ticket"] == "UNSELECTED"
    assert runtime_status["last_completed_ticket"] == "V3-PLANADOPT-001"
    assert runtime_status["last_partial_ticket"] == "V3-PRICECAPCACHE-001"
    assert runtime_status["next_safe_local_ticket"] is None
    assert runtime_status["combined_unfinished_ticket_count"] == 41
    assert runtime_status["current_repository_head_commit"] == (
        "810ed7f32a9f39df104a6959e84b71c59966fb44"
    )
    assert runtime_status["current_repository_head_parent"] == (
        "ad013aeeb4ea754ec7f0c751175e4badd5fc95b2"
    )
    assert runtime_status["current_repository_head_remote_resolved"] is True
    assert runtime_status["queued_successor_ticket"] is None
    assert runtime_status["queued_successor_ticket_status"] == "NONE"
    assert runtime_status["queued_successor_selected"] is False
    assert runtime_status["queued_successor_implementation_started"] is False
    assert runtime_status["withdrawn_successor_ticket"] == "V3-PRICEKEYORDER-001"
    assert runtime_status["withdrawn_successor_ticket_status"] == "WITHDRAWN_OPERATOR_ERROR"
    assert runtime_status["operator_results_current_worktree_required_for_ticket"] is False
    assert runtime_status["last_reconciled_operator_results_sha256"] == (
        CURRENT_OPERATOR_RESULTS_SHA256
    )
    assert runtime_status["last_reconciled_operator_results_bytes"] == 190_177
    assert runtime_status["last_reconciled_operator_results_lines"] == 3_377
    assert runtime_status["last_reconciled_operator_entry_timestamp"] == "2026-09-04T03:39Z"
    current_operator_status = runtime_status["operator_results_current_worktree_status"]
    assert "RECONCILED_EXACT_215EA0F2" in current_operator_status
    assert "NO_SUPPORTED_TRANSITION_EXISTS_TODAY" in current_operator_status
    assert "FUTURE_SEPARATELY_SELECTED_BOUNDED_TICKET_STOP" in current_operator_status
    assert "CURRENT_AND_NEXT_TICKET_UNSELECTED" in current_operator_status
    assert "ALL_AUTHORITY_FALSE" in current_operator_status
    assert runtime_status["current_provider_free_work"] is None
    selection_successor = runtime_status["candidate_selection_plan_successor"]
    assert selection_successor["successor_plan_schema_versions"] == ["1.5", "1.6", "1.7"]
    assert selection_successor["candidate_selection_plan_schema_raw_sha256"] == (
        CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256
    )
    assert selection_successor["active_plan_schema_version"] == "1.7"
    assert selection_successor["active_plan_sha256"] == ACTIVE_SELECTION_PLAN_SHA256
    assert selection_successor["active_plan_raw_sha256"] == ACTIVE_SELECTION_PLAN_RAW_SHA256
    assert selection_successor["active_plan_predecessor_sha256"] == (
        ACTIVE_SELECTION_PLAN_PREDECESSOR_SHA256
    )
    assert selection_successor["active_plan_unavailable_state_sha256"] == (
        ACTIVE_SELECTION_UNAVAILABLE_STATE_SHA256
    )
    assert selection_successor["active_plan_matched_revocation_set_sha256"] == (
        ACTIVE_SELECTION_MATCHED_REVOCATION_SET_SHA256
    )
    assert selection_successor["active_plan_unavailable_disposition"] == (
        "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
    )
    assert selection_successor["active_plan_has_active_candidate"] is False
    assert selection_successor["active_plan_retains_v1_price_cap_profile"] is True
    assert selection_successor["active_plan_adopts_v2_price_cap_profile"] is False
    assert selection_successor["active_plan_unchanged"] is False
    assert selection_successor["checked_in_successor_ticket"] == "V3-PLANADOPT-001"
    assert selection_successor["checked_in_successor_is_unavailable_candidate_state"] is True
    assert selection_successor["ordinary_reactivation_from_unavailable_predecessor_allowed"] is (
        False
    )
    assert (
        selection_successor[
            "future_reactivation_requires_separately_authenticated_ancestry_transition"
        ]
        is True
    )
    assert selection_successor["price_cap_profile_v2_upgrade_flag"] == (
        "--upgrade-price-cap-profile-v2"
    )
    for selection_successor_true_field in (
        "price_cap_profile_v2_upgrade_default_off",
        "price_cap_profile_v2_upgrade_exact_v1_predecessor_only",
        "price_cap_profile_v2_upgrade_same_candidate_route_supported",
        "price_cap_profile_v2_upgrade_rebuilds_shared_profile",
        "price_cap_profile_v2_upgrade_rebuilds_every_resulting_role_constraint",
        "price_cap_profile_v2_upgrade_validation_reproduces_exact_transition",
        "price_cap_profile_v2_upgrade_rejects_repeat_upgrade_downgrade_drift_and_tamper",
        "price_cap_profile_v2_upgrade_rejects_stateful_predecessor_substitution",
        "default_v1_successor_artifact_bytes_unchanged",
        "fresh_private_mode_0600_publication",
        "price_cap_profile_v3_algorithm_identifier_reserved",
    ):
        assert selection_successor[selection_successor_true_field] is True
    for selection_successor_false_field in (
        "operator_reported_successor_artifact_inspected_by_codex",
        "operator_reported_successor_selected_as_active_plan",
        "candidate_replacement_selected",
        "provider_or_network_accessed",
        "operator_command_emitted",
        "qualification_authority",
        "runtime_authority",
        "release_authority",
        "price_cap_profile_v3_upgrade_flag_available",
        "price_cap_profile_v3_successor_derivation_available",
        "price_cap_profile_v3_plan_emission_available",
        "price_cap_profile_v3_trusted_provider_cap_admissible",
    ):
        assert selection_successor[selection_successor_false_field] is False
    pricecapcache_work = runtime_status["last_partial_provider_free_work"]
    assert pricecapcache_work["ticket"] == "V3-PRICECAPCACHE-001"
    assert pricecapcache_work["slice"] == (
        "UNCONDITIONAL_V3_TRUSTED_BOUNDARY_REFUSAL_AND_UNREACHABLE_V3_ARTIFACTS"
    )
    assert pricecapcache_work["status"] == (
        "PARTIAL_TERMINAL_PROVIDER_FREE_NONAUTHORIZING_ATOMIC_PROVIDER_CAP_UNAVAILABLE"
    )
    assert pricecapcache_work["selected_at"] == "2026-09-04T00:56:31Z"
    assert pricecapcache_work["closure_timestamp"] == "2026-09-04T01:48:46Z"
    assert pricecapcache_work["provider_max_price_supported_dimensions"] == [
        "prompt",
        "completion",
        "request",
        "image",
    ]
    assert pricecapcache_work["preview_schema_versions_supported"] == ["1.0", "1.1", "1.2"]
    assert pricecapcache_work["pricing_attempt_schema_versions_supported"] == ["1.0", "1.1"]
    for pricecapcache_true_field in (
        "trusted_project_provider_price_cap_rejects_v3_unconditionally",
        "preview_schema_1_3_removed",
        "pricing_attempt_schema_1_2_removed",
        "old_schema_1_2_both_prompt_and_cache_write_units_understatement_reproduced",
        "old_schema_1_2_understatement_neutralized_by_unreachability",
        "v1_and_v2_behavior_preserved",
    ):
        assert pricecapcache_work[pricecapcache_true_field] is True
    for pricecapcache_false_field in (
        "requested_provider_enforced_dominance_established",
        "provider_request_bound_cache_write_cap_available",
        "provider_request_bound_total_cost_cap_available",
        "metadata_dominance_is_atomic",
        "reconciliation_occurs_before_spend",
        "v3_successor_derivation_available",
        "v3_successor_cli_available",
        "v3_plan_emitted_or_adopted",
        "v3_preview_or_attempt_publication_reachable",
        "operator_reported_private_v2_plan_adopted",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "operator_ledger_accessed_or_mutated_by_codex",
        "authority",
        "grants_authority",
    ):
        assert pricecapcache_work[pricecapcache_false_field] is False
    autonomy_work = runtime_status["prior_autonomy_provider_free_work"]
    assert autonomy_work["ticket"] == "V3-AUTONOMY-001"
    assert autonomy_work["slice"] == "PHASE_2_TYPED_PROVISIONING_AND_IDEMPOTENT_LOCAL_COST_LEDGER"
    assert autonomy_work["status"] == (
        "PARTIAL_TERMINAL_PROVIDER_FREE_NONAUTHORIZING_UNSUPPORTED_EXTERNAL_SURFACES_REFUSED"
    )
    assert autonomy_work["selected_at"] == "2026-09-03T22:26:22Z"
    assert autonomy_work["closure_timestamp"] == "2026-09-03T23:38:22Z"
    for autonomy_true_field in (
        "self_contained_typed_plan_state_refusal_receipt",
        "receipt_reproduces_exact_embedded_plan_and_state",
        "file_only_cli_configuration",
        "repository_finalized_and_digest_compared_before_final_name_link",
        "receipt_is_point_in_time_evidence_not_post_finalization_stability_guarantee",
        "audited_workspace_exclusions_honored",
        "atomic_no_replace_receipt_publication",
        "published_receipt_bytes_and_identity_revalidated",
        "identity_checked_rollback_under_cooperative_publication_lease",
        "receipt_ledger_and_workspace_reads_nonblocking",
        "fifo_substitution_refused",
        "cost_ledger_create_or_verify_idempotent",
        "cost_ledger_durable_provisioning_marker_bound",
        "cost_ledger_provisioning_lease_held_through_snapshot",
    ):
        assert autonomy_work[autonomy_true_field] is True
    assert autonomy_work["managed_toolchain_unresolved_role_count"] == 25
    assert autonomy_work["affected_local_matrix_tests_passed"] == 287
    assert autonomy_work["release_schema_and_autonomy_tests_passed"] == 65
    for autonomy_false_field in (
        "ambient_environment_configuration_accepted",
        "cost_ledger_reset_or_automatic_repair_permitted",
        "installed_toolchain_verified",
        "fork_endpoint_provisioned",
        "codeql_database_provisioned",
        "dependency_snapshot_provisioned",
        "zero_input_end_to_end_audit_proven",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "runtime_authority",
        "managed_run_ready",
        "grants_authority",
    ):
        assert autonomy_work[autonomy_false_field] is False
    testquality_work = runtime_status["prior_testquality_provider_free_work"]
    assert testquality_work["ticket"] == "V3-TESTQUALITY-001"
    assert testquality_work["slice"] == "SHARED_PROCESS_LOCAL_REVOCATION_LEASE_RACE"
    assert testquality_work["status"] == ("PARTIAL_PROVIDER_FREE_NONAUTHORIZING_COMPARISON_ONLY")
    assert testquality_work["selected_at"] == "2026-09-03T05:40:39Z"
    assert testquality_work["closure_timestamp"] == "2026-09-03T07:06:29Z"
    assert testquality_work["implementation_started"] is True
    for testquality_true_field in (
        "exact_utf8_statement_spans_bound",
        "contract_function_span_population_consistency_required",
        "live_process_local_foundry_seal_required_for_projection",
        "legacy_v1_0_replay_preserved",
        "bounded_lcov_parser_line_only",
        "compiler_exact_statement_producer_implemented",
        "raw_coverage_process_custody_implemented",
        "schema_v1_2_shared_receipt_implemented",
        "host_observed_compiler_exact_statement_inventory_available",
        "host_observed_coverage_process_receipt_available",
        "exact_mutation_executor_implemented",
        "executor_implementation_graph_bound",
        "process_local_mutation_comparison_implemented",
        "mutation_seals_pid_bound",
        "fork_serialization_and_copy_authority_loss_enforced",
        "one_shot_campaign_cleanup_handoff_implemented",
        "exact_live_observation_preserved_through_same_invocation_cleanup_handoff",
        "cleanup_handoff_exact_plan_spec_source_private_root_identity_mode_executor_pid_cleanup_observation_bound",
        "cleanup_handoff_replay_copy_serialization_fork_substitution_tamper_stale_authority_rejected",
        "observed_campaign_invalidation_or_replay_synchronously_cascades_to_dependent_scorecards",
        "baseexception_and_lock_interruption_clean_identity_scoped_seals",
        "shared_revocation_lease_available",
        "race_safe_live_dependency_authority_proven",
        "pid_bound_shared_domain_serializes_run_observation_campaign_score_and_handoff_replay",
        "composite_local_seals_revalidated_after_dependency_release",
        "decisive_scoring_uses_seal_sha_matched_immutable_schema_snapshots",
        "authenticated_snapshot_plan_matches_canonical_score_plan",
        "exact_live_sources_revalidated_at_registration",
        "dependent_revocation_callbacks_deferred_beyond_outer_lease",
        "baseexception_partial_paths_exact_remove_without_masking_primary",
        "fork_refuses_before_inherited_layer_locks",
        "canonical_inventory_generation_verified",
    ):
        assert testquality_work[testquality_true_field] is True
    assert testquality_work["durable_projection_authority"] == "comparison_only"
    assert testquality_work["shared_revocation_lease_scope"] == "PROCESS_LOCAL_COMPARISON_ONLY"
    assert testquality_work["race_safe_live_dependency_authority_scope"] == (
        "PROCESS_LOCAL_LEASE_LINEARIZATION_ONLY"
    )
    assert testquality_work["focused_run_observation_campaign_score_chain_passed"] == 166
    assert testquality_work["focused_chain_duration_seconds"] == "4.33"
    assert testquality_work["adjacent_unit_matrix_passed"] == 135
    assert testquality_work["adjacent_unit_matrix_duration_seconds"] == "19.41"
    assert testquality_work["execution_origin_integration_skipped"] == 1
    assert testquality_work["execution_origin_integration_skip_reason"] == (
        "HARDENED_LOCAL_ISOLATION_UNAVAILABLE"
    )
    assert testquality_work["broader_attempt_collected"] == 265
    assert testquality_work["broader_attempt_passed_before_operator_interrupt"] == 168
    assert testquality_work["broader_attempt_skipped_before_operator_interrupt"] == 1
    assert testquality_work["broader_attempt_duration_seconds"] == "547.50"
    assert testquality_work["repository_python_ruff_files_clean"] == 599
    assert testquality_work["strict_mypy_source_files_clean"] == 233
    for testquality_false_field in (
        "production_statement_evidence_emitted",
        "current_real_isolated_production_receipt_available",
        "decisive_real_mutation_execution_available",
        "portable_race_safe_disposal_available",
        "benchmark_mutation_credit_enabled",
        "production_campaign_authority_enabled",
        "production_disposal_authority_enabled",
        "one_shot_campaign_cleanup_handoff_is_independent_receipt",
        "same_interpreter_reflection_gap_eliminated",
        "asynchronous_exception_micro_gap_eliminated",
        "post_linearization_return_gap_eliminated",
        "one_shot_campaign_receipt_available",
        "current_real_mutation_campaign_receipt_available",
        "sealed_backend_available",
        "real_mutation_run_and_kill_artifact_available",
        "production_plan_generator_available",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "candidate_or_route_selected",
        "active_plan_changed",
        "retry_behavior_or_configuration_changed",
        "global_ledger_changed",
        "run_index_selected_or_inferred",
        "grants_authority",
        "authority",
        "broader_attempt_terminal_or_full_suite_credit",
        "terminal_full_suite_pass_credit",
    ):
        assert testquality_work[testquality_false_field] is False
    planadopt_work = runtime_status["last_completed_provider_free_work"]
    assert planadopt_work["ticket"] == "V3-PLANADOPT-001"
    assert planadopt_work["slice"] == (
        "DETERMINISTIC_SCHEMA_1_7_NO_ACTIVE_CANDIDATE_ADOPTION_AFTER_EXACT_ROUTE_REVOCATION"
    )
    assert planadopt_work["status"] == "COMPLETE_TERMINAL_PROVIDER_FREE_NONAUTHORIZING"
    assert planadopt_work["selected_at"] == "2026-09-04T02:44:26Z"
    assert planadopt_work["closure_timestamp"] == "2026-09-04T03:27:47Z"
    assert planadopt_work["active_plan_schema_version"] == "1.7"
    assert planadopt_work["active_plan_sha256"] == ACTIVE_SELECTION_PLAN_SHA256
    assert planadopt_work["active_plan_raw_sha256"] == ACTIVE_SELECTION_PLAN_RAW_SHA256
    assert planadopt_work["predecessor_plan_sha256"] == (ACTIVE_SELECTION_PLAN_PREDECESSOR_SHA256)
    assert planadopt_work["unavailable_state_sha256"] == (ACTIVE_SELECTION_UNAVAILABLE_STATE_SHA256)
    assert planadopt_work["matched_revocation_set_sha256"] == (
        ACTIVE_SELECTION_MATCHED_REVOCATION_SET_SHA256
    )
    assert planadopt_work["candidate_selection_plan_schema_raw_sha256"] == (
        CANDIDATE_SELECTION_PLAN_SCHEMA_RAW_SHA256
    )
    assert planadopt_work["unavailable_disposition"] == "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
    assert planadopt_work["direct_affected_tests_passed"] == 319
    assert planadopt_work["direct_affected_test_duration_seconds"] == 64.9
    assert planadopt_work["focused_tests_passed"] == 212
    assert planadopt_work["independent_review"] == "PASS_NO_BLOCKERS"
    for planadopt_true_field in (
        "implementation_started",
        "code_changed",
        "configuration_changed",
        "active_plan_changed",
        "judge_constraints_preserved",
        "v1_price_cap_profile_preserved",
        "future_reactivation_requires_separately_authenticated_ancestry_transition",
    ):
        assert planadopt_work[planadopt_true_field] is True
    for planadopt_false_field in (
        "active_candidate_present",
        "revoked_route_pinned",
        "v2_price_cap_profile_adopted",
        "retry_behavior_changed",
        "global_ledger_changed",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "candidate_or_route_selected",
        "run_index_selected_or_inferred",
        "qualification_runtime_audit_or_release_authority",
        "terminal_full_suite_pass_credit",
        "grants_authority",
        "authority",
    ):
        assert planadopt_work[planadopt_false_field] is False

    pricecapcomp_work = runtime_status["prior_pricecapcomp_provider_free_work"]
    assert pricecapcomp_work["ticket"] == "V3-PRICECAPCOMP-001"
    assert pricecapcomp_work["slice"] == (
        "EXACT_ZERO_WEB_SEARCH_REQUEST_UNIT_ENVELOPE_AND_DEFAULT_OFF_V1_TO_V2_SUCCESSOR_SELECTOR"
    )
    assert pricecapcomp_work["status"] == "COMPLETE_TERMINAL_PROVIDER_FREE_NONAUTHORIZING"
    assert pricecapcomp_work["closure_timestamp"] == "2026-09-03T21:41:10Z"
    assert pricecapcomp_work["focused_successor_and_cli_tests_passed"] == 120
    assert pricecapcomp_work["broad_affected_tests_passed"] == 1328
    assert pricecapcomp_work["broad_affected_test_warnings"] == 2
    assert pricecapcomp_work["release_autonomy_refresh_schema_tests_passed"] == 79
    assert pricecapcomp_work["independent_review"] == "PASS_NO_BLOCKER"
    for pricecapcomp_true_field in (
        "implementation_started",
        "v2_price_cap_algorithm_opt_in",
        "web_search_nonzero_price_retained",
        "search_tool_plugin_fields_prohibited",
        "exact_request_revalidated_before_reservation_and_transport",
        "profile_and_envelope_discovery_registration_projection_custody",
        "profile_and_envelope_preview_refresh_durable_custody",
        "profile_and_envelope_smoke_runtime_custody",
        "provider_egress_callable_graph_bound",
        "input_cache_write_remains_rejected",
        "active_v1_plan_bytes_unchanged",
        "supported_successor_cli_v1_to_v2_upgrade_available",
        "successor_cli_upgrade_default_off",
        "same_candidate_route_upgrade_supported",
        "exact_v1_predecessor_required_for_upgrade",
        "shared_v2_profile_and_every_resulting_role_constraint_rebuilt",
        "same_algorithm_or_v1_to_v2_transition_only",
        "repeat_upgrade_downgrade_drift_tamper_and_revocation_rejected",
        "stateful_predecessor_substitution_rejected",
        "fresh_private_mode_0600_successor_publication",
    ):
        assert pricecapcomp_work[pricecapcomp_true_field] is True
    assert pricecapcomp_work["web_search_maximum_units"] == 0
    assert pricecapcomp_work["web_search_maximum_cost_usd_exact"] == "0"
    for pricecapcomp_false_field in (
        "recorded_xai_route_admissible",
        "terminal_full_suite_pass_credit",
        "configuration_changed",
        "retry_behavior_changed",
        "active_plan_changed",
        "global_ledger_changed",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "candidate_or_route_selected",
        "run_index_selected_or_inferred",
        "qualification_runtime_audit_or_release_authority",
        "grants_authority",
        "authority",
    ):
        assert pricecapcomp_work[pricecapcomp_false_field] is False
    priceoverrides_work = runtime_status["prior_priceoverrides_provider_free_work"]
    assert priceoverrides_work["ticket"] == "V3-PRICEOVERRIDES-001"
    assert priceoverrides_work["slice"] == (
        "TYPED_TIERED_PRICING_RETENTION_AND_COST_AUTHORITY_REFUSAL"
    )
    assert priceoverrides_work["status"] == "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    assert priceoverrides_work["selected_at"] == "2026-09-03T09:30:38Z"
    assert priceoverrides_work["closure_timestamp"] == "2026-09-03T09:54:24Z"
    for priceoverrides_true_field in (
        "implementation_started",
        "typed_override_tier_model_implemented",
        "recorded_operator_shape_validated_and_retained",
        "exact_bounded_nonnegative_thresholds_enforced",
        "nested_exact_canonical_decimal_prices_enforced",
        "tier_count_and_provider_order_bounded",
        "duplicate_and_out_of_order_thresholds_rejected",
        "strict_threshold_inheritance_and_later_wins",
        "pricing_schedule_sha256_binds_base_and_ordered_tiers",
        "endpoint_snapshot_sha256_binds_schedule",
        "zdr_schedule_equivalence_required",
        "flat_endpoint_evidence_byte_identical",
        "accurate_non_scalar_refusal",
        "provider_free_preview_refuses_conditional_cost_authority",
        "endpoint_registration_refuses_conditional_cost_authority",
        "identity_sealing_refuses_conditional_cost_authority",
        "model_refresh_refuses_schedule_instead_of_dropping_it",
        "full_models_discover_recorded_shape_reaches_route_predicates",
        "code_changed",
    ):
        assert priceoverrides_work[priceoverrides_true_field] is True
    assert priceoverrides_work["tiered_pricing_cost_projection"] == "unavailable"
    assert priceoverrides_work["full_models_discover_failure_reasons"] == [
        "PRICE_CAP_NOT_EXPRESSIBLE",
        "PRICE_CAP_PROOF_UNAVAILABLE",
    ]
    assert priceoverrides_work["focused_tests_passed"] == 56
    assert priceoverrides_work["broad_affected_tests_passed"] == 481
    assert priceoverrides_work["strict_mypy_source_files_clean"] == 233
    for priceoverrides_false_field in (
        "sole_remaining_route_blocker_proven",
        "conditional_route_admissibility_proven",
        "retry_behavior_changed",
        "retry_configuration_changed",
        "active_plan_changed",
        "global_ledger_changed",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "candidate_or_route_selected",
        "run_index_selected_or_inferred",
        "qualification_runtime_audit_or_release_authority",
        "terminal_full_suite_pass_credit",
        "grants_authority",
        "authority",
    ):
        assert priceoverrides_work[priceoverrides_false_field] is False
    terminal_validation = runtime_status["last_validation"]
    assert terminal_validation["status"] == (
        "V3_PLANADOPT_001_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_CURRENT_AND_NEXT_TICKET_UNSELECTED"
    )
    assert terminal_validation["terminal_full_suite_run"] is False
    assert terminal_validation["terminal_full_suite_attempt_started"] is False
    assert "v3_priceoverrides_001_terminal_full_suite" not in terminal_validation
    assert terminal_validation["v3_pricelexeme_001_terminal_full_suite"] is None
    latest_validation = terminal_validation["latest_post_closure_validation"]
    assert latest_validation["validated_at"] == "2026-09-04T02:27:59Z"
    assert latest_validation["validation_scope"] == (
        "POST_CUTOFF_AFFECTED_MATRIX_AND_STATIC_CLOSURE"
    )
    assert latest_validation["affected_tests_passed"] == 1436
    assert latest_validation["affected_test_warnings"] == 2
    assert latest_validation["affected_test_duration_seconds"] == 245.19
    assert latest_validation["product_governance_tests_passed"] == 27
    assert latest_validation["canonical_generation_and_verification_passed"] is True
    assert latest_validation["ruff_format_files_checked"] == 588
    assert latest_validation["repository_wide_ruff_passed"] is True
    assert latest_validation["strict_mypy_source_files_clean"] == 235
    assert latest_validation["strict_json_validation_passed"] is True
    assert latest_validation["strict_json_files_checked"] == 20
    assert latest_validation["diff_integrity_passed"] is True
    assert latest_validation["implementation_review"] == "PASS_NO_BLOCKERS"
    pricecapcache_validation = terminal_validation["v3_pricecapcache_001_local_validation"]
    assert pricecapcache_validation["closure_timestamp"] == "2026-09-04T01:48:46Z"
    assert pricecapcache_validation["provider_max_price_supported_dimensions"] == [
        "prompt",
        "completion",
        "request",
        "image",
    ]
    assert pricecapcache_validation["preview_schema_versions_supported"] == ["1.0", "1.1", "1.2"]
    assert pricecapcache_validation["pricing_attempt_schema_versions_supported"] == ["1.0", "1.1"]
    assert pricecapcache_validation["candidate_selection_plan_schema_raw_sha256"] == (
        "009b2e5f2ee4f4f6a6202ceb168b6b953e64a66448b722bbf939358fb1aa72e3"
    )
    assert pricecapcache_validation["request_cost_preview_schema_raw_sha256"] == (
        "5aa3665fed2f7910993615d2c5edb93b59d52082c7015815de157b82a867db85"
    )
    assert pricecapcache_validation["pricing_attempt_schema_raw_sha256"] == (
        "31b964264627cdb742292f108b1fa2ac096bdfa17603558aa52cbed436529028"
    )
    assert pricecapcache_validation["route_runtime_schema_raw_sha256"] == (
        "94fb9f405d1365371961a6498462ea413e98cbfd982fb8c316710a7faab4ad04"
    )
    for pricecapcache_validation_true_field in (
        "trusted_project_provider_price_cap_rejects_v3_unconditionally",
        "preview_schema_1_3_removed",
        "pricing_attempt_schema_1_2_removed",
        "old_schema_1_2_both_prompt_and_cache_write_units_understatement_reproduced",
        "old_schema_1_2_understatement_neutralized_by_unreachability",
        "v1_and_v2_behavior_preserved",
        "post_cutoff_static_and_generation_validation_passed",
    ):
        assert pricecapcache_validation[pricecapcache_validation_true_field] is True
    for pricecapcache_validation_false_field in (
        "v3_successor_derivation_available",
        "v3_successor_cli_available",
        "v3_plan_preview_attempt_or_transport_reachable",
        "provider_request_bound_cache_write_cap_available",
        "provider_request_bound_total_cost_cap_available",
        "metadata_dominance_atomic",
        "reconciliation_before_spend",
        "provider_enforced_dominance_acceptance_met",
        "post_cutoff_focused_validation_in_progress",
        "terminal_full_suite_pass_credit",
        "provider_or_network_accessed_by_codex",
        "operator_ledger_accessed_or_mutated_by_codex",
        "operator_command_emitted_by_codex",
        "grants_authority",
    ):
        assert pricecapcache_validation[pricecapcache_validation_false_field] is False
    assert pricecapcache_validation["post_cutoff_affected_tests_passed"] == 1436
    assert pricecapcache_validation["post_cutoff_affected_test_warnings"] == 2
    assert pricecapcache_validation["post_cutoff_affected_test_duration_seconds"] == 245.19
    assert pricecapcache_validation["post_cutoff_product_governance_tests_passed"] == 27
    assert pricecapcache_validation["independent_review"] == "PASS_NO_BLOCKERS"
    historical_autonomy_validation = terminal_validation[
        "v3_autonomy_001_latest_post_closure_validation"
    ]
    assert historical_autonomy_validation["validated_at"] == "2026-09-04T00:25:42Z"
    assert historical_autonomy_validation["product_governance_tests_passed"] == 27
    pricecapcomp_validation = terminal_validation["v3_pricecapcomp_001_local_validation"]
    assert pricecapcomp_validation["closure_timestamp"] == "2026-09-03T21:41:10Z"
    assert pricecapcomp_validation["focused_selector_and_cli_tests_passed"] == 120
    assert pricecapcomp_validation["broad_affected_tests_passed"] == 1328
    assert pricecapcomp_validation["broad_affected_test_warnings"] == 2
    assert pricecapcomp_validation["release_autonomy_refresh_schema_tests_passed"] == 79
    for pricecapcomp_validation_true_field in (
        "supported_default_off_v1_to_v2_successor_selector",
        "successor_selector_exact_v1_predecessor_only",
        "successor_selector_same_route_upgrade_supported",
        "successor_selector_rebuilds_shared_profile_and_every_role_constraint",
        "successor_selector_exact_immediate_transition_validated",
        "successor_selector_rejects_repeat_upgrade_downgrade_drift_tamper_and_stateful_substitution",
        "v1_default_and_active_plan_bytes_unchanged",
        "input_cache_write_remains_rejected",
    ):
        assert pricecapcomp_validation[pricecapcomp_validation_true_field] is True
    for pricecapcomp_validation_false_field in (
        "recorded_xai_route_admissible",
        "terminal_full_suite_pass_credit",
        "provider_or_network_accessed",
        "operator_command_emitted",
        "candidate_or_route_selected",
        "active_plan_changed",
        "configuration_or_retry_behavior_changed",
        "global_ledger_changed",
        "run_index_selected_or_inferred",
        "qualification_runtime_audit_or_release_authority",
        "grants_authority",
    ):
        assert pricecapcomp_validation[pricecapcomp_validation_false_field] is False
    modelrefresh_validation = terminal_validation[
        "v3_modelrefresh_001_tier_schedule_local_validation"
    ]
    assert modelrefresh_validation["focused_core_tests_passed"] == 245
    assert modelrefresh_validation["schema_route_endpoint_tests_passed"] == 262
    assert modelrefresh_validation["independent_affected_tests_passed"] == 471
    assert modelrefresh_validation["composed_custody_tests_passed"] == 2
    assert modelrefresh_validation["live_route_preflight_schedule_join_implemented"] is True
    assert modelrefresh_validation["terminal_full_suite_pass_credit"] is False
    pricecaptier_validation = terminal_validation["v3_pricecaptier_001_local_validation"]
    assert pricecaptier_validation["focused_tests_passed"] == 280
    assert pricecaptier_validation["affected_tests_passed"] == 1251
    assert pricecaptier_validation["affected_test_warnings"] == 2
    assert pricecaptier_validation["adversarial_focused_tests_passed"] == 241
    assert pricecaptier_validation["primary_acceptance_met"] is False
    priceoverrides_validation = terminal_validation["v3_priceoverrides_001_local_validation"]
    assert priceoverrides_validation["status"] == (
        "COMPLETE_PROVIDER_FREE_TYPED_SCHEDULE_RETENTION_COST_PROJECTION_UNAVAILABLE_NONAUTHORIZING"
    )
    assert priceoverrides_validation["selected_at"] == "2026-09-03T09:30:38Z"
    assert priceoverrides_validation["closure_timestamp"] == "2026-09-03T09:54:24Z"
    for priceoverrides_validation_true_field in (
        "implementation_started",
        "operator_reported_direct_billable_prices_all_exact_decimal_strings",
        "operator_reported_nested_billable_prices_all_exact_decimal_strings",
        "structured_overrides_list_is_first_parser_blocker",
        "typed_override_tier_model_implemented",
        "recorded_operator_shape_validated_and_retained",
        "exact_bounded_nonnegative_thresholds_enforced",
        "nested_exact_canonical_decimal_prices_enforced",
        "tier_count_and_provider_order_bounded",
        "duplicate_and_out_of_order_thresholds_rejected",
        "strict_threshold_inheritance_and_later_wins",
        "pricing_schedule_sha256_binds_base_and_ordered_tiers",
        "endpoint_snapshot_sha256_binds_schedule",
        "zdr_schedule_equivalence_required",
        "flat_endpoint_evidence_byte_identical",
        "accurate_non_scalar_refusal",
        "provider_free_preview_refuses_conditional_cost_authority",
        "endpoint_registration_refuses_conditional_cost_authority",
        "identity_sealing_refuses_conditional_cost_authority",
        "model_refresh_refuses_schedule_instead_of_dropping_it",
        "full_models_discover_recorded_shape_reaches_route_predicates",
        "local_no_overrides_projection_performed_provider_free",
        "local_no_overrides_input_cache_write_variable_uncappable",
        "local_no_overrides_web_search_nonzero_uncappable",
        "canonical_generation_verified",
        "code_changed",
    ):
        assert priceoverrides_validation[priceoverrides_validation_true_field] is True
    assert priceoverrides_validation["tiered_pricing_cost_projection"] == "unavailable"
    assert priceoverrides_validation["full_models_discover_failure_reasons"] == [
        "PRICE_CAP_NOT_EXPRESSIBLE",
        "PRICE_CAP_PROOF_UNAVAILABLE",
    ]
    assert priceoverrides_validation["local_no_overrides_input_cache_write_value"] == "0"
    assert priceoverrides_validation["local_no_overrides_web_search_value"] == "0.01"
    assert priceoverrides_validation["focused_tests_passed"] == 56
    assert priceoverrides_validation["broad_affected_tests_passed"] == 481
    assert priceoverrides_validation["strict_mypy_source_files_clean"] == 233
    for priceoverrides_validation_false_field in (
        "operator_reported_numeric_billable_price_observed",
        "local_no_overrides_projection_passed",
        "sole_remaining_route_blocker_proven",
        "conditional_route_admissibility_proven",
        "configuration_changed",
        "retry_behavior_changed",
        "active_plan_changed",
        "global_ledger_changed",
        "provider_or_network_accessed_by_codex",
        "operator_command_emitted_by_codex",
        "candidate_or_route_selected",
        "run_index_selected_or_inferred",
        "qualification_runtime_audit_or_release_authority",
        "terminal_full_suite_pass_credit",
        "grants_authority",
    ):
        assert priceoverrides_validation[priceoverrides_validation_false_field] is False
    testquality_validation = terminal_validation["v3_testquality_001_local_validation"]
    assert testquality_validation["status"] == (
        "PARTIAL_PROVIDER_FREE_NONAUTHORIZING_SHARED_PROCESS_LOCAL_REVOCATION_LEASE_RACE_"
        "SLICE_COMPLETE_COMPARISON_ONLY"
    )
    assert testquality_validation["current_slice_selected_at"] == "2026-09-03T05:40:39Z"
    assert testquality_validation["current_slice_closure_timestamp"] == ("2026-09-03T07:06:29Z")
    assert testquality_validation["current_slice_implementation_started"] is True
    assert testquality_validation["focused_matrix_passed"] == 161
    assert testquality_validation["replay_and_execution_hardening_matrix_passed"] == 107
    assert testquality_validation["autonomy_producer_execution_boundary_matrix_passed"] == 54
    assert testquality_validation["release_schema_matrix_passed"] == 29
    assert testquality_validation["pipeline_interface_smoke_passed"] == 1
    assert testquality_validation["broad_integration_attempt_collected"] == 265
    assert testquality_validation["broad_integration_attempt_passed_before_interruption"] == 168
    assert testquality_validation["broad_integration_attempt_skipped"] == 1
    assert testquality_validation["broad_integration_attempt_duration_seconds"] == "547.50"
    assert testquality_validation["broad_integration_attempt_operator_interrupted"] is True
    assert testquality_validation["broad_integration_attempt_complete_pass_credit"] is False
    assert testquality_validation["repository_python_ruff_files_clean"] == 599
    assert testquality_validation["strict_mypy_source_files_clean"] == 233
    assert testquality_validation["focused_run_observation_campaign_score_chain_passed"] == 166
    assert testquality_validation["focused_chain_duration_seconds"] == "4.33"
    assert testquality_validation["adjacent_unit_matrix_passed"] == 135
    assert testquality_validation["adjacent_unit_matrix_duration_seconds"] == "19.41"
    assert testquality_validation["execution_origin_integration_skipped"] == 1
    assert testquality_validation["execution_origin_integration_skip_reason"] == (
        "HARDENED_LOCAL_ISOLATION_UNAVAILABLE"
    )
    assert (
        testquality_validation["focused_mutation_benchmark_coverage_integration_matrix_passed"]
        == 190
    )
    assert testquality_validation["runtime_hardening_and_replay_matrix_passed"] == 156
    assert testquality_validation["release_benchmark_schema_and_autonomy_matrix_passed"] == 66
    assert testquality_validation["product_documentation_and_objective_matrix_passed"] == 27
    for testquality_validation_true_field in (
        "schema_generation_passed",
        "scoped_ruff_passed",
        "strict_mypy_passed",
        "diff_integrity_passed",
        "exact_utf8_statement_spans_bound",
        "complete_contract_function_population_agreement_required",
        "live_process_local_foundry_seal_required",
        "legacy_v1_0_replay_preserved",
        "bounded_lcov_parser_line_only",
        "compiler_exact_statement_producer_implemented",
        "raw_coverage_process_custody_implemented",
        "schema_v1_2_shared_receipt_implemented",
        "host_observed_compiler_exact_statement_inventory_available",
        "host_observed_coverage_process_receipt_available",
        "exact_mutation_executor_implemented",
        "executor_implementation_graph_bound",
        "process_local_mutation_comparison_implemented",
        "mutation_seals_pid_bound",
        "fork_serialization_and_copy_authority_loss_enforced",
        "one_shot_campaign_cleanup_handoff_implemented",
        "exact_live_observation_preserved_through_same_invocation_cleanup_handoff",
        "cleanup_handoff_exact_plan_spec_source_private_root_identity_mode_executor_pid_cleanup_observation_bound",
        "cleanup_handoff_replay_copy_serialization_fork_substitution_tamper_stale_authority_rejected",
        "observed_campaign_invalidation_or_replay_synchronously_cascades_to_dependent_scorecards",
        "baseexception_and_lock_interruption_clean_identity_scoped_seals",
        "shared_revocation_lease_available",
        "race_safe_live_dependency_authority_proven",
        "pid_bound_shared_domain_serializes_run_observation_campaign_score_and_handoff_replay",
        "composite_local_seals_revalidated_after_dependency_release",
        "decisive_scoring_uses_seal_sha_matched_immutable_schema_snapshots",
        "authenticated_snapshot_plan_matches_canonical_score_plan",
        "exact_live_sources_revalidated_at_registration",
        "dependent_revocation_callbacks_deferred_beyond_outer_lease",
        "baseexception_partial_paths_exact_remove_without_masking_primary",
        "fork_refuses_before_inherited_layer_locks",
        "canonical_inventory_generation_verified",
    ):
        assert testquality_validation[testquality_validation_true_field] is True
    assert testquality_validation["durable_projection_authority"] == "comparison_only"
    assert testquality_validation["shared_revocation_lease_scope"] == (
        "PROCESS_LOCAL_COMPARISON_ONLY"
    )
    assert testquality_validation["race_safe_live_dependency_authority_scope"] == (
        "PROCESS_LOCAL_LEASE_LINEARIZATION_ONLY"
    )
    for testquality_validation_false_field in (
        "production_statement_evidence_emitted",
        "current_real_isolated_production_receipt_available",
        "decisive_real_mutation_execution_available",
        "portable_race_safe_disposal_available",
        "benchmark_mutation_credit_enabled",
        "production_campaign_authority_enabled",
        "production_disposal_authority_enabled",
        "one_shot_campaign_cleanup_handoff_is_independent_receipt",
        "same_interpreter_reflection_gap_eliminated",
        "asynchronous_exception_micro_gap_eliminated",
        "post_linearization_return_gap_eliminated",
        "one_shot_campaign_receipt_available",
        "current_real_mutation_campaign_receipt_available",
        "sealed_backend_available",
        "real_mutation_run_and_kill_artifact_available",
        "production_plan_generator_available",
        "provider_or_network_accessed",
        "operator_command_emitted",
        "grants_authority",
        "terminal_full_suite_pass_credit",
    ):
        assert testquality_validation[testquality_validation_false_field] is False
    priceform_validation = terminal_validation["v3_priceform_001_decision_validation"]
    for priceform_validation_true_field in (
        "policy_decision_closure",
        "decision_only",
        "ordinary_uncaptured_numeric_price_refusal_upheld",
        "captured_price_lexeme_canonical_string_storage_validated",
        "exact_cost_reserve_spend_and_reconcile_arithmetic_parity_validated",
    ):
        assert priceform_validation[priceform_validation_true_field] is True
    assert priceform_validation["affected_unit_matrix_passed"] == 795
    assert priceform_validation["affected_unit_matrix_warnings"] == 2
    for priceform_validation_false_field in (
        "code_changed",
        "retry_behavior_changed",
        "retry_configuration_changed",
        "active_plan_changed",
        "global_ledger_changed",
        "provider_or_network_accessed",
        "operator_command_emitted",
        "grants_authority",
        "terminal_full_suite_pass_credit",
    ):
        assert priceform_validation[priceform_validation_false_field] is False
    local_validation = terminal_validation["v3_pricelexeme_001_local_validation"]
    assert local_validation["status"] == (
        "PARTIAL_TERMINAL_PROVIDER_FREE_NONAUTHORIZING_DEFENSE_IN_DEPTH_PREMISE_"
        "SUPERSEDED_NONBLOCKING"
    )
    assert local_validation["historical_pre_hardening_affected_unit_matrix_passed"] == 795
    assert local_validation["historical_pre_hardening_affected_unit_matrix_warnings"] == 2
    assert local_validation["historical_pre_hardening_combined_custody_retest_passed"] == 24
    assert local_validation["historical_pre_hardening_schema_inventory_closure_passed"] == 126
    assert local_validation["parse_phase_numeric_token_ceiling"] == 100000
    assert local_validation["current_focused_price_and_endpoint_matrix_passed"] == 87
    assert local_validation["current_affected_unit_matrix_passed"] == 755
    assert local_validation["current_affected_unit_matrix_warnings"] == 2
    assert local_validation["current_refresh_runtime_staging_workflow_schema_matrix_passed"] == 220
    assert (
        local_validation["current_focused_detachment_and_transport_observation_cases_passed"] == 5
    )
    assert local_validation["current_schema_autonomy_matrix_passed"] == 66
    assert local_validation["current_product_governance_matrix_passed"] == 27
    assert local_validation["current_governance_matrix_passed"] == 93
    for local_validation_true_field in (
        "current_focused_validation_passed",
        "current_affected_validation_passed",
        "current_provider_free_localhost_integration_passed",
        "canonical_generation_verification_passed",
        "strict_duplicate_key_json_validation_passed",
        "parse_phase_numeric_token_ceiling_enforced_before_materialization",
        "decoder_issues_tokens_only_at_final_fixed_price_paths",
        "snapshot_admission_binds_original_layout_endpoint_index_and_price_field",
        "observed_field_index_or_layout_relocation_revokes_monotonically",
        "decoder_is_only_normal_issuer",
        "registry_only_slotless_marker",
        "exact_layout_full_path_and_price_field_bound",
        "detach_copy_and_deepcopy_preserve_same_identity",
        "construction_pickle_and_reduction_rejected",
        "setattr_delattr_and_observed_class_substitution_revoke_monotonically",
        "id_keyed_exact_weakref_registry",
        "exact_weakref_cleanup_and_id_reuse_bound",
        "scoped_ruff_passed",
        "strict_mypy_passed",
        "joined_raw_http_constrained_regression_passed",
    ):
        assert local_validation[local_validation_true_field] is True
    for local_validation_false_field in (
        "registry_lookup_invokes_marker_hash_or_equality",
        "relocation_restore_resurrects_authority",
        "independent_review_remaining_blocker",
        "provider_or_network_accessed",
        "operator_attempt_predates_current_hardened_price_lexemes_bytes",
        "fresh_current_byte_live_admissibility_proven",
        "fresh_current_byte_metadata_only_live_rerun_authorized",
        "fresh_current_byte_metadata_only_live_rerun_command_emitted_by_codex",
        "live_route_admissibility_proven",
        "terminal_full_suite_pass_credit",
    ):
        assert local_validation[local_validation_false_field] is False
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
    assert current_inventory["current_reconciliation_commit"] is None
    assert current_inventory["current_reconciliation_commit_pushed"] is False
    assert current_inventory["current_reconciliation_commit_remote_resolved"] is False
    assert current_inventory["current_reconciliation_uncommitted_worktree"] is True
    assert current_inventory["artifact_reconciled_for_slice"] == (
        "V3_PLANADOPT_001_COMPLETE_PROVIDER_FREE_NONAUTHORIZING_CURRENT_AND_NEXT_TICKET_UNSELECTED"
    )
    assert current_inventory["artifact_raw_sha256"] == (
        "adf4593aeaa78df69e8b2f38b6fab3243c666fa92b543fb7a8a2ad5b883d5799"
    )
    assert current_inventory["schema_raw_sha256"] == (
        "1ace15eed74459638a2141aefea6d95e61acad143c2f918ea5d0701a084f39d9"
    )
    assert current_inventory["inventory_sha256"] == (
        "95c9f5d08850956e38f83bb372ee52742b3d0000957609a0f81f0c7d9dce1a40"
    )
    assert current_inventory["source_discovery_semantics_sha256"] == (
        "a27b532fd9164ec0b7ef5bbbf755b986553858795dd624d6e2f54d745c5971df"
    )
    assert current_inventory["source_universe_sha256"] == (
        "642a157eb96853e129b16c7f00c2c311fea5bbd54a68fa002fd0fbe7f0428064"
    )
    assert current_inventory["source_count"] == 4000
    assert current_inventory["source_occurrence_count"] == 4003
    assert current_inventory["gate_source_count"] == 3950
    assert current_inventory["non_gating_source_count"] == 50
    assert current_inventory["completion_entrypoint_parameter_count"] == 343
    assert current_inventory["direct_environment_input_occurrence_count"] == 533
    assert current_inventory["explicit_non_field_gate_occurrence_count"] == 2128
    assert current_inventory["audited_module_universe_occurrence_count"] == 260
    assert current_inventory["logical_gate_count"] == 35
    assert current_inventory["unsatisfied_gate_count"] == 29
    assert current_inventory["current_manual_gate_count"] == 15
    for current_inventory_false_authority_field in (
        "provider_or_network_accessed",
        "secret_material_read",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert current_inventory[current_inventory_false_authority_field] is False
    assert (
        "V3_PLANADOPT_001_COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
        in (current_inventory["current_execution_status"])
    )
    assert (
        "ACTIVE_REPOSITORY_PLAN_SCHEMA_1_7_NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
        in (current_inventory["current_execution_status"])
    )
    assert "V1_PROFILE_PRESERVED_NO_V2_ADOPTION" in current_inventory["current_execution_status"]
    assert "V3_PLANADOPT_001_COMPLETE" in current_inventory["current_execution_status"]
    assert "V3_PRICECAPCACHE_001_LAST_PARTIAL" in current_inventory["current_execution_status"]
    assert (
        "HISTORICAL_V3_AUTONOMY_001_PARTIAL_PRESERVED"
        in (current_inventory["current_execution_status"])
    )
    assert (
        "OPERATOR_REPORTED_PRIVATE_V2_PLAN_96CC5301_EXERCISED_METADATA_ONLY"
        in (current_inventory["current_execution_status"])
    )
    assert "UNSELECTED_UNADOPTED" in current_inventory["current_execution_status"]
    assert "CURRENT_AND_NEXT_TICKET_UNSELECTED" in current_inventory["current_execution_status"]
    assert (
        "ALL_PROVIDER_COMMAND_CANDIDATE_ROUTE_CAMPAIGN_RUN_INDEX_QUALIFICATION_RUNTIME_AUDIT_"
        "RELEASE_AND_AUTHORITY_STATE_FALSE_OR_UNCHANGED"
        in current_inventory["current_execution_status"]
    )
    assert "COMBINED_UNFINISHED_TICKET_COUNT_41" in current_inventory["current_execution_status"]
    assert current_inventory["current_execution_next_action"].startswith(
        "STOP_WITH_CURRENT_AND_NEXT_LOCAL_TICKET_UNSELECTED_AFTER_V3_PLANADOPT_001_COMPLETE_CLOSURE"
    )
    assert runtime_status["candidate_commit_pushed"] is True
    assert runtime_status["candidate_commit_remote_resolved"] is True
    operator_reconciliation = runtime_status["current_operator_result_reconciliation"]
    assert operator_reconciliation["critical_path_ticket"] == "UNSELECTED"
    assert operator_reconciliation["operator_results_sha256"] == CURRENT_OPERATOR_RESULTS_SHA256
    assert operator_reconciliation["operator_results_bytes"] == 190_177
    assert operator_reconciliation["operator_results_lines"] == 3_377
    assert operator_reconciliation["latest_entry_timestamp"] == "2026-09-04T03:39Z"
    assert operator_reconciliation["operator_results_repository_commit"] == (
        CURRENT_OPERATOR_RESULTS_REPOSITORY_COMMIT
    )
    for current_operator_true_field in (
        "operator_supplied",
        "operator_verified_active_schema_1_7_no_candidate",
        "operator_verified_revoked_active_pin_removed",
        "operator_verified_v1_profile_retained_and_v2_not_adopted",
        "operator_observed_authenticated_ancestry_transition_gate",
        "authenticated_ancestry_transition_deferred_to_future_bounded_ticket",
        "operator_should_stop_probing_ancestry_transition",
    ):
        assert operator_reconciliation[current_operator_true_field] is True
    assert operator_reconciliation["independently_authenticated_by_codex"] is False
    assert operator_reconciliation["supported_authenticated_ancestry_transition_exists"] is False
    assert operator_reconciliation["current_active_plan_to_v2_supported_path_available"] is False
    assert operator_reconciliation["historical_v1_predecessor_to_v2_selection_path_available"]
    assert operator_reconciliation[
        "historical_v1_predecessor_operator_facing_v2_selection_command_available"
    ]
    assert operator_reconciliation[
        "production_v2_activation_deferred_to_future_separately_selected_ticket"
    ]
    assert operator_reconciliation["active_repository_plan_schema_version"] == "1.7"
    assert operator_reconciliation["active_repository_plan_sha256"] == ACTIVE_SELECTION_PLAN_SHA256
    assert operator_reconciliation["active_repository_plan_raw_sha256"] == (
        ACTIVE_SELECTION_PLAN_RAW_SHA256
    )
    assert operator_reconciliation["active_repository_plan_has_active_candidate"] is False
    assert operator_reconciliation["active_repository_plan_retains_v1_price_cap_profile"] is True
    assert operator_reconciliation["global_ledger_entry_count"] == 57
    assert operator_reconciliation["global_ledger_spent_usd_exact"] == "0.68118684"
    assert operator_reconciliation["completed_real_audits"] == 0
    assert operator_reconciliation["pricecaptier_ticket"] == "V3-PRICECAPTIER-001"
    assert operator_reconciliation["pricecaptier_ticket_status"] == (
        "PARTIAL_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert (
        operator_reconciliation["pricecaptier_exact_decimal_schedule_maximum_implemented"] is True
    )
    assert operator_reconciliation["pricecaptier_primary_acceptance_met"] is False
    assert operator_reconciliation["modelrefresh_ticket"] == "V3-MODELREFRESH-001"
    assert operator_reconciliation["modelrefresh_ticket_status"] == (
        "PARTIAL_TERMINAL_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation["modelrefresh_exact_ordered_schedule_retained"] is True
    assert operator_reconciliation["modelrefresh_equal_maximum_threshold_drift_detected"] is True
    assert (
        operator_reconciliation["modelrefresh_live_route_preflight_supports_tiered_schedules"]
        is True
    )
    assert operator_reconciliation["modelrefresh_xai_route_admissible"] is False
    assert operator_reconciliation["pricekeyorder_ticket"] == "V3-PRICEKEYORDER-001"
    assert operator_reconciliation["pricekeyorder_ticket_status"] == "WITHDRAWN_OPERATOR_ERROR"
    assert operator_reconciliation["pricekeyorder_prior_diagnosis_retracted_by_operator"] is True
    assert operator_reconciliation["pricekeyorder_prior_diagnosis_bypassed_provider_ingest"] is True
    assert operator_reconciliation["pricekeyorder_operator_requested_withdrawal"] is True
    assert operator_reconciliation["pricekeyorder_full_ingest_permutation_count"] == 120
    assert operator_reconciliation["pricekeyorder_full_ingest_distinct_pricing_hash_count"] == 1
    assert operator_reconciliation["pricekeyorder_full_ingest_distinct_snapshot_hash_count"] == 1
    assert operator_reconciliation["pricekeyorder_selected"] is False
    assert operator_reconciliation["pricekeyorder_implementation_started"] is False
    assert operator_reconciliation["priceoverrides_ticket"] == "V3-PRICEOVERRIDES-001"
    assert operator_reconciliation["priceoverrides_ticket_status"] == (
        "COMPLETE_PROVIDER_FREE_NONAUTHORIZING"
    )
    assert operator_reconciliation["priceoverrides_typed_override_tier_model_implemented"] is True
    assert (
        operator_reconciliation[
            "priceoverrides_pricing_schedule_sha256_binds_base_and_ordered_tiers"
        ]
        is True
    )
    assert operator_reconciliation["priceoverrides_flat_endpoint_evidence_byte_identical"] is True
    assert operator_reconciliation["priceoverrides_tiered_pricing_cost_projection"] == (
        "unavailable"
    )
    for operator_reconciliation_refusal_field in (
        "priceoverrides_provider_free_preview_refuses_conditional_cost_authority",
        "priceoverrides_endpoint_registration_refuses_conditional_cost_authority",
        "priceoverrides_identity_sealing_refuses_conditional_cost_authority",
        "priceoverrides_model_refresh_refuses_schedule_instead_of_dropping_it",
        "priceoverrides_full_models_discover_recorded_shape_reaches_route_predicates",
    ):
        assert operator_reconciliation[operator_reconciliation_refusal_field] is True
    assert operator_reconciliation["priceoverrides_full_models_discover_failure_reasons"] == [
        "PRICE_CAP_NOT_EXPRESSIBLE",
        "PRICE_CAP_PROOF_UNAVAILABLE",
    ]
    assert operator_reconciliation["priceoverrides_focused_tests_passed"] == 56
    for operator_reconciliation_false_authority_field in (
        "priceoverrides_grants_authority",
        "priceoverrides_qualification_runtime_audit_or_release_authority",
        "priceoverrides_provider_or_network_accessed_by_codex",
        "priceoverrides_operator_command_emitted_by_codex",
        "priceoverrides_run_index_selected_or_inferred",
        "candidate_price_overrides_ticket_selected",
        "candidate_price_overrides_grants_authority",
        "candidate_price_overrides_qualification_runtime_audit_or_release_authority",
        "candidate_price_overrides_provider_or_network_accessed_by_codex",
        "candidate_price_overrides_operator_command_emitted_by_codex",
        "candidate_price_overrides_run_index_selected_or_inferred",
        "candidate_conditional_future_route_currently_admissible",
        "candidate_conditional_future_route_selected",
        "candidate_replacement_selected",
        "current_selection_plan_candidate_runnable",
        "current_exact_campaign_command_available",
        "current_campaign_run_index_stated",
        "provider_or_network_accessed_by_codex",
        "credential_or_secret_material_accessed_by_codex",
        "operator_private_ledger_accessed_or_mutated_by_codex",
        "authority",
    ):
        assert operator_reconciliation[operator_reconciliation_false_authority_field] is False
    assert "V3-LINEAGE-001" not in requirements["L"]["tickets"]
    assert "V3-AUTHLINEAGE-RECEIPT-001" not in requirements["L"]["tickets"]
    assert "V3-PLANCONSTRAINTS-001" in requirements["L"]["tickets"]
    assert "V3-RUNTIMEADMIT-001" in requirements["L"]["tickets"]
    assert "V3-ENDPOINTLIST-001" in requirements["L"]["tickets"]
    assert "V3-HUMANCMP-001" not in requirements["R"]["tickets"]
    assert (
        "The optional human-comparison tier is not required"
        in (requirements["R"]["remaining_proof"])
    )
    assert "OBJECTIVE_OUT_OF_SCOPE" in runtime_status["blocked_tickets"]["V3-LINEAGE-001"]
    calibration_block = runtime_status["blocked_tickets"]["V3-CALIBRATE-001"]
    assert "V3-CALIBRATE-001 remains BLOCKED_TECHNICAL" in calibration_block
    assert "calibrated P2 plus successor C2" in calibration_block
    assert "V3-PLANADOPT-001 is the last COMPLETE provider-free ticket" in calibration_block
    assert CURRENT_OPERATOR_RESULTS_SHA256 in calibration_block
    assert "no supported transition exists today" in calibration_block
    assert "future separately selected bounded ticket" in calibration_block
    assert "private V2 plan" in calibration_block
    assert "genuinely exercised in metadata-only discovery" in calibration_block
    assert "active schema-1.7 plan has no active candidate and retains the exact V1 profile" in (
        calibration_block
    )
    assert "V3-PRICECAPCACHE-001 is last PARTIAL" in calibration_block
    assert "Historical V3-AUTONOMY-001 remains PARTIAL" in calibration_block
    assert "all external provisioning and zero-input audit criteria remain unmet" in (
        calibration_block
    )
    assert "V3-MODELREFRESH-001" in calibration_block
    assert "V3-PRICELEXEME-001" in calibration_block
    assert "V3-TESTQUALITY-001" in calibration_block
    assert "V3-CANDROUTE-001 remain PARTIAL" in calibration_block
    assert "active plan, retry behavior, configuration" in calibration_block.lower()
    assert "57-entry / 0.68118684 USD operator ledger" in calibration_block
    assert "zero completed real audits" in calibration_block
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

    assert len(ticket_id_list) == len(ticket_ids) == 92
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
        "V3-CANDROUTE-001",
        "V3-DEVAUDIT-001",
        "V3-DEVBENCH-001",
        "V3-DEVCOMPARE-001",
        "V3-DEVDECODE-001",
        "V3-DEVTELEMETRY-001",
        "V3-DEVREASON-001",
        "V3-DEVROUTE-001",
        "V3-DEVSCHALIGN-001",
        "V3-ENDPOINTLIST-001",
        "V3-EFFORT-001",
        "V3-EVIDENCEFORMAT-001",
        "V3-EXECORIGIN-001",
        "V3-FLOOR-001",
        "V3-FORKDIFF-001",
        "V3-GOVSYNC-002",
        "V3-IDENTITY-001",
        "V3-OBJECTIVE-002",
        "V3-OMISSION-001",
        "V3-OUTPUT-001",
        "V3-PIPEPERF-001",
        "V3-PLANCONSTRAINTS-001",
        "V3-PRICELEXEME-001",
        "V3-PRICEOVERRIDES-001",
        "V3-PRICECAPTIER-001",
        "V3-PRICECAPCOMP-001",
        "V3-PRICECAPCACHE-001",
        "V3-PRICEKEYORDER-001",
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
