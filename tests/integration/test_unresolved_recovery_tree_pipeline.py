"""Original automatic mixed-version recovery retains unresolved findings without audit credit."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.token_planning import ContextTokenPlanError, build_output_token_allocations
from mmaudit.models.truncation import CandidateReviewChannelState, frame_candidate_review_batch
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryChildResult
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter, _candidate, _surface_reviews
from tests.integration.test_generic_truncation_tree_pipeline import _extend_synthetic_scope
from tests.integration.test_pipeline import _run
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _one_whole_protocol_config,
    _recovery_entries,
    _truncated_parent_attempt,
)
from tests.integration.test_specialist_truncation_pipeline import (
    _assert_original_specialist_terminals,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot
from tests.unresolved_recovery_tree_support import TreeScenario, tree_scenarios


def _tree_config(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    case: TreeScenario,
    *,
    output_tokens: int | None = None,
) -> AuditConfig:
    specialist = case.role.startswith("specialist:")
    original = _one_whole_protocol_config(
        config_factory,
        monkeypatch,
        specialist=specialist,
        specialist_role=case.role.partition(":")[2] if specialist else "access_control",
        max_requests_per_agent=case.request_limit,
    )
    values = original.model_dump(mode="python")
    if output_tokens is not None:
        values["execution"]["max_output_tokens_per_request"] = output_tokens
    elif case.pattern == "MIXED":
        # 33 surfaces require more than the base fixture's 2,048-token allocation.
        # This is a validated synthetic run allocation, not a production-limit change.
        values["execution"]["max_output_tokens_per_request"] = 4_096
    return AuditConfig.model_validate(values).effective()


class UnresolvedTreeFake(FakeOpenRouter):
    """Select bounded synthetic response shapes; never replace a production custody check."""

    def __init__(self, scenario: TreeScenario) -> None:
        super().__init__(
            mode=(
                "truncation_recovery_specialist_tree"
                if scenario.role.startswith("specialist:")
                else "truncation_recovery_tree"
            )
        )
        self.scenario = scenario
        self.retained_ids_by_request: dict[str, tuple[str, str]] = {}

    def _completion(
        self,
        body: dict[str, Any],
        content: str,
        *,
        finish_reason: str = "stop",
        native_finish_reason: str = "stop",
    ) -> httpx.Response:
        metadata = body.get("metadata") or {}
        request_id = metadata.get("mmaudit_request_id")
        if isinstance(request_id, str) and request_id.startswith("scheduler-recovery-request-"):
            role = metadata["mmaudit_role"]
            assert role == self.scenario.role
            surfaces = _surface_reviews(body["messages"][1]["content"], role=role)
            state = self.scenario.child_state(len(surfaces))
            if state is None:
                # Some declared leaves have two surfaces, unlike the base one-surface fake.
                batch = CandidateReviewBatch.model_validate(
                    {"findings": [], "surface_reviews": surfaces}
                )
                content = frame_candidate_review_batch(batch).model_dump_json()
                finish_reason = native_finish_reason = "stop"
            elif state is not CandidateReviewChannelState.COMPLETE:
                ids = (
                    f"unresolved-{self.recovery_child_calls:04d}-first",
                    f"unresolved-{self.recovery_child_calls:04d}-second",
                )
                assert request_id not in self.retained_ids_by_request
                self.retained_ids_by_request[request_id] = ids
                batch = CandidateReviewBatch.model_validate(
                    {
                        "findings": [
                            _candidate(candidate_id=identity, role=role)
                            for identity in (*ids, "synthetic-invalid-tail")
                        ],
                        "surface_reviews": surfaces,
                    }
                )
                frames = frame_candidate_review_batch(batch).model_dump(mode="json")["frames"]
                if state is CandidateReviewChannelState.INVALID:
                    frames[3]["record"]["confidence"] = "synthetic-invalid-confidence"
                    count, phase, partial = 6, "SURFACE_REVIEW", '"surface_id":"synthetic-partial'
                else:
                    count, phase, partial = 3, "FINDING", '"candidate_id":"synthetic-partial'
                content = (
                    '{"frames":['
                    + ",".join(
                        json.dumps(frame, sort_keys=True, separators=(",", ":"))
                        for frame in frames[:count]
                    )
                    + ',{"schema_version":"1.0","sequence":'
                    + str(count)
                    + ',"phase":"'
                    + phase
                    + '","record":{'
                    + partial
                )
                finish_reason, native_finish_reason = "length", "max_tokens"
            else:
                assert finish_reason == "length"
        return super()._completion(
            body, content, finish_reason=finish_reason, native_finish_reason=native_finish_reason
        )


@pytest.mark.parametrize("request_id", (None, False, 0, "ordinary-request"))
def test_fixture_does_not_reinterpret_nonrecovery_requests(request_id: Any) -> None:
    fake = UnresolvedTreeFake(tree_scenarios()[0])
    response = fake._completion(
        {"model": "alpha/atlas-secure", "metadata": {"mmaudit_request_id": request_id}}, "{}"
    )
    assert response.json()["choices"][0]["message"]["content"] == "{}"
    assert not fake.retained_ids_by_request
    assert fake.chat_calls == fake.recovery_child_calls == 0


def test_mixed_fixture_reserves_every_original_output_channel_minimum() -> None:
    with pytest.raises(ContextTokenPlanError, match="surface output is infeasible"):
        build_output_token_allocations(required_output_tokens=2_048, requested_surface_count=33)
    allocations = build_output_token_allocations(
        required_output_tokens=4_096, requested_surface_count=33
    )
    assert sum(a.minimum_reserved_tokens for a in allocations) == 3_648
    assert sum(a.reserved_tokens for a in allocations) == 4_096


@pytest.mark.parametrize(
    "case", tuple(case for case in tree_scenarios() if case.pipeline), ids=lambda case: case.name
)
@pytest.mark.asyncio
async def test_automatic_unresolved_tree_preserves_original_scope_costs_roles_and_resume(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
    case: TreeScenario,
) -> None:
    _extend_synthetic_scope(vulnerable_repo, sources=case.sources)
    specialist = case.role.startswith("specialist:")
    role = case.role.partition(":")[2] if specialist else "access_control"
    config = _tree_config(config_factory, monkeypatch, case)
    ledger_path = tmp_path / "synthetic-ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path, cap_usd=Decimal(str(config.execution.budget_usd))
    )
    output = tmp_path / "synthetic-output"
    fake = UnresolvedTreeFake(case)
    first = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output)
    assert first.exit_code is ExitCode.INCOMPLETE and not first.report.completed
    assert fake.specialist_truncation_calls == int(specialist)
    assert fake.truncated_parent_calls == int(not specialist)
    assert fake.recovery_child_calls == case.expected_children
    entries = _recovery_entries(first.run_dir)
    families = tuple(e for e in entries if e["entry_kind"] == "FAMILY_ROOT")
    closures = tuple(e for e in entries if e["entry_kind"] == "FAMILY_CLOSED")
    results = tuple(e for e in entries if e["entry_kind"] == "CHILD_TERMINAL")
    activations = tuple(e for e in entries if e["entry_kind"] == "CHILD_ACTIVATED")
    assert len(results) == len(activations) == case.expected_children
    assert len(families) == len(closures) == case.expected_children // 2
    assert max(c["depth"] for f in families for c in f["recovery_plan"]["children"]) == (
        case.expected_depth
    )
    assert len(families[0]["recovery_plan"]["parent"]["requested_surface_ids"]) == case.sources
    assert families[0]["schema_version"] == "1.0"
    assert [e["global_request_ordinal"] for e in activations] == list(range(1, len(results) + 1))
    assert max(e["request_limit_count_after_child"] for e in activations) == len(results) + 1
    assert len(results) + 1 <= case.request_limit
    parent = _truncated_parent_attempt(first.run_dir)
    parent_id = parent["usage_record"]["request_id"]
    assert parent["usage_record"]["role"] == case.role
    result_by_task = {r["child_task_id"]: r for r in results}
    for family in families:
        assert family["request_limit_binding"] == families[0]["request_limit_binding"]
        assert family["request_limit_id"] == parent_id
        plan_parent = family["recovery_plan"]["parent"]
        surfaces = [s for c in family["recovery_plan"]["children"] for s in c["surface_ids"]]
        assert sorted(surfaces) == plan_parent["unfinished_surface_ids"]
        assert len(surfaces) == len(set(surfaces))
        assert set(surfaces).isdisjoint(plan_parent["retained_surface_ids"])
        if family.get("parent_family_id") is not None:
            bridge = result_by_task[plan_parent["parent_task_id"]]
            assert family["parent_terminal_result_sha256"] == bridge["entry_sha256"]
            assert family["truncation_projection"] == bridge["truncation_projection"]
            complete = family["truncation_projection"]["findings_state"] == "COMPLETE"
            assert family["schema_version"] == ("1.0" if complete else "1.1")
            assert family["recovery_plan"]["irreducible_channels"] == (
                [] if complete else ["findings"]
            )
    if specialist:
        assert _assert_original_specialist_terminals(entries, role=role) == results
    for result in results:
        typed = SchedulerTruncationRecoveryChildResult.model_validate_json(
            json.dumps(result), strict=True
        )
        assert typed.runtime_usage_record is not None and typed.runtime_activation is not None
        assert typed.runtime_usage_record.role == typed.runtime_activation.request_role == case.role
        state = case.child_state(len(typed.child_surface_ids))
        if state is None:
            assert typed.terminal_status.value == "SUCCEEDED"
            assert typed.completed_surface_ids == typed.child_surface_ids
        else:
            assert typed.terminal_status.value == "TRUNCATED"
            assert typed.truncation_projection is not None
            assert typed.truncation_projection.findings_state is state
            assert typed.completed_surface_ids == ()
            assert typed.runtime_output_artifact is None
            assert typed.runtime_specialist_accepted_outcome is None
            if state is not CandidateReviewChannelState.COMPLETE:
                assert (
                    tuple(f.candidate_id for f in typed.truncation_projection.findings)
                    == (fake.retained_ids_by_request[typed.child_logical_request_id])
                )
                assert len(typed.retained_surface_ids) == int(
                    state is CandidateReviewChannelState.INVALID
                )
    assert closures[-1]["family_id"] == families[0]["family_id"]
    assert closures[-1]["closure_status"] == (
        "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING" if case.fully_covered else "INCOMPLETE"
    )
    if case.fully_covered:
        closures_by_family = {c["family_id"]: c for c in closures}
        for family in families:
            assert (
                closures_by_family[family["family_id"]]["covered_unfinished_surface_ids"]
                == (family["recovery_plan"]["parent"]["unfinished_surface_ids"])
            )
    if case.pattern == "MIXED":
        assert {f["schema_version"] for f in families} == {"1.0", "1.1"}
        assert {f["truncation_projection"]["findings_state"] for f in families} == {
            "COMPLETE",
            "OPEN",
            "INVALID",
        }
    assert all(
        not e["completion_authorized"] and not e["review_credit_authorized"]
        for e in (*families, *closures)
    )
    assert not any(e["entry_kind"] == "FAMILY_PROMOTED" for e in entries)
    snapshot = ledger.snapshot()
    request_ids = {parent_id, *(r["child_logical_request_id"] for r in results)}
    charges = tuple(e for e in snapshot.entries if e.request_id in request_ids)
    assert len(charges) == len(results) + 1
    assert all(
        e.actual_cost_usd == e.accounted_cost_usd == Decimal("0.001")
        and e.accounted_cost_usd <= e.reserved_usd
        for e in charges
    )
    inventory = _candidate_and_surface_inventory(first.run_dir)
    assert b"unresolved-" not in inventory[0]
    assert b"scheduler-recovery-request-" not in inventory[1]
    specialist_bytes = (first.run_dir / "specialist-execution.json").read_bytes()
    if specialist:
        record = next(r for r in json.loads(specialist_bytes)["records"] if r["role"] == role)
        assert record["status"] == "failed"
        assert record["successful_requests"] == record["source_review_creditable_requests"] == 0
        assert record["accepted_outcomes"] == []
        assert set(record["failed_request_ids"]) == request_ids
    owner = first.run_dir / "private" / "scheduler-journal"
    original_files = _journal_private_file_snapshot(owner)
    ledger_bytes = ledger_path.read_bytes()
    resumed_fake = UnresolvedTreeFake(case)
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE and not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert resumed_fake.truncated_parent_calls == resumed_fake.specialist_truncation_calls == 0
    assert not resumed_fake.retained_ids_by_request
    assert _recovery_entries(first.run_dir) == entries
    assert _journal_private_file_snapshot(owner) == original_files
    assert ledger.snapshot() == snapshot and ledger_path.read_bytes() == ledger_bytes
    assert _candidate_and_surface_inventory(resumed.run_dir) == inventory
    assert (resumed.run_dir / "specialist-execution.json").read_bytes() == specialist_bytes
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)


@pytest.mark.asyncio
async def test_mixed_tree_cannot_dispatch_with_insufficient_original_output_allocation(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    case = next(c for c in tree_scenarios() if c.name == "mixed-specialist")
    _extend_synthetic_scope(vulnerable_repo, sources=case.sources)
    config = _tree_config(config_factory, monkeypatch, case, output_tokens=2_048)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-low-output-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    fake = UnresolvedTreeFake(case)
    result = await _run(config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger)
    assert result.exit_code is ExitCode.MODEL_FAILURE and not result.report.completed
    assert fake.specialist_truncation_calls == fake.recovery_child_calls == 0
    assert fake.chat_calls == 1  # Only the independent synthetic orientation request completed.
    assert _recovery_entries(result.run_dir) == ()
    metadata = json.loads((result.run_dir / "metadata.json").read_bytes())
    assert any(
        "specialist:false_negative_hunter: provider request cannot satisfy the bounded context plan"
        in reason
        for reason in metadata["incomplete_reasons"]
    )
    assert len(ledger.snapshot().entries) == 1
    assert ledger.snapshot().entries[0].actual_cost_usd == Decimal("0.001")
