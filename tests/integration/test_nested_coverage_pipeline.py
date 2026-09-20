"""Automatic nested coverage uses only synthetic in-memory transport and retains every liability."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.constants import ExitCode
from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.truncation import CandidateReviewChannelState, frame_candidate_review_batch
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryChildResult
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter, _candidate, _surface_reviews
from tests.integration.test_pipeline import _run
from tests.integration.test_recursive_retained_bridge_pipeline import (
    retained_bridge_repo as retained_bridge_repo,
)
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _one_whole_protocol_config,
    _recovery_entries,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot

RETAINED_IDS = ("nested-coverage-first", "nested-coverage-second")


class NestedFindingsFake(FakeOpenRouter):
    def __init__(self, state: CandidateReviewChannelState) -> None:
        super().__init__(mode="truncation_recovery_recursive")
        self.findings_state = state

    def _completion(
        self,
        body: dict[str, Any],
        content: str,
        *,
        finish_reason: str = "stop",
        native_finish_reason: str = "stop",
    ) -> httpx.Response:
        metadata = body.get("metadata") or {}
        request_id = metadata.get("mmaudit_request_id", "")
        if (
            isinstance(request_id, str)
            and request_id.startswith("scheduler-recovery-request-")
            and self.recovery_child_calls == 1
            and finish_reason == "length"
        ):
            role = metadata["mmaudit_role"]
            surfaces = _surface_reviews(body["messages"][1]["content"], role=role)
            assert len(surfaces) >= 3
            findings = [
                _candidate(candidate_id=identity, role=role)
                for identity in (*RETAINED_IDS, "nested-coverage-invalid")
            ]
            batch = CandidateReviewBatch.model_validate(
                {"findings": findings, "surface_reviews": surfaces}
            )
            frames = frame_candidate_review_batch(batch).model_dump(mode="json")["frames"]
            if self.findings_state is CandidateReviewChannelState.INVALID:
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
        return super()._completion(
            body, content, finish_reason=finish_reason, native_finish_reason=native_finish_reason
        )


@pytest.mark.parametrize("request_id", (None, False, 0, "ordinary-request"))
def test_fixture_leaves_nonrecovery_completion_unchanged(request_id: Any) -> None:
    fake = NestedFindingsFake(CandidateReviewChannelState.OPEN)
    response = fake._completion(
        {"model": "alpha/atlas-secure", "metadata": {"mmaudit_request_id": request_id}}, "{}"
    )
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "{}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state", (CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID)
)
@pytest.mark.parametrize("request_limit", (4, 5))
async def test_pipeline_selects_only_bounded_noncrediting_nested_coverage_and_resumes_original_owner(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    retained_bridge_repo: Path,
    tmp_path: Path,
    state: CandidateReviewChannelState,
    request_limit: int,
) -> None:
    config = _one_whole_protocol_config(
        config_factory, monkeypatch, max_requests_per_agent=request_limit
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    output = tmp_path / "synthetic-output"
    fake = NestedFindingsFake(state)
    first = await _run(
        config, retained_bridge_repo, tmp_path, fake, cost_ledger=ledger, output=output
    )
    assert first.exit_code is ExitCode.INCOMPLETE and not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == (4 if request_limit == 5 else 2)
    entries = _recovery_entries(first.run_dir)
    families = [e for e in entries if e["entry_kind"] == "FAMILY_ROOT"]
    closures = [e for e in entries if e["entry_kind"] == "FAMILY_CLOSED"]
    results = [e for e in entries if e["entry_kind"] == "CHILD_TERMINAL"]
    activations = [e for e in entries if e["entry_kind"] == "CHILD_ACTIVATED"]
    assert not any(e["entry_kind"] == "FAMILY_PROMOTED" for e in entries)
    assert families[0]["schema_version"] == "1.0"
    bridge = next(e for e in results if e["terminal_status"] == "TRUNCATED")
    assert bridge["truncation_projection"]["findings_state"] == state.value
    assert (
        tuple(f["candidate_id"] for f in bridge["truncation_projection"]["findings"])
        == RETAINED_IDS
    )
    typed_bridge = SchedulerTruncationRecoveryChildResult.model_validate_json(
        json.dumps(bridge), strict=True
    )
    assert typed_bridge.runtime_output_artifact is None
    assert typed_bridge.runtime_specialist_accepted_outcome is None
    assert len(families) == len(closures) == (2 if request_limit == 5 else 1)
    if request_limit == 5:
        nested = families[1]
        assert nested["schema_version"] == "1.1"
        assert nested["parent_terminal_result_sha256"] == bridge["entry_sha256"]
        assert nested["truncation_projection"] == bridge["truncation_projection"]
        assert nested["recovery_plan"]["irreducible_channels"] == ["findings"]
        assert nested["request_limit_binding"] == families[0]["request_limit_binding"]
        children = nested["recovery_plan"]["children"]
        covered = [surface for child in children for surface in child["surface_ids"]]
        assert len(covered) == len(set(covered))
        assert set(covered) == set(nested["recovery_plan"]["parent"]["unfinished_surface_ids"])
        assert set(covered).isdisjoint(bridge["retained_surface_ids"])
        assert closures[0]["closure_status"] == "COVERAGE_CLOSED"
        assert closures[1]["closure_status"] == "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING"
    else:
        assert closures[0]["closure_status"] == "INCOMPLETE"
    assert all(
        not e["completion_authorized"] and not e["review_credit_authorized"]
        for e in (*families, *closures)
    )
    assert [e["global_request_ordinal"] for e in activations] == list(
        range(1, len(activations) + 1)
    )
    assert max(e["request_limit_count_after_child"] for e in activations) <= request_limit
    snapshot = ledger.snapshot()
    recovery_ids = {e["child_logical_request_id"] for e in results}
    charges = [e for e in snapshot.entries if e.request_id in recovery_ids]
    assert len(charges) == len(results) == fake.recovery_child_calls
    assert all(
        e.actual_cost_usd == e.accounted_cost_usd == Decimal("0.001")
        and e.accounted_cost_usd <= e.reserved_usd
        for e in charges
    )
    inventory = _candidate_and_surface_inventory(first.run_dir)
    assert all(identity.encode() not in inventory[0] for identity in RETAINED_IDS)
    owner = first.run_dir / "private" / "scheduler-journal"
    original_files = _journal_private_file_snapshot(owner)
    resumed_fake = NestedFindingsFake(state)
    resumed = await _run(
        config,
        retained_bridge_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE and not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert _recovery_entries(first.run_dir) == entries
    assert _journal_private_file_snapshot(owner) == original_files
    assert ledger.snapshot() == snapshot
    assert _candidate_and_surface_inventory(resumed.run_dir) == inventory
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)
