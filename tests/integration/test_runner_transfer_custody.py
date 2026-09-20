"""Local ledger/native-negative integration, with explicitly isolated runner ownership."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from mmaudit.models.authenticated_calibration import (
    AuthenticatedCalibrationCandidateInputs,
    observe_authenticated_model_calibration,
)
from mmaudit.models.authenticated_runner import (
    _require_closed_cross_lineage_ledger_interval,
    issue_verified_cross_lineage_runner_custody,
)
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_runner_custody_transfer import (
    IsolatedRunner,
    assert_children_disposed,
    assert_source_consumed,
    isolated_function,
    require_children,
)
from tests.unit.test_runner_custody_transfer import isolated_runner as isolated_runner


def append_cost(subject: IsolatedRunner, mode: str) -> None:
    reservation = subject.ledger.reserve("synthetic-later-work", Decimal("1"))
    if mode == "known":
        subject.ledger.reconcile(reservation, Decimal("0.5"))
    elif mode == "unknown":
        subject.ledger.commit_for_transport(reservation)
        subject.ledger.reconcile(reservation, None)
    else:
        assert mode == "reserved"


@pytest.mark.parametrize("mode", ("known", "reserved", "unknown"))
def test_transfer_does_not_extend_original_exact_ledger_lifetime(
    isolated_runner: IsolatedRunner, forbid_network_and_secrets: list[str], mode: str
) -> None:
    subject = isolated_runner
    successor, _runs = subject.transfer(subject.original, evidence=subject.evidence)
    state = subject.registry.snapshot(successor).state
    append_cost(subject, mode)
    raw = subject.ledger.path.read_bytes()
    with pytest.raises(ValueError, match=r"ledger changed|non-overrun"):
        subject.require(successor, evidence=subject.evidence)
    with pytest.raises(ValueError, match=r"ledger changed|non-overrun"):
        _require_closed_cross_lineage_ledger_interval(state.closed_ledger_interval)
    subject.revoke(successor)
    assert_source_consumed(subject)
    assert_children_disposed(state)
    assert subject.ledger.path.read_bytes() == raw
    assert forbid_network_and_secrets == []


def test_ledger_change_during_move_disposes_successor_without_discarding_cost(
    isolated_runner: IsolatedRunner, forbid_network_and_secrets: list[str]
) -> None:
    subject = isolated_runner
    states: list[Any] = []

    def require(capability: Any, **kwargs: Any) -> Any:
        if capability is not subject.original:
            states.append(subject.registry.snapshot(capability).state)
            append_cost(subject, "unknown")
        return subject.require(capability, **kwargs)

    move = isolated_function(subject.transfer, require=require)
    with pytest.raises(ValueError, match="ledger changed"):
        move(subject.original, evidence=subject.evidence)
    assert_source_consumed(subject)
    assert subject.registry._entries == {}
    assert_children_disposed(states[0])
    entry = next(
        item
        for item in subject.ledger.snapshot().entries
        if item.request_id == "synthetic-later-work"
    )
    assert entry.actual_cost_usd is None
    assert entry.accounted_cost_usd == Decimal("1")
    assert forbid_network_and_secrets == []


def test_native_calibration_never_accepts_isolated_moved_runner_custody(
    isolated_runner: IsolatedRunner, forbid_network_and_secrets: list[str]
) -> None:
    subject = isolated_runner
    successor, runs = subject.transfer(subject.original, evidence=subject.evidence)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        observe_authenticated_model_calibration(
            selected_model_ids=(subject.evidence.runs[0].candidate_model_id,),
            benchmark_suite=subject.live.suite,
            ground_truth=subject.live.ground_truth,
            inputs=(AuthenticatedCalibrationCandidateInputs(successor, subject.evidence, runs),),
        )
    subject.revoke(successor)
    assert forbid_network_and_secrets == []


def test_structural_children_still_cannot_issue_a_native_runner(
    isolated_runner: IsolatedRunner, forbid_network_and_secrets: list[str]
) -> None:
    subject = isolated_runner
    with pytest.raises(ValueError, match="owned REAL transport origin"):
        issue_verified_cross_lineage_runner_custody(
            public_lineage_capability=subject.live.public_lineage,
            ground_truth_capability=subject.live.ground_truth,
            benchmark_suite=subject.live.suite,
            runs=subject.state.runs,
            closed_ledger_interval=subject.state.closed_ledger_interval,
        )
    require_children(subject.state.runs)
    assert forbid_network_and_secrets == []
