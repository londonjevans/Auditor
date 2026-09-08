"""Synthetic cumulative accounting only; unknown charges never become settled or free."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal

import pytest
from pydantic import ValidationError

from mmaudit.models.development_costs import DevelopmentCostError, DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import (
    MAX_UNCERTAIN_RESERVATION_ALLOWANCES,
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostReservationOverrunError,
    CostReservationStateError,
    PortfolioAttemptSlot,
    ReleaseReason,
)
from mmaudit.orchestration.development_budget import (
    DevelopmentBudgetSession,
    DevelopmentCostUncertainError,
    development_uncertain_reservations,
)
from tests.development_audit_support import audit_case
from tests.development_cost_support import development_case


def carry_policy(**changes):
    return DevelopmentCostPolicy.model_validate(
        {
            "overspend_risk_accepted": True,
            "total_budget_usd": Decimal("20"),
            "per_attempt_budget_usd": Decimal("5"),
            "maximum_attempts": 2,
            "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE",
            **changes,
        }
    )


def uncertain_ledger(tmp_path, *, request_id="prior-unknown", amount=Decimal("1")):
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    first = ledger.reserve(request_id, amount)
    ledger.reconcile(first, None)
    return ledger, first


def reserve_development(session, request_id="selected-next", *, attempt=1):
    endpoint, body = development_case()
    return session.reserve(
        endpoint_snapshot=endpoint, request_body=body, request_id=request_id, attempt=attempt
    )


def test_explicit_carry_policy_round_trips_without_changing_default_serialization():
    original = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("20"),
        per_attempt_budget_usd=Decimal("5"),
    )
    assert "uncertain_cost_policy" not in original.model_dump_json()
    carried = DevelopmentCostPolicy.model_validate(
        {**original.model_dump(), "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"}
    )
    assert carried.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
    assert carried == DevelopmentCostPolicy.model_validate_json(carried.model_dump_json())
    assert original.uncertain_cost_policy == "STOP"


def test_atomic_allowance_preserves_full_unknown_liability(tmp_path):
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    first = ledger.reserve("prior-unknown", Decimal("1"))
    unknown = ledger.reconcile(first, None)
    next_hold = ledger.reserve(
        "next-request",
        Decimal("2"),
        require_settled_prior_costs=True,
        allowed_uncertain_reservations=(first,),
    )
    state = ledger.snapshot()
    assert unknown in state.entries and unknown.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert unknown.actual_cost_usd is None and unknown.accounted_cost_usd == Decimal("1")
    assert state.spent_usd == Decimal("1") and state.active_reserved_usd == next_hold.reserved_usd
    assert state.remaining_usd == Decimal("17")


@pytest.mark.parametrize("mode", [None, True, 1, "carry", "SETTLED", [], {}])
def test_invalid_carry_modes_are_not_coerced(mode):
    with pytest.raises(ValidationError):
        carry_policy(uncertain_cost_policy=mode)


@pytest.mark.parametrize("acknowledgement", [False, 1, "true", None])
def test_carry_still_requires_exact_overspend_risk_acceptance(acknowledgement):
    with pytest.raises(ValidationError):
        carry_policy(overspend_risk_accepted=acknowledgement)


def test_carry_is_retained_in_plan_but_never_changes_provider_request_bytes():
    legacy = audit_case()
    selected = audit_case(policy=carry_policy(maximum_attempts=1))
    for old, new in zip(legacy.shards, selected.shards, strict=True):
        assert old.request_content == new.request_content
        assert old.estimate.request_sha256 == new.estimate.request_sha256
        assert (
            old.estimate.estimated_cost_per_attempt_usd
            == new.estimate.estimated_cost_per_attempt_usd
        )
        assert new.estimate.policy.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
        assert new.estimate.provider_enforced_ceiling is False
        assert new.estimate.qualification_eligible is new.estimate.release_eligible is False
    assert "CARRY_RESERVED_ESTIMATE" in selected.plan.model_dump_json()
    assert "uncertain_cost_policy" not in legacy.plan.model_dump_json()


@pytest.mark.parametrize("malformation", ["none", "list", "oversize", "no_settled_guard"])
def test_atomic_allowance_requires_bounded_exact_tuple_and_serialized_guard(tmp_path, malformation):
    ledger, first = uncertain_ledger(tmp_path)
    value = {
        "none": None,
        "list": [first],
        "oversize": (first,) * (MAX_UNCERTAIN_RESERVATION_ALLOWANCES + 1),
        "no_settled_guard": (first,),
    }[malformation]
    before = ledger.path.read_bytes()
    with pytest.raises(CostLedgerConfigurationError):
        ledger.reserve(
            "blocked",
            Decimal("1"),
            require_settled_prior_costs=malformation != "no_settled_guard",
            allowed_uncertain_reservations=value,
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize(
    "malformation", ["object", "id_type", "id", "request", "money", "float", "duplicate"]
)
def test_atomic_allowance_rejects_changed_or_duplicated_handles_without_write(
    tmp_path, malformation
):
    ledger, first = uncertain_ledger(tmp_path)
    value = {
        "object": (object(),),
        "id_type": (replace(first, reservation_id=1),),
        "id": (replace(first, reservation_id="0" * 32),),
        "request": (replace(first, request_id="absent-request"),),
        "money": (replace(first, reserved_usd=Decimal("2")),),
        "float": (replace(first, reserved_usd=1.0),),
        "duplicate": (first, first),
    }[malformation]
    before = ledger.path.read_bytes()
    with pytest.raises((CostLedgerConfigurationError, CostReservationStateError)):
        ledger.reserve(
            "blocked",
            Decimal("1"),
            require_settled_prior_costs=True,
            allowed_uncertain_reservations=value,
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("state", ["reserved", "released", "reconciled", "overrun"])
def test_allowance_is_not_a_capability_to_carry_other_entry_states(tmp_path, state):
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    first = ledger.reserve("first", Decimal("1"))
    if state == "released":
        ledger.release(first, reason=ReleaseReason.FAILED_BEFORE_SEND)
    elif state == "reconciled":
        ledger.reconcile(first, Decimal("0.1"))
    elif state == "overrun":
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(first, Decimal("2"))
    before = ledger.path.read_bytes()
    with pytest.raises(CostReservationStateError, match="stale"):
        ledger.reserve(
            "blocked",
            Decimal("1"),
            require_settled_prior_costs=True,
            allowed_uncertain_reservations=(first,),
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize(
    "blocker", ["pending", "portfolio", "unlisted", "budget", "overrun", "duplicate"]
)
def test_allowance_never_clears_other_atomic_reservation_guards(tmp_path, blocker):
    ledger, first = uncertain_ledger(tmp_path)
    request_id, requested = "next", Decimal("1")
    if blocker == "pending":
        ledger.reserve("pending", Decimal("1"))
    elif blocker == "portfolio":
        ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held-slot", Decimal("1")),))
    elif blocker == "unlisted":
        ledger.reconcile(ledger.reserve("unlisted", Decimal("1")), None)
    elif blocker == "budget":
        requested = Decimal("20")
    elif blocker == "overrun":
        other = ledger.reserve("overrun", Decimal("1"))
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(other, Decimal("2"))
    else:
        request_id = first.request_id
    before = ledger.path.read_bytes()
    with pytest.raises((CostBudgetExceededError, CostReservationStateError)):
        ledger.reserve(
            request_id,
            requested,
            require_settled_prior_costs=True,
            allowed_uncertain_reservations=(first,),
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("same_request", [False, True])
def test_development_continuation_keeps_history_and_requires_each_explicit_attempt(
    tmp_path, restart, same_request
):
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    session = DevelopmentBudgetSession(policy=carry_policy(), ledger=ledger)
    first = reserve_development(session, "first")
    with pytest.raises(DevelopmentCostUncertainError):
        session.reconcile(first, actual_cost_usd=None)
    prior = ledger.snapshot().entries[0]
    raw_prior = json.loads(ledger.path.read_bytes())["entries"][prior.request_id]
    if restart:
        ledger = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20"))
        session = DevelopmentBudgetSession(policy=carry_policy(), ledger=ledger)
    second = reserve_development(
        session, "first" if same_request else "second", attempt=2 if same_request else 1
    )
    session.reconcile(second, actual_cost_usd=Decimal("0.01"))
    state = ledger.snapshot()
    assert prior in state.entries and len(state.entries) == 2
    assert state.spent_usd == prior.reserved_usd + Decimal("0.01")
    assert state.remaining_usd == Decimal("20") - state.spent_usd
    assert json.loads(ledger.path.read_bytes())["entries"][prior.request_id] == raw_prior
    assert prior.actual_cost_usd is None and prior.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    strict = DevelopmentBudgetSession(
        policy=carry_policy(uncertain_cost_policy="STOP"), ledger=ledger
    )
    with pytest.raises(CostBudgetExceededError, match="settled"):
        reserve_development(strict, "strict-still-stops")
    with pytest.raises(CostReservationStateError):
        reserve_development(session, "first")


@pytest.mark.parametrize(
    "identifier",
    [
        "foreign",
        "dev-estimate-abc:1",
        "dev-estimate-" + "a" * 64 + ":0",
        "dev-estimate-" + "a" * 64 + ":33",
        "dev-estimate-" + "a" * 64 + ":01",
    ],
)
def test_development_never_implicitly_carries_noncanonical_or_foreign_history(tmp_path, identifier):
    ledger, _first = uncertain_ledger(tmp_path, request_id=identifier)
    before = ledger.path.read_bytes()
    session = DevelopmentBudgetSession(policy=carry_policy(), ledger=ledger)
    with pytest.raises(CostBudgetExceededError, match="settled"):
        reserve_development(session)
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("attempt", [1, 9, 10, 19, 20, 29, 30, 32])
def test_every_canonical_development_attempt_boundary_is_eligible(tmp_path, attempt):
    ledger, first = uncertain_ledger(tmp_path, request_id=f"dev-estimate-{'a' * 64}:{attempt}")
    assert development_uncertain_reservations(
        policy=carry_policy(), snapshot=ledger.snapshot()
    ) == (first,)


@pytest.mark.parametrize("transition", ["new_unknown", "pending", "known", "overrun"])
def test_under_lock_revalidation_detects_history_drift_after_session_snapshot(
    tmp_path, monkeypatch, transition
):
    ledger, first = uncertain_ledger(tmp_path, request_id="dev-estimate-" + "a" * 64 + ":1")
    session = DevelopmentBudgetSession(policy=carry_policy(), ledger=ledger)
    original = AtomicCostLedger.reserve
    after_transition = []

    def reserve_with_drift(self, request_id, amount, **kwargs):
        if transition in {"new_unknown", "pending"}:
            new = original(self, "dev-estimate-" + "b" * 64 + ":1", Decimal("1"))
            if transition == "new_unknown":
                self.reconcile(new, None)
        else:
            try:
                self.reconcile(first, Decimal("2") if transition == "overrun" else Decimal("0.1"))
            except CostReservationOverrunError:
                assert transition == "overrun"
        after_transition.append(self.path.read_bytes())
        return original(self, request_id, amount, **kwargs)

    monkeypatch.setattr(AtomicCostLedger, "reserve", reserve_with_drift)
    with pytest.raises((CostBudgetExceededError, CostReservationStateError)):
        reserve_development(session)
    assert after_transition == [ledger.path.read_bytes()]


def test_concurrent_carry_sessions_still_allow_only_one_active_hold(tmp_path):
    ledger, _first = uncertain_ledger(tmp_path, request_id="dev-estimate-" + "a" * 64 + ":1")

    def attempt(name):
        session = DevelopmentBudgetSession(
            policy=carry_policy(),
            ledger=AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20")),
        )
        try:
            reserve_development(session, name)
        except CostBudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, ("concurrent-a", "concurrent-b"))) == [False, True]
    assert len(ledger.snapshot().entries) == 2
    assert ledger.snapshot().spent_usd == Decimal("1")


def test_later_real_cost_overrun_remains_durable_after_prior_carry(tmp_path):
    ledger, first = uncertain_ledger(tmp_path, request_id="dev-estimate-" + "a" * 64 + ":1")
    session = DevelopmentBudgetSession(policy=carry_policy(), ledger=ledger)
    second = reserve_development(session)
    session.reconcile(second, actual_cost_usd=Decimal("0.01"))
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(first, Decimal("2"))
    before = ledger.path.read_bytes()
    with pytest.raises(CostBudgetExceededError, match="prior provider cost"):
        reserve_development(session, "after-known-overrun")
    assert ledger.path.read_bytes() == before
    assert ledger.snapshot().spent_usd == Decimal("2.01")


def test_development_allowance_projection_is_bounded_before_any_reservation(tmp_path):
    ledger, _first = uncertain_ledger(tmp_path, request_id="dev-estimate-" + "a" * 64 + ":1")
    snapshot = ledger.snapshot()
    oversized = replace(
        snapshot, entries=snapshot.entries * (MAX_UNCERTAIN_RESERVATION_ALLOWANCES + 1)
    )
    before = ledger.path.read_bytes()
    with pytest.raises(DevelopmentCostError, match="bounded allowance"):
        development_uncertain_reservations(policy=carry_policy(), snapshot=oversized)
    assert (
        development_uncertain_reservations(
            policy=carry_policy(uncertain_cost_policy="STOP"), snapshot=oversized
        )
        == ()
    )
    assert ledger.path.read_bytes() == before
