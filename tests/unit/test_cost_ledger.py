from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

import mmaudit.orchestration.cost_ledger as cost_ledger_module
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostLedgerCorruptError,
    CostReservationOverrunError,
    CostReservationStateError,
    PortfolioAttemptSlot,
    PortfolioHoldStatus,
    PortfolioSlotStatus,
    ReleaseReason,
    cost_ledger_snapshot_sha256,
)


def test_ledger_identity_is_stable_for_exact_file_and_distinct_across_ledgers(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first-costs.json"
    second_path = tmp_path / "second-costs.json"
    first = AtomicCostLedger.initialize(first_path, cap_usd=Decimal("1.00"))
    second = AtomicCostLedger.initialize(second_path, cap_usd=Decimal("1.00"))

    reopened = AtomicCostLedger.open_existing(first_path, cap_usd=Decimal("1.00"))

    assert first_path.read_bytes() == second_path.read_bytes()
    assert reopened.identity_sha256 == first.identity_sha256
    assert second.identity_sha256 != first.identity_sha256


def test_legacy_state_bytes_and_snapshot_hash_are_unchanged_without_portfolios(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    assert path.read_bytes() == b'{"cap_usd":"1","entries":{},"schema_version":1}\n'
    assert cost_ledger_snapshot_sha256(ledger.snapshot()) == (
        "42281f974f2fe05a1c0195156d400e06502f837d81099e033745858729003535"
    )

    reservation = ledger.reserve("legacy-request", Decimal("0.25"))
    ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
    assert "portfolio_holds" not in json.loads(path.read_text(encoding="utf-8"))


def test_portfolio_claim_conserves_capacity_and_exact_release_retains_history(
    tmp_path: Path,
) -> None:
    path = tmp_path / "portfolio-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1"))
    slots = (
        PortfolioAttemptSlot("request-a", Decimal("0.4")),
        PortfolioAttemptSlot("request-b", Decimal("0.3")),
    )
    portfolio = ledger.reserve_portfolio("a" * 64, slots)

    held = ledger.snapshot()
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 2
    assert held.entries == ()
    assert held.held_portfolio_usd == Decimal("0.7")
    assert held.active_reserved_usd == Decimal("0.7")
    assert held.remaining_usd == Decimal("0.3")

    claimed = ledger.claim_portfolio_slot(portfolio, "request-a", Decimal("0.25"))
    after_claim = ledger.snapshot()
    assert claimed.reserved_usd == Decimal("0.25")
    assert after_claim.held_portfolio_usd == Decimal("0.3")
    assert after_claim.active_reserved_usd == Decimal("0.55")
    assert after_claim.remaining_usd == Decimal("0.45")
    assert after_claim.portfolio_holds[0].claimed_slots == slots[:1]
    assert after_claim.portfolio_holds[0].remaining_slots == slots[1:]

    before_stale_release = path.read_bytes()
    with pytest.raises(CostReservationStateError, match="remaining slots changed"):
        ledger.release_portfolio(portfolio, expected_remaining_slots=slots)
    assert path.read_bytes() == before_stale_release

    released = ledger.release_portfolio(
        portfolio,
        expected_remaining_slots=slots[1:],
    )
    assert released.status is PortfolioHoldStatus.RELEASED
    assert released.claimed_slots == slots[:1]
    assert released.released_slots == slots[1:]
    assert ledger.snapshot().active_reserved_usd == Decimal("0.25")
    assert ledger.snapshot().portfolio_holds[0].slots[0].status is PortfolioSlotStatus.CLAIMED
    with pytest.raises(CostReservationStateError, match="already finalized"):
        ledger.release_portfolio(portfolio, expected_remaining_slots=())


def test_portfolio_reservation_and_failed_claim_are_atomic(tmp_path: Path) -> None:
    path = tmp_path / "atomic-portfolio-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("0.5"))
    before = path.read_bytes()

    with pytest.raises(CostBudgetExceededError, match="portfolio exceeds"):
        ledger.reserve_portfolio(
            "b" * 64,
            (
                PortfolioAttemptSlot("request-a", Decimal("0.3")),
                PortfolioAttemptSlot("request-b", Decimal("0.3")),
            ),
        )
    assert path.read_bytes() == before

    slots = (PortfolioAttemptSlot("request-a", Decimal("0.3")),)
    portfolio = ledger.reserve_portfolio("b" * 64, slots)
    held_bytes = path.read_bytes()
    with pytest.raises(CostBudgetExceededError, match="held portfolio ceiling"):
        ledger.claim_portfolio_slot(portfolio, "request-a", Decimal("0.31"))
    assert path.read_bytes() == held_bytes
    with pytest.raises(CostReservationStateError, match="not in portfolio"):
        ledger.claim_portfolio_slot(portfolio, "unknown-request", Decimal("0.1"))
    assert path.read_bytes() == held_bytes
    assert ledger.snapshot().portfolio_holds[0].remaining_slots == slots
    with pytest.raises(CostReservationStateError, match="already recorded"):
        ledger.reserve("request-a", Decimal("0.1"))


def test_portfolio_recovery_requires_exact_active_plan_and_slots(tmp_path: Path) -> None:
    path = tmp_path / "recover-portfolio-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1"))
    slots = (
        PortfolioAttemptSlot("request-a", Decimal("0.2")),
        PortfolioAttemptSlot("request-b", Decimal("0.2")),
    )
    portfolio = ledger.reserve_portfolio("c" * 64, slots)
    ledger.claim_portfolio_slot(portfolio, "request-a", Decimal("0.15"))

    reopened = AtomicCostLedger.open_existing(path, cap_usd=Decimal("1"))
    assert reopened.recover_portfolio("c" * 64, slots) == portfolio
    assert reopened.recover_portfolio("c" * 64, slots) == portfolio
    with pytest.raises(CostReservationStateError, match="durable initial slots"):
        reopened.recover_portfolio("c" * 64, slots[:1])
    with pytest.raises(CostReservationStateError, match="unknown portfolio"):
        reopened.recover_portfolio("d" * 64, slots)


def test_portfolio_claim_is_blocked_after_a_durable_reservation_overrun(
    tmp_path: Path,
) -> None:
    path = tmp_path / "overrun-portfolio-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1"))
    slots = (
        PortfolioAttemptSlot("request-a", Decimal("0.3")),
        PortfolioAttemptSlot("request-b", Decimal("0.3")),
    )
    portfolio = ledger.reserve_portfolio("d" * 64, slots)
    claimed = ledger.claim_portfolio_slot(portfolio, "request-a", Decimal("0.25"))
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(claimed, Decimal("0.4"))

    before_blocked_claim = path.read_bytes()
    with pytest.raises(CostBudgetExceededError, match="prior provider cost exceeded"):
        ledger.claim_portfolio_slot(portfolio, "request-b", Decimal("0.25"))
    assert path.read_bytes() == before_blocked_claim
    assert ledger.snapshot().portfolio_holds[0].remaining_slots == slots[1:]


def test_ledger_identity_changes_when_the_persistent_lock_is_replaced(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    retained_identity = ledger.identity_sha256

    ledger.lock_path.unlink()
    ledger.lock_path.touch(mode=0o600)
    ledger.lock_path.chmod(0o600)

    assert ledger.identity_sha256 != retained_identity


def test_ledger_identity_rejects_lock_swap_after_descriptor_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    original_open = cost_ledger_module._open_lock_file
    swapped = False

    def open_then_swap(lock_path: Path, *, create: bool) -> int:
        nonlocal swapped
        descriptor = original_open(lock_path, create=create)
        if not create and not swapped:
            swapped = True
            replacement = lock_path.with_name(f".{lock_path.name}.replacement")
            replacement.touch(mode=0o600)
            replacement.chmod(0o600)
            os.replace(replacement, lock_path)
        return descriptor

    monkeypatch.setattr(cost_ledger_module, "_open_lock_file", open_then_swap)

    with pytest.raises(CostLedgerConfigurationError, match="changed during"):
        _ = ledger.identity_sha256
    assert swapped


def test_reservation_reconciles_actual_cost_and_releases_unused_amount(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("1.00"))

    reservation = ledger.reserve("request-1", Decimal("0.70"))
    reserved = ledger.snapshot()

    assert reserved.spent_usd == 0
    assert reserved.active_reserved_usd == Decimal("0.70")
    assert reserved.remaining_usd == Decimal("0.30")

    entry = ledger.reconcile(reservation, Decimal("0.25"))
    reconciled = ledger.snapshot()

    assert entry.status is CostEntryStatus.RECONCILED
    assert entry.actual_cost_usd == Decimal("0.25")
    assert entry.accounted_cost_usd == Decimal("0.25")
    assert reconciled.spent_usd == Decimal("0.25")
    assert reconciled.active_reserved_usd == 0
    assert reconciled.remaining_usd == Decimal("0.75")


def test_atomic_reservations_never_race_past_cap_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    def attempt(index: int) -> bool:
        ledger = AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
        try:
            ledger.reserve(f"request-{index}", Decimal("0.10"))
        except CostBudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=20) as executor:
        accepted = list(executor.map(attempt, range(20)))

    snapshot = AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00")).snapshot()
    assert sum(accepted) == 10
    assert snapshot.active_reserved_usd == Decimal("1.00")
    assert snapshot.remaining_usd == 0
    assert not snapshot.over_cap


def test_atomic_reservations_never_race_past_cap_across_processes(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    AtomicCostLedger.initialize(path, cap_usd=Decimal("0.50"))
    program = "\n".join(
        [
            "import sys",
            "from decimal import Decimal",
            "from pathlib import Path",
            "from mmaudit.orchestration.cost_ledger import (",
            "    AtomicCostLedger, CostBudgetExceededError",
            ")",
            ("ledger = AtomicCostLedger.open_existing(Path(sys.argv[1]), cap_usd=Decimal('0.50'))"),
            "try:",
            "    ledger.reserve(sys.argv[2], Decimal('0.10'))",
            "except CostBudgetExceededError:",
            "    raise SystemExit(3)",
        ]
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", program, str(path), f"process-{index}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(12)
    ]
    results = [(*process.communicate(timeout=20), process.returncode) for process in processes]

    assert sum(returncode == 0 for _stdout, _stderr, returncode in results) == 5
    assert all(returncode in {0, 3} for _stdout, _stderr, returncode in results)
    assert all(not stdout and not stderr for stdout, stderr, _returncode in results)
    snapshot = AtomicCostLedger.open_existing(path, cap_usd=Decimal("0.50")).snapshot()
    assert snapshot.active_reserved_usd == Decimal("0.50")
    assert snapshot.remaining_usd == 0


def test_unfinished_reservation_survives_restart_and_is_conservatively_accounted(
    tmp_path: Path,
) -> None:
    path = tmp_path / "costs.json"
    first_process = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    original = first_process.reserve("interrupted-request", Decimal("0.60"))

    recovered_process = AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    recovered = recovered_process.active_reservation("interrupted-request")

    assert recovered == original
    assert recovered_process.snapshot().active_reserved_usd == Decimal("0.60")
    assert recovered is not None
    entry = recovered_process.reconcile(recovered, None)
    assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert entry.accounted_cost_usd == Decimal("0.60")
    assert recovered_process.snapshot().spent_usd == Decimal("0.60")
    assert recovered_process.snapshot().active_reserved_usd == 0


def test_new_uncertain_attempt_preserves_all_terminal_prior_entries(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("2.00"))
    prior_reservation = ledger.reserve("prior:attempt:1", Decimal("0.40"))
    ledger.reconcile(prior_reservation, Decimal("0.15"))
    before = ledger.snapshot()

    current_reservation = ledger.reserve("current:attempt:1", Decimal("0.70"))
    current = ledger.reconcile(current_reservation, None)
    after = ledger.snapshot()

    assert current.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert current.accounted_cost_usd == Decimal("0.70")
    assert after.spent_usd - before.spent_usd == current.accounted_cost_usd
    assert {
        entry.request_id: entry for entry in after.entries if entry.request_id != current.request_id
    } == {entry.request_id: entry for entry in before.entries}


def test_uncertain_transport_commit_can_reconcile_to_known_provider_cost(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("1.00"))
    reservation = ledger.reserve("transport-attempt", Decimal("0.60"))

    uncertain = ledger.reconcile(reservation, None)
    reconciled = ledger.reconcile(reservation, Decimal("0.123456789012345678"))

    assert uncertain.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert reconciled.status is CostEntryStatus.RECONCILED
    assert reconciled.actual_cost_usd == Decimal("0.123456789012345678")
    assert reconciled.accounted_cost_usd == Decimal("0.123456789012345678")
    assert ledger.snapshot().spent_usd == Decimal("0.123456789012345678")


def test_money_validation_ignores_hostile_ambient_precision_and_rejects_subclasses(
    tmp_path: Path,
) -> None:
    exact_cap = Decimal("999999999999.123456789012345678")
    exact_cost = Decimal("0.123456789012345678")
    with localcontext() as context:
        context.prec = 6
        ledger = AtomicCostLedger.initialize(tmp_path / "exact-costs.json", cap_usd=exact_cap)
        reservation = ledger.reserve("exact-request", exact_cost)
        entry = ledger.reconcile(reservation, exact_cost)
        with pytest.raises(CostLedgerConfigurationError, match="supported exact decimal bounds"):
            AtomicCostLedger.initialize(
                tmp_path / "overprecision-costs.json",
                cap_usd=Decimal("0.1234567890123456789"),
            )

        class DecimalSubclass(Decimal):
            pass

        with pytest.raises(CostLedgerConfigurationError, match="provided as Decimal"):
            AtomicCostLedger.initialize(
                tmp_path / "subclass-costs.json",
                cap_usd=DecimalSubclass("1"),
            )

    snapshot = ledger.snapshot()
    assert snapshot.cap_usd == exact_cap
    assert entry.actual_cost_usd == exact_cost
    assert snapshot.spent_usd == exact_cost


def test_proven_pre_send_failure_releases_capacity_and_records_closed_reason(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("1.00"))
    reservation = ledger.reserve("not-sent", Decimal("0.80"))

    released = ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)

    assert released.status is CostEntryStatus.RELEASED
    assert released.release_reason is ReleaseReason.FAILED_BEFORE_SEND
    assert ledger.snapshot().remaining_usd == Decimal("1.00")
    assert ledger.active_reservation("not-sent") is None


def test_actual_cost_overrun_is_persisted_and_fails_closed(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("1.00"))
    reservation = ledger.reserve("underestimated", Decimal("0.60"))

    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(reservation, Decimal("1.10"))

    snapshot = ledger.snapshot()
    assert snapshot.spent_usd == Decimal("1.10")
    assert snapshot.over_cap
    assert snapshot.has_reservation_overrun
    assert snapshot.remaining_usd == 0
    assert snapshot.entries[0].status is CostEntryStatus.RESERVATION_OVERRUN
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(reservation, Decimal("1.10"))
    with pytest.raises(CostBudgetExceededError):
        ledger.reserve("next-request", Decimal("0.01"))


def test_reservation_overrun_blocks_new_calls_even_when_total_is_below_cap(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("10.00"))
    reservation = ledger.reserve("underestimated", Decimal("0.60"))

    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(reservation, Decimal("0.70"))

    assert not ledger.snapshot().over_cap
    with pytest.raises(CostBudgetExceededError, match="exceeded its reservation"):
        ledger.reserve("blocked-after-overrun", Decimal("0.10"))


def test_reconciliation_and_release_are_idempotent_but_conflicts_fail(
    tmp_path: Path,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "costs.json", cap_usd=Decimal("1.00"))
    reconciled_reservation = ledger.reserve("reconciled", Decimal("0.40"))
    first = ledger.reconcile(reconciled_reservation, Decimal("0.20"))
    second = ledger.reconcile(reconciled_reservation, Decimal("0.20"))
    assert first == second
    with pytest.raises(CostReservationStateError):
        ledger.reconcile(reconciled_reservation, Decimal("0.21"))
    with pytest.raises(CostReservationStateError):
        ledger.release(
            reconciled_reservation,
            reason=ReleaseReason.CANCELLED_BEFORE_SEND,
        )

    released_reservation = ledger.reserve("released", Decimal("0.10"))
    released_first = ledger.release(
        released_reservation,
        reason=ReleaseReason.CANCELLED_BEFORE_SEND,
    )
    released_second = ledger.release(
        released_reservation,
        reason=ReleaseReason.CANCELLED_BEFORE_SEND,
    )
    assert released_first == released_second
    with pytest.raises(CostReservationStateError):
        ledger.release(released_reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)


def test_ledger_schema_has_no_arbitrary_metadata_or_secret_fields(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250.00"))
    reservation = ledger.reserve("safe-request-id", Decimal("0.50"))
    ledger.reconcile(reservation, Decimal("0.10"))

    persisted = json.loads(path.read_text(encoding="utf-8"))
    entry = persisted["entries"]["safe-request-id"]

    assert set(persisted) == {"schema_version", "cap_usd", "entries"}
    assert set(entry) == {
        "request_id",
        "reservation_id",
        "status",
        "reserved_usd",
        "actual_cost_usd",
        "accounted_cost_usd",
        "release_reason",
        "created_at",
        "updated_at",
    }
    assert "prompt" not in path.read_text(encoding="utf-8").lower()
    assert "authorization" not in path.read_text(encoding="utf-8").lower()


def test_malformed_or_extended_state_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["untrusted_metadata"] = "not allowed"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(CostLedgerCorruptError):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))


def test_duplicate_json_fields_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    path.write_text(
        '{"schema_version":1,"schema_version":1,"cap_usd":"1","entries":{}}\n',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(CostLedgerCorruptError, match="duplicate JSON field"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))


def test_cap_mismatch_duplicate_ids_and_non_decimal_values_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    ledger.reserve("unique-id", Decimal("0.10"))

    with pytest.raises(CostLedgerConfigurationError):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("2.00"))
    with pytest.raises(CostReservationStateError):
        ledger.reserve("unique-id", Decimal("0.10"))
    with pytest.raises(CostLedgerConfigurationError):
        AtomicCostLedger.initialize(
            tmp_path / "float.json",
            cap_usd=1.0,  # type: ignore[arg-type]
        )
    with pytest.raises(CostLedgerConfigurationError):
        ledger.reserve("float-cost", 0.1)  # type: ignore[arg-type]
    reservation = ledger.reserve("reason-type", Decimal("0.10"))
    with pytest.raises(CostLedgerConfigurationError, match="closed reason enum"):
        ledger.release(reservation, reason="failed_before_send")  # type: ignore[arg-type]


def test_group_writable_ledger_and_symlink_are_rejected(tmp_path: Path) -> None:
    writable = tmp_path / "writable.json"
    AtomicCostLedger.initialize(writable, cap_usd=Decimal("1.00"))
    writable.chmod(0o620)
    with pytest.raises(CostLedgerConfigurationError):
        AtomicCostLedger.open_existing(writable, cap_usd=Decimal("1.00"))

    private = tmp_path / "private.json"
    AtomicCostLedger.initialize(private, cap_usd=Decimal("1.00"))
    linked = tmp_path / "linked.json"
    linked.symlink_to(private)
    linked_lock = tmp_path / ".linked.json.lock"
    linked_lock.write_text("", encoding="utf-8")
    linked_lock.chmod(0o600)
    with pytest.raises(CostLedgerConfigurationError):
        AtomicCostLedger.open_existing(linked, cap_usd=Decimal("1.00"))


def test_initialization_is_explicit_one_time_and_creates_private_files(
    tmp_path: Path,
) -> None:
    path = tmp_path / "costs.json"

    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    assert ledger.path == path
    assert path.stat().st_mode & 0o777 == 0o600
    assert ledger.lock_path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1
    assert ledger.lock_path.stat().st_nlink == 1
    with pytest.raises(CostLedgerConfigurationError, match="initialization is one-time"):
        AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))


def test_open_existing_and_plain_construction_never_create_missing_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missing.json"
    lock_path = tmp_path / ".missing.json.lock"

    with pytest.raises(CostLedgerConfigurationError, match="existing cost ledger lock"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    with pytest.raises(CostLedgerConfigurationError, match="existing cost ledger lock"):
        AtomicCostLedger(path, cap_usd=Decimal("1.00"))

    assert not path.exists()
    assert not lock_path.exists()


def test_deleted_ledger_or_lock_is_not_silently_recreated(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    initialized = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    lock_path = initialized.lock_path

    path.unlink()
    with pytest.raises(CostLedgerConfigurationError, match="explicit initialization"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    assert not path.exists()
    assert lock_path.exists()
    with pytest.raises(CostLedgerConfigurationError, match="initialization is one-time"):
        AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    lock_path.unlink()
    with pytest.raises(CostLedgerConfigurationError, match="existing cost ledger lock"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    assert not path.exists()
    assert not lock_path.exists()


def test_ledger_requires_absolute_path_and_private_canonical_parent(tmp_path: Path) -> None:
    with pytest.raises(CostLedgerConfigurationError, match="absolute operator-selected"):
        AtomicCostLedger.initialize(Path("relative-costs.json"), cap_usd=Decimal("1.00"))

    non_private = tmp_path / "non-private"
    non_private.mkdir(mode=0o700)
    non_private.chmod(0o750)
    with pytest.raises(CostLedgerConfigurationError, match="mode 0700"):
        AtomicCostLedger.initialize(
            non_private / "costs.json",
            cap_usd=Decimal("1.00"),
        )

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(private, target_is_directory=True)
    with pytest.raises(CostLedgerConfigurationError, match="canonical non-symlink"):
        AtomicCostLedger.initialize(
            linked_parent / "costs.json",
            cap_usd=Decimal("1.00"),
        )


def test_non_private_or_multiply_linked_ledger_state_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    path.chmod(0o640)
    with pytest.raises(CostLedgerConfigurationError, match="mode-0600"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    path.chmod(0o600)

    linked_ledger = tmp_path / "linked-ledger.json"
    os.link(path, linked_ledger)
    linked_lock = tmp_path / ".linked-ledger.json.lock"
    linked_lock.write_text("", encoding="utf-8")
    linked_lock.chmod(0o600)
    with pytest.raises(CostLedgerConfigurationError, match="single-link"):
        AtomicCostLedger.open_existing(linked_ledger, cap_usd=Decimal("1.00"))

    linked_ledger.unlink()
    linked_lock.unlink()
    linked_lock_alias = tmp_path / "lock-alias"
    os.link(ledger.lock_path, linked_lock_alias)
    with pytest.raises(CostLedgerConfigurationError, match="single-link"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
