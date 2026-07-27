from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostLedgerCorruptError,
    CostReservationOverrunError,
    CostReservationStateError,
    ReleaseReason,
)


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
