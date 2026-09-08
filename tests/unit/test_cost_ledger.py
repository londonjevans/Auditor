from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
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


def test_provision_creates_once_then_reopens_without_resetting_state(tmp_path: Path) -> None:
    path = tmp_path / "managed-costs.json"

    created, was_created = AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))
    reservation = created.reserve("retained-request", Decimal("0.50"))
    created.reconcile(reservation, Decimal("0.25"))
    retained_bytes = path.read_bytes()
    retained_lock = created.lock_path.stat()
    retained_identity = created.identity_sha256

    reopened, was_reopened = AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))

    assert was_created is True
    assert was_reopened is False
    assert path.read_bytes() == retained_bytes
    assert (reopened.lock_path.stat().st_dev, reopened.lock_path.stat().st_ino) == (
        retained_lock.st_dev,
        retained_lock.st_ino,
    )
    assert reopened.identity_sha256 == retained_identity
    assert reopened.snapshot().spent_usd == Decimal("0.25")


def test_provision_preserves_an_active_reservation_exactly(tmp_path: Path) -> None:
    path = tmp_path / "active-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("2.00"))
    reservation = ledger.reserve("in-flight-request", Decimal("0.75"))
    retained_bytes = path.read_bytes()

    reopened, created = AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))

    assert created is False
    assert path.read_bytes() == retained_bytes
    assert reopened.active_reservation(reservation.request_id) == reservation
    assert reopened.snapshot().active_reserved_usd == Decimal("0.75")


def test_provision_marker_prevents_deleted_ledger_from_restoring_budget(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deleted-costs.json"
    ledger, created = AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))
    marker = tmp_path / ".deleted-costs.json.provision.lock"
    marker_identity = marker.stat()
    assert created is True

    path.unlink()
    ledger.lock_path.unlink()

    with pytest.raises(CostLedgerConfigurationError, match="automatic repair is forbidden"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))
    with pytest.raises(CostLedgerConfigurationError, match="initialization is one-time"):
        AtomicCostLedger.initialize(path, cap_usd=Decimal("2.00"))

    assert not path.exists()
    assert not ledger.lock_path.exists()
    assert (marker.stat().st_dev, marker.stat().st_ino) == (
        marker_identity.st_dev,
        marker_identity.st_ino,
    )


def test_concurrent_provision_has_one_creator_and_one_exact_reopener(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-costs.json"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _index: AtomicCostLedger.provision(
                    path,
                    cap_usd=Decimal("1.00"),
                ),
                range(2),
            )
        )

    assert sorted(created for _ledger, created in results) == [False, True]
    assert len({ledger.identity_sha256 for ledger, _created in results}) == 1
    assert all(ledger.snapshot().entries == () for ledger, _created in results)


def test_provision_waits_for_cross_process_initializer_before_opening_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "colliding-costs.json"
    release_winner = tmp_path / "release-winner"
    winner_ready = tmp_path / "winner-ready"
    loser_waiting = tmp_path / "loser-waiting"
    winner_result = tmp_path / "winner-result"
    loser_result = tmp_path / "loser-result"
    winner_script = """
import sys
import time
from decimal import Decimal
from pathlib import Path
import mmaudit.orchestration.cost_ledger as cost_ledger_module
from mmaudit.orchestration.cost_ledger import AtomicCostLedger

ledger_path = Path(sys.argv[1])
release_path = Path(sys.argv[2])
ready_path = Path(sys.argv[3])
result_path = Path(sys.argv[4])
original_open = cost_ledger_module._open_lock_file

def open_then_pause(path: Path, *, create: bool) -> int:
    descriptor = original_open(path, create=create)
    if create:
        ready_path.write_text("ready", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise SystemExit(97)
            time.sleep(0.001)
    return descriptor

cost_ledger_module._open_lock_file = open_then_pause
ledger = AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("1.00"))
result_path.write_text(ledger.identity_sha256, encoding="utf-8")
"""
    loser_script = """
import fcntl
import sys
import time
from decimal import Decimal
from pathlib import Path
import mmaudit.orchestration.cost_ledger as cost_ledger_module
from mmaudit.orchestration.cost_ledger import AtomicCostLedger

ledger_path = Path(sys.argv[1])
waiting_path = Path(sys.argv[2])
result_path = Path(sys.argv[3])
original_flock = cost_ledger_module.fcntl.flock
observed_collision = False

def observing_flock(descriptor: int, operation: int) -> None:
    global observed_collision
    try:
        original_flock(descriptor, operation)
    except BlockingIOError:
        if operation & fcntl.LOCK_NB and not observed_collision:
            observed_collision = True
            waiting_path.write_text("waiting", encoding="utf-8")
        raise

cost_ledger_module.fcntl.flock = observing_flock
ledger, created = AtomicCostLedger.provision(ledger_path, cap_usd=Decimal("1.00"))
result_path.write_text(
    f"{int(created)}:{int(observed_collision)}:{ledger.identity_sha256}",
    encoding="utf-8",
)
"""
    winner = subprocess.Popen(
        [
            sys.executable,
            "-c",
            winner_script,
            str(path),
            str(release_winner),
            str(winner_ready),
            str(winner_result),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not winner_ready.exists():
        if winner.poll() is not None:
            raise AssertionError(winner.communicate())
        if time.monotonic() >= deadline:
            winner.kill()
            raise AssertionError("initializer did not expose the pre-flock collision window")
        time.sleep(0.001)

    loser = subprocess.Popen(
        [sys.executable, "-c", loser_script, str(path), str(loser_waiting), str(loser_result)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not loser_waiting.exists():
        if loser.poll() is not None:
            raise AssertionError(loser.communicate())
        if time.monotonic() >= deadline:
            loser.kill()
            winner.kill()
            raise AssertionError("provisioner did not wait on the initialization guard")
        time.sleep(0.001)

    release_winner.touch()
    winner_output = winner.communicate(timeout=15)
    loser_output = loser.communicate(timeout=15)

    assert winner.returncode == 0, winner_output
    assert loser.returncode == 0, loser_output
    created, observed_collision, loser_identity = loser_result.read_text(encoding="utf-8").split(
        ":"
    )
    assert created == "0"
    assert observed_collision == "1"
    assert loser_identity == winner_result.read_text(encoding="utf-8")
    assert AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00")).snapshot().entries == ()


def test_provision_initialization_wait_is_bounded_without_creating_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "bounded-costs.json"
    guard = tmp_path / ".bounded-costs.json.provision.lock"
    ready = tmp_path / "holder-ready"
    release = tmp_path / "release-holder"
    holder_script = """
import fcntl
import os
import sys
import time
from pathlib import Path

guard_path = Path(sys.argv[1])
ready_path = Path(sys.argv[2])
release_path = Path(sys.argv[3])
descriptor = os.open(guard_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    ready_path.write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + 10
    while not release_path.exists():
        if time.monotonic() >= deadline:
            raise SystemExit(96)
        time.sleep(0.001)
finally:
    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)
"""
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_script, str(guard), str(ready), str(release)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not ready.exists():
        if holder.poll() is not None:
            raise AssertionError(holder.communicate())
        if time.monotonic() >= deadline:
            holder.kill()
            raise AssertionError("lock holder did not become ready")
        time.sleep(0.001)

    monkeypatch.setattr(cost_ledger_module, "_INITIALIZATION_LOCK_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(cost_ledger_module, "_INITIALIZATION_LOCK_RETRY_SECONDS", 0.001)
    try:
        with pytest.raises(CostLedgerConfigurationError, match="timed out waiting"):
            AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))
    finally:
        release.touch()
        holder_output = holder.communicate(timeout=15)

    assert holder.returncode == 0, holder_output
    assert not path.exists()
    assert not (tmp_path / ".bounded-costs.json.lock").exists()
    assert guard.exists()


def test_provision_guard_unlock_failure_does_not_misreport_completed_initialization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "unlock-costs.json"
    guard_descriptors: set[int] = set()
    original_open = cost_ledger_module._open_provision_lock_file
    real_fcntl = cost_ledger_module.fcntl

    def observe_open(guard_path: Path, *, create: bool) -> tuple[int, bool]:
        descriptor, created = original_open(guard_path, create=create)
        guard_descriptors.add(descriptor)
        return descriptor, created

    class FcntlProxy:
        LOCK_EX = real_fcntl.LOCK_EX
        LOCK_NB = real_fcntl.LOCK_NB
        LOCK_UN = real_fcntl.LOCK_UN

        @staticmethod
        def flock(descriptor: int, operation: int) -> None:
            if descriptor in guard_descriptors and operation == real_fcntl.LOCK_UN:
                raise OSError("synthetic guard unlock failure")
            real_fcntl.flock(descriptor, operation)

    monkeypatch.setattr(cost_ledger_module, "_open_provision_lock_file", observe_open)
    monkeypatch.setattr(cost_ledger_module, "fcntl", FcntlProxy)

    ledger, created = AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert created is True
    assert ledger.path == path
    assert path.exists()


@pytest.mark.parametrize("failed_fsync_call", [1, 2])
def test_provision_marker_fsync_failure_never_creates_budget_state(
    failed_fsync_call: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "marker-fsync-failure-costs.json"
    marker = tmp_path / ".marker-fsync-failure-costs.json.provision.lock"
    ordinary_lock = tmp_path / ".marker-fsync-failure-costs.json.lock"
    original_fsync = cost_ledger_module.os.fsync
    fsync_calls = 0

    def fail_marker_persistence(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == failed_fsync_call:
            raise OSError("synthetic provisioning marker fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(cost_ledger_module.os, "fsync", fail_marker_persistence)

    with pytest.raises(CostLedgerConfigurationError, match="marker could not be persisted"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert fsync_calls == failed_fsync_call
    assert not path.exists()
    assert not ordinary_lock.exists()
    # The durable marker is intentionally never removed as part of failure cleanup. If its
    # persistence is uncertain, retaining it prevents a later call from restoring the budget.
    assert marker.exists()
    with pytest.raises(CostLedgerConfigurationError, match="automatic repair is forbidden"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))


def test_provision_never_launders_a_post_write_custody_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "custody-failure-costs.json"
    original_require = cost_ledger_module._require_exact_lock_path
    calls = 0

    def fail_on_locked_context_exit(lock_path: Path, descriptor: int) -> None:
        nonlocal calls
        calls += 1
        original_require(lock_path, descriptor)
        if calls == 2:
            raise CostLedgerConfigurationError("injected final custody failure")

    monkeypatch.setattr(
        cost_ledger_module,
        "_require_exact_lock_path",
        fail_on_locked_context_exit,
    )

    with pytest.raises(CostLedgerConfigurationError, match="injected final custody failure"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert path.exists()
    assert (tmp_path / ".custody-failure-costs.json.lock").exists()


def test_provision_never_launders_a_prewrite_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "prewrite-failure-costs.json"

    def fail_open(_path: Path, *, create: bool) -> int:
        assert create is True
        raise CostLedgerConfigurationError("injected prewrite failure")

    monkeypatch.setattr(cost_ledger_module, "_open_lock_file", fail_open)

    with pytest.raises(CostLedgerConfigurationError, match="injected prewrite failure"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert not path.exists()
    assert not (tmp_path / ".prewrite-failure-costs.json.lock").exists()
    assert (tmp_path / ".prewrite-failure-costs.json.provision.lock").exists()


def test_provision_is_process_safe_for_one_creator_and_one_reopener(tmp_path: Path) -> None:
    path = tmp_path / "process-costs.json"
    gate = tmp_path / "start"
    script = """
import sys
import time
from decimal import Decimal
from pathlib import Path
from mmaudit.orchestration.cost_ledger import AtomicCostLedger

ledger_path = Path(sys.argv[1])
gate_path = Path(sys.argv[2])
ready_path = Path(sys.argv[3])
result_path = Path(sys.argv[4])
ready_path.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 10
while not gate_path.exists():
    if time.monotonic() >= deadline:
        raise SystemExit(99)
    time.sleep(0.001)
ledger, created = AtomicCostLedger.provision(ledger_path, cap_usd=Decimal("1.00"))
result_path.write_text(
    f"{int(created)}:{ledger.identity_sha256}",
    encoding="utf-8",
)
"""
    ready_paths = (tmp_path / "ready-1", tmp_path / "ready-2")
    result_paths = (tmp_path / "result-1", tmp_path / "result-2")
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(path),
                str(gate),
                str(ready),
                str(result),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for ready, result in zip(ready_paths, result_paths, strict=True)
    ]
    deadline = time.monotonic() + 10
    while not all(ready.exists() for ready in ready_paths):
        if time.monotonic() >= deadline:
            raise AssertionError("provision subprocesses did not reach the local barrier")
        time.sleep(0.001)
    gate.touch()
    completed = [process.communicate(timeout=15) for process in processes]

    assert [process.returncode for process in processes] == [0, 0], completed
    results = [result.read_text(encoding="utf-8") for result in result_paths]
    created = sorted(item.split(":", maxsplit=1)[0] for item in results)
    identities = {item.split(":", maxsplit=1)[1] for item in results}
    assert created == ["0", "1"]
    assert len(identities) == 1
    assert AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00")).snapshot().entries == ()


def test_provision_refuses_existing_mismatch_or_orphan_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "existing-costs.json"
    AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    retained_bytes = path.read_bytes()

    with pytest.raises(CostLedgerConfigurationError, match="configured cost cap"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))
    assert path.read_bytes() == retained_bytes

    orphan = tmp_path / "orphan-costs.json"
    orphan_lock = tmp_path / ".orphan-costs.json.lock"
    orphan_lock.touch(mode=0o600)
    orphan_lock.chmod(0o600)
    retained_lock = orphan_lock.read_bytes()

    with pytest.raises(CostLedgerConfigurationError, match="existing cost ledger is missing"):
        AtomicCostLedger.provision(orphan, cap_usd=Decimal("1.00"))
    assert not orphan.exists()
    assert orphan_lock.read_bytes() == retained_lock
    assert (tmp_path / ".orphan-costs.json.provision.lock").exists()


def test_provision_validates_legacy_state_before_adding_no_reset_marker(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-unmarked-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    marker = tmp_path / ".legacy-unmarked-costs.json.provision.lock"
    marker.unlink()
    retained_state = path.read_bytes()
    retained_lock = ledger.lock_path.read_bytes()

    with pytest.raises(CostLedgerConfigurationError, match="configured cost cap"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("2.00"))

    assert path.read_bytes() == retained_state
    assert ledger.lock_path.read_bytes() == retained_lock
    assert marker.exists()

    reopened, created = AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))
    assert created is False
    assert reopened.snapshot().entries == ()
    assert marker.exists()


def test_observed_legacy_pair_cannot_become_a_fresh_budget_during_marker_acquisition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-race-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    marker = tmp_path / ".legacy-race-costs.json.provision.lock"
    marker.unlink()
    original_open = cost_ledger_module._open_provision_lock_file
    mutated = False

    def delete_pair_then_open(guard_path: Path, *, create: bool) -> tuple[int, bool]:
        nonlocal mutated
        if not mutated:
            mutated = True
            path.unlink()
            ledger.lock_path.unlink()
        return original_open(guard_path, create=create)

    monkeypatch.setattr(
        cost_ledger_module,
        "_open_provision_lock_file",
        delete_pair_then_open,
    )

    with pytest.raises(CostLedgerConfigurationError, match="automatic repair is forbidden"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))
    with pytest.raises(CostLedgerConfigurationError, match="automatic repair is forbidden"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert mutated is True
    assert marker.exists()
    assert not path.exists()
    assert not ledger.lock_path.exists()


def test_incomplete_legacy_pair_completed_during_marker_acquisition_is_typed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-completion-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))
    marker = tmp_path / ".legacy-completion-costs.json.provision.lock"
    marker.unlink()
    ledger.lock_path.unlink()
    original_open = cost_ledger_module._open_provision_lock_file

    def complete_pair_then_open(guard_path: Path, *, create: bool) -> tuple[int, bool]:
        ledger.lock_path.write_bytes(b"")
        ledger.lock_path.chmod(0o600)
        return original_open(guard_path, create=create)

    monkeypatch.setattr(
        cost_ledger_module,
        "_open_provision_lock_file",
        complete_pair_then_open,
    )

    reopened, created = AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert created is False
    assert reopened.snapshot().entries == ()
    assert marker.exists()


def test_provision_refuses_corrupt_or_linked_state_without_mutation(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt-costs.json"
    AtomicCostLedger.initialize(corrupt, cap_usd=Decimal("1.00"))
    corrupt.write_bytes(b"{invalid-json\n")
    corrupt.chmod(0o600)
    retained_corrupt = corrupt.read_bytes()

    with pytest.raises(CostLedgerCorruptError, match="valid UTF-8 JSON"):
        AtomicCostLedger.provision(corrupt, cap_usd=Decimal("1.00"))
    assert corrupt.read_bytes() == retained_corrupt

    target = tmp_path / "linked-target.json"
    target_ledger = AtomicCostLedger.initialize(target, cap_usd=Decimal("1.00"))
    retained_target = target.read_bytes()
    linked = tmp_path / "linked-costs.json"
    linked.symlink_to(target)
    linked_lock = tmp_path / ".linked-costs.json.lock"
    linked_lock.write_bytes(b"retained-lock")
    linked_lock.chmod(0o600)
    retained_lock = linked_lock.read_bytes()

    with pytest.raises(CostLedgerConfigurationError):
        AtomicCostLedger.provision(linked, cap_usd=Decimal("1.00"))
    assert linked.is_symlink()
    assert linked.readlink() == target
    assert target.read_bytes() == retained_target
    assert target_ledger.lock_path.exists()
    assert linked_lock.read_bytes() == retained_lock


def test_fifo_ledger_state_is_rejected_without_blocking_or_mutation(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    path = tmp_path / "fifo-costs.json"
    lock = tmp_path / ".fifo-costs.json.lock"
    marker = tmp_path / ".fifo-costs.json.provision.lock"
    os.mkfifo(path, mode=0o600)
    lock.write_bytes(b"")
    lock.chmod(0o600)

    with pytest.raises(CostLedgerConfigurationError, match="single-link operator-owned"):
        AtomicCostLedger.open_existing(path, cap_usd=Decimal("1.00"))
    with pytest.raises(CostLedgerConfigurationError, match="single-link operator-owned"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert stat.S_ISFIFO(path.stat().st_mode)
    assert lock.read_bytes() == b""
    assert marker.exists()


@pytest.mark.parametrize("invalid_kind", ["symlink", "hardlink", "mode"])
def test_provision_refuses_invalid_coordination_lock_without_creating_state(
    invalid_kind: str,
    tmp_path: Path,
) -> None:
    path = tmp_path / "guarded-costs.json"
    provision_lock = tmp_path / ".guarded-costs.json.provision.lock"
    retained = tmp_path / "retained-guard"
    retained.write_bytes(b"retained")
    retained.chmod(0o600)
    if invalid_kind == "symlink":
        provision_lock.symlink_to(retained)
    elif invalid_kind == "hardlink":
        os.link(retained, provision_lock)
    else:
        provision_lock.write_bytes(b"invalid-mode")
        provision_lock.chmod(0o640)
    retained_bytes = retained.read_bytes()
    retained_provision_bytes = provision_lock.read_bytes()
    retained_provision_entry = provision_lock.lstat()

    with pytest.raises(CostLedgerConfigurationError, match="provisioning lock"):
        AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))

    assert not path.exists()
    assert not (tmp_path / ".guarded-costs.json.lock").exists()
    assert retained.read_bytes() == retained_bytes
    current_provision_entry = provision_lock.lstat()
    assert provision_lock.read_bytes() == retained_provision_bytes
    assert (current_provision_entry.st_dev, current_provision_entry.st_ino) == (
        retained_provision_entry.st_dev,
        retained_provision_entry.st_ino,
    )


@pytest.mark.parametrize("invalid_kind", ["missing", "symlink", "hardlink", "mode"])
def test_verify_only_provisioning_lease_refuses_invalid_marker_without_repair(
    invalid_kind: str,
    tmp_path: Path,
) -> None:
    path = tmp_path / "verify-only-costs.json"
    ledger, created = AtomicCostLedger.provision(path, cap_usd=Decimal("1.00"))
    marker = tmp_path / ".verify-only-costs.json.provision.lock"
    retained = tmp_path / "retained-verify-only-marker"
    retained_state = path.read_bytes()
    retained_lock = ledger.lock_path.read_bytes()
    state_entry = path.stat()
    lock_entry = ledger.lock_path.stat()
    marker.unlink()
    if invalid_kind == "symlink":
        retained.write_bytes(b"retained")
        retained.chmod(0o600)
        marker.symlink_to(retained)
    elif invalid_kind == "hardlink":
        retained.write_bytes(b"retained")
        retained.chmod(0o600)
        os.link(retained, marker)
    elif invalid_kind == "mode":
        marker.write_bytes(b"invalid-mode")
        marker.chmod(0o640)

    assert created is True
    marker_entry = marker.lstat() if invalid_kind != "missing" else None
    marker_bytes = marker.read_bytes() if invalid_kind != "missing" else None

    with (
        pytest.raises(
            CostLedgerConfigurationError,
            match=r"provisioning (?:marker is missing|lock)",
        ),
        AtomicCostLedger.provisioning_lease(
            path,
            cap_usd=Decimal("1.00"),
            create_missing=False,
        ),
    ):
        pass

    assert path.read_bytes() == retained_state
    assert ledger.lock_path.read_bytes() == retained_lock
    current_state_entry = path.stat()
    current_lock_entry = ledger.lock_path.stat()
    assert (current_state_entry.st_dev, current_state_entry.st_ino) == (
        state_entry.st_dev,
        state_entry.st_ino,
    )
    assert (current_lock_entry.st_dev, current_lock_entry.st_ino) == (
        lock_entry.st_dev,
        lock_entry.st_ino,
    )
    if invalid_kind == "missing":
        assert not marker.exists()
    else:
        assert marker_entry is not None
        current_marker_entry = marker.lstat()
        assert marker.read_bytes() == marker_bytes
        assert (current_marker_entry.st_dev, current_marker_entry.st_ino) == (
            marker_entry.st_dev,
            marker_entry.st_ino,
        )
        if invalid_kind in {"symlink", "hardlink"}:
            assert retained.read_bytes() == b"retained"


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
    provision_lock = tmp_path / ".costs.json.provision.lock"

    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("1.00"))

    assert ledger.path == path
    assert path.stat().st_mode & 0o777 == 0o600
    assert ledger.lock_path.stat().st_mode & 0o777 == 0o600
    assert provision_lock.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1
    assert ledger.lock_path.stat().st_nlink == 1
    assert provision_lock.stat().st_nlink == 1
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
