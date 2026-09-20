"""Real private-file/ledger joins using only disposable synthetic local evidence."""

from __future__ import annotations

import json
import os
from decimal import Decimal
from pathlib import Path

import pytest

import mmaudit.orchestration.calibration_population as population
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_calibration_population_journal import (
    journal_inputs,
    read_journal,
    registrations,
)


@pytest.fixture(autouse=True)
def offline_only(forbid_network_and_secrets: list[str]) -> None:
    assert not forbid_network_and_secrets


@pytest.mark.parametrize(
    "kind", ("mutation", "same-bytes-replace", "hardlink", "symlink", "extra", "missing")
)
def test_precommitted_file_custody_rejects_replacement_or_prefix_loss(
    tmp_path: Path, kind: str
) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    first = root / "000.json"
    original = first.read_bytes()
    if kind == "mutation":
        first.write_bytes(original + b" ")
    elif kind == "same-bytes-replace":
        replacement = tmp_path / "same-bytes.json"
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(first)
    elif kind == "hardlink":
        os.link(first, tmp_path / "linked.json")
    elif kind == "symlink":
        moved = tmp_path / "moved.json"
        first.rename(moved)
        first.symlink_to(moved)
    elif kind == "extra":
        (root / "unexpected.json").write_text("{}")
    else:
        first.rename(tmp_path / "removed.json")
    with pytest.raises(ValueError):
        journal.append("PREFLIGHT_PASSED", exact_model_id=plan.entries[0].exact_model_id)
    assert not (root / "001.json").exists()
    assert ledger.snapshot().entries == ()


@pytest.mark.parametrize(
    "kind", ("wrong-pin", "rehashed-slot", "wrong-predecessor", "noncanonical", "missing-event")
)
def test_reader_rejects_rehashed_transition_changes_or_ambiguous_prefix(
    tmp_path: Path, kind: str
) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    pin = journal.current.event_sha256
    journal.append("PREFLIGHT_PASSED", exact_model_id=plan.entries[0].exact_model_id)
    second = root / "001.json"
    raw = json.loads(second.read_bytes())
    if kind == "wrong-pin":
        pin = "c" * 64
    elif kind == "rehashed-slot":
        raw["slots"][1]["state"] = "REFUSED"
    elif kind == "wrong-predecessor":
        raw["previous_event_sha256"] = "d" * 64
    elif kind == "noncanonical":
        second.write_bytes(second.read_bytes() + b" ")
    else:
        second.rename(root / "002.json")
    if kind in {"rehashed-slot", "wrong-predecessor"}:
        raw["event_sha256"] = canonical_sha256(
            {key: value for key, value in raw.items() if key != "event_sha256"}
        )
        second.write_text(stable_json(raw))
    with pytest.raises(ValueError):
        population.load_calibration_population_journal(root, expected_registration_sha256=pin)


def test_fresh_private_outputs_never_overwrite_an_existing_journal(tmp_path: Path) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    args = {
        "evidence_root": root,
        "selection_plan": plan,
        "ledger": ledger,
        "present_registries": registrations(plan),
    }
    CalibrationPopulationJournal(**args)
    original = (root / "000.json").read_bytes()
    assert (root / "000.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="empty"):
        CalibrationPopulationJournal(**args)
    assert (root / "000.json").read_bytes() == original


def test_unknown_prior_bill_and_active_portfolio_hold_remain_in_registered_snapshot(
    tmp_path: Path,
) -> None:
    from mmaudit.orchestration.cost_ledger import PortfolioAttemptSlot

    root, plan, ledger = journal_inputs(tmp_path)
    reservation = ledger.reserve("synthetic-unknown", Decimal("1"))
    ledger.commit_for_transport(reservation)
    ledger.reconcile(reservation, None)
    # This low-level API also serves legacy accounting. Strict campaign readiness,
    # not the journal, refuses unknown bills and active holds before dispatch.
    ledger.reserve_portfolio("d" * 64, (PortfolioAttemptSlot("synthetic-held", Decimal("1")),))
    journal = CalibrationPopulationJournal(
        evidence_root=root, selection_plan=plan, ledger=ledger, present_registries=()
    )
    journal.append("FINISHED", disposition="FAILED")
    assert read_journal(root)[-1].ledger_snapshot == ledger.snapshot()
    assert read_journal(root)[-1].ledger_snapshot.entries[0].actual_cost_usd is None
    assert read_journal(root)[-1].ledger_snapshot.held_portfolio_usd == Decimal("1")
    from mmaudit.orchestration.authenticated_calibration_accounting import (
        calibration_ledger_accounting_scope,
    )

    with pytest.raises(ValueError), calibration_ledger_accounting_scope(ledger):
        pytest.fail("strict accounting admitted unknown or held liabilities")


@pytest.mark.parametrize("bound", ("event", "journal", "files"))
def test_evidence_bounds_preserve_previous_prefix_and_original_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    original = (root / "000.json").read_bytes()
    if bound == "event":
        monkeypatch.setattr(population, "_MAX_EVENT_BYTES", len(original) - 1)
    elif bound == "journal":
        monkeypatch.setattr(population, "_MAX_JOURNAL_BYTES", len(original) + 1)
    else:
        monkeypatch.setattr(population, "_MAX_EVENTS", 0)
    with pytest.raises(ValueError):
        journal.append("PREFLIGHT_PASSED", exact_model_id=plan.entries[0].exact_model_id)
    assert (root / "000.json").read_bytes() == original
    assert not (root / "001.json").exists()
    assert ledger.snapshot().entries == ()
