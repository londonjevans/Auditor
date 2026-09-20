"""Deterministic full-population state tests with a genuine disposable ledger."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.authenticated_runner import VerifiedCrossLineageRunnerCustody
from mmaudit.models.candidate_selection import (
    CandidateSelectionPlan,
    load_candidate_selection_plan,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
)
from mmaudit.orchestration.calibration_population import (
    CalibrationPopulationEvent,
    CalibrationPopulationJournal,
    load_calibration_population_journal,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_candidate_selection import _plan


def population_plan(count: int = 3) -> CandidateSelectionPlan:
    source = _plan()
    return seal_candidate_selection_plan(
        source_bindings=source.source_bindings,
        entries=tuple(
            seal_candidate_selection_entry(
                exact_model_id=f"synthetic/model-{i:02d}",
                priority_rank=i + 1,
                advisory_lineage_group=f"Synthetic advisory {i}",
                allowed_provider_endpoints=("synthetic-provider",),
            )
            for i in range(count)
        ),
        authenticated_runner_selection=None,
        unresolved_requirements=("Synthetic data has no lineage or provider authority.",),
    )


def journal_inputs(
    tmp_path: Path, count: int = 3
) -> tuple[Path, CandidateSelectionPlan, AtomicCostLedger]:
    root = tmp_path / "population"
    root.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    return root, population_plan(count), ledger


def registrations(plan: CandidateSelectionPlan) -> tuple[tuple[str, str, str], ...]:
    return tuple((entry.exact_model_id, "a" * 64, "b" * 64) for entry in plan.entries)


def read_journal(root: Path) -> tuple[CalibrationPopulationEvent, ...]:
    initial = CalibrationPopulationEvent.model_validate_json((root / "000.json").read_bytes())
    return load_calibration_population_journal(
        root, expected_registration_sha256=initial.event_sha256
    )


def test_registration_retains_every_missing_slot_and_known_prior_cost(tmp_path: Path) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    reservation = ledger.reserve("prior", Decimal("1"))
    ledger.reconcile(reservation, Decimal("0.25"))
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan)[:1],
    )
    event = read_journal(root)[0]
    assert event.selection_plan == plan
    assert tuple(slot.state for slot in event.slots) == ("PENDING", "MISSING", "MISSING")
    assert event.ledger_snapshot == ledger.snapshot()
    assert event.ledger_identity_sha256 == ledger.identity_sha256
    assert event.serialized_authority is event.model_qualification_authorized is False
    assert event.provider_call_authorized is event.release_authorized is False
    assert event.external_population_seal_required is True
    assert not isinstance(journal, VerifiedCrossLineageRunnerCustody)


def test_active_reference_population_does_not_collapse_to_three_selected_routes(
    tmp_path: Path,
) -> None:
    root, _, ledger = journal_inputs(tmp_path)
    plan = load_candidate_selection_plan(
        Path(__file__).parents[2] / "config/models.selection-plan.json"
    )
    journal = CalibrationPopulationJournal(
        evidence_root=root, selection_plan=plan, ledger=ledger, present_registries=()
    )
    assert len(journal.current.slots) == len(plan.entries) == 12
    assert all(slot.state == "MISSING" for slot in journal.current.slots)
    assert all(not entry.approved_roles and not entry.entry_authority for entry in plan.entries)
    assert journal.current.selection_plan == plan


@pytest.mark.parametrize("count", (1, 3, 64))
def test_complete_exact_plan_prefix_is_retained_but_never_qualification(
    tmp_path: Path, count: int
) -> None:
    root, plan, ledger = journal_inputs(tmp_path, count)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    for entry in plan.entries:
        journal.append("PREFLIGHT_PASSED", exact_model_id=entry.exact_model_id)
    for entry in plan.entries:
        journal.append("RUNNER_STARTED", exact_model_id=entry.exact_model_id)
        journal.append(
            "RUNNER_RETAINED", exact_model_id=entry.exact_model_id, runner_evidence_sha256="c" * 64
        )
    journal.append("FINISHED", disposition="CONSUMED")
    events = read_journal(root)
    assert len(events) == 3 * count + 2
    assert all(len(event.slots) == count for event in events)
    assert events[-1].disposition == "CONSUMED"
    assert events[-1].model_qualification_authorized is False
    assert ledger.snapshot().entries == ()  # runner-state records do not assert provider calls


@pytest.mark.parametrize("kind", ("PREFLIGHT_PASSED", "RUNNER_STARTED", "RUNNER_RETAINED"))
def test_slot_cannot_repeat_or_skip_required_boundaries(tmp_path: Path, kind: Any) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    if kind == "PREFLIGHT_PASSED":
        journal.append(kind, exact_model_id=plan.entries[0].exact_model_id)
    before = tuple(root.iterdir())
    with pytest.raises(ValueError):
        journal.append(kind, exact_model_id=plan.entries[0].exact_model_id)
    assert tuple(root.iterdir()) == before


@pytest.mark.parametrize("states", ("missing", "pending", "refused", "started"))
def test_completion_cannot_hide_any_incomplete_slot(tmp_path: Path, states: str) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=() if states == "missing" else registrations(plan),
    )
    if states == "refused":
        journal.append("PREFLIGHT_REFUSED", exact_model_id=plan.entries[0].exact_model_id)
    if states == "started":
        for entry in plan.entries:
            journal.append("PREFLIGHT_PASSED", exact_model_id=entry.exact_model_id)
        journal.append("RUNNER_STARTED", exact_model_id=plan.entries[0].exact_model_id)
    with pytest.raises(ValueError, match="cannot omit"):
        journal.append("FINISHED", disposition="CONSUMED")
    assert read_journal(root)[-1].disposition == "OPEN"


@pytest.mark.parametrize("status", ("FAILED", "CANCELLED"))
def test_failure_preserves_started_slot_unknown_bill_and_unattempted_tail(
    tmp_path: Path, status: Any
) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    for entry in plan.entries:
        journal.append("PREFLIGHT_PASSED", exact_model_id=entry.exact_model_id)
    journal.append("RUNNER_STARTED", exact_model_id=plan.entries[0].exact_model_id)
    reservation = ledger.reserve("unresolved-attempt", Decimal("1"))
    ledger.commit_for_transport(reservation)
    ledger.reconcile(reservation, None)
    journal.append("FINISHED", disposition=status)
    event = read_journal(root)[-1]
    assert tuple(slot.state for slot in event.slots) == ("FAILED", "READY", "READY")
    assert event.ledger_snapshot == ledger.snapshot()
    assert event.ledger_snapshot.entries[0].actual_cost_usd is None
    assert event.ledger_snapshot.spent_usd == 1
    with pytest.raises(ValueError, match="resume"):
        journal.append("RUNNER_STARTED", exact_model_id=plan.entries[1].exact_model_id)


@pytest.mark.parametrize(
    "change", ("subset", "authority", "hash", "time", "cost", "extra", "missing-field")
)
def test_serialized_event_rejects_inconsistent_or_noncanonical_claims(
    tmp_path: Path, change: str
) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    raw = json.loads((root / "000.json").read_bytes())
    if change == "subset":
        raw["slots"] = raw["slots"][:1]
    elif change == "authority":
        raw["provider_call_authorized"] = True
    elif change == "time":
        raw["recorded_at"] = "2026-09-10T12:00:00"
    elif change == "cost":
        raw["ledger_snapshot"]["spent_usd"] = "NaN"
    elif change == "extra":
        raw["provider_response"] = "not allowed"
    elif change == "missing-field":
        del raw["serialized_authority"]
    else:
        raw["event_sha256"] = "d" * 64
    if change != "hash":
        raw["event_sha256"] = canonical_sha256(
            {key: value for key, value in raw.items() if key != "event_sha256"}
        )
    with pytest.raises(ValueError):
        CalibrationPopulationEvent.model_validate_json(stable_json(raw))


@pytest.mark.parametrize(
    "shape",
    ("duplicate", "reverse", "outside", "bad-hash", "list", "short", "non-string", "oversize"),
)
def test_invalid_present_launch_set_cannot_publish_registration(tmp_path: Path, shape: str) -> None:
    root, plan, ledger = journal_inputs(tmp_path)
    present: Any = registrations(plan)
    if shape == "duplicate":
        present += present[:1]
    elif shape == "reverse":
        present = present[::-1]
    elif shape == "outside":
        present = (("other/outside", "a" * 64, "b" * 64),)
    elif shape == "bad-hash":
        present = ((present[0][0], "bad", "b" * 64),)
    elif shape == "list":
        present = list(present)
    elif shape == "short":
        present = ((present[0][0], "a" * 64),)
    elif shape == "non-string":
        present = ((present[0][0], "a" * 64, 123),)
    else:
        present = present[:1] * 65
    with pytest.raises(ValueError):
        CalibrationPopulationJournal(
            evidence_root=root, selection_plan=plan, ledger=ledger, present_registries=present
        )
    assert list(root.iterdir()) == []
