"""Bounded declared-population attempt records, never execution or qualification authority.

The reference plan supplies every slot, including unavailable candidates. These
private, append-only files retain incomplete work and original ledger liabilities;
neither their hashes nor successful loading can recreate live runner custody.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostLedgerSnapshot,
    PortfolioHoldStatus,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import observe_unlinked_directory
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

_MAX_EVENT_BYTES = 4_000_000
_MAX_JOURNAL_BYTES = 32_000_000
_MAX_EVENTS = 194  # registration + 64 preflights + 128 runner boundaries + finish
_SHA256 = r"^[0-9a-f]{64}$"
type PopulationEventKind = Literal[
    "REGISTERED",
    "PREFLIGHT_PASSED",
    "PREFLIGHT_REFUSED",
    "RUNNER_STARTED",
    "RUNNER_RETAINED",
    "FINISHED",
]
type PopulationDisposition = Literal["OPEN", "CONSUMED", "FAILED", "CANCELLED"]


class _FrozenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CalibrationPopulationSlot(_FrozenRecord):
    """Runner boundaries are not a count or assertion of provider dispatches."""

    exact_model_id: str
    state: Literal["MISSING", "PENDING", "READY", "REFUSED", "STARTED", "RETAINED", "FAILED"]
    registry_sha256: str | None = Field(pattern=_SHA256)
    launch_binding_sha256: str | None = Field(pattern=_SHA256)
    runner_evidence_sha256: str | None = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def bindings_match_state(self) -> Self:
        if (self.registry_sha256 is None) != (self.state == "MISSING"):
            raise ValueError("population slot registry does not match launch presence")
        if (self.launch_binding_sha256 is None) != (self.state == "MISSING"):
            raise ValueError("population slot launch binding does not match launch presence")
        if (self.runner_evidence_sha256 is not None) != (self.state == "RETAINED"):
            raise ValueError("population slot runner evidence does not match retention")
        return self


class CalibrationPopulationEvent(_FrozenRecord):
    """Complete nonauthorizing state after one exact append-only transition."""

    schema_version: Literal["1.0"] = "1.0"
    event_index: int = Field(ge=0, lt=_MAX_EVENTS)
    recorded_at: datetime
    kind: PopulationEventKind
    slot_index: int | None = Field(ge=0, lt=64)
    previous_event_sha256: str | None = Field(pattern=_SHA256)
    selection_plan: CandidateSelectionPlan
    slots: tuple[CalibrationPopulationSlot, ...] = Field(min_length=1, max_length=64)
    ledger_snapshot: CostLedgerSnapshot
    ledger_identity_sha256: str = Field(pattern=_SHA256)
    disposition: PopulationDisposition
    serialized_authority: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    external_population_seal_required: Literal[True] = True
    event_sha256: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def complete_population_and_event_are_bound(self) -> Self:
        if self.recorded_at.utcoffset() != timedelta(0):
            raise ValueError("population event time must be UTC")
        if tuple(slot.exact_model_id for slot in self.slots) != tuple(
            entry.exact_model_id for entry in self.selection_plan.entries
        ):
            raise ValueError("population event must retain the complete declared plan")
        if (self.kind == "REGISTERED") != (self.event_index == 0):
            raise ValueError("population registration must be the first event")
        if (self.previous_event_sha256 is None) != (self.event_index == 0):
            raise ValueError("population event predecessor is inconsistent")
        if (self.slot_index is None) != (self.kind in {"REGISTERED", "FINISHED"}):
            raise ValueError("population event slot is inconsistent")
        if self.slot_index is not None and self.slot_index >= len(self.slots):
            raise ValueError("population event slot is outside the declared plan")
        if (self.disposition != "OPEN") != (self.kind == "FINISHED"):
            raise ValueError("population disposition is not a terminal event")
        if self.kind == "REGISTERED" and any(
            slot.state not in {"MISSING", "PENDING"} for slot in self.slots
        ):
            raise ValueError("population registration cannot claim attempted work")
        if self.disposition == "CONSUMED":
            snapshot = self.ledger_snapshot
            if (
                any(slot.state != "RETAINED" for slot in self.slots)
                or snapshot.cap_usd != 250
                or snapshot.spent_usd >= snapshot.cap_usd
                or snapshot.over_cap
                or snapshot.has_reservation_overrun
                or snapshot.active_reserved_usd != 0
                or snapshot.held_portfolio_usd != 0
                or any(
                    entry.status not in {CostEntryStatus.RECONCILED, CostEntryStatus.RELEASED}
                    for entry in snapshot.entries
                )
                or any(
                    hold.status is PortfolioHoldStatus.ACTIVE for hold in snapshot.portfolio_holds
                )
            ):
                raise ValueError("population consumption cannot omit work or cost liabilities")
        if self.event_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"event_sha256"})
        ):
            raise ValueError("population event hash is inconsistent")
        return self


def _transition_slots(
    previous: CalibrationPopulationEvent,
    *,
    kind: PopulationEventKind,
    slot_index: int | None,
    disposition: PopulationDisposition,
    runner_evidence_sha256: str | None,
) -> tuple[CalibrationPopulationSlot, ...]:
    if previous.disposition != "OPEN" or kind == "REGISTERED":
        raise ValueError("population journal cannot resume or repeat registration")
    slots = list(previous.slots)
    if kind == "FINISHED":
        if slot_index is not None or disposition == "OPEN" or runner_evidence_sha256 is not None:
            raise ValueError("population finish has invalid transition inputs")
        if disposition != "CONSUMED":
            slots = [
                slot.model_copy(update={"state": "FAILED"}) if slot.state == "STARTED" else slot
                for slot in slots
            ]
        return tuple(slots)
    if disposition != "OPEN" or slot_index is None or not 0 <= slot_index < len(slots):
        raise ValueError("population transition requires its exact declared slot")
    before, after = {
        "PREFLIGHT_PASSED": ("PENDING", "READY"),
        "PREFLIGHT_REFUSED": ("PENDING", "REFUSED"),
        "RUNNER_STARTED": ("READY", "STARTED"),
        "RUNNER_RETAINED": ("STARTED", "RETAINED"),
    }[kind]
    if slots[slot_index].state != before:
        raise ValueError("population transition repeats or skips a slot boundary")
    if kind.startswith("PREFLIGHT_"):
        if (
            runner_evidence_sha256 is not None
            or any(slot.state in {"STARTED", "RETAINED", "FAILED"} for slot in slots)
            or any(slot.state == "PENDING" for slot in slots[:slot_index])
        ):
            raise ValueError("population preflight is not the next unattempted slot")
    elif kind == "RUNNER_STARTED":
        if (
            runner_evidence_sha256 is not None
            or any(slot.state != "RETAINED" for slot in slots[:slot_index])
            or any(slot.state != "READY" for slot in slots[slot_index:])
        ):
            raise ValueError("population start requires all preflights and a complete prefix")
    elif runner_evidence_sha256 is None:
        raise ValueError("population retention requires the original evidence hash")
    slots[slot_index] = slots[slot_index].model_copy(
        update={"state": after, "runner_evidence_sha256": runner_evidence_sha256}
    )
    return tuple(slots)


def _event(
    *,
    event_index: int,
    recorded_at: datetime,
    kind: PopulationEventKind,
    slot_index: int | None,
    previous_event_sha256: str | None,
    selection_plan: CandidateSelectionPlan,
    slots: tuple[CalibrationPopulationSlot, ...],
    ledger_snapshot: CostLedgerSnapshot,
    ledger_identity_sha256: str,
    disposition: PopulationDisposition,
) -> CalibrationPopulationEvent:
    provisional = CalibrationPopulationEvent.model_construct(
        event_index=event_index,
        recorded_at=recorded_at,
        kind=kind,
        slot_index=slot_index,
        previous_event_sha256=previous_event_sha256,
        selection_plan=selection_plan,
        slots=slots,
        ledger_snapshot=ledger_snapshot,
        ledger_identity_sha256=ledger_identity_sha256,
        disposition=disposition,
        event_sha256="0" * 64,
    )
    material = provisional.model_dump(mode="json", exclude={"event_sha256"})
    return CalibrationPopulationEvent.model_validate_json(
        stable_json({**material, "event_sha256": canonical_sha256(material)})
    )


def _require_transition(
    previous: CalibrationPopulationEvent, current: CalibrationPopulationEvent
) -> None:
    retained_hash = (
        current.slots[current.slot_index].runner_evidence_sha256
        if current.kind == "RUNNER_RETAINED" and current.slot_index is not None
        else None
    )
    expected = _transition_slots(
        previous,
        kind=current.kind,
        slot_index=current.slot_index,
        disposition=current.disposition,
        runner_evidence_sha256=retained_hash,
    )
    if (
        current.event_index != previous.event_index + 1
        or current.previous_event_sha256 != previous.event_sha256
        or current.recorded_at < previous.recorded_at
        or current.selection_plan != previous.selection_plan
        or current.ledger_identity_sha256 != previous.ledger_identity_sha256
        or current.slots != expected
    ):
        raise ValueError("population journal prefix or declaration changed")


def _event_names(evidence_root: Path) -> list[str]:
    observe_unlinked_directory(
        evidence_root, label="calibration population directory", allow_entry_metadata_change=True
    )
    names = []
    for path in evidence_root.iterdir():
        names.append(path.name)
        if len(names) > _MAX_EVENTS:
            raise ValueError("population journal has too many files")
    names.sort()
    return names


def load_calibration_population_journal(
    evidence_root: Path, *, expected_registration_sha256: str
) -> tuple[CalibrationPopulationEvent, ...]:
    """Read a bounded exact prefix; OPEN/failed records are evidence, not a resumable lease."""

    names = _event_names(evidence_root)
    if not names or names != [f"{index:03d}.json" for index in range(len(names))]:
        raise ValueError("population journal files are not an exact event prefix")
    events: list[CalibrationPopulationEvent] = []
    custody: list[RegularFileCustodyObservation] = []
    total_bytes = 0
    for name in names:
        observed = read_file_evidence(
            evidence_root=evidence_root, relative_path=name, max_bytes=_MAX_EVENT_BYTES
        )
        custody.append(
            observe_regular_file_custody(
                root=evidence_root,
                relative_path=name,
                expected_binding=observed.binding,
                label="calibration population event",
                max_bytes=_MAX_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        )
        total_bytes += len(observed.content)
        if total_bytes > _MAX_JOURNAL_BYTES:
            raise ValueError("population journal exceeds its total byte bound")
        current = CalibrationPopulationEvent.model_validate_json(observed.content)
        if stable_json(current.model_dump(mode="json")).encode("utf-8") != observed.content:
            raise ValueError("population event is not canonical exact JSON")
        if not events:
            if current.kind != "REGISTERED" or current.event_sha256 != expected_registration_sha256:
                raise ValueError("population registration does not match its expected pin")
        else:
            _require_transition(events[-1], current)
        events.append(current)
    for observation in custody:
        require_regular_file_custody_unchanged(
            observation,
            label="calibration population event",
            max_bytes=_MAX_EVENT_BYTES,
            allow_directory_entry_metadata_change=True,
        )
    if _event_names(evidence_root) != names:
        raise ValueError("population journal changed while loading its prefix")
    return tuple(events)


class CalibrationPopulationJournal:
    """Private single-writer evidence owner; never a spend ledger or native proof issuer."""

    def __init__(
        self,
        *,
        evidence_root: Path,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        present_registries: tuple[tuple[str, str, str], ...],
    ) -> None:
        if (
            type(ledger) is not AtomicCostLedger
            or type(selection_plan) is not CandidateSelectionPlan
        ):
            raise ValueError("population registration requires original typed plan and ledger")
        if (
            type(present_registries) is not tuple
            or len(present_registries) > 64
            or any(
                type(item) is not tuple
                or len(item) != 3
                or any(type(value) is not str for value in item)
                for item in present_registries
            )
        ):
            raise ValueError("population registration requires at most64 exact launch bindings")
        plan = CandidateSelectionPlan.model_validate_json(selection_plan.model_dump_json())
        declared = tuple(entry.exact_model_id for entry in plan.entries)
        present = tuple(model_id for model_id, _, _ in present_registries)
        if present != tuple(sorted(set(present))) or not set(present) <= set(declared):
            raise ValueError("population launches must be an exact sorted subset of the full plan")
        if _event_names(evidence_root):
            raise ValueError("population journal requires an empty existing directory")
        self._root = evidence_root
        self._ledger = ledger
        self._events: list[CalibrationPopulationEvent] = []
        self._custody: list[RegularFileCustodyObservation] = []
        self._bytes = 0
        registries = {
            model_id: (registry, launch) for model_id, registry, launch in present_registries
        }
        ledger_identity, snapshot = ledger.snapshot_with_identity_sha256()
        initial = _event(
            event_index=0,
            recorded_at=datetime.now(UTC),
            kind="REGISTERED",
            slot_index=None,
            previous_event_sha256=None,
            selection_plan=plan,
            slots=tuple(
                CalibrationPopulationSlot(
                    exact_model_id=model_id,
                    state="PENDING" if model_id in registries else "MISSING",
                    registry_sha256=registries[model_id][0] if model_id in registries else None,
                    launch_binding_sha256=registries[model_id][1]
                    if model_id in registries
                    else None,
                    runner_evidence_sha256=None,
                )
                for model_id in declared
            ),
            ledger_snapshot=snapshot,
            ledger_identity_sha256=ledger_identity,
            disposition="OPEN",
        )
        self._persist(initial)

    @property
    def registration(self) -> CalibrationPopulationEvent:
        """Return the original pre-dispatch declaration, not a new authority."""

        return self._events[0]

    @property
    def current(self) -> CalibrationPopulationEvent:
        return self._events[-1]

    def require_unchanged(self) -> None:
        for observation in self._custody:
            require_regular_file_custody_unchanged(
                observation,
                label="calibration population event",
                max_bytes=_MAX_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        if _event_names(self._root) != [f"{index:03d}.json" for index in range(len(self._events))]:
            raise ValueError("population journal directory changed")

    def append(
        self,
        kind: PopulationEventKind,
        *,
        exact_model_id: str | None = None,
        runner_evidence_sha256: str | None = None,
        disposition: PopulationDisposition = "OPEN",
    ) -> None:
        self.require_unchanged()
        previous = self.current
        slot_index = (
            tuple(slot.exact_model_id for slot in previous.slots).index(exact_model_id)
            if exact_model_id is not None
            else None
        )
        slots = _transition_slots(
            previous,
            kind=kind,
            slot_index=slot_index,
            disposition=disposition,
            runner_evidence_sha256=runner_evidence_sha256,
        )
        ledger_identity, snapshot = self._ledger.snapshot_with_identity_sha256()
        if ledger_identity != previous.ledger_identity_sha256:
            raise ValueError("population ledger identity changed")
        current = _event(
            event_index=len(self._events),
            recorded_at=datetime.now(UTC),
            kind=kind,
            slot_index=slot_index,
            previous_event_sha256=previous.event_sha256,
            selection_plan=previous.selection_plan,
            slots=slots,
            ledger_snapshot=snapshot,
            ledger_identity_sha256=ledger_identity,
            disposition=disposition,
        )
        _require_transition(previous, current)
        self._persist(current)

    def _persist(self, event: CalibrationPopulationEvent) -> None:
        material = event.model_dump(mode="json")
        size = len(stable_json(material).encode("utf-8"))
        if self._bytes + size > _MAX_JOURNAL_BYTES:
            raise ValueError("population journal exceeds its total byte bound")
        binding = write_json_evidence(
            evidence_root=self._root,
            relative_path=f"{event.event_index:03d}.json",
            value=material,
            max_bytes=_MAX_EVENT_BYTES,
            require_private_parent=True,
        )
        custody = observe_regular_file_custody(
            root=self._root,
            relative_path=binding.path,
            expected_binding=binding,
            label="calibration population event",
            max_bytes=_MAX_EVENT_BYTES,
            allow_directory_entry_metadata_change=True,
        )
        self._custody.append(custody)
        self._events.append(event)
        self._bytes += size
