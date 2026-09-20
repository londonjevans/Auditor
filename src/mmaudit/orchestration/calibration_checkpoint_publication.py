"""Source-owned checkpoint publication, not authenticated chain or release authority.

The legacy source preparation is retained but never submitted here. Only the
explicit checkpoint envelope is sent through the original once-only journal.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.models import calibration_checkpoint as _checkpoint
from mmaudit.models.calibration_checkpoint import (
    MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES,
    CalibrationCheckpointSubject,
    calibration_checkpoint_subject_bytes,
    read_calibration_checkpoint_subject,
)
from mmaudit.models.evidence_seal_authority import EvidenceTransparencyPrefixProof
from mmaudit.orchestration import calibration_calendar_publication as _source
from mmaudit.orchestration import opentimestamps_calendar_journal as _calendar
from mmaudit.orchestration.authenticated_calibration_measurement import (
    LiveRegisteredCalibrationMeasurement,
)
from mmaudit.orchestration.calibration_publication import (
    CalibrationPublicationSubject,
    _PublicationData,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.orchestration.opentimestamps_calendar_transport import (
    _require_contact,
    _require_origin,
)
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    require_regular_file_custody_unchanged,
)

_CHECKPOINT = "checkpoint.json"
_BINDING = "publication.json"
_SOURCE = "source"
_CALENDAR = "calendar"
_MAX_BINDING_BYTES = 16_000
_SHA = r"^[0-9a-f]{64}$"
_LABEL = "checkpoint calendar publication"


class CalibrationCheckpointCalendarBinding(_PublicationData):
    """Versioned recovery descriptor; it cannot upgrade an old subject-only receipt."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["CALIBRATION_CHECKPOINT_CALENDAR_PUBLICATION"] = (
        "CALIBRATION_CHECKPOINT_CALENDAR_PUBLICATION"
    )
    source_directory: Literal["source"] = "source"
    source_preparation_sha256: str = Field(pattern=_SHA)
    checkpoint_file: ManifestFileBinding
    registration_event_sha256: str = Field(pattern=_SHA)
    registration_publication_sha256: str | None = Field(pattern=_SHA)
    calendar_directory: Literal["calendar"] = "calendar"
    preparation: _calendar.CalendarJournalPreparation
    publication_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def descriptor_is_exact(self) -> Self:
        if (
            self.checkpoint_file.path != _CHECKPOINT
            or not 0 < self.checkpoint_file.size <= MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES
            or (self.preparation.phase == "POPULATION_REGISTRATION")
            != (self.registration_publication_sha256 is None)
            or self.publication_sha256
            != canonical_sha256(self.model_dump(mode="json", exclude={"publication_sha256"}))
        ):
            raise ValueError("checkpoint publication descriptor hash, phase or file differs")
        return self


@dataclass(frozen=True, slots=True)
class CalibrationCheckpointCalendarObservation:
    """Constructible recovery data, never a native proof or authenticated external seal."""

    binding: CalibrationCheckpointCalendarBinding
    subject: CalibrationPublicationSubject
    checkpoint: CalibrationCheckpointSubject
    calendar: _calendar.CalendarJournalObservation


def _names(root: Path, maximum: int = 4) -> set[str]:
    names = set()
    for path in root.iterdir():
        names.add(path.name)
        if len(names) > maximum:
            raise ValueError("checkpoint publication contains extra files")
    return names


@dataclass(frozen=True, slots=True)
class _RetainedCheckpoint:
    root: Path
    binding: CalibrationCheckpointCalendarBinding
    checkpoint: CalibrationCheckpointSubject
    source: _source._RetainedPublication
    directory: DirectoryCustodyObservation
    calendar_directory: DirectoryCustodyObservation
    custody: tuple[tuple[RegularFileCustodyObservation, int], ...]
    calendar_events: tuple[_calendar.CalendarJournalEvent, ...]
    calendar_custody: tuple[RegularFileCustodyObservation, ...]
    freeze_calendar: bool

    def require_unchanged(self) -> None:
        for directory in (self.directory, self.calendar_directory):
            require_same_unlinked_directory_objects(directory, label=_LABEL)
        self.source.require_unchanged()
        # This nested legacy preparation supplies source custody, never a second POST.
        if _names(self.source.root / _CALENDAR) != {"000.json"}:
            raise ValueError("checkpoint publication source preparation was dispatched or changed")
        for custody, bound in self.custody:
            require_regular_file_custody_unchanged(
                custody, label=_LABEL, max_bytes=bound, allow_directory_entry_metadata_change=True
            )
        for event, custody in zip(self.calendar_events, self.calendar_custody, strict=True):
            if (
                type(event) is not _calendar.CalendarJournalEvent
                or hashlib.sha256(stable_json(event.model_dump(mode="json")).encode()).hexdigest()
                != custody.binding.sha256
            ):
                raise ValueError("checkpoint calendar prefix memory differs from original bytes")
            require_regular_file_custody_unchanged(
                custody,
                label=_LABEL,
                max_bytes=_calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        if self.freeze_calendar and _names(
            self.root / _CALENDAR, _calendar.MAX_CALENDAR_JOURNAL_EVENTS
        ) != {f"{index:03d}.json" for index in range(len(self.calendar_events))}:
            raise ValueError("checkpoint predecessor calendar history changed")
        raw = calibration_checkpoint_subject_bytes(self.checkpoint)
        descriptor = stable_json(self.binding.model_dump(mode="json")).encode()
        if (
            hashlib.sha256(raw).hexdigest() != self.binding.checkpoint_file.sha256
            or hashlib.sha256(descriptor).hexdigest() != self.custody[0][0].binding.sha256
            or _names(self.root) != {_SOURCE, _CHECKPOINT, _BINDING, _CALENDAR}
        ):
            raise ValueError("checkpoint publication original files or in-memory data changed")


def _read_retained(
    root: Path,
    expected_publication_sha256: str,
    *,
    journal: _calendar._Journal | None = None,
    freeze_calendar: bool = False,
) -> _RetainedCheckpoint:
    _source._require_pin(expected_publication_sha256)
    directory = _source._private_directory(root)
    if _names(root) != {_SOURCE, _CHECKPOINT, _BINDING, _CALENDAR}:
        raise ValueError("checkpoint publication input set is incomplete")
    descriptor = read_file_evidence(
        evidence_root=root, relative_path=_BINDING, max_bytes=_MAX_BINDING_BYTES
    )
    binding = CalibrationCheckpointCalendarBinding.model_validate_json(descriptor.content)
    if (
        stable_json(binding.model_dump(mode="json")).encode() != descriptor.content
        or binding.publication_sha256 != expected_publication_sha256
    ):
        raise ValueError("checkpoint publication canonical descriptor or original pin differs")
    descriptor_custody = _source._private_file(root, descriptor.binding, _MAX_BINDING_BYTES)
    source = _source._read_retained(root / _SOURCE, binding.source_preparation_sha256)
    data = read_file_evidence(
        evidence_root=root,
        relative_path=_CHECKPOINT,
        max_bytes=MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES,
    )
    if data.binding != binding.checkpoint_file:
        raise ValueError("checkpoint publication envelope differs from its original descriptor")
    checkpoint = read_calibration_checkpoint_subject(data.content)
    if (
        checkpoint.population_subject_sha256 != source.subject.subject_sha256
        or checkpoint.phase != source.subject.phase
        or checkpoint.registration_event_sha256 != source.binding.registration_event_sha256
        or checkpoint.registration_event_sha256 != binding.registration_event_sha256
        or checkpoint.subject_sha256 != binding.preparation.subject_sha256
        or checkpoint.phase != binding.preparation.phase
        or source.binding.preparation.calendar_origin != binding.preparation.calendar_origin
    ):
        raise ValueError("checkpoint publication does not join its original source/preparation")
    checkpoint_custody = _source._private_file(
        root, data.binding, MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES
    )
    calendar_root = root / _CALENDAR
    calendar_directory = _source._private_directory(calendar_root)
    prepared = read_file_evidence(
        evidence_root=calendar_root,
        relative_path="000.json",
        max_bytes=_calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES,
    )
    event = _calendar.CalendarJournalEvent.model_validate_json(prepared.content)
    if (
        event.kind != "PREPARED"
        or event.preparation != binding.preparation
        or stable_json(event.model_dump(mode="json")).encode() != prepared.content
    ):
        raise ValueError("checkpoint publication original calendar preparation differs")
    if journal is None:
        with _calendar._locked_journal(calendar_root) as held:
            held.load(binding.preparation.preparation_sha256)
            events, event_custody = tuple(held.events), tuple(held.custody)
    else:
        journal.require_unchanged()
        if type(journal) is not _calendar._Journal or journal.root != calendar_root:
            raise ValueError("checkpoint preparation requires its original child journal")
        events, event_custody = tuple(journal.events), tuple(journal.custody)
    if not events or events[0] != event:
        raise ValueError("checkpoint calendar prefix differs from its original preparation")
    retained = _RetainedCheckpoint(
        root,
        binding,
        checkpoint,
        source,
        directory,
        calendar_directory,
        (
            (descriptor_custody, _MAX_BINDING_BYTES),
            (checkpoint_custody, MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES),
            (
                _source._private_file(
                    calendar_root, prepared.binding, _calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES
                ),
                _calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES,
            ),
        ),
        events,
        event_custody,
        freeze_calendar,
    )
    retained.require_unchanged()
    return retained


def _observation(
    retained: _RetainedCheckpoint, calendar: _calendar.CalendarJournalObservation
) -> CalibrationCheckpointCalendarObservation:
    retained.require_unchanged()
    if (
        type(calendar) is not _calendar.CalendarJournalObservation
        or not calendar.events
        or calendar.events[0].preparation != retained.binding.preparation
        or calendar.events[: len(retained.calendar_events)] != retained.calendar_events
    ):
        raise ValueError("checkpoint calendar observation differs from its original descriptor")
    return CalibrationCheckpointCalendarObservation(
        retained.binding, retained.source.subject, retained.checkpoint, calendar
    )


def _retain_original_calendar_history(
    retained: _RetainedCheckpoint, journal: _calendar._Journal
) -> _RetainedCheckpoint:
    """Keep creator/read-time inodes, including new outcomes, beyond child cleanup."""

    retained.require_unchanged()
    if (
        type(journal) is not _calendar._Journal
        or journal.root != retained.root / _CALENDAR
        or not len(retained.calendar_events)
        <= len(journal.events)
        <= _calendar.MAX_CALENDAR_JOURNAL_EVENTS
        or len(journal.events) != len(journal.custody)
        or tuple(journal.events[: len(retained.calendar_events)]) != retained.calendar_events
    ):
        raise ValueError("checkpoint recovery requires its complete original journal prefix")
    complete = replace(
        retained,
        calendar_events=tuple(journal.events),
        calendar_custody=tuple(journal.custody),
        freeze_calendar=True,
    )
    complete.require_unchanged()
    return complete


class PreparedCalibrationCheckpointPublication:
    """Borrow original source custody through submission and the enclosing scope cleanup."""

    def __init__(
        self,
        retained: _RetainedCheckpoint,
        calendar: _calendar.PreparedCalendarJournal,
        require_source: Callable[[], None],
    ) -> None:
        self._retained, self._calendar, self._require_source = retained, calendar, require_source
        self._original_calendar, self._original_journal = calendar, calendar._journal

    @property
    def binding(self) -> CalibrationCheckpointCalendarBinding:
        return self._retained.binding

    def require_unchanged(self) -> None:
        self._require_source()
        if (
            self._calendar is not self._original_calendar
            or self._calendar._journal is not self._original_journal
        ):
            raise ValueError("checkpoint publication original child owner changed")
        _retain_original_calendar_history(self._retained, self._original_journal)

    async def submit(
        self, *, allow_calendar_contact: bool = False, timeout_seconds: float = 10.0
    ) -> CalibrationCheckpointCalendarObservation:
        _require_contact(
            self.binding.preparation.calendar_origin, allow_calendar_contact, timeout_seconds
        )
        self.require_unchanged()
        try:
            observed = await self._calendar.submit(
                allow_calendar_contact=allow_calendar_contact, timeout_seconds=timeout_seconds
            )
            self.require_unchanged()
            return _observation(self._retained, observed)
        except asyncio.CancelledError:
            raise _source.CalibrationCalendarPublicationCancelled(
                self.binding.publication_sha256
            ) from None
        except Exception:
            raise _source.CalibrationCalendarPublicationError(
                self.binding.publication_sha256
            ) from None


@contextmanager
def _prepare(
    *,
    source: _source.PreparedCalibrationCalendarPublication,
    checkpoint: CalibrationCheckpointSubject,
    output_root: Path,
    directory: DirectoryCustodyObservation,
    registration_publication_sha256: str | None,
    require_source: Callable[[], None],
) -> Iterator[PreparedCalibrationCheckpointPublication]:
    require_source()
    checkpoint_file = write_json_evidence(
        evidence_root=output_root,
        relative_path=_CHECKPOINT,
        value=checkpoint.model_dump(mode="json"),
        max_bytes=MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES,
        require_private_parent=True,
    )
    original_checkpoint = _source._private_file(
        output_root, checkpoint_file, MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES
    )
    with _calendar.prepare_calibration_checkpoint_calendar_journal(
        evidence_root=output_root / _CALENDAR,
        subject=checkpoint,
        calendar_origin=source.binding.preparation.calendar_origin,
    ) as calendar:
        provisional = CalibrationCheckpointCalendarBinding.model_construct(
            source_preparation_sha256=source.binding.publication_sha256,
            checkpoint_file=checkpoint_file,
            registration_event_sha256=checkpoint.registration_event_sha256,
            registration_publication_sha256=registration_publication_sha256,
            preparation=calendar.preparation,
            publication_sha256="0" * 64,
        )
        material = provisional.model_dump(mode="json", exclude={"publication_sha256"})
        binding = CalibrationCheckpointCalendarBinding.model_validate_json(
            stable_json({**material, "publication_sha256": canonical_sha256(material)})
        )
        descriptor = write_json_evidence(
            evidence_root=output_root,
            relative_path=_BINDING,
            value=binding.model_dump(mode="json"),
            max_bytes=_MAX_BINDING_BYTES,
            require_private_parent=True,
        )
        original_descriptor = _source._private_file(output_root, descriptor, _MAX_BINDING_BYTES)
        retained = _read_retained(
            output_root, binding.publication_sha256, journal=calendar._journal
        )
        for custody, bound in (
            (original_checkpoint, MAX_CALIBRATION_CHECKPOINT_SUBJECT_BYTES),
            (original_descriptor, _MAX_BINDING_BYTES),
        ):
            require_regular_file_custody_unchanged(
                custody, label=_LABEL, max_bytes=bound, allow_directory_entry_metadata_change=True
            )
        require_same_unlinked_directory_objects(directory, label=_LABEL)
        owner = PreparedCalibrationCheckpointPublication(retained, calendar, require_source)
        owner.require_unchanged()
        yield owner
        owner.require_unchanged()
    owner.require_unchanged()


def _build_checkpoint_preparers() -> tuple[
    Callable[..., AbstractContextManager[PreparedCalibrationCheckpointPublication]],
    Callable[..., AbstractContextManager[PreparedCalibrationCheckpointPublication]],
]:
    source_module, checkpoint_module = _source, _checkpoint
    registration_source = source_module.prepare_calibration_registration_calendar
    measurement_source = source_module.prepare_calibration_measurement_calendar
    build = checkpoint_module.build_calibration_checkpoint_subject
    originals = (
        (source_module, "prepare_calibration_registration_calendar", registration_source),
        (source_module, "prepare_calibration_measurement_calendar", measurement_source),
        (checkpoint_module, "build_calibration_checkpoint_subject", build),
    )
    codes = tuple(function.__code__ for _, _, function in originals)

    def pristine() -> None:
        if (
            _source is not source_module
            or _checkpoint is not checkpoint_module
            or any(
                getattr(module, name) is not function or function.__code__ is not code
                for (module, name, function), code in zip(originals, codes, strict=True)
            )
        ):
            raise ValueError("checkpoint publication original source or envelope producers changed")

    @contextmanager
    def prepare_registration(
        *,
        population_root: Path,
        expected_registration_sha256: str,
        transparency_proof: EvidenceTransparencyPrefixProof,
        expected_checkpoint_sha256: str,
        output_root: Path,
        calendar_origin: str,
    ) -> Iterator[PreparedCalibrationCheckpointPublication]:
        pristine()
        _require_origin(calendar_origin)
        source_module._require_disjoint_output(output_root, (population_root,))
        directory = prepare_owned_empty_directory(output_root, label=_LABEL)
        with registration_source(
            population_root=population_root,
            expected_registration_sha256=expected_registration_sha256,
            output_root=output_root / _SOURCE,
            calendar_origin=calendar_origin,
        ) as source:
            original_source = source._retained

            def envelope() -> CalibrationCheckpointSubject:
                source.require_unchanged()
                if source._retained is not original_source:
                    raise ValueError("checkpoint publication original source owner changed")
                return build(
                    subject=original_source.subject,
                    transparency_proof=transparency_proof,
                    expected_checkpoint_sha256=expected_checkpoint_sha256,
                )

            checkpoint = envelope()
            expected = calibration_checkpoint_subject_bytes(checkpoint)

            def require() -> None:
                pristine()
                if calibration_checkpoint_subject_bytes(envelope()) != expected:
                    raise ValueError("checkpoint publication original registration proof changed")
                source.require_unchanged()
                pristine()

            with _prepare(
                source=source,
                checkpoint=checkpoint,
                output_root=output_root,
                directory=directory,
                registration_publication_sha256=None,
                require_source=require,
            ) as owner:
                yield owner
        owner.require_unchanged()

    @contextmanager
    def prepare_measurement(
        *,
        live: LiveRegisteredCalibrationMeasurement,
        ledger: AtomicCostLedger,
        population_root: Path,
        registration_root: Path,
        expected_registration_publication_sha256: str,
        transparency_proof: EvidenceTransparencyPrefixProof,
        expected_checkpoint_sha256: str,
        output_root: Path,
        calendar_origin: str,
    ) -> Iterator[PreparedCalibrationCheckpointPublication]:
        pristine()
        _require_origin(calendar_origin)
        source_module._require_disjoint_output(output_root, (population_root, registration_root))
        previous = _read_retained(
            registration_root, expected_registration_publication_sha256, freeze_calendar=True
        )
        if previous.checkpoint.phase != "POPULATION_REGISTRATION":
            raise ValueError("checkpoint measurement requires the original registration phase")
        directory = prepare_owned_empty_directory(output_root, label=_LABEL)
        with measurement_source(
            live=live,
            ledger=ledger,
            population_root=population_root,
            registration_root=registration_root / _SOURCE,
            expected_registration_publication_sha256=previous.binding.source_preparation_sha256,
            output_root=output_root / _SOURCE,
            calendar_origin=calendar_origin,
        ) as source:
            original_source = source._retained

            def envelope() -> CalibrationCheckpointSubject:
                previous.require_unchanged()
                source.require_unchanged()
                if source._retained is not original_source:
                    raise ValueError("checkpoint publication original source owner changed")
                return build(
                    subject=original_source.subject,
                    transparency_proof=transparency_proof,
                    expected_checkpoint_sha256=expected_checkpoint_sha256,
                    registration=previous.checkpoint,
                )

            checkpoint = envelope()
            expected = calibration_checkpoint_subject_bytes(checkpoint)

            def require() -> None:
                pristine()
                if calibration_checkpoint_subject_bytes(envelope()) != expected:
                    raise ValueError("checkpoint publication original measurement proof changed")
                previous.require_unchanged()
                source.require_unchanged()
                pristine()

            with _prepare(
                source=source,
                checkpoint=checkpoint,
                output_root=output_root,
                directory=directory,
                registration_publication_sha256=previous.binding.publication_sha256,
                require_source=require,
            ) as owner:
                yield owner
        owner.require_unchanged()

    return prepare_registration, prepare_measurement


prepare_calibration_registration_checkpoint, prepare_calibration_measurement_checkpoint = (
    _build_checkpoint_preparers()
)
del _build_checkpoint_preparers


def load_calibration_checkpoint_publication(
    *, output_root: Path, expected_publication_sha256: str
) -> CalibrationCheckpointCalendarObservation:
    """Read pinned checkpoint/source data; no original native capability is recreated."""

    retained = _read_retained(output_root, expected_publication_sha256)
    calendar = _calendar.load_calibration_calendar_journal(
        evidence_root=output_root / _CALENDAR,
        expected_preparation_sha256=retained.binding.preparation.preparation_sha256,
    )
    return _observation(retained, calendar)


async def recover_calibration_checkpoint_publication(
    *,
    output_root: Path,
    expected_publication_sha256: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalibrationCheckpointCalendarObservation:
    """GET only at the original checkpoint commitment; never issue new POST permission."""

    if allow_calendar_contact is not True:
        raise ValueError("checkpoint recovery requires explicit up-front contact authorization")
    retained = _read_retained(output_root, expected_publication_sha256)
    try:
        async with _calendar.recover_calibration_checkpoint_calendar_journal(
            evidence_root=output_root / _CALENDAR,
            expected_preparation_sha256=retained.binding.preparation.preparation_sha256,
            subject=retained.checkpoint,
            calendar_origin=retained.binding.preparation.calendar_origin,
            allow_calendar_contact=allow_calendar_contact,
            timeout_seconds=timeout_seconds,
        ) as (journal, calendar):
            complete = _retain_original_calendar_history(retained, journal)
            observation = _observation(complete, calendar)
        complete.require_unchanged()
        return observation
    except asyncio.CancelledError:
        raise _source.CalibrationCalendarPublicationCancelled(expected_publication_sha256) from None
    except Exception:
        raise _source.CalibrationCalendarPublicationError(expected_publication_sha256) from None
