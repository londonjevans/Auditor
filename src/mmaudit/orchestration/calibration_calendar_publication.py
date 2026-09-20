"""Source-owned population-to-calendar handoff, without external seal authority.

Private subjects and original nonce/request descriptors survive process loss.
Live source custody is borrowed only inside preparation/submission scopes; readers
and GET recovery never recreate a native measurement proof or external chronology.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.orchestration import calibration_publication as _publication
from mmaudit.orchestration import opentimestamps_calendar_journal as _calendar
from mmaudit.orchestration.authenticated_calibration_measurement import (
    LiveRegisteredCalibrationMeasurement,
)
from mmaudit.orchestration.calibration_publication import (
    MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES,
    CalibrationPublicationSubject,
    _PublicationData,
    calibration_publication_subject_bytes,
    read_calibration_publication_subject,
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
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

_SUBJECT = "subject.json"
_BINDING = "publication.json"
_CALENDAR = "calendar"
_MAX_BINDING_BYTES = 16_000
_SHA = r"^[0-9a-f]{64}$"
_LABEL = "population calendar publication"


class CalibrationCalendarPublicationBinding(_PublicationData):
    """Pinned private recovery descriptor, not native or external publication authority."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["CALIBRATION_CALENDAR_PUBLICATION"] = "CALIBRATION_CALENDAR_PUBLICATION"
    subject_file: ManifestFileBinding
    registration_event_sha256: str = Field(pattern=_SHA)
    registration_publication_sha256: str | None = Field(pattern=_SHA)
    calendar_directory: Literal["calendar"] = "calendar"
    preparation: _calendar.CalendarJournalPreparation
    publication_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def descriptor_is_exact_and_nonauthorizing(self) -> Self:
        if (
            self.subject_file.path != _SUBJECT
            or not 0 < self.subject_file.size <= MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES
            or (self.preparation.phase == "POPULATION_REGISTRATION")
            != (self.registration_publication_sha256 is None)
            or self.publication_sha256
            != canonical_sha256(self.model_dump(mode="json", exclude={"publication_sha256"}))
        ):
            raise ValueError("population calendar descriptor hash, phase or file binding differs")
        return self


@dataclass(frozen=True, slots=True)
class CalibrationCalendarPublicationObservation:
    """Constructible data; even an earlier live handoff cannot be revived by reading it."""

    binding: CalibrationCalendarPublicationBinding
    subject: CalibrationPublicationSubject
    calendar: _calendar.CalendarJournalObservation


class CalibrationCalendarPublicationError(ValueError):
    """The child may have published a digest; no source-owned handoff was completed."""

    def __init__(self, publication_sha256: str) -> None:
        super().__init__(
            "population calendar handoff refused; retain original descriptor for GET recovery"
        )
        self.publication_sha256 = publication_sha256
        self.publication_may_have_occurred = True


class CalibrationCalendarPublicationCancelled(asyncio.CancelledError):
    """Cancellation with the original durable descriptor, never a publication receipt."""

    def __init__(self, publication_sha256: str) -> None:
        super().__init__("population calendar handoff cancelled; retain original descriptor")
        self.publication_sha256 = publication_sha256
        self.publication_may_have_occurred = True


def _require_pin(value: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError(
            "population publication requires an exact externally retained descriptor pin"
        )


def _private_directory(root: Path) -> DirectoryCustodyObservation:
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("population publication root must be absolute and normalized")
    observed = observe_unlinked_directory(root, label=_LABEL, allow_entry_metadata_change=True)
    metadata = root.stat(follow_symlinks=False)
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
        raise ValueError("population publication directory must be private and owned")
    require_same_unlinked_directory_objects(observed, label=_LABEL)
    return observed


def _private_file(
    root: Path, binding: ManifestFileBinding, bound: int
) -> RegularFileCustodyObservation:
    custody = observe_regular_file_custody(
        root=root,
        relative_path=binding.path,
        expected_binding=binding,
        label=_LABEL,
        max_bytes=bound,
        allow_directory_entry_metadata_change=True,
    )
    metadata = (root / binding.path).stat(follow_symlinks=False)
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid():
        raise ValueError("population publication file must be private and owned")
    return custody


def _names(root: Path) -> set[str]:
    names = set()
    for path in root.iterdir():
        names.add(path.name)
        if len(names) > 3:
            raise ValueError("population publication contains extra files")
    return names


@dataclass(frozen=True, slots=True)
class _RetainedPublication:
    root: Path
    subject: CalibrationPublicationSubject
    binding: CalibrationCalendarPublicationBinding
    directory: DirectoryCustodyObservation
    calendar_directory: DirectoryCustodyObservation
    custody: tuple[tuple[RegularFileCustodyObservation, int], ...]

    def require_unchanged(self) -> None:
        for directory in (self.directory, self.calendar_directory):
            require_same_unlinked_directory_objects(directory, label=_LABEL)
        for custody, bound in self.custody:
            require_regular_file_custody_unchanged(
                custody, label=_LABEL, max_bytes=bound, allow_directory_entry_metadata_change=True
            )
        raw = calibration_publication_subject_bytes(self.subject)
        descriptor = stable_json(self.binding.model_dump(mode="json")).encode()
        if (
            hashlib.sha256(raw).hexdigest() != self.binding.subject_file.sha256
            or hashlib.sha256(descriptor).hexdigest() != self.custody[0][0].binding.sha256
            or _names(self.root) != {_SUBJECT, _BINDING, _CALENDAR}
        ):
            raise ValueError("population publication in-memory or retained input set changed")


def _read_retained(root: Path, expected_publication_sha256: str) -> _RetainedPublication:
    _require_pin(expected_publication_sha256)
    directory = _private_directory(root)
    if _names(root) != {_SUBJECT, _BINDING, _CALENDAR}:
        raise ValueError("population publication subject/descriptor/calendar set is incomplete")
    descriptor = read_file_evidence(
        evidence_root=root, relative_path=_BINDING, max_bytes=_MAX_BINDING_BYTES
    )
    binding = CalibrationCalendarPublicationBinding.model_validate_json(descriptor.content)
    if (
        stable_json(binding.model_dump(mode="json")).encode() != descriptor.content
        or binding.publication_sha256 != expected_publication_sha256
    ):
        raise ValueError("population publication canonical descriptor or original pin differs")
    descriptor_custody = _private_file(root, descriptor.binding, _MAX_BINDING_BYTES)
    observed = read_file_evidence(
        evidence_root=root,
        relative_path=_SUBJECT,
        max_bytes=MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES,
    )
    if observed.binding != binding.subject_file:
        raise ValueError("population publication subject file differs from original descriptor")
    subject = read_calibration_publication_subject(observed.content)
    if (
        subject.subject_sha256 != binding.preparation.subject_sha256
        or subject.phase != binding.preparation.phase
        or subject.population_events[0].event_sha256 != binding.registration_event_sha256
    ):
        raise ValueError("population publication descriptor does not join its original subject")
    subject_custody = _private_file(
        root, observed.binding, MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES
    )
    calendar_root = root / _CALENDAR
    calendar_directory = _private_directory(calendar_root)
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
        raise ValueError("population publication original calendar preparation differs")
    retained = _RetainedPublication(
        root,
        subject,
        binding,
        directory,
        calendar_directory,
        (
            (descriptor_custody, _MAX_BINDING_BYTES),
            (subject_custody, MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES),
            (
                _private_file(
                    calendar_root, prepared.binding, _calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES
                ),
                _calendar.MAX_CALENDAR_JOURNAL_EVENT_BYTES,
            ),
        ),
    )
    retained.require_unchanged()
    return retained


def _observation(
    retained: _RetainedPublication, calendar: _calendar.CalendarJournalObservation
) -> CalibrationCalendarPublicationObservation:
    retained.require_unchanged()
    if (
        type(calendar) is not _calendar.CalendarJournalObservation
        or not calendar.events
        or (calendar.events[0].preparation != retained.binding.preparation)
    ):
        raise ValueError("population calendar observation differs from its original descriptor")
    return CalibrationCalendarPublicationObservation(retained.binding, retained.subject, calendar)


class PreparedCalibrationCalendarPublication:
    """Borrowed live source custody; keep the enclosing scope through submit and cleanup."""

    def __init__(
        self,
        retained: _RetainedPublication,
        calendar: _calendar.PreparedCalendarJournal,
        require_source: Callable[[], None],
    ) -> None:
        self._retained, self._calendar, self._require_source = retained, calendar, require_source

    @property
    def binding(self) -> CalibrationCalendarPublicationBinding:
        return self._retained.binding

    def require_unchanged(self) -> None:
        self._require_source()
        self._retained.require_unchanged()

    async def submit(
        self, *, allow_calendar_contact: bool = False, timeout_seconds: float = 10.0
    ) -> CalibrationCalendarPublicationObservation:
        """Submit once with original live sources checked on both sides of the await."""

        _require_contact(
            self.binding.preparation.calendar_origin, allow_calendar_contact, timeout_seconds
        )
        self.require_unchanged()
        try:
            observed = await self._calendar.submit(
                allow_calendar_contact=allow_calendar_contact, timeout_seconds=timeout_seconds
            )
        except asyncio.CancelledError:
            raise CalibrationCalendarPublicationCancelled(self.binding.publication_sha256) from None
        except Exception:
            raise CalibrationCalendarPublicationError(self.binding.publication_sha256) from None
        try:
            self.require_unchanged()
            return _observation(self._retained, observed)
        except Exception:
            raise CalibrationCalendarPublicationError(self.binding.publication_sha256) from None


def _require_disjoint_output(root: Path, sources: tuple[Path, ...]) -> None:
    for path in (root, *sources):
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("population publication paths must be absolute and normalized")
    if any(root.is_relative_to(path) or path.is_relative_to(root) for path in sources):
        raise ValueError(
            "population publication output must be separate from all original source roots"
        )


@contextmanager
def _prepare(
    *,
    subject: CalibrationPublicationSubject,
    output_root: Path,
    calendar_origin: str,
    registration_publication_sha256: str | None,
    require_source: Callable[[], None],
) -> Iterator[PreparedCalibrationCalendarPublication]:
    _require_origin(calendar_origin)
    require_source()
    directory = prepare_owned_empty_directory(output_root, label=_LABEL)
    subject_binding = write_json_evidence(
        evidence_root=output_root,
        relative_path=_SUBJECT,
        value=subject.model_dump(mode="json"),
        max_bytes=MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES,
        require_private_parent=True,
    )
    subject_custody = _private_file(
        output_root, subject_binding, MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES
    )
    with _calendar.prepare_calibration_calendar_journal(
        evidence_root=output_root / _CALENDAR, subject=subject, calendar_origin=calendar_origin
    ) as calendar:
        provisional = CalibrationCalendarPublicationBinding.model_construct(
            subject_file=subject_binding,
            registration_event_sha256=subject.population_events[0].event_sha256,
            registration_publication_sha256=registration_publication_sha256,
            preparation=calendar.preparation,
            publication_sha256="0" * 64,
        )
        material = provisional.model_dump(mode="json", exclude={"publication_sha256"})
        binding = CalibrationCalendarPublicationBinding.model_validate_json(
            stable_json({**material, "publication_sha256": canonical_sha256(material)})
        )
        descriptor_binding = write_json_evidence(
            evidence_root=output_root,
            relative_path=_BINDING,
            value=binding.model_dump(mode="json"),
            max_bytes=_MAX_BINDING_BYTES,
            require_private_parent=True,
        )
        descriptor_custody = _private_file(output_root, descriptor_binding, _MAX_BINDING_BYTES)
        require_same_unlinked_directory_objects(directory, label=_LABEL)
        retained = _read_retained(output_root, binding.publication_sha256)
        for custody, bound in (
            (subject_custody, MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES),
            (descriptor_custody, _MAX_BINDING_BYTES),
        ):
            require_regular_file_custody_unchanged(
                custody, label=_LABEL, max_bytes=bound, allow_directory_entry_metadata_change=True
            )
        require_same_unlinked_directory_objects(directory, label=_LABEL)
        owner = PreparedCalibrationCalendarPublication(retained, calendar, require_source)
        owner.require_unchanged()
        yield owner
        owner.require_unchanged()
    # The child close is a fallible boundary too; no enclosing handoff precedes it.
    owner.require_unchanged()


def _build_source_preparers() -> tuple[
    Callable[..., AbstractContextManager[PreparedCalibrationCalendarPublication]],
    Callable[..., AbstractContextManager[PreparedCalibrationCalendarPublication]],
]:
    publication = _publication
    registration = publication.build_calibration_registration_publication
    measurement = publication.build_calibration_measurement_publication
    retain = publication._retained_journal
    require_journal = publication._require_journal
    originals = (
        ("build_calibration_registration_publication", registration, registration.__code__),
        ("build_calibration_measurement_publication", measurement, measurement.__code__),
        ("_retained_journal", retain, retain.__code__),
        ("_require_journal", require_journal, require_journal.__code__),
    )

    def pristine() -> None:
        if _publication is not publication or any(
            getattr(publication, name) is not function or function.__code__ is not code
            for name, function, code in originals
        ):
            raise ValueError("population publication original source producers changed")

    def source_guard(
        source: Callable[[], CalibrationPublicationSubject],
        root: Path,
        subject: CalibrationPublicationSubject,
    ) -> Callable[[], None]:
        expected = calibration_publication_subject_bytes(subject)
        events, custody = retain(root, subject.population_events[0].event_sha256)
        if events != subject.population_events:
            raise ValueError("population publication differs from the original source journal")

        def require() -> None:
            pristine()
            if calibration_publication_subject_bytes(source()) != expected:
                raise ValueError("population publication original source projection changed")
            require_journal(root, events, custody)
            pristine()

        require()
        return require

    @contextmanager
    def prepare_registration(
        *,
        population_root: Path,
        expected_registration_sha256: str,
        output_root: Path,
        calendar_origin: str,
    ) -> Iterator[PreparedCalibrationCalendarPublication]:
        """Retain the actual single-event registration and original calendar preparation."""

        pristine()
        _require_disjoint_output(output_root, (population_root,))

        def source() -> CalibrationPublicationSubject:
            return registration(
                evidence_root=population_root,
                expected_registration_sha256=expected_registration_sha256,
            )

        subject = source()
        require = source_guard(source, population_root, subject)
        with _prepare(
            subject=subject,
            output_root=output_root,
            calendar_origin=calendar_origin,
            registration_publication_sha256=None,
            require_source=require,
        ) as owner:
            yield owner

    @contextmanager
    def prepare_measurement(
        *,
        live: LiveRegisteredCalibrationMeasurement,
        ledger: AtomicCostLedger,
        population_root: Path,
        registration_root: Path,
        expected_registration_publication_sha256: str,
        output_root: Path,
        calendar_origin: str,
    ) -> Iterator[PreparedCalibrationCalendarPublication]:
        """Borrow original native custody; a descriptor is not proof of prior publication."""

        pristine()
        _require_disjoint_output(output_root, (population_root, registration_root))
        preceding = _read_retained(registration_root, expected_registration_publication_sha256)
        if preceding.subject.phase != "POPULATION_REGISTRATION":
            raise ValueError(
                "measurement publication requires the original registration descriptor"
            )

        if (
            type(live) is not LiveRegisteredCalibrationMeasurement
            or type(ledger) is not AtomicCostLedger
        ):
            raise ValueError(
                "population publication requires original live measurement and ledger types"
            )
        field_names = ("registration_sha256", "calibration", "policy", "verification")
        fields = tuple(getattr(live, name) for name in field_names)
        original_ledger = ledger.snapshot_with_identity_sha256()

        def require_original_live_fields() -> None:
            if any(
                getattr(live, name) is not value
                for name, value in zip(field_names, fields, strict=True)
            ):
                raise ValueError("population publication borrowed live fields changed")
            if ledger.snapshot_with_identity_sha256() != original_ledger:
                raise ValueError("population publication original ledger changed")

        def source() -> CalibrationPublicationSubject:
            require_original_live_fields()
            observed = measurement(live=live, evidence_root=population_root, ledger=ledger)
            require_original_live_fields()
            return observed

        subject = source()
        if (
            subject.population_events[:1] != preceding.subject.population_events
            or calendar_origin != preceding.binding.preparation.calendar_origin
        ):
            raise ValueError(
                "measurement publication registration population or calendar origin differs"
            )
        require_native = source_guard(source, population_root, subject)

        def require() -> None:
            require_native()
            preceding.require_unchanged()

        with _prepare(
            subject=subject,
            output_root=output_root,
            calendar_origin=calendar_origin,
            registration_publication_sha256=preceding.binding.publication_sha256,
            require_source=require,
        ) as owner:
            yield owner

    return prepare_registration, prepare_measurement


prepare_calibration_registration_calendar, prepare_calibration_measurement_calendar = (
    _build_source_preparers()
)
del _build_source_preparers


def load_calibration_calendar_publication(
    *, output_root: Path, expected_publication_sha256: str
) -> CalibrationCalendarPublicationObservation:
    """Read original private subject/request data without native or external authority."""

    retained = _read_retained(output_root, expected_publication_sha256)
    calendar = _calendar.load_calibration_calendar_journal(
        evidence_root=output_root / _CALENDAR,
        expected_preparation_sha256=retained.binding.preparation.preparation_sha256,
    )
    return _observation(retained, calendar)


async def recover_calibration_calendar_publication(
    *,
    output_root: Path,
    expected_publication_sha256: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalibrationCalendarPublicationObservation:
    """Recover using the externally pinned descriptor; only GET, never a live-proof reader."""

    if allow_calendar_contact is not True:
        raise ValueError(
            "population calendar recovery requires explicit up-front contact authorization"
        )
    retained = _read_retained(output_root, expected_publication_sha256)
    try:
        calendar = await _calendar.recover_calibration_calendar_journal(
            evidence_root=output_root / _CALENDAR,
            expected_preparation_sha256=retained.binding.preparation.preparation_sha256,
            subject=retained.subject,
            calendar_origin=retained.binding.preparation.calendar_origin,
            allow_calendar_contact=allow_calendar_contact,
            timeout_seconds=timeout_seconds,
        )
        return _observation(retained, calendar)
    except asyncio.CancelledError:
        raise CalibrationCalendarPublicationCancelled(expected_publication_sha256) from None
    except Exception:
        raise CalibrationCalendarPublicationError(expected_publication_sha256) from None
