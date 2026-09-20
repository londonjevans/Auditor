"""Private crash-recovery data, never external chronology or publication authority.

A fresh, process-locked owner retains preparation and dispatch intent before one
POST. Reopening only permits GET at that original commitment. Interrupted or
incoherent files refuse without repair; local hashes do not prevent coherent
storage rollback or authenticate a calendar, chain, time or population seal.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.calibration_checkpoint import (
    CalibrationCheckpointSubject,
    calibration_checkpoint_publication_request,
)
from mmaudit.models.opentimestamps_calendar import (
    CalendarCommitmentUnavailable,
    assemble_opentimestamps_submission_proof,
    prepare_opentimestamps_submission,
)
from mmaudit.orchestration import opentimestamps_calendar_transport as transport
from mmaudit.orchestration.calibration_publication import (
    CalibrationPublicationSubject,
    PublicationPhase,
    _PublicationData,
    calibration_publication_request,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    prepare_owned_empty_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

MAX_CALENDAR_LOOKUP_ATTEMPTS = 16
MAX_CALENDAR_JOURNAL_EVENTS = 3 + 2 * MAX_CALENDAR_LOOKUP_ATTEMPTS
MAX_CALENDAR_JOURNAL_EVENT_BYTES = 32_000
_SHA = r"^[0-9a-f]{64}$"
_LABEL = "calendar recovery journal"
type CalendarJournalKind = Literal[
    "PREPARED",
    "POST_STARTED",
    "POST_REPLAYED",
    "POST_UNCERTAIN",
    "LOOKUP_STARTED",
    "LOOKUP_REPLAYED",
    "LOOKUP_UNAVAILABLE",
    "LOOKUP_UNCERTAIN",
]


class CalendarJournalPreparation(BaseModel):
    """Exact serialized request context; construction conveys no dispatch authority."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    file_convention: Literal["SHA256_BINARY_SUBJECT_DIGEST_V1"] = "SHA256_BINARY_SUBJECT_DIGEST_V1"
    subject_sha256: str = Field(pattern=_SHA)
    phase: PublicationPhase
    file_sha256: str = Field(pattern=_SHA)
    nonce_hex: str = Field(pattern=r"^[0-9a-f]{32}$")
    calendar_origin: str = Field(min_length=1, max_length=512)
    method: Literal["POST"] = "POST"
    relative_path: Literal["digest"] = "digest"
    headers: tuple[tuple[str, str], ...] = Field(min_length=2, max_length=2)
    commitment_hex: str = Field(pattern=_SHA)
    body_hex: str = Field(pattern=_SHA)
    preparation_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def original_request_is_exact(self) -> Self:
        transport._require_origin(self.calendar_origin)
        request = prepare_opentimestamps_submission(
            file_sha256=self.file_sha256, nonce=bytes.fromhex(self.nonce_hex)
        )
        if (
            self.file_sha256 != hashlib.sha256(bytes.fromhex(self.subject_sha256)).hexdigest()
            or self.headers != request.headers
            or self.commitment_hex != request.commitment.hex()
            or self.body_hex != request.body.hex()
            or self.preparation_sha256
            != canonical_sha256(self.model_dump(mode="json", exclude={"preparation_sha256"}))
        ):
            raise ValueError("calendar preparation differs from its exact subject/request hash")
        return self


def _context(preparation: CalendarJournalPreparation) -> transport.CalendarSubmissionContext:
    return transport.CalendarSubmissionContext(
        preparation.file_sha256,
        bytes.fromhex(preparation.nonce_hex),
        prepare_opentimestamps_submission(
            file_sha256=preparation.file_sha256, nonce=bytes.fromhex(preparation.nonce_hex)
        ),
        preparation.calendar_origin,
    )


def _detached(preparation: CalendarJournalPreparation, body: bytes) -> bytes:
    context = _context(preparation)
    return assemble_opentimestamps_submission_proof(
        context.request,
        file_sha256=context.file_sha256,
        nonce=context.nonce,
        status_code=200,
        body=body,
    )


class CalendarJournalEvent(_PublicationData):
    """Canonical bounded local observations, including uncompleted dispatch intents."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["CALENDAR_RECOVERY_EVENT"] = "CALENDAR_RECOVERY_EVENT"
    event_index: int = Field(ge=0, lt=MAX_CALENDAR_JOURNAL_EVENTS)
    previous_event_sha256: str | None = Field(pattern=_SHA)
    kind: CalendarJournalKind
    preparation: CalendarJournalPreparation
    response_body_hex: str | None = Field(default=None, pattern=r"^[0-9a-f]+$", max_length=20_000)
    failure: Literal["EXCHANGE_REFUSED", "CANCELLED"] | None = None
    event_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def event_data_is_consistent(self) -> Self:
        if (self.event_index == 0) != (self.kind == "PREPARED") or (
            (self.event_index == 0) != (self.previous_event_sha256 is None)
        ):
            raise ValueError("calendar journal must start with a preparation")
        if self.kind in {"POST_REPLAYED", "LOOKUP_REPLAYED"}:
            if self.response_body_hex is None or self.failure is not None:
                raise ValueError("calendar replay event requires only complete proof bytes")
            _detached(self.preparation, bytes.fromhex(self.response_body_hex))
        elif self.kind in {"POST_UNCERTAIN", "LOOKUP_UNCERTAIN"}:
            if self.response_body_hex is not None or self.failure is None:
                raise ValueError("calendar uncertain event requires a nonreflecting failure label")
        elif self.response_body_hex is not None or self.failure is not None:
            raise ValueError("calendar intent/unavailable event cannot contain an outcome")
        if self.event_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"event_sha256"})
        ):
            raise ValueError("calendar event hash differs from its exact data")
        return self


def _require_transition(previous: CalendarJournalEvent, current: CalendarJournalEvent) -> None:
    if current.kind == "LOOKUP_STARTED":
        allowed = previous.kind != "PREPARED"
    else:
        allowed = (previous.kind, current.kind) in {
            ("PREPARED", "POST_STARTED"),
            ("POST_STARTED", "POST_REPLAYED"),
            ("POST_STARTED", "POST_UNCERTAIN"),
            ("LOOKUP_STARTED", "LOOKUP_REPLAYED"),
            ("LOOKUP_STARTED", "LOOKUP_UNAVAILABLE"),
            ("LOOKUP_STARTED", "LOOKUP_UNCERTAIN"),
        }
    if (
        not allowed
        or current.event_index != previous.event_index + 1
        or current.previous_event_sha256 != previous.event_sha256
        or current.preparation != previous.preparation
    ):
        raise ValueError("calendar journal prefix, context or transition differs")


def _preparation(subject: CalibrationPublicationSubject, origin: str) -> CalendarJournalPreparation:
    digest_file = calibration_publication_request(subject)
    return _preparation_for_digest(digest_file, subject.phase, origin)


def _preparation_for_digest(
    digest_file: bytes, phase: PublicationPhase, origin: str
) -> CalendarJournalPreparation:
    context = transport._prepare_submission_context(
        file_sha256=hashlib.sha256(digest_file).hexdigest(), calendar_origin=origin
    )
    provisional = CalendarJournalPreparation.model_construct(
        subject_sha256=digest_file.hex(),
        phase=phase,
        file_sha256=context.file_sha256,
        nonce_hex=context.nonce.hex(),
        calendar_origin=origin,
        headers=context.request.headers,
        commitment_hex=context.request.commitment.hex(),
        body_hex=context.request.body.hex(),
        preparation_sha256="0" * 64,
    )
    material = provisional.model_dump(mode="json", exclude={"preparation_sha256"})
    return CalendarJournalPreparation.model_validate_json(
        stable_json({**material, "preparation_sha256": canonical_sha256(material)})
    )


class CalendarJournalError(transport.CalendarTransportError):
    """No receipt: retained intent and context may still require lookup-only recovery."""

    def __init__(self, preparation: CalendarJournalPreparation, *, outcome_retained: bool) -> None:
        super().__init__(
            "calendar journal exchange refused; inspect retained intent, never repeat POST",
            publication_may_have_occurred=True,
            submission_context=_context(preparation),
        )
        self.preparation_sha256 = preparation.preparation_sha256
        self.outcome_retained = outcome_retained


class CalendarJournalCancelled(transport.CalendarSubmissionCancelled):
    """Cancellation remains cancellation, even if its outcome could not be retained."""

    def __init__(self, preparation: CalendarJournalPreparation, *, outcome_retained: bool) -> None:
        super().__init__(_context(preparation))
        self.preparation_sha256 = preparation.preparation_sha256
        self.outcome_retained = outcome_retained


@dataclass(frozen=True, slots=True)
class CalendarJournalObservation:
    """Data, not publication verification; fresh-owner callers must also exit its scope."""

    events: tuple[CalendarJournalEvent, ...]
    detached_proof: bytes | None


class _Journal:
    def __init__(self, root: Path, descriptor: int, *, fresh: bool) -> None:
        self.root, self.descriptor = root, descriptor
        self.pid = os.getpid()
        self.directory = observe_unlinked_directory(
            root, label=_LABEL, allow_entry_metadata_change=True
        )
        self.events: list[CalendarJournalEvent] = []
        self.custody: list[RegularFileCustodyObservation] = []
        self.closed = False
        self.post_eligible = fresh
        self._require_directory()

    def _require_directory(self) -> None:
        if self.closed or os.getpid() != self.pid:
            raise ValueError("calendar journal owner is closed or belongs to another process")
        require_same_unlinked_directory_objects(self.directory, label=_LABEL)
        held, entry = os.fstat(self.descriptor), self.root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(held.st_mode)
            or stat.S_IMODE(held.st_mode) != 0o700
            or held.st_uid != os.geteuid()
            or (held.st_dev, held.st_ino, held.st_mode, held.st_uid)
            != (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid)
        ):
            raise ValueError("calendar journal directory is not the exact private owned object")

    def _names(self) -> list[str]:
        self._require_directory()
        names = []
        for entry in self.root.iterdir():
            names.append(entry.name)
            if len(names) > MAX_CALENDAR_JOURNAL_EVENTS:
                raise ValueError("calendar journal exceeds its fixed event count")
        return sorted(names)

    def require_unchanged(self) -> None:
        self._require_directory()
        if len(self.events) != len(self.custody):
            raise ValueError("calendar journal retained event/custody count differs")
        for event, custody in zip(self.events, self.custody, strict=True):
            if (
                type(event) is not CalendarJournalEvent
                or hashlib.sha256(stable_json(event.model_dump(mode="json")).encode()).hexdigest()
                != custody.binding.sha256
            ):
                raise ValueError("calendar journal in-memory data differs from retained evidence")
            require_regular_file_custody_unchanged(
                custody,
                label=_LABEL,
                max_bytes=MAX_CALENDAR_JOURNAL_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        if self._names() != [f"{index:03d}.json" for index in range(len(self.events))]:
            raise ValueError("calendar journal contains a changed, missing or extra event")

    def _observe(self, name: str) -> RegularFileCustodyObservation:
        observed = observe_regular_file_custody(
            root=self.root,
            relative_path=name,
            label=_LABEL,
            max_bytes=MAX_CALENDAR_JOURNAL_EVENT_BYTES,
            allow_directory_entry_metadata_change=True,
        )
        metadata = (self.root / name).stat(follow_symlinks=False)
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid():
            raise ValueError("calendar journal event must be private and owned")
        return observed

    def load(self, expected_preparation_sha256: str) -> None:
        if (
            type(expected_preparation_sha256) is not str
            or len(expected_preparation_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_preparation_sha256)
        ):
            raise ValueError("calendar recovery requires an exact original preparation hash")
        names = self._names()
        if not names or names != [f"{index:03d}.json" for index in range(len(names))]:
            raise ValueError("calendar journal is not a nonempty exact event prefix")
        for name in names:
            data = read_file_evidence(
                evidence_root=self.root,
                relative_path=name,
                max_bytes=MAX_CALENDAR_JOURNAL_EVENT_BYTES,
            )
            custody = self._observe(name)
            event = CalendarJournalEvent.model_validate_json(data.content)
            if (
                custody.binding != data.binding
                or stable_json(event.model_dump(mode="json")).encode() != data.content
                or event.preparation.preparation_sha256 != expected_preparation_sha256
                or event.event_index != len(self.events)
            ):
                raise ValueError(
                    "calendar journal canonical data or original preparation pin differs"
                )
            if self.events:
                _require_transition(self.events[-1], event)
            self.events.append(event)
            self.custody.append(custody)
        if (
            sum(event.kind == "LOOKUP_STARTED" for event in self.events)
            > MAX_CALENDAR_LOOKUP_ATTEMPTS
        ):
            raise ValueError("calendar journal lookup attempt count exceeds its bound")
        self.require_unchanged()

    def append(
        self,
        kind: CalendarJournalKind,
        preparation: CalendarJournalPreparation,
        *,
        body: bytes | None = None,
        failure: Literal["EXCHANGE_REFUSED", "CANCELLED"] | None = None,
    ) -> CalendarJournalEvent:
        self.require_unchanged()
        provisional = CalendarJournalEvent.model_construct(
            event_index=len(self.events),
            kind=kind,
            preparation=preparation,
            previous_event_sha256=self.events[-1].event_sha256 if self.events else None,
            response_body_hex=body.hex() if body is not None else None,
            failure=failure,
            event_sha256="0" * 64,
        )
        material = provisional.model_dump(mode="json", exclude={"event_sha256"})
        event = CalendarJournalEvent.model_validate_json(
            stable_json({**material, "event_sha256": canonical_sha256(material)})
        )
        if self.events:
            _require_transition(self.events[-1], event)
        name = f"{len(self.events):03d}.json"
        binding = write_json_evidence(
            evidence_root=self.root,
            relative_path=name,
            value=event.model_dump(mode="json"),
            max_bytes=MAX_CALENDAR_JOURNAL_EVENT_BYTES,
            require_private_parent=True,
        )
        observed = self._observe(name)
        if observed.binding != binding:
            raise ValueError("calendar journal event changed after durable write")
        self.events.append(event)
        self.custody.append(observed)
        self.require_unchanged()
        return event


@contextmanager
def _locked_journal(root: Path, *, create: bool = False) -> Iterator[_Journal]:
    # No lock-file replacement race: separate opens lock the original directory inode.
    # On platforms/filesystems without directory flock, refuse instead of falling back.
    try:
        import fcntl
    except ImportError:
        raise ValueError("calendar journal requires supported local process exclusion") from None
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("calendar journal root must be absolute and normalized")
    if create:
        prepare_owned_empty_directory(root, label=_LABEL)
    observed = observe_unlinked_directory(root, label=_LABEL, allow_entry_metadata_change=True)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    journal = None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("calendar journal process lock is busy or unavailable") from None
        require_same_unlinked_directory_objects(observed, label=_LABEL)
        journal = _Journal(root, descriptor, fresh=create)
        yield journal
        journal.require_unchanged()
    finally:
        if journal is not None:
            journal.closed = True
        # Closing the last descriptor releases flock; a failed close cannot return success.
        os.close(descriptor)


def _require_subject(
    subject: CalibrationPublicationSubject | CalibrationCheckpointSubject,
    preparation: CalendarJournalPreparation,
    origin: str,
) -> None:
    if type(subject) is CalibrationCheckpointSubject:
        digest_file = calibration_checkpoint_publication_request(subject)
    elif type(subject) is CalibrationPublicationSubject:
        digest_file = calibration_publication_request(subject)
    else:
        raise ValueError("calibration publication requires its exact subject type")
    if (
        digest_file.hex() != preparation.subject_sha256
        or subject.phase != preparation.phase
        or origin != preparation.calendar_origin
    ):
        raise ValueError("calendar recovery subject, phase or original origin differs")


def _snapshot(journal: _Journal) -> CalendarJournalObservation:
    journal.require_unchanged()
    event = journal.events[-1]
    return CalendarJournalObservation(
        tuple(journal.events),
        _detached(event.preparation, bytes.fromhex(event.response_body_hex))
        if event.response_body_hex is not None
        else None,
    )


async def _perform(
    journal: _Journal,
    subject: CalibrationPublicationSubject | CalibrationCheckpointSubject,
    *,
    lookup: bool,
    allow_calendar_contact: bool,
    timeout_seconds: float,
) -> CalendarJournalObservation:
    preparation = journal.events[0].preparation
    _require_subject(subject, preparation, preparation.calendar_origin)
    context = _context(preparation)
    if not lookup:
        if not journal.post_eligible or len(journal.events) != 1:
            raise ValueError("reopened or attempted calendar journal cannot POST")
        journal.post_eligible = False
    if lookup and (
        journal.events[-1].kind == "PREPARED"
        or sum(event.kind == "LOOKUP_STARTED" for event in journal.events)
        >= MAX_CALENDAR_LOOKUP_ATTEMPTS
        or len(journal.events) + 2 > MAX_CALENDAR_JOURNAL_EVENTS
    ):
        raise ValueError("calendar journal has no dispatched request or remaining lookup slots")
    # This complete, fsynced event is retained before entering the HTTP coroutine.
    journal.append("LOOKUP_STARTED" if lookup else "POST_STARTED", preparation)
    try:
        if lookup:
            try:
                exchange = await transport.lookup_opentimestamps_calendar(
                    commitment=context.request.commitment,
                    calendar_origin=context.calendar_origin,
                    allow_calendar_contact=allow_calendar_contact,
                    timeout_seconds=timeout_seconds,
                )
                body: bytes | None = exchange.response_body
            except CalendarCommitmentUnavailable:
                body = None
        else:
            submission = await transport._submit_prepared_context(
                context=context,
                allow_calendar_contact=allow_calendar_contact,
                timeout_seconds=timeout_seconds,
            )
            body = submission.exchange.response_body
        _require_subject(subject, preparation, preparation.calendar_origin)
        journal.append(
            "LOOKUP_UNAVAILABLE"
            if body is None
            else "LOOKUP_REPLAYED"
            if lookup
            else "POST_REPLAYED",
            preparation,
            body=body,
        )
        return _snapshot(journal)
    except (Exception, asyncio.CancelledError) as failure:
        cancelled = isinstance(failure, asyncio.CancelledError)
        retained = False
        try:
            journal.append(
                "LOOKUP_UNCERTAIN" if lookup else "POST_UNCERTAIN",
                preparation,
                failure="CANCELLED" if cancelled else "EXCHANGE_REFUSED",
            )
            retained = True
        except Exception:
            # Do not truncate/repair history. The explicit exception flag retains this gap.
            pass
        if cancelled:
            raise CalendarJournalCancelled(preparation, outcome_retained=retained) from None
        raise CalendarJournalError(preparation, outcome_retained=retained) from None


class PreparedCalendarJournal:
    """A fresh, still-locked local owner. Reconstructed event data cannot resume POST."""

    def __init__(
        self,
        journal: _Journal,
        subject: CalibrationPublicationSubject | CalibrationCheckpointSubject,
    ) -> None:
        if type(journal) is not _Journal or not journal.post_eligible or len(journal.events) != 1:
            raise ValueError("calendar submission requires a fresh local journal owner")
        self._journal, self._subject = journal, subject
        self._attempted = False

    @property
    def preparation(self) -> CalendarJournalPreparation:
        return self._journal.events[0].preparation

    async def submit(
        self, *, allow_calendar_contact: bool = False, timeout_seconds: float = 10.0
    ) -> CalendarJournalObservation:
        """POST at most once within this fresh owner; the enclosing context must also close."""

        transport._require_contact(
            self.preparation.calendar_origin, allow_calendar_contact, timeout_seconds
        )
        self._journal.require_unchanged()
        if self._attempted or len(self._journal.events) != 1:
            raise ValueError("calendar fresh owner cannot repeat POST")
        self._attempted = True
        return await _perform(
            self._journal,
            self._subject,
            lookup=False,
            allow_calendar_contact=allow_calendar_contact,
            timeout_seconds=timeout_seconds,
        )


@contextmanager
def prepare_calibration_calendar_journal(
    *, evidence_root: Path, subject: CalibrationPublicationSubject, calendar_origin: str
) -> Iterator[PreparedCalendarJournal]:
    """Retain a fresh nonce/request offline; callers can pin it before explicit dispatch.

    Keep the original subject, origin and returned preparation hash outside this
    directory for recovery. Closing before submission leaves PREPARED evidence;
    reopening never converts that abandoned preparation into permission to POST.
    """

    transport._require_origin(calendar_origin)
    calibration_publication_request(subject)
    with _locked_journal(evidence_root, create=True) as journal:
        preparation = _preparation(subject, calendar_origin)
        journal.append("PREPARED", preparation)
        yield PreparedCalendarJournal(journal, subject)


def load_calibration_calendar_journal(
    *, evidence_root: Path, expected_preparation_sha256: str
) -> CalendarJournalObservation:
    """Read under process exclusion without HTTP, history repair or authority promotion."""

    with _locked_journal(evidence_root) as journal:
        journal.load(expected_preparation_sha256)
        observation = _snapshot(journal)
    return observation


@contextmanager
def prepare_calibration_checkpoint_calendar_journal(
    *, evidence_root: Path, subject: CalibrationCheckpointSubject, calendar_origin: str
) -> Iterator[PreparedCalendarJournal]:
    """Prepare an explicitly typed checkpoint subject using the same digest-file convention.

    Existing population entry points still refuse checkpoint subjects. The new
    envelope carries the semantic domain; no old population receipt is reinterpreted.
    """

    transport._require_origin(calendar_origin)
    digest_file = calibration_checkpoint_publication_request(subject)
    with _locked_journal(evidence_root, create=True) as journal:
        preparation = _preparation_for_digest(digest_file, subject.phase, calendar_origin)
        journal.append("PREPARED", preparation)
        yield PreparedCalendarJournal(journal, subject)


async def recover_calibration_calendar_journal(
    *,
    evidence_root: Path,
    expected_preparation_sha256: str,
    subject: CalibrationPublicationSubject,
    calendar_origin: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalendarJournalObservation:
    """One recorded GET at the original commitment; no reconstructed state may POST."""

    transport._require_contact(calendar_origin, allow_calendar_contact, timeout_seconds)
    calibration_publication_request(subject)
    with _locked_journal(evidence_root) as journal:
        journal.load(expected_preparation_sha256)
        _require_subject(subject, journal.events[0].preparation, calendar_origin)
        observation = await _perform(
            journal,
            subject,
            lookup=True,
            allow_calendar_contact=allow_calendar_contact,
            timeout_seconds=timeout_seconds,
        )
    return observation


@asynccontextmanager
async def recover_calibration_checkpoint_calendar_journal(
    *,
    evidence_root: Path,
    expected_preparation_sha256: str,
    subject: CalibrationCheckpointSubject,
    calendar_origin: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> AsyncIterator[tuple[_Journal, CalendarJournalObservation]]:
    """Borrow original GET journal custody until cleanup; never reconstruct POST authority.

    The source owner retains the complete original event/file observations before
    this scope closes and must recheck them after all enclosing cleanup.
    """

    transport._require_contact(calendar_origin, allow_calendar_contact, timeout_seconds)
    calibration_checkpoint_publication_request(subject)
    with _locked_journal(evidence_root) as journal:
        journal.load(expected_preparation_sha256)
        _require_subject(subject, journal.events[0].preparation, calendar_origin)
        observation = await _perform(
            journal,
            subject,
            lookup=True,
            allow_calendar_contact=allow_calendar_contact,
            timeout_seconds=timeout_seconds,
        )
        yield journal, observation
