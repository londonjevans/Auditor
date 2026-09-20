"""Two-phase calendar recording at the real registered/native batch boundaries.

Calendar replies, including pending proofs, are data, not external seals or paid
permission. Existing authenticated preflights, native proofs and all release gates
remain mandatory. No file reader reconstructs this one-task recording lifecycle.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Literal, Never, SupportsIndex

from mmaudit.models import authenticated_calibration as _native
from mmaudit.models import calibration_checkpoint as _checkpoint
from mmaudit.models.authenticated_calibration import authenticated_model_calibration_bytes
from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.models.evidence_seal_authority import EvidenceTransparencyPrefixProof
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration import authenticated_calibration_measurement as _measurement
from mmaudit.orchestration import calibration_calendar_publication as _publication
from mmaudit.orchestration import calibration_checkpoint_publication as _checkpoint_publication
from mmaudit.orchestration import calibration_publication as _population_publication
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterLaunch,
)
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, cost_ledger_snapshot_sha256
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.orchestration.opentimestamps_calendar_journal import MAX_CALENDAR_JOURNAL_EVENT_BYTES
from mmaudit.orchestration.opentimestamps_calendar_transport import _require_contact
from mmaudit.release_io import read_file_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    require_regular_file_custody_unchanged,
)


@dataclass(frozen=True, slots=True)
class CalendarRecordedCalibrationResult:
    """Detached observations only; recording order is not authenticated chronology."""

    registration: _publication.CalibrationCalendarPublicationObservation
    measurement_publication: _publication.CalibrationCalendarPublicationObservation
    measurement: _measurement.RegisteredCalibrationMeasurementResult


@dataclass(frozen=True, slots=True)
class CheckpointRecordedCalibrationResult:
    """Distinct checkpoint-profile data; never reinterpret a population-only receipt."""

    registration: _checkpoint_publication.CalibrationCheckpointCalendarObservation
    measurement_publication: _checkpoint_publication.CalibrationCheckpointCalendarObservation
    measurement: _measurement.RegisteredCalibrationMeasurementResult


class OwnedCheckpointCalibrationCompletion:
    """Scoped original completion custody, never a native proof or an external seal."""

    __slots__ = ()

    def __new__(cls) -> OwnedCheckpointCalibrationCompletion:
        raise TypeError("checkpoint completion is owned by its original scope")

    def __copy__(self) -> Never:
        raise TypeError("checkpoint completion cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("checkpoint completion cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("checkpoint completion cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("checkpoint completion cannot be serialized")


@dataclass(frozen=True, slots=True)
class _RetainedNativeCompletion:
    live: _measurement.LiveRegisteredCalibrationMeasurement
    registration: str
    calibration: _native.AuthenticatedModelCalibrationArtifact
    policy: QualificationPolicy | None
    verification: _native.VerifiedAuthenticatedModelCalibration
    calibration_bytes: bytes
    policy_bytes: bytes | None

    def require_unchanged(self) -> None:
        if (
            type(self.live) is not _measurement.LiveRegisteredCalibrationMeasurement
            or any(
                getattr(self.live, name) is not original
                for name, original in (
                    ("registration_sha256", self.registration),
                    ("calibration", self.calibration),
                    ("policy", self.policy),
                    ("verification", self.verification),
                )
            )
            or authenticated_model_calibration_bytes(self.calibration) != self.calibration_bytes
            or (stable_json(self.policy).encode() if self.policy is not None else None)
            != self.policy_bytes
        ):
            raise ValueError("checkpoint completion original native inputs changed")


@dataclass(frozen=True, slots=True)
class _CheckpointSeed:
    log_id: str
    initial_proof: EvidenceTransparencyPrefixProof | None
    expected_checkpoint: str | None
    original_bytes: bytes | None

    def require_unchanged(self) -> None:
        _checkpoint._require_pin(self.log_id)
        if self.initial_proof is None:
            if self.expected_checkpoint is not None or self.original_bytes is not None:
                raise ValueError("fresh checkpoint log requires an explicit absent initial tip")
            return
        if self.expected_checkpoint is None:
            raise ValueError("checkpoint controller requires the original initial tip pin")
        _checkpoint._require_pin(self.expected_checkpoint)
        if (
            _checkpoint._proof_bytes(self.initial_proof) != self.original_bytes
            or self.initial_proof.checkpoint.log_id_sha256 != self.log_id
            or self.initial_proof.checkpoint.checkpoint_sha256 != self.expected_checkpoint
            or self.initial_proof.checkpoint.tree_size
            > _checkpoint.MAX_CALIBRATION_CHECKPOINT_LOG_LEAVES - 2
        ):
            raise ValueError("checkpoint controller initial tip changed or lacks two phase slots")


def _freeze_checkpoint_seed(
    supplied: tuple[str, EvidenceTransparencyPrefixProof | None, str | None],
) -> _CheckpointSeed:
    log_id, proof, expected = supplied
    seed = _CheckpointSeed(
        log_id, proof, expected, None if proof is None else _checkpoint._proof_bytes(proof)
    )
    seed.require_unchanged()
    return seed


class _CalendarRecording:
    """Internal phase handle, not a native proof or an external-publication capability."""

    __slots__ = ()

    def __init__(self) -> None:
        raise TypeError("calendar recording handles are owned by the original controller")

    def __reduce__(self) -> Never:
        raise TypeError("calendar recording handles cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("calendar recording handles cannot be serialized")


@dataclass(frozen=True, slots=True)
class _RecordedPublication:
    retained: _publication._RetainedPublication
    observation: _publication.CalibrationCalendarPublicationObservation
    pin: str
    custody: tuple[RegularFileCustodyObservation, ...]

    def require_unchanged(self) -> None:
        self.retained.require_unchanged()
        for item in self.custody:
            require_regular_file_custody_unchanged(
                item,
                label="calendar controller original event",
                max_bytes=MAX_CALENDAR_JOURNAL_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        if (
            _publication.load_calibration_calendar_publication(
                output_root=self.retained.root, expected_publication_sha256=self.pin
            )
            != self.observation
        ):
            raise ValueError("calendar recording original phase history changed")


@dataclass(frozen=True, slots=True)
class _RecordedCheckpointPublication:
    retained: _checkpoint_publication._RetainedCheckpoint
    observation: _checkpoint_publication.CalibrationCheckpointCalendarObservation
    pin: str

    def require_unchanged(self) -> None:
        self.retained.require_unchanged()
        if (
            _checkpoint_publication.load_calibration_checkpoint_publication(
                output_root=self.retained.root, expected_publication_sha256=self.pin
            )
            != self.observation
        ):
            raise ValueError("checkpoint recording original phase history changed")
        self.retained.require_unchanged()


def _retain_checkpoint_publication(
    owner: _checkpoint_publication.PreparedCalibrationCheckpointPublication,
    observation: _checkpoint_publication.CalibrationCheckpointCalendarObservation,
) -> _RecordedCheckpointPublication:
    owner.require_unchanged()
    journal = owner._calendar._journal
    journal.require_unchanged()
    if (
        tuple(event.kind for event in observation.calendar.events)
        != ("PREPARED", "POST_STARTED", "POST_REPLAYED")
        or tuple(journal.events) != observation.calendar.events
        or len(journal.custody) != 3
    ):
        raise ValueError("checkpoint recording requires one original complete exchange history")
    retained = _checkpoint_publication._retain_original_calendar_history(owner._retained, journal)
    return _RecordedCheckpointPublication(retained, observation, owner.binding.publication_sha256)


def _retain_publication(
    owner: _publication.PreparedCalibrationCalendarPublication,
    observation: _publication.CalibrationCalendarPublicationObservation,
) -> _RecordedPublication:
    # Retain the creator's original event observations before its child lock closes.
    owner.require_unchanged()
    journal = owner._calendar._journal
    journal.require_unchanged()
    if (
        tuple(event.kind for event in observation.calendar.events)
        != ("PREPARED", "POST_STARTED", "POST_REPLAYED")
        or tuple(journal.events) != observation.calendar.events
        or len(journal.custody) != 3
    ):
        raise ValueError("calendar recording requires one original complete exchange history")
    return _RecordedPublication(
        owner._retained, observation, owner.binding.publication_sha256, tuple(journal.custody)
    )


def _native_output_bindings(
    live: _measurement.LiveRegisteredCalibrationMeasurement,
) -> tuple[ManifestFileBinding, ...]:
    values = [
        (
            _measurement._MEASUREMENT,
            authenticated_model_calibration_bytes(live.calibration),
        )
    ]
    if live.policy is not None:
        values.append((_measurement._POLICY, stable_json(live.policy).encode()))
    return tuple(
        ManifestFileBinding(path=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        for name, raw in values
    )


@dataclass(slots=True)
class _RecordingState:
    selection_plan: CandidateSelectionPlan
    ledger: AtomicCostLedger
    population_root: Path
    registration_root: Path
    measurement_root: Path
    origin: str
    exchange_timeout: float
    task: asyncio.Task[object]
    pid: int
    deadline: float
    timer: asyncio.Timeout
    checkpoint_seed: _CheckpointSeed | None = None
    phase: Literal["NEW", "REGISTERING", "REGISTERED", "MEASURING", "MEASURED"] = "NEW"
    journal: CalibrationPopulationJournal | None = None
    registration: _RecordedPublication | _RecordedCheckpointPublication | None = None
    measurement: _RecordedPublication | _RecordedCheckpointPublication | None = None


@dataclass(frozen=True, slots=True)
class _CheckpointCompletionState:
    recording: _CalendarRecording
    native: _RetainedNativeCompletion
    result: CheckpointRecordedCalibrationResult
    measurement: _measurement.RegisteredCalibrationMeasurementResult
    measurement_values: tuple[
        _native.AuthenticatedModelCalibrationArtifact,
        QualificationPolicy | None,
        _measurement.RegisteredCalibrationMeasurementReceipt,
    ]
    receipt_bytes: bytes
    require_terminal: Callable[[], None]


def _build_calendar_controller() -> tuple[
    Callable[..., Awaitable[CalendarRecordedCalibrationResult]],
    Callable[[_CalendarRecording, CalibrationPopulationJournal], Awaitable[None]],
    Callable[
        [_CalendarRecording, _measurement.LiveRegisteredCalibrationMeasurement], Awaitable[None]
    ],
    Callable[[_CalendarRecording], None],
    Callable[..., Awaitable[CheckpointRecordedCalibrationResult]],
    Callable[..., AbstractAsyncContextManager[OwnedCheckpointCalibrationCompletion]],
    Callable[[OwnedCheckpointCalibrationCompletion], CheckpointRecordedCalibrationResult],
]:
    publication, measurement = _publication, _measurement
    prepare_registration = publication.prepare_calibration_registration_calendar
    prepare_measurement = publication.prepare_calibration_measurement_calendar
    measurement_scope = measurement.registered_calibration_measurement_scope
    read_measurement = measurement.load_registered_calibration_measurement
    retain_file, require_files = measurement._retain_file, measurement._require_files
    originals = (
        (publication, "prepare_calibration_registration_calendar", prepare_registration),
        (publication, "prepare_calibration_measurement_calendar", prepare_measurement),
        (
            publication,
            "load_calibration_calendar_publication",
            publication.load_calibration_calendar_publication,
        ),
        (measurement, "registered_calibration_measurement_scope", measurement_scope),
        (measurement, "load_registered_calibration_measurement", read_measurement),
        (measurement, "_retain_file", retain_file),
        (measurement, "_require_files", require_files),
    )
    codes = tuple(function.__code__ for _, _, function in originals)
    checkpoint_publication, checkpoint, population = (
        _checkpoint_publication,
        _checkpoint,
        _population_publication,
    )
    checkpoint_registration = checkpoint_publication.prepare_calibration_registration_checkpoint
    checkpoint_measurement = checkpoint_publication.prepare_calibration_measurement_checkpoint
    extend_proof = checkpoint.extend_calibration_checkpoint_proof
    registration_subject = population.build_calibration_registration_publication
    measurement_subject = population.build_calibration_measurement_publication
    checkpoint_originals = (
        (
            checkpoint_publication,
            "prepare_calibration_registration_checkpoint",
            checkpoint_registration,
        ),
        (
            checkpoint_publication,
            "prepare_calibration_measurement_checkpoint",
            checkpoint_measurement,
        ),
        (
            checkpoint_publication,
            "load_calibration_checkpoint_publication",
            checkpoint_publication.load_calibration_checkpoint_publication,
        ),
        (checkpoint, "extend_calibration_checkpoint_proof", extend_proof),
        (population, "build_calibration_registration_publication", registration_subject),
        (population, "build_calibration_measurement_publication", measurement_subject),
    )
    checkpoint_codes = tuple(function.__code__ for _, _, function in checkpoint_originals)
    states: dict[_CalendarRecording, _RecordingState] = {}
    completions: dict[OwnedCheckpointCalibrationCompletion, _CheckpointCompletionState] = {}
    native, encode_native, encode_json = (
        _native,
        authenticated_model_calibration_bytes,
        stable_json,
    )
    require_native = native._require_verified_authenticated_model_calibration
    native_type = _RetainedNativeCompletion
    native_data_check = native_type.require_unchanged
    completion_functions = (require_native, encode_native, encode_json, native_data_check)
    completion_codes = tuple(function.__code__ for function in completion_functions)

    def pristine() -> None:
        if (
            _publication is not publication
            or _measurement is not measurement
            or any(
                getattr(module, name) is not function or function.__code__ is not code
                for (module, name, function), code in zip(originals, codes, strict=True)
            )
        ):
            raise ValueError("calendar controller original producer exports changed")

    def checkpoint_pristine() -> None:
        if (
            _checkpoint_publication is not checkpoint_publication
            or _checkpoint is not checkpoint
            or _population_publication is not population
            or any(
                getattr(module, name) is not function or function.__code__ is not code
                for (module, name, function), code in zip(
                    checkpoint_originals, checkpoint_codes, strict=True
                )
            )
        ):
            raise ValueError("checkpoint controller original producers changed")

    def completion_pristine() -> None:
        if (
            _native is not native
            or native._require_verified_authenticated_model_calibration is not require_native
            or native.authenticated_model_calibration_bytes is not encode_native
            or authenticated_model_calibration_bytes is not encode_native
            or stable_json is not encode_json
            or _RetainedNativeCompletion is not native_type
            or native_type.require_unchanged is not native_data_check
            or any(
                function.__code__ is not code
                for function, code in zip(completion_functions, completion_codes, strict=True)
            )
        ):
            raise ValueError("checkpoint completion original native dependencies changed")

    def owned(key: _CalendarRecording) -> _RecordingState:
        pristine()
        if type(key) is not _CalendarRecording or key not in states:
            raise ValueError("calendar recording is absent or closed")
        state = states[key]
        if state.checkpoint_seed is not None:
            checkpoint_pristine()
            state.checkpoint_seed.require_unchanged()
        if os.getpid() != state.pid or asyncio.current_task() is not state.task:
            raise ValueError("calendar recording belongs to another task or process")
        if state.task.cancelling():
            raise asyncio.CancelledError
        if state.timer.expired() or monotonic() >= state.deadline:
            raise ValueError("calendar recording overall deadline expired")
        return state

    def require_recording(key: _CalendarRecording) -> None:
        state = owned(key)
        if state.registration is None or state.phase not in {
            "REGISTERED",
            "MEASURING",
            "MEASURED",
        }:
            raise ValueError("calendar recording has no original registration exchange")
        state.registration.require_unchanged()
        if state.measurement is not None:
            state.measurement.require_unchanged()
        owned(key)

    def observe_original_completion(
        completion: OwnedCheckpointCalibrationCompletion,
    ) -> CheckpointRecordedCalibrationResult:
        """Observe still-owned terminal data; never recreate disposed native verification."""

        completion_pristine()
        if (
            type(completion) is not OwnedCheckpointCalibrationCompletion
            or completion not in completions
        ):
            raise ValueError("checkpoint completion is absent or closed")
        retained = completions[completion]
        state = owned(retained.recording)
        native_data_check(retained.native)
        try:
            require_native(retained.native.verification, retained.native.calibration)
        except ValueError as exc:
            if str(exc) != "authenticated calibration verification is absent or revoked":
                raise
        else:
            raise ValueError("checkpoint completion requires original native disposal")
        result = retained.result
        if (
            type(state.registration) is not _RecordedCheckpointPublication
            or type(state.measurement) is not _RecordedCheckpointPublication
            or result.registration is not state.registration.observation
            or result.measurement_publication is not state.measurement.observation
            or result.measurement is not retained.measurement
            or any(
                getattr(result.measurement, name) is not original
                for name, original in zip(
                    ("calibration", "policy", "receipt"), retained.measurement_values, strict=True
                )
            )
            or encode_native(result.measurement.calibration) != retained.native.calibration_bytes
            or (
                encode_json(result.measurement.policy).encode()
                if result.measurement.policy is not None
                else None
            )
            != retained.native.policy_bytes
            or encode_json(result.measurement.receipt).encode() != retained.receipt_bytes
        ):
            raise ValueError("checkpoint completion original result changed")
        retained.require_terminal()
        require_recording(retained.recording)
        retained.require_terminal()
        native_data_check(retained.native)
        completion_pristine()
        owned(retained.recording)
        return result

    def observe_completion(
        completion: OwnedCheckpointCalibrationCompletion,
    ) -> CheckpointRecordedCalibrationResult:
        """An observed custody fault is terminal, even if the caller restores the data."""

        try:
            return observe_original_completion(completion)
        except BaseException:
            if type(completion) is OwnedCheckpointCalibrationCompletion:
                completions.pop(completion, None)
            raise

    async def record_registration(
        key: _CalendarRecording, journal: CalibrationPopulationJournal
    ) -> None:
        state = owned(key)
        if (
            state.phase != "NEW"
            or type(journal) is not CalibrationPopulationJournal
            or journal.current != journal.registration
            or journal.registration.selection_plan != state.selection_plan
            or state.ledger.snapshot_with_identity_sha256()
            != (journal.registration.ledger_identity_sha256, journal.registration.ledger_snapshot)
        ):
            raise ValueError(
                "calendar controller requires its original preflight-free registration"
            )
        state.phase, state.journal = "REGISTERING", journal
        if state.checkpoint_seed is not None:
            subject = registration_subject(
                evidence_root=state.population_root,
                expected_registration_sha256=journal.registration.event_sha256,
            )
            proof = extend_proof(
                population_subject_sha256=subject.subject_sha256,
                log_id_sha256=state.checkpoint_seed.log_id,
                previous=state.checkpoint_seed.initial_proof,
            )
            owned(key)
            with checkpoint_registration(
                population_root=state.population_root,
                expected_registration_sha256=journal.registration.event_sha256,
                transparency_proof=proof,
                expected_checkpoint_sha256=proof.checkpoint.checkpoint_sha256,
                output_root=state.registration_root,
                calendar_origin=state.origin,
            ) as checkpoint_owner:
                checkpoint_observation = await checkpoint_owner.submit(
                    allow_calendar_contact=True, timeout_seconds=state.exchange_timeout
                )
                recorded: _RecordedPublication | _RecordedCheckpointPublication = (
                    _retain_checkpoint_publication(checkpoint_owner, checkpoint_observation)
                )
        else:
            with prepare_registration(
                population_root=state.population_root,
                expected_registration_sha256=journal.registration.event_sha256,
                output_root=state.registration_root,
                calendar_origin=state.origin,
            ) as owner:
                observation = await owner.submit(
                    allow_calendar_contact=True, timeout_seconds=state.exchange_timeout
                )
                recorded = _retain_publication(owner, observation)
        recorded.require_unchanged()
        journal.require_unchanged()
        owned(key)
        state.registration, state.phase = recorded, "REGISTERED"
        require_recording(key)

    async def record_measurement(
        key: _CalendarRecording, live: _measurement.LiveRegisteredCalibrationMeasurement
    ) -> None:
        require_recording(key)
        state = owned(key)
        registration = state.registration
        if (
            state.phase != "REGISTERED"
            or registration is None
            or state.journal is None
            or state.journal.current.kind != "RUNNER_RETAINED"
            or live.registration_sha256 != state.journal.registration.event_sha256
        ):
            raise ValueError("calendar controller requires its complete original live measurement")
        state.phase = "MEASURING"
        if state.checkpoint_seed is not None:
            if type(registration) is not _RecordedCheckpointPublication:
                raise ValueError("checkpoint measurement requires its original checkpoint phase")
            subject = measurement_subject(
                live=live, ledger=state.ledger, evidence_root=state.population_root
            )
            proof = extend_proof(
                population_subject_sha256=subject.subject_sha256,
                log_id_sha256=state.checkpoint_seed.log_id,
                previous=registration.observation.checkpoint.transparency_proof,
            )
            owned(key)
            with checkpoint_measurement(
                live=live,
                ledger=state.ledger,
                population_root=state.population_root,
                registration_root=state.registration_root,
                expected_registration_publication_sha256=registration.pin,
                transparency_proof=proof,
                expected_checkpoint_sha256=proof.checkpoint.checkpoint_sha256,
                output_root=state.measurement_root,
                calendar_origin=state.origin,
            ) as checkpoint_owner:
                checkpoint_observation = await checkpoint_owner.submit(
                    allow_calendar_contact=True, timeout_seconds=state.exchange_timeout
                )
                recorded: _RecordedPublication | _RecordedCheckpointPublication = (
                    _retain_checkpoint_publication(checkpoint_owner, checkpoint_observation)
                )
        else:
            with prepare_measurement(
                live=live,
                ledger=state.ledger,
                population_root=state.population_root,
                registration_root=state.registration_root,
                expected_registration_publication_sha256=registration.pin,
                output_root=state.measurement_root,
                calendar_origin=state.origin,
            ) as owner:
                observation = await owner.submit(
                    allow_calendar_contact=True, timeout_seconds=state.exchange_timeout
                )
                recorded = _retain_publication(owner, observation)
        recorded.require_unchanged()
        require_recording(key)
        state.measurement, state.phase = recorded, "MEASURED"
        require_recording(key)

    @asynccontextmanager
    async def execute(
        *,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        evidence_root: Path,
        output_root: Path,
        registration_publication_root: Path,
        measurement_publication_root: Path,
        calendar_origin: str,
        launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
        operator_secrets: tuple[OperatorSecrets, ...],
        allow_calendar_contact: bool = False,
        calendar_timeout_seconds: float = 10.0,
        timeout_seconds: float = 3600.0,
        checkpoint_inputs: tuple[str, EvidenceTransparencyPrefixProof | None, str | None]
        | None = None,
        retain_completion: bool = False,
    ) -> AsyncIterator[
        tuple[
            CalendarRecordedCalibrationResult | CheckpointRecordedCalibrationResult,
            OwnedCheckpointCalibrationCompletion | None,
        ]
    ]:
        """Record both phases with original owners; never adopt a seal or authorize a run.

        Publication roots must be new and disjoint from each other and the original
        private population/measurement roots. Failure retains original artifacts;
        only the existing explicitly authorized GET recovery can inspect later data.
        """

        if type(operator_secrets) is not tuple or not 0 <= len(operator_secrets) <= 64:
            raise ValueError("calendar controller requires 0..64 owned secret holders")
        key: _CalendarRecording | None = None
        completion: OwnedCheckpointCalibrationCompletion | None = None
        completed_normally = False
        try:
            pristine()
            if retain_completion:
                completion_pristine()
                if checkpoint_inputs is None:
                    raise ValueError("native completion requires the explicit checkpoint profile")
            seed = None
            if checkpoint_inputs is not None:
                checkpoint_pristine()
                seed = _freeze_checkpoint_seed(checkpoint_inputs)
            _require_contact(calendar_origin, allow_calendar_contact, calendar_timeout_seconds)
            if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 86400:
                raise ValueError("calendar recording deadline must be within 86400s")
            if type(ledger) is not AtomicCostLedger:
                raise ValueError("calendar recording requires the original atomic ledger")
            publication._require_disjoint_output(
                registration_publication_root,
                (evidence_root, output_root, measurement_publication_root),
            )
            publication._require_disjoint_output(
                measurement_publication_root, (evidence_root, output_root)
            )
            task = asyncio.current_task()
            if task is None or task.cancelling():
                raise asyncio.CancelledError
            timer = asyncio.timeout(timeout_seconds)
            key = object.__new__(_CalendarRecording)
            state = _RecordingState(
                selection_plan,
                ledger,
                evidence_root,
                registration_publication_root,
                measurement_publication_root,
                calendar_origin,
                calendar_timeout_seconds,
                task,
                os.getpid(),
                monotonic() + timeout_seconds,
                timer,
                seed,
            )
            states[key] = state
            retained_native = None
            async with timer:
                async with measurement_scope(
                    selection_plan=selection_plan,
                    ledger=ledger,
                    evidence_root=evidence_root,
                    output_root=output_root,
                    launches=launches,
                    operator_secrets=operator_secrets,
                    timeout_seconds=timeout_seconds,
                    _calendar_recording=key,
                ) as live:
                    require_recording(key)
                    if state.phase != "MEASURED":
                        raise ValueError("calendar controller did not record both original phases")
                    registration_sha = live.registration_sha256
                    native_custody = tuple(
                        retain_file(output_root, binding)
                        for binding in _native_output_bindings(live)
                    )
                    if retain_completion:
                        completion_pristine()
                        require_native(live.verification, live.calibration)
                        retained_native = native_type(
                            live,
                            live.registration_sha256,
                            live.calibration,
                            live.policy,
                            live.verification,
                            encode_native(live.calibration),
                            encode_json(live.policy).encode() if live.policy is not None else None,
                        )
                        native_data_check(retained_native)
                        require_native(live.verification, live.calibration)
                        completion_pristine()
                # Native calibration/runner/accounting disposal and completion precede readback.
                require_recording(key)
                require_files(native_custody)
                receipt_file = read_file_evidence(
                    evidence_root=output_root,
                    relative_path=measurement._RECEIPT,
                    max_bytes=measurement._RECEIPT_BYTES,
                )
                native_custody += (retain_file(output_root, receipt_file.binding),)
                result = read_measurement(
                    evidence_root=evidence_root,
                    output_root=output_root,
                    expected_registration_sha256=registration_sha,
                )
                if stable_json(result.receipt).encode() != receipt_file.content:
                    raise ValueError("calendar recording original completion receipt changed")
                registration, measured = state.registration, state.measurement
                if (
                    registration is None
                    or measured is None
                    or (
                        measured.observation.subject.calibration != result.calibration
                        or measured.observation.subject.policy != result.policy
                        or measured.observation.subject.population_events[-1].event_sha256
                        != result.receipt.retained_event_sha256
                        or registration.observation.binding.registration_event_sha256
                        != result.receipt.registration_sha256
                    )
                ):
                    raise ValueError("calendar observations differ from the original completion")

                def require_completion() -> None:
                    require_files(native_custody)
                    journal = state.journal
                    if journal is None:
                        raise ValueError("calendar recording lost its original population")
                    journal.require_unchanged()
                    final = journal.current
                    identity, snapshot = ledger.snapshot_with_identity_sha256()
                    if (
                        final.kind != "FINISHED"
                        or final.disposition != "CONSUMED"
                        or final.event_sha256 != result.receipt.completed_event_sha256
                        or identity != result.receipt.ledger_identity_sha256
                        or snapshot != final.ledger_snapshot
                        or cost_ledger_snapshot_sha256(snapshot)
                        != result.receipt.final_ledger_snapshot_sha256
                    ):
                        raise ValueError("calendar recording terminal population or ledger changed")

                require_completion()
                require_recording(key)
                require_completion()
                if seed is not None:
                    if not isinstance(
                        registration, _RecordedCheckpointPublication
                    ) or not isinstance(measured, _RecordedCheckpointPublication):
                        raise ValueError(
                            "checkpoint recording cannot reinterpret old population receipts"
                        )
                    checkpoint_result = CheckpointRecordedCalibrationResult(
                        registration.observation, measured.observation, result
                    )
                    if retain_completion:
                        if retained_native is None:
                            raise ValueError("checkpoint completion lost its original live inputs")
                        completion = object.__new__(OwnedCheckpointCalibrationCompletion)
                        completions[completion] = _CheckpointCompletionState(
                            key,
                            retained_native,
                            checkpoint_result,
                            result,
                            (result.calibration, result.policy, result.receipt),
                            receipt_file.content,
                            require_completion,
                        )
                        observe_completion(completion)
                        yield checkpoint_result, completion
                        observe_completion(completion)
                    else:
                        yield checkpoint_result, None
                else:
                    if not isinstance(registration, _RecordedPublication) or not isinstance(
                        measured, _RecordedPublication
                    ):
                        raise ValueError(
                            "population recording cannot reinterpret checkpoint receipts"
                        )
                    yield (
                        CalendarRecordedCalibrationResult(
                            registration.observation, measured.observation, result
                        ),
                        None,
                    )
            if completion is not None:
                observe_completion(completion)
            completed_normally = True
        finally:
            try:
                # Keep legacy cleanup ordering; completion custody survives its final cleanup.
                if completion is None and key is not None:
                    states.pop(key, None)
                for secret in operator_secrets:
                    if type(secret) is OperatorSecrets:
                        secret.clear()
                if completion is not None and completed_normally:
                    observe_completion(completion)
            finally:
                if completion is not None:
                    completions.pop(completion, None)
                if key is not None:
                    states.pop(key, None)

    async def execute_population(
        *,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        evidence_root: Path,
        output_root: Path,
        registration_publication_root: Path,
        measurement_publication_root: Path,
        calendar_origin: str,
        launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
        operator_secrets: tuple[OperatorSecrets, ...],
        allow_calendar_contact: bool = False,
        calendar_timeout_seconds: float = 10.0,
        timeout_seconds: float = 3600.0,
    ) -> CalendarRecordedCalibrationResult:
        """Keep the original population-only entry point and receipt semantics."""

        async with execute(
            selection_plan=selection_plan,
            ledger=ledger,
            evidence_root=evidence_root,
            output_root=output_root,
            registration_publication_root=registration_publication_root,
            measurement_publication_root=measurement_publication_root,
            calendar_origin=calendar_origin,
            launches=launches,
            operator_secrets=operator_secrets,
            allow_calendar_contact=allow_calendar_contact,
            calendar_timeout_seconds=calendar_timeout_seconds,
            timeout_seconds=timeout_seconds,
        ) as (result, _completion):
            if not isinstance(result, CalendarRecordedCalibrationResult):
                raise ValueError("population-only recording returned the wrong profile")
            return result

    async def execute_checkpoint(
        *,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        evidence_root: Path,
        output_root: Path,
        registration_publication_root: Path,
        measurement_publication_root: Path,
        calendar_origin: str,
        transparency_log_id_sha256: str,
        initial_transparency_proof: EvidenceTransparencyPrefixProof | None,
        expected_initial_checkpoint_sha256: str | None,
        launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
        operator_secrets: tuple[OperatorSecrets, ...],
        allow_calendar_contact: bool = False,
        calendar_timeout_seconds: float = 10.0,
        timeout_seconds: float = 3600.0,
    ) -> CheckpointRecordedCalibrationResult:
        """Record actual phase checkpoint extensions; an initial tip is not accepted history.

        Require an explicit log identity and original initial proof/pin, or an
        explicit None pair for a fresh log. Both phase slots are reserved before
        registration. This never selects chain trust or grants paid permission.
        """

        async with execute(
            selection_plan=selection_plan,
            ledger=ledger,
            evidence_root=evidence_root,
            output_root=output_root,
            registration_publication_root=registration_publication_root,
            measurement_publication_root=measurement_publication_root,
            calendar_origin=calendar_origin,
            launches=launches,
            operator_secrets=operator_secrets,
            allow_calendar_contact=allow_calendar_contact,
            calendar_timeout_seconds=calendar_timeout_seconds,
            timeout_seconds=timeout_seconds,
            checkpoint_inputs=(
                transparency_log_id_sha256,
                initial_transparency_proof,
                expected_initial_checkpoint_sha256,
            ),
        ) as (result, _completion):
            if not isinstance(result, CheckpointRecordedCalibrationResult):
                raise ValueError("checkpoint recording returned the wrong profile")
            return result

    @asynccontextmanager
    async def completion_scope(
        *,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        evidence_root: Path,
        output_root: Path,
        registration_publication_root: Path,
        measurement_publication_root: Path,
        calendar_origin: str,
        transparency_log_id_sha256: str,
        initial_transparency_proof: EvidenceTransparencyPrefixProof | None,
        expected_initial_checkpoint_sha256: str | None,
        launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
        operator_secrets: tuple[OperatorSecrets, ...],
        allow_calendar_contact: bool = False,
        calendar_timeout_seconds: float = 10.0,
        timeout_seconds: float = 3600.0,
    ) -> AsyncIterator[OwnedCheckpointCalibrationCompletion]:
        """Retain original native-to-terminal custody under the original task and deadline.

        The handle becomes available only after native disposal and terminal checks,
        and is invalidated on every exit. No file reader can reconstruct it, and no
        observation is an external seal, policy adoption, release or paid permission.
        """

        async with execute(
            selection_plan=selection_plan,
            ledger=ledger,
            evidence_root=evidence_root,
            output_root=output_root,
            registration_publication_root=registration_publication_root,
            measurement_publication_root=measurement_publication_root,
            calendar_origin=calendar_origin,
            launches=launches,
            operator_secrets=operator_secrets,
            allow_calendar_contact=allow_calendar_contact,
            calendar_timeout_seconds=calendar_timeout_seconds,
            timeout_seconds=timeout_seconds,
            checkpoint_inputs=(
                transparency_log_id_sha256,
                initial_transparency_proof,
                expected_initial_checkpoint_sha256,
            ),
            retain_completion=True,
        ) as (_result, completion):
            if completion is None:
                raise ValueError("checkpoint completion requires its original scope")
            yield completion

    return (
        execute_population,
        record_registration,
        record_measurement,
        require_recording,
        execute_checkpoint,
        completion_scope,
        observe_completion,
    )


(
    execute_calendar_recorded_calibration_measurement,
    _record_calendar_registration,
    _record_calendar_measurement,
    _require_calendar_recording,
    execute_checkpoint_recorded_calibration_measurement,
    checkpoint_calibration_completion_scope,
    observe_checkpoint_calibration_completion,
) = _build_calendar_controller()
del _build_calendar_controller
