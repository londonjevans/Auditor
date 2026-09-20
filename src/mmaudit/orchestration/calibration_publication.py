"""Full-population publication inputs, not external authentication or release authority.

Registration and measurement are distinct log subjects. Native measurement needs
the original live proof; structural comparison needs both exact log prefixes.
No constructor, JSON reader or local prefix can prove external publication or the
pre-dispatch chronology that a trusted publisher/verifier must still establish.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models import authenticated_calibration as _native
from mmaudit.models.authenticated_calibration import (
    AuthenticatedModelCalibrationArtifact,
    authenticated_model_calibration_bytes,
)
from mmaudit.models.evidence_seal_authority import EvidenceTransparencyPrefixProof
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.orchestration.authenticated_calibration_measurement import (
    _POLICY_BYTES,
    LiveRegisteredCalibrationMeasurement,
    _require_population_join,
)
from mmaudit.orchestration.calibration_population import (
    _MAX_EVENT_BYTES,
    _MAX_EVENTS,
    _MAX_JOURNAL_BYTES,
    CalibrationPopulationEvent,
    _require_transition,
    load_calibration_population_journal,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES = 66_000_000
MAX_CALIBRATION_PUBLICATION_COMPARISON_BYTES = 76_000_000
_SHA = r"^[0-9a-f]{64}$"
type PublicationPhase = Literal["POPULATION_REGISTRATION", "MEASURED_POPULATION"]


class _PublicationData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    serialized_authority: Literal[False] = False
    external_publication_verified: Literal[False] = False
    pre_dispatch_anchoring_verified: Literal[False] = False
    policy_adoption_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    external_comparison_required: Literal[True] = True

    @field_validator(
        "serialized_authority",
        "external_publication_verified",
        "pre_dispatch_anchoring_verified",
        "policy_adoption_authorized",
        "model_qualification_authorized",
        "provider_call_authorized",
        "release_authorized",
        "external_comparison_required",
        mode="before",
    )
    @classmethod
    def exact_boolean_flags(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("publication flags must be exact nonauthorizing booleans")
        return value


class CalibrationPublicationSubject(_PublicationData):
    """Canonical private source material; only its 32-byte digest is a publication request."""

    schema_version: Literal["1.0"] = "1.0"
    subject_domain: Literal["MMAUDIT_CALIBRATION_POPULATION"] = "MMAUDIT_CALIBRATION_POPULATION"
    phase: PublicationPhase
    population_events: tuple[CalibrationPopulationEvent, ...] = Field(
        min_length=1, max_length=_MAX_EVENTS
    )
    calibration: AuthenticatedModelCalibrationArtifact | None
    policy: QualificationPolicy | None
    proposal_status: Literal[
        "NOT_MEASURED", "PROPOSED_NOT_ADOPTED", "NATIVE_POLICY_DERIVATION_REFUSED"
    ]
    subject_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def phase_population_cost_and_policy_are_exact(self) -> Self:
        events = self.population_events
        if events[0].kind != "REGISTERED":
            raise ValueError("publication subject must start with the original registration")
        sizes = tuple(len(stable_json(event.model_dump(mode="json")).encode()) for event in events)
        if any(size > _MAX_EVENT_BYTES for size in sizes) or sum(sizes) > _MAX_JOURNAL_BYTES:
            raise ValueError("publication subject journal exceeds its original byte bounds")
        for previous, current in pairwise(events):
            _require_transition(previous, current)
        if self.phase == "POPULATION_REGISTRATION":
            if (
                len(events) != 1
                or self.calibration is not None
                or self.policy is not None
                or self.proposal_status != "NOT_MEASURED"
            ):
                raise ValueError("registration publication cannot incorporate later work")
        else:
            if self.calibration is None or events[-1].disposition != "OPEN":
                raise ValueError(
                    "measurement publication requires a complete still-owned population"
                )
            authenticated_model_calibration_bytes(self.calibration)
            if self.policy is not None and len(stable_json(self.policy).encode()) > _POLICY_BYTES:
                raise ValueError("publication policy exceeds its original byte bound")
            _require_population_join(self.calibration, events)
            # Pure data reconstruction does not manufacture the native proof required by the API.
            try:
                proposed = _native._policy_proposal(self.calibration)
            except ValueError:
                proposed = None
            if self.policy != proposed or self.proposal_status != (
                "PROPOSED_NOT_ADOPTED"
                if proposed is not None
                else "NATIVE_POLICY_DERIVATION_REFUSED"
            ):
                raise ValueError("publication policy/refusal differs from the fixed measurement")
        if self.subject_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"subject_sha256"})
        ):
            raise ValueError("calibration publication subject hash is inconsistent")
        return self


class CalibrationPublicationComparison(_PublicationData):
    """Exact inclusion/extension comparison data, never a trusted log-origin assertion."""

    schema_version: Literal["1.0"] = "1.0"
    registration: CalibrationPublicationSubject
    measurement: CalibrationPublicationSubject
    registration_proof: EvidenceTransparencyPrefixProof
    measurement_proof: EvidenceTransparencyPrefixProof
    comparison_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def both_phases_extend_the_same_registration_and_log(self) -> Self:
        registration, measurement = self.registration, self.measurement
        first, last = self.registration_proof, self.measurement_proof
        if (
            registration.phase != "POPULATION_REGISTRATION"
            or measurement.phase != "MEASURED_POPULATION"
            or registration.population_events != measurement.population_events[:1]
            or first.authority_subject_sha256 != registration.subject_sha256
            or last.authority_subject_sha256 != measurement.subject_sha256
            or first.checkpoint.log_id_sha256 != last.checkpoint.log_id_sha256
            or last.previous_checkpoint != first.checkpoint
            or last.leaf_sha256s[: first.checkpoint.tree_size] != first.leaf_sha256s
            or last.subject_leaf_index < first.checkpoint.tree_size
        ):
            raise ValueError(
                "calibration publication phases do not extend the exact population/log"
            )
        if self.comparison_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"comparison_sha256"})
        ):
            raise ValueError("calibration publication comparison hash is inconsistent")
        return self


def read_calibration_publication_subject(raw: bytes) -> CalibrationPublicationSubject:
    """Strict bounded data readback; never issue or recreate live verification."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES:
        raise ValueError("calibration publication subject bytes are absent or over bound")
    subject = CalibrationPublicationSubject.model_validate_json(raw, strict=True)
    if stable_json(subject.model_dump(mode="json")).encode() != raw:
        raise ValueError("calibration publication subject bytes are not canonical")
    return subject


def calibration_publication_subject_bytes(subject: CalibrationPublicationSubject) -> bytes:
    if type(subject) is not CalibrationPublicationSubject:
        raise ValueError("calibration publication requires its exact subject type")
    raw = stable_json(subject.model_dump(mode="json")).encode()
    read_calibration_publication_subject(raw)
    return raw


def calibration_publication_request(subject: CalibrationPublicationSubject) -> bytes:
    """Return only the exact subject digest, not journal/source/ledger or credential data."""

    validated = read_calibration_publication_subject(calibration_publication_subject_bytes(subject))
    return bytes.fromhex(validated.subject_sha256)


def read_calibration_publication_comparison(raw: bytes) -> CalibrationPublicationComparison:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CALIBRATION_PUBLICATION_COMPARISON_BYTES:
        raise ValueError("calibration publication comparison bytes are absent or over bound")
    comparison = CalibrationPublicationComparison.model_validate_json(raw, strict=True)
    for subject in (comparison.registration, comparison.measurement):
        calibration_publication_subject_bytes(subject)
    if stable_json(comparison.model_dump(mode="json")).encode() != raw:
        raise ValueError("calibration publication comparison bytes are not canonical")
    return comparison


def calibration_publication_comparison_bytes(comparison: CalibrationPublicationComparison) -> bytes:
    if type(comparison) is not CalibrationPublicationComparison:
        raise ValueError("calibration publication requires its exact comparison type")
    raw = stable_json(comparison.model_dump(mode="json")).encode()
    read_calibration_publication_comparison(raw)
    return raw


def _subject(
    *,
    phase: PublicationPhase,
    events: tuple[CalibrationPopulationEvent, ...],
    calibration: AuthenticatedModelCalibrationArtifact | None = None,
    policy: QualificationPolicy | None = None,
) -> CalibrationPublicationSubject:
    provisional = CalibrationPublicationSubject.model_construct(
        phase=phase,
        population_events=events,
        calibration=calibration,
        policy=policy,
        proposal_status="NOT_MEASURED"
        if phase == "POPULATION_REGISTRATION"
        else ("PROPOSED_NOT_ADOPTED" if policy is not None else "NATIVE_POLICY_DERIVATION_REFUSED"),
        subject_sha256="0" * 64,
    )
    material = provisional.model_dump(mode="json", exclude={"subject_sha256"})
    material["subject_sha256"] = canonical_sha256(material)
    return read_calibration_publication_subject(stable_json(material).encode())


def _retained_journal(
    root: Path,
    registration_sha256: str,
) -> tuple[tuple[CalibrationPopulationEvent, ...], tuple[RegularFileCustodyObservation, ...]]:
    events = load_calibration_population_journal(
        root, expected_registration_sha256=registration_sha256
    )
    custody = []
    for event in events:
        raw = stable_json(event.model_dump(mode="json")).encode()
        binding = ManifestFileBinding(
            path=f"{event.event_index:03d}.json",
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
        )
        custody.append(
            observe_regular_file_custody(
                root=root,
                relative_path=binding.path,
                expected_binding=binding,
                label="calibration publication journal",
                max_bytes=_MAX_EVENT_BYTES,
                allow_directory_entry_metadata_change=True,
            )
        )
    return events, tuple(custody)


def _require_journal(
    root: Path,
    events: tuple[CalibrationPopulationEvent, ...],
    custody: tuple[RegularFileCustodyObservation, ...],
) -> None:
    for item in custody:
        require_regular_file_custody_unchanged(
            item,
            label="calibration publication journal",
            max_bytes=_MAX_EVENT_BYTES,
            allow_directory_entry_metadata_change=True,
        )
    if (
        load_calibration_population_journal(
            root, expected_registration_sha256=events[0].event_sha256
        )
        != events
    ):
        raise ValueError("calibration publication journal changed during construction")


def build_calibration_registration_publication(
    *,
    evidence_root: Path,
    expected_registration_sha256: str,
) -> CalibrationPublicationSubject:
    """Read the single-event prefix before preflight; this does not itself publish it."""

    events, custody = _retained_journal(evidence_root, expected_registration_sha256)
    subject = _subject(phase="POPULATION_REGISTRATION", events=events)
    _require_journal(evidence_root, events, custody)
    return subject


def _build_native_measurement_publication() -> Callable[..., CalibrationPublicationSubject]:
    native = _native
    require = native._require_verified_authenticated_model_calibration
    derive = native.derive_authenticated_calibration_policy
    originals = (
        ("_require_verified_authenticated_model_calibration", require, require.__code__),
        ("derive_authenticated_calibration_policy", derive, derive.__code__),
    )

    def pristine() -> None:
        if any(
            getattr(native, name) is not function or function.__code__ is not code
            for name, function, code in originals
        ):
            raise ValueError("calibration publication native verifier bindings changed")

    def build(
        *,
        live: LiveRegisteredCalibrationMeasurement,
        evidence_root: Path,
        ledger: AtomicCostLedger,
    ) -> CalibrationPublicationSubject:
        """Borrow original native custody; ownership and mandatory disposal stay with its scope."""

        pristine()
        if (
            type(live) is not LiveRegisteredCalibrationMeasurement
            or type(ledger) is not AtomicCostLedger
        ):
            raise ValueError("measurement publication requires exact native input and ledger types")
        registration, calibration, policy, verification = (
            live.registration_sha256,
            live.calibration,
            live.policy,
            live.verification,
        )
        require(verification, calibration)
        events, custody = _retained_journal(evidence_root, registration)
        _require_population_join(calibration, events)
        expected_ledger = events[-1].ledger_identity_sha256, events[-1].ledger_snapshot
        if ledger.snapshot_with_identity_sha256() != expected_ledger:
            raise ValueError("measurement publication differs from the current original ledger")
        try:
            proposed = derive(calibration=calibration, verification=verification)
        except ValueError:
            require(verification, calibration)
            proposed = None
        if policy != proposed:
            raise ValueError("measurement publication does not contain the original policy/refusal")
        subject = _subject(
            phase="MEASURED_POPULATION", events=events, calibration=calibration, policy=policy
        )
        # Original verification observes its sources again. Check the journal,
        # ledger and borrowed fields after that observation, not only before it.
        require(verification, calibration)
        pristine()
        _require_journal(evidence_root, events, custody)
        if ledger.snapshot_with_identity_sha256() != expected_ledger or any(
            getattr(live, name) is not original
            for name, original in zip(
                ("registration_sha256", "calibration", "policy", "verification"),
                (registration, calibration, policy, verification),
                strict=True,
            )
        ):
            raise ValueError("measurement publication source or ledger changed during construction")
        pristine()
        return subject

    return build


build_calibration_measurement_publication = _build_native_measurement_publication()
del _build_native_measurement_publication


def build_calibration_publication_comparison(
    *,
    registration: CalibrationPublicationSubject,
    measurement: CalibrationPublicationSubject,
    registration_proof: EvidenceTransparencyPrefixProof,
    measurement_proof: EvidenceTransparencyPrefixProof,
) -> CalibrationPublicationComparison:
    """Compare supplied data only; no external log is contacted and no capability is issued."""

    if any(
        type(value) is not expected
        for value, expected in (
            (registration, CalibrationPublicationSubject),
            (measurement, CalibrationPublicationSubject),
            (registration_proof, EvidenceTransparencyPrefixProof),
            (measurement_proof, EvidenceTransparencyPrefixProof),
        )
    ):
        raise ValueError("calibration publication comparison requires exact data types")
    provisional = CalibrationPublicationComparison.model_construct(
        registration=registration,
        measurement=measurement,
        registration_proof=registration_proof,
        measurement_proof=measurement_proof,
        comparison_sha256="0" * 64,
    )
    material = provisional.model_dump(mode="json", exclude={"comparison_sha256"})
    material["comparison_sha256"] = canonical_sha256(material)
    return read_calibration_publication_comparison(stable_json(material).encode())
