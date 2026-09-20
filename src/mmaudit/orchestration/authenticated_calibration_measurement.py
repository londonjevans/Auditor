"""Owned native measurement and nonauthorizing completion of a registered population.

Staged measurement survives policy refusal. Completion is published only after the
original calibration, runner, child and accounting scopes have disposed custody.
Loading files never recreates those proofs or supplies the still-required seals.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models import authenticated_calibration as _native
from mmaudit.models.authenticated_calibration import (
    MAX_AUTHENTICATED_CALIBRATION_BYTES,
    AuthenticatedModelCalibrationArtifact,
    VerifiedAuthenticatedModelCalibration,
    authenticated_model_calibration_bytes,
    read_authenticated_model_calibration,
)
from mmaudit.models.authenticated_runner_execution import _preflight_private_output_leaf
from mmaudit.models.authenticated_runner_ledger import _snapshot_sha256 as _runner_snapshot_sha256
from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.authenticated_calibration_openrouter import (
    _owned_registered_calibration_scope,
)
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterLaunch,
)
from mmaudit.orchestration.calibration_population import (
    CalibrationPopulationEvent,
    load_calibration_population_journal,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, cost_ledger_snapshot_sha256
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, write_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)
from mmaudit.repository.file_custody import (
    RegularFileCustodyObservation,
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)

if TYPE_CHECKING:
    from mmaudit.orchestration.calibration_calendar_controller import _CalendarRecording

_SHA = r"^[0-9a-f]{64}$"
_MEASUREMENT = "calibration.json"
_POLICY = "policy.json"
_RECEIPT = "measurement.json"
_POLICY_BYTES = 1_000_000
_RECEIPT_BYTES = 64_000
type PolicyProposalStatus = Literal["PROPOSED_NOT_ADOPTED", "NATIVE_POLICY_DERIVATION_REFUSED"]


class RegisteredCalibrationMeasurementReceipt(BaseModel):
    """Exact completion data; a self-hash is not authentication or policy adoption."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    registration_sha256: str = Field(pattern=_SHA)
    retained_event_sha256: str = Field(pattern=_SHA)
    completed_event_sha256: str = Field(pattern=_SHA)
    selection_plan_sha256: str = Field(pattern=_SHA)
    selected_model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    ledger_identity_sha256: str = Field(pattern=_SHA)
    final_ledger_snapshot_sha256: str = Field(pattern=_SHA)
    measurement_file: ManifestFileBinding
    measurement_sha256: str = Field(pattern=_SHA)
    policy_file: ManifestFileBinding | None
    policy_sha256: str | None = Field(pattern=_SHA)
    proposal_status: PolicyProposalStatus
    serialized_authority: Literal[False] = False
    policy_adoption_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    external_population_seal_required: Literal[True] = True
    receipt_sha256: str = Field(pattern=_SHA)

    @field_validator(
        "serialized_authority",
        "policy_adoption_authorized",
        "model_qualification_authorized",
        "provider_call_authorized",
        "release_authorized",
        "external_population_seal_required",
        mode="before",
    )
    @classmethod
    def flags_are_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("measurement authority flags must be exact booleans")
        return value

    @model_validator(mode="after")
    def complete_bindings(self) -> Self:
        proposed = self.proposal_status == "PROPOSED_NOT_ADOPTED"
        if (
            (self.policy_file is not None) != proposed
            or (self.policy_sha256 is not None) != proposed
            or self.measurement_file.path != _MEASUREMENT
            or not 0 < self.measurement_file.size <= MAX_AUTHENTICATED_CALIBRATION_BYTES
            or (
                self.policy_file is not None
                and (
                    self.policy_file.path != _POLICY
                    or not 0 < self.policy_file.size <= _POLICY_BYTES
                )
            )
            or tuple(sorted(set(self.selected_model_ids))) != self.selected_model_ids
            or self.receipt_sha256
            != canonical_sha256(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        ):
            raise ValueError("registered measurement receipt bindings are inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class LiveRegisteredCalibrationMeasurement:
    """Original proof is usable only inside the owned scope, including trusted sealing."""

    registration_sha256: str
    calibration: AuthenticatedModelCalibrationArtifact
    policy: QualificationPolicy | None
    verification: VerifiedAuthenticatedModelCalibration

    def __reduce__(self) -> Never:
        raise TypeError("live registered measurement cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("live registered measurement cannot be serialized")


@dataclass(frozen=True, slots=True)
class RegisteredCalibrationMeasurementResult:
    """Detached data only; there is deliberately no verification-capability field."""

    receipt: RegisteredCalibrationMeasurementReceipt
    calibration: AuthenticatedModelCalibrationArtifact
    policy: QualificationPolicy | None


def _output_names(root: Path) -> tuple[str, ...]:
    names: list[str] = []
    for entry in root.iterdir():
        names.append(entry.name)
        if len(names) > 3:
            raise ValueError("registered measurement output directory exceeds its bound")
    return tuple(sorted(names))


def _retain_file(root: Path, binding: ManifestFileBinding) -> RegularFileCustodyObservation:
    return observe_regular_file_custody(
        root=root,
        relative_path=binding.path,
        expected_binding=binding,
        label="registered measurement output",
        max_bytes=MAX_AUTHENTICATED_CALIBRATION_BYTES,
        allow_directory_entry_metadata_change=True,
    )


def _require_files(custody: tuple[RegularFileCustodyObservation, ...]) -> None:
    for item in custody:
        require_regular_file_custody_unchanged(
            item,
            label="registered measurement output",
            max_bytes=MAX_AUTHENTICATED_CALIBRATION_BYTES,
            allow_directory_entry_metadata_change=True,
        )


def _require_population_join(
    calibration: AuthenticatedModelCalibrationArtifact,
    events: tuple[CalibrationPopulationEvent, ...],
) -> CalibrationPopulationEvent:
    """Join each original closed interval, not merely the final cost or selected subset."""

    registration, last = events[0], events[-1]
    retained = events[-2] if last.kind == "FINISHED" else last
    if (
        retained.disposition != "OPEN"
        or retained.kind != "RUNNER_RETAINED"
        or any(slot.state != "RETAINED" for slot in retained.slots)
        or calibration.selected_model_ids != tuple(slot.exact_model_id for slot in retained.slots)
        or Decimal(calibration.retained_cost_usd) != retained.ledger_snapshot.spent_usd
        or last.ledger_snapshot != retained.ledger_snapshot
        or (last.kind == "FINISHED" and last.disposition != "CONSUMED")
    ):
        raise ValueError("measurement differs from its complete retained population or cost")
    starts = tuple(event for event in events if event.kind == "RUNNER_STARTED")
    ends = tuple(event for event in events if event.kind == "RUNNER_RETAINED")
    if len(starts) != len(calibration.sources) or len(ends) != len(calibration.sources):
        raise ValueError("measurement does not retain every declared runner interval")
    for source, slot, start, end in zip(
        calibration.sources, retained.slots, starts, ends, strict=True
    ):
        evidence = source.runner_evidence
        interval = evidence.ledger_interval
        if (
            evidence.evidence_sha256 != slot.runner_evidence_sha256
            or any(run.candidate_registry_sha256 != slot.registry_sha256 for run in source.runs)
            or interval.ledger_identity_sha256 != registration.ledger_identity_sha256
            or interval.initial_snapshot_sha256 != _runner_snapshot_sha256(start.ledger_snapshot)
            or interval.final_snapshot_sha256 != _runner_snapshot_sha256(end.ledger_snapshot)
            or Decimal(interval.initial_spent_usd) != start.ledger_snapshot.spent_usd
            or Decimal(interval.final_spent_usd) != end.ledger_snapshot.spent_usd
        ):
            raise ValueError(
                "measurement runner/registry/ledger interval differs from registration"
            )
    return retained


def load_registered_calibration_measurement(
    *,
    evidence_root: Path,
    output_root: Path,
    expected_registration_sha256: str,
) -> RegisteredCalibrationMeasurementResult:
    """Bounded structural readback only; cannot authenticate completion or grant credit."""

    observed = read_file_evidence(
        evidence_root=output_root, relative_path=_RECEIPT, max_bytes=_RECEIPT_BYTES
    )
    receipt = RegisteredCalibrationMeasurementReceipt.model_validate_json(observed.content)
    if stable_json(receipt).encode() != observed.content:
        raise ValueError("registered measurement receipt is not canonical")
    if receipt.registration_sha256 != expected_registration_sha256:
        raise ValueError("registered measurement differs from the expected registration")
    custody = [_retain_file(output_root, observed.binding)]
    measurement = read_file_evidence(
        evidence_root=output_root,
        relative_path=_MEASUREMENT,
        max_bytes=MAX_AUTHENTICATED_CALIBRATION_BYTES,
    )
    if measurement.binding != receipt.measurement_file:
        raise ValueError("registered measurement file binding differs")
    custody.append(_retain_file(output_root, measurement.binding))
    calibration = read_authenticated_model_calibration(measurement.content)
    policy = None
    if receipt.policy_file is not None:
        observed_policy = read_file_evidence(
            evidence_root=output_root, relative_path=_POLICY, max_bytes=_POLICY_BYTES
        )
        if observed_policy.binding != receipt.policy_file:
            raise ValueError("registered measurement policy file binding differs")
        custody.append(_retain_file(output_root, observed_policy.binding))
        policy = QualificationPolicy.model_validate_json(observed_policy.content, strict=True)
        if stable_json(policy).encode() != observed_policy.content:
            raise ValueError("registered measurement policy is not canonical")
    # Pure reconstruction is only data consistency; native derivation still requires its proof.
    try:
        expected_policy = _native._policy_proposal(calibration)
    except ValueError:
        expected_policy = None
    if policy != expected_policy:
        raise ValueError("registered policy/refusal differs from the fixed measurement projection")
    events = load_calibration_population_journal(
        evidence_root, expected_registration_sha256=expected_registration_sha256
    )
    retained = _require_population_join(calibration, events)
    last = events[-1]
    if (
        last.disposition != "CONSUMED"
        or receipt.retained_event_sha256 != retained.event_sha256
        or receipt.completed_event_sha256 != last.event_sha256
        or receipt.selection_plan_sha256 != last.selection_plan.plan_sha256
        or receipt.selected_model_ids != calibration.selected_model_ids
        or receipt.ledger_identity_sha256 != last.ledger_identity_sha256
        or receipt.final_ledger_snapshot_sha256 != cost_ledger_snapshot_sha256(last.ledger_snapshot)
        or receipt.measurement_sha256 != calibration.artifact_sha256
        or receipt.policy_sha256 != (policy.policy_sha256 if policy else None)
        or _output_names(output_root) != tuple(sorted(item.binding.path for item in custody))
    ):
        raise ValueError("registered measurement completion joins differ")
    _require_files(tuple(custody))
    return RegisteredCalibrationMeasurementResult(receipt, calibration, policy)


def _build_registered_measurement_scope() -> Callable[
    ..., AbstractAsyncContextManager[LiveRegisteredCalibrationMeasurement]
]:
    native = _native
    names = (
        "observe_authenticated_model_calibration",
        "derive_authenticated_calibration_policy",
        "_require_verified_authenticated_model_calibration",
        "revoke_verified_authenticated_model_calibration",
    )
    observe = native.observe_authenticated_model_calibration
    derive = native.derive_authenticated_calibration_policy
    require = native._require_verified_authenticated_model_calibration
    revoke = native.revoke_verified_authenticated_model_calibration
    originals = (observe, derive, require, revoke)
    codes = tuple(function.__code__ for function in originals)
    batch_scope = _owned_registered_calibration_scope

    def pristine() -> None:
        if any(
            getattr(native, name) is not function or function.__code__ is not code
            for name, function, code in zip(names, originals, codes, strict=True)
        ):
            raise ValueError("registered measurement native exports changed")

    @asynccontextmanager
    async def scope(
        *,
        selection_plan: CandidateSelectionPlan,
        ledger: AtomicCostLedger,
        evidence_root: Path,
        output_root: Path,
        launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
        operator_secrets: tuple[OperatorSecrets, ...],
        timeout_seconds: float = 3600.0,
        _calendar_recording: _CalendarRecording | None = None,
    ) -> AsyncIterator[LiveRegisteredCalibrationMeasurement]:
        """Own native measurement through consumption; publish only after mandatory disposal.

        Both roots must be separate existing empty private directories. No paid run,
        retry, resume, policy adoption or external seal is authorized by this API.
        """

        if type(operator_secrets) is not tuple or not 0 <= len(operator_secrets) <= 64:
            raise ValueError("registered measurement requires 0..64 owned secret holders")
        try:
            pristine()
            for name in (_MEASUREMENT, _POLICY, _RECEIPT):
                _preflight_private_output_leaf(output_root / name)
            directory = observe_unlinked_directory(
                output_root,
                label="registered measurement outputs",
                allow_entry_metadata_change=True,
            )
            if _output_names(output_root) or output_root == evidence_root:
                raise ValueError(
                    "registered measurement requires a separate empty output directory"
                )
            async with batch_scope(
                selection_plan=selection_plan,
                ledger=ledger,
                evidence_root=evidence_root,
                launches=launches,
                operator_secrets=operator_secrets,
                timeout_seconds=timeout_seconds,
                _calendar_recording=_calendar_recording,
            ) as (batch, journal):
                pristine()
                calibration, verification = observe(
                    selected_model_ids=batch.selected_model_ids,
                    benchmark_suite=batch.benchmark_suite,
                    ground_truth=batch.ground_truth,
                    inputs=batch.inputs,
                )
                # Take responsibility for the original lease before any later validation or I/O.
                try:
                    require(verification, calibration)
                    registration = journal.registration.event_sha256
                    journal.require_unchanged()
                    events = load_calibration_population_journal(
                        evidence_root, expected_registration_sha256=registration
                    )
                    retained = _require_population_join(calibration, events)
                    if retained != journal.current:
                        raise ValueError("registered measurement journal changed")
                    require_same_unlinked_directory_objects(directory, label="measurement outputs")
                    measurement_bytes = authenticated_model_calibration_bytes(calibration)
                    binding = write_file_evidence(
                        evidence_root=output_root,
                        relative_path=_MEASUREMENT,
                        content=measurement_bytes,
                        max_bytes=MAX_AUTHENTICATED_CALIBRATION_BYTES,
                    )
                    custody: tuple[RegularFileCustodyObservation, ...] = (
                        _retain_file(output_root, binding),
                    )
                    try:
                        policy = derive(calibration=calibration, verification=verification)
                    except ValueError:
                        # Invalid custody/runtime is fatal, not a numeric-support refusal.
                        require(verification, calibration)
                        pristine()
                        policy = None
                    policy_binding = None
                    policy_bytes = stable_json(policy).encode() if policy is not None else None
                    if policy is not None:
                        policy_binding = write_json_evidence(
                            evidence_root=output_root,
                            relative_path=_POLICY,
                            value=policy,
                            max_bytes=_POLICY_BYTES,
                            require_private_parent=True,
                        )
                        custody += (_retain_file(output_root, policy_binding),)
                    live = LiveRegisteredCalibrationMeasurement(
                        registration, calibration, policy, verification
                    )
                    fields = (registration, calibration, policy, verification)

                    def require_unchanged() -> None:
                        pristine()
                        require(verification, calibration)
                        journal.require_unchanged()
                        if (
                            journal.current != retained
                            or ledger.snapshot_with_identity_sha256()
                            != (retained.ledger_identity_sha256, retained.ledger_snapshot)
                            or any(
                                getattr(live, name) is not value
                                for name, value in zip(
                                    (
                                        "registration_sha256",
                                        "calibration",
                                        "policy",
                                        "verification",
                                    ),
                                    fields,
                                    strict=True,
                                )
                            )
                            or _output_names(output_root)
                            != tuple(sorted(item.binding.path for item in custody))
                            or (stable_json(policy).encode() if policy is not None else None)
                            != policy_bytes
                        ):
                            raise ValueError("registered measurement inputs or cost changed")
                        _require_files(custody)

                    require_unchanged()
                    if _calendar_recording is not None:
                        from mmaudit.orchestration.calibration_calendar_controller import (
                            _record_calendar_measurement,
                        )

                        await _record_calendar_measurement(_calendar_recording, live)
                        require_unchanged()
                    yield live
                    require_unchanged()
                finally:
                    # Missing custody is an error, never suppressed to obtain completion.
                    revoke(verification)
                    try:
                        require(verification, calibration)
                    except ValueError as exc:
                        if (
                            str(exc)
                            != "authenticated calibration verification is absent or revoked"
                        ):
                            raise
                    else:
                        raise ValueError("registered measurement verification survived disposal")
            # Original runner/child/accounting cleanup and terminal journal precede this receipt.
            pristine()
            journal.require_unchanged()
            _require_files(custody)
            if _output_names(output_root) != tuple(sorted(item.binding.path for item in custody)):
                raise ValueError("registered measurement output set changed during cleanup")
            if (
                authenticated_model_calibration_bytes(calibration) != measurement_bytes
                or (stable_json(policy).encode() if policy is not None else None) != policy_bytes
            ):
                raise ValueError("registered measurement data changed during cleanup")
            events = load_calibration_population_journal(
                evidence_root, expected_registration_sha256=registration
            )
            if _require_population_join(calibration, events) != retained:
                raise ValueError("registered measurement terminal population changed")
            terminal = events[-1]
            if terminal.disposition != "CONSUMED" or ledger.snapshot_with_identity_sha256() != (
                terminal.ledger_identity_sha256,
                terminal.ledger_snapshot,
            ):
                raise ValueError("registered measurement has no clean terminal ledger")
            draft = RegisteredCalibrationMeasurementReceipt.model_construct(
                registration_sha256=registration,
                retained_event_sha256=retained.event_sha256,
                completed_event_sha256=terminal.event_sha256,
                selection_plan_sha256=terminal.selection_plan.plan_sha256,
                selected_model_ids=calibration.selected_model_ids,
                ledger_identity_sha256=terminal.ledger_identity_sha256,
                final_ledger_snapshot_sha256=cost_ledger_snapshot_sha256(terminal.ledger_snapshot),
                measurement_file=binding,
                measurement_sha256=calibration.artifact_sha256,
                policy_file=policy_binding,
                policy_sha256=policy.policy_sha256 if policy else None,
                proposal_status="PROPOSED_NOT_ADOPTED"
                if policy
                else "NATIVE_POLICY_DERIVATION_REFUSED",
                receipt_sha256="0" * 64,
            )
            material = draft.model_dump(mode="json", exclude={"receipt_sha256"})
            material["receipt_sha256"] = canonical_sha256(material)
            receipt = RegisteredCalibrationMeasurementReceipt.model_validate_json(
                stable_json(material)
            )
            write_json_evidence(
                evidence_root=output_root,
                relative_path=_RECEIPT,
                value=receipt,
                max_bytes=_RECEIPT_BYTES,
                require_private_parent=True,
            )
        finally:
            for secret in operator_secrets:
                if type(secret) is OperatorSecrets:
                    secret.clear()

    return scope


registered_calibration_measurement_scope = _build_registered_measurement_scope()
del _build_registered_measurement_scope


async def execute_registered_calibration_measurement(
    *,
    selection_plan: CandidateSelectionPlan,
    ledger: AtomicCostLedger,
    evidence_root: Path,
    output_root: Path,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
    operator_secrets: tuple[OperatorSecrets, ...],
    timeout_seconds: float = 3600.0,
) -> RegisteredCalibrationMeasurementResult:
    """Unattended native consumption returning only detached, nonauthorizing evidence."""

    async with registered_calibration_measurement_scope(
        selection_plan=selection_plan,
        ledger=ledger,
        evidence_root=evidence_root,
        output_root=output_root,
        launches=launches,
        operator_secrets=operator_secrets,
        timeout_seconds=timeout_seconds,
    ) as live:
        registration = live.registration_sha256
    return load_registered_calibration_measurement(
        evidence_root=evidence_root,
        output_root=output_root,
        expected_registration_sha256=registration,
    )
