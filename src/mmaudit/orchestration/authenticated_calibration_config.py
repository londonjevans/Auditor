"""Native measured-policy configuration proposals, never successor release admission.

The current source release still admits only its compiled qualification-policy
pin. C2 is canonical proposed data, not an AuditConfig executable under P1. A
future source-pinned successor and external seal/J2 gates must adopt it separately.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.config import (
    AuditConfig,
    canonical_audit_config_json,
    parse_canonical_audit_config,
)
from mmaudit.models.calibration_transition import qualification_policy_independent_config_sha256
from mmaudit.models.qualification import QualificationPolicy
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration import calibration_publication as _publication
from mmaudit.orchestration.authenticated_calibration_measurement import (
    _POLICY_BYTES,
    LiveRegisteredCalibrationMeasurement,
)
from mmaudit.orchestration.calibration_publication import (
    CalibrationPublicationSubject,
    _require_journal,
    _retained_journal,
    calibration_publication_subject_bytes,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacyProfile
from mmaudit.reporting.json_report import stable_json

MAX_AUTHENTICATED_CALIBRATION_CONFIG_PROPOSAL_BYTES = 76_000_000
_CONFIG_BYTES = 2_000_000
_SHA = r"^[0-9a-f]{64}$"


def _policy_bytes(policy: QualificationPolicy) -> bytes:
    if type(policy) is not QualificationPolicy:
        raise ValueError("configuration proposal requires an exact predecessor policy")
    raw = stable_json(policy.model_dump(mode="json")).encode()
    if len(raw) > _POLICY_BYTES:
        raise ValueError("configuration proposal policy exceeds its original byte bound")
    QualificationPolicy.model_validate_json(raw, strict=True)
    return raw


def _configuration_payload(raw: str) -> dict[str, Any]:
    if type(raw) is not str or not 0 < len(raw.encode()) <= _CONFIG_BYTES:
        raise ValueError("configuration proposal exceeds its original config byte bound")
    payload = json.loads(raw)
    if (
        type(payload) is not dict
        or json.dumps(payload, sort_keys=True, separators=(",", ":")) != raw
    ):
        raise ValueError("configuration proposal config is not canonical")
    return payload


def _successor_config(raw: str, predecessor_sha256: str, successor_sha256: str) -> str:
    """Change one existing pin; never create missing configuration or admit it at runtime."""

    payload = _configuration_payload(raw)
    try:
        pins = payload["maximum_assurance"]["qualification"]
        if type(pins) is not dict or pins["policy_sha256"] != predecessor_sha256:
            raise ValueError("configuration proposal does not pin its original P1")
        pins["policy_sha256"] = successor_sha256
    except (KeyError, TypeError) as exc:
        raise ValueError("configuration proposal lacks the allowed policy-pin path") from exc
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class AuthenticatedCalibrationConfigProposal(BaseModel):
    """Full native measurement and exact C1/C2 data; no future release pins are fabricated."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    transition_kind: Literal["qualification_policy_only"] = "qualification_policy_only"
    allowed_config_path: Literal["maximum_assurance.qualification.policy_sha256"] = (
        "maximum_assurance.qualification.policy_sha256"
    )
    proposal_status: Literal["PROPOSED_NOT_ADOPTED"] = "PROPOSED_NOT_ADOPTED"
    measurement_subject: CalibrationPublicationSubject
    predecessor_policy: QualificationPolicy
    predecessor_effective_config_json: str = Field(min_length=1, max_length=_CONFIG_BYTES)
    successor_effective_config_json: str = Field(min_length=1, max_length=_CONFIG_BYTES)
    predecessor_effective_config_sha256: str = Field(pattern=_SHA)
    successor_effective_config_sha256: str = Field(pattern=_SHA)
    policy_independent_config_sha256: str = Field(pattern=_SHA)
    external_population_seal_required: Literal[True] = True
    successor_release_binding_required: Literal[True] = True
    independent_qualification_required: Literal[True] = True
    serialized_authority: Literal[False] = False
    policy_adoption_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    proposal_sha256: str = Field(pattern=_SHA)

    @field_validator(
        "external_population_seal_required",
        "successor_release_binding_required",
        "independent_qualification_required",
        "serialized_authority",
        "policy_adoption_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_call_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def flags_are_exact_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("configuration proposal flags must be exact nonauthorizing booleans")
        return value

    @model_validator(mode="after")
    def native_population_and_single_config_delta_are_exact(self) -> Self:
        subject = self.measurement_subject
        calibration_publication_subject_bytes(subject)
        calibration, policy = subject.calibration, subject.policy
        if (
            subject.phase != "MEASURED_POPULATION"
            or subject.proposal_status != "PROPOSED_NOT_ADOPTED"
            or calibration is None
            or policy is None
            or self.predecessor_policy.schema_version != "1.0"
            or policy.schema_version != "2.0"
            or self.predecessor_policy.policy_sha256 == policy.policy_sha256
        ):
            raise ValueError("configuration proposal requires a supported native P1-to-P2 policy")
        _policy_bytes(self.predecessor_policy)
        predecessor_raw = self.predecessor_effective_config_json
        successor_raw = self.successor_effective_config_json
        _configuration_payload(successor_raw)
        if successor_raw != _successor_config(
            predecessor_raw, self.predecessor_policy.policy_sha256, policy.policy_sha256
        ):
            raise ValueError("configuration proposal changes more than the allowed policy pin")
        predecessor_sha = hashlib.sha256(predecessor_raw.encode()).hexdigest()
        successor_sha = hashlib.sha256(successor_raw.encode()).hexdigest()
        if (
            predecessor_sha != self.predecessor_effective_config_sha256
            or successor_sha != self.successor_effective_config_sha256
        ):
            raise ValueError("configuration proposal full config hashes differ")
        # A reader in P1 validates C1; a source-pinned P2 reader may validate C2.
        # Neither path changes which pin AuditConfig admits in that source release.
        try:
            active = parse_canonical_audit_config(predecessor_raw)
        except ValueError:
            active = parse_canonical_audit_config(successor_raw)
        if (
            active.profile is not AuditProfile.MAXIMUM_ASSURANCE
            or active.privacy.profile is not PrivacyProfile.SYNTHETIC_BENCHMARK
            or active.maximum_assurance.allow_downgrade
            or active != active.effective()
            or qualification_policy_independent_config_sha256(active)
            != self.policy_independent_config_sha256
        ):
            raise ValueError("configuration proposal requires the exact effective maximum profile")
        pins = active.maximum_assurance.qualification
        for source in calibration.sources:
            evidence = source.runner_evidence
            if (
                evidence.effective_config_sha256 != predecessor_sha
                or evidence.benchmark_corpus_sha256 != pins.corpus_sha256
                or evidence.benchmark_ground_truth_sha256 != pins.ground_truth_sha256
                or any(
                    run.effective_config_sha256 != predecessor_sha
                    or run.policy_sha256 != self.predecessor_policy.policy_sha256
                    for run in source.runs
                )
            ):
                raise ValueError("configuration proposal differs from measured P1/C1 or truth")
        if self.proposal_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"proposal_sha256"})
        ):
            raise ValueError("configuration proposal hash is inconsistent")
        return self


def read_authenticated_calibration_config_proposal(
    raw: bytes,
) -> AuthenticatedCalibrationConfigProposal:
    """Read bounded canonical proposed data; never recreate native or release custody."""

    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_AUTHENTICATED_CALIBRATION_CONFIG_PROPOSAL_BYTES
    ):
        raise ValueError("configuration proposal bytes are absent or over bound")
    result = AuthenticatedCalibrationConfigProposal.model_validate_json(raw, strict=True)
    if stable_json(result.model_dump(mode="json")).encode() != raw:
        raise ValueError("configuration proposal bytes are not canonical")
    return result


def authenticated_calibration_config_proposal_bytes(
    proposal: AuthenticatedCalibrationConfigProposal,
) -> bytes:
    if type(proposal) is not AuthenticatedCalibrationConfigProposal:
        raise ValueError("configuration proposal requires its exact data type")
    raw = stable_json(proposal.model_dump(mode="json")).encode()
    read_authenticated_calibration_config_proposal(raw)
    return raw


def proposed_successor_config_bytes(proposal: AuthenticatedCalibrationConfigProposal) -> bytes:
    """Export exact C2 proposal bytes, not an executable configuration or authorization."""

    validated = read_authenticated_calibration_config_proposal(
        authenticated_calibration_config_proposal_bytes(proposal)
    )
    return validated.successor_effective_config_json.encode()


def _assemble_proposal(
    subject: CalibrationPublicationSubject,
    predecessor_policy: QualificationPolicy,
    predecessor_config: AuditConfig,
) -> AuthenticatedCalibrationConfigProposal:
    if subject.policy is None:
        raise ValueError("native policy refusal cannot produce a successor configuration")
    predecessor_raw = canonical_audit_config_json(predecessor_config)
    successor_raw = _successor_config(
        predecessor_raw, predecessor_policy.policy_sha256, subject.policy.policy_sha256
    )
    provisional = AuthenticatedCalibrationConfigProposal.model_construct(
        measurement_subject=subject,
        predecessor_policy=predecessor_policy,
        predecessor_effective_config_json=predecessor_raw,
        successor_effective_config_json=successor_raw,
        predecessor_effective_config_sha256=hashlib.sha256(predecessor_raw.encode()).hexdigest(),
        successor_effective_config_sha256=hashlib.sha256(successor_raw.encode()).hexdigest(),
        policy_independent_config_sha256=qualification_policy_independent_config_sha256(
            predecessor_config
        ),
        proposal_sha256="0" * 64,
    )
    payload = provisional.model_dump(mode="json", exclude={"proposal_sha256"})
    payload["proposal_sha256"] = canonical_sha256(payload)
    return read_authenticated_calibration_config_proposal(stable_json(payload).encode())


def _build_native_config_proposal() -> Callable[..., AuthenticatedCalibrationConfigProposal]:
    module = _publication
    publish = module.build_calibration_measurement_publication
    original_code = publish.__code__

    def pristine() -> None:
        if (
            module.build_calibration_measurement_publication is not publish
            or publish.__code__ is not original_code
        ):
            raise ValueError("configuration proposal native publication binding changed")

    def build(
        *,
        live: LiveRegisteredCalibrationMeasurement,
        evidence_root: Path,
        ledger: AtomicCostLedger,
        predecessor_policy: QualificationPolicy,
        predecessor_config: AuditConfig,
    ) -> AuthenticatedCalibrationConfigProposal:
        """Borrow and recheck original live population custody without adopting its policy."""

        pristine()
        if (
            type(predecessor_config) is not AuditConfig
            or type(live) is not LiveRegisteredCalibrationMeasurement
            or type(ledger) is not AtomicCostLedger
        ):
            raise ValueError("configuration proposal requires exact predecessor/native input types")
        live_fields = ("registration_sha256", "calibration", "policy", "verification")
        original_live = tuple(getattr(live, field) for field in live_fields)
        policy_raw = _policy_bytes(predecessor_policy)
        config_raw = canonical_audit_config_json(predecessor_config)
        config = parse_canonical_audit_config(config_raw)
        policy = QualificationPolicy.model_validate_json(policy_raw, strict=True)
        subject = publish(live=live, evidence_root=evidence_root, ledger=ledger)
        events, custody = _retained_journal(evidence_root, live.registration_sha256)
        if events != subject.population_events:
            raise ValueError("configuration proposal native population changed before construction")
        result = _assemble_proposal(subject, policy, config)
        if publish(live=live, evidence_root=evidence_root, ledger=ledger) != subject:
            raise ValueError("configuration proposal native population changed during construction")
        _require_journal(evidence_root, events, custody)
        if (
            _policy_bytes(predecessor_policy) != policy_raw
            or canonical_audit_config_json(predecessor_config) != config_raw
            or any(
                getattr(live, field) is not original
                for field, original in zip(live_fields, original_live, strict=True)
            )
            or ledger.snapshot_with_identity_sha256()
            != (events[-1].ledger_identity_sha256, events[-1].ledger_snapshot)
        ):
            raise ValueError("configuration proposal source changed during construction")
        pristine()
        return result

    return build


build_authenticated_calibration_config_proposal = _build_native_config_proposal()
del _build_native_config_proposal
