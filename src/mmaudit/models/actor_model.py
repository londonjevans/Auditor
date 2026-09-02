"""Typed operator-authored actor and incentive evidence for severity calibration."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

ACTOR_MODEL_MAX_BYTES = 1_000_000
ACTOR_CONSTRAINT_MIN_MATERIAL_DURATION_SECONDS = 86_400
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ID_PATTERN = r"^[a-z][a-z0-9._:-]{0,159}$"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _plain_text(value: str, *, label: str, maximum: int = 2_000) -> str:
    if (
        not value
        or value != value.strip()
        or len(value) > maximum
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError(f"{label} must be bounded normalized plain text")
    return value


def _canonical_strings(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be unique and canonically sorted")
    return values


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("actor-model source contains duplicate object keys")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> object:
    raise ValueError(f"actor-model source contains non-finite JSON: {value}")


def _governance_conflict_identity(
    *,
    kind: ActorGovernanceConflictKind,
    role_id: str,
    source_finding_ids: tuple[str, ...],
    actor_model_sha256: str | None,
    code_evidence_sha256s: tuple[str, ...],
) -> str:
    return _canonical_sha256(
        {
            "kind": kind.value,
            "role_id": role_id,
            "source_finding_ids": source_finding_ids,
            "actor_model_sha256": actor_model_sha256,
            "code_evidence_sha256s": code_evidence_sha256s,
        }
    )


class ActorEvidenceModel(BaseModel):
    """Strict immutable base for operator-authored and derived actor evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ActorRoleOccupancy(StrEnum):
    CURRENTLY_HELD = "currently_held"
    ADMITTED_UNFILLED = "admitted_unfilled"


class ActorCapitalSeniority(StrEnum):
    FIRST_LOSS = "first_loss"
    JUNIOR = "junior"
    PARI_PASSU = "pari_passu"
    SENIOR = "senior"
    NONE = "none"
    UNKNOWN = "unknown"


class ActorCapitalMateriality(StrEnum):
    MATERIAL = "material"
    IMMATERIAL = "immaterial"
    UNKNOWN = "unknown"


class ActorExposureState(StrEnum):
    PRESENT = "present"
    NONE = "none"
    UNKNOWN = "unknown"


class ActorEconomicExposureKind(StrEnum):
    FEE_REVENUE = "fee_revenue"
    PROTOCOL_FAILURE_LOSS = "protocol_failure_loss"


class ActorHarmedPartyDisposition(StrEnum):
    IDENTIFIED = "identified"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class ActorConstraintEffect(StrEnum):
    REDUCES_OPPORTUNISTIC_EXECUTION = "reduces_opportunistic_execution"
    LIMITS_ACTION_FREQUENCY = "limits_action_frequency"
    DELAYS_ACTION = "delays_action"
    REQUIRES_MULTIPARTY_APPROVAL = "requires_multiparty_approval"
    OTHER = "other"


class ActorModelInputState(StrEnum):
    CURRENT = "current"
    MISSING = "missing"
    INVALID = "invalid"
    FUTURE = "future"
    STALE = "stale"


class ActorModelApplicability(StrEnum):
    """Whether a finding's mechanism depends on privileged actor conduct."""

    PRIVILEGED_ACTOR_REQUIRED = "privileged_actor_required"
    NO_PRIVILEGED_ACTOR_REQUIRED = "no_privileged_actor_required"
    UNSTATED = "unstated"


class ActorLikelihoodAdjustment(StrEnum):
    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"
    UNASSESSED = "unassessed"


class ActorAssessmentDisposition(StrEnum):
    CURRENT_ROLE = "current_role"
    NOT_APPLICABLE_NONPRIVILEGED = "not_applicable_nonprivileged"
    ORDINARY_LEGITIMATE_BEHAVIOR = "ordinary_legitimate_behavior"
    ALIGNED_ACTION_JUSTIFIED = "aligned_action_justified"
    ALIGNED_ACTION_UNJUSTIFIED = "aligned_action_unjustified"
    ADMITTED_ROLE_UNFILLED = "admitted_role_unfilled"
    ROLE_UNMODELED = "role_unmodeled"
    CONTEXT_UNVERIFIED = "context_unverified"
    FINDING_ACTOR_UNSTATED = "finding_actor_unstated"
    ACTOR_MODEL_MISSING = "actor_model_missing"
    ACTOR_MODEL_INVALID = "actor_model_invalid"
    ACTOR_MODEL_FUTURE = "actor_model_future"
    ACTOR_MODEL_STALE = "actor_model_stale"


class ActorRemediationFocus(StrEnum):
    """Host-derived remediation framing produced from the actor disposition."""

    REACHABLE_STATE_TRANSITION = "reachable_state_transition"
    LEGITIMATE_STATE_TRANSITION = "legitimate_state_transition"
    ROLE_ACTIVATION_CONTROL = "role_activation_control"
    ECONOMIC_PLAUSIBILITY = "economic_plausibility"
    ACTOR_CONTEXT_VERIFICATION = "actor_context_verification"


def actor_remediation_guidance(focus: ActorRemediationFocus) -> str:
    """Return the bounded client-facing instruction for a host-derived focus."""

    return {
        ActorRemediationFocus.REACHABLE_STATE_TRANSITION: (
            "Mitigate the reachable state transition under the recorded actor assumptions."
        ),
        ActorRemediationFocus.LEGITIMATE_STATE_TRANSITION: (
            "Treat this as ordinary legitimate behavior, not misconduct; make the state "
            "transition safe without relying on adversarial-intent assumptions."
        ),
        ActorRemediationFocus.ROLE_ACTIVATION_CONTROL: (
            "Control role activation and reassess reachability when an admitted role becomes held."
        ),
        ActorRemediationFocus.ECONOMIC_PLAUSIBILITY: (
            "Validate the recorded economic rationale before treating the permitted action as "
            "a plausible adversarial path."
        ),
        ActorRemediationFocus.ACTOR_CONTEXT_VERIFICATION: (
            "Obtain current, exact actor evidence before relying on the severity calibration."
        ),
    }[focus]


class ActorGovernanceConflictKind(StrEnum):
    CODE_PERMITS_ADMITTED_UNFILLED_ROLE = "code_permits_admitted_unfilled_role"
    CODE_ROLE_ABSENT_FROM_ACTOR_MODEL = "code_role_absent_from_actor_model"
    ACTOR_ROLE_BINDING_ABSENT_FROM_CODE = "actor_role_binding_absent_from_code"
    GRAPH_EVIDENCE_INCOMPLETE = "graph_evidence_incomplete"
    FINDING_REFERENCES_UNMODELED_ROLE = "finding_references_unmodeled_role"
    FINDING_REFERENCES_UNMODELED_PARTY = "finding_references_unmodeled_party"
    FINDING_HARMED_PARTY_UNRESOLVED = "finding_harmed_party_unresolved"
    FINDING_REFERENCES_UNKNOWN_PERMISSION = "finding_references_unknown_permission"
    FINDING_REFERENCES_UNKNOWN_CONSTRAINT = "finding_references_unknown_constraint"
    FINDING_REFERENCES_UNSUPPORTED_CONSTRAINT = "finding_references_unsupported_constraint"
    FINDING_REFERENCES_UNKNOWN_STATED_INTEREST = "finding_references_unknown_stated_interest"
    FINDING_REFERENCES_UNKNOWN_CONCENTRATED_ROLE = "finding_references_unknown_concentrated_role"
    FINDING_REFERENCES_UNSUPPORTED_ECONOMIC_EXPOSURE = (
        "finding_references_unsupported_economic_exposure"
    )
    FINDING_REFERENCES_UNKNOWN_PLAUSIBILITY_EVIDENCE = (
        "finding_references_unknown_plausibility_evidence"
    )
    FINDING_DEPENDS_ON_ADMITTED_UNFILLED_ROLE = "finding_depends_on_admitted_unfilled_role"


class ActorSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActorCodeRoleEvidence(ActorEvidenceModel):
    node_id: str = Field(min_length=1, max_length=500)
    label: str = Field(min_length=1, max_length=500)
    path: str = Field(min_length=1, max_length=4_000)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    provenance: Literal["compiler", "fallback", "static_tool", "heuristic", "model_suggested"]
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=500)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, **values: Any) -> Self:
        if "evidence_sha256" in values:
            raise ValueError("actor code-role evidence hash is derived")
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        return cls.model_validate({**payload, "evidence_sha256": _canonical_sha256(payload)})

    @model_validator(mode="after")
    def code_evidence_is_exact(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("actor code-role evidence line interval is invalid")
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if self.evidence_sha256 != _canonical_sha256(payload):
            raise ValueError("actor code-role evidence hash is inconsistent")
        return self


class ActorEvidenceReference(ActorEvidenceModel):
    evidence_id: str = Field(pattern=_ID_PATTERN)
    kind: Literal[
        "adr",
        "governance_record",
        "operating_record",
        "operator_assertion",
    ]
    description: str = Field(min_length=1, max_length=2_000)
    content_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @field_validator("description")
    @classmethod
    def description_is_plain_text(cls, value: str) -> str:
        return _plain_text(value, label="actor evidence description")


class ActorEconomicExposure(ActorEvidenceModel):
    state: ActorExposureState
    description: str = Field(min_length=1, max_length=2_000)

    @field_validator("description")
    @classmethod
    def description_is_plain_text(cls, value: str) -> str:
        return _plain_text(value, label="actor economic exposure")


class ActorCapitalPosition(ActorEvidenceModel):
    position_id: str = Field(pattern=_ID_PATTERN)
    waterfall_id: str = Field(pattern=_ID_PATTERN)
    description: str = Field(min_length=1, max_length=2_000)
    asset_or_exposure: str = Field(min_length=1, max_length=500)
    amount_description: str = Field(min_length=1, max_length=500)
    amount_exact: str | None = Field(
        default=None,
        pattern=r"^(?:0|[1-9][0-9]{0,35})(?:\.[0-9]{1,36})?$",
    )
    amount_unit: str | None = Field(default=None, min_length=1, max_length=80)
    materiality: ActorCapitalMateriality
    seniority: ActorCapitalSeniority
    loss_absorption_order: int | None = Field(default=None, ge=0, le=1_000_000)

    @field_validator(
        "description",
        "asset_or_exposure",
        "amount_description",
        "amount_unit",
    )
    @classmethod
    def text_is_plain(cls, value: str | None) -> str | None:
        return None if value is None else _plain_text(value, label="actor capital position")

    @model_validator(mode="after")
    def seniority_has_an_explicit_order(self) -> Self:
        if (self.amount_exact is None) != (self.amount_unit is None):
            raise ValueError("exact capital amount and unit must be paired")
        if self.materiality is ActorCapitalMateriality.MATERIAL and (
            self.amount_exact is None or Decimal(self.amount_exact) <= 0
        ):
            raise ValueError("material capital requires a positive exact amount")
        if self.materiality is ActorCapitalMateriality.MATERIAL and self.seniority in {
            ActorCapitalSeniority.NONE,
            ActorCapitalSeniority.UNKNOWN,
        }:
            raise ValueError("material capital requires explicit comparable seniority")
        has_order = self.loss_absorption_order is not None
        if self.seniority in {ActorCapitalSeniority.NONE, ActorCapitalSeniority.UNKNOWN}:
            if has_order:
                raise ValueError("none/unknown capital seniority cannot claim a loss order")
        elif not has_order:
            raise ValueError("capital at risk requires an explicit loss-absorption order")
        return self


class ActorParty(ActorEvidenceModel):
    party_id: str = Field(pattern=_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=500)
    capital_positions: tuple[ActorCapitalPosition, ...] = Field(min_length=1, max_length=50)
    fee_revenue_exposure: ActorEconomicExposure
    protocol_failure_loss: ActorEconomicExposure
    stated_interests: tuple[str, ...] = Field(min_length=1, max_length=50)
    evidence_reference_ids: tuple[str, ...] = Field(min_length=1, max_length=100)

    @field_validator("display_name")
    @classmethod
    def display_name_is_plain_text(cls, value: str) -> str:
        return _plain_text(value, label="actor party display name", maximum=500)

    @field_validator("stated_interests")
    @classmethod
    def interests_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_plain_text(item, label="actor stated interest") for item in value)
        return _canonical_strings(normalized, label="actor stated interests")

    @field_validator("evidence_reference_ids")
    @classmethod
    def evidence_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="actor party evidence references")

    @field_validator("capital_positions")
    @classmethod
    def capital_positions_are_canonical(
        cls,
        value: tuple[ActorCapitalPosition, ...],
    ) -> tuple[ActorCapitalPosition, ...]:
        identifiers = tuple(position.position_id for position in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor capital positions must be unique and sorted")
        return value


class ActorOperationalConstraint(ActorEvidenceModel):
    constraint_id: str = Field(pattern=_ID_PATTERN)
    effect: ActorConstraintEffect
    description: str = Field(min_length=1, max_length=2_000)
    duration_seconds: int | None = Field(default=None, ge=1, le=31_536_000)
    applies_to_permissions: tuple[str, ...] = Field(min_length=1, max_length=100)
    required_approver_role_ids: tuple[str, ...] = Field(max_length=100)

    @field_validator("description")
    @classmethod
    def description_is_plain_text(cls, value: str) -> str:
        return _plain_text(value, label="actor operational constraint")

    @field_validator("applies_to_permissions")
    @classmethod
    def permissions_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            _plain_text(item, label="constrained actor permission") for item in value
        )
        return _canonical_strings(normalized, label="constrained actor permissions")

    @field_validator("required_approver_role_ids")
    @classmethod
    def approver_roles_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="constraint approver roles")

    @model_validator(mode="after")
    def approver_roles_match_effect(self) -> Self:
        temporal_effects = {
            ActorConstraintEffect.REDUCES_OPPORTUNISTIC_EXECUTION,
            ActorConstraintEffect.LIMITS_ACTION_FREQUENCY,
            ActorConstraintEffect.DELAYS_ACTION,
        }
        if (self.effect in temporal_effects) != (self.duration_seconds is not None):
            raise ValueError(
                "temporal actor constraints require one exact duration and other effects forbid it"
            )
        requires_approvers = self.effect is ActorConstraintEffect.REQUIRES_MULTIPARTY_APPROVAL
        if requires_approvers != bool(self.required_approver_role_ids):
            raise ValueError("multiparty approval effect requires exact approver role IDs only")
        return self


class PrivilegedActorRole(ActorEvidenceModel):
    role_id: str = Field(pattern=_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=500)
    code_identifiers: tuple[str, ...] = Field(min_length=1, max_length=100)
    occupancy: ActorRoleOccupancy
    holder_party_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    admitted_holder_class: str | None = Field(default=None, min_length=1, max_length=500)
    concentrated_with_role_ids: tuple[str, ...] = Field(max_length=100)
    permissions: tuple[str, ...] = Field(min_length=1, max_length=100)
    operational_constraints: tuple[ActorOperationalConstraint, ...] = Field(
        default=(),
        max_length=100,
    )
    evidence_reference_ids: tuple[str, ...] = Field(min_length=1, max_length=100)

    @field_validator("display_name", "admitted_holder_class")
    @classmethod
    def optional_text_is_plain(cls, value: str | None) -> str | None:
        return (
            None
            if value is None
            else _plain_text(value, label="privileged actor role text", maximum=500)
        )

    @field_validator(
        "code_identifiers",
        "concentrated_with_role_ids",
        "permissions",
        "evidence_reference_ids",
    )
    @classmethod
    def string_inventories_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_plain_text(item, label="privileged role inventory") for item in value)
        return _canonical_strings(normalized, label="privileged role inventory")

    @field_validator("operational_constraints")
    @classmethod
    def constraints_are_canonical(
        cls,
        value: tuple[ActorOperationalConstraint, ...],
    ) -> tuple[ActorOperationalConstraint, ...]:
        identifiers = tuple(item.constraint_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor operational constraints must be unique and sorted")
        return value

    @model_validator(mode="after")
    def occupancy_fields_are_exact(self) -> Self:
        if self.occupancy is ActorRoleOccupancy.CURRENTLY_HELD:
            if self.holder_party_id is None or self.admitted_holder_class is not None:
                raise ValueError("currently held roles require only an exact holder party")
        elif self.holder_party_id is not None or self.admitted_holder_class is None:
            raise ValueError("admitted-unfilled roles require only an admitted holder class")
        if any(
            not set(constraint.applies_to_permissions) <= set(self.permissions)
            for constraint in self.operational_constraints
        ):
            raise ValueError("actor constraint references a permission absent from its role")
        return self


class ActorModel(ActorEvidenceModel):
    """Versioned operator assertion about privileged actors and economic incentives."""

    schema_version: Literal["1.0"]
    authorship: Literal["operator_authored"]
    subject_id: str = Field(pattern=_ID_PATTERN)
    subject_name: str = Field(min_length=1, max_length=500)
    authored_at: datetime
    valid_from: datetime
    valid_until: datetime
    evidence_references: tuple[ActorEvidenceReference, ...] = Field(
        min_length=1,
        max_length=500,
    )
    parties: tuple[ActorParty, ...] = Field(min_length=1, max_length=500)
    roles: tuple[PrivilegedActorRole, ...] = Field(min_length=1, max_length=500)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, **values: Any) -> Self:
        if "artifact_sha256" in values:
            raise ValueError("actor model artifact_sha256 is derived")
        values.setdefault("schema_version", "1.0")
        values.setdefault("authorship", "operator_authored")
        provisional = cls.model_construct(**values, artifact_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"artifact_sha256"})
        return cls.model_validate_json(
            json.dumps(
                {**payload, "artifact_sha256": _canonical_sha256(payload)},
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )

    @field_validator("subject_name")
    @classmethod
    def subject_name_is_plain_text(cls, value: str) -> str:
        return _plain_text(value, label="actor model subject name", maximum=500)

    @field_validator("authored_at", "valid_from", "valid_until")
    @classmethod
    def timestamps_are_exact_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("actor model timestamps must be UTC-aware")
        if value.microsecond:
            raise ValueError("actor model timestamps must use whole seconds")
        return value

    @field_validator("evidence_references")
    @classmethod
    def evidence_is_canonical(
        cls,
        value: tuple[ActorEvidenceReference, ...],
    ) -> tuple[ActorEvidenceReference, ...]:
        identifiers = tuple(item.evidence_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor evidence references must be unique and sorted")
        return value

    @field_validator("parties")
    @classmethod
    def parties_are_canonical(cls, value: tuple[ActorParty, ...]) -> tuple[ActorParty, ...]:
        identifiers = tuple(item.party_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor parties must be unique and sorted")
        return value

    @field_validator("roles")
    @classmethod
    def roles_are_canonical(
        cls,
        value: tuple[PrivilegedActorRole, ...],
    ) -> tuple[PrivilegedActorRole, ...]:
        identifiers = tuple(item.role_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("privileged actor roles must be unique and sorted")
        return value

    @model_validator(mode="after")
    def references_concentration_and_hash_are_exact(self) -> Self:
        if not self.authored_at <= self.valid_from < self.valid_until:
            raise ValueError("actor model validity interval is inconsistent")
        evidence_ids = {item.evidence_id for item in self.evidence_references}
        party_ids = {item.party_id for item in self.parties}
        role_ids = {item.role_id for item in self.roles}
        code_identifiers = tuple(
            identifier for role in self.roles for identifier in role.code_identifiers
        )
        if len(code_identifiers) != len(set(code_identifiers)):
            raise ValueError("actor role code identifiers must be globally unique")
        for party in self.parties:
            if not set(party.evidence_reference_ids) <= evidence_ids:
                raise ValueError("actor party references unknown operator evidence")
        for role in self.roles:
            if not set(role.evidence_reference_ids) <= evidence_ids:
                raise ValueError("privileged role references unknown operator evidence")
            if role.holder_party_id is not None and role.holder_party_id not in party_ids:
                raise ValueError("privileged role references an unknown holder party")
            if not set(role.concentrated_with_role_ids) <= role_ids - {role.role_id}:
                raise ValueError("role concentration references an unknown or self role")
            expected_concentration = tuple(
                sorted(
                    peer.role_id
                    for peer in self.roles
                    if role.holder_party_id is not None
                    and peer.role_id != role.role_id
                    and peer.holder_party_id == role.holder_party_id
                )
            )
            if role.concentrated_with_role_ids != expected_concentration:
                raise ValueError("role concentration differs from the exact holder inventory")
            if any(
                not set(constraint.required_approver_role_ids) <= role_ids - {role.role_id}
                for constraint in role.operational_constraints
            ):
                raise ValueError("actor constraint references an unknown or self approver role")
        positions_by_waterfall: dict[str, list[ActorCapitalPosition]] = {}
        for party in self.parties:
            for position in party.capital_positions:
                if position.loss_absorption_order is not None:
                    positions_by_waterfall.setdefault(position.waterfall_id, []).append(position)
        for positions in positions_by_waterfall.values():
            orders = tuple(position.loss_absorption_order for position in positions)
            minimum_order = min(order for order in orders if order is not None)
            maximum_order = max(order for order in orders if order is not None)
            for position in positions:
                if (
                    position.seniority is ActorCapitalSeniority.FIRST_LOSS
                    and position.loss_absorption_order != minimum_order
                ):
                    raise ValueError("first-loss capital is not first in its exact waterfall")
                if (
                    position.seniority is ActorCapitalSeniority.SENIOR
                    and position.loss_absorption_order != maximum_order
                ):
                    raise ValueError("senior capital is not last in its exact waterfall")
                peers = tuple(
                    peer
                    for peer in positions
                    if peer.loss_absorption_order == position.loss_absorption_order
                )
                if position.seniority is ActorCapitalSeniority.PARI_PASSU and len(peers) < 2:
                    raise ValueError("pari-passu capital requires a peer at the same loss order")
                if len(peers) > 1 and any(
                    peer.seniority is not ActorCapitalSeniority.PARI_PASSU for peer in peers
                ):
                    raise ValueError("shared loss order must be declared pari passu")
        payload = self.model_dump(mode="json", exclude={"artifact_sha256"})
        if self.artifact_sha256 != _canonical_sha256(payload):
            raise ValueError("actor model artifact hash differs from its semantic content")
        return self

    def is_current(self, *, at: datetime) -> bool:
        if at.tzinfo is None:
            raise ValueError("actor model freshness requires an aware timestamp")
        return self.valid_from <= at < self.valid_until

    def role(self, role_id: str) -> PrivilegedActorRole | None:
        return next((role for role in self.roles if role.role_id == role_id), None)

    def party(self, party_id: str) -> ActorParty | None:
        return next((party for party in self.parties if party.party_id == party_id), None)


class ActorModelSourceEvidence(ActorEvidenceModel):
    """Raw-file identity plus the exact self-hashed semantic actor model."""

    schema_version: Literal["1.0"] = "1.0"
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_bytes: int = Field(ge=1, le=ACTOR_MODEL_MAX_BYTES)
    actor_model: ActorModel
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, *, raw: bytes, actor_model: ActorModel) -> Self:
        try:
            decoded = raw.decode("utf-8")
            parsed = json.loads(
                decoded,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_nonfinite_json,
            )
            if not isinstance(parsed, dict):
                raise ValueError("actor-model source must be a JSON object")
            canonical = json.dumps(
                parsed,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
            parsed_actor_model = ActorModel.model_validate_json(canonical, strict=True)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise ValueError("raw actor-model source is not the supplied typed model") from exc
        if parsed_actor_model != actor_model:
            raise ValueError("raw actor-model source differs from the supplied typed model")
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "source_bytes": len(raw),
            "actor_model": actor_model.model_dump(mode="json"),
        }
        return cls.model_validate_json(
            json.dumps(
                {**payload, "evidence_sha256": _canonical_sha256(payload)},
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )

    @model_validator(mode="after")
    def evidence_is_self_hashed(self) -> Self:
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if self.evidence_sha256 != _canonical_sha256(payload):
            raise ValueError("actor-model source evidence hash is inconsistent")
        return self


class ActorModelInputEvidence(ActorEvidenceModel):
    """Run-start evaluation of one configured operator actor-model input."""

    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    state: ActorModelInputState
    configured: bool
    configured_path: str | None = Field(max_length=4_000)
    source_evidence: ActorModelSourceEvidence | None = None
    rejected_source_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    rejected_source_bytes: int | None = Field(default=None, ge=1, le=ACTOR_MODEL_MAX_BYTES)
    limitations: tuple[str, ...] = Field(default=(), max_length=100)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, **values: Any) -> Self:
        if "evidence_sha256" in values:
            raise ValueError("actor-model input evidence hash is derived")
        values.setdefault("schema_version", "1.0")
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        return cls.model_validate_json(
            json.dumps(
                {**payload, "evidence_sha256": _canonical_sha256(payload)},
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("actor-model evaluation timestamp must be aware")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_plain_text(item, label="actor-model limitation") for item in value)
        return _canonical_strings(normalized, label="actor-model limitations")

    @field_validator("configured_path")
    @classmethod
    def configured_path_is_exact(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = value.split("/")
        if (
            not value
            or value != value.strip()
            or "\\" in value
            or value.startswith(("/", "-"))
            or any(part in {"", ".", ".."} for part in parts)
            or not value.lower().endswith(".json")
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("actor-model configured path must be normalized and relative")
        return value

    @model_validator(mode="after")
    def state_fields_and_hash_are_exact(self) -> Self:
        if self.configured != (self.configured_path is not None):
            raise ValueError("actor-model configured state differs from its exact path")
        rejected_fields_paired = (self.rejected_source_sha256 is None) == (
            self.rejected_source_bytes is None
        )
        if not rejected_fields_paired:
            raise ValueError("rejected actor-model source identity must be paired")
        if self.state is ActorModelInputState.CURRENT:
            if not self.configured or self.source_evidence is None or self.limitations:
                raise ValueError("current actor-model input requires only parsed source evidence")
            if self.rejected_source_sha256 is not None:
                raise ValueError("current actor-model input cannot retain rejected source identity")
        elif self.state in {ActorModelInputState.STALE, ActorModelInputState.FUTURE}:
            if not self.configured or self.source_evidence is None or not self.limitations:
                raise ValueError("non-current parsed actor model requires source and limitation")
            if self.rejected_source_sha256 is not None:
                raise ValueError("parsed actor-model input cannot retain rejected source identity")
        elif self.state is ActorModelInputState.INVALID:
            if not self.configured or self.source_evidence is not None or not self.limitations:
                raise ValueError("invalid actor-model input requires only a limitation")
        elif (
            self.configured
            or self.source_evidence is not None
            or self.rejected_source_sha256 is not None
            or not self.limitations
        ):
            raise ValueError("missing actor-model input requires only a limitation")
        if self.source_evidence is not None:
            actor_model = self.source_evidence.actor_model
            expected_state = (
                ActorModelInputState.FUTURE
                if self.evaluated_at < actor_model.valid_from
                else (
                    ActorModelInputState.STALE
                    if self.evaluated_at >= actor_model.valid_until
                    else ActorModelInputState.CURRENT
                )
            )
            if self.state is not expected_state:
                raise ValueError("actor-model input state differs from its validity interval")
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if self.evidence_sha256 != _canonical_sha256(payload):
            raise ValueError("actor-model input evidence hash is inconsistent")
        return self


class CandidateActorContext(ActorEvidenceModel):
    """One finding's explicit actor assumptions; never an assertion of role ownership."""

    role_id: str = Field(pattern=_ID_PATTERN)
    severity_basis: Literal["code_mechanism_only"]
    harmed_party_disposition: ActorHarmedPartyDisposition
    harmed_party_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    privileged_action_required: bool
    permission: str | None = Field(default=None, min_length=1, max_length=2_000)
    misconduct_required: bool
    ordinary_legitimate_behavior: bool
    action_against_stated_interest: bool
    stated_interest: str | None = Field(default=None, min_length=1, max_length=2_000)
    relevant_constraint_ids: tuple[str, ...] = Field(default=(), max_length=100)
    required_concentrated_role_ids: tuple[str, ...] = Field(default=(), max_length=100)
    relevant_economic_exposures: tuple[ActorEconomicExposureKind, ...] = Field(
        default=(),
        max_length=2,
    )
    plausibility_rationale: str | None = Field(default=None, min_length=1, max_length=2_000)
    plausibility_evidence_reference_ids: tuple[str, ...] = Field(
        default=(),
        max_length=100,
    )

    @field_validator(
        "relevant_constraint_ids",
        "required_concentrated_role_ids",
        "plausibility_evidence_reference_ids",
    )
    @classmethod
    def constraints_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="finding actor constraints")

    @field_validator("relevant_economic_exposures")
    @classmethod
    def economic_exposures_are_canonical(
        cls,
        value: tuple[ActorEconomicExposureKind, ...],
    ) -> tuple[ActorEconomicExposureKind, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("finding economic exposures must be unique and sorted")
        return value

    @field_validator("permission", "stated_interest", "plausibility_rationale")
    @classmethod
    def rationale_is_plain(cls, value: str | None) -> str | None:
        return None if value is None else _plain_text(value, label="actor plausibility rationale")

    @model_validator(mode="after")
    def behavior_flags_do_not_conflict(self) -> Self:
        if (self.harmed_party_disposition is ActorHarmedPartyDisposition.IDENTIFIED) != (
            self.harmed_party_id is not None
        ):
            raise ValueError("identified harmed-party disposition requires exactly one party ID")
        if self.ordinary_legitimate_behavior and self.misconduct_required:
            raise ValueError("ordinary legitimate behavior cannot require misconduct")
        if not self.privileged_action_required and self.action_against_stated_interest:
            raise ValueError("non-privileged behavior cannot claim privileged interest conflict")
        if self.privileged_action_required != (self.permission is not None):
            raise ValueError("privileged actor context requires one exact role permission")
        if not self.privileged_action_required and self.relevant_constraint_ids:
            raise ValueError("non-privileged actor context cannot claim privileged constraints")
        if not self.privileged_action_required and (
            self.required_concentrated_role_ids or self.relevant_economic_exposures
        ):
            raise ValueError("non-privileged actor context cannot claim privileged economics")
        if self.action_against_stated_interest != (self.stated_interest is not None):
            raise ValueError("against-interest actor context requires one exact stated interest")
        if (self.plausibility_rationale is None) != (not self.plausibility_evidence_reference_ids):
            raise ValueError(
                "actor plausibility rationale and evidence references must be present together"
            )
        if self.ordinary_legitimate_behavior and self.plausibility_rationale is None:
            raise ValueError(
                "ordinary legitimate behavior requires operator-bound plausibility evidence"
            )
        return self


class FindingActorAssessment(ActorEvidenceModel):
    schema_version: Literal["1.0"] = "1.0"
    input_state: ActorModelInputState
    disposition: ActorAssessmentDisposition
    actor_model_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    actor_model_source_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    role_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    severity_basis: Literal["code_mechanism_only"] | None = None
    harmed_party_disposition: ActorHarmedPartyDisposition | None = None
    harmed_party_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    role_occupancy: ActorRoleOccupancy | None = None
    holder_party_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    concentrated_with_role_ids: tuple[str, ...] = Field(default=(), max_length=100)
    holder_fee_revenue_exposure: ActorExposureState | None = None
    holder_protocol_failure_loss: ActorExposureState | None = None
    privileged_action_required: bool | None = None
    permission: str | None = Field(default=None, min_length=1, max_length=2_000)
    baseline_finding_sha256: str = Field(pattern=_SHA256_PATTERN)
    original_severity: ActorSeverity
    calibrated_severity: ActorSeverity
    likelihood_adjustment: ActorLikelihoodAdjustment
    misconduct_required: bool | None = None
    ordinary_legitimate_behavior: bool | None = None
    action_against_stated_interest: bool | None = None
    stated_interest: str | None = Field(default=None, min_length=1, max_length=2_000)
    capital_consumed_before_harmed_party: bool | None = None
    applied_constraint_ids: tuple[str, ...] = Field(default=(), max_length=100)
    required_concentrated_role_ids: tuple[str, ...] = Field(default=(), max_length=100)
    relevant_economic_exposures: tuple[ActorEconomicExposureKind, ...] = Field(
        default=(),
        max_length=2,
    )
    plausibility_rationale: str | None = Field(default=None, min_length=1, max_length=2_000)
    plausibility_evidence_reference_ids: tuple[str, ...] = Field(
        default=(),
        max_length=100,
    )
    remediation_focus: ActorRemediationFocus
    limitation: str | None = Field(default=None, min_length=1, max_length=2_000)
    governance_conflict_id: str | None = Field(
        default=None,
        pattern=r"^actor-governance:[0-9a-f]{64}$",
    )
    assessment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, **values: Any) -> Self:
        if "assessment_sha256" in values:
            raise ValueError("actor assessment hash is derived")
        values.setdefault("schema_version", "1.0")
        provisional = cls.model_construct(**values, assessment_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"assessment_sha256"})
        return cls.model_validate_json(
            json.dumps(
                {**payload, "assessment_sha256": _canonical_sha256(payload)},
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )

    @field_validator(
        "applied_constraint_ids",
        "concentrated_with_role_ids",
        "required_concentrated_role_ids",
        "plausibility_evidence_reference_ids",
    )
    @classmethod
    def constraints_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="applied actor constraints")

    @field_validator("relevant_economic_exposures")
    @classmethod
    def economic_exposures_are_canonical(
        cls,
        value: tuple[ActorEconomicExposureKind, ...],
    ) -> tuple[ActorEconomicExposureKind, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("applied actor economic exposures must be unique and sorted")
        return value

    @field_validator("permission", "stated_interest", "plausibility_rationale", "limitation")
    @classmethod
    def optional_text_is_plain(cls, value: str | None) -> str | None:
        return None if value is None else _plain_text(value, label="actor assessment text")

    @model_validator(mode="after")
    def assessment_fields_and_hash_are_exact(self) -> Self:
        source_present = self.actor_model_source_sha256 is not None
        model_present = self.actor_model_sha256 is not None
        if source_present != model_present:
            raise ValueError("actor assessment source and semantic hashes must be paired")
        if (
            self.disposition
            in {
                ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
                ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
                ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
                ActorAssessmentDisposition.ACTOR_MODEL_STALE,
                ActorAssessmentDisposition.FINDING_ACTOR_UNSTATED,
                ActorAssessmentDisposition.ROLE_UNMODELED,
                ActorAssessmentDisposition.CONTEXT_UNVERIFIED,
            }
            and self.limitation is None
        ):
            raise ValueError("unresolved actor assessment requires an explicit limitation")
        noncurrent_disposition = {
            ActorModelInputState.MISSING: ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
            ActorModelInputState.INVALID: ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
            ActorModelInputState.FUTURE: ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
            ActorModelInputState.STALE: ActorAssessmentDisposition.ACTOR_MODEL_STALE,
        }.get(self.input_state)
        if noncurrent_disposition is not None and self.disposition is not noncurrent_disposition:
            raise ValueError("non-current actor assessment disposition differs from input state")
        if self.input_state is ActorModelInputState.CURRENT and self.disposition in {
            ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
            ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
            ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
            ActorAssessmentDisposition.ACTOR_MODEL_STALE,
        }:
            raise ValueError("current actor assessment cannot claim non-current input disposition")
        if noncurrent_disposition is not None and (
            self.limitation is None
            or self.likelihood_adjustment is not ActorLikelihoodAdjustment.UNASSESSED
        ):
            raise ValueError(
                "non-current actor assessment requires a limitation and unassessed likelihood"
            )
        if self.input_state in {ActorModelInputState.MISSING, ActorModelInputState.INVALID} and (
            model_present
        ):
            raise ValueError("unavailable actor-model assessment cannot claim model evidence")
        if self.input_state in {ActorModelInputState.FUTURE, ActorModelInputState.STALE} and (
            not model_present
        ):
            raise ValueError("future/stale actor assessment requires exact model evidence")
        if self.input_state is ActorModelInputState.CURRENT and not model_present:
            raise ValueError("current actor assessment requires exact actor-model evidence")
        context_present = self.role_id is not None
        context_fields = (
            self.severity_basis,
            self.harmed_party_disposition,
            self.privileged_action_required,
            self.misconduct_required,
            self.ordinary_legitimate_behavior,
            self.action_against_stated_interest,
        )
        if (context_present and any(value is None for value in context_fields)) or (
            not context_present and any(value is not None for value in context_fields)
        ):
            raise ValueError("actor assessment context fields must be present together")
        if self.harmed_party_disposition is not None and (
            (self.harmed_party_disposition is ActorHarmedPartyDisposition.IDENTIFIED)
            != (self.harmed_party_id is not None)
        ):
            raise ValueError("actor assessment harmed-party disposition is inconsistent")
        if self.privileged_action_required is not None and (
            self.privileged_action_required != (self.permission is not None)
        ):
            raise ValueError("actor assessment permission differs from privileged conduct")
        if self.action_against_stated_interest is not None and (
            self.action_against_stated_interest != (self.stated_interest is not None)
        ):
            raise ValueError("actor assessment stated interest differs from conduct framing")
        if (self.plausibility_rationale is None) != (not self.plausibility_evidence_reference_ids):
            raise ValueError(
                "actor assessment plausibility rationale and evidence must be present together"
            )
        expected_focus = {
            ActorAssessmentDisposition.ORDINARY_LEGITIMATE_BEHAVIOR: (
                ActorRemediationFocus.LEGITIMATE_STATE_TRANSITION
            ),
            ActorAssessmentDisposition.ADMITTED_ROLE_UNFILLED: (
                ActorRemediationFocus.ROLE_ACTIVATION_CONTROL
            ),
            ActorAssessmentDisposition.ALIGNED_ACTION_JUSTIFIED: (
                ActorRemediationFocus.ECONOMIC_PLAUSIBILITY
            ),
            ActorAssessmentDisposition.ALIGNED_ACTION_UNJUSTIFIED: (
                ActorRemediationFocus.ECONOMIC_PLAUSIBILITY
            ),
        }.get(self.disposition)
        if expected_focus is None:
            expected_focus = (
                ActorRemediationFocus.ACTOR_CONTEXT_VERIFICATION
                if self.disposition
                in {
                    ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
                    ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
                    ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
                    ActorAssessmentDisposition.ACTOR_MODEL_STALE,
                    ActorAssessmentDisposition.FINDING_ACTOR_UNSTATED,
                    ActorAssessmentDisposition.ROLE_UNMODELED,
                    ActorAssessmentDisposition.CONTEXT_UNVERIFIED,
                }
                else ActorRemediationFocus.REACHABLE_STATE_TRANSITION
            )
        if self.remediation_focus is not expected_focus:
            raise ValueError("actor remediation focus differs from its disposition")
        if (
            self.input_state is not ActorModelInputState.CURRENT
            and self.calibrated_severity is not self.original_severity
        ):
            raise ValueError("non-current actor evidence cannot change severity")
        payload = self.model_dump(mode="json", exclude={"assessment_sha256"})
        if self.assessment_sha256 != _canonical_sha256(payload):
            raise ValueError("finding actor assessment hash is inconsistent")
        return self


class ActorGovernanceFinding(ActorEvidenceModel):
    schema_version: Literal["1.0"] = "1.0"
    conflict_id: str = Field(pattern=r"^actor-governance:[0-9a-f]{64}$")
    kind: ActorGovernanceConflictKind
    role_id: str = Field(pattern=_ID_PATTERN)
    source_finding_ids: tuple[str, ...] = Field(default=(), max_length=100_000)
    detail: str = Field(min_length=1, max_length=2_000)
    actor_model_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    code_evidence: tuple[ActorCodeRoleEvidence, ...] = Field(default=(), max_length=1_000)
    finding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        kind: ActorGovernanceConflictKind,
        role_id: str,
        source_finding_ids: tuple[str, ...],
        detail: str,
        actor_model_sha256: str | None,
        code_evidence: tuple[ActorCodeRoleEvidence, ...] = (),
    ) -> Self:
        identifiers = _canonical_strings(source_finding_ids, label="governance source findings")
        canonical_code_evidence = tuple(
            sorted(code_evidence, key=lambda item: item.evidence_sha256)
        )
        if len(canonical_code_evidence) != len(
            {item.evidence_sha256 for item in canonical_code_evidence}
        ):
            raise ValueError("actor governance code evidence must be unique")
        identity = _governance_conflict_identity(
            kind=kind,
            role_id=role_id,
            source_finding_ids=identifiers,
            actor_model_sha256=actor_model_sha256,
            code_evidence_sha256s=tuple(item.evidence_sha256 for item in canonical_code_evidence),
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "conflict_id": f"actor-governance:{identity}",
            "kind": kind,
            "role_id": role_id,
            "source_finding_ids": identifiers,
            "detail": detail,
            "actor_model_sha256": actor_model_sha256,
            "code_evidence": tuple(
                item.model_dump(mode="json") for item in canonical_code_evidence
            ),
        }
        return cls(**payload, finding_sha256=_canonical_sha256(payload))

    @field_validator("source_finding_ids")
    @classmethod
    def source_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="governance source findings")

    @field_validator("detail")
    @classmethod
    def detail_is_plain(cls, value: str) -> str:
        return _plain_text(value, label="actor governance finding")

    @field_validator("code_evidence")
    @classmethod
    def code_evidence_is_canonical(
        cls,
        value: tuple[ActorCodeRoleEvidence, ...],
    ) -> tuple[ActorCodeRoleEvidence, ...]:
        identities = tuple(item.evidence_sha256 for item in value)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("actor governance code evidence must be unique and sorted")
        return value

    @model_validator(mode="after")
    def finding_is_self_hashed(self) -> Self:
        expected_conflict_id = "actor-governance:" + _governance_conflict_identity(
            kind=self.kind,
            role_id=self.role_id,
            source_finding_ids=self.source_finding_ids,
            actor_model_sha256=self.actor_model_sha256,
            code_evidence_sha256s=tuple(item.evidence_sha256 for item in self.code_evidence),
        )
        if self.conflict_id != expected_conflict_id:
            raise ValueError("actor governance conflict ID is inconsistent")
        payload = self.model_dump(mode="json", exclude={"finding_sha256"})
        if self.finding_sha256 != _canonical_sha256(payload):
            raise ValueError("actor governance finding hash is inconsistent")
        return self


class ActorFindingAssessmentBinding(ActorEvidenceModel):
    finding_id: str = Field(min_length=1, max_length=500)
    baseline_finding_sha256: str = Field(pattern=_SHA256_PATTERN)
    assessment_sha256: str = Field(pattern=_SHA256_PATTERN)


class ActorModelEvaluation(ActorEvidenceModel):
    """Run-level custody proving every reported severity received an actor assessment."""

    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    input_evidence: ActorModelInputEvidence
    governance_findings: tuple[ActorGovernanceFinding, ...] = Field(default=(), max_length=100_000)
    finding_assessments: tuple[ActorFindingAssessmentBinding, ...] = Field(
        default=(),
        max_length=100_000,
    )
    evaluation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, **values: Any) -> Self:
        if "evaluation_sha256" in values:
            raise ValueError("actor evaluation hash is derived")
        values.setdefault("schema_version", "1.0")
        provisional = cls.model_construct(**values, evaluation_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evaluation_sha256"})
        return cls.model_validate_json(
            json.dumps(
                {**payload, "evaluation_sha256": _canonical_sha256(payload)},
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )

    @field_validator("evaluated_at")
    @classmethod
    def evaluated_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("actor evaluation timestamp must be aware")
        return value

    @field_validator("governance_findings")
    @classmethod
    def governance_is_canonical(
        cls,
        value: tuple[ActorGovernanceFinding, ...],
    ) -> tuple[ActorGovernanceFinding, ...]:
        identifiers = tuple(item.conflict_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor governance findings must be unique and sorted")
        return value

    @field_validator("finding_assessments")
    @classmethod
    def assessments_are_canonical(
        cls,
        value: tuple[ActorFindingAssessmentBinding, ...],
    ) -> tuple[ActorFindingAssessmentBinding, ...]:
        identifiers = tuple(item.finding_id for item in value)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("actor finding assessments must be unique and sorted")
        return value

    @model_validator(mode="after")
    def state_and_hash_are_exact(self) -> Self:
        if self.evaluated_at != self.input_evidence.evaluated_at:
            raise ValueError("actor evaluation timestamp differs from input evidence")
        payload = self.model_dump(mode="json", exclude={"evaluation_sha256"})
        if self.evaluation_sha256 != _canonical_sha256(payload):
            raise ValueError("actor model evaluation hash is inconsistent")
        return self


__all__ = [
    "ACTOR_CONSTRAINT_MIN_MATERIAL_DURATION_SECONDS",
    "ACTOR_MODEL_MAX_BYTES",
    "ActorAssessmentDisposition",
    "ActorCapitalMateriality",
    "ActorCapitalPosition",
    "ActorCapitalSeniority",
    "ActorCodeRoleEvidence",
    "ActorConstraintEffect",
    "ActorEconomicExposure",
    "ActorEconomicExposureKind",
    "ActorEvidenceReference",
    "ActorExposureState",
    "ActorFindingAssessmentBinding",
    "ActorGovernanceConflictKind",
    "ActorGovernanceFinding",
    "ActorHarmedPartyDisposition",
    "ActorLikelihoodAdjustment",
    "ActorModel",
    "ActorModelApplicability",
    "ActorModelEvaluation",
    "ActorModelInputEvidence",
    "ActorModelInputState",
    "ActorModelSourceEvidence",
    "ActorOperationalConstraint",
    "ActorParty",
    "ActorRemediationFocus",
    "ActorRoleOccupancy",
    "ActorSeverity",
    "CandidateActorContext",
    "FindingActorAssessment",
    "PrivilegedActorRole",
    "actor_remediation_guidance",
]
