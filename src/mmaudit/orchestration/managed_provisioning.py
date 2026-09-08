"""Typed nonauthorizing setup and refusal evidence for managed audit inputs.

This module is deliberately pure.  It binds one exact managed-toolchain declaration and
effective configuration, accepts only typed observations from a separately controlled local
setup boundary, and reduces them to deterministic refusal evidence.  It grants no trust,
spend admission, process identity, execution, or runtime authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.config import AuditConfig, RepositoryPinnedForkMatrixStateConfig
from mmaudit.models.schemas import LanguageCapabilityProfile, StrictModel
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainError,
    ManagedToolchainRole,
    preflight_managed_toolchain_config,
    resolve_managed_toolchain_config,
)

MANAGED_PROVISIONING_SCHEMA_VERSION = "1.0"
MANAGED_PROVISIONING_OBJECTIVE_SHA256 = (
    "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUIREMENT_ID_PATTERN = r"^[a-z][a-z0-9-]{0,127}$"
_DECIMAL_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,18})?$"
_LIMITATION_PATTERN = r"^[ -~]{1,300}$"
MAX_MANAGED_PROVISIONING_STATE_BYTES = 1024 * 1024
MAX_MANAGED_PROVISIONING_RECEIPT_BYTES = 2 * 1024 * 1024
_MAX_TOOLCHAIN_ROLES = 28
_MAX_FORK_REQUIREMENTS = 9
_MAX_VERIFIED_REQUIREMENTS = 12
_MAX_REFUSALS = 41
_MAX_LEDGER_ENTRIES = 100_000
_MAX_PORTFOLIO_HOLDS = 256
SetupPolicySha256 = Literal[
    "ff438f3fd072329a5abfadfebc75e800a4cb36dbaa0d4e8c9f761d8e4b76750f",
    "7d0d9c2a7ded8b955fafb027abdb1bb20e8a25577335dc945e6745c8ab174f19",
]
_SETUP_POLICY = {
    "schema": "mmaudit.managed-provisioning-policy.v2",
    "local_actions": [
        "create-or-open-exact-cost-ledger",
        "verify-configured-private-dependency-snapshot",
    ],
    "dependency_checks": [
        "exact-detected-hardhat-root-set",
        "target-lockfiles-and-inert-package-trees",
        "supplied-exact-version-advisories",
        "pre-and-post-publication-rechecks",
    ],
    "unverified_inputs": [
        "codeql-database-and-query-suite",
        "dependency-archive-provenance",
        "dependency-advisory-freshness-and-completeness",
        "installed-managed-toolchain",
        "pinned-loopback-fork",
    ],
    "authority": False,
}
MANAGED_PROVISIONING_POLICY_SHA256 = hashlib.sha256(
    json.dumps(_SETUP_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()

_REFUSAL_LIMITATIONS: dict[ManagedProvisioningRefusalCode, str]


class ManagedProvisioningError(ValueError):
    """Raised when provisioning evidence cannot be reduced safely."""


class ManagedProvisioningKind(StrEnum):
    """Closed pre-run input kinds represented by the Phase-2 contract."""

    COST_LEDGER = "COST_LEDGER"
    PINNED_FORK_RPC = "PINNED_FORK_RPC"
    CODEQL_DATABASE = "CODEQL_DATABASE"
    DEPENDENCY_SNAPSHOT = "DEPENDENCY_SNAPSHOT"


class ManagedProvisioningAction(StrEnum):
    """Local setup action recorded without implying authority."""

    NONE = "NONE"
    CREATED = "CREATED"
    VERIFIED_EXISTING = "VERIFIED_EXISTING"


class ManagedProvisioningObservationStatus(StrEnum):
    """Outcome of one bounded local observation."""

    NOT_REQUIRED = "NOT_REQUIRED"
    VERIFIED_NONAUTHORIZING = "VERIFIED_NONAUTHORIZING"
    REFUSED = "REFUSED"


class ManagedProvisioningRefusalCode(StrEnum):
    """Closed reasons that cannot contain paths, endpoints, or exception text."""

    MISSING_CONFIGURATION = "MISSING_CONFIGURATION"
    MISSING_INPUT = "MISSING_INPUT"
    INVALID_LOCAL_STATE = "INVALID_LOCAL_STATE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    UNRESOLVED_TOOLCHAIN_ROLE = "UNRESOLVED_TOOLCHAIN_ROLE"
    INSTALLED_TOOLCHAIN_UNVERIFIED = "INSTALLED_TOOLCHAIN_UNVERIFIED"
    UNSUPPORTED_RUNTIME_SURFACE = "UNSUPPORTED_RUNTIME_SURFACE"


_REFUSAL_LIMITATIONS = {
    ManagedProvisioningRefusalCode.MISSING_CONFIGURATION: (
        "Required managed provisioning configuration is absent."
    ),
    ManagedProvisioningRefusalCode.MISSING_INPUT: (
        "Required managed provisioning input is absent."
    ),
    ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE: (
        "Managed provisioning local state failed exact validation."
    ),
    ManagedProvisioningRefusalCode.IDENTITY_MISMATCH: (
        "Managed provisioning input identity differs from the plan."
    ),
    ManagedProvisioningRefusalCode.UNAVAILABLE: (
        "Managed provisioning input cannot be observed by this boundary."
    ),
    ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE: (
        "Required managed toolchain identity is unresolved."
    ),
    ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED: (
        "Installed process identities remain outside this setup receipt."
    ),
    ManagedProvisioningRefusalCode.UNSUPPORTED_RUNTIME_SURFACE: (
        "Provisioning input lacks a current exact local verifier."
    ),
}


class ManagedProvisioningStateStatus(StrEnum):
    """Aggregate state; neither value grants runtime authority."""

    VERIFIED_NONAUTHORIZING = "VERIFIED_NONAUTHORIZING"
    REFUSED_INCOMPLETE = "REFUSED_INCOMPLETE"


class _ValidatedFrozenProvisioningModel(StrictModel):
    """Frozen base whose copy path always re-runs strict validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        del deep
        payload = self.model_dump(mode="python")
        if update is not None:
            payload.update(update)
        return type(self).model_validate(payload, strict=True)


class ManagedProvisioningRequirement(_ValidatedFrozenProvisioningModel):
    """One exact configuration-bound local prerequisite."""

    requirement_id: str = Field(pattern=_REQUIREMENT_ID_PATTERN)
    kind: ManagedProvisioningKind
    required: bool
    config_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    expected_identity_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_path_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_cap_usd_exact: str | None = Field(default=None, pattern=_DECIMAL_PATTERN)

    @field_validator("required", mode="before")
    @classmethod
    def required_is_an_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("managed provisioning required flag must be a boolean")
        return value

    @field_validator(
        "config_binding_sha256",
        "expected_identity_sha256",
        "expected_path_sha256",
    )
    @classmethod
    def requirement_hashes_are_not_sentinels(cls, value: str | None) -> str | None:
        if value == "0" * 64:
            raise ValueError("managed provisioning requirement hash cannot be a sentinel")
        return value

    @model_validator(mode="after")
    def expected_cost_fields_are_scoped(self) -> Self:
        if self.kind is ManagedProvisioningKind.COST_LEDGER:
            if self.expected_cap_usd_exact is None:
                raise ValueError("cost-ledger requirement lacks an exact cap")
        elif self.expected_path_sha256 is not None or self.expected_cap_usd_exact is not None:
            raise ValueError("only a cost-ledger requirement may bind path and cap fields")
        return self


class ManagedProvisioningPlan(_ValidatedFrozenProvisioningModel):
    """Pure setup plan derived from one exact bundle and effective config."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["managed-provisioning-plan"] = "managed-provisioning-plan"
    objective_sha256: Literal[
        "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
    ] = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
    # Preserve v1 receipt identity; only newly derived plans use v2.
    setup_policy_sha256: SetupPolicySha256 = (
        "7d0d9c2a7ded8b955fafb027abdb1bb20e8a25577335dc945e6745c8ab174f19"
    )
    source_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    repository_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    required_roles: tuple[ManagedToolchainRole, ...] = Field(max_length=_MAX_TOOLCHAIN_ROLES)
    unresolved_required_roles: tuple[ManagedToolchainRole, ...] = Field(
        max_length=_MAX_TOOLCHAIN_ROLES
    )
    cost_ledger: ManagedProvisioningRequirement
    codeql: ManagedProvisioningRequirement
    dependency_snapshot: ManagedProvisioningRequirement
    fork_rpcs: tuple[ManagedProvisioningRequirement, ...] = Field(max_length=_MAX_FORK_REQUIREMENTS)
    status: Literal["PLAN_NONAUTHORIZING"] = "PLAN_NONAUTHORIZING"
    independently_trusted: Literal[False]
    installed_members_verified: Literal[False]
    runtime_authority: Literal[False]
    managed_run_ready: Literal[False]
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "independently_trusted",
        "installed_members_verified",
        "runtime_authority",
        "managed_run_ready",
        mode="before",
    )
    @classmethod
    def authority_flags_are_exact_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("managed provisioning plan authority flags must be false")
        return value

    @field_validator(
        "source_bundle_sha256",
        "effective_config_sha256",
        "repository_identity_sha256",
        "plan_sha256",
    )
    @classmethod
    def plan_hashes_are_not_sentinels(cls, value: str) -> str:
        if value == "0" * 64:
            raise ValueError("managed provisioning plan hash cannot be a sentinel")
        return value

    @model_validator(mode="after")
    def plan_is_canonical_and_self_hashed(self) -> Self:
        if self.required_roles != tuple(sorted(set(self.required_roles), key=str)):
            raise ValueError("managed provisioning roles must be unique and sorted")
        if self.unresolved_required_roles != tuple(
            sorted(set(self.unresolved_required_roles), key=str)
        ) or not set(self.unresolved_required_roles).issubset(self.required_roles):
            raise ValueError("managed provisioning unresolved roles are inconsistent")
        fixed = (
            (self.cost_ledger, "cost-ledger", ManagedProvisioningKind.COST_LEDGER, True),
            (self.codeql, "codeql", ManagedProvisioningKind.CODEQL_DATABASE, self.codeql.required),
            (
                self.dependency_snapshot,
                "dependency-snapshot",
                ManagedProvisioningKind.DEPENDENCY_SNAPSHOT,
                self.dependency_snapshot.required,
            ),
        )
        for requirement, identifier, kind, required in fixed:
            if (
                requirement.requirement_id != identifier
                or requirement.kind is not kind
                or requirement.required is not required
            ):
                raise ValueError("managed provisioning fixed requirement is inconsistent")
        fork_ids = tuple(item.requirement_id for item in self.fork_rpcs)
        if fork_ids != tuple(sorted(set(fork_ids))) or any(
            item.kind is not ManagedProvisioningKind.PINNED_FORK_RPC
            or not item.required
            or not item.requirement_id.startswith("fork-rpc-")
            for item in self.fork_rpcs
        ):
            raise ValueError("managed provisioning fork requirements are inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
        if self.plan_sha256 != expected:
            raise ValueError("managed provisioning plan hash is inconsistent")
        return self


class _ObservationBase(_ValidatedFrozenProvisioningModel):
    requirement_id: str = Field(pattern=_REQUIREMENT_ID_PATTERN)
    config_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: ManagedProvisioningObservationStatus
    action: ManagedProvisioningAction
    refusal_code: ManagedProvisioningRefusalCode | None
    limitation: str | None = Field(pattern=_LIMITATION_PATTERN)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("config_binding_sha256", "evidence_sha256")
    @classmethod
    def observation_hashes_are_not_sentinels(cls, value: str) -> str:
        if value == "0" * 64:
            raise ValueError("managed provisioning observation hash cannot be a sentinel")
        return value

    def _validate_common(self, *, kind: ManagedProvisioningKind) -> None:
        if self.status is ManagedProvisioningObservationStatus.NOT_REQUIRED:
            if self.action is not ManagedProvisioningAction.NONE or any(
                value is not None for value in (self.refusal_code, self.limitation)
            ):
                raise ValueError(f"{kind.value} not-required observation carries state")
        elif self.status is ManagedProvisioningObservationStatus.REFUSED:
            if (
                self.action is not ManagedProvisioningAction.NONE
                or self.refusal_code is None
                or self.limitation is None
            ):
                raise ValueError(f"{kind.value} refusal is incomplete")
            if self.limitation != _REFUSAL_LIMITATIONS[self.refusal_code]:
                raise ValueError(f"{kind.value} refusal limitation is not compiled")
        elif self.refusal_code is not None or self.limitation is not None:
            raise ValueError(f"{kind.value} verified observation carries a refusal")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError(f"{kind.value} observation hash is inconsistent")


class CostLedgerProvisioningObservation(_ObservationBase):
    kind: Literal[ManagedProvisioningKind.COST_LEDGER]
    ledger_path_sha256: str | None = Field(pattern=_SHA256_PATTERN)
    provisioning_marker_identity_sha256: str | None = Field(pattern=_SHA256_PATTERN)
    ledger_identity_sha256: str | None = Field(pattern=_SHA256_PATTERN)
    ledger_snapshot_sha256: str | None = Field(pattern=_SHA256_PATTERN)
    cap_usd_exact: str | None = Field(pattern=_DECIMAL_PATTERN)
    entry_count: int | None = Field(ge=0, le=_MAX_LEDGER_ENTRIES)
    active_reservation_count: int | None = Field(ge=0, le=_MAX_LEDGER_ENTRIES)
    portfolio_hold_count: int | None = Field(ge=0, le=_MAX_PORTFOLIO_HOLDS)
    active_portfolio_hold_count: int | None = Field(ge=0, le=1)
    held_portfolio_usd_exact: str | None = Field(pattern=_DECIMAL_PATTERN)

    @field_validator(
        "ledger_path_sha256",
        "provisioning_marker_identity_sha256",
        "ledger_identity_sha256",
        "ledger_snapshot_sha256",
    )
    @classmethod
    def ledger_hashes_are_not_sentinels(cls, value: str | None) -> str | None:
        if value == "0" * 64:
            raise ValueError("managed provisioning ledger hash cannot be a sentinel")
        return value

    @model_validator(mode="after")
    def observation_is_exact(self) -> Self:
        self._validate_common(kind=ManagedProvisioningKind.COST_LEDGER)
        evidence = (
            self.ledger_path_sha256,
            self.provisioning_marker_identity_sha256,
            self.ledger_identity_sha256,
            self.ledger_snapshot_sha256,
            self.cap_usd_exact,
            self.entry_count,
            self.active_reservation_count,
            self.portfolio_hold_count,
            self.active_portfolio_hold_count,
            self.held_portfolio_usd_exact,
        )
        if self.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING:
            if self.action not in {
                ManagedProvisioningAction.CREATED,
                ManagedProvisioningAction.VERIFIED_EXISTING,
            } or any(value is None for value in evidence):
                raise ValueError("verified cost-ledger observation is incomplete")
            if (
                self.active_reservation_count is not None
                and self.entry_count is not None
                and self.active_reservation_count > self.entry_count
            ):
                raise ValueError("active cost reservations exceed ledger entries")
            if (
                self.active_portfolio_hold_count is not None
                and self.portfolio_hold_count is not None
                and self.active_portfolio_hold_count > self.portfolio_hold_count
            ):
                raise ValueError("active portfolio holds exceed ledger holds")
            if self.active_portfolio_hold_count == 0 and self.held_portfolio_usd_exact != "0":
                raise ValueError("inactive portfolio holds cannot retain a held amount")
        elif any(value is not None for value in evidence):
            raise ValueError("unverified cost-ledger observation carries evidence")
        return self

    @classmethod
    def verified(
        cls,
        *,
        requirement_id: str,
        config_binding_sha256: str,
        action: ManagedProvisioningAction,
        ledger_path_sha256: str,
        provisioning_marker_identity_sha256: str,
        ledger_identity_sha256: str,
        ledger_snapshot_sha256: str,
        cap_usd_exact: str,
        entry_count: int,
        active_reservation_count: int,
        portfolio_hold_count: int,
        active_portfolio_hold_count: int,
        held_portfolio_usd_exact: str,
    ) -> CostLedgerProvisioningObservation:
        payload: dict[str, Any] = {
            "kind": ManagedProvisioningKind.COST_LEDGER,
            "requirement_id": requirement_id,
            "config_binding_sha256": config_binding_sha256,
            "status": ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING,
            "action": action,
            "refusal_code": None,
            "limitation": None,
            "ledger_path_sha256": ledger_path_sha256,
            "provisioning_marker_identity_sha256": provisioning_marker_identity_sha256,
            "ledger_identity_sha256": ledger_identity_sha256,
            "ledger_snapshot_sha256": ledger_snapshot_sha256,
            "cap_usd_exact": cap_usd_exact,
            "entry_count": entry_count,
            "active_reservation_count": active_reservation_count,
            "portfolio_hold_count": portfolio_hold_count,
            "active_portfolio_hold_count": active_portfolio_hold_count,
            "held_portfolio_usd_exact": held_portfolio_usd_exact,
        }
        payload["evidence_sha256"] = _canonical_sha256(_json_payload(payload))
        return cls.model_validate(payload)

    @classmethod
    def refused(
        cls,
        requirement: ManagedProvisioningRequirement,
        *,
        code: ManagedProvisioningRefusalCode,
    ) -> CostLedgerProvisioningObservation:
        return cls.model_validate(_refused_payload(requirement, code))


class _SimpleProvisioningObservation(_ObservationBase):
    configured_identity_sha256: str | None = Field(pattern=_SHA256_PATTERN)
    observed_identity_sha256: str | None = Field(pattern=_SHA256_PATTERN)

    def _validate_simple(self, *, kind: ManagedProvisioningKind) -> None:
        self._validate_common(kind=kind)
        if self.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING:
            if (
                self.action is not ManagedProvisioningAction.VERIFIED_EXISTING
                or self.configured_identity_sha256 is None
                or self.observed_identity_sha256 != self.configured_identity_sha256
            ):
                raise ValueError(f"verified {kind.value} identity is inconsistent")
        elif any(
            value is not None
            for value in (self.configured_identity_sha256, self.observed_identity_sha256)
        ):
            raise ValueError(f"unverified {kind.value} observation carries identity")

    @classmethod
    def verified(
        cls,
        requirement: ManagedProvisioningRequirement,
        *,
        observed_identity_sha256: str,
    ) -> Self:
        if not requirement.required or requirement.expected_identity_sha256 is None:
            raise ManagedProvisioningError(
                "managed provisioning verification requires one expected identity"
            )
        payload: dict[str, Any] = {
            "kind": requirement.kind,
            "requirement_id": requirement.requirement_id,
            "config_binding_sha256": requirement.config_binding_sha256,
            "status": ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING,
            "action": ManagedProvisioningAction.VERIFIED_EXISTING,
            "refusal_code": None,
            "limitation": None,
            "configured_identity_sha256": requirement.expected_identity_sha256,
            "observed_identity_sha256": observed_identity_sha256,
        }
        payload["evidence_sha256"] = _canonical_sha256(_json_payload(payload))
        return cls.model_validate(payload)

    @classmethod
    def refused(
        cls,
        requirement: ManagedProvisioningRequirement,
        *,
        code: ManagedProvisioningRefusalCode,
    ) -> Self:
        return cls.model_validate(_simple_payload(requirement, code=code))

    @classmethod
    def not_required(cls, requirement: ManagedProvisioningRequirement) -> Self:
        if requirement.required:
            raise ManagedProvisioningError("required provisioning input cannot be not-required")
        return cls.model_validate(_simple_payload(requirement, code=None))


class ForkRpcProvisioningObservation(_SimpleProvisioningObservation):
    kind: Literal[ManagedProvisioningKind.PINNED_FORK_RPC]

    @model_validator(mode="after")
    def observation_is_exact(self) -> Self:
        self._validate_simple(kind=ManagedProvisioningKind.PINNED_FORK_RPC)
        return self


class CodeQLProvisioningObservation(_SimpleProvisioningObservation):
    kind: Literal[ManagedProvisioningKind.CODEQL_DATABASE]

    @model_validator(mode="after")
    def observation_is_exact(self) -> Self:
        self._validate_simple(kind=ManagedProvisioningKind.CODEQL_DATABASE)
        return self


class DependencySnapshotProvisioningObservation(_SimpleProvisioningObservation):
    kind: Literal[ManagedProvisioningKind.DEPENDENCY_SNAPSHOT]

    @model_validator(mode="after")
    def observation_is_exact(self) -> Self:
        self._validate_simple(kind=ManagedProvisioningKind.DEPENDENCY_SNAPSHOT)
        return self


class ManagedProvisioningObservations(_ValidatedFrozenProvisioningModel):
    """Exact observation set supplied to the pure reducer."""

    cost_ledger: CostLedgerProvisioningObservation
    codeql: CodeQLProvisioningObservation
    dependency_snapshot: DependencySnapshotProvisioningObservation
    fork_rpcs: tuple[ForkRpcProvisioningObservation, ...] = Field(max_length=_MAX_FORK_REQUIREMENTS)

    @model_validator(mode="after")
    def observations_are_canonical(self) -> Self:
        ids = tuple(item.requirement_id for item in self.fork_rpcs)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("managed provisioning fork observations must be unique and sorted")
        return self

    @classmethod
    def refused_for(
        cls,
        plan: ManagedProvisioningPlan,
        *,
        code: ManagedProvisioningRefusalCode,
    ) -> ManagedProvisioningObservations:
        validated = _validate_plan(plan)
        return cls(
            cost_ledger=CostLedgerProvisioningObservation.refused(validated.cost_ledger, code=code),
            codeql=_simple_for_requirement(
                CodeQLProvisioningObservation,
                validated.codeql,
                code=code,
            ),
            dependency_snapshot=_simple_for_requirement(
                DependencySnapshotProvisioningObservation,
                validated.dependency_snapshot,
                code=code,
            ),
            fork_rpcs=tuple(
                _simple_for_requirement(
                    ForkRpcProvisioningObservation,
                    requirement,
                    code=code,
                )
                for requirement in validated.fork_rpcs
            ),
        )


class ManagedProvisioningRefusal(_ValidatedFrozenProvisioningModel):
    requirement_id: str = Field(pattern=_REQUIREMENT_ID_PATTERN)
    code: ManagedProvisioningRefusalCode
    limitation: str = Field(pattern=_LIMITATION_PATTERN)

    @model_validator(mode="after")
    def limitation_is_compiled(self) -> Self:
        if self.limitation != _REFUSAL_LIMITATIONS[self.code]:
            raise ValueError("managed provisioning refusal limitation is not compiled")
        return self


class ManagedProvisioningState(_ValidatedFrozenProvisioningModel):
    """Deterministic setup receipt that is never spend or runtime authority."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["managed-provisioning-state"]
    objective_sha256: Literal["e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"]
    setup_policy_sha256: SetupPolicySha256
    source_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    repository_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    observations: ManagedProvisioningObservations
    verified_requirement_ids: tuple[Annotated[str, Field(pattern=_REQUIREMENT_ID_PATTERN)], ...] = (
        Field(max_length=_MAX_VERIFIED_REQUIREMENTS)
    )
    refusals: tuple[ManagedProvisioningRefusal, ...] = Field(
        min_length=1,
        max_length=_MAX_REFUSALS,
    )
    status: Literal[ManagedProvisioningStateStatus.REFUSED_INCOMPLETE]
    local_checks_recorded: Literal[True]
    self_consistent: Literal[True]
    independently_trusted: Literal[False]
    bundle_trusted: Literal[False]
    installed_members_verified: Literal[False]
    transitive_dependency_closure_verified: Literal[False]
    image_side_attestation_verified: Literal[False]
    provisioning_state_verified: Literal[False]
    execution_evidence_verified: Literal[False]
    spend_admission_evaluated: Literal[False]
    runtime_authority: Literal[False]
    managed_run_ready: Literal[False]
    provider_or_network_accessed: Literal[False]
    repository_content_hashed: Literal[True]
    operator_secret_sources_accessed: Literal[False]
    state_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "local_checks_recorded",
        "self_consistent",
        "repository_content_hashed",
        mode="before",
    )
    @classmethod
    def consistency_flags_are_exact_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("managed provisioning recorded-state flags must be true")
        return value

    @field_validator(
        "source_plan_sha256",
        "source_bundle_sha256",
        "effective_config_sha256",
        "repository_identity_sha256",
        "state_sha256",
    )
    @classmethod
    def state_hashes_are_not_sentinels(cls, value: str) -> str:
        if value == "0" * 64:
            raise ValueError("managed provisioning state hash cannot be a sentinel")
        return value

    @field_validator(
        "independently_trusted",
        "bundle_trusted",
        "installed_members_verified",
        "transitive_dependency_closure_verified",
        "image_side_attestation_verified",
        "provisioning_state_verified",
        "execution_evidence_verified",
        "spend_admission_evaluated",
        "runtime_authority",
        "managed_run_ready",
        "provider_or_network_accessed",
        "operator_secret_sources_accessed",
        mode="before",
    )
    @classmethod
    def security_flags_are_exact_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("managed provisioning security flags must be false")
        return value

    @model_validator(mode="after")
    def state_is_canonical_and_self_hashed(self) -> Self:
        if self.verified_requirement_ids != tuple(sorted(set(self.verified_requirement_ids))):
            raise ValueError("managed provisioning verified IDs must be unique and sorted")
        refusal_ids = tuple(item.requirement_id for item in self.refusals)
        if refusal_ids != tuple(sorted(set(refusal_ids))):
            raise ValueError("managed provisioning refusals must be unique and sorted")
        observations = (
            self.observations.cost_ledger,
            self.observations.codeql,
            self.observations.dependency_snapshot,
            *self.observations.fork_rpcs,
        )
        observation_ids = tuple(item.requirement_id for item in observations)
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("managed provisioning observation IDs must be unique")
        expected_verified_ids = tuple(
            sorted(
                item.requirement_id
                for item in observations
                if item.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING
            )
        )
        if self.verified_requirement_ids != expected_verified_ids:
            raise ValueError("managed provisioning verified IDs differ from observations")
        refusals = {item.requirement_id: item for item in self.refusals}
        for observation in observations:
            refusal = refusals.get(observation.requirement_id)
            if observation.status is ManagedProvisioningObservationStatus.REFUSED:
                if refusal is None or refusal.code is not observation.refusal_code:
                    raise ValueError("managed provisioning refusal differs from observation")
            elif refusal is not None:
                raise ValueError("managed provisioning non-refusal observation has a refusal")
        installation = refusals.get("managed-toolchain-installation")
        if (
            installation is None
            or installation.code
            is not ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED
        ):
            raise ValueError("managed provisioning installation refusal is required")
        observation_id_set = set(observation_ids)
        for refusal in self.refusals:
            if refusal.requirement_id in observation_id_set or refusal is installation:
                continue
            if (
                not refusal.requirement_id.startswith("managed-toolchain-")
                or refusal.code is not ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE
            ):
                raise ValueError("managed provisioning extra refusal is invalid")
        expected_status = (
            ManagedProvisioningStateStatus.REFUSED_INCOMPLETE
            if self.refusals
            else ManagedProvisioningStateStatus.VERIFIED_NONAUTHORIZING
        )
        if self.status is not expected_status:
            raise ValueError("managed provisioning aggregate status is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"state_sha256"}))
        if self.state_sha256 != expected:
            raise ValueError("managed provisioning state hash is inconsistent")
        return self


class ManagedProvisioningReceipt(_ValidatedFrozenProvisioningModel):
    """Self-contained plan/state envelope with no execution or spend authority."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["managed-provisioning-receipt"]
    objective_sha256: Literal["e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"]
    setup_policy_sha256: SetupPolicySha256
    plan: ManagedProvisioningPlan
    state: ManagedProvisioningState
    self_consistent: Literal[True]
    spend_admission_evaluated: Literal[False]
    runtime_authority: Literal[False]
    managed_run_ready: Literal[False]
    provider_or_network_accessed: Literal[False]
    operator_secret_sources_accessed: Literal[False]
    receipt_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("self_consistent", mode="before")
    @classmethod
    def receipt_consistency_is_exact_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("managed provisioning receipt consistency must be true")
        return value

    @field_validator(
        "spend_admission_evaluated",
        "runtime_authority",
        "managed_run_ready",
        "provider_or_network_accessed",
        "operator_secret_sources_accessed",
        mode="before",
    )
    @classmethod
    def receipt_authority_flags_are_exact_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("managed provisioning receipt authority flags must be false")
        return value

    @field_validator("receipt_sha256")
    @classmethod
    def receipt_hash_is_not_a_sentinel(cls, value: str) -> str:
        if value == "0" * 64:
            raise ValueError("managed provisioning receipt hash cannot be a sentinel")
        return value

    @model_validator(mode="after")
    def receipt_is_plan_bound_and_self_hashed(self) -> Self:
        if (
            self.setup_policy_sha256 != self.plan.setup_policy_sha256
            or self.state.setup_policy_sha256 != self.plan.setup_policy_sha256
            or self.state.source_plan_sha256 != self.plan.plan_sha256
            or self.state.source_bundle_sha256 != self.plan.source_bundle_sha256
            or self.state.effective_config_sha256 != self.plan.effective_config_sha256
            or self.state.repository_identity_sha256 != self.plan.repository_identity_sha256
        ):
            raise ValueError("managed provisioning receipt state differs from its plan")
        try:
            verify_managed_provisioning_state(self.plan, self.state)
        except ValueError as exc:
            raise ValueError(
                "managed provisioning receipt state cannot be reproduced from its plan"
            ) from exc
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if self.receipt_sha256 != expected:
            raise ValueError("managed provisioning receipt hash is inconsistent")
        return self


def derive_managed_provisioning_plan(
    bundle: ManagedToolchainBundle,
    config: AuditConfig,
    *,
    repository_identity_sha256: str,
) -> ManagedProvisioningPlan:
    """Derive a complete pure plan without touching host inputs or installed tools."""

    if type(bundle) is not ManagedToolchainBundle or type(config) is not AuditConfig:
        raise ManagedProvisioningError("managed provisioning requires exact compiled inputs")
    if (
        type(repository_identity_sha256) is not str
        or repository_identity_sha256 == "0" * 64
        or re.fullmatch(_SHA256_PATTERN, repository_identity_sha256) is None
    ):
        raise ManagedProvisioningError("managed provisioning repository identity is invalid")
    try:
        validated_bundle, effective, required_roles = preflight_managed_toolchain_config(
            bundle,
            config,
            allow_unresolved=True,
        )
        members = {member.role: member for member in validated_bundle.members}
        unresolved_roles = tuple(
            role
            for role in required_roles
            if members[role].disposition is not ManagedToolchainDisposition.PINNED
        )
        if not unresolved_roles:
            projection = resolve_managed_toolchain_config(validated_bundle, config)
            if (
                projection.source_bundle_sha256 != validated_bundle.bundle_sha256
                or projection.effective_config_sha256 != effective.stable_hash()
                or projection.required_roles != required_roles
            ):
                raise ManagedToolchainError(
                    "managed toolchain resolver projection differs from provisioning inputs"
                )
        budget_usd_exact = _decimal_text(effective.execution.budget_usd)
        if re.fullmatch(_DECIMAL_PATTERN, budget_usd_exact) is None:
            raise ManagedProvisioningError(
                "managed provisioning budget exceeds the exact ledger representation"
            )
    except ManagedProvisioningError:
        raise
    except (ManagedToolchainError, ValueError) as exc:
        raise ManagedProvisioningError(
            "managed provisioning plan inputs cannot be projected exactly"
        ) from exc
    cost_binding = _canonical_sha256(
        {
            "budget_usd": effective.execution.budget_usd,
            "cost_ledger_path_sha256": _optional_text_sha256(effective.execution.cost_ledger_path),
        }
    )
    codeql_required = effective.scanners.codeql.enabled or effective.scanners.codeql.required
    codeql_binding = _canonical_sha256(
        {
            "database_path_sha256": _optional_text_sha256(effective.scanners.codeql.database_path),
            "query_suite_sha256": _optional_text_sha256(effective.scanners.codeql.query_suite),
            "required": codeql_required,
        }
    )
    dependency = effective.dependency_preparation
    dependency_required = dependency.enabled or dependency.required
    dependency_binding = _canonical_sha256(
        {
            "snapshot_path_sha256": _optional_text_sha256(dependency.offline_snapshot_path),
            "expected_snapshot_sha256": dependency.offline_snapshot_sha256,
            "required": dependency_required,
        }
    )
    fork_requirements: list[ManagedProvisioningRequirement] = []
    solidity = effective.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
    main_fork_required = (
        solidity
        and effective.smart_contracts.enabled
        and (
            effective.reproduction.enabled
            or effective.scanners.foundry_fork.enabled
            or effective.scanners.hardhat_fork.enabled
            or effective.smart_contracts.allow_fork_probing
        )
    )
    if main_fork_required:
        expected = (
            _canonical_sha256(
                {
                    "expected_chain_id": effective.reproduction.expected_chain_id,
                    "pinned_block_number": effective.reproduction.pinned_block_number,
                }
            )
            if effective.reproduction.expected_chain_id is not None
            and effective.reproduction.pinned_block_number is not None
            else None
        )
        fork_requirements.append(
            _requirement(
                requirement_id="fork-rpc-primary",
                kind=ManagedProvisioningKind.PINNED_FORK_RPC,
                required=True,
                binding={
                    "environment_name": effective.smart_contracts.fork_rpc_url_env,
                    "expected_chain_id": effective.reproduction.expected_chain_id,
                    "pinned_block_number": effective.reproduction.pinned_block_number,
                },
                expected_identity_sha256=expected,
            )
        )
    for state in effective.smart_contracts.repository_suite.fork_matrix_states:
        if isinstance(state, RepositoryPinnedForkMatrixStateConfig):
            fork_requirements.append(
                _requirement(
                    requirement_id=f"fork-rpc-matrix-{state.state_id}",
                    kind=ManagedProvisioningKind.PINNED_FORK_RPC,
                    required=True,
                    binding=state.model_dump(mode="json"),
                    expected_identity_sha256=state.state_source_sha256,
                )
            )
    fork_requirements.sort(key=lambda item: item.requirement_id)
    payload: dict[str, Any] = {
        "schema_version": MANAGED_PROVISIONING_SCHEMA_VERSION,
        "artifact_kind": "managed-provisioning-plan",
        "objective_sha256": MANAGED_PROVISIONING_OBJECTIVE_SHA256,
        "setup_policy_sha256": MANAGED_PROVISIONING_POLICY_SHA256,
        "source_bundle_sha256": validated_bundle.bundle_sha256,
        "effective_config_sha256": effective.stable_hash(),
        "repository_identity_sha256": repository_identity_sha256,
        "required_roles": [role.value for role in required_roles],
        "unresolved_required_roles": [role.value for role in unresolved_roles],
        "cost_ledger": _requirement(
            requirement_id="cost-ledger",
            kind=ManagedProvisioningKind.COST_LEDGER,
            required=True,
            binding=cost_binding,
            expected_path_sha256=_optional_text_sha256(effective.execution.cost_ledger_path),
            expected_cap_usd_exact=budget_usd_exact,
        ).model_dump(mode="json"),
        "codeql": _requirement(
            requirement_id="codeql",
            kind=ManagedProvisioningKind.CODEQL_DATABASE,
            required=codeql_required,
            binding=codeql_binding,
        ).model_dump(mode="json"),
        "dependency_snapshot": _requirement(
            requirement_id="dependency-snapshot",
            kind=ManagedProvisioningKind.DEPENDENCY_SNAPSHOT,
            required=dependency_required,
            binding=dependency_binding,
            expected_identity_sha256=dependency.offline_snapshot_sha256,
        ).model_dump(mode="json"),
        "fork_rpcs": [item.model_dump(mode="json") for item in fork_requirements],
        "status": "PLAN_NONAUTHORIZING",
        "independently_trusted": False,
        "installed_members_verified": False,
        "runtime_authority": False,
        "managed_run_ready": False,
    }
    payload["plan_sha256"] = _canonical_sha256(payload)
    return ManagedProvisioningPlan.model_validate(payload)


def reduce_managed_provisioning_observations(
    plan: ManagedProvisioningPlan,
    observations: ManagedProvisioningObservations,
) -> ManagedProvisioningState:
    """Reduce exact observations to one deterministic, nonauthorizing receipt."""

    validated_plan = _validate_plan(plan)
    if type(observations) is not ManagedProvisioningObservations:
        raise ManagedProvisioningError(
            "managed provisioning observations must be the exact compiled type"
        )
    validated = ManagedProvisioningObservations.model_validate_json(
        observations.model_dump_json(), strict=True
    )
    if len(validated_plan.fork_rpcs) != len(validated.fork_rpcs):
        raise ManagedProvisioningError("managed provisioning fork observation set differs")
    expected = (
        (validated_plan.cost_ledger, validated.cost_ledger),
        (validated_plan.codeql, validated.codeql),
        (validated_plan.dependency_snapshot, validated.dependency_snapshot),
        *tuple(zip(validated_plan.fork_rpcs, validated.fork_rpcs, strict=True)),
    )
    verified_ids: list[str] = []
    refusals: list[ManagedProvisioningRefusal] = []
    for requirement, observation in expected:
        if (
            observation.requirement_id != requirement.requirement_id
            or observation.config_binding_sha256 != requirement.config_binding_sha256
        ):
            raise ManagedProvisioningError("managed provisioning observation differs from plan")
        if not requirement.required:
            if observation.status is not ManagedProvisioningObservationStatus.NOT_REQUIRED:
                raise ManagedProvisioningError("optional provisioning input must be not required")
            continue
        if observation.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING:
            if isinstance(observation, CostLedgerProvisioningObservation):
                if (
                    observation.ledger_path_sha256 != requirement.expected_path_sha256
                    or observation.cap_usd_exact != requirement.expected_cap_usd_exact
                ):
                    raise ManagedProvisioningError(
                        "managed provisioning cost ledger differs from plan"
                    )
            elif isinstance(observation, _SimpleProvisioningObservation) and (
                requirement.expected_identity_sha256 is None
                or observation.configured_identity_sha256 != requirement.expected_identity_sha256
            ):
                raise ManagedProvisioningError(
                    "managed provisioning observed identity differs from plan"
                )
            verified_ids.append(requirement.requirement_id)
        elif observation.status is ManagedProvisioningObservationStatus.REFUSED:
            assert observation.refusal_code is not None
            assert observation.limitation is not None
            refusals.append(
                ManagedProvisioningRefusal(
                    requirement_id=requirement.requirement_id,
                    code=observation.refusal_code,
                    limitation=_REFUSAL_LIMITATIONS[observation.refusal_code],
                )
            )
        else:
            raise ManagedProvisioningError("required provisioning input was not observed")
    for role in validated_plan.unresolved_required_roles:
        refusals.append(
            ManagedProvisioningRefusal(
                requirement_id=f"managed-toolchain-{role.value}",
                code=ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE,
                limitation=_REFUSAL_LIMITATIONS[
                    ManagedProvisioningRefusalCode.UNRESOLVED_TOOLCHAIN_ROLE
                ],
            )
        )
    refusals.append(
        ManagedProvisioningRefusal(
            requirement_id="managed-toolchain-installation",
            code=ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED,
            limitation=_REFUSAL_LIMITATIONS[
                ManagedProvisioningRefusalCode.INSTALLED_TOOLCHAIN_UNVERIFIED
            ],
        )
    )
    refusals.sort(key=lambda item: (item.requirement_id, item.code.value))
    payload: dict[str, Any] = {
        "schema_version": MANAGED_PROVISIONING_SCHEMA_VERSION,
        "artifact_kind": "managed-provisioning-state",
        "objective_sha256": MANAGED_PROVISIONING_OBJECTIVE_SHA256,
        "setup_policy_sha256": validated_plan.setup_policy_sha256,
        "source_plan_sha256": validated_plan.plan_sha256,
        "source_bundle_sha256": validated_plan.source_bundle_sha256,
        "effective_config_sha256": validated_plan.effective_config_sha256,
        "repository_identity_sha256": validated_plan.repository_identity_sha256,
        "observations": validated.model_dump(mode="json"),
        "verified_requirement_ids": sorted(set(verified_ids)),
        "refusals": [item.model_dump(mode="json") for item in refusals],
        "status": "REFUSED_INCOMPLETE",
        "local_checks_recorded": True,
        "self_consistent": True,
        "independently_trusted": False,
        "bundle_trusted": False,
        "installed_members_verified": False,
        "transitive_dependency_closure_verified": False,
        "image_side_attestation_verified": False,
        "provisioning_state_verified": False,
        "execution_evidence_verified": False,
        "spend_admission_evaluated": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "provider_or_network_accessed": False,
        "repository_content_hashed": True,
        "operator_secret_sources_accessed": False,
    }
    payload["state_sha256"] = _canonical_sha256(payload)
    return ManagedProvisioningState.model_validate(payload)


def verify_managed_provisioning_state(
    plan: ManagedProvisioningPlan,
    state: ManagedProvisioningState,
) -> ManagedProvisioningState:
    """Strictly revalidate and reproduce one receipt from its bound plan."""

    validated_plan = _validate_plan(plan)
    if type(state) is not ManagedProvisioningState:
        raise ManagedProvisioningError("managed provisioning state must be the exact compiled type")
    validated = ManagedProvisioningState.model_validate_json(state.model_dump_json(), strict=True)
    if validated.source_plan_sha256 != validated_plan.plan_sha256:
        raise ManagedProvisioningError("managed provisioning state differs from its plan")
    reproduced = reduce_managed_provisioning_observations(validated_plan, validated.observations)
    if reproduced != validated:
        raise ManagedProvisioningError("managed provisioning state cannot be reproduced")
    return validated


def build_managed_provisioning_receipt(
    plan: ManagedProvisioningPlan,
    state: ManagedProvisioningState,
) -> ManagedProvisioningReceipt:
    """Build one self-contained, reproducible plan/state envelope."""

    validated_plan = _validate_plan(plan)
    validated_state = verify_managed_provisioning_state(validated_plan, state)
    payload: dict[str, Any] = {
        "schema_version": MANAGED_PROVISIONING_SCHEMA_VERSION,
        "artifact_kind": "managed-provisioning-receipt",
        "objective_sha256": MANAGED_PROVISIONING_OBJECTIVE_SHA256,
        "setup_policy_sha256": validated_plan.setup_policy_sha256,
        "plan": validated_plan.model_dump(mode="json"),
        "state": validated_state.model_dump(mode="json"),
        "self_consistent": True,
        "spend_admission_evaluated": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "provider_or_network_accessed": False,
        "operator_secret_sources_accessed": False,
    }
    payload["receipt_sha256"] = _canonical_sha256(payload)
    return ManagedProvisioningReceipt.model_validate(payload)


def verify_managed_provisioning_receipt(
    receipt: ManagedProvisioningReceipt,
) -> ManagedProvisioningReceipt:
    """Strictly reproduce a self-contained receipt without external inputs."""

    if type(receipt) is not ManagedProvisioningReceipt:
        raise ManagedProvisioningError(
            "managed provisioning receipt must be the exact compiled type"
        )
    return ManagedProvisioningReceipt.model_validate_json(
        receipt.model_dump_json(),
        strict=True,
    )


def render_managed_provisioning_state(state: ManagedProvisioningState) -> str:
    """Render exact canonical bytes after strict validation."""

    if type(state) is not ManagedProvisioningState:
        raise ManagedProvisioningError("managed provisioning state must be the exact compiled type")
    validated = ManagedProvisioningState.model_validate_json(state.model_dump_json(), strict=True)
    return (
        json.dumps(
            validated.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_managed_provisioning_state(content: bytes | str) -> ManagedProvisioningState:
    """Structurally parse one bounded canonical receipt without granting plan authority."""

    if type(content) is str:
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ManagedProvisioningError("managed provisioning state is not valid UTF-8") from exc
    elif type(content) is bytes:
        raw = content
    else:
        raise ManagedProvisioningError("managed provisioning state input type is invalid")
    if not raw or len(raw) > MAX_MANAGED_PROVISIONING_STATE_BYTES:
        raise ManagedProvisioningError("managed provisioning state exceeds its input bound")
    _strict_json_object(raw)
    try:
        state = ManagedProvisioningState.model_validate_json(raw, strict=True)
    except ValueError as exc:
        raise ManagedProvisioningError("managed provisioning state is invalid") from exc
    if render_managed_provisioning_state(state).encode("utf-8") != raw:
        raise ManagedProvisioningError("managed provisioning state bytes are not canonical")
    return state


def parse_and_verify_managed_provisioning_state(
    plan: ManagedProvisioningPlan,
    content: bytes | str,
) -> ManagedProvisioningState:
    """Parse canonical bytes and reproduce them against the exact source plan."""

    return verify_managed_provisioning_state(plan, parse_managed_provisioning_state(content))


def render_managed_provisioning_receipt(receipt: ManagedProvisioningReceipt) -> str:
    """Render one strictly reproduced self-contained receipt as canonical bytes."""

    validated = verify_managed_provisioning_receipt(receipt)
    return (
        json.dumps(
            validated.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_managed_provisioning_receipt(content: bytes | str) -> ManagedProvisioningReceipt:
    """Parse and reproduce one bounded canonical self-contained receipt."""

    if type(content) is str:
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ManagedProvisioningError(
                "managed provisioning receipt is not valid UTF-8"
            ) from exc
    elif type(content) is bytes:
        raw = content
    else:
        raise ManagedProvisioningError("managed provisioning receipt input type is invalid")
    if not raw or len(raw) > MAX_MANAGED_PROVISIONING_RECEIPT_BYTES:
        raise ManagedProvisioningError("managed provisioning receipt exceeds its input bound")
    _strict_json_object(raw)
    try:
        receipt = ManagedProvisioningReceipt.model_validate_json(raw, strict=True)
    except ValueError as exc:
        raise ManagedProvisioningError("managed provisioning receipt is invalid") from exc
    if render_managed_provisioning_receipt(receipt).encode("utf-8") != raw:
        raise ManagedProvisioningError("managed provisioning receipt bytes are not canonical")
    return receipt


def _simple_for_requirement[SimpleObservationT: _SimpleProvisioningObservation](
    model: type[SimpleObservationT],
    requirement: ManagedProvisioningRequirement,
    *,
    code: ManagedProvisioningRefusalCode,
) -> SimpleObservationT:
    if not requirement.required:
        return model.not_required(requirement)
    return model.refused(requirement, code=code)


def _refused_payload(
    requirement: ManagedProvisioningRequirement,
    code: ManagedProvisioningRefusalCode,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": ManagedProvisioningKind.COST_LEDGER,
        "requirement_id": requirement.requirement_id,
        "config_binding_sha256": requirement.config_binding_sha256,
        "status": ManagedProvisioningObservationStatus.REFUSED,
        "action": ManagedProvisioningAction.NONE,
        "refusal_code": code,
        "limitation": _REFUSAL_LIMITATIONS[code],
        "ledger_path_sha256": None,
        "provisioning_marker_identity_sha256": None,
        "ledger_identity_sha256": None,
        "ledger_snapshot_sha256": None,
        "cap_usd_exact": None,
        "entry_count": None,
        "active_reservation_count": None,
        "portfolio_hold_count": None,
        "active_portfolio_hold_count": None,
        "held_portfolio_usd_exact": None,
    }
    payload["evidence_sha256"] = _canonical_sha256(_json_payload(payload))
    return cast(dict[str, object], payload)


def _simple_payload(
    requirement: ManagedProvisioningRequirement,
    *,
    code: ManagedProvisioningRefusalCode | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": requirement.kind,
        "requirement_id": requirement.requirement_id,
        "config_binding_sha256": requirement.config_binding_sha256,
        "status": (
            ManagedProvisioningObservationStatus.NOT_REQUIRED
            if code is None
            else ManagedProvisioningObservationStatus.REFUSED
        ),
        "action": ManagedProvisioningAction.NONE,
        "refusal_code": code,
        "limitation": None if code is None else _REFUSAL_LIMITATIONS[code],
        "configured_identity_sha256": None,
        "observed_identity_sha256": None,
    }
    payload["evidence_sha256"] = _canonical_sha256(_json_payload(payload))
    return payload


def _requirement(
    *,
    requirement_id: str,
    kind: ManagedProvisioningKind,
    required: bool,
    binding: object,
    expected_identity_sha256: str | None = None,
    expected_path_sha256: str | None = None,
    expected_cap_usd_exact: str | None = None,
) -> ManagedProvisioningRequirement:
    binding_sha256 = (
        binding
        if isinstance(binding, str) and re.fullmatch(_SHA256_PATTERN, binding)
        else _canonical_sha256(binding)
    )
    return ManagedProvisioningRequirement(
        requirement_id=requirement_id,
        kind=kind,
        required=required,
        config_binding_sha256=binding_sha256,
        expected_identity_sha256=expected_identity_sha256,
        expected_path_sha256=expected_path_sha256,
        expected_cap_usd_exact=expected_cap_usd_exact,
    )


def _validate_plan(plan: ManagedProvisioningPlan) -> ManagedProvisioningPlan:
    if type(plan) is not ManagedProvisioningPlan:
        raise ManagedProvisioningError("managed provisioning plan must be the exact compiled type")
    return ManagedProvisioningPlan.model_validate_json(plan.model_dump_json(), strict=True)


def _optional_text_sha256(value: str | None) -> str | None:
    return None if value is None else hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decimal_text(value: int | float | Decimal) -> str:
    rendered = format(Decimal(str(value)), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _json_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(json.dumps(value, default=str)))


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _strict_json_object(content: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ManagedProvisioningError("managed provisioning JSON contains a duplicate key")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ManagedProvisioningError(
            f"managed provisioning JSON contains non-finite value {value}"
        )

    try:
        decoded = content.decode("utf-8", errors="strict")
        payload = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedProvisioningError("managed provisioning state is not strict JSON") from exc
    if not isinstance(payload, dict):
        raise ManagedProvisioningError("managed provisioning state must be one JSON object")
    return cast(dict[str, object], payload)
