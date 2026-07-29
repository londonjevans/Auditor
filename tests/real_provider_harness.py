"""Fail-closed environment gate for explicitly paid provider tests."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.generation_evidence import (
    EVENTUAL_GENERATION_USAGE_MISMATCH_CODES,
    MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS,
    GenerationReconciliationMismatchCode,
    OpenRouterGenerationEvidence,
)
from mmaudit.models.identity import (
    OpenRouterIdentityBindingResult,
    OpenRouterIdentityDiagnosticCode,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json

REAL_PROVIDER_OPT_IN = "MMAUDIT_RUN_REAL_PROVIDER_TESTS"
REAL_PROVIDER_SECRET_FILE = "MMAUDIT_SECRETS_ENV_FILE"
REAL_PROVIDER_COST_CAP = "MMAUDIT_REAL_PROVIDER_COST_CAP_USD"
REAL_PROVIDER_COST_LEDGER = "MMAUDIT_OPENROUTER_COST_LEDGER"
REAL_PROVIDER_MODEL = "MMAUDIT_REAL_PROVIDER_MODEL_ID"
REAL_PROVIDER_MODEL_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_MODEL_ALLOWLIST"
REAL_PROVIDER_ENDPOINT_ALLOWLIST = "MMAUDIT_REAL_PROVIDER_ENDPOINT_ALLOWLIST"
REAL_PROVIDER_PRIVACY_PROFILE = "MMAUDIT_REAL_PROVIDER_PRIVACY_PROFILE"
REAL_PROVIDER_EVIDENCE_OUTPUT = "MMAUDIT_REAL_PROVIDER_EVIDENCE_OUTPUT"

_MAX_REMEDIATION_BUDGET_USD = Decimal("250.00")
_MONEY_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?\Z")
_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PROVIDER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_NON_EXACT_MODEL_NAMES = frozenset({"auto", "free", "latest", "random"})
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SAFE_GENERATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$"
SMOKE_FIXTURE_PATH = "tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"
SMOKE_FIXTURE_SHA256 = "bbb0127919f734caedffb6f9143a634b6925ff4451985d1410a47e1637f1517b"
SMOKE_MAX_OUTPUT_TOKENS: Literal[1024] = 1_024
SMOKE_REASONING_EFFORT: Literal["none"] = "none"
_PLACEHOLDER_TOKENS = frozenset(
    {"alpha", "dummy", "example", "fake", "placeholder", "synthetic", "test", "vendor"}
)


class RealProviderTestConfigurationError(ValueError):
    """Raised before secret loading or network access when opt-in is incomplete."""


@dataclass(frozen=True)
class RealProviderTestSettings:
    """Validated, non-secret settings for one exact paid provider smoke request."""

    secret_file: Path
    cost_ledger: Path
    cost_cap_usd: Decimal
    model_id: str
    model_allowlist: tuple[str, ...]
    provider_endpoint_allowlist: tuple[str, ...]
    privacy_profile: Literal["STRICT_ZDR"]
    evidence_output: Path


@dataclass(frozen=True)
class RealProviderSmokeReasoningCapabilities:
    """Validated catalog controls required to disable optional smoke reasoning."""

    mandatory: Literal[False]
    default_enabled: bool
    supports_max_tokens: bool


class SyntheticProviderSmokeResponse(BaseModel):
    """Strict minimal response used only for synthetic provider transport validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["OK"]
    marker: Literal["mmaudit-synthetic-provider-smoke-v1"]


def real_provider_smoke_verification_subject_sha256(
    *,
    fixture_sha256: str,
    internal_request_id: str,
    openrouter_generation_id: str,
    requested_model_id: str,
    canonical_model_id: str,
    validated_response_sha256: str,
    prompt_sha256: str,
    schema_sha256: str,
    endpoint_snapshot_sha256: str,
    discovery_evidence_sha256: str,
) -> str:
    """Bind generation verification to the exact non-secret smoke result."""

    hash_values = (
        fixture_sha256,
        validated_response_sha256,
        prompt_sha256,
        schema_sha256,
        endpoint_snapshot_sha256,
        discovery_evidence_sha256,
    )
    if any(re.fullmatch(_SHA256_PATTERN, value) is None for value in hash_values):
        raise ValueError("smoke verification subject requires complete SHA-256 bindings")
    if re.fullmatch(_SAFE_REQUEST_ID_PATTERN, internal_request_id) is None:
        raise ValueError("smoke verification subject request ID is invalid")
    if re.fullmatch(_SAFE_GENERATION_ID_PATTERN, openrouter_generation_id) is None:
        raise ValueError("smoke verification subject generation ID is invalid")
    if any(
        _MODEL_PATTERN.fullmatch(value) is None
        for value in (requested_model_id, canonical_model_id)
    ):
        raise ValueError("smoke verification subject model ID is invalid")
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "ticket_id": "V3-SMOKE-001",
            "fixture_sha256": fixture_sha256,
            "internal_request_id": internal_request_id,
            "openrouter_generation_id": openrouter_generation_id,
            "requested_model_id": requested_model_id,
            "canonical_model_id": canonical_model_id,
            "validated_response_sha256": validated_response_sha256,
            "prompt_sha256": prompt_sha256,
            "schema_sha256": schema_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "discovery_evidence_sha256": discovery_evidence_sha256,
        }
    )


class _RealProviderSmokeEvidenceBody(BaseModel):
    """Bounded non-secret facts required to credit the real synthetic smoke."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    ticket_id: Literal["V3-SMOKE-001"]
    evidence_kind: Literal["real_openrouter_synthetic_smoke"]
    status: Literal["SUCCESS"]
    execution_evidence: Literal["real"]
    fixture_path: Literal["tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"]
    fixture_sha256: str = Field(pattern=_SHA256_PATTERN)
    internal_request_id: str = Field(pattern=_SAFE_REQUEST_ID_PATTERN)
    openrouter_generation_id: str = Field(pattern=_SAFE_GENERATION_ID_PATTERN)
    requested_model_id: str
    canonical_model_id: str
    returned_model_id: str
    generation_model_id: str
    approved_provider_endpoint: str
    actual_provider_endpoint: str
    actual_provider_name: str = Field(min_length=1, max_length=128)
    provider_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    started_at: datetime
    ended_at: datetime
    latency_ms: int = Field(ge=0)
    finish_reason: Literal["stop"]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    cached_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    requested_max_output_tokens: Literal[1024]
    requested_reasoning_effort: Literal["none"]
    requested_reasoning_excluded: Literal[True]
    model_reasoning_mandatory: Literal[False]
    model_reasoning_default_enabled: bool
    model_reasoning_supports_max_tokens: bool
    actual_cost_usd: str
    accounted_cost_usd: str
    ledger_cap_usd: str
    ledger_spent_before_usd: str
    ledger_spent_usd: str
    smoke_spend_delta_usd: str
    ledger_active_reserved_usd: Literal["0"]
    ledger_remaining_usd: str
    validation_status: Literal["valid"]
    identity_strength: ModelIdentityStrength
    privacy_profile: Literal["STRICT_ZDR"]
    require_zdr: Literal[True]
    data_collection: Literal["deny"]
    allow_fallbacks: Literal[False]
    fallback_used: Literal[False]
    substitution_detected: Literal[False]
    raw_prompts_stored: Literal[False]
    raw_responses_stored: Literal[False]
    validated_output: SyntheticProviderSmokeResponse

    @field_validator(
        "requested_model_id",
        "canonical_model_id",
        "returned_model_id",
        "generation_model_id",
    )
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        if _MODEL_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke evidence model ID must be exact")
        return value

    @field_validator("approved_provider_endpoint", "actual_provider_endpoint")
    @classmethod
    def provider_endpoints_are_safe(cls, value: str) -> str:
        if _PROVIDER_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke evidence provider endpoint is invalid")
        return value

    @field_validator("actual_provider_name")
    @classmethod
    def provider_name_is_canonical(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("smoke evidence provider name is invalid")
        return value

    @field_validator(
        "actual_cost_usd",
        "accounted_cost_usd",
        "ledger_cap_usd",
        "ledger_spent_before_usd",
        "ledger_spent_usd",
        "smoke_spend_delta_usd",
        "ledger_active_reserved_usd",
        "ledger_remaining_usd",
    )
    @classmethod
    def money_is_canonical(cls, value: str) -> str:
        if _canonical_nonnegative_decimal(value) != value:
            raise ValueError("smoke evidence cost must be a canonical non-negative decimal")
        return value

    @model_validator(mode="after")
    def evidence_is_coherent(self) -> Self:
        if self.fixture_sha256 != SMOKE_FIXTURE_SHA256:
            raise ValueError("smoke fixture hash differs from the committed pinned fixture")
        aliases = {self.requested_model_id, self.canonical_model_id}
        if self.requested_model_id.split("/", 1)[0] != self.canonical_model_id.split("/", 1)[0]:
            raise ValueError("requested and canonical smoke models have different authors")
        if self.returned_model_id not in aliases:
            raise ValueError("returned smoke model is outside the frozen alias pair")
        if self.generation_model_id not in aliases:
            raise ValueError("generation model is outside the frozen alias pair")
        if self.actual_provider_endpoint != self.approved_provider_endpoint:
            raise ValueError("actual provider endpoint differs from the approved route")
        if self.identity_strength not in {
            ModelIdentityStrength.IMMUTABLE_VERSION_BOUND,
            ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND,
        }:
            raise ValueError("identity_strength must be bound before smoke credit")
        expected_subject = real_provider_smoke_verification_subject_sha256(
            fixture_sha256=self.fixture_sha256,
            internal_request_id=self.internal_request_id,
            openrouter_generation_id=self.openrouter_generation_id,
            requested_model_id=self.requested_model_id,
            canonical_model_id=self.canonical_model_id,
            validated_response_sha256=self.validated_response_sha256,
            prompt_sha256=self.prompt_sha256,
            schema_sha256=self.schema_sha256,
            endpoint_snapshot_sha256=self.endpoint_snapshot_sha256,
            discovery_evidence_sha256=self.discovery_evidence_sha256,
        )
        if self.verification_subject_sha256 != expected_subject:
            raise ValueError("smoke verification subject hash is inconsistent")
        if self.ended_at < self.started_at:
            raise ValueError("smoke request ended before it started")
        if self.reasoning_tokens != 0:
            raise ValueError("smoke reasoning was not disabled as requested")
        if self.reasoning_tokens > self.completion_tokens:
            raise ValueError("smoke reasoning tokens exceed completion tokens")
        if self.completion_tokens > self.requested_max_output_tokens:
            raise ValueError("smoke completion tokens exceed the requested output ceiling")
        if self.cached_tokens > self.prompt_tokens:
            raise ValueError("smoke cached tokens exceed prompt tokens")
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("smoke total tokens do not reconcile")
        actual = Decimal(self.actual_cost_usd)
        accounted = Decimal(self.accounted_cost_usd)
        cap = Decimal(self.ledger_cap_usd)
        spent_before = Decimal(self.ledger_spent_before_usd)
        spent = Decimal(self.ledger_spent_usd)
        spend_delta = Decimal(self.smoke_spend_delta_usd)
        remaining = Decimal(self.ledger_remaining_usd)
        if accounted < actual:
            raise ValueError("smoke accounted cost is below actual cost")
        if spent < accounted:
            raise ValueError("ledger spent total is below the smoke accounted cost")
        if spent_before + spend_delta != spent or spend_delta != accounted:
            raise ValueError("smoke ledger spend delta does not reconcile")
        if spend_delta > Decimal("5"):
            raise ValueError("smoke spend exceeded its stage cap")
        if spent + remaining != cap:
            raise ValueError("smoke ledger totals do not reconcile")
        return self


class RealProviderSmokeEvidence(_RealProviderSmokeEvidenceBody):
    """Self-hashed successful real-provider smoke artifact."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("smoke evidence self-hash is inconsistent")
        return self


class _RealProviderSmokeRejectionEvidenceBody(BaseModel):
    """Bounded non-secret facts for one schema-valid but unbound smoke response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    ticket_id: Literal["V3-SMOKE-001"]
    evidence_kind: Literal["real_openrouter_synthetic_smoke_rejection"]
    status: Literal["REJECTED_IDENTITY_UNBOUND"]
    creditable: Literal[False]
    execution_evidence: Literal["real"]
    fixture_path: Literal["tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"]
    fixture_sha256: str = Field(pattern=_SHA256_PATTERN)
    internal_request_id: str = Field(pattern=_SAFE_REQUEST_ID_PATTERN)
    openrouter_generation_id: str = Field(pattern=_SAFE_GENERATION_ID_PATTERN)
    requested_model_id: str
    canonical_model_id: str
    returned_model_id: str
    selected_model_id: str
    approved_provider_endpoint: str
    actual_provider_endpoint: str
    selected_provider_identity: str = Field(min_length=1, max_length=128)
    selected_provider_name: str = Field(min_length=1, max_length=128)
    response_provider_identity: str | None = Field(default=None, max_length=128)
    model_identity_control_satisfied: bool
    endpoint_control_satisfied: bool
    provider_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_binding_status: Literal["generation_metadata_unbound"]
    identity_diagnostic_codes: tuple[OpenRouterIdentityDiagnosticCode, ...] = Field(
        min_length=1,
        max_length=32,
    )
    generation_observation: OpenRouterGenerationEvidence | None = None
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    started_at: datetime
    ended_at: datetime
    latency_ms: int = Field(ge=0)
    finish_reason: Literal["stop"]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    cached_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    requested_max_output_tokens: Literal[1024]
    requested_reasoning_effort: Literal["none"]
    requested_reasoning_excluded: Literal[True]
    reasoning_control_satisfied: bool
    output_control_satisfied: bool
    ledger_entry_request_id: str = Field(pattern=_SAFE_REQUEST_ID_PATTERN)
    ledger_entry_status: CostEntryStatus
    reserved_cost_usd: str
    provider_reported_cost_usd: str | None
    actual_cost_usd: str | None
    accounted_cost_usd: str
    cost_reconciled: bool
    ledger_cap_usd: str
    ledger_spent_before_usd: str
    ledger_spent_usd: str
    smoke_spend_delta_usd: str
    ledger_delta_reconciled: bool
    ledger_prior_entries_sha256_before: str = Field(pattern=_SHA256_PATTERN)
    ledger_prior_entries_sha256_after: str = Field(pattern=_SHA256_PATTERN)
    ledger_prior_entries_unchanged: bool
    ledger_active_reserved_usd: str
    ledger_reservations_closed: bool
    ledger_over_cap: bool
    ledger_has_reservation_overrun: bool
    ledger_remaining_usd: str
    stage_cost_control_satisfied: bool
    validation_status: Literal["valid"]
    identity_strength: Literal[ModelIdentityStrength.UNBOUND]
    privacy_profile: Literal["STRICT_ZDR"]
    require_zdr: Literal[True]
    data_collection: Literal["deny"]
    allow_fallbacks: Literal[False]
    fallback_used: Literal[False]
    substitution_detected: Literal[False]
    raw_prompts_stored: Literal[False]
    raw_responses_stored: Literal[False]
    validated_output: SyntheticProviderSmokeResponse

    @field_validator(
        "requested_model_id",
        "canonical_model_id",
        "returned_model_id",
        "selected_model_id",
    )
    @classmethod
    def rejection_model_ids_are_exact(cls, value: str) -> str:
        if _MODEL_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke rejection model ID must be exact")
        return value

    @field_validator("approved_provider_endpoint", "actual_provider_endpoint")
    @classmethod
    def rejection_provider_endpoints_are_safe(cls, value: str) -> str:
        if _PROVIDER_PATTERN.fullmatch(value) is None:
            raise ValueError("smoke rejection provider endpoint is invalid")
        return value

    @field_validator(
        "selected_provider_identity",
        "selected_provider_name",
        "response_provider_identity",
    )
    @classmethod
    def rejection_provider_observations_are_safe(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(not character.isprintable() for character in value)
        ):
            raise ValueError("smoke rejection provider observation is invalid")
        return value

    @field_validator("identity_diagnostic_codes")
    @classmethod
    def rejection_diagnostics_are_sorted_unique(
        cls,
        value: tuple[OpenRouterIdentityDiagnosticCode, ...],
    ) -> tuple[OpenRouterIdentityDiagnosticCode, ...]:
        labels = tuple(item.value for item in value)
        if labels != tuple(sorted(set(labels))):
            raise ValueError("smoke rejection diagnostic codes must be sorted and unique")
        return value

    @field_validator(
        "reserved_cost_usd",
        "accounted_cost_usd",
        "ledger_cap_usd",
        "ledger_spent_before_usd",
        "ledger_spent_usd",
        "smoke_spend_delta_usd",
        "ledger_active_reserved_usd",
        "ledger_remaining_usd",
    )
    @classmethod
    def rejection_money_is_canonical(cls, value: str) -> str:
        if _canonical_nonnegative_decimal(value) != value:
            raise ValueError("smoke rejection cost must be a canonical non-negative decimal")
        return value

    @field_validator("provider_reported_cost_usd", "actual_cost_usd")
    @classmethod
    def optional_rejection_money_is_canonical(cls, value: str | None) -> str | None:
        if value is not None and _canonical_nonnegative_decimal(value) != value:
            raise ValueError("optional smoke rejection cost must be canonical")
        return value

    @model_validator(mode="after")
    def rejection_evidence_is_coherent(self) -> Self:
        if self.fixture_sha256 != SMOKE_FIXTURE_SHA256:
            raise ValueError("smoke rejection fixture differs from the committed pinned fixture")
        aliases = {self.requested_model_id, self.canonical_model_id}
        if self.requested_model_id.split("/", 1)[0] != self.canonical_model_id.split("/", 1)[0]:
            raise ValueError("requested and canonical smoke rejection models differ by author")
        models_satisfied = self.returned_model_id in aliases and self.selected_model_id in aliases
        if self.model_identity_control_satisfied is not models_satisfied:
            raise ValueError("smoke rejection model-control status is inconsistent")
        endpoint_satisfied = self.actual_provider_endpoint == self.approved_provider_endpoint
        if self.endpoint_control_satisfied is not endpoint_satisfied:
            raise ValueError("smoke rejection endpoint-control status is inconsistent")
        if self.ended_at < self.started_at:
            raise ValueError("smoke rejection request ended before it started")
        if self.reasoning_tokens > self.completion_tokens:
            raise ValueError("smoke rejection reasoning tokens exceed completion tokens")
        if self.reasoning_control_satisfied is not (self.reasoning_tokens == 0):
            raise ValueError("smoke rejection reasoning-control status is inconsistent")
        if self.output_control_satisfied is not (
            self.completion_tokens <= self.requested_max_output_tokens
        ):
            raise ValueError("smoke rejection output-control status is inconsistent")
        if self.cached_tokens > self.prompt_tokens:
            raise ValueError("smoke rejection cached tokens exceed prompt tokens")
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("smoke rejection token totals do not reconcile")
        if self.generation_observation is None:
            if (
                OpenRouterIdentityDiagnosticCode.GENERATION_METADATA_MISSING
                not in self.identity_diagnostic_codes
            ):
                raise ValueError(
                    "smoke rejection without generation observation lacks missing-metadata "
                    "diagnostic"
                )
        elif (
            self.generation_observation.execution_evidence is not ExecutionEvidenceKind.REAL
            or self.generation_observation.generation_id != self.openrouter_generation_id
        ):
            raise ValueError("smoke rejection generation observation is not request-bound REAL")
        if self.ledger_entry_request_id != f"{self.internal_request_id}:attempt:1":
            raise ValueError("smoke rejection ledger request ID is not attempt-bound")
        reserved = Decimal(self.reserved_cost_usd)
        provider_reported = (
            None
            if self.provider_reported_cost_usd is None
            else Decimal(self.provider_reported_cost_usd)
        )
        actual = None if self.actual_cost_usd is None else Decimal(self.actual_cost_usd)
        accounted = Decimal(self.accounted_cost_usd)
        cap = Decimal(self.ledger_cap_usd)
        spent_before = Decimal(self.ledger_spent_before_usd)
        spent = Decimal(self.ledger_spent_usd)
        spend_delta = Decimal(self.smoke_spend_delta_usd)
        remaining = Decimal(self.ledger_remaining_usd)
        if self.ledger_entry_status is CostEntryStatus.RECONCILED:
            cost_status_valid = (
                actual is not None
                and provider_reported == actual
                and actual <= reserved
                and accounted == actual
                and self.cost_reconciled
            )
        elif self.ledger_entry_status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
            cost_status_valid = (
                actual is None
                and provider_reported is None
                and accounted == reserved
                and not self.cost_reconciled
            )
        elif self.ledger_entry_status is CostEntryStatus.RESERVATION_OVERRUN:
            cost_status_valid = (
                actual is not None
                and provider_reported == actual
                and actual > reserved
                and accounted == actual
                and not self.cost_reconciled
            )
        else:
            cost_status_valid = False
        if not cost_status_valid:
            raise ValueError("smoke rejection cost lifecycle is inconsistent")
        if spent < accounted:
            raise ValueError("ledger spent total is below the rejection accounted cost")
        if spent_before + spend_delta != spent:
            raise ValueError("smoke rejection ledger spend change is inconsistent")
        if self.ledger_delta_reconciled is not (spend_delta == accounted):
            raise ValueError("smoke rejection ledger-delta status is inconsistent")
        if self.ledger_prior_entries_unchanged is not (
            self.ledger_prior_entries_sha256_before == self.ledger_prior_entries_sha256_after
        ):
            raise ValueError("smoke rejection prior-ledger status is inconsistent")
        if self.ledger_reservations_closed is not (Decimal(self.ledger_active_reserved_usd) == 0):
            raise ValueError("smoke rejection reservation status is inconsistent")
        if self.ledger_over_cap is not (cap - spent - Decimal(self.ledger_active_reserved_usd) < 0):
            raise ValueError("smoke rejection over-cap status is inconsistent")
        if self.ledger_has_reservation_overrun is not (
            self.ledger_entry_status is CostEntryStatus.RESERVATION_OVERRUN
        ):
            raise ValueError("smoke rejection overrun status is inconsistent")
        if self.stage_cost_control_satisfied is not (accounted <= Decimal("5")):
            raise ValueError("smoke rejection stage-cost status is inconsistent")
        if remaining != max(
            Decimal(0),
            cap - spent - Decimal(self.ledger_active_reserved_usd),
        ):
            raise ValueError("smoke rejection ledger totals do not reconcile")
        return self


class RealProviderSmokeRejectionEvidence(_RealProviderSmokeRejectionEvidenceBody):
    """Self-hashed non-creditable evidence for one valid unbound provider response."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def rejection_evidence_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("smoke rejection evidence self-hash is inconsistent")
        return self


class _RealProviderSmokeVerificationRejectionEvidenceBody(BaseModel):
    """Non-creditable evidence for a bound response rejected by fresh verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    ticket_id: Literal["V3-SMOKE-001"]
    evidence_kind: Literal["real_openrouter_synthetic_smoke_verification_rejection"]
    status: Literal["REJECTED_GENERATION_VERIFICATION"]
    creditable: Literal[False]
    fixture_path: Literal["tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol"]
    fixture_sha256: str = Field(pattern=_SHA256_PATTERN)
    canonical_model_id: str
    approved_provider_endpoint: str
    verification_subject_sha256: str = Field(pattern=_SHA256_PATTERN)
    identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_generation_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    mismatch_code: GenerationReconciliationMismatchCode
    reconciliation_attempts: int = Field(
        ge=1,
        le=MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS,
    )
    reconciliation_exhausted: bool
    usage_record: UsageRecord
    ledger_entry_request_id: str = Field(pattern=_SAFE_REQUEST_ID_PATTERN)
    ledger_entry_status: CostEntryStatus
    reserved_cost_usd: str
    actual_cost_usd: str | None
    accounted_cost_usd: str
    cost_reconciled: bool
    ledger_cap_usd: str
    ledger_spent_before_usd: str
    ledger_spent_usd: str
    smoke_spend_delta_usd: str
    ledger_delta_reconciled: bool
    ledger_prior_entries_sha256_before: str = Field(pattern=_SHA256_PATTERN)
    ledger_prior_entries_sha256_after: str = Field(pattern=_SHA256_PATTERN)
    ledger_prior_entries_unchanged: bool
    ledger_active_reserved_usd: str
    ledger_reservations_closed: bool
    ledger_over_cap: bool
    ledger_has_reservation_overrun: bool
    ledger_remaining_usd: str
    stage_cost_control_satisfied: bool
    privacy_profile: Literal["STRICT_ZDR"]
    require_zdr: Literal[True]
    data_collection: Literal["deny"]
    allow_fallbacks: Literal[False]
    raw_prompts_stored: Literal[False]
    raw_responses_stored: Literal[False]
    validated_output: SyntheticProviderSmokeResponse

    @field_validator("canonical_model_id")
    @classmethod
    def verification_rejection_model_is_exact(cls, value: str) -> str:
        if _MODEL_PATTERN.fullmatch(value) is None:
            raise ValueError("verification rejection model ID must be exact")
        return value

    @field_validator("approved_provider_endpoint")
    @classmethod
    def verification_rejection_endpoint_is_safe(cls, value: str) -> str:
        if _PROVIDER_PATTERN.fullmatch(value) is None:
            raise ValueError("verification rejection endpoint is invalid")
        return value

    @field_validator(
        "reserved_cost_usd",
        "accounted_cost_usd",
        "ledger_cap_usd",
        "ledger_spent_before_usd",
        "ledger_spent_usd",
        "smoke_spend_delta_usd",
        "ledger_active_reserved_usd",
        "ledger_remaining_usd",
    )
    @classmethod
    def verification_rejection_money_is_canonical(cls, value: str) -> str:
        if _canonical_nonnegative_decimal(value) != value:
            raise ValueError("verification rejection cost must be canonical")
        return value

    @field_validator("actual_cost_usd")
    @classmethod
    def optional_verification_rejection_money_is_canonical(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None and _canonical_nonnegative_decimal(value) != value:
            raise ValueError("optional verification rejection cost must be canonical")
        return value

    @model_validator(mode="after")
    def verification_rejection_is_coherent(self) -> Self:
        if self.fixture_sha256 != SMOKE_FIXTURE_SHA256:
            raise ValueError("verification rejection fixture differs from the pinned fixture")
        record = self.usage_record
        aliases = {record.requested_model, self.canonical_model_id}
        if (
            record.requested_model.split("/", 1)[0] != self.canonical_model_id.split("/", 1)[0]
            or record.returned_model not in aliases
            or record.actual_model not in aliases
        ):
            raise ValueError("verification rejection model identity is inconsistent")
        if (
            record.execution_evidence is not ExecutionEvidenceKind.REAL
            or record.validation_status is not ModelRequestValidationStatus.VALID
            or record.status != "success"
            or record.identity_strength
            not in {
                ModelIdentityStrength.IMMUTABLE_VERSION_BOUND,
                ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND,
            }
            or record.routing.get("identity_binding_status") != "generation_metadata_bound"
            or record.actual_provider_endpoint != self.approved_provider_endpoint
            or record.fallback_used
            or record.substitution_detected
            or record.finish_reason != "stop"
        ):
            raise ValueError("verification rejection requires one bound valid REAL response")
        raw_binding = record.routing.get("identity_binding")
        try:
            binding = OpenRouterIdentityBindingResult.model_validate(raw_binding)
        except (AttributeError, ValueError):
            raise ValueError("verification rejection identity binding is invalid") from None
        if (
            binding.binding_sha256 != self.identity_binding_sha256
            or binding.strength is not record.identity_strength
            or binding.generation is None
            or binding.generation.generation_id != record.openrouter_generation_id
            or binding.generation.generation_evidence_sha256
            != self.initial_generation_evidence_sha256
        ):
            raise ValueError("verification rejection identity evidence is inconsistent")
        endpoint_snapshot_sha256 = _required_usage_routing_sha256(
            record,
            "endpoint_snapshot_sha256",
        )
        discovery_evidence_sha256 = _required_usage_routing_sha256(
            record,
            "discovery_evidence_sha256",
        )
        if (
            record.openrouter_generation_id is None
            or record.validated_response_sha256 is None
            or record.schema_sha256 is None
            or self.verification_subject_sha256
            != real_provider_smoke_verification_subject_sha256(
                fixture_sha256=self.fixture_sha256,
                internal_request_id=record.request_id,
                openrouter_generation_id=record.openrouter_generation_id,
                requested_model_id=record.requested_model,
                canonical_model_id=self.canonical_model_id,
                validated_response_sha256=record.validated_response_sha256,
                prompt_sha256=record.prompt_sha256,
                schema_sha256=record.schema_sha256,
                endpoint_snapshot_sha256=endpoint_snapshot_sha256,
                discovery_evidence_sha256=discovery_evidence_sha256,
            )
        ):
            raise ValueError("verification rejection subject is inconsistent")
        if self.reconciliation_exhausted is not (
            self.mismatch_code in EVENTUAL_GENERATION_USAGE_MISMATCH_CODES
        ):
            raise ValueError("verification rejection exhaustion status is inconsistent")
        if self.ledger_entry_request_id != f"{record.request_id}:attempt:1":
            raise ValueError("verification rejection ledger request ID is not attempt-bound")
        if record.reasoning_tokens != 0 or record.completion_tokens > SMOKE_MAX_OUTPUT_TOKENS:
            raise ValueError("verification rejection request controls are inconsistent")
        if record.cached_tokens > record.prompt_tokens:
            raise ValueError("verification rejection cached tokens exceed prompt tokens")
        reserved = Decimal(self.reserved_cost_usd)
        actual = None if self.actual_cost_usd is None else Decimal(self.actual_cost_usd)
        accounted = Decimal(self.accounted_cost_usd)
        cap = Decimal(self.ledger_cap_usd)
        spent_before = Decimal(self.ledger_spent_before_usd)
        spent = Decimal(self.ledger_spent_usd)
        spend_delta = Decimal(self.smoke_spend_delta_usd)
        active_reserved = Decimal(self.ledger_active_reserved_usd)
        remaining = Decimal(self.ledger_remaining_usd)
        if self.ledger_entry_status is CostEntryStatus.RECONCILED:
            cost_status_valid = (
                actual is not None
                and record.reported_cost_usd is not None
                and Decimal(str(record.reported_cost_usd)) == actual
                and accounted == actual
                and actual <= reserved
                and self.cost_reconciled
            )
        elif self.ledger_entry_status is CostEntryStatus.RESERVATION_OVERRUN:
            cost_status_valid = (
                actual is not None
                and record.reported_cost_usd is not None
                and Decimal(str(record.reported_cost_usd)) == actual
                and accounted == actual
                and actual > reserved
                and not self.cost_reconciled
            )
        else:
            cost_status_valid = False
        if not cost_status_valid:
            raise ValueError("verification rejection cost lifecycle is inconsistent")
        if (
            spent_before + spend_delta != spent
            or self.ledger_delta_reconciled is not (spend_delta == accounted)
            or self.ledger_prior_entries_unchanged
            is not (
                self.ledger_prior_entries_sha256_before == self.ledger_prior_entries_sha256_after
            )
            or self.ledger_reservations_closed is not (active_reserved == 0)
            or self.ledger_over_cap is not (cap - spent - active_reserved < 0)
            or self.ledger_has_reservation_overrun
            is not (self.ledger_entry_status is CostEntryStatus.RESERVATION_OVERRUN)
            or self.stage_cost_control_satisfied is not (accounted <= Decimal("5"))
            or remaining != max(Decimal(0), cap - spent - active_reserved)
        ):
            raise ValueError("verification rejection ledger evidence is inconsistent")
        return self


class RealProviderSmokeVerificationRejectionEvidence(
    _RealProviderSmokeVerificationRejectionEvidenceBody
):
    """Self-hashed non-creditable post-bind verification rejection."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def verification_rejection_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("verification rejection self-hash is inconsistent")
        return self


def real_provider_tests_enabled(environ: Mapping[str, str]) -> bool:
    """Require the exact opt-in sentinel; truthy alternatives are rejected."""

    return environ.get(REAL_PROVIDER_OPT_IN) == "1"


def load_pinned_synthetic_smoke_fixture(repository_root: Path) -> tuple[str, str]:
    """Read the exact committed smoke fixture without following or sharing links."""

    observed = read_file_evidence(
        evidence_root=repository_root,
        relative_path=SMOKE_FIXTURE_PATH,
        max_bytes=20_000,
    )
    if observed.binding.sha256 != SMOKE_FIXTURE_SHA256:
        raise ValueError("the synthetic provider fixture differs from its pinned hash")
    try:
        source = observed.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("the synthetic provider fixture is not strict UTF-8") from exc
    if not source or "\x00" in source:
        raise ValueError("the synthetic provider fixture is empty or invalid")
    return source, observed.binding.sha256


def validate_smoke_reasoning_off_preflight(
    *,
    models_payload: Any,
    exact_model_id: str,
) -> RealProviderSmokeReasoningCapabilities:
    """Require catalog proof that explicit reasoning disablement is permitted."""

    if _MODEL_PATTERN.fullmatch(exact_model_id) is None:
        raise RealProviderTestConfigurationError("smoke reasoning model ID is invalid")
    if not isinstance(models_payload, dict):
        raise RealProviderTestConfigurationError("smoke model catalog is invalid")
    models = models_payload.get("data")
    if (
        not isinstance(models, list)
        or not models
        or len(models) > 10_000
        or any(not isinstance(item, dict) for item in models)
    ):
        raise RealProviderTestConfigurationError("smoke model catalog is invalid")
    matches = [item for item in models if item.get("id") == exact_model_id]
    if len(matches) != 1:
        raise RealProviderTestConfigurationError(
            "smoke model catalog does not bind exactly one requested model"
        )
    selected = matches[0]
    parameters = selected.get("supported_parameters")
    reasoning = selected.get("reasoning")
    if (
        not isinstance(parameters, list)
        or "reasoning" not in parameters
        or not isinstance(reasoning, dict)
    ):
        raise RealProviderTestConfigurationError(
            "smoke model does not publish reasoning control metadata"
        )
    mandatory = reasoning.get("mandatory")
    default_enabled = reasoning.get("default_enabled")
    supports_max_tokens = reasoning.get("supports_max_tokens", False)
    if (
        mandatory is not False
        or not isinstance(default_enabled, bool)
        or not isinstance(supports_max_tokens, bool)
    ):
        raise RealProviderTestConfigurationError(
            "smoke model cannot prove optional bounded reasoning controls"
        )
    return RealProviderSmokeReasoningCapabilities(
        mandatory=False,
        default_enabled=default_enabled,
        supports_max_tokens=supports_max_tokens,
    )


def load_real_provider_test_settings(
    environ: Mapping[str, str],
) -> RealProviderTestSettings:
    """Validate every non-secret prerequisite before the secret file is opened."""

    if not real_provider_tests_enabled(environ):
        raise RealProviderTestConfigurationError(
            f"paid provider tests require {REAL_PROVIDER_OPT_IN}=1"
        )

    secret_file_text = _required_value(environ, REAL_PROVIDER_SECRET_FILE)
    secret_file = Path(secret_file_text)
    if not secret_file.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_SECRET_FILE} must be an absolute operator-controlled path"
        )

    cost_text = _required_value(environ, REAL_PROVIDER_COST_CAP)
    if not _MONEY_PATTERN.fullmatch(cost_text):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be a plain positive decimal"
        )
    try:
        cost_cap = Decimal(cost_text)
    except InvalidOperation:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be a plain positive decimal"
        ) from None
    if cost_cap <= 0 or cost_cap > _MAX_REMEDIATION_BUDGET_USD:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_CAP} must be greater than zero and at most 250.00"
        )
    cost_ledger = Path(_required_value(environ, REAL_PROVIDER_COST_LEDGER))
    if not cost_ledger.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_COST_LEDGER} must be an absolute operator-controlled path"
        )

    model_allowlist = _parse_allowlist(
        environ,
        REAL_PROVIDER_MODEL_ALLOWLIST,
        validator=_is_exact_non_placeholder_model,
        item_label="exact non-placeholder model ID",
    )
    model_id = _required_value(environ, REAL_PROVIDER_MODEL)
    if not _is_exact_non_placeholder_model(model_id):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_MODEL} must be an exact non-placeholder author/model ID"
        )
    if model_id not in model_allowlist:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_MODEL} must appear in {REAL_PROVIDER_MODEL_ALLOWLIST}"
        )

    provider_allowlist = _parse_allowlist(
        environ,
        REAL_PROVIDER_ENDPOINT_ALLOWLIST,
        validator=_is_exact_non_placeholder_provider,
        item_label="exact non-placeholder provider endpoint",
    )
    if len(provider_allowlist) != 1:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_ENDPOINT_ALLOWLIST} must select exactly one provider endpoint"
        )
    privacy_profile = _required_value(environ, REAL_PROVIDER_PRIVACY_PROFILE)
    if privacy_profile != "STRICT_ZDR":
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_PRIVACY_PROFILE} must be exactly STRICT_ZDR"
        )
    evidence_output = Path(_required_value(environ, REAL_PROVIDER_EVIDENCE_OUTPUT))
    if not evidence_output.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be an absolute output path"
        )
    return RealProviderTestSettings(
        secret_file=secret_file,
        cost_ledger=cost_ledger,
        cost_cap_usd=cost_cap,
        model_id=model_id,
        model_allowlist=model_allowlist,
        provider_endpoint_allowlist=provider_allowlist,
        privacy_profile="STRICT_ZDR",
        evidence_output=evidence_output,
    )


def seal_real_provider_smoke_evidence(
    value: Mapping[str, Any],
) -> RealProviderSmokeEvidence:
    """Validate smoke facts and bind their exact canonical public projection."""

    if "evidence_sha256" in value:
        raise ValueError("smoke evidence must be sealed exactly once")
    body = _RealProviderSmokeEvidenceBody.model_validate(dict(value))
    payload = body.model_dump(mode="json")
    return RealProviderSmokeEvidence.model_validate(
        {
            **payload,
            "evidence_sha256": canonical_sha256(payload),
        }
    )


def seal_real_provider_smoke_rejection_evidence(
    value: Mapping[str, Any],
) -> RealProviderSmokeRejectionEvidence:
    """Validate one non-creditable rejection and bind its canonical public projection."""

    if "evidence_sha256" in value:
        raise ValueError("smoke rejection evidence must be sealed exactly once")
    body = _RealProviderSmokeRejectionEvidenceBody.model_validate(dict(value))
    payload = body.model_dump(mode="json")
    return RealProviderSmokeRejectionEvidence.model_validate(
        {
            **payload,
            "evidence_sha256": canonical_sha256(payload),
        }
    )


def seal_real_provider_smoke_verification_rejection_evidence(
    value: Mapping[str, Any],
) -> RealProviderSmokeVerificationRejectionEvidence:
    """Validate and self-hash one post-bind verification rejection."""

    if "evidence_sha256" in value:
        raise ValueError("verification rejection evidence must be sealed exactly once")
    body = _RealProviderSmokeVerificationRejectionEvidenceBody.model_validate(dict(value))
    payload = body.model_dump(mode="json")
    return RealProviderSmokeVerificationRejectionEvidence.model_validate(
        {
            **payload,
            "evidence_sha256": canonical_sha256(payload),
        }
    )


def preflight_real_provider_smoke_output(
    *,
    output_path: Path,
    forbidden_paths: tuple[Path, ...],
) -> None:
    """Reject unsafe or colliding evidence destinations before provider spend."""

    if not output_path.is_absolute():
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be an absolute fresh JSON file"
        )
    if (
        output_path.suffix != ".json"
        or output_path.name.startswith(("-", "."))
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", output_path.name) is None
    ):
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must name a bounded JSON artifact"
        )
    normalized_output = Path(os.path.abspath(output_path))
    normalized_forbidden = {Path(os.path.abspath(path)) for path in forbidden_paths}
    if normalized_output in normalized_forbidden:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} collides with a protected input"
        )
    current = Path(normalized_output.anchor)
    try:
        for part in normalized_output.parent.parts[1:]:
            current /= part
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or current.is_junction()
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise RealProviderTestConfigurationError(
                    f"{REAL_PROVIDER_EVIDENCE_OUTPUT} traverses an unsafe parent"
                )
    except OSError as exc:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} parent is unavailable"
        ) from exc
    try:
        normalized_output.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RealProviderTestConfigurationError(
            f"{REAL_PROVIDER_EVIDENCE_OUTPUT} could not be checked safely"
        ) from exc
    raise RealProviderTestConfigurationError(
        f"{REAL_PROVIDER_EVIDENCE_OUTPUT} must be a fresh destination"
    )


def real_provider_smoke_rejection_output_path(
    *,
    success_output: Path,
    internal_request_id: str,
) -> Path:
    """Derive a bounded sibling path without exposing the provider request identifier."""

    preflight_real_provider_smoke_output(
        output_path=success_output,
        forbidden_paths=(),
    )
    if re.fullmatch(_SAFE_REQUEST_ID_PATTERN, internal_request_id) is None:
        raise ValueError("smoke rejection request ID is invalid")
    request_digest = hashlib.sha256(
        f"{success_output.name}\0{internal_request_id}".encode()
    ).hexdigest()[:24]
    bounded_stem = success_output.stem[:80]
    rejection_output = success_output.with_name(
        f"{bounded_stem}.rejected-unbound-{request_digest}.json"
    )
    preflight_real_provider_smoke_output(
        output_path=rejection_output,
        forbidden_paths=(success_output,),
    )
    return rejection_output


def real_provider_smoke_verification_rejection_output_path(
    *,
    success_output: Path,
    internal_request_id: str,
) -> Path:
    """Derive a value-free sibling path for one post-bind verification rejection."""

    preflight_real_provider_smoke_output(
        output_path=success_output,
        forbidden_paths=(),
    )
    if re.fullmatch(_SAFE_REQUEST_ID_PATTERN, internal_request_id) is None:
        raise ValueError("verification rejection request ID is invalid")
    request_digest = hashlib.sha256(
        f"{success_output.name}\0verification\0{internal_request_id}".encode()
    ).hexdigest()[:24]
    bounded_stem = success_output.stem[:72]
    rejection_output = success_output.with_name(
        f"{bounded_stem}.rejected-generation-verification-{request_digest}.json"
    )
    preflight_real_provider_smoke_output(
        output_path=rejection_output,
        forbidden_paths=(success_output,),
    )
    return rejection_output


def write_real_provider_smoke_evidence(
    *,
    output_path: Path,
    evidence: RealProviderSmokeEvidence,
    forbidden_values: tuple[str, ...],
) -> ManifestFileBinding:
    """Write one fresh private artifact after a final secret-content scan."""

    preflight_real_provider_smoke_output(
        output_path=output_path,
        forbidden_paths=(),
    )
    serialized = stable_json(evidence)
    if _contains_forbidden_authorization_surface(serialized):
        raise ValueError("smoke evidence contains a forbidden authorization surface")
    if any(value and value in serialized for value in forbidden_values):
        raise ValueError("smoke evidence contains a forbidden value")
    return write_json_evidence(
        evidence_root=output_path.parent,
        relative_path=output_path.name,
        value=evidence,
        max_bytes=64_000,
    )


def write_real_provider_smoke_rejection_evidence(
    *,
    success_output: Path,
    evidence: RealProviderSmokeRejectionEvidence,
    forbidden_values: tuple[str, ...],
) -> ManifestFileBinding:
    """Write one fresh private rejection artifact while leaving success absent."""

    rejection_output = real_provider_smoke_rejection_output_path(
        success_output=success_output,
        internal_request_id=evidence.internal_request_id,
    )
    serialized = stable_json(evidence)
    if _contains_forbidden_authorization_surface(serialized):
        raise ValueError("smoke rejection evidence contains a forbidden authorization surface")
    if any(value and value in serialized for value in forbidden_values):
        raise ValueError("smoke rejection evidence contains a forbidden value")
    return write_json_evidence(
        evidence_root=rejection_output.parent,
        relative_path=rejection_output.name,
        value=evidence,
        max_bytes=64_000,
    )


def write_real_provider_smoke_verification_rejection_evidence(
    *,
    success_output: Path,
    evidence: RealProviderSmokeVerificationRejectionEvidence,
    forbidden_values: tuple[str, ...],
) -> ManifestFileBinding:
    """Write one fresh private post-bind rejection after a final canary scan."""

    rejection_output = real_provider_smoke_verification_rejection_output_path(
        success_output=success_output,
        internal_request_id=evidence.usage_record.request_id,
    )
    serialized = stable_json(evidence)
    if _contains_forbidden_authorization_surface(serialized):
        raise ValueError("verification rejection contains a forbidden authorization surface")
    if any(value and value in serialized for value in forbidden_values):
        raise ValueError("verification rejection contains a forbidden value")
    return write_json_evidence(
        evidence_root=rejection_output.parent,
        relative_path=rejection_output.name,
        value=evidence,
        max_bytes=96_000,
    )


def _contains_forbidden_authorization_surface(serialized: str) -> bool:
    """Reject credential-bearing authorization data without rejecting privacy evidence labels."""

    lowered = serialized.casefold()
    return '"authorization"' in lowered or "bearer " in lowered


def _required_usage_routing_sha256(record: UsageRecord, key: str) -> str:
    value = record.routing.get(key)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"verification rejection usage omitted {key}")
    return value


def _required_value(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value or value != value.strip():
        raise RealProviderTestConfigurationError(f"{name} is required and must be canonical")
    return value


def _parse_allowlist(
    environ: Mapping[str, str],
    name: str,
    *,
    validator: Callable[[str], bool],
    item_label: str,
) -> tuple[str, ...]:
    raw = _required_value(environ, name)
    values = tuple(item.strip() for item in raw.split(","))
    if (
        not values
        or any(not value for value in values)
        or len(values) != len(set(values))
        or any(not validator(value) for value in values)
    ):
        raise RealProviderTestConfigurationError(
            f"{name} must contain unique comma-separated {item_label}s"
        )
    return values


def _is_exact_non_placeholder_model(value: str) -> bool:
    if not _MODEL_PATTERN.fullmatch(value):
        return False
    author, model = value.split("/", 1)
    normalized_model = model.casefold()
    if normalized_model in _NON_EXACT_MODEL_NAMES or normalized_model.endswith(":latest"):
        return False
    return not _contains_placeholder_token(author) and not _contains_placeholder_token(model)


def _is_exact_non_placeholder_provider(value: str) -> bool:
    return bool(_PROVIDER_PATTERN.fullmatch(value)) and not _contains_placeholder_token(value)


def _contains_placeholder_token(value: str) -> bool:
    tokens = re.split(r"[^a-z0-9]+", value.casefold())
    return any(token in _PLACEHOLDER_TOKENS for token in tokens)


def _canonical_nonnegative_decimal(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is None:
        raise ValueError("cost is not a canonical decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("cost is not a canonical decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("cost is not a canonical non-negative decimal")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized or "0"
