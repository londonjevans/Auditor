"""Strict, non-secret attestation for OpenRouter generation metadata."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal, Never, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mmaudit.models.identifiers import is_exact_openrouter_model_id
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import (
    _is_structurally_generation_bindable_usage_record,
    _validated_usage_copy_preserving_owned_attestation,
    is_generation_bindable_usage_record,
)

_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_GENERATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_SAFE_TEXT_MAX_LENGTH = 256
_SOURCE_API_IDENTITY = "openrouter:/api/v1/generation"
_SCHEMA_VERSION = "1.0"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$")


class GenerationEvidenceValidationError(ValueError):
    """Raised when generation metadata cannot support a bounded attestation."""


class GenerationReconciliationMismatchCode(StrEnum):
    """Non-secret field identity for one exact generation/usage contradiction."""

    ACTUAL_MODEL = "actual model"
    RETURNED_MODEL = "returned model"
    GENERATION_MODEL = "generation model"
    GENERATION_ID = "generation ID"
    ROUTING_GENERATION_ID = "routing generation ID"
    REQUESTED_MODEL = "requested exact model"
    ROUTED_MODEL = "routed actual model"
    ROUTED_CANONICAL_MODEL = "routed canonical model"
    CATALOG_IDENTITY_BINDING = "catalog identity binding"
    DISCOVERY_EVIDENCE_BINDING = "discovery evidence binding"
    PROVIDER = "expected provider"
    ROUTED_PROVIDER = "routed provider"
    FINISH_REASON = "finish reason"
    ROUTED_FINISH_REASON = "routing finish reason"
    NATIVE_FINISH_REASON = "native finish reason"
    PROMPT_TOKENS = "prompt tokens"
    COMPLETION_TOKENS = "completion tokens"
    REASONING_TOKENS = "reasoning tokens"
    CACHED_TOKENS = "cached tokens"
    REPORTED_COST = "reported cost"
    REQUEST_TIMESTAMP = "request timestamp"


EVENTUAL_GENERATION_USAGE_MISMATCH_CODES = frozenset(
    {
        GenerationReconciliationMismatchCode.PROMPT_TOKENS,
        GenerationReconciliationMismatchCode.COMPLETION_TOKENS,
        GenerationReconciliationMismatchCode.REASONING_TOKENS,
        GenerationReconciliationMismatchCode.CACHED_TOKENS,
        GenerationReconciliationMismatchCode.REPORTED_COST,
    }
)


class GenerationReconciliationMismatchError(GenerationEvidenceValidationError):
    """Exact non-secret mismatch whose retry policy is determined by its code."""

    def __init__(self, code: GenerationReconciliationMismatchCode) -> None:
        if not isinstance(code, GenerationReconciliationMismatchCode):
            raise TypeError("generation reconciliation mismatch code is invalid")
        self.code = code
        super().__init__(f"generation evidence does not reconcile {code.value}")

    @property
    def is_eventual_usage_field(self) -> bool:
        """Return whether the same generation may still publish a settled value."""

        return self.code in EVENTUAL_GENERATION_USAGE_MISMATCH_CODES


@dataclass(frozen=True, slots=True)
class GenerationVerificationRequest:
    """One exact report case whose provider generation must be re-fetched."""

    benchmark_report_sha256: str
    case_id: str
    exact_model_id: str
    canonical_model_id: str
    catalog_identity_binding_sha256: str
    discovery_evidence_sha256: str
    expected_provider_name: str
    usage_record: UsageRecord

    def __post_init__(self) -> None:
        if _SHA256_PATTERN.fullmatch(self.benchmark_report_sha256) is None:
            raise GenerationEvidenceValidationError("benchmark report hash is invalid")
        if _CASE_ID_PATTERN.fullmatch(self.case_id) is None:
            raise GenerationEvidenceValidationError("benchmark case ID is invalid")
        _require_exact_model_id(self.exact_model_id)
        _require_exact_model_id(self.canonical_model_id)
        if (
            self.catalog_identity_binding_sha256
            != _canonical_sha256(
                {
                    "canonical_slug": self.canonical_model_id,
                    "id": self.exact_model_id,
                }
            )
            or _SHA256_PATTERN.fullmatch(self.discovery_evidence_sha256) is None
        ):
            raise GenerationEvidenceValidationError(
                "generation verification model identity binding is invalid"
            )
        _require_safe_text(self.expected_provider_name, "expected provider name")
        if not isinstance(self.usage_record, UsageRecord):
            raise GenerationEvidenceValidationError(
                "generation verification request usage is invalid"
            )
        try:
            usage_record = _validated_usage_copy_preserving_owned_attestation(self.usage_record)
        except ValidationError:
            raise GenerationEvidenceValidationError(
                "generation verification request usage is invalid"
            ) from None
        if usage_record.openrouter_generation_id is None:
            raise GenerationEvidenceValidationError(
                "generation verification request lacks a generation ID"
            )
        if (
            usage_record.requested_model != self.exact_model_id
            or usage_record.returned_model not in {self.exact_model_id, self.canonical_model_id}
            or usage_record.actual_model not in {self.exact_model_id, self.canonical_model_id}
            or usage_record.routing.get("selected_model") != usage_record.actual_model
            or usage_record.routing.get("canonical_model") != self.canonical_model_id
            or usage_record.routing.get("catalog_identity_binding_sha256")
            != self.catalog_identity_binding_sha256
            or usage_record.routing.get("discovery_evidence_sha256")
            != self.discovery_evidence_sha256
        ):
            raise GenerationEvidenceValidationError(
                "generation verification usage has a different model identity binding"
            )
        object.__setattr__(self, "usage_record", usage_record)


@dataclass(frozen=True, slots=True)
class _TrustedGenerationBinding:
    benchmark_report_sha256: str
    case_id: str
    exact_model_id: str
    canonical_model_id: str
    catalog_identity_binding_sha256: str
    discovery_evidence_sha256: str
    expected_provider_name: str
    usage_record_sha256: str
    attestation: OpenRouterGenerationEvidence


class TrustedGenerationVerification:
    """Opaque in-memory proof that generation metadata was freshly re-fetched.

    This capability is intentionally not a Pydantic model and cannot be copied,
    pickled, or reconstructed from a serialized benchmark artifact. Only the exact
    owned OpenRouter client may issue it after authentication and fresh metadata
    queries.
    """

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedGenerationVerification:
        del cls
        raise TypeError("trusted generation verification cannot be constructed directly")

    def __init__(
        self,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        del self, _args, _kwargs

    def attestation_for(
        self,
        *,
        benchmark_report_sha256: str,
        case_id: str,
        exact_model_id: str,
        canonical_model_id: str,
        catalog_identity_binding_sha256: str,
        discovery_evidence_sha256: str,
        usage_record: UsageRecord,
        expected_provider_name: str,
    ) -> OpenRouterGenerationEvidence:
        """Resolve only the exact report/case/usage tuple fetched by the issuer."""

        try:
            validated_usage = _validated_usage_copy_preserving_owned_attestation(usage_record)
        except (AttributeError, ValidationError):
            raise GenerationEvidenceValidationError(
                "generation verification usage is invalid"
            ) from None
        binding = _trusted_generation_binding_for(
            self,
            benchmark_report_sha256,
            exact_model_id,
            case_id,
        )
        if (
            binding is None
            or binding.canonical_model_id != canonical_model_id
            or binding.catalog_identity_binding_sha256 != catalog_identity_binding_sha256
            or binding.discovery_evidence_sha256 != discovery_evidence_sha256
            or binding.expected_provider_name != expected_provider_name
            or binding.usage_record_sha256 != _usage_record_sha256(validated_usage)
        ):
            raise GenerationEvidenceValidationError(
                "generation verification capability does not bind this report case"
            )
        return _reconcile_generation_evidence_structural(
            binding.attestation,
            usage_record=validated_usage,
            expected_exact_model=exact_model_id,
            expected_canonical_model=canonical_model_id,
            expected_catalog_identity_binding_sha256=(catalog_identity_binding_sha256),
            expected_discovery_evidence_sha256=discovery_evidence_sha256,
            expected_provider_name=expected_provider_name,
        )

    def __copy__(self) -> None:
        raise TypeError("trusted generation verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("trusted generation verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted generation verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted generation verification cannot be serialized")


def _build_generation_capability_authority() -> tuple[
    Callable[
        [TrustedGenerationVerification, tuple[_TrustedGenerationBinding, ...]],
        None,
    ],
    Callable[
        [TrustedGenerationVerification, str, str, str],
        _TrustedGenerationBinding | None,
    ],
]:
    """Keep generation-capability bindings outside caller-mutable instances."""

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedGenerationVerification],
            dict[tuple[str, str, str], _TrustedGenerationBinding],
        ],
    ] = {}
    lock = threading.RLock()

    def register(
        capability: TrustedGenerationVerification,
        bindings: tuple[_TrustedGenerationBinding, ...],
    ) -> None:
        indexed = {
            (
                item.benchmark_report_sha256,
                item.exact_model_id,
                item.case_id,
            ): item
            for item in bindings
        }
        if not bindings or len(indexed) != len(bindings):
            raise GenerationEvidenceValidationError(
                "trusted generation verification bindings are empty or duplicate"
            )
        key = id(capability)

        def discard(reference: weakref.ReferenceType[TrustedGenerationVerification]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, indexed)

    def binding_for(
        capability: TrustedGenerationVerification,
        report_sha256: str,
        exact_model_id: str,
        case_id: str,
    ) -> _TrustedGenerationBinding | None:
        with lock:
            registered = registry.get(id(capability))
        if (
            type(capability) is not TrustedGenerationVerification
            or registered is None
            or registered[0]() is not capability
        ):
            raise GenerationEvidenceValidationError(
                "generation verification capability is not trusted"
            )
        return registered[1].get((report_sha256, exact_model_id, case_id))

    return register, binding_for


_register_trusted_generation_capability, _trusted_generation_binding_for = (
    _build_generation_capability_authority()
)


class OpenRouterGenerationEvidence(BaseModel):
    """Allowlisted, self-hashed projection of the official generation response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    source_api_identity: Literal["openrouter:/api/v1/generation"]
    generation_id: str = Field(pattern=_GENERATION_ID_PATTERN)
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    provider_name: str = Field(min_length=1, max_length=_SAFE_TEXT_MAX_LENGTH)
    finish_reason: str = Field(min_length=1, max_length=100)
    native_finish_reason: str | None = Field(default=None, max_length=100)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    native_prompt_tokens: int | None = Field(default=None, ge=0)
    native_completion_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)
    cached_tokens: int | None = Field(default=None, ge=0)
    total_cost_usd: str
    cancelled: Literal[False]
    created_at: datetime | None = None
    request_id: str | None = Field(default=None, pattern=_REQUEST_ID_PATTERN)
    latency_ms: str | None = None
    generation_time_ms: str | None = None
    retrieved_at: datetime
    retrieval_attempts: int = Field(ge=1, le=4)
    execution_evidence: ExecutionEvidenceKind
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def evidence_is_canonical_and_self_bound(self) -> OpenRouterGenerationEvidence:
        _require_exact_model_id(self.exact_model_id)
        _require_safe_text(self.provider_name, "provider name")
        _require_safe_text(self.finish_reason, "finish reason", max_length=100)
        if self.native_finish_reason is not None:
            _require_safe_text(
                self.native_finish_reason,
                "native finish reason",
                max_length=100,
            )
        if self.reasoning_tokens is not None and self.reasoning_tokens > self.completion_tokens:
            raise ValueError("generation reasoning tokens exceed completion tokens")
        if self.cached_tokens is not None and self.cached_tokens > self.prompt_tokens:
            raise ValueError("generation cached tokens exceed prompt tokens")
        if _canonical_nonnegative_decimal(self.total_cost_usd, "total cost") != (
            self.total_cost_usd
        ):
            raise ValueError("generation total cost is not canonically encoded")
        for label, decimal_value in (
            ("latency", self.latency_ms),
            ("generation time", self.generation_time_ms),
        ):
            if (
                decimal_value is not None
                and _canonical_nonnegative_decimal(decimal_value, label) != decimal_value
            ):
                raise ValueError(f"generation {label} is not canonically encoded")
        for label, timestamp_value in (
            ("created_at", self.created_at),
            ("retrieved_at", self.retrieved_at),
        ):
            if timestamp_value is not None and (
                timestamp_value.tzinfo is None or timestamp_value.utcoffset() is None
            ):
                raise ValueError(f"generation {label} must be timezone-aware")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("generation evidence hash is inconsistent")
        return self


def validate_generation_id(generation_id: str) -> str:
    """Return one bounded, query-safe generation identifier."""

    if (
        not isinstance(generation_id, str)
        or re.fullmatch(_GENERATION_ID_PATTERN, generation_id) is None
    ):
        raise GenerationEvidenceValidationError(
            "generation lookup requires a bounded safe generation identifier"
        )
    return generation_id


def validate_openrouter_generation_payload(
    payload: Any,
    *,
    requested_generation_id: str,
    retrieved_at: datetime,
    execution_evidence: ExecutionEvidenceKind,
    retrieval_attempts: int = 1,
) -> OpenRouterGenerationEvidence:
    """Project a generation response without retaining source or completion content."""

    generation_id = validate_generation_id(requested_generation_id)
    if not isinstance(execution_evidence, ExecutionEvidenceKind):
        raise GenerationEvidenceValidationError("generation execution evidence is invalid")
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise GenerationEvidenceValidationError(
            "generation retrieval timestamp must be timezone-aware"
        )
    if (
        not isinstance(retrieval_attempts, int)
        or isinstance(retrieval_attempts, bool)
        or not 1 <= retrieval_attempts <= 4
    ):
        raise GenerationEvidenceValidationError(
            "generation retrieval attempts are outside the bounded polling policy"
        )
    envelope = _required_mapping(payload, "generation response")
    data = _required_mapping(envelope.get("data"), "generation response data")
    observed_generation_id = _required_pattern_string(
        data.get("id"),
        pattern=_GENERATION_ID_PATTERN,
        label="generation ID",
    )
    if observed_generation_id != generation_id:
        raise GenerationEvidenceValidationError(
            "generation response does not bind the requested generation ID"
        )
    exact_model_id = _required_pattern_string(
        data.get("model"),
        pattern=_MODEL_ID_PATTERN,
        label="exact model",
        max_length=384,
    )
    _require_exact_model_id(exact_model_id)
    provider_name = _required_safe_text(data.get("provider_name"), "provider name")
    finish_reason = _required_safe_text(
        data.get("finish_reason"),
        "finish reason",
        max_length=100,
    )
    native_finish_reason = _optional_safe_text(
        data.get("native_finish_reason"),
        "native finish reason",
        max_length=100,
    )
    prompt_tokens = _required_nonnegative_int(data.get("tokens_prompt"), "prompt tokens")
    completion_tokens = _required_nonnegative_int(
        data.get("tokens_completion"),
        "completion tokens",
    )
    native_prompt_tokens = _optional_nonnegative_int(
        data.get("native_tokens_prompt"),
        "native prompt tokens",
    )
    native_completion_tokens = _optional_nonnegative_int(
        data.get("native_tokens_completion"),
        "native completion tokens",
    )
    reasoning_tokens = _optional_nonnegative_int(
        data.get("native_tokens_reasoning"),
        "reasoning tokens",
    )
    cached_tokens = _optional_nonnegative_int(
        data.get("native_tokens_cached"),
        "cached tokens",
    )
    total_cost = _canonical_nonnegative_decimal(data.get("total_cost"), "total cost")
    reported_usage = data.get("usage")
    if reported_usage is not None and (
        _canonical_nonnegative_decimal(reported_usage, "usage cost") != total_cost
    ):
        raise GenerationEvidenceValidationError(
            "generation total cost and usage cost are inconsistent"
        )
    cancelled = data.get("cancelled")
    if cancelled is not False:
        raise GenerationEvidenceValidationError(
            "cancelled generation cannot support successful execution evidence"
        )
    created_at = _optional_datetime(data.get("created_at"), "created_at")
    request_id = _optional_pattern_string(
        data.get("request_id"),
        pattern=_REQUEST_ID_PATTERN,
        label="request ID",
    )
    latency = _optional_nonnegative_decimal(data.get("latency"), "latency")
    generation_time = _optional_nonnegative_decimal(
        data.get("generation_time"),
        "generation time",
    )
    serialized: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "source_api_identity": _SOURCE_API_IDENTITY,
        "generation_id": observed_generation_id,
        "exact_model_id": exact_model_id,
        "provider_name": provider_name,
        "finish_reason": finish_reason,
        "native_finish_reason": native_finish_reason,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "native_prompt_tokens": native_prompt_tokens,
        "native_completion_tokens": native_completion_tokens,
        "reasoning_tokens": reasoning_tokens,
        "cached_tokens": cached_tokens,
        "total_cost_usd": total_cost,
        "cancelled": False,
        "created_at": _datetime_json(created_at) if created_at is not None else None,
        "request_id": request_id,
        "latency_ms": latency,
        "generation_time_ms": generation_time,
        "retrieved_at": _datetime_json(retrieved_at.astimezone(UTC)),
        "retrieval_attempts": retrieval_attempts,
        "execution_evidence": execution_evidence,
    }
    return OpenRouterGenerationEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": _canonical_sha256(serialized),
        }
    )


def reconcile_generation_evidence(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
) -> OpenRouterGenerationEvidence:
    """Require owned REAL usage and exact independent generation metadata."""

    return _reconcile_generation_evidence(
        evidence,
        usage_record=usage_record,
        expected_exact_model=expected_exact_model,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(expected_catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expected_discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
        require_runtime_attestation=True,
    )


def _reconcile_generation_evidence_structural(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
) -> OpenRouterGenerationEvidence:
    """Validate a serialized join without minting owned runtime provenance."""

    return _reconcile_generation_evidence(
        evidence,
        usage_record=usage_record,
        expected_exact_model=expected_exact_model,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(expected_catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expected_discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
        require_runtime_attestation=False,
    )


def _reconcile_generation_evidence(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
    require_runtime_attestation: bool,
) -> OpenRouterGenerationEvidence:
    """Reconcile exact fields under an explicit runtime-provenance policy."""

    _require_exact_model_id(expected_exact_model)
    _require_exact_model_id(expected_canonical_model)
    if (
        expected_catalog_identity_binding_sha256
        != _canonical_sha256(
            {
                "canonical_slug": expected_canonical_model,
                "id": expected_exact_model,
            }
        )
        or _SHA256_PATTERN.fullmatch(expected_discovery_evidence_sha256) is None
    ):
        raise GenerationEvidenceValidationError(
            "generation reconciliation model identity binding is invalid"
        )
    _require_safe_text(expected_provider_name, "expected provider name")
    if not isinstance(evidence, OpenRouterGenerationEvidence):
        raise GenerationEvidenceValidationError("generation evidence has an invalid type")
    if not isinstance(usage_record, UsageRecord):
        raise GenerationEvidenceValidationError("generation usage record has an invalid type")
    try:
        evidence = OpenRouterGenerationEvidence.model_validate(evidence.model_dump(mode="json"))
        usage_record = _validated_usage_copy_preserving_owned_attestation(usage_record)
    except ValidationError:
        raise GenerationEvidenceValidationError(
            "generation reconciliation evidence is not schema-valid"
        ) from None
    if evidence.execution_evidence is not ExecutionEvidenceKind.REAL:
        raise GenerationEvidenceValidationError(
            "non-real generation metadata cannot attest a production request"
        )
    usage_is_bindable = (
        is_generation_bindable_usage_record(usage_record)
        if require_runtime_attestation
        else _is_structurally_generation_bindable_usage_record(usage_record)
    )
    if not usage_is_bindable:
        raise GenerationEvidenceValidationError(
            "generation attestation requires one bindable real certification request"
        )
    routing = usage_record.routing
    actual_model = usage_record.actual_model
    if actual_model not in {expected_exact_model, expected_canonical_model}:
        raise GenerationReconciliationMismatchError(
            GenerationReconciliationMismatchCode.ACTUAL_MODEL
        )
    if usage_record.returned_model not in {
        expected_exact_model,
        expected_canonical_model,
    }:
        raise GenerationReconciliationMismatchError(
            GenerationReconciliationMismatchCode.RETURNED_MODEL
        )
    if evidence.exact_model_id not in {
        expected_exact_model,
        expected_canonical_model,
    }:
        raise GenerationReconciliationMismatchError(
            GenerationReconciliationMismatchCode.GENERATION_MODEL
        )
    comparisons = (
        (
            evidence.generation_id,
            usage_record.openrouter_generation_id,
            GenerationReconciliationMismatchCode.GENERATION_ID,
        ),
        (
            evidence.generation_id,
            routing.get("generation_id"),
            GenerationReconciliationMismatchCode.ROUTING_GENERATION_ID,
        ),
        (
            usage_record.requested_model,
            expected_exact_model,
            GenerationReconciliationMismatchCode.REQUESTED_MODEL,
        ),
        (
            routing.get("selected_model"),
            actual_model,
            GenerationReconciliationMismatchCode.ROUTED_MODEL,
        ),
        (
            routing.get("canonical_model"),
            expected_canonical_model,
            GenerationReconciliationMismatchCode.ROUTED_CANONICAL_MODEL,
        ),
        (
            routing.get("catalog_identity_binding_sha256"),
            expected_catalog_identity_binding_sha256,
            GenerationReconciliationMismatchCode.CATALOG_IDENTITY_BINDING,
        ),
        (
            routing.get("discovery_evidence_sha256"),
            expected_discovery_evidence_sha256,
            GenerationReconciliationMismatchCode.DISCOVERY_EVIDENCE_BINDING,
        ),
        (
            evidence.provider_name,
            expected_provider_name,
            GenerationReconciliationMismatchCode.PROVIDER,
        ),
        (
            routing.get("selected_provider_name"),
            expected_provider_name,
            GenerationReconciliationMismatchCode.ROUTED_PROVIDER,
        ),
        (
            evidence.finish_reason,
            usage_record.finish_reason,
            GenerationReconciliationMismatchCode.FINISH_REASON,
        ),
        (
            evidence.finish_reason,
            routing.get("finish_reason"),
            GenerationReconciliationMismatchCode.ROUTED_FINISH_REASON,
        ),
        (
            evidence.native_finish_reason,
            routing.get("native_finish_reason"),
            GenerationReconciliationMismatchCode.NATIVE_FINISH_REASON,
        ),
    )
    for observed, expected, code in comparisons:
        if observed != expected:
            raise GenerationReconciliationMismatchError(code)
    if evidence.created_at is not None:
        assert usage_record.started_at is not None
        assert usage_record.ended_at is not None
        created_at = evidence.created_at.astimezone(UTC)
        if not (
            usage_record.started_at.astimezone(UTC) - timedelta(minutes=5)
            <= created_at
            <= usage_record.ended_at.astimezone(UTC) + timedelta(minutes=5)
        ):
            raise GenerationReconciliationMismatchError(
                GenerationReconciliationMismatchCode.REQUEST_TIMESTAMP
            )
    eventual_token_comparisons = (
        (
            evidence.prompt_tokens,
            usage_record.prompt_tokens,
            GenerationReconciliationMismatchCode.PROMPT_TOKENS,
        ),
        (
            evidence.completion_tokens,
            usage_record.completion_tokens,
            GenerationReconciliationMismatchCode.COMPLETION_TOKENS,
        ),
        (
            evidence.reasoning_tokens,
            usage_record.reasoning_tokens,
            GenerationReconciliationMismatchCode.REASONING_TOKENS,
        ),
        (
            evidence.cached_tokens,
            usage_record.cached_tokens,
            GenerationReconciliationMismatchCode.CACHED_TOKENS,
        ),
    )
    for observed, expected, code in eventual_token_comparisons:
        if observed is not None and observed != expected:
            raise GenerationReconciliationMismatchError(code)
    assert usage_record.reported_cost_usd is not None
    usage_cost = _canonical_nonnegative_decimal(
        usage_record.reported_cost_usd,
        "usage-record cost",
    )
    if evidence.total_cost_usd != usage_cost:
        raise GenerationReconciliationMismatchError(
            GenerationReconciliationMismatchCode.REPORTED_COST
        )
    return evidence


def validate_generation_evidence_against_usage(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
) -> OpenRouterGenerationEvidence:
    """Compatibility spelling for explicit generation/usage reconciliation."""

    return reconcile_generation_evidence(
        evidence,
        usage_record=usage_record,
        expected_exact_model=expected_exact_model,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(expected_catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expected_discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
    )


def _issue_trusted_generation_verification(
    *,
    requests: tuple[GenerationVerificationRequest, ...],
    attestations: tuple[OpenRouterGenerationEvidence, ...],
    verification_started_at: datetime,
) -> TrustedGenerationVerification:
    """Issue one opaque capability from an exact authenticated re-fetch set."""

    if verification_started_at.tzinfo is None or verification_started_at.utcoffset() is None:
        raise GenerationEvidenceValidationError(
            "generation verification start time must be timezone-aware"
        )
    if not requests or len(requests) != len(attestations):
        raise GenerationEvidenceValidationError(
            "generation verification requires an exact non-empty attestation set"
        )
    normalized_requests = tuple(
        GenerationVerificationRequest(
            benchmark_report_sha256=request.benchmark_report_sha256,
            case_id=request.case_id,
            exact_model_id=request.exact_model_id,
            canonical_model_id=request.canonical_model_id,
            catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
            discovery_evidence_sha256=request.discovery_evidence_sha256,
            expected_provider_name=request.expected_provider_name,
            usage_record=request.usage_record,
        )
        for request in requests
    )
    request_keys = tuple(
        (
            request.benchmark_report_sha256,
            request.exact_model_id,
            request.case_id,
        )
        for request in normalized_requests
    )
    request_ids = tuple(request.usage_record.request_id for request in normalized_requests)
    generation_ids = tuple(
        request.usage_record.openrouter_generation_id for request in normalized_requests
    )
    if (
        len(set(request_keys)) != len(request_keys)
        or len(set(request_ids)) != len(request_ids)
        or len(set(generation_ids)) != len(generation_ids)
        or None in generation_ids
    ):
        raise GenerationEvidenceValidationError(
            "generation verification requests contain replayed identities"
        )
    attestations_by_id = {attestation.generation_id: attestation for attestation in attestations}
    if len(attestations_by_id) != len(attestations) or set(attestations_by_id) != set(
        generation_ids
    ):
        raise GenerationEvidenceValidationError(
            "generation verification response set differs from requested generations"
        )
    started_at = verification_started_at.astimezone(UTC)
    bindings: list[_TrustedGenerationBinding] = []
    for request in normalized_requests:
        generation_id = request.usage_record.openrouter_generation_id
        assert generation_id is not None
        attestation = OpenRouterGenerationEvidence.model_validate(
            attestations_by_id[generation_id].model_dump(mode="json")
        )
        if attestation.retrieved_at.astimezone(UTC) < started_at:
            raise GenerationEvidenceValidationError(
                "generation verification did not use a fresh provider re-fetch"
            )
        _reconcile_generation_evidence_structural(
            attestation,
            usage_record=request.usage_record,
            expected_exact_model=request.exact_model_id,
            expected_canonical_model=request.canonical_model_id,
            expected_catalog_identity_binding_sha256=(request.catalog_identity_binding_sha256),
            expected_discovery_evidence_sha256=request.discovery_evidence_sha256,
            expected_provider_name=request.expected_provider_name,
        )
        bindings.append(
            _TrustedGenerationBinding(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=(request.catalog_identity_binding_sha256),
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                expected_provider_name=request.expected_provider_name,
                usage_record_sha256=_usage_record_sha256(request.usage_record),
                attestation=attestation,
            )
        )
    capability = object.__new__(TrustedGenerationVerification)
    _register_trusted_generation_capability(capability, tuple(bindings))
    return capability


def _usage_record_sha256(record: UsageRecord) -> str:
    return _canonical_sha256(record.model_dump(mode="json"))


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise GenerationEvidenceValidationError(f"{label} must be an object")
    return value


def _required_pattern_string(
    value: Any,
    *,
    pattern: str,
    label: str,
    max_length: int = 256,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) > max_length
        or re.fullmatch(pattern, value) is None
    ):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    return value


def _optional_pattern_string(
    value: Any,
    *,
    pattern: str,
    label: str,
) -> str | None:
    if value is None:
        return None
    return _required_pattern_string(value, pattern=pattern, label=label)


def _required_safe_text(
    value: Any,
    label: str,
    *,
    max_length: int = _SAFE_TEXT_MAX_LENGTH,
) -> str:
    if not isinstance(value, str):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    return _require_safe_text(value, label, max_length=max_length)


def _optional_safe_text(
    value: Any,
    label: str,
    *,
    max_length: int,
) -> str | None:
    if value is None:
        return None
    return _required_safe_text(value, label, max_length=max_length)


def _require_safe_text(
    value: str,
    label: str,
    *,
    max_length: int = _SAFE_TEXT_MAX_LENGTH,
) -> str:
    if (
        not value
        or len(value) > max_length
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    return value


def _required_nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    return value


def _optional_nonnegative_int(value: Any, label: str) -> int | None:
    if value is None:
        return None
    return _required_nonnegative_int(value, label)


def _canonical_nonnegative_decimal(value: Any, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int, float, str)):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    if isinstance(value, float) and not math.isfinite(value):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    try:
        normalized = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid") from None
    if not normalized.is_finite() or normalized < 0:
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


def _optional_nonnegative_decimal(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _canonical_nonnegative_decimal(value, label)


def _optional_datetime(value: Any, label: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, (str, datetime)):
        raise GenerationEvidenceValidationError(f"generation {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    except ValueError:
        raise GenerationEvidenceValidationError(f"generation {label} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GenerationEvidenceValidationError(f"generation {label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _datetime_json(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _require_exact_model_id(model_id: str) -> None:
    if not is_exact_openrouter_model_id(model_id):
        raise GenerationEvidenceValidationError(
            "generation evidence requires an exact author/model identifier"
        )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return _canonical_nonnegative_decimal(value, "decimal")
    raise TypeError("unsupported generation evidence value")
