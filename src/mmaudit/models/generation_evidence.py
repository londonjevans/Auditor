"""Strict, non-secret attestation for OpenRouter generation metadata."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Never, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mmaudit.models.identifiers import is_exact_openrouter_model_id
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import (
    _has_authrunner_owned_real_usage_origin,
    _has_owned_real_usage_attestation,
    _is_structurally_generation_bindable_usage_record,
    _is_structurally_generation_reconcilable_usage_record,
    _validated_usage_copy_preserving_owned_attestation,
    is_generation_bindable_usage_record,
    is_generation_reconcilable_usage_record,
    noncrediting_unknown_token_smoke_usage_error,
    structurally_noncrediting_unknown_token_smoke_usage_error,
)

_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_GENERATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_SAFE_TEXT_MAX_LENGTH = 256
_SOURCE_API_IDENTITY = "openrouter:/api/v1/generation"
_SCHEMA_VERSION = "1.1"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$")
MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS = 7

_TRUSTED_HAS_OWNED_REAL_USAGE_ATTESTATION = _has_owned_real_usage_attestation
_TRUSTED_NONCREDITING_UNKNOWN_TOKEN_SMOKE_USAGE_ERROR = noncrediting_unknown_token_smoke_usage_error
_TRUSTED_STRUCTURALLY_NONCREDITING_UNKNOWN_TOKEN_SMOKE_USAGE_ERROR = (
    structurally_noncrediting_unknown_token_smoke_usage_error
)
_INITIAL_REAL_BINDING_RECONCILIATION_ISSUER = object()


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


class _GenerationReconciliationPolicy(StrEnum):
    """Closed structural reconciliation policy carried by one frozen expectation."""

    GENERIC = "GENERIC"
    NONCREDITING_UNKNOWN_TOKEN_SMOKE = "NONCREDITING_UNKNOWN_TOKEN_SMOKE"


@dataclass(frozen=True, slots=True)
class GenerationReconciliationExpectation:
    """Expected identity and usage for one eventual generation observation."""

    exact_model_id: str
    canonical_model_id: str
    catalog_identity_binding_sha256: str
    discovery_evidence_sha256: str
    expected_provider_name: str
    require_certification: bool
    usage_record: UsageRecord
    _initial_real_binding_issuer: InitVar[object | None] = None
    reconciliation_policy: _GenerationReconciliationPolicy = field(init=False)

    def __post_init__(self, _initial_real_binding_issuer: object | None) -> None:
        if (
            type(self) is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
            or GenerationReconciliationExpectation
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
            or GenerationReconciliationExpectation.__init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_INIT
            or GenerationReconciliationExpectation.__post_init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_POST_INIT
            or _GenerationReconciliationPolicy is not _TRUSTED_GENERATION_RECONCILIATION_POLICY_TYPE
            or tuple(_GenerationReconciliationPolicy)
            != _TRUSTED_GENERATION_RECONCILIATION_POLICY_VALUES
            or _has_owned_real_usage_attestation is not _TRUSTED_HAS_OWNED_REAL_USAGE_ATTESTATION
            or noncrediting_unknown_token_smoke_usage_error
            is not _TRUSTED_NONCREDITING_UNKNOWN_TOKEN_SMOKE_USAGE_ERROR
            or structurally_noncrediting_unknown_token_smoke_usage_error
            is not _TRUSTED_STRUCTURALLY_NONCREDITING_UNKNOWN_TOKEN_SMOKE_USAGE_ERROR
        ):
            raise GenerationEvidenceValidationError(
                "generation reconciliation usage-policy runtime is not pristine"
            )
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
        if not isinstance(self.require_certification, bool):
            raise GenerationEvidenceValidationError(
                "generation reconciliation certification policy is invalid"
            )
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
            usage_record.routing.get("certification_request") is True
        ) is not self.require_certification:
            raise GenerationEvidenceValidationError(
                "generation reconciliation certification policy differs from usage"
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
            or usage_record.routing.get("selected_provider_name") != self.expected_provider_name
        ):
            raise GenerationEvidenceValidationError(
                "generation verification usage has a different model identity binding"
            )
        runtime_smoke = noncrediting_unknown_token_smoke_usage_error(usage_record) is None
        structural_smoke = (
            structurally_noncrediting_unknown_token_smoke_usage_error(usage_record) is None
        )
        if _initial_real_binding_issuer is not None:
            if (
                _initial_real_binding_issuer is not _INITIAL_REAL_BINDING_RECONCILIATION_ISSUER
                or not structural_smoke
                or not _has_owned_real_usage_attestation(usage_record)
            ):
                raise GenerationEvidenceValidationError(
                    "initial REAL smoke reconciliation authority is invalid"
                )
            policy = _GenerationReconciliationPolicy.NONCREDITING_UNKNOWN_TOKEN_SMOKE
        elif runtime_smoke:
            policy = _GenerationReconciliationPolicy.NONCREDITING_UNKNOWN_TOKEN_SMOKE
        else:
            policy = _GenerationReconciliationPolicy.GENERIC
        object.__setattr__(self, "usage_record", usage_record)
        object.__setattr__(self, "reconciliation_policy", policy)


def _initial_real_generation_reconciliation_expectation(
    *,
    exact_model_id: str,
    canonical_model_id: str,
    catalog_identity_binding_sha256: str,
    discovery_evidence_sha256: str,
    expected_provider_name: str,
    require_certification: bool,
    usage_record: UsageRecord,
) -> GenerationReconciliationExpectation:
    """Seal the sole pre-origin exception for owned REAL v3 smoke binding."""

    if (
        GenerationReconciliationExpectation
        is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
        or _initial_real_generation_reconciliation_expectation
        is not _TRUSTED_INITIAL_REAL_GENERATION_RECONCILIATION_EXPECTATION
    ):
        raise GenerationEvidenceValidationError(
            "initial REAL generation reconciliation runtime is not pristine"
        )
    return _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE(
        exact_model_id=exact_model_id,
        canonical_model_id=canonical_model_id,
        catalog_identity_binding_sha256=catalog_identity_binding_sha256,
        discovery_evidence_sha256=discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
        require_certification=require_certification,
        usage_record=usage_record,
        _initial_real_binding_issuer=_INITIAL_REAL_BINDING_RECONCILIATION_ISSUER,
    )


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
        if (
            type(self) is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_TYPE
            or GenerationVerificationRequest is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_TYPE
            or GenerationVerificationRequest.__init__
            is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_INIT
            or GenerationVerificationRequest.__post_init__
            is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_POST_INIT
            or GenerationVerificationRequest.reconciliation_expectation
            is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_RECONCILIATION_EXPECTATION
        ):
            raise GenerationEvidenceValidationError(
                "generation verification request runtime is not pristine"
            )
        if _SHA256_PATTERN.fullmatch(self.benchmark_report_sha256) is None:
            raise GenerationEvidenceValidationError("benchmark report hash is invalid")
        if _CASE_ID_PATTERN.fullmatch(self.case_id) is None:
            raise GenerationEvidenceValidationError("benchmark case ID is invalid")
        expectation = self.reconciliation_expectation()
        object.__setattr__(self, "usage_record", expectation.usage_record)

    def reconciliation_expectation(self) -> GenerationReconciliationExpectation:
        """Return the core provider observation expected by this report case."""

        if (
            GenerationReconciliationExpectation
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
            or GenerationReconciliationExpectation.__init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_INIT
            or GenerationReconciliationExpectation.__post_init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_POST_INIT
        ):
            raise GenerationEvidenceValidationError(
                "generation reconciliation expectation runtime is not pristine"
            )
        return _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE(
            exact_model_id=self.exact_model_id,
            canonical_model_id=self.canonical_model_id,
            catalog_identity_binding_sha256=self.catalog_identity_binding_sha256,
            discovery_evidence_sha256=self.discovery_evidence_sha256,
            expected_provider_name=self.expected_provider_name,
            require_certification=True,
            usage_record=self.usage_record,
        )


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


@dataclass(frozen=True, slots=True)
class _TrustedGenerationCapabilitySnapshot:
    """Exact hidden generation lease observed before a potentially long reconciliation."""

    process_id: int
    bindings: Mapping[tuple[str, str, str], _TrustedGenerationBinding]
    nonce: object


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
        lease_snapshot = _snapshot_trusted_generation_capability(self)
        binding = lease_snapshot.bindings.get((benchmark_report_sha256, exact_model_id, case_id))
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
        if (
            GenerationReconciliationExpectation
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
            or GenerationReconciliationExpectation.__init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_INIT
            or GenerationReconciliationExpectation.__post_init__
            is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_POST_INIT
            or _GenerationReconciliationPolicy is not _TRUSTED_GENERATION_RECONCILIATION_POLICY_TYPE
            or tuple(_GenerationReconciliationPolicy)
            != _TRUSTED_GENERATION_RECONCILIATION_POLICY_VALUES
            or _reconcile_generation_expectation_structural
            is not _TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL
        ):
            raise GenerationEvidenceValidationError(
                "generation verification reconciliation runtime is not pristine"
            )
        expectation = _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE(
            exact_model_id=exact_model_id,
            canonical_model_id=canonical_model_id,
            catalog_identity_binding_sha256=catalog_identity_binding_sha256,
            discovery_evidence_sha256=discovery_evidence_sha256,
            expected_provider_name=expected_provider_name,
            require_certification=True,
            usage_record=validated_usage,
        )
        result = _TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL(
            binding.attestation,
            expectation=expectation,
        )
        _recheck_trusted_generation_capability(self, lease_snapshot)
        return result

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
    Callable[
        [TrustedGenerationVerification],
        _TrustedGenerationCapabilitySnapshot,
    ],
    Callable[
        [TrustedGenerationVerification, _TrustedGenerationCapabilitySnapshot],
        None,
    ],
    Callable[[TrustedGenerationVerification], None],
]:
    """Keep PID-local generation bindings outside caller-mutable instances."""

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedGenerationVerification],
            int,
            Mapping[tuple[str, str, str], _TrustedGenerationBinding],
            object,
        ],
    ] = {}
    lock = threading.RLock()
    trusted_capability_type = TrustedGenerationVerification
    trusted_getpid = os.getpid

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

        if type(capability) is not trusted_capability_type:
            raise GenerationEvidenceValidationError(
                "generation verification capability is not trusted"
            )
        reference = weakref.ref(capability, discard)
        with lock:
            current = registry.get(key)
            if current is not None and current[0]() is capability:
                raise GenerationEvidenceValidationError(
                    "generation verification capability is already registered"
                )
            registry[key] = (
                reference,
                trusted_getpid(),
                MappingProxyType(indexed),
                object(),
            )

    def snapshot(
        capability: TrustedGenerationVerification,
    ) -> _TrustedGenerationCapabilitySnapshot:
        if type(capability) is not trusted_capability_type:
            raise GenerationEvidenceValidationError(
                "generation verification capability is not trusted"
            )
        with lock:
            registered = registry.get(id(capability))
        if registered is None or registered[0]() is not capability:
            raise GenerationEvidenceValidationError(
                "generation verification capability is not trusted"
            )
        if registered[1] != trusted_getpid():
            raise GenerationEvidenceValidationError(
                "generation verification capability belongs to another process"
            )
        return _TrustedGenerationCapabilitySnapshot(
            process_id=registered[1],
            bindings=registered[2],
            nonce=registered[3],
        )

    def recheck(
        capability: TrustedGenerationVerification,
        lease_snapshot: _TrustedGenerationCapabilitySnapshot,
    ) -> None:
        if type(capability) is not trusted_capability_type:
            raise GenerationEvidenceValidationError(
                "generation verification capability changed or was revoked during reconciliation"
            )
        with lock:
            registered = registry.get(id(capability))
        if (
            type(lease_snapshot) is not _TrustedGenerationCapabilitySnapshot
            or registered is None
            or registered[0]() is not capability
            or registered[1] != trusted_getpid()
            or registered[1] != lease_snapshot.process_id
            or registered[2] is not lease_snapshot.bindings
            or registered[3] is not lease_snapshot.nonce
        ):
            raise GenerationEvidenceValidationError(
                "generation verification capability changed or was revoked during reconciliation"
            )

    def binding_for(
        capability: TrustedGenerationVerification,
        report_sha256: str,
        exact_model_id: str,
        case_id: str,
    ) -> _TrustedGenerationBinding | None:
        lease_snapshot = snapshot(capability)
        return lease_snapshot.bindings.get((report_sha256, exact_model_id, case_id))

    def revoke(capability: TrustedGenerationVerification) -> None:
        """Remove one exact current-PID structural generation lease permanently."""

        if type(capability) is not trusted_capability_type:
            raise GenerationEvidenceValidationError(
                "generation verification capability is absent, mismatched, or revoked"
            )
        key = id(capability)
        with lock:
            registered = registry.get(key)
            if registered is None or registered[0]() is not capability:
                raise GenerationEvidenceValidationError(
                    "generation verification capability is absent, mismatched, or revoked"
                )
            if registered[1] != trusted_getpid():
                raise GenerationEvidenceValidationError(
                    "generation verification capability belongs to another process"
                )
            removed = registry.pop(key)
        if removed is not registered:
            raise GenerationEvidenceValidationError(
                "generation verification capability changed during revocation"
            )

    return register, binding_for, snapshot, recheck, revoke


(
    _register_trusted_generation_capability,
    _trusted_generation_binding_for,
    _snapshot_trusted_generation_capability,
    _recheck_trusted_generation_capability,
    _revoke_trusted_generation_capability,
) = _build_generation_capability_authority()


def _build_authrunner_generation_origin_authority() -> tuple[
    Callable[..., None],
    Callable[
        [TrustedGenerationVerification, tuple[GenerationVerificationRequest, ...]],
        TrustedGenerationVerification,
    ],
    Callable[..., bool],
    Callable[[TrustedGenerationVerification], None],
]:
    """Keep fresh REAL re-fetch origin separate from structural test capabilities."""

    type RequestBinding = tuple[str, str, str, str]
    type Issuer = tuple[
        object,
        type[object],
        Callable[..., object],
        Callable[[], bool],
        Callable[[object], ExecutionEvidenceKind],
    ]

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedGenerationVerification],
            tuple[RequestBinding, ...],
            object,
            int,
        ],
    ] = {}
    issuer: Issuer | None = None
    lock = threading.RLock()
    trusted_sys = sys
    trusted_self_module = trusted_sys.modules[__name__]
    trusted_hashlib = hashlib
    trusted_json = json
    trusted_sha256 = trusted_hashlib.sha256
    trusted_json_dumps = trusted_json.dumps
    trusted_binding_for = _trusted_generation_binding_for
    trusted_snapshot = _snapshot_trusted_generation_capability
    trusted_recheck = _recheck_trusted_generation_capability
    trusted_usage_origin = _has_authrunner_owned_real_usage_origin
    trusted_capability_type = TrustedGenerationVerification
    trusted_getpid = os.getpid

    def trusted_usage_sha256(record: UsageRecord) -> str:
        return trusted_sha256(
            trusted_json_dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    def register_issuer(
        *,
        module: object,
        client_type: type[object],
        refetch_method: Callable[..., object],
        pristine_predicate: Callable[[], bool],
        execution_evidence_resolver: Callable[[object], ExecutionEvidenceKind],
    ) -> None:
        """Register the exact OpenRouter authenticated refetch method once."""

        nonlocal issuer
        frame = trusted_sys._getframe(1)
        module_name = getattr(module, "__name__", None)
        module_values = getattr(module, "__dict__", None)
        if (
            module_name != "mmaudit.models.openrouter"
            or type(module_values) is not dict
            or frame.f_globals is not module_values
            or frame.f_code.co_name != "<module>"
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or client_type.__module__ != module_name
            or vars(client_type).get("create_trusted_generation_verification") is not refetch_method
            or getattr(refetch_method, "__module__", None) != module_name
            or getattr(refetch_method, "__qualname__", None)
            != "OpenRouterClient.create_trusted_generation_verification"
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
        ):
            raise RuntimeError("AUTHRUNNER generation-origin issuer registration is invalid")
        with lock:
            if issuer is not None:
                raise RuntimeError("AUTHRUNNER generation-origin issuer is already registered")
            issuer = (
                module,
                client_type,
                refetch_method,
                pristine_predicate,
                execution_evidence_resolver,
            )

    def mark(
        capability: TrustedGenerationVerification,
        requests: tuple[GenerationVerificationRequest, ...],
    ) -> TrustedGenerationVerification:
        """Strong-mark one exact capability returned by the pristine live refetch path."""

        with lock:
            registered_issuer = issuer
        if registered_issuer is None:
            raise GenerationEvidenceValidationError(
                "AUTHRUNNER generation-origin issuer is not registered"
            )
        (
            module,
            client_type,
            refetch_method,
            pristine_predicate,
            execution_evidence_resolver,
        ) = registered_issuer
        frame = trusted_sys._getframe(1)
        module_name = getattr(module, "__name__", "")
        module_values = getattr(module, "__dict__", None)
        client = frame.f_locals.get("self")
        if (
            type(module_values) is not dict
            or globals().get("sys") is not trusted_sys
            or globals().get("hashlib") is not trusted_hashlib
            or globals().get("json") is not trusted_json
            or trusted_hashlib.sha256 is not trusted_sha256
            or trusted_json.dumps is not trusted_json_dumps
            or trusted_sys.modules.get(__name__) is not trusted_self_module
            or getattr(trusted_self_module, "_trusted_generation_binding_for", None)
            is not trusted_binding_for
            or getattr(trusted_self_module, "_snapshot_trusted_generation_capability", None)
            is not trusted_snapshot
            or getattr(trusted_self_module, "_recheck_trusted_generation_capability", None)
            is not trusted_recheck
            or getattr(trusted_self_module, "_has_authrunner_owned_real_usage_origin", None)
            is not trusted_usage_origin
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or vars(client_type).get("create_trusted_generation_verification") is not refetch_method
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
            or frame.f_globals is not module_values
            or frame.f_code is not refetch_method.__code__
            or type(client) is not client_type
        ):
            raise GenerationEvidenceValidationError(
                "AUTHRUNNER generation origin requires the pristine refetch path"
            )
        try:
            budget = object.__getattribute__(client, "budget")
            atomic_ledger = object.__getattribute__(budget, "atomic_ledger")
        except (AttributeError, TypeError):
            atomic_ledger = None
        if (
            not pristine_predicate()
            or execution_evidence_resolver(client) is not ExecutionEvidenceKind.REAL
            or object.__getattribute__(client, "_owns_client") is not True
            or object.__getattribute__(client, "_authentication_validated") is not True
            or atomic_ledger is None
            or type(capability) is not trusted_capability_type
            or type(requests) is not tuple
            or not requests
        ):
            raise GenerationEvidenceValidationError(
                "AUTHRUNNER generation origin requires an owned REAL fresh refetch"
            )
        lease_snapshot = trusted_snapshot(capability)
        request_bindings: list[RequestBinding] = []
        for request in requests:
            if type(request) is not GenerationVerificationRequest or not trusted_usage_origin(
                request.usage_record,
                atomic_ledger=atomic_ledger,
            ):
                raise GenerationEvidenceValidationError(
                    "AUTHRUNNER generation origin requires owned REAL request usage"
                )
            binding = trusted_binding_for(
                capability,
                request.benchmark_report_sha256,
                request.exact_model_id,
                request.case_id,
            )
            usage_sha256 = trusted_usage_sha256(request.usage_record)
            if binding is None or binding.usage_record_sha256 != usage_sha256:
                raise GenerationEvidenceValidationError(
                    "AUTHRUNNER generation origin differs from the fresh refetch set"
                )
            request_bindings.append(
                (
                    request.benchmark_report_sha256,
                    request.exact_model_id,
                    request.case_id,
                    usage_sha256,
                )
            )
        frozen_bindings = tuple(request_bindings)
        key = id(capability)

        def discard(reference: weakref.ReferenceType[TrustedGenerationVerification]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        inserted = False
        with lock:
            if key in registry:
                raise GenerationEvidenceValidationError(
                    "AUTHRUNNER generation origin is already registered"
                )
            registry[key] = (
                reference,
                frozen_bindings,
                atomic_ledger,
                trusted_getpid(),
            )
            inserted = True
        try:
            trusted_recheck(capability, lease_snapshot)
            return capability
        except BaseException:
            if inserted:
                with lock:
                    current = registry.get(key)
                    if current is not None and current[0] is reference:
                        registry.pop(key, None)
            raise

    def contains(
        capability: TrustedGenerationVerification,
        *,
        atomic_ledger: object | None = None,
    ) -> bool:
        if type(capability) is not trusted_capability_type:
            return False
        try:
            lease_snapshot = trusted_snapshot(capability)
        except GenerationEvidenceValidationError:
            return False
        with lock:
            registered_issuer = issuer
        if registered_issuer is None:
            return False
        (
            module,
            client_type,
            refetch_method,
            pristine_predicate,
            execution_evidence_resolver,
        ) = registered_issuer
        module_name = getattr(module, "__name__", "")
        if (
            globals().get("sys") is not trusted_sys
            or globals().get("hashlib") is not trusted_hashlib
            or globals().get("json") is not trusted_json
            or trusted_hashlib.sha256 is not trusted_sha256
            or trusted_json.dumps is not trusted_json_dumps
            or trusted_sys.modules.get(__name__) is not trusted_self_module
            or getattr(trusted_self_module, "_trusted_generation_binding_for", None)
            is not trusted_binding_for
            or getattr(trusted_self_module, "_snapshot_trusted_generation_capability", None)
            is not trusted_snapshot
            or getattr(trusted_self_module, "_recheck_trusted_generation_capability", None)
            is not trusted_recheck
            or getattr(trusted_self_module, "_has_authrunner_owned_real_usage_origin", None)
            is not trusted_usage_origin
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or vars(client_type).get("create_trusted_generation_verification") is not refetch_method
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
            or not pristine_predicate()
        ):
            return False
        with lock:
            registered = registry.get(id(capability))
        if (
            registered is None
            or registered[0]() is not capability
            or registered[3] != trusted_getpid()
            or (atomic_ledger is not None and registered[2] is not atomic_ledger)
        ):
            return False
        try:
            result = all(
                (binding := lease_snapshot.bindings.get((report_sha256, exact_model_id, case_id)))
                is not None
                and binding.usage_record_sha256 == usage_sha256
                for report_sha256, exact_model_id, case_id, usage_sha256 in registered[1]
            )
            trusted_recheck(capability, lease_snapshot)
            return result
        except GenerationEvidenceValidationError:
            return False

    def revoke(capability: TrustedGenerationVerification) -> None:
        """Remove a current-PID AUTHRUNNER origin mark when one is present."""

        if type(capability) is not trusted_capability_type:
            return
        key = id(capability)
        with lock:
            registered = registry.get(key)
            if registered is None or registered[0]() is not capability:
                return
            if registered[3] != trusted_getpid():
                raise GenerationEvidenceValidationError(
                    "generation verification capability belongs to another process"
                )
            removed = registry.pop(key)
        if removed is not registered:
            raise GenerationEvidenceValidationError(
                "generation verification AUTHRUNNER origin changed during revocation"
            )

    return register_issuer, mark, contains, revoke


(
    _register_authrunner_generation_origin_issuer,
    _attest_authrunner_generation_origin,
    _has_authrunner_generation_origin,
    _revoke_authrunner_generation_origin,
) = _build_authrunner_generation_origin_authority()
del _build_authrunner_generation_origin_authority


def _build_generation_revocation_authority() -> Callable[[TrustedGenerationVerification], None]:
    """Capture fail-safe removal of both generation-capability registries."""

    namespace = globals()
    trusted_sys = sys
    trusted_os = os
    trusted_getpid = trusted_os.getpid
    trusted_self_module = trusted_sys.modules[__name__]
    trusted_capability_type = TrustedGenerationVerification
    trusted_core_revoke = _revoke_trusted_generation_capability
    trusted_origin_revoke = _revoke_authrunner_generation_origin
    trusted_binding_for = _trusted_generation_binding_for
    trusted_snapshot = _snapshot_trusted_generation_capability
    trusted_recheck = _recheck_trusted_generation_capability
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            namespace.get("sys") is not trusted_sys
            or namespace.get("os") is not trusted_os
            or trusted_os.getpid is not trusted_getpid
            or trusted_sys.modules.get(__name__) is not trusted_self_module
            or namespace.get("TrustedGenerationVerification") is not trusted_capability_type
            or namespace.get("_revoke_trusted_generation_capability") is not trusted_core_revoke
            or namespace.get("_revoke_authrunner_generation_origin") is not trusted_origin_revoke
            or namespace.get("_trusted_generation_binding_for") is not trusted_binding_for
            or namespace.get("_snapshot_trusted_generation_capability") is not trusted_snapshot
            or namespace.get("_recheck_trusted_generation_capability") is not trusted_recheck
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
        ):
            raise GenerationEvidenceValidationError(
                "generation verification revocation runtime is not pristine"
            )

    def revoke(capability: TrustedGenerationVerification) -> None:
        """Permanently invalidate one exact current-PID generation capability."""

        # Clear a pre-existing origin first, invalidate the structural lease, then
        # clear again to close a concurrent origin-mark race.  Each operation uses
        # captured closures; mutated public bindings are reported only after removal.
        trusted_origin_revoke(capability)
        try:
            trusted_core_revoke(capability)
        finally:
            trusted_origin_revoke(capability)
        require_pristine()

    public_bindings["revoke_trusted_generation_verification"] = revoke
    return revoke


revoke_trusted_generation_verification = _build_generation_revocation_authority()
del _build_generation_revocation_authority


class OpenRouterGenerationEvidence(BaseModel):
    """Allowlisted, self-hashed projection of the official generation response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0", "1.1"]
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
    retrieval_attempts: int = Field(
        ge=1,
        le=MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS,
    )
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
        completion_token_bound = (
            self.native_completion_tokens
            if self.native_completion_tokens is not None
            else self.completion_tokens
        )
        if (
            self.schema_version == "1.0"
            and self.reasoning_tokens is not None
            and self.reasoning_tokens > completion_token_bound
        ):
            raise ValueError("generation reasoning tokens exceed completion tokens")
        prompt_token_bound = (
            self.native_prompt_tokens
            if self.native_prompt_tokens is not None
            else self.prompt_tokens
        )
        if self.cached_tokens is not None and self.cached_tokens > prompt_token_bound:
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
        or not 1 <= retrieval_attempts <= MAX_GENERATION_EVIDENCE_RETRIEVAL_ATTEMPTS
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


def reconcile_noncrediting_smoke_generation_evidence(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
) -> OpenRouterGenerationEvidence:
    """Reconcile one owned UNKNOWN-envelope smoke without granting general credit."""

    usage_error = noncrediting_unknown_token_smoke_usage_error(usage_record)
    if usage_error is not None:
        raise GenerationEvidenceValidationError(
            f"noncrediting UNKNOWN-envelope smoke usage is invalid ({usage_error})"
        )
    return _reconcile_generation_evidence(
        evidence,
        usage_record=usage_record,
        expected_exact_model=expected_exact_model,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(expected_catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expected_discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
        require_runtime_attestation=True,
        allow_noncrediting_unknown_token_accounting=True,
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
    require_certification: bool = True,
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
        require_certification=require_certification,
    )


def _reconcile_noncrediting_smoke_generation_evidence_structural(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord,
    expected_exact_model: str,
    expected_canonical_model: str,
    expected_catalog_identity_binding_sha256: str,
    expected_discovery_evidence_sha256: str,
    expected_provider_name: str,
) -> OpenRouterGenerationEvidence:
    """Replay one serialized UNKNOWN-envelope smoke generation join without authority."""

    usage_error = structurally_noncrediting_unknown_token_smoke_usage_error(usage_record)
    if usage_error is not None:
        raise GenerationEvidenceValidationError(
            f"serialized noncrediting UNKNOWN-envelope smoke usage is invalid ({usage_error})"
        )
    return _reconcile_generation_evidence(
        evidence,
        usage_record=usage_record,
        expected_exact_model=expected_exact_model,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(expected_catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expected_discovery_evidence_sha256,
        expected_provider_name=expected_provider_name,
        require_runtime_attestation=False,
        allow_noncrediting_unknown_token_accounting=True,
    )


_TRUSTED_RECONCILE_GENERATION_EVIDENCE_STRUCTURAL = _reconcile_generation_evidence_structural
_TRUSTED_RECONCILE_NONCREDITING_SMOKE_GENERATION_EVIDENCE_STRUCTURAL = (
    _reconcile_noncrediting_smoke_generation_evidence_structural
)


def _reconcile_generation_expectation_structural(
    evidence: OpenRouterGenerationEvidence,
    *,
    expectation: GenerationReconciliationExpectation,
) -> OpenRouterGenerationEvidence:
    """Dispatch one frozen expectation without widening generic generation credit."""

    if (
        type(expectation) is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
        or GenerationReconciliationExpectation
        is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE
        or GenerationReconciliationExpectation.__init__
        is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_INIT
        or GenerationReconciliationExpectation.__post_init__
        is not _TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_POST_INIT
        or _GenerationReconciliationPolicy is not _TRUSTED_GENERATION_RECONCILIATION_POLICY_TYPE
        or tuple(_GenerationReconciliationPolicy)
        != _TRUSTED_GENERATION_RECONCILIATION_POLICY_VALUES
        or _reconcile_generation_expectation_structural
        is not _TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL
        or _reconcile_generation_evidence_structural
        is not _TRUSTED_RECONCILE_GENERATION_EVIDENCE_STRUCTURAL
        or _reconcile_noncrediting_smoke_generation_evidence_structural
        is not _TRUSTED_RECONCILE_NONCREDITING_SMOKE_GENERATION_EVIDENCE_STRUCTURAL
        or structurally_noncrediting_unknown_token_smoke_usage_error
        is not _TRUSTED_STRUCTURALLY_NONCREDITING_UNKNOWN_TOKEN_SMOKE_USAGE_ERROR
    ):
        raise GenerationEvidenceValidationError(
            "generation reconciliation dispatcher runtime is not pristine"
        )
    if (
        expectation.reconciliation_policy
        is _GenerationReconciliationPolicy.NONCREDITING_UNKNOWN_TOKEN_SMOKE
    ):
        if (
            not expectation.require_certification
            or structurally_noncrediting_unknown_token_smoke_usage_error(expectation.usage_record)
            is not None
        ):
            raise GenerationEvidenceValidationError(
                "noncrediting smoke reconciliation expectation is invalid"
            )
        return _reconcile_noncrediting_smoke_generation_evidence_structural(
            evidence,
            usage_record=expectation.usage_record,
            expected_exact_model=expectation.exact_model_id,
            expected_canonical_model=expectation.canonical_model_id,
            expected_catalog_identity_binding_sha256=(expectation.catalog_identity_binding_sha256),
            expected_discovery_evidence_sha256=expectation.discovery_evidence_sha256,
            expected_provider_name=expectation.expected_provider_name,
        )
    if expectation.reconciliation_policy is not _GenerationReconciliationPolicy.GENERIC:
        raise GenerationEvidenceValidationError(
            "generation reconciliation expectation policy is invalid"
        )
    return _reconcile_generation_evidence_structural(
        evidence,
        usage_record=expectation.usage_record,
        expected_exact_model=expectation.exact_model_id,
        expected_canonical_model=expectation.canonical_model_id,
        expected_catalog_identity_binding_sha256=(expectation.catalog_identity_binding_sha256),
        expected_discovery_evidence_sha256=expectation.discovery_evidence_sha256,
        expected_provider_name=expectation.expected_provider_name,
        require_certification=expectation.require_certification,
    )


_TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL = _reconcile_generation_expectation_structural
_TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_TYPE = GenerationReconciliationExpectation
_TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_INIT = GenerationReconciliationExpectation.__init__
_TRUSTED_GENERATION_RECONCILIATION_EXPECTATION_POST_INIT = (
    GenerationReconciliationExpectation.__post_init__
)
_TRUSTED_GENERATION_VERIFICATION_REQUEST_TYPE = GenerationVerificationRequest
_TRUSTED_GENERATION_VERIFICATION_REQUEST_INIT = GenerationVerificationRequest.__init__
_TRUSTED_GENERATION_VERIFICATION_REQUEST_POST_INIT = GenerationVerificationRequest.__post_init__
_TRUSTED_GENERATION_VERIFICATION_REQUEST_RECONCILIATION_EXPECTATION = (
    GenerationVerificationRequest.reconciliation_expectation
)
_TRUSTED_INITIAL_REAL_GENERATION_RECONCILIATION_EXPECTATION = (
    _initial_real_generation_reconciliation_expectation
)
_TRUSTED_GENERATION_RECONCILIATION_POLICY_TYPE = _GenerationReconciliationPolicy
_TRUSTED_GENERATION_RECONCILIATION_POLICY_VALUES = tuple(_GenerationReconciliationPolicy)


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
    require_certification: bool = True,
    allow_noncrediting_unknown_token_accounting: bool = False,
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
        (
            noncrediting_unknown_token_smoke_usage_error(usage_record)
            if require_runtime_attestation
            else structurally_noncrediting_unknown_token_smoke_usage_error(usage_record)
        )
        is None
        if allow_noncrediting_unknown_token_accounting
        else (
            is_generation_bindable_usage_record(usage_record)
            if require_certification
            else is_generation_reconcilable_usage_record(
                usage_record,
                require_certification=False,
            )
        )
        if require_runtime_attestation
        else (
            _is_structurally_generation_bindable_usage_record(usage_record)
            if require_certification
            else _is_structurally_generation_reconcilable_usage_record(
                usage_record,
                require_certification=False,
            )
        )
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
    _require_matching_generation_token_pair(evidence, usage_record)
    token_detail = usage_record.token_detail_accounting_evidence
    eventual_token_comparisons = (
        (
            evidence.reasoning_tokens,
            (
                token_detail.provider_reasoning_tokens
                if token_detail is not None
                else usage_record.reasoning_tokens
            ),
            GenerationReconciliationMismatchCode.REASONING_TOKENS,
        ),
        (
            evidence.cached_tokens,
            (
                token_detail.provider_cached_tokens
                if token_detail is not None
                else usage_record.cached_tokens
            ),
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


def _require_matching_generation_token_pair(
    evidence: OpenRouterGenerationEvidence,
    usage_record: UsageRecord,
) -> None:
    """Require one whole normalized or complete native prompt/completion tuple."""

    token_detail = usage_record.token_detail_accounting_evidence
    expected_pair = (
        (
            token_detail.provider_prompt_tokens,
            token_detail.provider_completion_tokens,
        )
        if token_detail is not None
        else (usage_record.prompt_tokens, usage_record.completion_tokens)
    )
    observed_pairs = [(evidence.prompt_tokens, evidence.completion_tokens)]
    if evidence.native_prompt_tokens is not None and evidence.native_completion_tokens is not None:
        observed_pairs.append(
            (
                evidence.native_prompt_tokens,
                evidence.native_completion_tokens,
            )
        )
    if expected_pair in observed_pairs:
        return
    mismatch_code = (
        GenerationReconciliationMismatchCode.PROMPT_TOKENS
        if all(prompt_tokens != expected_pair[0] for prompt_tokens, _ in observed_pairs)
        else GenerationReconciliationMismatchCode.COMPLETION_TOKENS
    )
    raise GenerationReconciliationMismatchError(mismatch_code)


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
        if (
            GenerationVerificationRequest.reconciliation_expectation
            is not _TRUSTED_GENERATION_VERIFICATION_REQUEST_RECONCILIATION_EXPECTATION
            or _reconcile_generation_expectation_structural
            is not _TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL
        ):
            raise GenerationEvidenceValidationError(
                "generation verification issue runtime is not pristine"
            )
        expectation = _TRUSTED_GENERATION_VERIFICATION_REQUEST_RECONCILIATION_EXPECTATION(request)
        _TRUSTED_RECONCILE_GENERATION_EXPECTATION_STRUCTURAL(
            attestation,
            expectation=expectation,
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
