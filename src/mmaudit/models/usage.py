"""Thread-safe request usage collection."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import threading
import weakref
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from itertools import pairwise
from types import FunctionType
from typing import Any, Literal, cast

from pydantic import BaseModel, ValidationError

from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.output_modes import supported_output_modes
from mmaudit.models.reasoning import INDEPENDENT_REASONING_COMPONENT_ENVELOPE_METHOD
from mmaudit.models.schemas import (
    ContextRequestEvidence,
    ContextRequestRelationship,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    StructuredOutputEvidence,
    StructuredOutputResponseFormat,
    UsageRecord,
)
from mmaudit.models.token_planning import RequestTokenPlan
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
)
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WHOLE_PROTOCOL_INDEXED_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_REQUEST_LIMIT_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_RECOVERY_REQUEST_LIMIT_RESERVATIONS = 33
_MAX_METERED_UNITS = 2**63 - 1
MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX = 999_999_999
_CANONICAL_SMOKE_RUN_INDEX_PATTERN = re.compile(r"^[1-9][0-9]{0,8}$")


def require_authenticated_runner_smoke_run_index(value: object) -> int:
    """Return one strict positive bounded index without accepting bools or coercion."""

    if type(value) is not int or value < 1 or value > MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX:
        raise ValueError(
            "authenticated runner smoke run index must be a strict integer from 1 through "
            f"{MAX_AUTHENTICATED_RUNNER_SMOKE_RUN_INDEX}"
        )
    return value


def parse_authenticated_runner_smoke_run_index(value: object) -> int:
    """Parse only canonical positive decimal text into a bounded smoke run index."""

    if type(value) is not str or _CANONICAL_SMOKE_RUN_INDEX_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "authenticated runner smoke run index must be canonical positive decimal text"
        )
    return require_authenticated_runner_smoke_run_index(int(value))


def _build_authrunner_usage_origin_scope_validator() -> tuple[
    Callable[[UsageRecord], str | None],
    Callable[[UsageRecord], bool],
    Callable[[str, object], str | None],
    Callable[[str, object], AuthrunnerNoncreditingUnknownTokenSmokeScope | None],
]:
    """Bind each closed AUTHRUNNER proof kind to its disjoint request namespace."""

    routes = {
        "RELEASE_PINNED_MODEL_BENCHMARK": (
            "RELEASE",
            re.compile(r"^authrunner\.candidate\.(?:primary|replay):case-[0-9a-f]{16}$"),
        ),
        "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION": (
            "RELEASE",
            re.compile(r"^cross-lineage-[0-9a-f]{64}$"),
        ),
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK": (
            "NONCREDITING_SMOKE",
            re.compile(
                r"^authrunner\.smoke\.r(?:[1-9][0-9]{0,8})\.candidate\."
                r"(?:primary|replay):[0-9a-f]{64}$"
            ),
        ),
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION": (
            "NONCREDITING_SMOKE",
            re.compile(
                r"^authrunner\.smoke\.r(?:[1-9][0-9]{0,8})\.judge\."
                r"(?:primary|replay):[0-9a-f]{64}$"
            ),
        ),
    }
    namespaces = tuple(pattern for _scope, pattern in routes.values())
    smoke_proof_kinds = frozenset(
        proof_kind
        for proof_kind, (scope, _pattern) in routes.items()
        if scope == "NONCREDITING_SMOKE"
    )
    smoke_namespaces = tuple(
        pattern for scope, pattern in routes.values() if scope == "NONCREDITING_SMOKE"
    )
    usage_record_type = UsageRecord

    def has_noncrediting_smoke_coordinate(record: UsageRecord) -> bool:
        if type(record) is not usage_record_type:
            return False
        proof_kind = record.routing.get("privacy_source_proof_kind")
        return bool(
            any(pattern.fullmatch(record.request_id) for pattern in smoke_namespaces)
            or (type(proof_kind) is str and proof_kind in smoke_proof_kinds)
        )

    def classify_coordinates(request_id: str, proof_kind: object) -> str | None:
        """Classify one request/proof pair through the canonical closed route table."""

        request_uses_closed_namespace = bool(
            type(request_id) is str
            and any(pattern.fullmatch(request_id) is not None for pattern in namespaces)
        )
        if not isinstance(proof_kind, str):
            if request_uses_closed_namespace:
                raise ValueError("AUTHRUNNER request namespace lacks its closed privacy proof kind")
            return None
        if not request_uses_closed_namespace:
            if proof_kind in {
                "RELEASE_PINNED_MODEL_BENCHMARK",
                "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
            }:
                return "RELEASE"
            if proof_kind not in {
                "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
                "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            }:
                return None
        route = routes.get(proof_kind)
        if route is None:
            raise ValueError("AUTHRUNNER request namespace lacks its closed privacy proof kind")
        scope, request_pattern = route
        if type(request_id) is not str or request_pattern.fullmatch(request_id) is None:
            raise ValueError(
                "AUTHRUNNER privacy proof kind does not match its closed request namespace"
            )
        return scope

    def validate(record: UsageRecord) -> str | None:
        if type(record) is not usage_record_type:
            return None
        return classify_coordinates(
            record.request_id,
            record.routing.get("privacy_source_proof_kind"),
        )

    def classify_smoke_coordinates(
        request_id: str,
        proof_kind: object,
    ) -> AuthrunnerNoncreditingUnknownTokenSmokeScope | None:
        uses_smoke_namespace = bool(
            type(request_id) is str
            and any(pattern.fullmatch(request_id) is not None for pattern in smoke_namespaces)
        )
        uses_smoke_proof = type(proof_kind) is str and proof_kind in smoke_proof_kinds
        if not uses_smoke_namespace and not uses_smoke_proof:
            return None
        try:
            scope = classify_coordinates(request_id, proof_kind)
        except ValueError:
            return "INVALID"
        if scope != "NONCREDITING_SMOKE":
            return "INVALID"
        return (
            "CANDIDATE"
            if proof_kind == "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"
            else (
                "JUDGE"
                if proof_kind == "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"
                else "INVALID"
            )
        )

    return (
        validate,
        has_noncrediting_smoke_coordinate,
        classify_coordinates,
        classify_smoke_coordinates,
    )


(
    _authrunner_usage_origin_scope,
    _has_authrunner_noncrediting_smoke_coordinate,
    _authrunner_request_origin_scope,
    _authrunner_noncrediting_smoke_request_scope,
) = _build_authrunner_usage_origin_scope_validator()
del _build_authrunner_usage_origin_scope_validator


AuthrunnerNoncreditingUnknownTokenSmokeScope = Literal["CANDIDATE", "JUDGE", "INVALID"]


def _build_authrunner_noncrediting_unknown_token_smoke_scope_classifier() -> Callable[
    [UsageRecord],
    AuthrunnerNoncreditingUnknownTokenSmokeScope | None,
]:
    origin_scope_validator = _authrunner_usage_origin_scope
    has_smoke_coordinate = _has_authrunner_noncrediting_smoke_coordinate
    accounting_method = INDEPENDENT_REASONING_COMPONENT_ENVELOPE_METHOD
    usage_record_type = UsageRecord
    real_evidence = ExecutionEvidenceKind.REAL
    proof_scopes: tuple[
        tuple[str, Literal["CANDIDATE", "JUDGE"]],
        ...,
    ] = (
        ("PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK", "CANDIDATE"),
        ("PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION", "JUDGE"),
    )

    def classify(
        record: UsageRecord,
    ) -> AuthrunnerNoncreditingUnknownTokenSmokeScope | None:
        """Classify the exact v3 smoke surface without treating validity as scope.

        This pure classifier deliberately checks only closed AUTHRUNNER coordinates and
        request-surface markers. Strict usage validation remains a separate decision, so
        malformed smoke evidence cannot escape a safety cutoff by failing validation.
        """

        if type(record) is not usage_record_type:
            return None
        proof_kind = record.routing.get("privacy_source_proof_kind")
        try:
            origin_scope = origin_scope_validator(record)
        except ValueError:
            return "INVALID" if has_smoke_coordinate(record) else None
        if origin_scope != "NONCREDITING_SMOKE":
            return None
        if (
            record.execution_evidence is not real_evidence
            or record.role != "model_benchmark"
            or type(proof_kind) is not str
        ):
            return "INVALID"
        raw_plan = record.routing.get("request_token_plan")
        if (
            type(raw_plan) is not dict
            or raw_plan.get("schema_version") != "3.0"
            or raw_plan.get("request_id") != record.request_id
            or raw_plan.get("role") != record.role
            or raw_plan.get("token_detail_accounting_method") != accounting_method
            or type(raw_plan.get("requested_surface_count")) is not int
            or type(raw_plan.get("wire_max_tokens")) is not int
            or record.token_detail_accounting_evidence is None
        ):
            return "INVALID"
        return next(
            (scope for expected_proof, scope in proof_scopes if proof_kind == expected_proof),
            "INVALID",
        )

    return classify


authrunner_noncrediting_unknown_token_smoke_scope = (
    _build_authrunner_noncrediting_unknown_token_smoke_scope_classifier()
)
del _build_authrunner_noncrediting_unknown_token_smoke_scope_classifier


def candidate_falsifier_role_prefix(candidate_id: str) -> str:
    """Return the host-controlled role prefix binding a review to one candidate."""

    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate falsifier role requires a non-empty candidate ID")
    candidate_sha256 = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    return f"candidate_falsifier:{candidate_sha256}"


def candidate_falsifier_role(candidate_id: str, reviewer_index: int) -> str:
    """Return the exact per-candidate role for one of two independent reviewers."""

    if reviewer_index not in {1, 2}:
        raise ValueError("candidate falsifier reviewer index must be one or two")
    return f"{candidate_falsifier_role_prefix(candidate_id)}:reviewer_{reviewer_index}"


def source_backed_whole_protocol_context(
    record: UsageRecord,
) -> ContextRequestEvidence | None:
    """Return exact typed source evidence for one canonical whole-protocol review."""

    if _WHOLE_PROTOCOL_INDEXED_ROLE.fullmatch(record.role) is None:
        return None
    raw_evidence = record.routing.get("context_request_evidence")
    if not isinstance(raw_evidence, dict):
        return None
    try:
        evidence = ContextRequestEvidence.model_validate(raw_evidence)
    except ValueError:
        return None
    if (
        evidence.request_id != record.request_id
        or evidence.request_role != record.role
        or evidence.context_role != "whole_protocol_review"
        or evidence.relationship is not ContextRequestRelationship.WHOLE_PROTOCOL_INDEXED
        or record.user_prompt_sha256 is None
        or evidence.rendered_sha256 != record.user_prompt_sha256
        or evidence.source_bytes <= 0
        or record.routing.get("context_request_evidence_sha256") != evidence.evidence_sha256
    ):
        return None
    return evidence


def usage_requires_audit_policy_evidence(record: UsageRecord) -> bool:
    """Require policy custody for every detached REAL production-audit usage record.

    Release-pinned qualification benchmarks have a narrower live OpenRouter exemption that
    rechecks an opaque provenance observation and the complete provider-visible request shape.
    Audit reports, model-execution artifacts, scheduler evidence, and manifests are not benchmark
    custody boundaries, so caller-asserted roles, classifications, proof kinds, or hashes cannot
    recreate that live exemption after serialization.
    """

    if type(record) is not UsageRecord:
        return True
    return record.execution_evidence is ExecutionEvidenceKind.REAL


def is_creditable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Return whether one completed provider request has strict, coherent evidence."""

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
    )


def is_recovery_creditable_usage_record(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Return whether owned valid usage is strict at one external recovery position."""

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
        recovery_request_limit_scope=request_limit_scope,
        recovery_request_limit_count_before=request_limit_count_before,
    )


def is_accountable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
) -> bool:
    """Return whether exact paid-attempt accounting is safe without review credit."""

    return _is_accountable_usage_record(
        record,
        require_real=require_real,
        require_runtime_attestation=True,
    )


def is_structurally_accountable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
) -> bool:
    """Validate serialized accounting evidence without granting REAL authority."""

    return _is_accountable_usage_record(
        record,
        require_real=require_real,
        require_runtime_attestation=False,
    )


def is_recovery_accountable_usage_record(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
    require_real: bool = False,
) -> bool:
    """Return whether owned usage is accountable at one externally supplied chain position."""

    return _is_accountable_usage_record(
        record,
        require_real=require_real,
        require_runtime_attestation=True,
        recovery_request_limit_scope=request_limit_scope,
        recovery_request_limit_count_before=request_limit_count_before,
    )


def is_structurally_recovery_accountable_usage_record(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
    require_real: bool = False,
) -> bool:
    """Validate serialized recovery accounting shape without granting runtime authority."""

    return _is_accountable_usage_record(
        record,
        require_real=require_real,
        require_runtime_attestation=False,
        recovery_request_limit_scope=request_limit_scope,
        recovery_request_limit_count_before=request_limit_count_before,
    )


def _is_accountable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool,
    require_runtime_attestation: bool,
    recovery_request_limit_scope: str | None = None,
    recovery_request_limit_count_before: int | None = None,
) -> bool:
    recovery_mode = recovery_request_limit_scope is not None
    if recovery_mode != (recovery_request_limit_count_before is not None):
        return False
    if record.execution_evidence not in {
        ExecutionEvidenceKind.REAL,
        ExecutionEvidenceKind.MOCK,
    }:
        return False
    if require_real and record.execution_evidence is not ExecutionEvidenceKind.REAL:
        return False
    if (
        record.execution_evidence is ExecutionEvidenceKind.REAL
        and require_runtime_attestation
        and not _has_owned_real_usage_attestation(record)
    ):
        return False
    if (
        record.started_at is None
        or record.ended_at is None
        or record.ended_at < record.started_at
        or record.timestamp != record.started_at
        or record.latency_ms is None
        or record.retry_count != record.attempts - 1
        or record.user_prompt_sha256 is None
        or record.request_body_sha256 is None
        or record.schema_sha256 is None
        or record.accounted_cost_usd_exact is None
    ):
        return False
    try:
        accounted = Decimal(record.accounted_cost_usd_exact)
        reported = (
            Decimal(record.reported_cost_usd_exact)
            if record.reported_cost_usd_exact is not None
            else None
        )
    except InvalidOperation:
        return False
    if (
        accounted < 0
        or float(accounted) != record.accounted_cost_usd
        or (reported is None) != (record.reported_cost_usd is None)
        or (
            reported is not None
            and (
                reported < 0 or reported > accounted or float(reported) != record.reported_cost_usd
            )
        )
    ):
        return False
    raw_context = record.routing.get("context_request_evidence")
    try:
        context = ContextRequestEvidence.model_validate(raw_context)
        plan = (
            recovery_request_token_plan_from_usage(
                record,
                request_limit_scope=recovery_request_limit_scope,
                request_limit_count_before=recovery_request_limit_count_before,
            )
            if recovery_mode
            and recovery_request_limit_scope is not None
            and recovery_request_limit_count_before is not None
            else request_token_plan_from_usage(record)
        )
        if plan is None:
            return False
        token_evidence = atomic_token_reservations_from_usage(record, plan)
        request_evidence = (
            recovery_atomic_request_limit_reservations_from_usage(
                record,
                plan,
                request_limit_scope=recovery_request_limit_scope,
                request_limit_count_before=recovery_request_limit_count_before,
            )
            if recovery_mode
            and recovery_request_limit_scope is not None
            and recovery_request_limit_count_before is not None
            else atomic_request_limit_reservations_from_usage(record, plan)
        )
    except (TypeError, ValueError):
        return False
    return (
        context.request_id == record.request_id
        and context.request_role == record.role
        and record.routing.get("context_request_evidence_sha256") == context.evidence_sha256
        and len(token_evidence) == record.attempts
        and len(request_evidence) == record.attempts
        and tuple(item.request_id for item in token_evidence)
        == tuple(item.request_id for item in request_evidence)
    )


def is_generation_bindable_usage_record(record: UsageRecord) -> bool:
    """Return whether REAL certification transport evidence may fetch generation metadata."""

    return is_generation_reconcilable_usage_record(
        record,
        require_certification=True,
    )


def is_generation_reconcilable_usage_record(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> bool:
    """Return whether owned REAL transport evidence may be reconciled."""

    if not isinstance(require_certification, bool):
        return False
    return _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
        allow_unbound_real=True,
    )


NoncreditingUnknownTokenSmokeUsageError = Literal[
    "UsageTypeError",
    "UsageOriginError",
    "UsageEnvelopeError",
    "UnexpectedGeneralCreditability",
]


def noncrediting_unknown_token_smoke_usage_error(
    record: UsageRecord,
) -> NoncreditingUnknownTokenSmokeUsageError | None:
    """Validate one owned v3 UNKNOWN-envelope smoke record without granting credit."""

    if type(record) is not UsageRecord:
        return "UsageTypeError"
    try:
        origin_scope = _authrunner_usage_origin_scope(record)
    except ValueError:
        return "UsageOriginError"
    if (
        record.execution_evidence is not ExecutionEvidenceKind.REAL
        or not _has_owned_real_usage_attestation(record)
        or not _has_authrunner_owned_real_usage_origin(record)
        or origin_scope != "NONCREDITING_SMOKE"
    ):
        return "UsageOriginError"
    if not _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=True,
        allow_unbound_real=True,
        allow_noncrediting_unknown_token_accounting=True,
    ):
        return "UsageEnvelopeError"
    if is_creditable_usage_record(
        record,
        require_real=True,
        require_certification=True,
    ):
        return "UnexpectedGeneralCreditability"
    return None


def structurally_noncrediting_unknown_token_smoke_usage_error(
    record: UsageRecord,
) -> NoncreditingUnknownTokenSmokeUsageError | None:
    """Replay a serialized v3 UNKNOWN-envelope smoke without minting runtime credit."""

    if type(record) is not UsageRecord:
        return "UsageTypeError"
    try:
        origin_scope = _authrunner_usage_origin_scope(record)
    except ValueError:
        return "UsageOriginError"
    if (
        record.execution_evidence is not ExecutionEvidenceKind.REAL
        or origin_scope != "NONCREDITING_SMOKE"
    ):
        return "UsageOriginError"
    if not _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=True,
        allow_unbound_real=True,
        require_runtime_attestation=False,
        allow_noncrediting_unknown_token_accounting=True,
    ):
        return "UsageEnvelopeError"
    if is_structurally_creditable_usage_record(
        record,
        require_real=True,
        require_certification=True,
    ):
        return "UnexpectedGeneralCreditability"
    return None


StructuredOutputRoutingFailureCode = Literal[
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_TYPE",
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_SCHEMA",
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_CANONICAL",
    "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED",
    "STRUCTURED_OUTPUT_ROUTING:TRUNCATED",
    "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH",
    "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS",
    "STRUCTURED_OUTPUT_ROUTING:SELECTED_PROVIDER_ENDPOINT",
    "STRUCTURED_OUTPUT_ROUTING:PROMPT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_BODY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:SCHEMA_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:ORIGINAL_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:VALIDATED_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:PROVIDER_POLICY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:ENDPOINT_SNAPSHOT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:OUTPUT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED_ROUTING",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRE_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRED_PROVIDER_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REASONING_REQUEST_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_RESPONSE_FORMAT",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_PROTOCOL_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_REQUEST_BODY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_ORIGINAL_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_VALIDATED_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_OUTPUT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_MODE",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_PARAMETER_SUBSET",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRE_PARAMETERS",
]

STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES: tuple[StructuredOutputRoutingFailureCode, ...] = (
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_TYPE",
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_SCHEMA",
    "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_CANONICAL",
    "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED",
    "STRUCTURED_OUTPUT_ROUTING:TRUNCATED",
    "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH",
    "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS",
    "STRUCTURED_OUTPUT_ROUTING:SELECTED_PROVIDER_ENDPOINT",
    "STRUCTURED_OUTPUT_ROUTING:PROMPT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_BODY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:SCHEMA_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:ORIGINAL_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:VALIDATED_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:PROVIDER_POLICY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:ENDPOINT_SNAPSHOT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:OUTPUT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED_ROUTING",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRE_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRED_PROVIDER_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REASONING_REQUEST_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_RESPONSE_FORMAT",
    "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_PROTOCOL_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_REQUEST_BODY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_ORIGINAL_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_VALIDATED_RESPONSE_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_OUTPUT_CAPABILITY_SHA256",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_MODE",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_PARAMETER_SUBSET",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS",
    "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRE_PARAMETERS",
)

StrictUsageFailureCode = (
    Literal[
        "RECOVERY_SCOPE",
        "EXECUTION",
        "RUNTIME_ATTESTATION",
        "STATUS",
        "REQUIRED_FIELDS",
        "TIMING",
        "HASHES",
        "TOKEN_ALGEBRA",
        "COST",
        "ENDPOINT",
        "ROUTER_IDENTITY",
        "PRIVACY_ROUTING",
        "TOKEN_PLAN_ROUTING",
        "REPAIR_TEMPORAL_ROUTING",
        "ALIAS",
        "CERTIFICATION",
        "BOUND_IDENTITY",
        "CERTIFICATION_ROUTE",
        "SMOKE_SCOPE",
        "UNEXPECTED_GENERAL_CREDITABILITY",
    ]
    | StructuredOutputRoutingFailureCode
)

STRICT_USAGE_FAILURE_CODES: tuple[StrictUsageFailureCode, ...] = (
    "RECOVERY_SCOPE",
    "EXECUTION",
    "RUNTIME_ATTESTATION",
    "STATUS",
    "REQUIRED_FIELDS",
    "TIMING",
    "HASHES",
    "TOKEN_ALGEBRA",
    "COST",
    "ENDPOINT",
    "ROUTER_IDENTITY",
    "PRIVACY_ROUTING",
    *STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES,
    "TOKEN_PLAN_ROUTING",
    "REPAIR_TEMPORAL_ROUTING",
    "ALIAS",
    "CERTIFICATION",
    "BOUND_IDENTITY",
    "CERTIFICATION_ROUTE",
    "SMOKE_SCOPE",
    "UNEXPECTED_GENERAL_CREDITABILITY",
)


def _strict_usage_record_failure_code(
    record: UsageRecord,
    *,
    require_real: bool,
    require_certification: bool,
    allow_unbound_real: bool,
    require_runtime_attestation: bool = True,
    allow_noncrediting_unknown_token_accounting: bool = False,
    recovery_request_limit_scope: str | None = None,
    recovery_request_limit_count_before: int | None = None,
    validate_recovery_coordinates: Callable[..., None],
    has_owned_real_attestation: Callable[[UsageRecord], bool],
    has_valid_privacy_routing: Callable[[UsageRecord], bool],
    structured_output_routing_failure_code: Callable[
        [UsageRecord], StructuredOutputRoutingFailureCode | None
    ],
    has_valid_token_plan_routing: Callable[..., bool],
    is_sha256: Callable[[Any], bool],
    has_valid_bound_identity: Callable[[UsageRecord], bool],
    real_evidence: ExecutionEvidenceKind,
    mock_evidence: ExecutionEvidenceKind,
    valid_status: ModelRequestValidationStatus,
    canonical_bound_strength: ModelIdentityStrength,
    decimal_type: type[Decimal],
    invalid_operation_type: type[InvalidOperation],
    math_isfinite: Callable[[float], bool],
    hashlib_sha256: Callable[..., Any],
    json_dumps: Callable[..., str],
    sha256_pattern: re.Pattern[str],
) -> StrictUsageFailureCode | None:
    """Return the first closed reason an exact usage record is not strict."""

    recovery_mode = recovery_request_limit_scope is not None
    if recovery_mode != (recovery_request_limit_count_before is not None):
        return "RECOVERY_SCOPE"
    if recovery_mode:
        assert recovery_request_limit_scope is not None
        assert recovery_request_limit_count_before is not None
        try:
            validate_recovery_coordinates(
                record,
                request_limit_scope=recovery_request_limit_scope,
                request_limit_count_before=recovery_request_limit_count_before,
            )
        except ValueError:
            return "RECOVERY_SCOPE"
    if record.execution_evidence not in {
        real_evidence,
        mock_evidence,
    }:
        return "EXECUTION"
    if require_real and record.execution_evidence is not real_evidence:
        return "EXECUTION"
    if (
        record.execution_evidence is real_evidence
        and require_runtime_attestation
        and not has_owned_real_attestation(record)
    ):
        return "RUNTIME_ATTESTATION"
    if type(record.routing) is not dict:
        return "REQUIRED_FIELDS"
    if (
        record.status != "success"
        or record.validation_status is not valid_status
        or record.substitution_detected
        or record.provider_error_classification is not None
        or record.finish_reason != "stop"
    ):
        return "STATUS"
    required_strings = (
        record.request_id,
        record.role,
        record.requested_model,
        record.returned_model,
        record.actual_model,
        record.provider,
        record.actual_provider_endpoint,
        record.openrouter_generation_id,
    )
    if any(type(value) is not str or not value.strip() for value in required_strings):
        return "REQUIRED_FIELDS"
    if (
        record.started_at is None
        or record.ended_at is None
        or record.ended_at < record.started_at
        or record.timestamp != record.started_at
        or record.latency_ms is None
        or record.retry_count is None
        or record.retry_count != record.attempts - 1
    ):
        return "TIMING"
    if not all(
        type(value) is str and sha256_pattern.fullmatch(value) is not None
        for value in (
            record.prompt_sha256,
            record.response_sha256,
            record.validated_response_sha256,
            record.request_body_sha256,
            record.schema_sha256,
        )
    ):
        return "HASHES"
    if (
        record.prompt_tokens <= 0
        or record.completion_tokens <= 0
        or record.total_tokens != record.prompt_tokens + record.completion_tokens
        or record.cached_tokens > record.prompt_tokens
    ):
        return "TOKEN_ALGEBRA"
    if (
        record.reported_cost_usd is None
        or not math_isfinite(record.reported_cost_usd)
        or not math_isfinite(record.accounted_cost_usd)
        or record.accounted_cost_usd + 1e-12 < record.reported_cost_usd
    ):
        return "COST"
    if record.execution_evidence is real_evidence:
        if record.reported_cost_usd_exact is None or record.accounted_cost_usd_exact is None:
            return "COST"
        try:
            exact_reported = decimal_type(record.reported_cost_usd_exact)
            exact_accounted = decimal_type(record.accounted_cost_usd_exact)
        except invalid_operation_type:
            return "COST"
        if (
            exact_accounted < exact_reported
            or float(exact_reported) != record.reported_cost_usd
            or float(exact_accounted) != record.accounted_cost_usd
        ):
            return "COST"
    actual_endpoint = record.actual_provider_endpoint
    if type(actual_endpoint) is not str:
        return "ENDPOINT"
    if record.configured_provider_endpoints and (
        any(type(endpoint) is not str for endpoint in record.configured_provider_endpoints)
        or actual_endpoint.casefold()
        not in {endpoint.casefold() for endpoint in record.configured_provider_endpoints}
    ):
        return "ENDPOINT"
    routing = record.routing
    if not (
        routing.get("generation_id") == record.openrouter_generation_id
        and routing.get("selected_model") == record.actual_model
        and routing.get("selected_provider_endpoint") == actual_endpoint
        and routing.get("router_strategy") in {"direct", "fallback"}
        and routing.get("finish_reason") == record.finish_reason
        and routing.get("schema_sha256") == record.schema_sha256
        and is_sha256(routing.get("router_metadata_sha256"))
        and is_sha256(routing.get("provider_policy_sha256"))
        and routing.get("validation_status") == "valid"
    ):
        return "ROUTER_IDENTITY"
    if not has_valid_privacy_routing(record):
        return "PRIVACY_ROUTING"
    structured_output_failure = structured_output_routing_failure_code(record)
    if structured_output_failure is not None:
        return structured_output_failure
    if not has_valid_token_plan_routing(
        record,
        recovery_request_limit_scope=recovery_request_limit_scope,
        recovery_request_limit_count_before=recovery_request_limit_count_before,
        allow_noncrediting_unknown_token_accounting=(allow_noncrediting_unknown_token_accounting),
    ):
        return "TOKEN_PLAN_ROUTING"
    if not (
        routing.get("repair_used") is False
        and routing.get("repair_request") is False
        and routing.get("request_started_at") == record.started_at.isoformat()
        and routing.get("request_ended_at") == record.ended_at.isoformat()
        and routing.get("latency_ms") == record.latency_ms
    ):
        return "REPAIR_TEMPORAL_ROUTING"
    aliases = routing.get("accepted_model_aliases")
    if record.returned_model != record.requested_model and (
        not isinstance(aliases, list)
        or aliases != sorted(set(aliases))
        or record.returned_model not in aliases
        or record.actual_model not in aliases
        or routing.get("provisional_identity_strength") != canonical_bound_strength.value
    ):
        return "ALIAS"
    certification_request = routing.get("certification_request") is True
    if require_certification and not certification_request:
        return "CERTIFICATION"
    if not certification_request:
        if (
            not allow_unbound_real
            and record.execution_evidence is real_evidence
            and not has_valid_bound_identity(record)
        ):
            return "BOUND_IDENTITY"
        return None
    canonical_model = routing.get("canonical_model")
    actual_model = record.actual_model
    expected_identity_hash = (
        hashlib_sha256(
            json_dumps(
                {
                    "canonical_slug": canonical_model,
                    "id": record.requested_model,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if isinstance(canonical_model, str)
        else None
    )
    if not allow_unbound_real and not has_valid_bound_identity(record):
        return "BOUND_IDENTITY"
    if not (
        not record.fallback_used
        and actual_model in {record.requested_model, canonical_model}
        and routing.get("catalog_identity_binding_sha256") == expected_identity_hash
        and len(record.configured_provider_endpoints) == 1
        and routing.get("provider_fallbacks_allowed") is False
        and routing.get("router_strategy") == "direct"
        and routing.get("router_attempt") == 1
        and routing.get("router_attempt_count") == 1
        and routing.get("router_pipeline") == []
        and is_sha256(routing.get("endpoint_snapshot_sha256"))
        and is_sha256(routing.get("endpoint_pricing_sha256"))
        and is_sha256(routing.get("catalog_identity_binding_sha256"))
        and is_sha256(routing.get("catalog_snapshot_sha256"))
        and is_sha256(routing.get("discovery_provenance_sha256"))
        and is_sha256(routing.get("discovery_evidence_sha256"))
    ):
        return "CERTIFICATION_ROUTE"
    return None


def _build_strict_usage_record_validators() -> tuple[
    Callable[..., bool],
    Callable[..., tuple[StrictUsageFailureCode, ...]],
]:
    """Close strict acceptance and diagnostics over one immutable evaluator."""

    failure_code = _strict_usage_record_failure_code
    failure_codes = STRICT_USAGE_FAILURE_CODES
    module_globals = globals()
    validate_recovery_coordinates = _validate_recovery_request_limit_coordinates
    owned_attestation_predicate = _has_owned_real_usage_attestation
    privacy_routing_predicate = _has_valid_privacy_routing
    structured_output_routing_predicate = _has_valid_structured_output_routing
    structured_output_routing_failure = _structured_output_routing_failure_code
    token_plan_routing_predicate = _has_valid_token_plan_routing
    sha256_predicate = _is_sha256
    bound_identity_predicate = _has_valid_bound_identity
    nested_helpers = (
        (
            "_validate_recovery_request_limit_coordinates",
            validate_recovery_coordinates,
        ),
        ("_has_owned_real_usage_attestation", owned_attestation_predicate),
        ("_has_valid_privacy_routing", privacy_routing_predicate),
        ("_has_valid_structured_output_routing", structured_output_routing_predicate),
        (
            "_structured_output_routing_failure_code",
            structured_output_routing_failure,
        ),
        ("_has_valid_token_plan_routing", token_plan_routing_predicate),
        ("_is_sha256", sha256_predicate),
        ("_has_valid_bound_identity", bound_identity_predicate),
    )
    execution_evidence_type = ExecutionEvidenceKind
    real_evidence = ExecutionEvidenceKind.REAL
    mock_evidence = ExecutionEvidenceKind.MOCK
    validation_status_type = ModelRequestValidationStatus
    valid_status = ModelRequestValidationStatus.VALID
    identity_strength_type = ModelIdentityStrength
    canonical_bound_strength = ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND
    decimal_type = Decimal
    invalid_operation_type = InvalidOperation
    math_module = math
    math_isfinite = math.isfinite
    hashlib_module = hashlib
    hashlib_sha256 = hashlib.sha256
    json_module = json
    json_dumps = json.dumps
    sha256_pattern = _SHA256
    usage_record_type = UsageRecord
    origin_scope_validator = _authrunner_usage_origin_scope
    authrunner_attestation_predicate = _has_authrunner_owned_real_usage_origin

    def evaluator_boundary_is_pristine() -> bool:
        return bool(
            all(module_globals.get(name) is helper for name, helper in nested_helpers)
            and module_globals.get("ExecutionEvidenceKind") is execution_evidence_type
            and ExecutionEvidenceKind.REAL is real_evidence
            and ExecutionEvidenceKind.MOCK is mock_evidence
            and module_globals.get("ModelRequestValidationStatus") is validation_status_type
            and ModelRequestValidationStatus.VALID is valid_status
            and module_globals.get("ModelIdentityStrength") is identity_strength_type
            and (
                ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND is canonical_bound_strength
            )
            and module_globals.get("Decimal") is decimal_type
            and module_globals.get("InvalidOperation") is invalid_operation_type
            and module_globals.get("math") is math_module
            and math.isfinite is math_isfinite
            and module_globals.get("hashlib") is hashlib_module
            and hashlib.sha256 is hashlib_sha256
            and module_globals.get("json") is json_module
            and json.dumps is json_dumps
            and module_globals.get("_SHA256") is sha256_pattern
            and module_globals.get("UsageRecord") is usage_record_type
            and module_globals.get("_authrunner_usage_origin_scope") is origin_scope_validator
            and (
                module_globals.get("_has_owned_real_usage_attestation")
                is owned_attestation_predicate
            )
            and (
                module_globals.get("_has_authrunner_owned_real_usage_origin")
                is authrunner_attestation_predicate
            )
        )

    def evaluate(
        record: UsageRecord,
        *,
        require_real: bool,
        require_certification: bool,
        allow_unbound_real: bool,
        require_runtime_attestation: bool = True,
        allow_noncrediting_unknown_token_accounting: bool = False,
        recovery_request_limit_scope: str | None = None,
        recovery_request_limit_count_before: int | None = None,
    ) -> StrictUsageFailureCode | None:
        return failure_code(
            record,
            require_real=require_real,
            require_certification=require_certification,
            allow_unbound_real=allow_unbound_real,
            require_runtime_attestation=require_runtime_attestation,
            allow_noncrediting_unknown_token_accounting=(
                allow_noncrediting_unknown_token_accounting
            ),
            recovery_request_limit_scope=recovery_request_limit_scope,
            recovery_request_limit_count_before=recovery_request_limit_count_before,
            validate_recovery_coordinates=validate_recovery_coordinates,
            has_owned_real_attestation=owned_attestation_predicate,
            has_valid_privacy_routing=privacy_routing_predicate,
            structured_output_routing_failure_code=structured_output_routing_failure,
            has_valid_token_plan_routing=token_plan_routing_predicate,
            is_sha256=sha256_predicate,
            has_valid_bound_identity=bound_identity_predicate,
            real_evidence=real_evidence,
            mock_evidence=mock_evidence,
            valid_status=valid_status,
            canonical_bound_strength=canonical_bound_strength,
            decimal_type=decimal_type,
            invalid_operation_type=invalid_operation_type,
            math_isfinite=math_isfinite,
            hashlib_sha256=hashlib_sha256,
            json_dumps=json_dumps,
            sha256_pattern=sha256_pattern,
        )

    def is_strict_usage_record(
        record: UsageRecord,
        *,
        require_real: bool,
        require_certification: bool,
        allow_unbound_real: bool,
        require_runtime_attestation: bool = True,
        allow_noncrediting_unknown_token_accounting: bool = False,
        recovery_request_limit_scope: str | None = None,
        recovery_request_limit_count_before: int | None = None,
    ) -> bool:
        """Return whether the one source-of-truth strict usage evaluator accepts."""

        if not evaluator_boundary_is_pristine():
            return False
        failure = evaluate(
            record,
            require_real=require_real,
            require_certification=require_certification,
            allow_unbound_real=allow_unbound_real,
            require_runtime_attestation=require_runtime_attestation,
            allow_noncrediting_unknown_token_accounting=(
                allow_noncrediting_unknown_token_accounting
            ),
            recovery_request_limit_scope=recovery_request_limit_scope,
            recovery_request_limit_count_before=recovery_request_limit_count_before,
        )
        return failure is None and evaluator_boundary_is_pristine()

    def smoke_usage_diagnostics(
        record: UsageRecord,
        *,
        require_runtime_attestation: bool,
    ) -> tuple[StrictUsageFailureCode, ...]:
        """Return one bounded smoke usage failure code without exposing raw evidence."""

        if (
            not evaluator_boundary_is_pristine()
            or type(record) is not usage_record_type
            or type(require_runtime_attestation) is not bool
        ):
            return ("REQUIRED_FIELDS",)
        try:
            origin_scope = origin_scope_validator(record)
        except ValueError:
            return ("SMOKE_SCOPE",)
        if record.execution_evidence is not real_evidence or origin_scope != "NONCREDITING_SMOKE":
            return ("SMOKE_SCOPE",)
        if require_runtime_attestation and (not owned_attestation_predicate(record)):
            return ("RUNTIME_ATTESTATION",)
        failure = evaluate(
            record,
            require_real=True,
            require_certification=True,
            allow_unbound_real=True,
            require_runtime_attestation=require_runtime_attestation,
            allow_noncrediting_unknown_token_accounting=True,
        )
        if not evaluator_boundary_is_pristine():
            return ("REQUIRED_FIELDS",)
        if failure is not None:
            return (failure,) if failure in failure_codes else ("REQUIRED_FIELDS",)
        unexpected_credit = (
            evaluate(
                record,
                require_real=True,
                require_certification=True,
                allow_unbound_real=False,
                require_runtime_attestation=require_runtime_attestation,
                allow_noncrediting_unknown_token_accounting=False,
            )
            is None
        )
        if not evaluator_boundary_is_pristine():
            return ("REQUIRED_FIELDS",)
        return ("UNEXPECTED_GENERAL_CREDITABILITY",) if unexpected_credit else ()

    return is_strict_usage_record, smoke_usage_diagnostics


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def request_token_plan_from_usage(record: UsageRecord) -> RequestTokenPlan | None:
    """Return strict plan evidence, rejecting any present but incoherent projection."""

    plan = _request_token_plan_evidence_from_usage(record)
    if plan is not None:
        atomic_request_limit_reservations_from_usage(record, plan)
    return plan


def recovery_request_token_plan_from_usage(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> RequestTokenPlan | None:
    """Return strict plan evidence for one externally anchored recovery-count position.

    The supplied scope and starting count are comparison inputs only. Serialized usage cannot
    select them, and this parser does not grant scheduler, dispatch, recovery, or review authority.
    """

    _validate_recovery_request_limit_coordinates(
        record,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=request_limit_count_before,
    )
    plan = _request_token_plan_evidence_from_usage(record)
    if plan is not None:
        recovery_atomic_request_limit_reservations_from_usage(
            record,
            plan,
            request_limit_scope=request_limit_scope,
            request_limit_count_before=request_limit_count_before,
        )
    return plan


def _request_token_plan_evidence_from_usage(record: UsageRecord) -> RequestTokenPlan | None:
    """Parse request/token evidence without choosing request-count recovery authority."""

    raw_plan = record.routing.get("request_token_plan")
    raw_hash = record.routing.get("request_token_plan_sha256")
    if raw_plan is None:
        if raw_hash is not None:
            raise ValueError("usage routing has a token-plan hash without its evidence")
        return None
    if not isinstance(raw_plan, dict) or not _is_sha256(raw_hash):
        raise ValueError("usage routing token-plan evidence is malformed")
    plan = _strict_json_evidence(RequestTokenPlan, raw_plan, label="request token plan")
    if (
        _canonical_request_token_plan_projection(plan) != raw_plan
        or raw_hash != plan.plan_sha256
        or plan.request_id != record.request_id
        or plan.role != record.role
        or plan.route_intersection.exact_model_ids != (record.requested_model,)
    ):
        raise ValueError("usage routing token plan differs from its request")
    configured_endpoints = {
        endpoint.casefold() for endpoint in record.configured_provider_endpoints
    }
    planned_endpoints = {
        endpoint.casefold() for endpoint in plan.route_intersection.provider_endpoints
    }
    local_mock_route = (
        record.execution_evidence is ExecutionEvidenceKind.MOCK
        and planned_endpoints == {"mmaudit-local-mock"}
    )
    if configured_endpoints and not local_mock_route and configured_endpoints != planned_endpoints:
        raise ValueError("usage routing token plan differs from configured endpoints")
    atomic_token_reservations_from_usage(record, plan)
    return plan


def atomic_token_reservations_from_usage(
    record: UsageRecord,
    plan: RequestTokenPlan | None = None,
) -> tuple[AtomicTokenReservationEvidence, ...]:
    """Return the exact ordered atomic reservation inventory for every provider attempt."""

    resolved_plan = plan
    if resolved_plan is None:
        raw_plan = record.routing.get("request_token_plan")
        raw_hash = record.routing.get("request_token_plan_sha256")
        if not isinstance(raw_plan, dict) or not _is_sha256(raw_hash):
            raise ValueError("usage routing token-plan evidence is malformed")
        resolved_plan = _strict_json_evidence(
            RequestTokenPlan,
            raw_plan,
            label="request token plan",
        )
    raw_evidence = record.routing.get("atomic_token_reservation")
    raw_hash = record.routing.get("atomic_token_reservation_sha256")
    if not isinstance(raw_evidence, dict) or not _is_sha256(raw_hash):
        raise ValueError("usage routing atomic token reservation is malformed")
    assert isinstance(raw_hash, str)
    final_evidence = _strict_json_evidence(
        AtomicTokenReservationEvidence,
        raw_evidence,
        label="atomic token reservation",
    )
    raw_inventory = record.routing.get("atomic_token_reservations")
    raw_inventory_hashes = record.routing.get("atomic_token_reservation_sha256s")
    inventory: tuple[AtomicTokenReservationEvidence, ...]
    inventory_hashes: tuple[str, ...]
    if raw_inventory is None and raw_inventory_hashes is None:
        if record.attempts != 1:
            raise ValueError("retried usage lacks a complete atomic reservation inventory")
        inventory = (final_evidence,)
        inventory_hashes = (raw_hash,)
    else:
        if (
            not isinstance(raw_inventory, list)
            or not isinstance(raw_inventory_hashes, list)
            or len(raw_inventory) != record.attempts
            or len(raw_inventory_hashes) != record.attempts
            or any(not isinstance(item, dict) for item in raw_inventory)
            or any(not _is_sha256(item) for item in raw_inventory_hashes)
        ):
            raise ValueError("usage routing atomic reservation inventory is malformed")
        inventory = tuple(
            _strict_json_evidence(
                AtomicTokenReservationEvidence,
                item,
                label="atomic token reservation",
            )
            for item in raw_inventory
        )
        inventory_hashes = tuple(raw_inventory_hashes)
    expected_request_ids = tuple(
        record.request_id if attempt == 1 else f"{record.request_id}:attempt:{attempt}"
        for attempt in range(1, record.attempts + 1)
    )
    if tuple(item.request_id for item in inventory) != expected_request_ids:
        raise ValueError("usage routing atomic reservation attempts are incomplete or unordered")
    if len(set(inventory_hashes)) != len(inventory_hashes):
        raise ValueError("usage routing atomic reservation hashes must be unique")
    for evidence, evidence_hash in zip(inventory, inventory_hashes, strict=True):
        if (
            evidence_hash != evidence.evidence_sha256
            or evidence.exact_model_id != record.requested_model
            or evidence.role != record.role
            or evidence.request_token_plan_sha256 != resolved_plan.plan_sha256
            or evidence.planned_prompt_tokens != resolved_plan.prompt_byte_upper_bound_tokens
            or evidence.planned_visible_output_tokens != resolved_plan.reserved_output_tokens
            or evidence.planned_reasoning_tokens != resolved_plan.reserved_reasoning_tokens
            or evidence.planned_completion_tokens != resolved_plan.requested_completion_tokens
            or evidence.global_input_token_limit
            != resolved_plan.global_budget.global_input_token_budget
            or evidence.global_output_token_limit
            != resolved_plan.global_budget.global_output_token_budget
        ):
            raise ValueError("usage routing atomic reservation differs from its token plan")
    if (
        final_evidence != inventory[-1]
        or raw_evidence != final_evidence.model_dump(mode="json")
        or raw_hash != final_evidence.evidence_sha256
    ):
        raise ValueError(
            "usage routing final atomic reservation differs from its token plan or inventory"
        )
    return inventory


def atomic_request_limit_reservations_from_usage(
    record: UsageRecord,
    plan: RequestTokenPlan | None = None,
) -> tuple[AtomicRequestLimitReservationEvidence, ...]:
    """Return scheduled request-count evidence, or an empty tuple for legacy requests."""

    inventory = _atomic_request_limit_reservation_inventory_from_usage(record, plan)
    if not inventory:
        return ()
    if (
        tuple(item.request_limit_scope for item in inventory)
        != (record.request_id,) * record.attempts
        or tuple(item.request_limit_count_before for item in inventory)
        != tuple(range(record.attempts))
        or tuple(item.request_limit_count_after for item in inventory)
        != tuple(range(1, record.attempts + 1))
        or len({item.request_limit_maximum for item in inventory}) != 1
    ):
        raise ValueError("scheduled usage request-limit attempts are incomplete or unordered")
    return inventory


def recovery_atomic_request_limit_reservations_from_usage(
    record: UsageRecord,
    plan: RequestTokenPlan | None = None,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> tuple[AtomicRequestLimitReservationEvidence, ...]:
    """Validate one bounded recovery inventory against caller-supplied chain coordinates.

    This comparison-only API deliberately requires the root scope and exact starting count from
    a separate trusted custody boundary. It never derives either authority input from serialized
    usage and does not make the record creditable by itself.
    """

    _validate_recovery_request_limit_coordinates(
        record,
        request_limit_scope=request_limit_scope,
        request_limit_count_before=request_limit_count_before,
    )
    inventory = _atomic_request_limit_reservation_inventory_from_usage(
        record,
        plan,
        maximum_inventory_size=_MAX_RECOVERY_REQUEST_LIMIT_RESERVATIONS,
    )
    if not inventory:
        raise ValueError("recovery usage lacks request-limit reservation evidence")
    count_after = request_limit_count_before + record.attempts
    if (
        tuple(item.request_limit_scope for item in inventory)
        != (request_limit_scope,) * record.attempts
        or tuple(item.request_limit_count_before for item in inventory)
        != tuple(range(request_limit_count_before, count_after))
        or tuple(item.request_limit_count_after for item in inventory)
        != tuple(range(request_limit_count_before + 1, count_after + 1))
        or len({item.request_limit_maximum for item in inventory}) != 1
    ):
        raise ValueError("recovery usage request-limit attempts are incomplete or unordered")
    return inventory


def _validate_recovery_request_limit_coordinates(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> None:
    """Reject unbounded recovery material before parsing nested reservation inventories."""

    if (
        type(request_limit_scope) is not str
        or _REQUEST_LIMIT_SCOPE.fullmatch(request_limit_scope) is None
    ):
        raise ValueError("recovery request-limit scope is invalid")
    if (
        type(request_limit_count_before) is not int
        or not 0 <= request_limit_count_before <= _MAX_METERED_UNITS
    ):
        raise ValueError("recovery request-limit starting count is invalid")
    if (
        type(record.attempts) is not int
        or not 1 <= record.attempts <= _MAX_RECOVERY_REQUEST_LIMIT_RESERVATIONS
        or request_limit_count_before > _MAX_METERED_UNITS - record.attempts
    ):
        raise ValueError("recovery request-limit inventory exceeds its compiled bound")


def _atomic_request_limit_reservation_inventory_from_usage(
    record: UsageRecord,
    plan: RequestTokenPlan | None,
    *,
    maximum_inventory_size: int | None = None,
) -> tuple[AtomicRequestLimitReservationEvidence, ...]:
    """Parse exact request-limit evidence without selecting ordinary or recovery semantics."""

    evidence_keys = (
        "atomic_request_limit_reservations",
        "atomic_request_limit_reservation_sha256s",
        "atomic_request_limit_reservation",
        "atomic_request_limit_reservation_sha256",
    )
    raw_values = tuple(record.routing.get(key) for key in evidence_keys)
    if all(value is None for value in raw_values):
        return ()
    if any(value is None for value in raw_values):
        raise ValueError("usage routing request-limit reservation evidence is incomplete")
    raw_inventory, raw_inventory_hashes, raw_final, raw_final_hash = raw_values
    if (
        not isinstance(raw_inventory, list)
        or not isinstance(raw_inventory_hashes, list)
        or not isinstance(raw_final, dict)
        or not _is_sha256(raw_final_hash)
        or (
            maximum_inventory_size is not None
            and (
                len(raw_inventory) > maximum_inventory_size
                or len(raw_inventory_hashes) > maximum_inventory_size
            )
        )
        or len(raw_inventory) != record.attempts
        or len(raw_inventory_hashes) != record.attempts
        or any(not isinstance(item, dict) for item in raw_inventory)
        or any(not _is_sha256(item) for item in raw_inventory_hashes)
    ):
        raise ValueError("usage routing request-limit reservation evidence is malformed")
    resolved_plan = plan
    if resolved_plan is None:
        resolved_plan = _request_token_plan_evidence_from_usage(record)
        if resolved_plan is None:
            raise ValueError("request-limit reservations require a request token plan")
    inventory = tuple(
        _strict_json_evidence(
            AtomicRequestLimitReservationEvidence,
            item,
            label="request-limit reservation",
        )
        for item in raw_inventory
    )
    inventory_hashes = tuple(raw_inventory_hashes)
    final_evidence = _strict_json_evidence(
        AtomicRequestLimitReservationEvidence,
        raw_final,
        label="request-limit reservation",
    )
    expected_request_ids = tuple(
        record.request_id if attempt == 1 else f"{record.request_id}:attempt:{attempt}"
        for attempt in range(1, record.attempts + 1)
    )
    if tuple(item.request_id for item in inventory) != expected_request_ids:
        raise ValueError("usage routing request-limit attempts are incomplete or unordered")
    for evidence, evidence_hash in zip(inventory, inventory_hashes, strict=True):
        if (
            evidence.evidence_sha256 != evidence_hash
            or evidence.exact_model_id != record.requested_model
            or evidence.role != record.role
            or evidence.request_token_plan_sha256 != resolved_plan.plan_sha256
        ):
            raise ValueError("scheduled usage request-limit evidence differs from its request")
    if (
        final_evidence != inventory[-1]
        or raw_final != final_evidence.model_dump(mode="json")
        or raw_final_hash != final_evidence.evidence_sha256
    ):
        raise ValueError("usage routing final request-limit reservation differs from inventory")
    return inventory


def _atomic_token_reservation_from_usage(
    record: UsageRecord,
    plan: RequestTokenPlan,
) -> AtomicTokenReservationEvidence:
    return atomic_token_reservations_from_usage(record, plan)[-1]


def _canonical_request_token_plan_projection(plan: RequestTokenPlan) -> dict[str, Any]:
    """Return the exact serialized shape used by the plan's schema version."""

    projection = plan.model_dump(mode="json")
    if plan.schema_version == "1.0":
        projection.pop("reasoning_plan")
    return projection


def _strict_json_evidence[EvidenceT: BaseModel](
    evidence_type: type[EvidenceT],
    raw_evidence: dict[str, Any],
    *,
    label: str,
) -> EvidenceT:
    try:
        serialized = json.dumps(
            raw_evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        return evidence_type.model_validate_json(serialized, strict=True)
    except (TypeError, ValueError, ValidationError):
        raise ValueError(f"{label} is invalid") from None


def _has_valid_token_plan_routing(
    record: UsageRecord,
    *,
    recovery_request_limit_scope: str | None = None,
    recovery_request_limit_count_before: int | None = None,
    allow_noncrediting_unknown_token_accounting: bool = False,
) -> bool:
    if "request_token_plan" not in record.routing:
        return False
    recovery_mode = recovery_request_limit_scope is not None
    if recovery_mode != (recovery_request_limit_count_before is not None):
        return False
    try:
        plan = (
            recovery_request_token_plan_from_usage(
                record,
                request_limit_scope=recovery_request_limit_scope,
                request_limit_count_before=recovery_request_limit_count_before,
            )
            if recovery_mode
            and recovery_request_limit_scope is not None
            and recovery_request_limit_count_before is not None
            else request_token_plan_from_usage(record)
        )
    except ValueError:
        return False
    if plan is None:
        return False
    if plan.schema_version == "3.0":
        return allow_noncrediting_unknown_token_accounting and (
            _has_valid_noncrediting_unknown_token_plan_routing(record, plan)
        )
    if plan.schema_version != "2.0":
        return False
    reasoning_plan = plan.reasoning_plan
    reasoning = record.reasoning_evidence
    if (reasoning_plan is None) != (reasoning is None):
        return False
    if reasoning is not None and (
        reasoning.request_plan != reasoning_plan
        or reasoning.request_token_plan_sha256 != plan.plan_sha256
        or reasoning.request_body_sha256 != record.request_body_sha256
        or reasoning.provider_completion_tokens != record.completion_tokens
        or (
            reasoning.observation_available
            and reasoning.observed_reasoning_tokens != record.reasoning_tokens
        )
        or (not reasoning.observation_available and record.reasoning_tokens != 0)
    ):
        return False
    if (
        reasoning_plan is not None
        and reasoning_plan.control_profile.mode != "disabled"
        and reasoning_plan.control_profile.reserved_reasoning_tokens > 0
        and (
            reasoning is None
            or reasoning.state != "active_observed"
            or reasoning.observed_reasoning_tokens is None
            or reasoning.observed_reasoning_tokens <= 0
        )
    ):
        return False
    limits = plan.route_intersection
    return (
        record.prompt_tokens <= plan.prompt_byte_upper_bound_tokens
        and record.prompt_tokens <= limits.max_prompt_tokens
        and record.completion_tokens <= plan.requested_completion_tokens
        and record.completion_tokens <= limits.max_completion_tokens
        and record.prompt_tokens + record.completion_tokens <= limits.context_tokens
        and record.reasoning_tokens <= record.completion_tokens
        and record.reasoning_tokens <= plan.reserved_reasoning_tokens
        and record.completion_tokens - record.reasoning_tokens <= plan.reserved_output_tokens
        and (
            not record.configured_provider_endpoints
            or limits.provider_endpoints == ("mmaudit-local-mock",)
            or (
                isinstance(record.actual_provider_endpoint, str)
                and record.actual_provider_endpoint.casefold()
                in {endpoint.casefold() for endpoint in limits.provider_endpoints}
            )
        )
    )


def _has_valid_noncrediting_unknown_token_plan_routing(
    record: UsageRecord,
    plan: RequestTokenPlan,
) -> bool:
    """Validate v3 full-plan accounting while deliberately withholding general credit."""

    token_detail = record.token_detail_accounting_evidence
    reasoning_plan = plan.reasoning_plan
    reasoning = record.reasoning_evidence
    if (
        plan.schema_version != "3.0"
        or plan.token_detail_accounting_method
        != "MMAUDIT_INDEPENDENT_REASONING_COMPONENT_ENVELOPE_V1"
        or plan.wire_max_tokens != plan.reserved_output_tokens
        or token_detail is None
        or token_detail.accounting_method != plan.token_detail_accounting_method
        or token_detail.request_token_plan_sha256 != plan.plan_sha256
        or token_detail.request_body_sha256 != record.request_body_sha256
        or reasoning_plan is None
        or reasoning is None
        or reasoning.schema_version != "1.1"
        or reasoning.request_plan != reasoning_plan
        or reasoning.request_token_plan_sha256 != plan.plan_sha256
        or reasoning.request_body_sha256 != record.request_body_sha256
        or reasoning.provider_completion_tokens != token_detail.provider_completion_tokens
        or reasoning.observed_reasoning_tokens != token_detail.provider_reasoning_tokens
        or reasoning.token_detail_accounting_evidence_sha256 != token_detail.evidence_sha256
    ):
        return False
    control = reasoning_plan.control_profile
    if (
        control.mode != "disabled"
        and control.reserved_reasoning_tokens > 0
        and (
            reasoning.state != "active_observed"
            or token_detail.provider_reasoning_tokens is None
            or token_detail.provider_reasoning_tokens <= 0
        )
    ):
        return False
    limits = plan.route_intersection
    raw_prompt = token_detail.provider_prompt_tokens
    raw_completion = token_detail.provider_completion_tokens
    raw_reasoning = token_detail.provider_reasoning_tokens
    if raw_reasoning is None:
        return False
    return (
        raw_prompt <= plan.prompt_byte_upper_bound_tokens
        and raw_prompt <= limits.max_prompt_tokens
        and raw_completion <= plan.reserved_output_tokens
        and raw_reasoning <= plan.reserved_reasoning_tokens
        and token_detail.accounted_prompt_tokens == plan.prompt_byte_upper_bound_tokens
        and token_detail.accounted_visible_output_tokens == plan.reserved_output_tokens
        and token_detail.accounted_reasoning_tokens == plan.reserved_reasoning_tokens
        and token_detail.accounted_completion_tokens == plan.requested_completion_tokens
        and token_detail.accounted_total_tokens
        == plan.prompt_byte_upper_bound_tokens + plan.requested_completion_tokens
        and record.prompt_tokens == token_detail.provider_prompt_tokens
        and record.completion_tokens == token_detail.provider_completion_tokens
        and record.reasoning_tokens == raw_reasoning
        and record.total_tokens == token_detail.provider_total_tokens
        and record.cached_tokens == token_detail.provider_cached_tokens
        and (
            not record.configured_provider_endpoints
            or (
                isinstance(record.actual_provider_endpoint, str)
                and record.actual_provider_endpoint.casefold()
                in {endpoint.casefold() for endpoint in limits.provider_endpoints}
            )
        )
    )


def _structured_output_routing_failure_code(
    record: UsageRecord,
) -> StructuredOutputRoutingFailureCode | None:
    """Return one closed, value-free structured-output routing failure clause."""

    raw_evidence = record.routing.get("structured_output")
    if not isinstance(raw_evidence, dict):
        return "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_TYPE"
    try:
        evidence = StructuredOutputEvidence.model_validate(raw_evidence)
    except ValidationError:
        if dict.get(raw_evidence, "repair_evidence") is not None:
            return "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED"
        if dict.__contains__(raw_evidence, "truncated") and (
            dict.get(raw_evidence, "truncated") is not False
        ):
            return "STRUCTURED_OUTPUT_ROUTING:TRUNCATED"
        requested_mode = dict.get(raw_evidence, "requested_mode")
        achieved_mode = dict.get(raw_evidence, "achieved_mode")
        if (
            type(requested_mode) is str
            and type(achieved_mode) is str
            and requested_mode != achieved_mode
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH"
        return "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_SCHEMA"
    if evidence.model_dump(mode="json") != raw_evidence:
        return "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_CANONICAL"
    if evidence.repair_used:
        return "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED"
    if evidence.truncated:
        return "STRUCTURED_OUTPUT_ROUTING:TRUNCATED"
    if evidence.requested_mode is not evidence.achieved_mode:
        return "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH"
    if tuple(record.configured_provider_endpoints) != evidence.configured_provider_endpoints:
        return "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS"
    if record.actual_provider_endpoint != evidence.selected_provider_endpoint:
        return "STRUCTURED_OUTPUT_ROUTING:SELECTED_PROVIDER_ENDPOINT"
    if record.prompt_sha256 != evidence.prompt_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:PROMPT_SHA256"
    if record.request_body_sha256 != evidence.request_body_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:REQUEST_BODY_SHA256"
    if record.schema_sha256 != evidence.schema_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:SCHEMA_SHA256"
    if record.response_sha256 != evidence.original_response_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:ORIGINAL_RESPONSE_SHA256"
    if record.validated_response_sha256 != evidence.validated_response_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:VALIDATED_RESPONSE_SHA256"
    if record.routing.get("provider_policy_sha256") != evidence.provider_policy_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:PROVIDER_POLICY_SHA256"
    if record.routing.get("endpoint_snapshot_sha256") != evidence.endpoint_snapshot_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:ENDPOINT_SNAPSHOT_SHA256"
    if record.routing.get("output_capability_sha256") != evidence.output_capability_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:OUTPUT_CAPABILITY_SHA256"
    if record.routing.get("repair_used") is not evidence.repair_used:
        return "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED_ROUTING"

    request_shape_routing = {
        "structured_output_mode": evidence.requested_mode.value,
        "structured_output_request_shape_sha256": evidence.request_shape_sha256,
        "structured_output_require_parameters": evidence.provider_require_parameters,
        "structured_output_required_provider_parameters": list(
            evidence.required_provider_parameters
        ),
        "structured_output_reasoning_request_sha256": (evidence.reasoning_request_sha256),
        "structured_output_response_format": (
            None
            if evidence.response_format is StructuredOutputResponseFormat.OMITTED
            else evidence.response_format.value
        ),
        "structured_output_protocol_sha256": evidence.strict_protocol_sha256,
    }
    if any(key in record.routing for key in request_shape_routing):
        if record.routing.get("structured_output_mode") != evidence.requested_mode.value:
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE"
        if (
            record.routing.get("structured_output_request_shape_sha256")
            != evidence.request_shape_sha256
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_SHA256"
        if (
            record.routing.get("structured_output_require_parameters")
            != evidence.provider_require_parameters
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRE_PARAMETERS"
        if record.routing.get("structured_output_required_provider_parameters") != list(
            evidence.required_provider_parameters
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRED_PROVIDER_PARAMETERS"
        if (
            record.routing.get("structured_output_reasoning_request_sha256")
            != evidence.reasoning_request_sha256
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REASONING_REQUEST_SHA256"
        expected_response_format = (
            None
            if evidence.response_format is StructuredOutputResponseFormat.OMITTED
            else evidence.response_format.value
        )
        if record.routing.get("structured_output_response_format") != expected_response_format:
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_RESPONSE_FORMAT"
        if (
            record.routing.get("structured_output_protocol_sha256")
            != evidence.strict_protocol_sha256
        ):
            return "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_PROTOCOL_SHA256"

    redundant_routing = {
        "structured_output_supported_modes": [
            mode.value
            for mode in supported_output_modes(evidence.endpoint_structured_output_parameters)
        ],
        "structured_output_capability_sha256": evidence.output_capability_sha256,
        "structured_output_request_body_sha256": evidence.request_body_sha256,
        "structured_output_original_response_sha256": (evidence.original_response_sha256),
        "structured_output_validated_response_sha256": (evidence.validated_response_sha256),
    }
    if (
        "structured_output_supported_modes" in record.routing
        and record.routing.get("structured_output_supported_modes")
        != redundant_routing["structured_output_supported_modes"]
    ):
        return "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES"
    if (
        "structured_output_capability_sha256" in record.routing
        and record.routing.get("structured_output_capability_sha256")
        != evidence.output_capability_sha256
    ):
        return "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_CAPABILITY_SHA256"
    if (
        "structured_output_request_body_sha256" in record.routing
        and record.routing.get("structured_output_request_body_sha256")
        != evidence.request_body_sha256
    ):
        return "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_REQUEST_BODY_SHA256"
    if (
        "structured_output_original_response_sha256" in record.routing
        and record.routing.get("structured_output_original_response_sha256")
        != evidence.original_response_sha256
    ):
        return "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_ORIGINAL_RESPONSE_SHA256"
    if (
        "structured_output_validated_response_sha256" in record.routing
        and record.routing.get("structured_output_validated_response_sha256")
        != evidence.validated_response_sha256
    ):
        return "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_VALIDATED_RESPONSE_SHA256"

    binding = _validated_identity_binding(record)
    if binding is None:
        return None
    capabilities = binding.snapshot.endpoint_capabilities
    required_special_parameters = set(capabilities.required_parameters) - {
        "max_tokens",
        "temperature",
    }
    if binding.snapshot.endpoint_snapshot_sha256 != evidence.endpoint_snapshot_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256"
    if capabilities.output_capability_sha256 != evidence.output_capability_sha256:
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_OUTPUT_CAPABILITY_SHA256"
    if capabilities.structured_output_mode is not evidence.requested_mode:
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_MODE"
    if not set(evidence.endpoint_structured_output_parameters).issubset(
        capabilities.structured_output_parameters
    ):
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_PARAMETER_SUBSET"
    if set(evidence.required_provider_parameters) != required_special_parameters:
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
    if (
        binding.snapshot.provider_policy.require_parameters
        is not evidence.provider_require_parameters
    ):
        return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRE_PARAMETERS"
    return None


def _has_valid_structured_output_routing(record: UsageRecord) -> bool:
    return _structured_output_routing_failure_code(record) is None


def _has_valid_privacy_routing(record: UsageRecord) -> bool:
    routing = record.routing
    if routing.get("data_collection") != "deny":
        return False
    profile = routing.get("privacy_profile")
    if profile is None:
        return False
    if (
        not _is_sha256(routing.get("effective_privacy_policy_sha256"))
        or not _is_sha256(routing.get("privacy_source_sha256"))
        or not _is_sha256(routing.get("privacy_source_provenance_sha256"))
    ):
        return False
    if profile == PrivacyProfile.STRICT_ZDR.value:
        return (
            routing.get("zdr_requested") is True
            and routing.get("privacy_authorization") == "STRICT_ZDR_ENFORCED"
            and routing.get("privacy_endpoint_policy_class") == EndpointPolicyClass.ZDR.value
        )
    if profile not in {
        PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT.value,
        PrivacyProfile.SYNTHETIC_BENCHMARK.value,
    }:
        return False
    source_classification = routing.get("privacy_source_classification")
    if (
        profile == PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT.value
        and source_classification != PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
    ):
        return False
    if profile == PrivacyProfile.SYNTHETIC_BENCHMARK.value and source_classification not in {
        PrivacySourceClassification.SYNTHETIC_COMMITTED.value,
        PrivacySourceClassification.PUBLIC_BENCHMARK.value,
    }:
        return False
    if routing.get("zdr_requested") is True:
        return (
            routing.get("privacy_authorization") == "STRICT_ZDR_ENFORCED"
            and routing.get("privacy_endpoint_policy_class") == EndpointPolicyClass.ZDR.value
        )
    if (
        not _is_sha256(routing.get("privacy_consent_file_sha256"))
        or not _is_sha256(routing.get("privacy_consent_sha256"))
        or not _valid_consent_expiry(record)
    ):
        return False
    return (
        routing.get("zdr_requested") is False
        and routing.get("privacy_authorization") == "CONSENT_BOUND_NON_ZDR"
        and routing.get("privacy_endpoint_policy_class")
        == EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED.value
    )


def _valid_consent_expiry(record: UsageRecord) -> bool:
    value = record.routing.get("privacy_consent_expires_at")
    if not isinstance(value, str):
        return False
    try:
        expires_at = datetime.fromisoformat(value)
    except ValueError:
        return False
    if (
        expires_at.tzinfo is None
        or expires_at.utcoffset() != UTC.utcoffset(expires_at)
        or expires_at.microsecond != 0
        or expires_at.isoformat() != value
        or record.ended_at is None
    ):
        return False
    return expires_at > record.ended_at


def _build_owned_real_usage_authority() -> tuple[
    Callable[[UsageRecord], UsageRecord],
    Callable[[UsageRecord], bool],
]:
    """Keep REAL runtime authority outside caller-mutable Pydantic state."""

    registry: dict[int, tuple[weakref.ReferenceType[UsageRecord], str]] = {}
    lock = threading.RLock()

    def attest(record: UsageRecord) -> UsageRecord:
        if type(record) is not UsageRecord:
            raise ValueError("REAL usage attestation requires an exact usage record")
        if record.execution_evidence is not ExecutionEvidenceKind.REAL:
            raise ValueError("REAL usage attestation rejects non-REAL evidence")
        key = id(record)
        digest = _usage_record_sha256(record)

        def discard(reference: weakref.ReferenceType[UsageRecord]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(record, discard)
        with lock:
            registry[key] = (reference, digest)
        return record

    def contains(record: UsageRecord) -> bool:
        key = id(record)
        with lock:
            registered = registry.get(key)
        return (
            registered is not None
            and registered[0]() is record
            and registered[1] == _usage_record_sha256(record)
        )

    return attest, contains


_attest_owned_real_usage_record, _has_owned_real_usage_attestation = (
    _build_owned_real_usage_authority()
)


def _build_authrunner_usage_origin_process_boundary() -> Callable[[int], bool]:
    """Bind usage-origin membership to the process that inserted it."""

    trusted_getpid = os.getpid

    def is_current_process(registered_pid: int) -> bool:
        return type(registered_pid) is int and registered_pid == trusted_getpid()

    return is_current_process


_authrunner_usage_origin_process_is_current = _build_authrunner_usage_origin_process_boundary()
del _build_authrunner_usage_origin_process_boundary


def _build_authrunner_owned_real_usage_origin_authority() -> tuple[
    Callable[..., None],
    Callable[..., UsageRecord],
    Callable[[UsageRecord, UsageRecord], UsageRecord],
    Callable[..., bool],
    Callable[[UsageRecord], None],
    Callable[[], None],
]:
    """Keep AUTHRUNNER transport origin separate from generic REAL test custody."""

    type Issuer = tuple[
        object,
        type[object],
        Callable[..., object],
        Callable[..., object],
        Callable[..., object],
        Callable[..., object],
        object,
        Callable[[], bool],
        Callable[[object], ExecutionEvidenceKind],
        Callable[..., bool],
    ]

    registry: dict[int, tuple[weakref.ReferenceType[UsageRecord], str, object, str, int]] = {}
    issuer: Issuer | None = None
    issuer_callable_states: tuple[tuple[object, ...], ...] | None = None
    lock = threading.RLock()
    trusted_sys = sys
    trusted_self_module = trusted_sys.modules[__name__]
    trusted_usage_sha256 = _usage_record_sha256
    trusted_generic_origin = _has_owned_real_usage_attestation
    trusted_bound_identity = _has_valid_bound_identity
    trusted_origin_scope = _authrunner_usage_origin_scope
    trusted_getpid = os.getpid
    trusted_process_is_current = _authrunner_usage_origin_process_is_current
    empty_cell = object()

    def function_state(function: FunctionType) -> tuple[object, ...]:
        closure = function.__closure__
        closure_values: list[tuple[object, object]] = []
        for cell in closure or ():
            try:
                contents = cell.cell_contents
            except ValueError:
                contents = empty_cell
            closure_values.append((cell, contents))
        kwdefaults = function.__kwdefaults__
        attributes = function.__dict__
        return (
            function,
            function.__code__,
            function.__defaults__,
            kwdefaults,
            tuple(sorted((name, value) for name, value in (kwdefaults or {}).items())),
            function.__globals__,
            closure,
            tuple(closure_values),
            attributes,
            tuple(sorted(attributes.items())),
        )

    def function_state_is_current(state: tuple[object, ...] | None) -> bool:
        if state is None or type(state[0]) is not FunctionType:
            return False
        function = state[0]
        assert type(function) is FunctionType
        current_kwdefaults = function.__kwdefaults__
        current_attributes = function.__dict__
        current_closure = function.__closure__
        expected_kwdefaults = state[4]
        expected_closure = state[7]
        expected_attributes = state[9]
        if (
            type(expected_kwdefaults) is not tuple
            or type(expected_closure) is not tuple
            or type(expected_attributes) is not tuple
            or function.__code__ is not state[1]
            or function.__defaults__ is not state[2]
            or current_kwdefaults is not state[3]
            or function.__globals__ is not state[5]
            or current_closure is not state[6]
            or current_attributes is not state[8]
            or type(current_kwdefaults) not in {dict, type(None)}
            or type(current_attributes) is not dict
            or len(current_kwdefaults or {}) != len(expected_kwdefaults)
            or any(
                (current_kwdefaults or {}).get(name) is not value
                for name, value in expected_kwdefaults
            )
            or len(current_attributes) != len(expected_attributes)
            or any(current_attributes.get(name) is not value for name, value in expected_attributes)
            or len(current_closure or ()) != len(expected_closure)
        ):
            return False
        for current_cell, expected in zip(
            current_closure or (),
            expected_closure,
            strict=True,
        ):
            if type(expected) is not tuple or len(expected) != 2:
                return False
            expected_cell, expected_value = expected
            if current_cell is not expected_cell:
                return False
            try:
                current_value = current_cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if current_value is not expected_value:
                return False
        return True

    def function_graph_state(
        function: FunctionType,
        *,
        excluded_functions: tuple[FunctionType, ...] = (),
    ) -> tuple[tuple[object, ...], ...]:
        states: list[tuple[object, ...]] = []
        seen: set[int] = set()

        def visit_value(value: object) -> None:
            if any(value is excluded for excluded in excluded_functions):
                return
            if type(value) is FunctionType:
                visit_function(value)
            elif type(value) is tuple:
                for item in value:
                    visit_value(item)

        def visit_function(current: FunctionType) -> None:
            key = id(current)
            if key in seen:
                return
            seen.add(key)
            state = function_state(current)
            states.append(state)
            for value in current.__defaults__ or ():
                visit_value(value)
            for value in (current.__kwdefaults__ or {}).values():
                visit_value(value)
            closure_values = state[7]
            if type(closure_values) is not tuple:
                return
            for closure_value in closure_values:
                if type(closure_value) is not tuple or len(closure_value) != 2:
                    return
                _cell, value = closure_value
                visit_value(value)
            for value in current.__dict__.values():
                visit_value(value)

        visit_function(function)
        return tuple(states)

    def function_graph_state_is_current(
        states: tuple[tuple[object, ...], ...] | None,
    ) -> bool:
        return bool(states and all(function_state_is_current(state) for state in states))

    def register_issuer(
        *,
        module: object,
        client_type: type[object],
        completion_method: Callable[..., object],
        bound_origin_method: Callable[..., object],
        bound_wrapper_method: Callable[..., object],
        bound_result_method: Callable[..., object],
        trusted_identity_issuer: object,
        pristine_predicate: Callable[[], bool],
        execution_evidence_resolver: Callable[[object], ExecutionEvidenceKind],
        receipt_consumer: Callable[..., bool],
    ) -> None:
        """Register the exact OpenRouter bound-success call chain once at import time."""

        nonlocal issuer, issuer_callable_states
        frame = trusted_sys._getframe(1)
        module_name = getattr(module, "__name__", None)
        module_values = getattr(module, "__dict__", None)
        pristine_kwdefaults = pristine_predicate.__kwdefaults__
        graph_guard = (
            pristine_kwdefaults.get("_provider_authority_graph_is_pristine")
            if type(pristine_kwdefaults) is dict
            else None
        )
        expected_methods = (
            ("complete_with_evidence", completion_method),
            ("_bind_real_completion_identity", bound_origin_method),
            ("_usage_with_bound_identity", bound_wrapper_method),
            ("_usage_with_identity_result", bound_result_method),
        )
        if (
            module_name != "mmaudit.models.openrouter"
            or type(module_values) is not dict
            or frame.f_globals is not module_values
            or frame.f_code.co_name != "<module>"
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or client_type.__module__ != module_name
            or any(
                vars(client_type).get(name) is not method
                or getattr(method, "__module__", None) != module_name
                or getattr(method, "__qualname__", None) != f"OpenRouterClient.{name}"
                for name, method in expected_methods
            )
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
            or getattr(module, "_consume_provider_initial_receipt_composite", None)
            is not receipt_consumer
            or type(graph_guard) is not FunctionType
            or any(
                type(function) is not FunctionType
                for function in (
                    completion_method,
                    bound_origin_method,
                    bound_wrapper_method,
                    bound_result_method,
                    pristine_predicate,
                    execution_evidence_resolver,
                    receipt_consumer,
                )
            )
        ):
            raise RuntimeError("AUTHRUNNER usage-origin issuer registration is invalid")
        with lock:
            if issuer is not None:
                raise RuntimeError("AUTHRUNNER usage-origin issuer is already registered")
            issuer = (
                module,
                client_type,
                completion_method,
                bound_origin_method,
                bound_wrapper_method,
                bound_result_method,
                trusted_identity_issuer,
                pristine_predicate,
                execution_evidence_resolver,
                receipt_consumer,
            )
            registered_functions = (
                completion_method,
                bound_origin_method,
                bound_wrapper_method,
                bound_result_method,
                pristine_predicate,
                execution_evidence_resolver,
                receipt_consumer,
            )
            issuer_callable_states = (
                *(
                    function_state(cast(FunctionType, function))
                    for function in registered_functions[:-1]
                ),
                *function_graph_state(
                    cast(FunctionType, registered_functions[-1]),
                    excluded_functions=(graph_guard,),
                ),
            )

    def finalize_issuer_function_states() -> None:
        """Refresh the registered predicate graph after its final receipt binding."""

        nonlocal issuer_callable_states
        frame = trusted_sys._getframe(1)
        with lock:
            registered_issuer = issuer
        if registered_issuer is None:
            raise RuntimeError("AUTHRUNNER usage-origin issuer is not registered")
        module = registered_issuer[0]
        module_values = getattr(module, "__dict__", None)
        pristine_predicate = registered_issuer[7]
        pristine_kwdefaults = pristine_predicate.__kwdefaults__
        graph_guard = (
            pristine_kwdefaults.get("_provider_authority_graph_is_pristine")
            if type(pristine_kwdefaults) is dict
            else None
        )
        functions = (
            registered_issuer[2],
            registered_issuer[3],
            registered_issuer[4],
            registered_issuer[5],
            registered_issuer[7],
            registered_issuer[8],
            registered_issuer[9],
        )
        if (
            type(module_values) is not dict
            or frame.f_code.co_name != "<module>"
            or frame.f_globals is not module_values
            or type(graph_guard) is not FunctionType
            or any(type(function) is not FunctionType for function in functions)
        ):
            raise RuntimeError("AUTHRUNNER usage-origin issuer finalization is invalid")
        refreshed = (
            *(function_state(cast(FunctionType, function)) for function in functions[:-1]),
            *function_graph_state(
                cast(FunctionType, functions[-1]),
                excluded_functions=(graph_guard,),
            ),
        )
        with lock:
            if issuer is not registered_issuer:
                raise RuntimeError("AUTHRUNNER usage-origin issuer changed during finalization")
            issuer_callable_states = refreshed

    def mark(
        record: UsageRecord,
        *,
        receipt_composite: object | None = None,
        provisional_usage: UsageRecord | None = None,
        generation: object | None = None,
        binding: object | None = None,
        expectation_sha256: str | None = None,
    ) -> UsageRecord:
        """Strong-mark only the registered pristine OpenRouter bound-success stack."""

        with lock:
            registered_issuer = issuer
        if registered_issuer is None:
            raise ValueError("AUTHRUNNER usage-origin issuer is not registered")
        (
            module,
            client_type,
            completion_method,
            bound_origin_method,
            bound_wrapper_method,
            bound_result_method,
            trusted_identity_issuer,
            pristine_predicate,
            execution_evidence_resolver,
            receipt_consumer,
        ) = registered_issuer
        result_frame = trusted_sys._getframe(1)
        wrapper_frame = result_frame.f_back
        origin_frame = wrapper_frame.f_back if wrapper_frame is not None else None
        completion_frame = origin_frame.f_back if origin_frame is not None else None
        module_name = getattr(module, "__name__", "")
        module_values = getattr(module, "__dict__", None)
        client = result_frame.f_locals.get("self")
        if (
            type(module_values) is not dict
            or globals().get("sys") is not trusted_sys
            or trusted_sys.modules.get(__name__) is not trusted_self_module
            or getattr(trusted_self_module, "_usage_record_sha256", None)
            is not trusted_usage_sha256
            or getattr(trusted_self_module, "_has_owned_real_usage_attestation", None)
            is not trusted_generic_origin
            or getattr(trusted_self_module, "_has_valid_bound_identity", None)
            is not trusted_bound_identity
            or getattr(trusted_self_module, "_authrunner_usage_origin_scope", None)
            is not trusted_origin_scope
            or getattr(trusted_self_module, "_authrunner_usage_origin_process_is_current", None)
            is not trusted_process_is_current
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or vars(client_type).get("complete_with_evidence") is not completion_method
            or vars(client_type).get("_bind_real_completion_identity") is not bound_origin_method
            or vars(client_type).get("_usage_with_bound_identity") is not bound_wrapper_method
            or vars(client_type).get("_usage_with_identity_result") is not bound_result_method
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
            or getattr(module, "_consume_provider_initial_receipt_composite", None)
            is not receipt_consumer
            or not function_graph_state_is_current(issuer_callable_states)
            or result_frame.f_globals is not module_values
            or result_frame.f_code is not bound_result_method.__code__
            or wrapper_frame is None
            or wrapper_frame.f_globals is not module_values
            or wrapper_frame.f_code is not bound_wrapper_method.__code__
            or origin_frame is None
            or origin_frame.f_globals is not module_values
            or origin_frame.f_code is not bound_origin_method.__code__
            or completion_frame is None
            or completion_frame.f_globals is not module_values
            or completion_frame.f_code is not completion_method.__code__
            or wrapper_frame.f_locals.get("self") is not client
            or origin_frame.f_locals.get("self") is not client
            or completion_frame.f_locals.get("self") is not client
            or type(client) is not client_type
            or result_frame.f_locals.get("trusted_issuer") is not trusted_identity_issuer
            or wrapper_frame.f_locals.get("trusted_issuer") is not trusted_identity_issuer
            or result_frame.f_locals.get("require_bound") is not True
        ):
            raise ValueError("AUTHRUNNER usage origin requires the pristine bound-success path")
        try:
            budget = object.__getattribute__(client, "budget")
            atomic_ledger = object.__getattribute__(budget, "atomic_ledger")
        except (AttributeError, TypeError):
            atomic_ledger = None
        try:
            origin_scope = trusted_origin_scope(record)
        except ValueError:
            origin_scope = None
        if (
            not pristine_predicate()
            or execution_evidence_resolver(client) is not ExecutionEvidenceKind.REAL
            or object.__getattribute__(client, "_owns_client") is not True
            or object.__getattribute__(client, "_authentication_validated") is not True
            or atomic_ledger is None
            or type(record) is not UsageRecord
            or record.execution_evidence is not ExecutionEvidenceKind.REAL
            or record.role != "model_benchmark"
            or record.routing.get("privacy_profile") != PrivacyProfile.SYNTHETIC_BENCHMARK.value
            or record.routing.get("privacy_source_classification")
            not in {
                PrivacySourceClassification.SYNTHETIC_COMMITTED.value,
                PrivacySourceClassification.PUBLIC_BENCHMARK.value,
            }
            or origin_scope is None
            or not trusted_generic_origin(record)
            or not trusted_bound_identity(record)
        ):
            raise ValueError("AUTHRUNNER usage origin requires owned REAL bound-success evidence")
        exact_smoke = origin_scope == "NONCREDITING_SMOKE"
        if exact_smoke:
            if type(provisional_usage) is not UsageRecord or not receipt_consumer(
                receipt_composite,
                client=client,
                usage_record=provisional_usage,
                generation=generation,
                binding=binding,
                expectation_sha256=expectation_sha256,
            ):
                raise ValueError("AUTHRUNNER smoke usage origin lacks one-shot receipt custody")
        elif any(
            value is not None
            for value in (
                receipt_composite,
                provisional_usage,
                generation,
                binding,
                expectation_sha256,
            )
        ):
            raise ValueError("AUTHRUNNER release usage origin rejects smoke receipt custody")
        key = id(record)
        digest = trusted_usage_sha256(record)

        def discard(reference: weakref.ReferenceType[UsageRecord]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(record, discard)
        with lock:
            if key in registry:
                raise ValueError("AUTHRUNNER usage origin is already registered")
            registry[key] = (
                reference,
                digest,
                atomic_ledger,
                origin_scope,
                trusted_getpid(),
            )
        return record

    def contains(
        record: UsageRecord,
        *,
        atomic_ledger: object | None = None,
    ) -> bool:
        if type(record) is not UsageRecord:
            return False
        with lock:
            registered_issuer = issuer
        if registered_issuer is None:
            return False
        (
            module,
            client_type,
            completion_method,
            bound_origin_method,
            bound_wrapper_method,
            bound_result_method,
            _trusted_identity_issuer,
            pristine_predicate,
            execution_evidence_resolver,
            receipt_consumer,
        ) = registered_issuer
        module_name = getattr(module, "__name__", "")
        if (
            globals().get("sys") is not trusted_sys
            or trusted_sys.modules.get(__name__) is not trusted_self_module
            or getattr(trusted_self_module, "_usage_record_sha256", None)
            is not trusted_usage_sha256
            or getattr(trusted_self_module, "_has_owned_real_usage_attestation", None)
            is not trusted_generic_origin
            or getattr(trusted_self_module, "_has_valid_bound_identity", None)
            is not trusted_bound_identity
            or getattr(trusted_self_module, "_authrunner_usage_origin_scope", None)
            is not trusted_origin_scope
            or getattr(trusted_self_module, "_authrunner_usage_origin_process_is_current", None)
            is not trusted_process_is_current
            or trusted_sys.modules.get(module_name) is not module
            or getattr(module, "OpenRouterClient", None) is not client_type
            or vars(client_type).get("complete_with_evidence") is not completion_method
            or vars(client_type).get("_bind_real_completion_identity") is not bound_origin_method
            or vars(client_type).get("_usage_with_bound_identity") is not bound_wrapper_method
            or vars(client_type).get("_usage_with_identity_result") is not bound_result_method
            or getattr(module, "_openrouter_client_callables_are_pristine", None)
            is not pristine_predicate
            or getattr(module, "trusted_openrouter_execution_evidence", None)
            is not execution_evidence_resolver
            or getattr(module, "_consume_provider_initial_receipt_composite", None)
            is not receipt_consumer
            or not function_graph_state_is_current(issuer_callable_states)
            or not pristine_predicate()
        ):
            return False
        with lock:
            registered = registry.get(id(record))
        try:
            current_scope = trusted_origin_scope(record)
        except ValueError:
            current_scope = None
        return bool(
            registered is not None
            and registered[0]() is record
            and registered[1] == trusted_usage_sha256(record)
            and (atomic_ledger is None or registered[2] is atomic_ledger)
            and registered[3] == current_scope
            and trusted_process_is_current(registered[4])
        )

    def propagate(source: UsageRecord, normalized: UsageRecord) -> UsageRecord:
        """Propagate origin only across one exact schema-normalized trusted copy."""

        if (
            type(source) is not UsageRecord
            or type(normalized) is not UsageRecord
            or not contains(source)
            or source is normalized
            or trusted_usage_sha256(source) != trusted_usage_sha256(normalized)
            or not trusted_generic_origin(normalized)
        ):
            raise ValueError("AUTHRUNNER usage origin cannot propagate from this source")
        key = id(normalized)
        digest = trusted_usage_sha256(normalized)

        def discard(reference: weakref.ReferenceType[UsageRecord]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(normalized, discard)
        with lock:
            if key in registry:
                raise ValueError("AUTHRUNNER usage origin is already registered")
            registry[key] = (
                reference,
                digest,
                registry[id(source)][2],
                registry[id(source)][3],
                trusted_getpid(),
            )
        return normalized

    def revoke(record: UsageRecord) -> None:
        """Remove one exact current origin mark during a failed publication transaction."""

        if type(record) is not UsageRecord:
            return
        key = id(record)
        with lock:
            registered = registry.get(key)
            if registered is None or registered[0]() is not record:
                return
            if not trusted_process_is_current(registered[4]):
                raise ValueError("AUTHRUNNER usage origin belongs to another process")
            removed = registry.pop(key)
        if removed is not registered:
            raise ValueError("AUTHRUNNER usage origin changed during revocation")

    return register_issuer, mark, propagate, contains, revoke, finalize_issuer_function_states


def _validated_usage_copy_preserving_owned_attestation(
    record: UsageRecord,
) -> UsageRecord:
    """Schema-normalize a trusted in-memory record without dropping its capability."""

    trusted_real = (
        record.execution_evidence is ExecutionEvidenceKind.REAL
        and _has_owned_real_usage_attestation(record)
    )
    trusted_authrunner_origin = trusted_real and _has_authrunner_owned_real_usage_origin(record)
    normalized = UsageRecord.model_validate(record.model_dump(mode="json"))
    if trusted_real:
        normalized = _attest_owned_real_usage_record(normalized)
    if trusted_authrunner_origin:
        normalized = _propagate_authrunner_owned_real_usage_origin(record, normalized)
    return normalized


def _is_structurally_generation_bindable_usage_record(record: UsageRecord) -> bool:
    """Validate serialized transport shape without granting REAL runtime credit."""

    return _is_structurally_generation_reconcilable_usage_record(
        record,
        require_certification=True,
    )


def _is_structurally_generation_reconcilable_usage_record(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> bool:
    """Validate serialized generation-reconciliation shape without runtime credit."""

    if not isinstance(require_certification, bool):
        return False
    return _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
        allow_unbound_real=True,
        require_runtime_attestation=False,
    )


def is_structurally_creditable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Validate serialized evidence shape without granting runtime execution credit."""

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
        require_runtime_attestation=False,
    )


def is_structurally_recovery_creditable_usage_record(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Validate serialized strict recovery usage without granting runtime authority."""

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
        require_runtime_attestation=False,
        recovery_request_limit_scope=request_limit_scope,
        recovery_request_limit_count_before=request_limit_count_before,
    )


# Retain the existing internal import surface while callers migrate to the
# explicitly named serialized-evidence predicate.
_is_structurally_creditable_usage_record = is_structurally_creditable_usage_record


def _usage_record_sha256(record: UsageRecord) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class _TrustedUsageRecoveryScope:
    """Opaque one-shot authority for records recovered from one validated journal."""

    __slots__ = ("__weakref__",)


type UsageRecoveryRequestLimitCoordinate = tuple[str, str, int]


def _build_trusted_usage_recovery_authority() -> tuple[
    Callable[..., _TrustedUsageRecoveryScope],
    Callable[[tuple[UsageRecord, ...], _TrustedUsageRecoveryScope], tuple[UsageRecord, ...]],
]:
    """Keep recovery authority process-local and outside serialized evidence."""

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[_TrustedUsageRecoveryScope],
            tuple[str, ...],
            tuple[UsageRecoveryRequestLimitCoordinate, ...],
            bool,
        ],
    ] = {}
    lock = threading.RLock()

    def normalize_shape(records: tuple[UsageRecord, ...]) -> tuple[UsageRecord, ...]:
        normalized = tuple(
            UsageRecord.model_validate(record.model_dump(mode="json")) for record in records
        )
        request_ids = tuple(record.request_id for record in normalized)
        if request_ids != tuple(sorted(set(request_ids))):
            raise ValueError("journal recovery usage identities must be unique and sorted")
        return normalized

    def normalize_coordinates(
        normalized: tuple[UsageRecord, ...],
        coordinates: tuple[UsageRecoveryRequestLimitCoordinate, ...],
    ) -> tuple[UsageRecoveryRequestLimitCoordinate, ...]:
        if (
            type(coordinates) is not tuple
            or len(coordinates) > _MAX_RECOVERY_REQUEST_LIMIT_RESERVATIONS
        ):
            raise ValueError("journal usage recovery coordinates exceed their compiled bound")
        exact: list[UsageRecoveryRequestLimitCoordinate] = []
        for item in coordinates:
            if type(item) is not tuple or len(item) != 3:
                raise ValueError("journal usage recovery coordinate is invalid")
            request_id, root_scope, count_before = item
            if (
                type(request_id) is not str
                or type(root_scope) is not str
                or _REQUEST_LIMIT_SCOPE.fullmatch(request_id) is None
                or _REQUEST_LIMIT_SCOPE.fullmatch(root_scope) is None
                or type(count_before) is not int
                or not 0 <= count_before <= _MAX_METERED_UNITS
            ):
                raise ValueError("journal usage recovery coordinate is invalid")
            exact.append((request_id, root_scope, count_before))
        frozen = tuple(exact)
        coordinate_ids = tuple(item[0] for item in frozen)
        record_ids = {record.request_id for record in normalized}
        if (
            frozen != tuple(sorted(frozen, key=lambda item: item[0]))
            or coordinate_ids != tuple(sorted(set(coordinate_ids)))
            or not set(coordinate_ids).issubset(record_ids)
        ):
            raise ValueError("journal usage recovery coordinates are not exact and sorted")
        return frozen

    def normalize_structural(
        records: tuple[UsageRecord, ...],
        coordinates: tuple[UsageRecoveryRequestLimitCoordinate, ...],
    ) -> tuple[UsageRecord, ...]:
        normalized = normalize_shape(records)
        frozen_coordinates = normalize_coordinates(normalized, coordinates)
        coordinate_by_request = {item[0]: item for item in frozen_coordinates}
        request_ids = {record.request_id for record in normalized}
        record_by_request = {record.request_id: record for record in normalized}
        chains: dict[str, list[tuple[int, int, int, str]]] = {}
        for record in normalized:
            coordinate = coordinate_by_request.get(record.request_id)
            require_real = record.execution_evidence is ExecutionEvidenceKind.REAL
            if coordinate is None:
                if require_real and not (
                    is_structurally_creditable_usage_record(record, require_real=True)
                    or is_structurally_accountable_usage_record(record, require_real=True)
                ):
                    raise ValueError("journal recovery contains structurally invalid REAL usage")
                continue
            _request_id, root_scope, count_before = coordinate
            if not (
                is_structurally_recovery_creditable_usage_record(
                    record,
                    request_limit_scope=root_scope,
                    request_limit_count_before=count_before,
                    require_real=require_real,
                )
                or is_structurally_recovery_accountable_usage_record(
                    record,
                    request_limit_scope=root_scope,
                    request_limit_count_before=count_before,
                    require_real=require_real,
                )
            ):
                raise ValueError("journal recovery contains invalid recovery-scoped usage")
            plan = recovery_request_token_plan_from_usage(
                record,
                request_limit_scope=root_scope,
                request_limit_count_before=count_before,
            )
            if plan is None:
                raise ValueError("journal recovery-scoped usage lacks its token plan")
            inventory = recovery_atomic_request_limit_reservations_from_usage(
                record,
                plan,
                request_limit_scope=root_scope,
                request_limit_count_before=count_before,
            )
            chains.setdefault(root_scope, []).append(
                (
                    count_before,
                    inventory[-1].request_limit_count_after,
                    inventory[0].request_limit_maximum,
                    record.request_id,
                )
            )
        for root_scope, chain in chains.items():
            if root_scope not in request_ids:
                raise ValueError("journal usage recovery coordinate has an unknown root scope")
            ordered = tuple(sorted(chain, key=lambda item: (item[0], item[3])))
            root_maximum: int | None = None
            root_count_after: int | None = None
            if root_scope not in coordinate_by_request:
                root_record = record_by_request[root_scope]
                try:
                    root_plan = request_token_plan_from_usage(root_record)
                    root_inventory = (
                        atomic_request_limit_reservations_from_usage(root_record, root_plan)
                        if root_plan is not None
                        else ()
                    )
                except (TypeError, ValueError):
                    root_inventory = ()
                if not root_inventory:
                    raise ValueError(
                        "journal usage recovery coordinate lacks exact root request evidence"
                    )
                root_maximum = root_inventory[0].request_limit_maximum
                root_count_after = root_inventory[-1].request_limit_count_after
            if (
                sum(item[1] - item[0] for item in ordered)
                > _MAX_RECOVERY_REQUEST_LIMIT_RESERVATIONS
                or len({item[2] for item in ordered}) != 1
                or (root_maximum is not None and ordered[0][2] != root_maximum)
                or (root_count_after is not None and ordered[0][0] != root_count_after)
                or any(current[1] != following[0] for current, following in pairwise(ordered))
            ):
                raise ValueError("journal usage recovery coordinate chain is inconsistent")
        return normalized

    def issue(
        records: tuple[UsageRecord, ...],
        *,
        recovery_request_limit_coordinates: tuple[
            UsageRecoveryRequestLimitCoordinate,
            ...,
        ] = (),
    ) -> _TrustedUsageRecoveryScope:
        normalized = normalize_structural(records, recovery_request_limit_coordinates)
        frozen_coordinates = normalize_coordinates(
            normalized,
            recovery_request_limit_coordinates,
        )
        hashes = tuple(_usage_record_sha256(record) for record in normalized)
        scope = object.__new__(_TrustedUsageRecoveryScope)
        key = id(scope)

        def discard(reference: weakref.ReferenceType[_TrustedUsageRecoveryScope]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(scope, discard)
        with lock:
            registry[key] = (reference, hashes, frozen_coordinates, False)
        return scope

    def recover(
        records: tuple[UsageRecord, ...],
        scope: _TrustedUsageRecoveryScope,
    ) -> tuple[UsageRecord, ...]:
        normalized_shape = normalize_shape(records)
        hashes = tuple(_usage_record_sha256(record) for record in normalized_shape)
        with lock:
            registered = registry.get(id(scope))
            if (
                type(scope) is not _TrustedUsageRecoveryScope
                or registered is None
                or registered[0]() is not scope
                or registered[1] != hashes
                or registered[3]
            ):
                raise ValueError("journal usage recovery capability is invalid or consumed")
            frozen_coordinates = registered[2]
        normalized = normalize_structural(records, frozen_coordinates)
        if tuple(_usage_record_sha256(record) for record in normalized) != hashes:
            raise ValueError("journal usage recovery changed during validation")
        with lock:
            registered = registry.get(id(scope))
            if (
                registered is None
                or registered[0]() is not scope
                or registered[1] != hashes
                or registered[2] != frozen_coordinates
                or registered[3]
            ):
                raise ValueError("journal usage recovery capability is invalid or consumed")
            registry[id(scope)] = (
                registered[0],
                registered[1],
                registered[2],
                True,
            )
        return tuple(
            _attest_owned_real_usage_record(record)
            if record.execution_evidence is ExecutionEvidenceKind.REAL
            else record
            for record in normalized
        )

    return issue, recover


(
    _issue_trusted_usage_recovery_scope,
    _recover_trusted_usage_records,
) = _build_trusted_usage_recovery_authority()


def _has_valid_bound_identity(record: UsageRecord) -> bool:
    binding = _validated_identity_binding(record)
    return (
        binding is not None
        and binding.strength is not ModelIdentityStrength.UNBOUND
        and binding.generation is not None
        and "unbound_generation_observation" not in record.routing
        and record.routing.get("identity_binding_status") == "generation_metadata_bound"
        and _identity_binding_matches_record(record, binding)
        and binding.generation.generation_id == record.openrouter_generation_id
        and binding.generation.execution_evidence == record.execution_evidence.value
    )


(
    _register_authrunner_owned_real_usage_origin_issuer,
    _attest_authrunner_owned_real_usage_origin,
    _propagate_authrunner_owned_real_usage_origin,
    _has_authrunner_owned_real_usage_origin,
    _revoke_authrunner_owned_real_usage_origin,
    _finalize_authrunner_owned_real_usage_origin_issuer,
) = _build_authrunner_owned_real_usage_origin_authority()
del _build_authrunner_owned_real_usage_origin_authority

(
    _is_strict_usage_record,
    noncrediting_unknown_token_smoke_usage_diagnostics,
) = _build_strict_usage_record_validators()
del _build_strict_usage_record_validators


def _has_valid_unbound_identity_conclusion(record: UsageRecord) -> bool:
    binding = _validated_identity_binding(record)
    return (
        binding is not None
        and binding.strength is ModelIdentityStrength.UNBOUND
        and binding.generation is None
        and record.identity_strength is ModelIdentityStrength.UNBOUND
        and record.routing.get("identity_binding_status") == "generation_metadata_unbound"
        and _has_valid_unbound_generation_observation(record)
        and _identity_binding_matches_record(record, binding)
    )


def _has_valid_unbound_generation_observation(record: UsageRecord) -> bool:
    raw_observation = record.routing.get("unbound_generation_observation")
    if raw_observation is None:
        return True
    if not isinstance(raw_observation, dict):
        return False
    # Import lazily because generation evidence depends on usage validation.
    from mmaudit.models.generation_evidence import OpenRouterGenerationEvidence

    try:
        observation = OpenRouterGenerationEvidence.model_validate(raw_observation)
    except ValidationError:
        return False
    return observation.model_dump(mode="json") == raw_observation


def _validated_identity_binding(
    record: UsageRecord,
) -> OpenRouterIdentityBindingResult | None:
    raw_binding = record.routing.get("identity_binding")
    if not isinstance(raw_binding, dict):
        return None
    try:
        return OpenRouterIdentityBindingResult.model_validate(raw_binding)
    except ValidationError:
        return None


def _identity_binding_matches_record(
    record: UsageRecord,
    binding: OpenRouterIdentityBindingResult,
) -> bool:
    request = binding.request
    started_at = record.started_at
    ended_at = record.ended_at
    if started_at is None or ended_at is None:
        return False
    return (
        binding.strength is record.identity_strength
        and record.routing.get("identity_binding_sha256") == binding.binding_sha256
        and request.internal_request_id == record.request_id
        and request.execution_evidence == record.execution_evidence.value
        and request.requested_slug == record.requested_model
        and request.returned_slug == record.returned_model
        and request.selected_model_slug == record.actual_model
        and request.actual_provider_endpoint == record.actual_provider_endpoint
        and request.actual_provider_name == record.routing.get("selected_provider_name")
        and request.openrouter_generation_id == record.openrouter_generation_id
        and request.request_body_sha256 == record.request_body_sha256
        and request.response_sha256 == record.response_sha256
        and request.validated_response_sha256 == record.validated_response_sha256
        and request.started_at == started_at.astimezone(UTC).replace(microsecond=0)
        and request.completed_at == ended_at.astimezone(UTC).replace(microsecond=0)
        and request.fallback_used == record.routing.get("provider_fallback_used")
        and binding.snapshot.snapshot_sha256 == record.routing.get("identity_snapshot_sha256")
        and binding.snapshot.catalog_identity_binding_sha256
        == record.routing.get("catalog_identity_binding_sha256")
        and binding.snapshot.endpoint_snapshot_sha256
        == record.routing.get("endpoint_snapshot_sha256")
    )


class UsageLedger:
    """Collect immutable request records without global state."""

    def __init__(self) -> None:
        self._records: list[UsageRecord] = []

    def add(self, record: UsageRecord) -> None:
        self._records.append(record)

    def replace_with_bound_identity(self, record: UsageRecord) -> None:
        """Replace one owned provisional record only with its sealed identity upgrade."""

        if not _has_valid_bound_identity(record):
            raise ValueError("usage identity replacement requires a valid bound identity")
        self._replace_with_identity_result(record)

    def replace_with_unbound_identity(self, record: UsageRecord) -> None:
        """Retain one owned fail-closed identity conclusion and bounded diagnostics."""

        if not _has_valid_unbound_identity_conclusion(record):
            raise ValueError("usage identity replacement requires a valid unbound conclusion")
        self._replace_with_identity_result(record)

    def _replace_with_identity_result(self, record: UsageRecord) -> None:
        """Replace a provisional record without changing immutable request evidence."""

        matching = [
            (index, existing)
            for index, existing in enumerate(self._records)
            if existing.request_id == record.request_id
        ]
        if len(matching) != 1:
            raise ValueError("usage identity replacement requires one owned request record")
        index, existing = matching[0]
        if existing == record:
            return
        if existing.execution_evidence is ExecutionEvidenceKind.REAL and (
            not _has_owned_real_usage_attestation(existing)
            or not _has_owned_real_usage_attestation(record)
        ):
            raise ValueError("REAL usage identity replacement requires owned runtime provenance")
        if (
            existing.identity_strength is not ModelIdentityStrength.UNBOUND
            or existing.routing.get("identity_binding_status") != "generation_metadata_pending"
        ):
            raise ValueError("usage identity replacement cannot overwrite a concluded record")
        existing_core = existing.model_dump(
            mode="json",
            exclude={"identity_strength", "routing"},
        )
        replacement_core = record.model_dump(
            mode="json",
            exclude={"identity_strength", "routing"},
        )
        expected_routing = {
            **existing.routing,
            "identity_binding": record.routing.get("identity_binding"),
            "identity_binding_sha256": record.routing.get("identity_binding_sha256"),
            "identity_binding_status": record.routing.get("identity_binding_status"),
        }
        if "unbound_generation_observation" in record.routing:
            expected_routing["unbound_generation_observation"] = record.routing[
                "unbound_generation_observation"
            ]
        if replacement_core != existing_core or record.routing != expected_routing:
            raise ValueError("usage identity replacement changed immutable request evidence")
        self._records[index] = record

    @property
    def records(self) -> list[UsageRecord]:
        return list(self._records)

    @property
    def accounted_cost_usd(self) -> float:
        return sum(record.accounted_cost_usd for record in self._records)

    def role_requests(self, role: str) -> int:
        return sum(1 for record in self._records if record.role == role)
