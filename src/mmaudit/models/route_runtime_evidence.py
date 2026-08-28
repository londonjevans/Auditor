"""Durable, nonauthorizing runtime evidence for exact route predicates.

The public artifact is a structural projection of one canonical authenticated-runner
smoke bundle.  It cannot issue provider, runner, qualification, campaign, or release
authority.  Only the opaque PID-local capability returned by the verifier may be used
to derive runtime-predicate transition reasons.
"""

from __future__ import annotations

import json
import os
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

import mmaudit.models.route_constraints as _route_constraints_module
from mmaudit.models.authenticated_runner_smoke import (
    MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES,
    AuthenticatedRunnerSmokeCostPlan,
    AuthenticatedRunnerSmokeEvidenceBundle,
    AuthenticatedRunnerSmokeRunEvidence,
    authenticated_runner_smoke_evidence_bytes,
    revalidate_authenticated_runner_smoke_evidence_bytes,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import CandidateModel, QualificationPolicy
from mmaudit.models.reasoning import (
    INDEPENDENT_REASONING_COMPONENT_ENVELOPE_METHOD,
    TokenDetailAccountingEvidence,
)
from mmaudit.models.route_constraints import (
    ExactRouteRole,
    NormalizedRouteFacts,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateReason,
    RoutePredicateReport,
    bind_live_route_facts,
    bind_registry_route_facts,
    bind_runtime_route_facts,
    evaluate_route_predicates,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    StructuredOutputEvidence,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    RequestTokenPlan,
    request_token_plan_projection_sha256,
)
from mmaudit.models.usage import structurally_noncrediting_unknown_token_smoke_usage_error
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json_bytes

MAX_ROUTE_RUNTIME_EVIDENCE_BYTES: Final[int] = MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES + 250_000
"""Maximum canonical size of one runtime projection and its embedded source bundle."""

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_FUTURE_SKEW = timedelta(minutes=5)
_AUTHORITY_FIELDS = (
    "full_corpus_execution_completed",
    "benchmark_authorized",
    "benchmark_scoring_authorized",
    "grants_review_credit",
    "grants_completion_credit",
    "model_qualification_authorized",
    "calibration_authorized",
    "production_selection_authorized",
    "runner_custody_authorized",
    "runner_authority_authorized",
    "authseal_comparison_authorized",
    "seal_publication_authorized",
    "audit_execution_authorized",
    "audit_completion_authorized",
    "authority_issuance_authorized",
    "provider_call_authorized",
    "source_egress_authorized",
    "baseline_update_authorized",
    "release_authorized",
    "campaign_admission_authorized",
)


class RouteRuntimeEvidenceError(ValueError):
    """Durable runtime evidence is malformed, mismatched, or not verifiable."""


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class RouteRuntimeObservation(_FrozenStrictModel):
    """Exact runtime observations derived for one constrained campaign route."""

    schema_version: Literal["1.0"] = "1.0"
    role: ExactRouteRole
    exact_model_id: str = Field(min_length=3, max_length=300)
    canonical_model_slug: str = Field(min_length=3, max_length=300)
    provider_endpoint: str = Field(min_length=1, max_length=256)
    provider_name: str = Field(min_length=1, max_length=256)
    selection_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    route_predicate_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    exact_route_constraint_sha256: str = Field(pattern=_SHA256_PATTERN)
    registry_route_predicate_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_run_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    request_ids: tuple[str, ...] = Field(min_length=1, max_length=2)
    usage_record_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    request_cost_plan_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    request_cost_preview_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    request_body_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    response_schema_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    validated_response_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    structured_output_evidence_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    token_detail_evidence_sha256s: tuple[str, ...] = Field(min_length=1, max_length=2)
    usage_ended_at: tuple[datetime, ...] = Field(min_length=1, max_length=2)
    observed_from: datetime
    observed_through: datetime
    empirical_schema_conformance_proven: bool
    token_detail_reporting_convention_proven: bool
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("usage_ended_at", "observed_from", "observed_through")
    @classmethod
    def timestamps_are_utc(
        cls,
        value: tuple[datetime, ...] | datetime,
    ) -> tuple[datetime, ...] | datetime:
        values = value if isinstance(value, tuple) else (value,)
        if any(item.tzinfo is None or item.utcoffset() != timedelta(0) for item in values):
            raise ValueError("route runtime observation timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def inventory_and_hash_are_exact(self) -> Self:
        expected_count = 2 if self.role is ExactRouteRole.CANDIDATE else 1
        inventories = (
            self.source_run_sha256s,
            self.request_ids,
            self.usage_record_sha256s,
            self.request_cost_plan_sha256s,
            self.request_cost_preview_sha256s,
            self.request_body_sha256s,
            self.response_schema_sha256s,
            self.validated_response_sha256s,
            self.structured_output_evidence_sha256s,
            self.token_detail_evidence_sha256s,
            self.usage_ended_at,
        )
        if any(len(items) != expected_count for items in inventories):
            raise ValueError("route runtime observation has the wrong role inventory")
        unique_inventories = (
            self.source_run_sha256s,
            self.request_ids,
            self.usage_record_sha256s,
            self.request_cost_plan_sha256s,
            self.request_cost_preview_sha256s,
            self.request_body_sha256s,
            self.structured_output_evidence_sha256s,
            self.token_detail_evidence_sha256s,
        )
        if any(len(set(items)) != len(items) for items in unique_inventories):
            raise ValueError("route runtime observation reuses source evidence")
        if (
            tuple(sorted(self.usage_ended_at)) != self.usage_ended_at
            or self.observed_from != self.usage_ended_at[0]
            or self.observed_through != self.usage_ended_at[-1]
        ):
            raise ValueError("route runtime observation interval is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"observation_sha256"}))
        if self.observation_sha256 != expected:
            raise ValueError("route runtime observation hash is inconsistent")
        return self


class RouteRuntimeEvidenceArtifact(_FrozenStrictModel):
    """Canonical runtime projection retaining its complete nonauthorizing source."""

    artifact_kind: Literal["authenticated_runner_route_runtime_evidence"] = (
        "authenticated_runner_route_runtime_evidence"
    )
    schema_version: Literal["1.0"] = "1.0"
    source_kind: Literal["AUTHENTICATED_RUNNER_NONCREDITING_SMOKE_V1_2"] = (
        "AUTHENTICATED_RUNNER_NONCREDITING_SMOKE_V1_2"
    )
    source_bundle: AuthenticatedRunnerSmokeEvidenceBundle
    source_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    maximum_benchmark_evidence_age_days: int = Field(ge=1, le=30)
    observations: tuple[RouteRuntimeObservation, ...] = Field(min_length=3, max_length=3)
    full_corpus_execution_completed: Literal[False] = False
    benchmark_authorized: Literal[False] = False
    benchmark_scoring_authorized: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    calibration_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    runner_authority_authorized: Literal[False] = False
    authseal_comparison_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    audit_execution_authorized: Literal[False] = False
    audit_completion_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    baseline_update_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    campaign_admission_authorized: Literal[False] = False
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(*_AUTHORITY_FIELDS, mode="before")
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("route runtime evidence grants no authority or credit")
        return value

    @model_validator(mode="after")
    def source_projection_and_hash_are_exact(self) -> Self:
        if (
            self.source_bundle.schema_version != "1.2"
            or self.source_bundle_sha256 != self.source_bundle.bundle_sha256
        ):
            raise ValueError("route runtime evidence source is not an exact smoke v1.2 bundle")
        expected_observations = _derive_runtime_observations(self.source_bundle)
        if self.observations != expected_observations:
            raise ValueError("route runtime observations differ from their durable source")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"artifact_sha256"}))
        if self.artifact_sha256 != expected:
            raise ValueError("route runtime evidence hash is inconsistent")
        return self


class VerifiedThreeRouteRuntimeEvidence:
    """Opaque PID-local proof of canonical three-route runtime evidence replay."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> VerifiedThreeRouteRuntimeEvidence:
        del cls
        raise TypeError("verified three-route runtime evidence cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified three-route runtime evidence cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified three-route runtime evidence cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified three-route runtime evidence cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified three-route runtime evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class _VerifiedRuntimeEvidenceState:
    process_id: int
    artifact_bytes: bytes
    artifact_sha256: str
    qualification_policy_json: str
    qualification_policy_sha256: str
    nonce: object


@dataclass(frozen=True, slots=True)
class _RuntimeSourceItem:
    run: AuthenticatedRunnerSmokeRunEvidence
    model: CandidateModel
    plan: AuthenticatedRunnerSmokeCostPlan
    usage: UsageRecord
    proof_kind: Literal[
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
    ]


def _validated_policy(policy: QualificationPolicy) -> QualificationPolicy:
    if type(policy) is not QualificationPolicy:
        raise RouteRuntimeEvidenceError("route runtime qualification policy type is invalid")
    try:
        raw = policy.model_dump_json()
        validated = QualificationPolicy.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError):
        raise RouteRuntimeEvidenceError("route runtime qualification policy is invalid") from None
    if type(validated) is not QualificationPolicy or validated != policy:
        raise RouteRuntimeEvidenceError("route runtime qualification policy changed on replay")
    return validated


def _usage_sha256(usage: UsageRecord) -> str:
    return canonical_sha256(usage.model_dump(mode="json"))


def _structured_output_evidence(usage: UsageRecord) -> StructuredOutputEvidence | None:
    raw = usage.routing.get("structured_output")
    if type(raw) is not dict:
        return None
    try:
        evidence = StructuredOutputEvidence.model_validate(raw)
    except (TypeError, ValueError, ValidationError):
        return None
    return evidence if type(evidence) is StructuredOutputEvidence else None


def _token_detail_evidence(usage: UsageRecord) -> TokenDetailAccountingEvidence | None:
    evidence = usage.token_detail_accounting_evidence
    return evidence if type(evidence) is TokenDetailAccountingEvidence else None


def _request_token_plan(usage: UsageRecord) -> RequestTokenPlan | None:
    raw = usage.routing.get("request_token_plan")
    if type(raw) is not dict:
        return None
    try:
        plan = RequestTokenPlan.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError, ValidationError):
        return None
    if type(plan) is not RequestTokenPlan or plan.model_dump(mode="json") != raw:
        return None
    return plan


def _schema_proof_is_valid(item: _RuntimeSourceItem) -> bool:
    usage = item.usage
    model = item.model
    preview = item.plan.request_preview
    structured = _structured_output_evidence(usage)
    return (
        usage.attempts == 1
        and usage.retry_count == 0
        and model.structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        and preview.structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        and preview.strict_output_protocol_sha256 is None
        and structured is not None
        and structured.model_dump(mode="json") == usage.routing.get("structured_output")
        and structured.requested_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        and structured.achieved_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        and structured.configured_provider_endpoints == tuple(usage.configured_provider_endpoints)
        and structured.selected_provider_endpoint == usage.actual_provider_endpoint
        and structured.prompt_sha256 == usage.prompt_sha256
        and structured.request_body_sha256 == usage.request_body_sha256
        and structured.provider_policy_sha256 == usage.routing.get("provider_policy_sha256")
        and structured.schema_sha256 == usage.schema_sha256
        and structured.original_response_sha256 == usage.response_sha256
        and structured.validated_response_sha256 == usage.validated_response_sha256
        and not structured.repair_used
        and not structured.truncated
        and usage.routing.get("repair_used") is False
        and usage.routing.get("repair_request") is False
        and usage.routing.get("structured_output_mode")
        == StructuredOutputMode.NATIVE_JSON_SCHEMA.value
        and usage.routing.get("structured_output_request_shape_sha256")
        == structured.request_shape_sha256
        and usage.routing.get("structured_output_protocol_sha256") is None
        and preview.output_request_shape_sha256 == structured.request_shape_sha256
        and preview.response_schema_sha256 == structured.schema_sha256
        and preview.output_capability_sha256 == structured.output_capability_sha256
        and preview.endpoint_policy_snapshot_sha256 == structured.endpoint_snapshot_sha256
    )


def _token_detail_proof_is_valid(item: _RuntimeSourceItem) -> bool:
    plan = _request_token_plan(item.usage)
    evidence = _token_detail_evidence(item.usage)
    return (
        item.plan.request_preview.schema_version == "1.1"
        and plan is not None
        and plan.schema_version == "3.0"
        and evidence is not None
        and evidence.accounting_method == INDEPENDENT_REASONING_COMPONENT_ENVELOPE_METHOD
        and plan.token_detail_accounting_method == evidence.accounting_method
        and item.plan.request_preview.token_detail_accounting_method == evidence.accounting_method
        and evidence.completion_semantics == "UNKNOWN_INCLUSIVE_OR_ADDITIVE"
        and evidence.accounting_basis == "FULL_REQUEST_PLAN_RESERVATION"
        and evidence.provider_total_relation == "PROMPT_PLUS_COMPLETION"
        and evidence.request_body_sha256 == item.usage.request_body_sha256
        and evidence.request_token_plan_sha256 == plan.plan_sha256
        and item.usage.routing.get("request_token_plan_sha256") == plan.plan_sha256
        and item.plan.request_preview.request_token_plan_projection_sha256
        == request_token_plan_projection_sha256(plan)
        and plan.wire_max_tokens
        == item.plan.request_preview.wire_max_tokens
        == plan.reserved_output_tokens
        and evidence.planned_prompt_tokens
        == plan.prompt_byte_upper_bound_tokens
        == item.plan.request_preview.prompt_byte_upper_bound_tokens
        and evidence.planned_visible_output_tokens
        == plan.reserved_output_tokens
        == item.plan.request_preview.reserved_output_tokens
        and evidence.planned_reasoning_tokens
        == plan.reserved_reasoning_tokens
        == item.plan.request_preview.reserved_reasoning_tokens
        and evidence.planned_completion_tokens
        == plan.requested_completion_tokens
        == item.plan.request_preview.requested_completion_tokens
    )


def _validate_source_item(item: _RuntimeSourceItem) -> None:
    usage = item.usage
    model = item.model
    preview = item.plan.request_preview
    route_custody = (
        model.selection_plan_sha256,
        model.route_predicate_profile_sha256,
        model.exact_route_constraint_sha256,
        model.route_predicate_report_sha256,
    )
    if (
        type(item.run) is not AuthenticatedRunnerSmokeRunEvidence
        or type(model) is not CandidateModel
        or type(item.plan) is not AuthenticatedRunnerSmokeCostPlan
        or type(usage) is not UsageRecord
        or any(value is None for value in route_custody)
        or model.output_capability_sha256 is None
        or usage.execution_evidence is not ExecutionEvidenceKind.REAL
        or usage.validation_status is not ModelRequestValidationStatus.VALID
        or usage.status != "success"
        or usage.fallback_used
        or usage.substitution_detected
        or structurally_noncrediting_unknown_token_smoke_usage_error(usage) is not None
        or usage.routing.get("privacy_source_proof_kind") != item.proof_kind
        or usage.ended_at is None
        or usage.ended_at.tzinfo is None
        or usage.ended_at.utcoffset() != timedelta(0)
    ):
        raise ValueError("route runtime source usage is not a route-bound REAL success")
    if (
        preview.schema_version != "1.1"
        or preview.exact_model_id != model.exact_model_id
        or preview.provider_endpoint != model.approved_provider_endpoint
        or preview.discovery_evidence_sha256 != model.discovery_evidence_sha256
        or preview.endpoint_policy_snapshot_sha256 != model.endpoint_snapshot_sha256
        or preview.output_capability_sha256 != model.output_capability_sha256
        or preview.response_schema_sha256 != usage.schema_sha256
    ):
        raise ValueError("route runtime source differs from its exact route preview")


def _one_exact(values: tuple[Any, ...], *, label: str) -> Any:
    if not values or any(value != values[0] for value in values[1:]):
        raise ValueError(f"route runtime source has inconsistent {label}")
    return values[0]


def _derive_observation(
    role: ExactRouteRole,
    items: tuple[_RuntimeSourceItem, ...],
) -> RouteRuntimeObservation:
    expected_count = 2 if role is ExactRouteRole.CANDIDATE else 1
    if len(items) != expected_count:
        raise ValueError("route runtime source has the wrong role usage count")
    for item in items:
        _validate_source_item(item)
    models = tuple(item.model for item in items)
    previews = tuple(item.plan.request_preview for item in items)
    usages = tuple(item.usage for item in items)
    structured = tuple(_structured_output_evidence(usage) for usage in usages)
    token_details = tuple(_token_detail_evidence(usage) for usage in usages)
    ended_at = tuple(sorted(usage.ended_at for usage in usages if usage.ended_at is not None))
    route_custody = (
        "exact_model_id",
        "canonical_model_slug",
        "approved_provider_endpoint",
        "approved_provider_name",
        "selection_plan_sha256",
        "route_predicate_profile_sha256",
        "exact_route_constraint_sha256",
        "route_predicate_report_sha256",
        "discovery_evidence_sha256",
        "endpoint_snapshot_sha256",
        "output_capability_sha256",
    )
    common_model = {
        field: _one_exact(
            tuple(getattr(model, field) for model in models),
            label=field,
        )
        for field in route_custody
    }
    common_preview = {
        field: _one_exact(
            tuple(getattr(preview, field) for preview in previews),
            label=field,
        )
        for field in (
            "discovery_manifest_sha256",
            "discovery_evidence_sha256",
            "discovery_provenance_sha256",
        )
    }
    if common_model["discovery_evidence_sha256"] != common_preview["discovery_evidence_sha256"]:
        raise ValueError("route runtime source discovery binding is inconsistent")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "role": role,
        "exact_model_id": common_model["exact_model_id"],
        "canonical_model_slug": common_model["canonical_model_slug"],
        "provider_endpoint": common_model["approved_provider_endpoint"],
        "provider_name": common_model["approved_provider_name"],
        "selection_plan_sha256": common_model["selection_plan_sha256"],
        "route_predicate_profile_sha256": common_model["route_predicate_profile_sha256"],
        "exact_route_constraint_sha256": common_model["exact_route_constraint_sha256"],
        "registry_route_predicate_report_sha256": common_model["route_predicate_report_sha256"],
        "discovery_manifest_sha256": common_preview["discovery_manifest_sha256"],
        "discovery_evidence_sha256": common_preview["discovery_evidence_sha256"],
        "discovery_provenance_sha256": common_preview["discovery_provenance_sha256"],
        "endpoint_snapshot_sha256": common_model["endpoint_snapshot_sha256"],
        "output_capability_sha256": common_model["output_capability_sha256"],
        "source_run_sha256s": tuple(item.run.run_sha256 for item in items),
        "request_ids": tuple(usage.request_id for usage in usages),
        "usage_record_sha256s": tuple(_usage_sha256(usage) for usage in usages),
        "request_cost_plan_sha256s": tuple(item.plan.plan_sha256 for item in items),
        "request_cost_preview_sha256s": tuple(preview.preview_sha256 for preview in previews),
        "request_body_sha256s": tuple(usage.request_body_sha256 for usage in usages),
        "response_schema_sha256s": tuple(usage.schema_sha256 for usage in usages),
        "validated_response_sha256s": tuple(usage.validated_response_sha256 for usage in usages),
        "structured_output_evidence_sha256s": tuple(
            (
                evidence.evidence_sha256
                if evidence is not None
                else canonical_sha256(usage.routing.get("structured_output"))
            )
            for evidence, usage in zip(structured, usages, strict=True)
        ),
        "token_detail_evidence_sha256s": tuple(
            evidence.evidence_sha256 if evidence is not None else canonical_sha256(None)
            for evidence in token_details
        ),
        "usage_ended_at": ended_at,
        "observed_from": ended_at[0],
        "observed_through": ended_at[-1],
        "empirical_schema_conformance_proven": all(_schema_proof_is_valid(item) for item in items),
        "token_detail_reporting_convention_proven": all(
            _token_detail_proof_is_valid(item) for item in items
        ),
    }
    if any(
        value is None
        for field in (
            "request_body_sha256s",
            "response_schema_sha256s",
            "validated_response_sha256s",
        )
        for value in payload[field]
    ):
        raise ValueError("route runtime source usage lacks required hashes")
    unsealed = RouteRuntimeObservation.model_construct(
        **payload,
        observation_sha256="0" * 64,
    )
    payload["observation_sha256"] = canonical_sha256(
        unsealed.model_dump(mode="json", exclude={"observation_sha256"})
    )
    return RouteRuntimeObservation.model_validate(payload, strict=True)


def _derive_runtime_observations(
    bundle: AuthenticatedRunnerSmokeEvidenceBundle,
) -> tuple[RouteRuntimeObservation, RouteRuntimeObservation, RouteRuntimeObservation]:
    if type(bundle) is not AuthenticatedRunnerSmokeEvidenceBundle or bundle.schema_version not in {
        "1.2",
        "1.3",
    }:
        raise ValueError("route runtime evidence requires an exact smoke v1.2 or v1.3 bundle")
    primary, replay = bundle.runs
    primary_candidate_usage = primary.candidate_report.result.usage_record
    replay_candidate_usage = replay.candidate_report.result.usage_record
    primary_judge_usage = primary.adjudication_report.cases[0].usage_record
    replay_judge_usage = replay.adjudication_report.cases[0].usage_record
    if any(
        usage is None
        for usage in (
            primary_candidate_usage,
            replay_candidate_usage,
            primary_judge_usage,
            replay_judge_usage,
        )
    ):
        raise ValueError("route runtime evidence lacks its complete usage inventory")
    assert primary_candidate_usage is not None
    assert replay_candidate_usage is not None
    assert primary_judge_usage is not None
    assert replay_judge_usage is not None
    return (
        _derive_observation(
            ExactRouteRole.CANDIDATE,
            (
                _RuntimeSourceItem(
                    run=primary,
                    model=primary.candidate,
                    plan=primary.candidate_cost_plan,
                    usage=primary_candidate_usage,
                    proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
                ),
                _RuntimeSourceItem(
                    run=replay,
                    model=replay.candidate,
                    plan=replay.candidate_cost_plan,
                    usage=replay_candidate_usage,
                    proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
                ),
            ),
        ),
        _derive_observation(
            ExactRouteRole.PRIMARY_JUDGE,
            (
                _RuntimeSourceItem(
                    run=primary,
                    model=primary.judge,
                    plan=primary.judge_cost_plan,
                    usage=primary_judge_usage,
                    proof_kind="PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
                ),
            ),
        ),
        _derive_observation(
            ExactRouteRole.REPLAY_JUDGE,
            (
                _RuntimeSourceItem(
                    run=replay,
                    model=replay.judge,
                    plan=replay.judge_cost_plan,
                    usage=replay_judge_usage,
                    proof_kind="PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
                ),
            ),
        ),
    )


def build_route_runtime_evidence_artifact(
    *,
    smoke_bundle: AuthenticatedRunnerSmokeEvidenceBundle,
    qualification_policy: QualificationPolicy,
) -> RouteRuntimeEvidenceArtifact:
    """Derive runtime observations solely from canonical sealed smoke evidence."""

    if type(smoke_bundle) is not AuthenticatedRunnerSmokeEvidenceBundle:
        raise RouteRuntimeEvidenceError("route runtime smoke bundle type is invalid")
    policy = _validated_policy(qualification_policy)
    try:
        bundle = revalidate_authenticated_runner_smoke_evidence_bytes(
            authenticated_runner_smoke_evidence_bytes(smoke_bundle)
        )
        observations = _derive_runtime_observations(bundle)
        hash_payload: dict[str, Any] = {
            "artifact_kind": "authenticated_runner_route_runtime_evidence",
            "schema_version": "1.0",
            "source_kind": "AUTHENTICATED_RUNNER_NONCREDITING_SMOKE_V1_2",
            "source_bundle": bundle.model_dump(mode="json"),
            "source_bundle_sha256": bundle.bundle_sha256,
            "qualification_policy_sha256": policy.policy_sha256,
            "maximum_benchmark_evidence_age_days": (policy.maximum_benchmark_evidence_age_days),
            "observations": tuple(item.model_dump(mode="json") for item in observations),
            **{field: False for field in _AUTHORITY_FIELDS},
        }
        payload: dict[str, Any] = {
            **hash_payload,
            "source_bundle": bundle,
            "observations": observations,
            "artifact_sha256": canonical_sha256(hash_payload),
        }
        artifact = RouteRuntimeEvidenceArtifact.model_validate(payload, strict=True)
        return revalidate_route_runtime_evidence_bytes(route_runtime_evidence_bytes(artifact))
    except RouteRuntimeEvidenceError:
        raise
    except (IndexError, TypeError, ValueError, ValidationError):
        raise RouteRuntimeEvidenceError(
            "authenticated runner smoke evidence cannot prove exact runtime predicates"
        ) from None


def route_runtime_evidence_bytes(artifact: RouteRuntimeEvidenceArtifact) -> bytes:
    """Return the sole bounded canonical serialization of one runtime artifact."""

    if type(artifact) is not RouteRuntimeEvidenceArtifact:
        raise RouteRuntimeEvidenceError("route runtime evidence artifact type is invalid")
    try:
        raw = stable_json_bytes(artifact)
    except (TypeError, ValueError, ValidationError):
        raise RouteRuntimeEvidenceError("route runtime evidence artifact is invalid") from None
    if not raw or len(raw) > MAX_ROUTE_RUNTIME_EVIDENCE_BYTES:
        raise RouteRuntimeEvidenceError("route runtime evidence artifact exceeds its byte bound")
    return raw


def revalidate_route_runtime_evidence_bytes(raw: bytes) -> RouteRuntimeEvidenceArtifact:
    """Replay only the exact canonical bounded runtime artifact representation."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_ROUTE_RUNTIME_EVIDENCE_BYTES:
        raise RouteRuntimeEvidenceError("route runtime evidence bytes are invalid")
    try:
        artifact = RouteRuntimeEvidenceArtifact.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError):
        raise RouteRuntimeEvidenceError("route runtime evidence bytes do not validate") from None
    if type(artifact) is not RouteRuntimeEvidenceArtifact:
        raise RouteRuntimeEvidenceError("route runtime parser returned the wrong exact type")
    if route_runtime_evidence_bytes(artifact) != raw:
        raise RouteRuntimeEvidenceError("route runtime evidence bytes are not canonical")
    return artifact


def _runtime_binding_matches(
    observation: RouteRuntimeObservation,
    *,
    role: ExactRouteRole,
    model: CandidateModel,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
    facts: NormalizedRouteFacts,
    report: RoutePredicateReport,
) -> bool:
    matching_artifacts = tuple(
        item
        for item in manifest.artifacts
        if item.exact_model_id == model.exact_model_id
        and item.approved_provider_endpoint == model.approved_provider_endpoint
    )
    snapshot = evidence.endpoint_snapshot
    profile = snapshot.route_predicate_profile
    constraint = snapshot.exact_route_constraint
    discovery_facts = snapshot.normalized_route_facts
    discovery_report = snapshot.route_predicate_report
    if profile is None or constraint is None or discovery_facts is None or discovery_report is None:
        return False
    return (
        role is observation.role
        and model.exact_model_id == observation.exact_model_id
        and model.canonical_model_slug == observation.canonical_model_slug
        and model.approved_provider_endpoint == observation.provider_endpoint
        and model.approved_provider_name == observation.provider_name
        and model.selection_plan_sha256 == observation.selection_plan_sha256
        and model.route_predicate_profile_sha256 == observation.route_predicate_profile_sha256
        and model.exact_route_constraint_sha256 == observation.exact_route_constraint_sha256
        and model.route_predicate_report_sha256
        == observation.registry_route_predicate_report_sha256
        and model.discovery_evidence_sha256 == observation.discovery_evidence_sha256
        and model.endpoint_snapshot_sha256 == observation.endpoint_snapshot_sha256
        and model.output_capability_sha256 == observation.output_capability_sha256
        and manifest.manifest_sha256 == observation.discovery_manifest_sha256
        and manifest.run_provenance.provenance_sha256 == observation.discovery_provenance_sha256
        and len(matching_artifacts) == 1
        and matching_artifacts[0].discovery_evidence_sha256 == observation.discovery_evidence_sha256
        and evidence.exact_model_id == observation.exact_model_id
        and evidence.canonical_slug == observation.canonical_model_slug
        and evidence.approved_provider_endpoint == observation.provider_endpoint
        and evidence.provider_name == observation.provider_name
        and evidence.discovery_evidence_sha256 == observation.discovery_evidence_sha256
        and evidence.provenance.provenance_sha256 == observation.discovery_provenance_sha256
        and evidence.endpoint_snapshot_sha256 == observation.endpoint_snapshot_sha256
        and evidence.output_capability_sha256 == observation.output_capability_sha256
        and snapshot.snapshot_sha256 == observation.endpoint_snapshot_sha256
        and profile.profile_sha256 == observation.route_predicate_profile_sha256
        and constraint.constraint_sha256 == observation.exact_route_constraint_sha256
        and constraint.profile_sha256 == profile.profile_sha256
        and constraint.role is role
        and constraint.exact_model_id == observation.exact_model_id
        and constraint.provider_endpoint == observation.provider_endpoint
        and discovery_facts.expected_selection_plan_sha256 == observation.selection_plan_sha256
        and discovery_report.profile_sha256 == profile.profile_sha256
        and discovery_report.constraint_sha256 == constraint.constraint_sha256
        and discovery_report.facts_sha256 == discovery_facts.facts_sha256
        and facts.expected_selection_plan_sha256 == observation.selection_plan_sha256
        and facts.registry_selection_plan_sha256 == observation.selection_plan_sha256
        and facts.registry_profile_sha256 == observation.route_predicate_profile_sha256
        and facts.registry_constraint_sha256 == observation.exact_route_constraint_sha256
        and report.profile_sha256 == observation.route_predicate_profile_sha256
        and report.constraint_sha256 == observation.exact_route_constraint_sha256
        and report.facts_sha256 == facts.facts_sha256
    )


def _runtime_freshness_reason(
    observation: RouteRuntimeObservation,
    policy: QualificationPolicy,
    now: datetime,
) -> RoutePredicateReason | None:
    if (
        observation.observed_through > now + _FUTURE_SKEW
        or now - observation.observed_from
        >= timedelta(days=policy.maximum_benchmark_evidence_age_days)
    ):
        return RoutePredicateReason.RUNTIME_EVIDENCE_STALE
    return None


def _runtime_freshness_reason_for_test(
    observation: RouteRuntimeObservation,
    qualification_policy: QualificationPolicy,
    *,
    now: datetime,
) -> RoutePredicateReason | None:
    """Pure deterministic age classifier; it cannot issue a runtime capability."""

    if type(observation) is not RouteRuntimeObservation:
        raise RouteRuntimeEvidenceError("route runtime test observation type is invalid")
    policy = _validated_policy(qualification_policy)
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise RouteRuntimeEvidenceError("route runtime test time is invalid")
    return _runtime_freshness_reason(observation, policy, now)


def _build_runtime_capability_authority() -> tuple[
    Callable[..., VerifiedThreeRouteRuntimeEvidence],
    Callable[
        [
            VerifiedThreeRouteRuntimeEvidence,
            ExactRouteRole,
            CandidateModel,
            OpenRouterModelDiscoveryRunManifest,
            OpenRouterModelDiscoveryEvidence,
            NormalizedRouteFacts,
            RoutePredicateReport,
            QualificationPolicy,
        ],
        tuple[RoutePredicateReason | None, RoutePredicateReason | None],
    ],
]:
    registry: weakref.WeakKeyDictionary[
        VerifiedThreeRouteRuntimeEvidence, _VerifiedRuntimeEvidenceState
    ] = weakref.WeakKeyDictionary()
    lock = threading.RLock()
    trusted_getpid = os.getpid
    trusted_datetime_now = datetime.now
    trusted_utc = UTC
    capability_type = VerifiedThreeRouteRuntimeEvidence
    artifact_type = RouteRuntimeEvidenceArtifact
    policy_type = QualificationPolicy
    model_type = CandidateModel
    manifest_type = OpenRouterModelDiscoveryRunManifest
    evidence_type = OpenRouterModelDiscoveryEvidence
    facts_type = NormalizedRouteFacts
    report_type = RoutePredicateReport
    trusted_artifact_bytes = route_runtime_evidence_bytes
    trusted_revalidate_artifact = revalidate_route_runtime_evidence_bytes
    trusted_policy_validator = _validated_policy
    trusted_binding_matches = _runtime_binding_matches
    trusted_bind_registry_facts = bind_registry_route_facts
    trusted_bind_live_facts = bind_live_route_facts
    trusted_bind_runtime_facts = bind_runtime_route_facts
    trusted_evaluate_predicates = evaluate_route_predicates
    trusted_future_skew = _FUTURE_SKEW
    trusted_timedelta = timedelta
    trusted_invalid_reason = RoutePredicateReason.RUNTIME_EVIDENCE_INVALID
    trusted_mismatch_reason = RoutePredicateReason.RUNTIME_EVIDENCE_BINDING_MISMATCH
    trusted_stale_reason = RoutePredicateReason.RUNTIME_EVIDENCE_STALE
    trusted_empirical_id = RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE
    trusted_token_detail_id = RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION
    trusted_unavailable = RoutePredicateDisposition.UNAVAILABLE
    trusted_empirical_unavailable = RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE
    trusted_token_detail_unavailable = RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE

    def system_clock() -> datetime:
        return trusted_datetime_now(trusted_utc).replace(microsecond=0)

    def issue(
        artifact: RouteRuntimeEvidenceArtifact,
        qualification_policy: QualificationPolicy,
    ) -> VerifiedThreeRouteRuntimeEvidence:
        if type(artifact) is not artifact_type:
            raise RouteRuntimeEvidenceError("route runtime verification artifact type is invalid")
        policy = trusted_policy_validator(qualification_policy)
        try:
            raw = trusted_artifact_bytes(artifact)
            replayed = trusted_revalidate_artifact(raw)
        except RouteRuntimeEvidenceError:
            raise
        if (
            replayed.qualification_policy_sha256 != policy.policy_sha256
            or replayed.maximum_benchmark_evidence_age_days
            != policy.maximum_benchmark_evidence_age_days
        ):
            raise RouteRuntimeEvidenceError(
                "route runtime evidence differs from the qualification policy"
            )
        now = system_clock()
        if (
            type(now) is not datetime
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
            or now.microsecond != 0
        ):
            raise RouteRuntimeEvidenceError("route runtime verification clock is invalid")
        capability = object.__new__(capability_type)
        state = _VerifiedRuntimeEvidenceState(
            process_id=trusted_getpid(),
            artifact_bytes=raw,
            artifact_sha256=replayed.artifact_sha256,
            qualification_policy_json=policy.model_dump_json(),
            qualification_policy_sha256=policy.policy_sha256,
            nonce=object(),
        )
        with lock:
            registry[capability] = state
        return capability

    def verify(
        artifact: RouteRuntimeEvidenceArtifact,
        qualification_policy: QualificationPolicy,
    ) -> VerifiedThreeRouteRuntimeEvidence:
        return issue(artifact, qualification_policy)

    def reasons(
        capability: VerifiedThreeRouteRuntimeEvidence,
        role: ExactRouteRole,
        model: CandidateModel,
        manifest: OpenRouterModelDiscoveryRunManifest,
        evidence: OpenRouterModelDiscoveryEvidence,
        facts: NormalizedRouteFacts,
        report: RoutePredicateReport,
        qualification_policy: QualificationPolicy,
    ) -> tuple[RoutePredicateReason | None, RoutePredicateReason | None]:
        invalid = (
            trusted_invalid_reason,
            trusted_invalid_reason,
        )
        mismatch = (
            trusted_mismatch_reason,
            trusted_mismatch_reason,
        )
        stale = (
            trusted_stale_reason,
            trusted_stale_reason,
        )
        if type(capability) is not capability_type:
            return invalid
        with lock:
            state = registry.get(capability)
        if state is None or state.process_id != trusted_getpid():
            return invalid
        try:
            artifact = trusted_revalidate_artifact(state.artifact_bytes)
            issued_policy = policy_type.model_validate_json(state.qualification_policy_json)
            policy = trusted_policy_validator(qualification_policy)
            now = system_clock()
        except (RouteRuntimeEvidenceError, TypeError, ValueError, ValidationError):
            return invalid
        if (
            type(artifact) is not artifact_type
            or artifact.artifact_sha256 != state.artifact_sha256
            or type(issued_policy) is not policy_type
            or issued_policy.policy_sha256 != state.qualification_policy_sha256
            or policy != issued_policy
            or policy.model_dump_json() != state.qualification_policy_json
            or artifact.qualification_policy_sha256 != policy.policy_sha256
            or artifact.maximum_benchmark_evidence_age_days
            != policy.maximum_benchmark_evidence_age_days
            or type(now) is not datetime
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
            or now.microsecond != 0
            or type(role) is not ExactRouteRole
            or type(model) is not model_type
            or type(manifest) is not manifest_type
            or type(evidence) is not evidence_type
            or type(facts) is not facts_type
            or type(report) is not report_type
        ):
            return invalid
        try:
            detached_model = model_type.model_validate_json(model.model_dump_json())
            detached_manifest = manifest_type.model_validate_json(manifest.model_dump_json())
            detached_evidence = evidence_type.model_validate_json(evidence.model_dump_json())
            detached_facts = facts_type.model_validate_json(facts.model_dump_json())
            detached_report = report_type.model_validate_json(report.model_dump_json())
        except (TypeError, ValueError, ValidationError):
            return invalid
        matches = tuple(item for item in artifact.observations if item.role is role)
        if len(matches) != 1:
            return invalid
        observation = matches[0]
        profile = detached_evidence.endpoint_snapshot.route_predicate_profile
        constraint = detached_evidence.endpoint_snapshot.exact_route_constraint
        discovery_facts = detached_evidence.endpoint_snapshot.normalized_route_facts
        if profile is None or constraint is None or discovery_facts is None:
            return mismatch
        try:
            expected_registry_facts = trusted_bind_registry_facts(
                discovery_facts,
                registry_selection_plan_sha256=observation.selection_plan_sha256,
                profile=profile,
                constraint=constraint,
            )
            expected_registry_report = trusted_evaluate_predicates(
                profile=profile,
                constraint=constraint,
                facts=expected_registry_facts,
            )
            expected_facts = expected_registry_facts
            if detached_facts.frozen_live_equivalent is not None:
                expected_facts = trusted_bind_live_facts(
                    expected_facts,
                    frozen_live_equivalent=detached_facts.frozen_live_equivalent,
                )
            if detached_facts.runtime_required_output_tokens is None:
                return mismatch
            expected_facts = trusted_bind_runtime_facts(
                expected_facts,
                required_output_tokens=detached_facts.runtime_required_output_tokens,
            )
            expected_report = trusted_evaluate_predicates(
                profile=profile,
                constraint=constraint,
                facts=detached_facts,
            )
        except (TypeError, ValueError):
            return mismatch
        if (
            expected_registry_report.report_sha256
            != observation.registry_route_predicate_report_sha256
            or expected_registry_report.report_sha256
            != detached_model.route_predicate_report_sha256
            or expected_facts != detached_facts
            or expected_report != detached_report
        ):
            return mismatch
        if not trusted_binding_matches(
            observation,
            role=role,
            model=detached_model,
            manifest=detached_manifest,
            evidence=detached_evidence,
            facts=detached_facts,
            report=detached_report,
        ):
            return mismatch
        if (
            observation.observed_through > now + trusted_future_skew
            or now - observation.observed_from
            >= trusted_timedelta(days=policy.maximum_benchmark_evidence_age_days)
        ):
            return stale
        results = {item.predicate_id: item for item in detached_report.results}
        empirical = results.get(trusted_empirical_id)
        token_detail = results.get(trusted_token_detail_id)
        empirical_ready = (
            empirical is not None
            and empirical.disposition is trusted_unavailable
            and empirical.reason is trusted_empirical_unavailable
        )
        token_detail_ready = (
            token_detail is not None
            and token_detail.disposition is trusted_unavailable
            and token_detail.reason is trusted_token_detail_unavailable
        )
        return (
            (
                None
                if observation.empirical_schema_conformance_proven and empirical_ready
                else trusted_invalid_reason
            ),
            (
                None
                if observation.token_detail_reporting_convention_proven and token_detail_ready
                else trusted_invalid_reason
            ),
        )

    return verify, reasons


(
    verify_route_runtime_evidence,
    _runtime_predicate_transition_reasons,
) = _build_runtime_capability_authority()
del _build_runtime_capability_authority


def runtime_predicate_transition_reasons(
    capability: VerifiedThreeRouteRuntimeEvidence,
    *,
    role: ExactRouteRole,
    model: CandidateModel,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
    facts: NormalizedRouteFacts,
    report: RoutePredicateReport,
    qualification_policy: QualificationPolicy,
) -> tuple[RoutePredicateReason | None, RoutePredicateReason | None]:
    """Derive the two FULL-only transition reasons from exact verified evidence."""

    return _runtime_predicate_transition_reasons(
        capability,
        role,
        model,
        manifest,
        evidence,
        facts,
        report,
        qualification_policy,
    )


_route_constraints_module._register_runtime_predicate_consumer(
    module_globals=globals(),
    consumer=runtime_predicate_transition_reasons,
)
del _route_constraints_module


__all__ = [
    "MAX_ROUTE_RUNTIME_EVIDENCE_BYTES",
    "RouteRuntimeEvidenceArtifact",
    "RouteRuntimeEvidenceError",
    "RouteRuntimeObservation",
    "VerifiedThreeRouteRuntimeEvidence",
    "build_route_runtime_evidence_artifact",
    "revalidate_route_runtime_evidence_bytes",
    "route_runtime_evidence_bytes",
    "runtime_predicate_transition_reasons",
    "verify_route_runtime_evidence",
]
