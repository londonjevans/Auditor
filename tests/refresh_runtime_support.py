"""Coherent synthetic refresh/selection authorities for provider-free tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from mmaudit.config import AuditConfig
from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.policy_selection import (
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    LineageReviewStatus,
    VerifiedProductionQualification,
    seal_candidate_registry,
    seal_operator_lineage_review,
)
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    CANDIDATE_REGISTRY_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshAttempt,
    ModelRefreshDiff,
    ModelRefreshFreshness,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    build_model_refresh_source_evidence,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    seal_model_refresh_attempt,
)
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshEvidence,
    AuditModelRefreshPricingEvidence,
    VerifiedAuditModelRefreshGuard,
    VerifiedAuditModelRefreshPricingAuthority,
    resolve_verified_audit_model_refresh_guard,
    resolve_verified_audit_model_refresh_pricing_authority,
)
from mmaudit.models.refresh_staging import (
    PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
    PREVIOUS_SNAPSHOT_FILENAME,
    PREVIOUS_SOURCE_EVIDENCE_FILENAME,
    PREVIOUS_WORKFLOW_STATUS_FILENAME,
    ModelRefreshWorkflowDisposition,
    ModelRefreshWorkflowStatus,
    StagedModelRefreshArtifact,
    ValidatedModelRefreshHistory,
)
from mmaudit.models.schemas import AuditModelRefreshPricingAttemptEvidence, UsageRecord
from mmaudit.orchestration.budgets import EndpointRequestCostBound
from tests.conftest import MODEL_IDS, base_config_data, model_registry_entry
from tests.qualification_support import synthetic_production_qualification
from tests.unit.test_model_policy_selection import (
    BASE_TIME,
    _policy_authority,
    _policy_bundle,
    _resolve,
)

_JSON_ADAPTER = TypeAdapter(Any)
_PRICING = {"completion": "0.000002", "prompt": "0.000001"}
_PARAMETERS = ["max_tokens", "reasoning", "response_format", "temperature"]
_SOFT_HOURS = 1
_HARD_HOURS = 2
_TOLERANCE = "0.05"


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            _JSON_ADAPTER.dump_python(value, mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SyntheticRefreshRuntime:
    config: AuditConfig
    history: ValidatedModelRefreshHistory
    technical_qualification: VerifiedProductionQualification
    audit_selection_evidence: AuditModelSelectionEvidenceBundle
    audit_selection: VerifiedAuditModelSelection
    evidence: AuditModelRefreshEvidence
    guard: VerifiedAuditModelRefreshGuard
    pricing_evidence: AuditModelRefreshPricingEvidence
    pricing_authority: VerifiedAuditModelRefreshPricingAuthority
    verified_at: datetime

    @property
    def runtime_bindings(self) -> dict[str, str]:
        selection = self.audit_selection_evidence.selection
        return {
            "expected_workflow_status_sha256": (
                self.history.workflow_status.workflow_status_sha256
            ),
            "expected_audit_scope_sha256": selection.audit_scope_sha256,
            "expected_source_sha256": selection.source_sha256,
            "expected_audit_context_sha256": selection.audit_context_sha256,
            "expected_client_constraints_sha256": selection.client_constraints_sha256,
        }


def synthetic_refresh_runtime(
    tmp_path: Path,
    *,
    excluded_ids: frozenset[str] = frozenset(),
    extra_unselected_candidate: bool = False,
    source_sha256_override: str | None = None,
    qualified_pricing: dict[str, str] | None = None,
    previous_pricing: dict[str, str] | None = None,
    current_pricing: dict[str, str] | None = None,
) -> SyntheticRefreshRuntime:
    """Issue coherent refresh and bounded-pricing authorities without provider I/O."""

    config, model_ids, roots = _runtime_config()
    qualified_price_map = dict(_PRICING if qualified_pricing is None else qualified_pricing)
    registry = _candidate_registry(
        config=config,
        model_ids=model_ids,
        roots=roots,
        created_at=BASE_TIME - timedelta(hours=2),
        pricing=qualified_price_map,
    )
    technical = synthetic_production_qualification(
        config,
        BASE_TIME,
        candidate_registry=registry,
    )
    refresh_registry = (
        _registry_with_extra_unselected_candidate(registry)
        if extra_unselected_candidate
        else registry
    )
    policy = _policy_bundle(
        technical,
        excluded_ids=excluded_ids,
        source_sha256_override=source_sha256_override,
    )
    authority = _policy_authority(tmp_path / "policy-authority", policy)
    _selection, audit_evidence, audit_selection = _resolve(technical, policy, authority)
    verified_at = audit_selection.selected_at
    history = _history(
        registry=refresh_registry,
        technical=technical,
        current_at=verified_at,
        previous_pricing=(qualified_price_map if previous_pricing is None else previous_pricing),
        current_pricing=(qualified_price_map if current_pricing is None else current_pricing),
    )
    evidence, guard = resolve_verified_audit_model_refresh_guard(
        history=history,
        expected_workflow_status_sha256=history.workflow_status.workflow_status_sha256,
        expected_source_commit=history.workflow_status.source_commit,
        expected_workflow_run_id=history.workflow_status.workflow_run_id,
        expected_workflow_run_attempt=history.workflow_status.workflow_run_attempt,
        technical_qualification=technical,
        audit_selection_evidence=audit_evidence,
        audit_selection=audit_selection,
        expected_pricing_tolerance_fraction=_TOLERANCE,
        expected_soft_max_age_hours=_SOFT_HOURS,
        expected_hard_max_age_hours=_HARD_HOURS,
        verified_at=verified_at,
    )
    pricing_evidence, pricing_authority = resolve_verified_audit_model_refresh_pricing_authority(
        history=history,
        refresh_evidence=evidence,
        refresh_guard=guard,
        expected_workflow_status_sha256=(history.workflow_status.workflow_status_sha256),
        expected_source_commit=history.workflow_status.source_commit,
        expected_workflow_run_id=history.workflow_status.workflow_run_id,
        expected_workflow_run_attempt=(history.workflow_status.workflow_run_attempt),
        technical_qualification=technical,
        audit_selection_evidence=audit_evidence,
        audit_selection=audit_selection,
        expected_pricing_tolerance_fraction=_TOLERANCE,
        expected_soft_max_age_hours=_SOFT_HOURS,
        expected_hard_max_age_hours=_HARD_HOURS,
        verified_at=verified_at,
    )
    return SyntheticRefreshRuntime(
        config=config,
        history=history,
        technical_qualification=technical,
        audit_selection_evidence=audit_evidence,
        audit_selection=audit_selection,
        evidence=evidence,
        guard=guard,
        pricing_evidence=pricing_evidence,
        pricing_authority=pricing_authority,
        verified_at=verified_at,
    )


def synthetic_refresh_runtime_for_authorities(
    *,
    config: AuditConfig,
    candidate_registry: CandidateRegistry,
    technical_qualification: VerifiedProductionQualification,
    audit_selection_evidence: AuditModelSelectionEvidenceBundle,
    audit_selection: VerifiedAuditModelSelection,
    verified_at: datetime,
    current_pricing: dict[str, str] | None = None,
) -> SyntheticRefreshRuntime:
    """Issue exact CURRENT refresh custody for already-resolved synthetic authorities."""

    history = _history(
        registry=candidate_registry,
        technical=technical_qualification,
        current_at=verified_at,
        current_pricing=current_pricing,
    )
    evidence, guard = resolve_verified_audit_model_refresh_guard(
        history=history,
        expected_workflow_status_sha256=history.workflow_status.workflow_status_sha256,
        expected_source_commit=history.workflow_status.source_commit,
        expected_workflow_run_id=history.workflow_status.workflow_run_id,
        expected_workflow_run_attempt=history.workflow_status.workflow_run_attempt,
        technical_qualification=technical_qualification,
        audit_selection_evidence=audit_selection_evidence,
        audit_selection=audit_selection,
        expected_pricing_tolerance_fraction=_TOLERANCE,
        expected_soft_max_age_hours=_SOFT_HOURS,
        expected_hard_max_age_hours=_HARD_HOURS,
        verified_at=verified_at,
    )
    pricing_evidence, pricing_authority = resolve_verified_audit_model_refresh_pricing_authority(
        history=history,
        refresh_evidence=evidence,
        refresh_guard=guard,
        expected_workflow_status_sha256=(history.workflow_status.workflow_status_sha256),
        expected_source_commit=history.workflow_status.source_commit,
        expected_workflow_run_id=history.workflow_status.workflow_run_id,
        expected_workflow_run_attempt=(history.workflow_status.workflow_run_attempt),
        technical_qualification=technical_qualification,
        audit_selection_evidence=audit_selection_evidence,
        audit_selection=audit_selection,
        expected_pricing_tolerance_fraction=_TOLERANCE,
        expected_soft_max_age_hours=_SOFT_HOURS,
        expected_hard_max_age_hours=_HARD_HOURS,
        verified_at=verified_at,
    )
    return SyntheticRefreshRuntime(
        config=config,
        history=history,
        technical_qualification=technical_qualification,
        audit_selection_evidence=audit_selection_evidence,
        audit_selection=audit_selection,
        evidence=evidence,
        guard=guard,
        pricing_evidence=pricing_evidence,
        pricing_authority=pricing_authority,
        verified_at=verified_at,
    )


def bind_usage_to_refresh_runtime(
    record: UsageRecord,
    runtime: SyntheticRefreshRuntime,
) -> UsageRecord:
    """Attach the exact non-authorizing refresh route and scalar transport joins."""

    routes = tuple(
        route
        for route in runtime.evidence.routes
        if route.exact_model_id == record.requested_model and route.audit_selected
    )
    if len(routes) != 1:
        raise ValueError("synthetic usage model lacks an exact audit refresh route")
    route = routes[0]
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "audit_model_refresh_evidence_sha256": runtime.evidence.evidence_sha256,
                "audit_model_refresh_workflow_status_sha256": (
                    runtime.evidence.workflow_status_sha256
                ),
                "audit_model_refresh_snapshot_sha256": runtime.evidence.snapshot_sha256,
                "audit_model_refresh_route_evidence_sha256": route.route_evidence_sha256,
                "audit_model_refresh_guard_capability_sha256": (runtime.guard.capability_sha256),
                "audit_model_refresh_technical_route_set_sha256": (
                    runtime.evidence.technical_route_set_sha256
                ),
                "audit_model_refresh_audit_route_set_sha256": (
                    runtime.evidence.audit_route_set_sha256
                ),
                "audit_model_refresh_expires_at": runtime.evidence.expires_at.isoformat(),
                "audit_model_refresh_route_evidence": route.model_dump(mode="json"),
            }
        }
    )


def bind_usage_to_refresh_pricing_runtime(
    record: UsageRecord,
    runtime: SyntheticRefreshRuntime,
) -> UsageRecord:
    """Attach exact non-authorizing refreshed prices and per-attempt cost bounds."""

    routes = tuple(
        route
        for route in runtime.pricing_evidence.routes
        if route.exact_model_id == record.requested_model and route.audit_selected
    )
    if len(routes) != 1:
        raise ValueError("synthetic usage model lacks an exact audit pricing route")
    route = routes[0]
    if record.request_body_sha256 is None:
        raise ValueError("synthetic pricing custody requires a request-body hash")
    current_endpoint_snapshot_sha256 = record.routing.get("endpoint_snapshot_sha256")
    if not isinstance(current_endpoint_snapshot_sha256, str):
        raise ValueError("synthetic pricing custody requires a current endpoint snapshot")

    provider_max_price: dict[str, str] = {}
    cost_bound_pricing: dict[str, str] = {}
    with localcontext() as context:
        context.prec = 160
        for field, raw_price in route.current_pricing.items():
            current = Decimal(raw_price)
            if field in {"completion", "image", "prompt"}:
                cap = current * Decimal(1_000_000)
                provider_max_price[field] = _canonical_decimal(cap)
                cost_bound_pricing[field] = _canonical_decimal(cap / Decimal(1_000_000))
            elif field == "request":
                provider_max_price[field] = _canonical_decimal(current)
                cost_bound_pricing[field] = _canonical_decimal(current)
            else:
                cost_bound_pricing[field] = _canonical_decimal(current)
    maximum_units = {field: 1_000_000_000 for field in cost_bound_pricing}
    provisional_bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=record.requested_model,
        provider_endpoint=route.approved_provider_endpoint,
        request_material="synthetic refresh-runtime request",
        pricing=cost_bound_pricing,
        maximum_units=maximum_units,
    )
    endpoint_bound = EndpointRequestCostBound(
        exact_model_id=provisional_bound.exact_model_id,
        provider_endpoint=provisional_bound.provider_endpoint,
        request_material_sha256=record.request_body_sha256,
        pricing_snapshot_sha256=provisional_bound.pricing_snapshot_sha256,
        components=provisional_bound.components,
    )
    checked_at = record.started_at or record.timestamp
    attempts = tuple(
        AuditModelRefreshPricingAttemptEvidence.from_bound(
            logical_request_id=record.request_id,
            attempt_request_id=(
                record.request_id
                if attempt_index == 1
                else f"{record.request_id}:attempt:{attempt_index}"
            ),
            attempt_index=attempt_index,
            reservation_checked_at=checked_at,
            transport_checked_at=checked_at,
            current_endpoint_snapshot_sha256=current_endpoint_snapshot_sha256,
            request_body_sha256=record.request_body_sha256,
            pricing_evidence=runtime.pricing_evidence,
            pricing_authority=runtime.pricing_authority,
            pricing_route=route,
            endpoint_cost_bound=endpoint_bound,
            provider_max_price=provider_max_price,
        )
        for attempt_index in range(1, record.attempts + 1)
    )
    final_attempt = attempts[-1]
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "endpoint_snapshot_sha256": current_endpoint_snapshot_sha256,
                "endpoint_pricing_sha256": route.current_pricing_sha256,
                "qualified_pricing_snapshot_sha256": (route.qualified_pricing_snapshot_sha256),
                "audit_model_refresh_pricing_route_evidence": route.model_dump(mode="json"),
                "audit_model_refresh_pricing_evidence_sha256": (
                    runtime.pricing_evidence.evidence_sha256
                ),
                "audit_model_refresh_pricing_workflow_status_sha256": (
                    runtime.pricing_evidence.workflow_status_sha256
                ),
                "audit_model_refresh_pricing_previous_snapshot_sha256": (
                    runtime.pricing_evidence.previous_snapshot_sha256
                ),
                "audit_model_refresh_pricing_current_snapshot_sha256": (
                    runtime.pricing_evidence.current_snapshot_sha256
                ),
                "audit_model_refresh_pricing_refresh_evidence_sha256": (
                    runtime.pricing_evidence.refresh_evidence_sha256
                ),
                "audit_model_refresh_pricing_refresh_guard_capability_sha256": (
                    runtime.pricing_evidence.refresh_guard_capability_sha256
                ),
                "audit_model_refresh_pricing_route_evidence_sha256": (route.route_evidence_sha256),
                "audit_model_refresh_pricing_authority_capability_sha256": (
                    runtime.pricing_authority.capability_sha256
                ),
                "audit_model_refresh_pricing_technical_route_set_sha256": (
                    runtime.pricing_evidence.technical_pricing_route_set_sha256
                ),
                "audit_model_refresh_pricing_audit_route_set_sha256": (
                    runtime.pricing_evidence.audit_pricing_route_set_sha256
                ),
                "audit_model_refresh_pricing_qualified_pricing_snapshot_sha256": (
                    route.qualified_pricing_snapshot_sha256
                ),
                "audit_model_refresh_pricing_current_pricing_snapshot_sha256": (
                    route.current_pricing_sha256
                ),
                "audit_model_refresh_pricing_tolerance_fraction": (
                    runtime.pricing_evidence.pricing_tolerance_fraction
                ),
                "audit_model_refresh_pricing_expires_at": (
                    runtime.pricing_evidence.expires_at.isoformat()
                ),
                "audit_model_refresh_pricing_attempts": [
                    attempt.model_dump(mode="json") for attempt in attempts
                ],
                "audit_model_refresh_pricing_attempt_sha256s": [
                    attempt.evidence_sha256 for attempt in attempts
                ],
                "audit_model_refresh_pricing_attempt": final_attempt.model_dump(mode="json"),
                "audit_model_refresh_pricing_attempt_sha256": final_attempt.evidence_sha256,
            }
        }
    )


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _registry_with_extra_unselected_candidate(registry: CandidateRegistry) -> CandidateRegistry:
    model_id = "juliet/jade-new"
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.PENDING,
        reviewed_model_ids=(model_id,),
        rationale="Synthetic newly discovered unselected candidate.",
    )
    extra = CandidateModel(
        exact_model_id=model_id,
        canonical_model_slug=model_id,
        root_lineage=None,
        lineage_review=review,
        discovery_evidence_sha256=_sha(["discovery", model_id]),
        approved_provider_endpoint="provider-extra/fp8",
        approved_provider_name="Synthetic Provider",
        endpoint_snapshot_sha256=_sha(["endpoint", model_id]),
        output_capability_sha256=hashlib.sha256(f"output:{model_id}".encode()).hexdigest(),
        model_metadata_snapshot_sha256=_sha(["metadata", model_id]),
        pricing_snapshot_sha256=_sha(_PRICING),
        context_size=100_000,
        max_prompt_tokens=91_808,
        max_prompt_tokens_source="metadata",
        output_limit=8_192,
        output_limit_source="metadata",
        structured_output_supported=True,
        structured_output_mode=StructuredOutputMode.JSON_OBJECT,
        reasoning_supported=True,
        zdr_eligible=True,
        data_collection_deny_eligible=True,
        operational_status=CandidateOperationalStatus.AVAILABLE,
        benchmark_status=CandidateBenchmarkStatus.PENDING,
    )
    return seal_candidate_registry(
        created_at=registry.created_at + timedelta(seconds=1),
        discovery_run_sha256=_sha(["runtime-refresh-extra", registry.registry_sha256]),
        candidates=(*registry.candidates, extra),
    )


def _runtime_config() -> tuple[AuditConfig, tuple[str, ...], tuple[str, ...]]:
    data = base_config_data()
    base_ids = tuple(MODEL_IDS.values())
    extra_ids = (
        "golf/glacier-secure",
        "hotel/harbor-secure",
        "india/ion-secure",
    )
    model_ids = (*base_ids, *extra_ids)
    roots = tuple(f"sha256:{_sha(f'root-{index}')}" for index in range(6))
    data["privacy"]["approved_model_lineages"] = list(roots)
    data["models"]["registry"] = [
        model_registry_entry(
            model_id,
            root_lineage=roots[index] if index < 6 else roots[index - 6],
        )
        for index, model_id in enumerate(model_ids)
    ]
    data["models"]["specialists"] = {
        "access_control": {"primary": extra_ids[0], "fallbacks": []},
        "false_negative_hunter": {"primary": extra_ids[1], "fallbacks": []},
        "report_quality": {"primary": extra_ids[2], "fallbacks": []},
    }
    return AuditConfig.model_validate(data), tuple(sorted(model_ids)), roots


def _candidate_registry(
    *,
    config: AuditConfig,
    model_ids: tuple[str, ...],
    roots: tuple[str, ...],
    created_at: datetime,
    provider_endpoint: str | None = None,
    provider_name: str = "Synthetic Provider",
    pricing: dict[str, str] | None = None,
) -> CandidateRegistry:
    roles = (*ALL_MODEL_ROLES, *tuple(sorted(config.models.specialists)))
    approved_roles = tuple(sorted({*roles, "falsifier", "whole_protocol_review"}))
    configured_roots = {
        entry["canonical_model_id"]: entry["root_lineage"]
        for entry in config.model_dump(mode="json")["models"]["registry"]
    }
    configured_roots.update(
        {
            model_id: f"sha256:{hashlib.sha256(f'lineage:{model_id}'.encode()).hexdigest()}"
            for model_id in model_ids
            if model_id not in configured_roots
        }
    )
    expiry = created_at + timedelta(days=30)
    model_ids_by_root = {
        root: tuple(model_id for model_id in model_ids if configured_roots[model_id] == root)
        for root in sorted(set(configured_roots.values()))
    }
    reviews = {
        root: seal_operator_lineage_review(
            status=LineageReviewStatus.APPROVED,
            reviewed_model_ids=reviewed_model_ids,
            rationale="Synthetic independent lineage review for provider-free testing.",
            root_lineage=root,
            reviewed_by="synthetic-reviewer",
            reviewed_at=created_at,
            evidence_sha256=_sha(["lineage", root, *reviewed_model_ids]),
        )
        for root, reviewed_model_ids in model_ids_by_root.items()
    }
    candidates: list[CandidateModel] = []
    for index, model_id in enumerate(model_ids):
        root = configured_roots[model_id]
        endpoint = provider_endpoint or f"provider-{index}/fp8"
        candidates.append(
            CandidateModel(
                exact_model_id=model_id,
                canonical_model_slug=model_id,
                root_lineage=root,
                lineage_review=reviews[root],
                discovery_evidence_sha256=_sha(["discovery", model_id]),
                approved_provider_endpoint=endpoint,
                approved_provider_name=provider_name,
                endpoint_snapshot_sha256=_sha(["endpoint", model_id]),
                output_capability_sha256=_sha(["output", model_id]),
                model_metadata_snapshot_sha256=_sha(["metadata", model_id]),
                pricing_snapshot_sha256=_sha(_PRICING if pricing is None else pricing),
                context_size=100_000,
                max_prompt_tokens=91_808,
                max_prompt_tokens_source="metadata",
                output_limit=8_192,
                output_limit_source="metadata",
                structured_output_supported=True,
                structured_output_mode=StructuredOutputMode.JSON_OBJECT,
                reasoning_supported=True,
                zdr_eligible=True,
                data_collection_deny_eligible=True,
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PASSED,
                benchmark_artifact_sha256=hashlib.sha256(f"report:{model_id}".encode()).hexdigest(),
                qualification_expires_at=expiry,
                approved_roles=approved_roles,
            )
        )
    assert len(roots) >= 6
    return seal_candidate_registry(
        created_at=created_at,
        discovery_run_sha256=_sha(["runtime-refresh", *model_ids]),
        candidates=tuple(candidates),
    )


def _history(
    *,
    registry: CandidateRegistry,
    technical: VerifiedProductionQualification,
    current_at: datetime,
    previous_pricing: dict[str, str] | None = None,
    current_pricing: dict[str, str] | None = None,
) -> ValidatedModelRefreshHistory:
    previous_at = current_at - timedelta(hours=1)
    previous_source, previous_snapshot = _source_snapshot(
        registry,
        previous_at,
        pricing=previous_pricing,
    )
    current_source, current_snapshot = _source_snapshot(
        registry,
        current_at,
        pricing=current_pricing,
    )
    selected_routes = tuple(
        SelectedModelRoute(
            exact_model_id=model.exact_model_id,
            provider_endpoint=model.approved_provider_endpoint,
        )
        for model in technical.models
    )
    diff = diff_model_refresh(
        current=current_snapshot,
        previous=previous_snapshot,
        previous_source_evidence=previous_source,
        previous_candidate_registry=registry,
        candidate_registry=registry,
        pricing_tolerance_fraction=_TOLERANCE,
        compared_at=current_at,
        selected_routes=selected_routes,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=current_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=current_snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=current_at,
        snapshot=current_snapshot,
        soft_max_age_hours=_SOFT_HOURS,
        hard_max_age_hours=_HARD_HOURS,
        production_selection_present=True,
    )
    previous_status = _workflow_status(
        validated_at=previous_at,
        run_id="100",
        registry=registry,
        source=previous_source,
        snapshot=previous_snapshot,
    )
    status = _workflow_status(
        validated_at=current_at,
        run_id="101",
        registry=registry,
        source=current_source,
        snapshot=current_snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
        previous_status=previous_status,
        previous_registry=registry,
        previous_source=previous_source,
        previous_snapshot=previous_snapshot,
    )
    return ValidatedModelRefreshHistory(
        workflow_status=status,
        candidate_registry=registry,
        source_evidence=current_source,
        snapshot=current_snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
        previous_workflow_status=previous_status,
        previous_candidate_registry=registry,
        previous_source_evidence=previous_source,
        previous_snapshot=previous_snapshot,
    )


def _source_snapshot(
    registry: CandidateRegistry,
    retrieved_at: datetime,
    *,
    pricing: dict[str, str] | None = None,
) -> tuple[ModelRefreshSourceEvidence, ModelRefreshSnapshot]:
    catalog = [_catalog_model(candidate.exact_model_id) for candidate in registry.candidates]
    endpoints = [
        _endpoint(
            candidate.exact_model_id,
            candidate.approved_provider_endpoint,
            pricing=pricing,
        )
        for candidate in registry.candidates
    ]
    payloads = {
        candidate.exact_model_id: _endpoint_envelope(
            candidate.exact_model_id,
            _endpoint(
                candidate.exact_model_id,
                candidate.approved_provider_endpoint,
                pricing=pricing,
            ),
        )
        for candidate in registry.candidates
    }
    source = build_model_refresh_source_evidence(
        retrieved_at=retrieved_at,
        catalog_payload={"data": catalog},
        zdr_payload={"data": endpoints},
        candidate_registry=registry,
        candidate_endpoint_payloads=payloads,
        authenticated_metadata=True,
    )
    return source, build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )


def _catalog_model(model_id: str) -> dict[str, Any]:
    return {
        "id": model_id,
        "canonical_slug": model_id,
        "context_length": 100_000,
        "top_provider": {
            "context_length": 100_000,
            "max_completion_tokens": 8_192,
        },
        "supported_parameters": list(_PARAMETERS),
    }


def _endpoint(
    model_id: str,
    endpoint: str,
    *,
    pricing: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "model_id": model_id,
        "slug": endpoint,
        "provider_name": "Synthetic Provider",
        "status": 0,
        "context_length": 100_000,
        "max_prompt_tokens": 91_808,
        "max_completion_tokens": 8_192,
        "supported_parameters": list(_PARAMETERS),
        "pricing": dict(_PRICING if pricing is None else pricing),
    }


def _endpoint_envelope(model_id: str, endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": {
            "id": model_id,
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }


def _binding(filename: str, artifact_sha256: str) -> StagedModelRefreshArtifact:
    return StagedModelRefreshArtifact(
        filename=filename,
        content_sha256=_sha(["content", filename, artifact_sha256]),
        artifact_sha256=artifact_sha256,
        byte_count=1,
    )


def _workflow_status(
    *,
    validated_at: datetime,
    run_id: str,
    registry: CandidateRegistry,
    source: ModelRefreshSourceEvidence,
    snapshot: ModelRefreshSnapshot,
    diff: ModelRefreshDiff | None = None,
    attempt: ModelRefreshAttempt | None = None,
    freshness: ModelRefreshFreshness | None = None,
    previous_status: ModelRefreshWorkflowStatus | None = None,
    previous_registry: CandidateRegistry | None = None,
    previous_source: ModelRefreshSourceEvidence | None = None,
    previous_snapshot: ModelRefreshSnapshot | None = None,
) -> ModelRefreshWorkflowStatus:
    current_hashes = {
        CANDIDATE_REGISTRY_FILENAME: registry.registry_sha256,
        SOURCE_EVIDENCE_FILENAME: source.source_evidence_sha256,
        SNAPSHOT_FILENAME: snapshot.snapshot_sha256,
        DIFF_FILENAME: _sha(["previous-diff", run_id]) if diff is None else diff.diff_sha256,
        ATTEMPT_FILENAME: (
            _sha(["previous-attempt", run_id]) if attempt is None else attempt.attempt_sha256
        ),
        FRESHNESS_FILENAME: (
            _sha(["previous-freshness", run_id])
            if freshness is None
            else freshness.freshness_sha256
        ),
    }
    predecessor_hashes: dict[str, str] = {}
    if previous_status is not None:
        assert previous_registry is not None
        assert previous_source is not None
        assert previous_snapshot is not None
        predecessor_hashes = {
            PREVIOUS_WORKFLOW_STATUS_FILENAME: previous_status.workflow_status_sha256,
            PREVIOUS_CANDIDATE_REGISTRY_FILENAME: previous_registry.registry_sha256,
            PREVIOUS_SOURCE_EVIDENCE_FILENAME: previous_source.source_evidence_sha256,
            PREVIOUS_SNAPSHOT_FILENAME: previous_snapshot.snapshot_sha256,
        }
    artifacts = tuple(
        _binding(filename, artifact_sha256)
        for filename, artifact_sha256 in sorted({**current_hashes, **predecessor_hashes}.items())
    )
    values: dict[str, Any] = {
        "schema_version": "4.0",
        "validated_at": validated_at,
        "disposition": ModelRefreshWorkflowDisposition.COMPLETED.value,
        "refresh_exit_status": 0,
        "source_commit": "1" * 40,
        "workflow_run_id": run_id,
        "workflow_run_attempt": "1",
        "previous_workflow_run_id": (
            None if previous_status is None else previous_status.workflow_run_id
        ),
        "previous_workflow_run_attempt": (
            None if previous_status is None else previous_status.workflow_run_attempt
        ),
        "previous_workflow_status_sha256": (
            None if previous_status is None else previous_status.workflow_status_sha256
        ),
        "candidate_registry_sha256": registry.registry_sha256,
        "pricing_tolerance_fraction": _TOLERANCE,
        "soft_max_age_hours": _SOFT_HOURS,
        "hard_max_age_hours": _HARD_HOURS,
        "policy_projection_expected": False,
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts],
    }
    values["workflow_status_sha256"] = _sha(values)
    return ModelRefreshWorkflowStatus.model_validate(values)
