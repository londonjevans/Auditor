from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    ModelRequestValidationStatus,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.orchestration.model_coverage import (
    build_model_review_coverage,
    build_model_surface_requests,
    model_review_critical_surface_gate,
    plan_model_surface_review_assignments,
)


def _entity(
    entity_id: str,
    kind: SolidityEntityKind,
    name: str,
    line: int,
    *,
    contract_name: str | None = "Vault",
    visibility: str | None = None,
    signature: str | None = None,
) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=kind,
        name=name,
        contract_name=contract_name,
        path="src/Vault.sol",
        start_line=line,
        end_line=line + 1,
        byte_start=line,
        byte_end=line + 1,
        source_hash="a" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_model_coverage_test",
        visibility=visibility,
        signature=signature,
    )


def _edge(
    graph: SolidityGraphKind,
    source_id: str,
    target_id: str,
    label: str,
    line: int,
) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=label,
        provenance=SolidityProvenance.COMPILER,
        path="src/Vault.sol",
        start_line=line,
        end_line=line,
        source_hash="a" * 64,
        confidence=1,
        transformation="synthetic_model_coverage_test",
    )


def _inventory() -> tuple[SoliditySymbolIndex, SolidityGraphSet, InvariantSuite]:
    index = SoliditySymbolIndex(
        projects=[
            SolidityProjectMetadata(
                project_type=SolidityProjectType.FOUNDRY,
                project_root=".",
                source_directories=["src"],
            )
        ],
        entities=[
            _entity(
                "contract:Vault",
                SolidityEntityKind.CONTRACT,
                "Vault",
                1,
                contract_name=None,
            ),
            _entity(
                "function:Vault.deposit",
                SolidityEntityKind.FUNCTION,
                "deposit",
                10,
                visibility="external",
                signature="deposit(uint256)",
            ),
            _entity(
                "function:Vault.adminSet",
                SolidityEntityKind.FUNCTION,
                "adminSet",
                20,
                visibility="public",
                signature="adminSet(uint256)",
            ),
            _entity(
                "state:Vault.totalAssets",
                SolidityEntityKind.STATE_VARIABLE,
                "totalAssets",
                5,
            ),
        ],
        ast_sources=["src/Vault.sol"],
    )
    graphs = SolidityGraphSet(
        edges=[
            _edge(
                SolidityGraphKind.ASSET_FLOW,
                "function:Vault.deposit",
                "asset:synthetic",
                "observed asset inflow",
                11,
            ),
            _edge(
                SolidityGraphKind.PRIVILEGE,
                "function:Vault.adminSet",
                "role:admin",
                "administrator guarded transition",
                21,
            ),
            _edge(
                SolidityGraphKind.EXTERNAL_CALL,
                "function:Vault.deposit",
                "external:token",
                "bounded synthetic token call",
                12,
            ),
            _edge(
                SolidityGraphKind.STATE_WRITE,
                "function:Vault.deposit",
                "state:Vault.totalAssets",
                "writes totalAssets",
                13,
            ),
        ]
    )
    invariants = InvariantSuite(
        invariants=[
            InvariantSpec(
                id="inv:observed-assets",
                title="Observed assets back accounting",
                category=InvariantCategory.ACCOUNTING,
                description="Recorded accounting cannot exceed locally observed assets.",
                template=InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
                locations=[
                    Location(
                        path="src/Vault.sol",
                        start_line=10,
                        end_line=14,
                        content_hash="a" * 64,
                    )
                ],
                entity_ids=["function:Vault.deposit"],
                state_variables=["totalAssets"],
                functions=["deposit(uint256)"],
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                template_available=True,
                evidence_hash="b" * 64,
            )
        ],
        templates_available_count=1,
    )
    return index, graphs, invariants


def _usage(
    role: str,
    model_id: str,
    request_id: str,
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> UsageRecord:
    started_at = datetime.now(UTC)
    generation_id = f"generation-{request_id}"
    schema_sha256 = "e" * 64
    return UsageRecord(
        request_id=request_id,
        role=role,
        execution_evidence=execution_evidence,
        requested_model=model_id,
        returned_model=model_id,
        actual_model=model_id,
        provider="approved-provider",
        model_family=model_id.split("/", 1)[0],
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=20,
        total_tokens=120,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing={
            "generation_id": generation_id,
            "selected_model": model_id,
            "selected_provider_endpoint": "approved-provider",
            "router_strategy": "direct",
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "f" * 64,
            "provider_policy_sha256": "0" * 64,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "request_started_at": started_at.isoformat(),
            "request_ended_at": started_at.isoformat(),
            "latency_ms": 0,
        },
        prompt_sha256="c" * 64,
        response_sha256="d" * 64,
        validated_response_sha256="f" * 64,
        request_body_sha256="a" * 64,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=["approved-provider"],
        actual_provider_endpoint="approved-provider",
        started_at=started_at,
        ended_at=started_at,
        latency_ms=0,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )


def _record(
    request: ModelSurfaceReviewRequest,
    role: str,
    *,
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
) -> ModelSurfaceReviewRecord:
    if request.allowed_locations:
        location = request.allowed_locations[0]
        citation = ModelSurfaceReviewCitation(
            location=location,
            symbol=location.symbol,
        )
    else:
        citation = ModelSurfaceReviewCitation(symbol=request.allowed_symbols[0])
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=role,
        status=status,
        rationale="The named invariant and reachable state transition were reviewed.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        assumptions=(),
        confidence=0.9,
    )


def _artifact(
    requests: list[ModelSurfaceReviewRequest],
    usage: UsageRecord,
    *,
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    manifest_sha256: str | None = None,
) -> ModelSurfaceReviewArtifact:
    records = tuple(_record(request, usage.role, status=status) for request in requests)
    ids = tuple(request.surface_id for request in requests)
    payload = {
        "schema_version": "1.0",
        "request_id": usage.request_id,
        "review_role": usage.role,
        "requested_surface_ids": list(ids),
        "requested_surface_ids_sha256": hashlib.sha256(
            json.dumps(
                list(ids),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
        "requested_surface_manifest_sha256": manifest_sha256
        or ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests),
        "prompt_sha256": usage.prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in records],
    }
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    return ModelSurfaceReviewArtifact.model_validate(payload)


def _requests() -> tuple[
    SoliditySymbolIndex,
    SolidityGraphSet,
    InvariantSuite,
    list[ModelSurfaceReviewRequest],
]:
    index, graphs, invariants = _inventory()
    requests = build_model_surface_requests(
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )
    return index, graphs, invariants, requests


def test_surface_requests_cover_full_deterministic_inventory() -> None:
    _, _, _, requests = _requests()

    assert len(requests) == 9
    assert requests == sorted(requests, key=lambda request: request.surface_id)
    assert set(request.kind for request in requests) == set(ModelReviewSurfaceKind)
    assert all(
        request.contract
        and request.function_or_state_surface
        and (request.allowed_locations or request.allowed_symbols)
        and request.invariant_considered
        for request in requests
    )


def test_surface_request_plan_distributes_critical_surfaces_across_lineages(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    _, _, _, requests = _requests()

    assignments = plan_model_surface_review_assignments(config, requests)

    assigned_roles = {
        request.surface_id: [
            role for role, role_requests in assignments.items() if request in role_requests
        ]
        for request in requests
    }
    assert all(
        len(assigned_roles[request.surface_id]) == (3 if request.critical else 1)
        for request in requests
    )
    assert all(
        role_requests == sorted(role_requests, key=lambda item: item.surface_id)
        for role_requests in assignments.values()
    )


def test_surface_request_plan_excludes_unapproved_lineage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    excluded = next(
        entry.root_lineage
        for entry in base.models.registry
        if entry.canonical_model_id == base.models.configuration.primary
    )
    approved = tuple(
        lineage for lineage in base.privacy.approved_model_lineages if lineage != excluded
    )
    config = base.model_copy(
        update={"privacy": base.privacy.model_copy(update={"approved_model_lineages": approved})}
    )
    _, _, _, requests = _requests()

    assignments = plan_model_surface_review_assignments(config, requests)

    for request in requests:
        assigned = sum(request in role_requests for role_requests in assignments.values())
        assert assigned == (2 if request.critical else 1)


def test_context_delivery_or_successful_usage_without_response_earns_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, _ = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-context-only")

    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.denominator == 9
    assert coverage.overall.numerator == 0
    assert all(not surface.evidence_references for surface in coverage.surfaces)
    assert not coverage.critical_gate_passed


def test_three_independent_response_lineages_cover_critical_surfaces(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", config.models.source_audit.primary, "request-1"),
        _usage("business_logic", config.models.business_logic.primary, "request-2"),
        _usage("configuration", config.models.configuration.primary, "request-3"),
    ]

    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=[_artifact(requests, usage) for usage in usages],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == coverage.overall.denominator == 9
    assert coverage.critical.numerator == coverage.critical.denominator == 9
    assert coverage.critical_gate_passed
    assert all(len(surface.root_lineages) == 3 for surface in coverage.surfaces)
    assert all(len(surface.evidence_references) == 3 for surface in coverage.surfaces)
    assert ModelReviewCoverage.model_validate_json(coverage.model_dump_json()) == coverage


def test_mock_and_unregistered_models_are_retained_as_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    mock = _usage(
        "source_audit",
        config.models.source_audit.primary,
        "request-mock",
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )
    unknown = _usage("source_audit", "unknown/unqualified", "request-unknown")

    coverage = build_model_review_coverage(
        config,
        usage_records=[mock, unknown],
        review_artifacts=[_artifact(requests, mock), _artifact(requests, unknown)],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(len(surface.evidence_references) == 2 for surface in coverage.surfaces)
    assert all(
        all(not reference.credited for reference in surface.evidence_references)
        for surface in coverage.surfaces
    )
    assert any("mock model usage was excluded" in item for item in coverage.limitations)
    assert any("unregistered model" in item for item in coverage.limitations)


def test_same_lineage_aliases_do_not_inflate_independence(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    source = base.models.source_audit.primary
    alias = "mirror/borealis-secure"
    registry = [
        entry.model_copy(update={"aliases": (alias,)})
        if entry.canonical_model_id == source
        else entry
        for entry in base.models.registry
    ]
    config = base.model_copy(
        update={
            "models": base.models.model_copy(
                update={
                    "registry": tuple(registry),
                    "source_audit": base.models.source_audit.model_copy(
                        update={"fallbacks": [alias]}
                    ),
                }
            )
        }
    )
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", source, "request-canonical"),
        _usage("source_audit", alias, "request-alias"),
    ]
    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=[_artifact(requests, usage) for usage in usages],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == coverage.overall.denominator
    assert all(len(surface.root_lineages) == 1 for surface in coverage.surfaces)
    assert coverage.critical.numerator == 0
    assert not coverage.critical_gate_passed


def test_request_manifest_or_response_hash_splice_is_not_credited(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-splice")
    artifact = _artifact(requests, usage, manifest_sha256="9" * 64)
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(
        "manifest hash was inconsistent" in surface.evidence_references[0].reason
        for surface in coverage.surfaces
    )


def test_inconclusive_and_not_reviewed_records_are_explicit_no_credit(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usages = [
        _usage("source_audit", config.models.source_audit.primary, "request-inconclusive"),
        _usage("business_logic", config.models.business_logic.primary, "request-not-reviewed"),
    ]
    artifacts = [
        _artifact(requests, usages[0], status=ModelSurfaceReviewStatus.INCONCLUSIVE),
        _artifact(requests, usages[1], status=ModelSurfaceReviewStatus.NOT_REVIEWED),
    ]
    coverage = build_model_review_coverage(
        config,
        usage_records=usages,
        review_artifacts=artifacts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert {reference.status for reference in coverage.surfaces[0].evidence_references} == {
        ModelSurfaceReviewStatus.INCONCLUSIVE,
        ModelSurfaceReviewStatus.NOT_REVIEWED,
    }


def test_role_mismatch_is_not_credited_and_gate_fails(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants, requests = _requests()
    usage = _usage("source_audit", config.models.source_audit.primary, "request-role")
    artifact = _artifact(requests, usage).model_copy(update={"review_role": "verifier"})
    coverage = build_model_review_coverage(
        config,
        usage_records=[usage],
        review_artifacts=[artifact],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == 0
    assert all(
        "not an allowed investigator role" in surface.evidence_references[0].reason
        for surface in coverage.surfaces
    )
    gate = model_review_critical_surface_gate(coverage, required=True)
    assert gate.required and not gate.passed
