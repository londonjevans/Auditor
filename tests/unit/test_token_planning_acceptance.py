from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from mmaudit.config import AuditConfig
from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.schemas import (
    ContextPackage,
    ExecutionEvidenceKind,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ScannerFinding,
    Severity,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    PROMPT_ALLOCATION_CATEGORIES,
    ContextOmissionCategory,
    ContextOmissionReason,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    build_request_token_plan,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import (
    AtomicTokenReservationEvidence,
    BudgetManager,
)
from mmaudit.orchestration.context import (
    ContextBuilder,
    context_category_byte_counts,
    context_category_measurements,
    render_context,
)
from mmaudit.orchestration.context_manifest import (
    ActualTokenUsageSource,
    ContextRequestEvidence,
    build_context_manifest,
    load_context_manifest,
    write_context_manifest,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map

_MODEL_ID = "alpha/atlas-secure"
_ENDPOINT_ID = "synthetic-provider"
_SOURCE_PATH = "src/SyntheticVault.sol"
_SOURCE_LOCATION_HASH = hashlib.sha256(b"synthetic-source-location").hexdigest()


class _Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str


def _write_large_synthetic_repository(root: Path, *, source_bytes: int) -> None:
    source_path = root / _SOURCE_PATH
    source_path.parent.mkdir(parents=True)
    blocks = ["pragma solidity ^0.8.20;\n"]
    index = 0
    while len("".join(blocks).encode("utf-8")) < source_bytes:
        declarations = "".join(
            (
                f"    uint256 internal syntheticValue{index}_{offset}; "
                "// deterministic local defensive fixture padding\n"
            )
            for offset in range(80)
        )
        blocks.append(f"contract SyntheticVault{index} {{\n{declarations}}}\n")
        index += 1
    source_path.write_text("".join(blocks), encoding="utf-8")


def _metadata_inventory(
    *,
    entity_count: int,
    edge_count: int,
    invariant_count: int,
    scanner_count: int,
    payload_size: int,
) -> tuple[SoliditySymbolIndex, SolidityGraphSet, InvariantSuite, list[ScannerFinding]]:
    detail = "m" * payload_size
    entities = [
        SolidityEntity(
            id=f"function:SyntheticVault.surface{index}",
            kind=SolidityEntityKind.FUNCTION,
            name=f"surface{index}",
            contract_name="SyntheticVault",
            path=_SOURCE_PATH,
            start_line=1,
            end_line=1,
            byte_start=index,
            byte_end=index + 1,
            source_hash=_SOURCE_LOCATION_HASH,
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            transformation="synthetic token-planning acceptance fixture",
            visibility="external",
            signature=f"surface{index}()",
            documentation=detail,
        )
        for index in range(entity_count)
    ]
    edges = [
        SolidityGraphEdge(
            graph=SolidityGraphKind.STATE_WRITE,
            source_id=f"function:SyntheticVault.surface{index % max(1, entity_count)}",
            target_id=f"state:SyntheticVault.value{index}",
            label=f"synthetic state transition {index}: {detail}",
            provenance=SolidityProvenance.COMPILER,
            path=_SOURCE_PATH,
            start_line=1,
            end_line=1,
            source_hash=_SOURCE_LOCATION_HASH,
            confidence=1,
            transformation="synthetic token-planning acceptance fixture",
            metadata={"bounded_detail": detail},
        )
        for index in range(edge_count)
    ]
    invariants = [
        InvariantSpec(
            id=f"inv:synthetic-accounting-{index}",
            title=f"Synthetic accounting invariant {index}",
            category=InvariantCategory.ACCOUNTING,
            description=(
                "Recorded synthetic accounting remains bounded by observed assets. " + detail
            ),
            template=InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
            locations=[
                Location(
                    path=_SOURCE_PATH,
                    start_line=1,
                    end_line=1,
                    content_hash=_SOURCE_LOCATION_HASH,
                )
            ],
            entity_ids=[f"function:SyntheticVault.surface{index % max(1, entity_count)}"],
            state_variables=[f"value{index}"],
            functions=[f"surface{index % max(1, entity_count)}()"],
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            template_available=True,
            evidence_hash=hashlib.sha256(f"invariant:{index}".encode()).hexdigest(),
        )
        for index in range(invariant_count)
    ]
    scanner_findings = [
        ScannerFinding(
            scanner="synthetic-static",
            rule_id=f"synthetic-rule-{index}",
            title=f"Synthetic normalized finding {index}",
            severity=Severity.MEDIUM,
            message=f"Bounded local scanner observation {index}: {detail}",
            locations=[Location(path=_SOURCE_PATH, start_line=1, end_line=1)],
            fingerprint=hashlib.sha256(f"scanner:{index}".encode()).hexdigest(),
        )
        for index in range(scanner_count)
    ]
    return (
        SoliditySymbolIndex(
            projects=[],
            entities=entities,
            ast_sources=[_SOURCE_PATH],
        ),
        SolidityGraphSet(
            edges=edges,
            analyzed_graphs=[SolidityGraphKind.STATE_WRITE],
        ),
        InvariantSuite(
            invariants=invariants,
            templates_available_count=len(invariants),
        ),
        scanner_findings,
    )


def _build_context(
    *,
    root: Path,
    config: AuditConfig,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    invariants: InvariantSuite,
    scanner_findings: list[ScannerFinding],
    requested_budget: int,
) -> ContextPackage:
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    return ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=scanner_findings,
        solidity_index=index,
        solidity_graphs=graphs,
        solidity_invariants=invariants,
        maximum_source_tokens_per_request=(config.token_budgets.maximum_source_tokens_per_request),
    ).build("source_audit", requested_budget=requested_budget)


def test_many_tiny_source_files_do_not_reserve_away_fitting_analysis_metadata(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    source_path = tmp_path / _SOURCE_PATH
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "pragma solidity ^0.8.20; contract SyntheticVault {}\n",
        encoding="utf-8",
    )
    for index in range(99):
        (tmp_path / f"tiny_{index:03d}.sol").write_text("// x\n", encoding="utf-8")
    config = config_factory(
        repository={"max_total_context_bytes": 100_000},
        privacy={"fail_on_detected_secret": False},
    )
    index, graphs, invariants, scanner_findings = _metadata_inventory(
        entity_count=40,
        edge_count=60,
        invariant_count=20,
        scanner_count=10,
        payload_size=120,
    )

    package = _build_context(
        root=tmp_path,
        config=config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        scanner_findings=scanner_findings,
        requested_budget=100_000,
    )

    assert package.bytes_used > 75_000
    assert package.excerpts
    assert package.solidity_index is not None
    assert len(package.solidity_index.entities) == 40
    assert package.solidity_invariants is not None
    assert len(package.solidity_invariants.invariants) == 20
    assert len(package.scanner_findings) == 10


def _request_plan_from_context(
    package: ContextPackage,
    *,
    request_id: str,
    required_output_tokens: int = 32_768,
) -> RequestTokenPlan:
    measurements = context_category_measurements(package)
    allocations = tuple(
        (
            PromptTokenAllocation.from_measurement(
                category,
                content_sha256=measurements[category.value].content_sha256,
                utf8_bytes=measurements[category.value].utf8_bytes,
            )
            if category.value in measurements
            else PromptTokenAllocation.from_text(category, "")
        )
        for category in PROMPT_ALLOCATION_CATEGORIES
    )
    route = EndpointRouteTokenCapacity.build(
        exact_model_id=_MODEL_ID,
        provider_endpoint=_ENDPOINT_ID,
        endpoint_snapshot_sha256="a" * 64,
        context_tokens=1_000_000,
        max_prompt_tokens=900_000,
        max_prompt_tokens_source="metadata",
        max_completion_tokens=64_000,
        max_completion_tokens_source="metadata",
    )
    return build_request_token_plan(
        request_id=request_id,
        role="source_audit",
        route_intersection=EndpointRouteIntersection.build((route,)),
        allocations=allocations,
        required_output_tokens=required_output_tokens,
        reserved_reasoning_tokens=0,
        global_input_token_budget=2_000_000,
        global_output_token_budget=200_000,
        maximum_source_tokens_per_request=200_000,
        prompt_envelope_byte_upper_bound_tokens=sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in allocations
        ),
    )


def _mock_usage(plan: RequestTokenPlan) -> UsageRecord:
    reservation = AtomicTokenReservationEvidence.build(
        request_id=plan.request_id,
        exact_model_id=_MODEL_ID,
        role=plan.role,
        request_token_plan_sha256=plan.plan_sha256,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        global_input_token_limit=plan.global_budget.global_input_token_budget,
        global_output_token_limit=plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=0,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=0,
        reserved_output_tokens_before=0,
    )
    prompt_tokens = max(1, plan.estimated_prompt_tokens)
    completion_tokens = 100
    timestamp = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return UsageRecord(
        request_id=plan.request_id,
        role=plan.role,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model=_MODEL_ID,
        returned_model=_MODEL_ID,
        actual_model=_MODEL_ID,
        provider="Synthetic",
        model_family="atlas-secure",
        timestamp=timestamp,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        reported_cost_usd=0.001,
        accounted_cost_usd=0.001,
        routing={
            "request_token_plan": plan.model_dump(mode="json"),
            "request_token_plan_sha256": plan.plan_sha256,
            "atomic_token_reservations": [reservation.model_dump(mode="json")],
            "atomic_token_reservation_sha256s": [reservation.evidence_sha256],
            "atomic_token_reservation": reservation.model_dump(mode="json"),
            "atomic_token_reservation_sha256": reservation.evidence_sha256,
        },
        prompt_sha256="1" * 64,
        user_prompt_sha256="2" * 64,
        response_sha256="3" * 64,
        validated_response_sha256="4" * 64,
        request_body_sha256="5" * 64,
        schema_sha256="6" * 64,
        openrouter_generation_id="generation-token-acceptance",
        configured_provider_endpoints=[_ENDPOINT_ID],
        actual_provider_endpoint=_ENDPOINT_ID,
        started_at=timestamp,
        ended_at=timestamp,
        latency_ms=0,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        identity_strength=ModelIdentityStrength.UNBOUND,
        status="success",
        attempts=1,
    )


def _completion_response(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"X-Generation-Id": "generation-token-acceptance"},
        json={
            "id": "generation-token-acceptance",
            "model": _MODEL_ID,
            "provider": _ENDPOINT_ID,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "native_finish_reason": "stop",
                    "message": {"role": "assistant", "content": content},
                }
            ],
            "usage": {
                "prompt_tokens": 200_000,
                "completion_tokens": 100,
                "total_tokens": 200_100,
                "cost": 0.001,
            },
            "openrouter_metadata": {
                "requested": _MODEL_ID,
                "strategy": "direct",
                "attempt": 1,
                "endpoints": {
                    "total": 1,
                    "available": [
                        {
                            "provider": _ENDPOINT_ID,
                            "model": _MODEL_ID,
                            "selected": True,
                        }
                    ],
                },
                "attempts": [
                    {
                        "provider": _ENDPOINT_ID,
                        "model": _MODEL_ID,
                        "status": 200,
                    }
                ],
                "pipeline": [],
            },
        },
    )


def test_large_metadata_pressure_compacts_before_source_is_exhausted(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "metadata-pressure"
    _write_large_synthetic_repository(repository, source_bytes=590_000)
    index, graphs, invariants, scanner_findings = _metadata_inventory(
        entity_count=520,
        edge_count=720,
        invariant_count=80,
        scanner_count=200,
        payload_size=2_048,
    )
    config = config_factory(
        repository={
            "max_file_bytes": 700_000,
            "max_total_context_bytes": 120_000,
        },
        privacy={"fail_on_detected_secret": False},
    )

    package = _build_context(
        root=repository,
        config=config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        scanner_findings=scanner_findings,
        requested_budget=120_000,
    )
    categories = context_category_byte_counts(package)
    omission_categories = {item.category for item in package.omissions}
    expected_metadata_omissions = {
        ContextOmissionCategory.FRAMEWORK,
        ContextOmissionCategory.GRAPH,
        ContextOmissionCategory.INVARIANT,
        ContextOmissionCategory.SCANNER,
    }

    assert package.bytes_used <= package.byte_budget == 120_000
    assert categories["source"] >= 8_192
    assert package.solidity_graphs is None or len(package.solidity_graphs.edges) < len(graphs.edges)
    assert package.solidity_index is None or len(package.solidity_index.entities) < len(
        index.entities
    )
    assert package.solidity_invariants is None or len(package.solidity_invariants.invariants) < len(
        invariants.invariants
    )
    assert len(package.scanner_findings) < len(scanner_findings)
    assert expected_metadata_omissions <= omission_categories
    assert all(
        item.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
        for item in package.omissions
        if item.category in expected_metadata_omissions
    )
    assert all(len(item.omitted_item_sha256) == 64 for item in package.omissions)


def test_metadata_omission_hashes_bind_each_actual_inventory_reduction(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "omission-identity"
    _write_large_synthetic_repository(repository, source_bytes=80_000)
    index, graphs, invariants, scanner_findings = _metadata_inventory(
        entity_count=520,
        edge_count=720,
        invariant_count=80,
        scanner_count=200,
        payload_size=2_048,
    )
    marker = "changed-inventory-marker"
    changed_edges = list(graphs.edges)
    changed_edges[0] = changed_edges[0].model_copy(
        update={"label": f"{marker}:{changed_edges[0].label}"}
    )
    changed_graphs = graphs.model_copy(update={"edges": changed_edges})
    config = config_factory(
        repository={
            "max_file_bytes": 100_000,
            "max_total_context_bytes": 120_000,
        },
        privacy={"fail_on_detected_secret": False},
    )

    original = _build_context(
        root=repository,
        config=config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        scanner_findings=scanner_findings,
        requested_budget=120_000,
    )
    changed = _build_context(
        root=repository,
        config=config,
        index=index,
        graphs=changed_graphs,
        invariants=invariants,
        scanner_findings=scanner_findings,
        requested_budget=120_000,
    )
    original_graph_hashes = {
        item.omitted_item_sha256
        for item in original.omissions
        if item.category is ContextOmissionCategory.GRAPH
        and item.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
    }
    changed_graph_hashes = {
        item.omitted_item_sha256
        for item in changed.omissions
        if item.category is ContextOmissionCategory.GRAPH
        and item.reason is ContextOmissionReason.METADATA_BUDGET_EXCLUDED
    }

    assert len(original_graph_hashes) >= 6
    assert len(changed_graph_hashes) >= 6
    assert original_graph_hashes != changed_graph_hashes
    assert marker not in json.dumps(
        [item.model_dump(mode="json") for item in changed.omissions],
        sort_keys=True,
    )


def test_persisted_manifest_binds_nonzero_semantic_context_allocations(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "semantic-categories"
    _write_large_synthetic_repository(repository, source_bytes=80_000)
    index, graphs, invariants, scanner_findings = _metadata_inventory(
        entity_count=1,
        edge_count=1,
        invariant_count=1,
        scanner_count=1,
        payload_size=64,
    )
    config = config_factory(
        repository={
            "max_file_bytes": 100_000,
            "max_total_context_bytes": 300_000,
        },
        privacy={"fail_on_detected_secret": False},
        execution={"max_output_tokens_per_request": 32_768},
        token_budgets={"reserved_output_tokens": 32_768},
    )
    package = _build_context(
        root=repository,
        config=config,
        index=index,
        graphs=graphs,
        invariants=invariants,
        scanner_findings=scanner_findings,
        requested_budget=300_000,
    )
    plan = _request_plan_from_context(package, request_id="semantic-allocation-request")
    manifest = build_context_manifest(
        run_id="semantic-allocation-run",
        usage_records=[_mock_usage(plan)],
    )
    manifest_path = tmp_path / "context-manifest.json"
    write_context_manifest(manifest_path, manifest)
    loaded = load_context_manifest(manifest_path)

    request = loaded.requests[0]
    assert isinstance(request, ContextRequestEvidence)
    allocation_tokens = {
        allocation.category: allocation.estimate.estimated_tokens
        for allocation in request.request_plan.allocations
    }
    total_tokens = {
        category.category: category.estimated_tokens for category in loaded.totals.categories
    }
    for category in (
        PromptAllocationCategory.FRAMEWORK,
        PromptAllocationCategory.GRAPH,
        PromptAllocationCategory.INVARIANT,
        PromptAllocationCategory.SCANNER,
    ):
        assert allocation_tokens[category] > 0
        assert total_tokens[category] == allocation_tokens[category]
    assert allocation_tokens[PromptAllocationCategory.PRIOR_AUDIT] == 0
    assert total_tokens[PromptAllocationCategory.PRIOR_AUDIT] == 0
    assert request.actual_usage.source is ActualTokenUsageSource.MOCK_RESPONSE
    assert request.request_plan.reserved_output_tokens == 32_768
    assert {
        allocation.category.value for allocation in request.request_plan.output_allocations
    } == {
        "coverage",
        "findings",
        "summary",
    }


@pytest.mark.asyncio
async def test_high_capacity_context_executes_through_fake_provider_and_manifest(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    repository = tmp_path / "high-capacity"
    _write_large_synthetic_repository(repository, source_bytes=590_000)
    index, graphs, invariants, scanner_findings = _metadata_inventory(
        entity_count=0,
        edge_count=0,
        invariant_count=0,
        scanner_count=0,
        payload_size=0,
    )
    config = config_factory(
        repository={
            "max_file_bytes": 700_000,
            "max_total_context_bytes": 700_000,
        },
        privacy={"fail_on_detected_secret": False},
        execution={
            "max_request_bytes": 1_000_000,
            "max_output_tokens_per_request": 32_768,
        },
        token_budgets={
            "usable_input_fraction": 0.75,
            "reserved_output_tokens": 32_768,
        },
    )
    transport = httpx.MockTransport(
        lambda _request: _completion_response('{"answer":"high-capacity context reviewed"}')
    )
    http_client = httpx.AsyncClient(
        transport=transport,
        base_url="https://fake.test/api/v1/",
    )
    usage = UsageLedger()
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            global_input_token_budget=config.token_budgets.global_input_token_budget,
            global_output_token_budget=config.token_budgets.global_output_token_budget,
        ),
        usage=usage,
        http_client=http_client,
        token_budgets=config.token_budgets,
    )
    try:
        package_budget = client.context_package_byte_budget([_MODEL_ID])
        package = _build_context(
            root=repository,
            config=config,
            index=index,
            graphs=graphs,
            invariants=invariants,
            scanner_findings=scanner_findings,
            requested_budget=package_budget,
        )
        result = await client.complete(
            role="source_audit",
            models=[_MODEL_ID],
            system_prompt="Review only the supplied bounded synthetic source.",
            user_prompt="Review this synthetic context.\n" + render_context(package),
            context_package=package,
            response_model=_Answer,
            schema_name="answer",
        )
    finally:
        client.clear_credentials()
        await http_client.aclose()

    assert result.answer == "high-capacity context reviewed"
    assert len(usage.records) == 1
    plan = RequestTokenPlan.model_validate_json(
        json.dumps(usage.records[0].routing["request_token_plan"])
    )
    assert 190_000 <= plan.estimated_prompt_tokens <= 210_000
    assert plan.reserved_output_tokens == 32_768
    assert plan.prompt_byte_upper_bound_tokens <= plan.usable_prompt_tokens

    manifest = build_context_manifest(
        run_id="high-capacity-run",
        usage_records=usage.records,
    )
    manifest_path = tmp_path / "high-capacity-context-manifest.json"
    write_context_manifest(manifest_path, manifest)
    loaded = load_context_manifest(manifest_path)

    assert loaded.totals.planned_prompt_tokens == plan.estimated_prompt_tokens
    assert loaded.totals.reserved_output_tokens == 32_768
    assert loaded.totals.mock_reported_request_count == 1
    assert loaded.totals.mock_reported_prompt_tokens == 200_000
