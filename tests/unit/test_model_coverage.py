from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    ContextPackage,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    Location,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    RepositoryMap,
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
    model_review_critical_surface_gate,
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
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )
    index = SoliditySymbolIndex(
        projects=[project],
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


def _repository_map() -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic",
        languages={"Solidity": 1},
        frameworks=["Foundry"],
        manifests=["foundry.toml"],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[],
    )


def _context(
    role: str,
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
    invariants: InvariantSuite,
) -> ContextPackage:
    return ContextPackage(
        role=role,
        byte_budget=100_000,
        bytes_used=10_000,
        repository_map=_repository_map(),
        scanner_findings=[],
        excerpts=[],
        solidity_index=index,
        solidity_graphs=graphs,
        solidity_invariants=invariants,
    )


def _usage(role: str, model_id: str, request_id: str) -> UsageRecord:
    return UsageRecord(
        request_id=request_id,
        role=role,
        requested_model=model_id,
        returned_model=model_id,
        model_family=model_id.split("/", 1)[0],
        timestamp=datetime.now(UTC),
        prompt_sha256="c" * 64,
        response_sha256="d" * 64,
        status="success",
        attempts=1,
    )


def test_model_review_coverage_emits_every_surface_kind_and_lineage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants = _inventory()
    records = [
        _usage("source_audit", config.models.source_audit.primary, "request-1"),
        _usage("business_logic", config.models.business_logic.primary, "request-2"),
    ]
    contexts = [
        _context("source_audit", index, graphs, invariants),
        _context("business_logic", index, graphs, invariants),
    ]

    coverage = build_model_review_coverage(
        config,
        usage_records=records,
        contexts=contexts,
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert set(coverage.by_kind) == set(ModelReviewSurfaceKind)
    expected_denominators = {
        ModelReviewSurfaceKind.CONTRACT: 1,
        ModelReviewSurfaceKind.ENTRY_POINT: 2,
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION: 1,
        ModelReviewSurfaceKind.ASSET_FUNCTION: 1,
        ModelReviewSurfaceKind.CALL: 1,
        ModelReviewSurfaceKind.STATE: 1,
        ModelReviewSurfaceKind.INVARIANT: 1,
        ModelReviewSurfaceKind.TEMPLATE: 1,
    }
    assert {
        kind: metric.denominator for kind, metric in coverage.by_kind.items()
    } == expected_denominators
    assert all(metric.numerator == metric.denominator for metric in coverage.by_kind.values())
    assert coverage.overall.numerator == coverage.overall.denominator == 9
    assert coverage.critical.numerator == coverage.critical.denominator == 9
    assert coverage.critical_gate_passed
    assert all(
        surface.reviewer_roles == ["business_logic", "source_audit"]
        and len(surface.root_lineages) == 2
        for surface in coverage.surfaces
    )
    assert ModelReviewCoverage.model_validate_json(coverage.model_dump_json()) == coverage


def test_critical_surface_gate_cannot_be_masked_by_complete_aggregate_coverage(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    index, graphs, invariants = _inventory()
    second_graphs = graphs.model_copy(
        update={
            "edges": [
                edge for edge in graphs.edges if edge.graph is not SolidityGraphKind.ASSET_FLOW
            ]
        }
    )
    coverage = build_model_review_coverage(
        config,
        usage_records=[
            _usage("source_audit", config.models.source_audit.primary, "request-1"),
            _usage("business_logic", config.models.business_logic.primary, "request-2"),
        ],
        contexts=[
            _context("source_audit", index, graphs, invariants),
            _context("business_logic", index, second_graphs, invariants),
        ],
        index=index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
    )

    assert coverage.overall.numerator == coverage.overall.denominator
    assert coverage.critical.numerator == coverage.critical.denominator - 1
    asset_surface = next(
        surface
        for surface in coverage.surfaces
        if surface.kind is ModelReviewSurfaceKind.ASSET_FUNCTION
    )
    assert asset_surface.reviewed
    assert len(asset_surface.root_lineages) == 1
    gate = model_review_critical_surface_gate(coverage, required=True)
    assert gate.required
    assert not gate.passed
    assert gate.artifacts == ["model-review-coverage.json"]
