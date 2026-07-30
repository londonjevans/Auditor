from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mmaudit.agents.specialists import specialist_context_budget
from mmaudit.models.schemas import ContextPackage, SolidityGraphKind
from mmaudit.orchestration.context import (
    ContextBudgetError,
    ContextBuilder,
    context_category_byte_counts,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.solidity.coverage import build_solidity_coverage
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.retrieval import compact_solidity_graphs, compact_solidity_index

pytestmark = [pytest.mark.large_scale, pytest.mark.slow]

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "solidity" / "realistic_scale"
PROFILE_IDS = ("solidity_005k", "solidity_015k", "solidity_035k")
EXPECTED_GRAPH_KINDS = {
    SolidityGraphKind.ASSET_FLOW,
    SolidityGraphKind.DELEGATECALL,
    SolidityGraphKind.EXTERNAL_CALL,
    SolidityGraphKind.INITIALIZER,
    SolidityGraphKind.ORACLE_DEPENDENCY,
    SolidityGraphKind.PRIVILEGE,
    SolidityGraphKind.PROXY,
    SolidityGraphKind.STATE_WRITE,
}


def _manifest(profile_id: str) -> dict[str, Any]:
    return json.loads(
        (FIXTURE_ROOT / profile_id / "fixture-manifest.json").read_text(encoding="utf-8")
    )


def _scale_config(config_factory):
    return config_factory(
        repository={
            "max_files": 500,
            "max_walk_entries": 2_000,
            "max_file_bytes": 48_000,
            "max_discovery_bytes": 10_000_000,
            "max_total_context_bytes": 600_000,
        },
    )


def _analyze(profile_id: str, config_factory):
    root = FIXTURE_ROOT / profile_id
    config = _scale_config(config_factory)
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index_build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, index_build)
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=index_build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    return config, discovery, projects, index_build, graphs, coverage


def test_realistic_scale_index_graph_and_coverage_populations_are_monotonic(
    config_factory,
) -> None:
    previous_population = (0, 0, 0, 0)

    for profile_id in PROFILE_IDS:
        manifest = _manifest(profile_id)
        _, discovery, projects, index_build, graphs, coverage = _analyze(
            profile_id,
            config_factory,
        )
        solidity_paths = {
            item.relative_path for item in discovery.files if item.language == "Solidity"
        }
        indexed_paths = {entity.path for entity in index_build.index.entities}
        populated_graphs = {edge.graph for edge in graphs.edges}

        assert not discovery.omitted
        assert len(projects) == 1
        assert len(solidity_paths) == manifest["actual"]["solidity_file_count"]
        assert set(index_build.index.fallback_sources) == solidity_paths
        assert solidity_paths <= indexed_paths
        assert populated_graphs >= EXPECTED_GRAPH_KINDS
        assert coverage.files_discovered == len(solidity_paths)
        assert coverage.solidity_files_analyzed == len(solidity_paths)
        assert coverage.contracts_indexed >= manifest["structure"]["abstract_contracts"]
        assert coverage.functions_indexed >= manifest["structure"]["functions"]
        assert coverage.graph_edge_counts[SolidityGraphKind.ASSET_FLOW.value] > 0
        assert coverage.graph_edge_counts[SolidityGraphKind.EXTERNAL_CALL.value] > 0

        public_review = coverage.quality_metrics["public_external_entry_points_reviewed"]
        privileged_review = coverage.quality_metrics["privileged_entry_points_reviewed"]
        asset_flows = coverage.quality_metrics["asset_flows_classified"]
        assert public_review.numerator == 0
        assert public_review.denominator > 0
        assert privileged_review.numerator == 0
        assert privileged_review.denominator > 0
        assert asset_flows.denominator > 0
        assert asset_flows.numerator == asset_flows.denominator

        population = (
            coverage.files_discovered,
            coverage.contracts_indexed,
            coverage.functions_indexed,
            len(graphs.edges),
        )
        assert all(
            current > previous
            for current, previous in zip(population, previous_population, strict=True)
        )
        previous_population = population


def test_realistic_scale_has_stable_bounded_semantic_sharding_inputs(
    config_factory,
) -> None:
    """Characterize real shard inputs without claiming V3-SHARD-001 implementation."""

    _, _, _, index_build, graphs, _ = _analyze("solidity_015k", config_factory)
    compact_index_a = compact_solidity_index(
        index_build.index,
        role="specialist:access_control",
        max_entities=500,
    )
    compact_index_b = compact_solidity_index(
        index_build.index,
        role="specialist:access_control",
        max_entities=500,
    )
    compact_graphs_a = compact_solidity_graphs(
        graphs,
        role="specialist:access_control",
        max_edges=700,
    )
    compact_graphs_b = compact_solidity_graphs(
        graphs,
        role="specialist:access_control",
        max_edges=700,
    )

    assert compact_index_a is not None
    assert compact_graphs_a is not None
    assert compact_index_a == compact_index_b
    assert compact_graphs_a == compact_graphs_b
    assert len(compact_index_a.entities) == 500
    assert len(compact_graphs_a.edges) == 700
    assert any("entities omitted" in warning for warning in compact_index_a.warnings)
    assert any("graph edges omitted" in warning for warning in compact_graphs_a.warnings)
    assert any(entity.name == "pause" for entity in compact_index_a.entities)
    assert any(edge.graph is SolidityGraphKind.PRIVILEGE for edge in compact_graphs_a.edges)


@pytest.mark.parametrize(
    "profile_id",
    (
        "solidity_005k",
        pytest.param(
            "solidity_015k",
            marks=pytest.mark.xfail(
                raises=ContextBudgetError,
                strict=True,
                reason=(
                    "V3-OMISSION-001: per-item omission evidence currently exhausts "
                    "the specialist package budget"
                ),
            ),
        ),
        "solidity_035k",
    ),
)
def test_realistic_scale_specialist_context_degrades_with_bounded_omissions(
    profile_id: str,
    config_factory,
) -> None:
    """Desired V3-OMISSION-001 behavior; current failure is never treated as success."""

    try:
        package, budget = _build_specialist_context(profile_id, config_factory)
    except ContextBudgetError as error:
        assert str(error) == (
            "serialized metadata for role specialist:access_control exceeds "
            "its 256000-byte allocation"
        )
        raise

    categories = context_category_byte_counts(package)
    assert package.bytes_used <= budget
    assert package.excerpts
    assert categories["source"] > 0


@pytest.mark.parametrize(
    "profile_id",
    (
        "solidity_005k",
        pytest.param(
            "solidity_035k",
            marks=pytest.mark.xfail(
                raises=AssertionError,
                strict=True,
                reason=(
                    "V3-OMISSION-001: the successful package still exceeds the "
                    "declared 64-record omission bound"
                ),
            ),
        ),
    ),
)
def test_realistic_scale_successful_context_has_bounded_omission_ledger(
    profile_id: str,
    config_factory,
) -> None:
    package, _ = _build_specialist_context(profile_id, config_factory)

    assert len(package.omissions) <= 64


def _build_specialist_context(
    profile_id: str,
    config_factory,
) -> tuple[ContextPackage, int]:
    config = _scale_config(config_factory)
    root = FIXTURE_ROOT / profile_id
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    budget = specialist_context_budget(
        "access_control",
        total_context_bytes=config.repository.max_total_context_bytes,
        planned_packages=31,
    )
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=200_000,
    ).build(
        "specialist:access_control",
        requested_budget=budget,
    )
    return package, budget
