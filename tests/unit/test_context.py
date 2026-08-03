from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.agents.specialists import specialist_context_budget
from mmaudit.models.schemas import (
    ContextPackage,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.models.token_planning import ContextOmissionReason
from mmaudit.orchestration.context import (
    ContextBoundaryError,
    ContextBudgetError,
    ContextBuilder,
    context_category_byte_counts,
    context_category_measurements,
    context_json_escape_overhead_tokens,
    render_context,
    revalidate_context_package,
    revalidate_model_surface_context_package,
)
from mmaudit.orchestration.model_coverage import model_review_edge_subject_id
from mmaudit.orchestration.model_review_evidence import build_source_file_review_request
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.solidity.retrieval import compact_solidity_graphs, compact_solidity_index


def test_specialist_context_budget_uses_source_and_package_bounds() -> None:
    source_bounded = specialist_context_budget(
        "access_control",
        total_context_bytes=2_000_000,
        maximum_source_tokens_per_request=200_000,
    )
    package_bounded = specialist_context_budget(
        "invariant_review",
        total_context_bytes=400_000,
        maximum_source_tokens_per_request=200_000,
    )

    assert source_bounded == 665_536
    assert package_bounded == 400_000


def _internal_call_surface_builder(
    tmp_path: Path,
    config_factory,
) -> tuple[ContextBuilder, ModelSurfaceReviewRequest, SolidityGraphEdge, SolidityGraphEdge]:
    repository = tmp_path / "internal-call-context"
    repository.mkdir()
    source = """contract NestedCall {
    function enter() external {
        _route();
    }
    function _route() internal {
        target.call("");
    }
}
"""
    (repository / "NestedCall.sol").write_text(source, encoding="utf-8")
    config = config_factory(
        repository={"max_total_context_bytes": 100_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())

    def entity(
        *,
        entity_id: str,
        name: str,
        start_line: int,
        end_line: int,
        visibility: str,
        signature: str,
    ) -> SolidityEntity:
        return SolidityEntity(
            id=entity_id,
            kind=SolidityEntityKind.FUNCTION,
            name=name,
            contract_name="NestedCall",
            path="NestedCall.sol",
            start_line=start_line,
            end_line=end_line,
            byte_start=0,
            byte_end=len(source.encode("utf-8")),
            source_hash=line_range_hash(source, start_line, end_line),
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            transformation="synthetic_exact_internal_call_context",
            visibility=visibility,
            signature=signature,
        )

    entry = entity(
        entity_id="function:NestedCall.enter",
        name="enter",
        start_line=2,
        end_line=4,
        visibility="external",
        signature="enter()",
    )
    internal = entity(
        entity_id="function:NestedCall._route",
        name="_route",
        start_line=5,
        end_line=7,
        visibility="internal",
        signature="_route()",
    )
    upstream = SolidityGraphEdge(
        graph=SolidityGraphKind.STATE_DEPENDENCY,
        source_id=entry.id,
        target_id=internal.id,
        label="deterministic upstream dependency",
        provenance=SolidityProvenance.COMPILER,
        path="NestedCall.sol",
        start_line=3,
        end_line=3,
        source_hash=line_range_hash(source, 3, 3),
        confidence=1,
        transformation="synthetic_non_call_reachability_edge",
    )
    requested_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.LOW_LEVEL_CALL,
        source_id=internal.id,
        target_id="external-target:target.call",
        label="target.call",
        provenance=SolidityProvenance.COMPILER,
        path="NestedCall.sol",
        start_line=6,
        end_line=6,
        source_hash=line_range_hash(source, 6, 6),
        confidence=1,
        transformation="synthetic_exact_requested_call",
    )

    def node(entity: SolidityEntity) -> SolidityGraphNode:
        return SolidityGraphNode(
            id=entity.id,
            kind=SolidityGraphNodeKind.ENTITY,
            label=entity.signature or entity.name,
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            source_hash=entity.source_hash,
            provenance=entity.provenance,
            confidence=entity.confidence,
            transformation="synthetic_exact_entity_node",
        )

    index = SoliditySymbolIndex(
        projects=[],
        entities=[entry, internal],
        ast_sources=["NestedCall.sol"],
    )
    graphs = SolidityGraphSet(
        nodes=[node(entry), node(internal)],
        edges=[requested_edge, upstream],
        analyzed_graphs=[SolidityGraphKind.LOW_LEVEL_CALL, SolidityGraphKind.STATE_DEPENDENCY],
        coverage={SolidityGraphKind.LOW_LEVEL_CALL.value: 1},
    )
    subject_id = model_review_edge_subject_id(requested_edge)
    request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.CALL,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.CALL,
        subject_id=subject_id,
        contract="NestedCall",
        function_or_state_surface="_route() -> target.call",
        critical=True,
        allowed_locations=(
            Location(
                path=requested_edge.path,
                start_line=requested_edge.start_line,
                end_line=requested_edge.end_line,
                content_hash=requested_edge.source_hash,
            ),
        ),
        allowed_symbols=tuple(
            sorted({internal.id, internal.name, internal.signature or internal.name})
        ),
        invariant_considered="The exact reachable call must preserve state and asset integrity.",
    )
    return (
        ContextBuilder(
            discovery=discovery,
            repository_map=build_repository_map(discovery),
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
            solidity_index=index,
            solidity_graphs=graphs,
        ),
        request,
        upstream,
        requested_edge,
    )


def test_call_surface_custody_retains_internal_source_path_and_allows_edge_only_target(
    tmp_path: Path,
    config_factory,
) -> None:
    builder, request, upstream, requested_edge = _internal_call_surface_builder(
        tmp_path,
        config_factory,
    )

    package = builder.build("business_logic", requested_model_surfaces=[request])

    assert package.solidity_graphs is not None
    assert {
        model_review_edge_subject_id(upstream),
        model_review_edge_subject_id(requested_edge),
    } <= {model_review_edge_subject_id(edge) for edge in package.solidity_graphs.edges}
    assert {upstream.source_id, upstream.target_id} <= {
        node.id for node in package.solidity_graphs.nodes
    }
    assert requested_edge.target_id not in {node.id for node in package.solidity_graphs.nodes}
    assert revalidate_model_surface_context_package(package) == package


@pytest.mark.parametrize("removed_fact", ["requested_edge", "source_node"])
def test_provider_preflight_rejects_nested_call_fact_removal(
    tmp_path: Path,
    config_factory,
    removed_fact: str,
) -> None:
    builder, request, _upstream, requested_edge = _internal_call_surface_builder(
        tmp_path,
        config_factory,
    )
    package = builder.build("business_logic", requested_model_surfaces=[request]).model_copy(
        deep=True
    )
    assert package.solidity_graphs is not None
    if removed_fact == "requested_edge":
        package.solidity_graphs.edges = [
            edge for edge in package.solidity_graphs.edges if edge != requested_edge
        ]
    else:
        package.solidity_graphs.nodes = [
            node for node in package.solidity_graphs.nodes if node.id != requested_edge.source_id
        ]
    package = package.model_copy(update={"bytes_used": len(render_context(package).encode())})

    with pytest.raises(ContextBoundaryError, match="model-surface custody"):
        revalidate_model_surface_context_package(package)


def test_entity_surface_context_rejects_missing_typed_index(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    source = next(item for item in discovery.files if item.relative_path == "app.py")
    subject_id = "function:SyntheticApplication.entry"
    request = ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
            ModelReviewSurfaceKind.ENTRY_POINT,
            subject_id,
        ),
        kind=ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id=subject_id,
        contract="SyntheticApplication",
        function_or_state_surface="entry",
        critical=True,
        allowed_locations=(
            Location(
                path=source.relative_path,
                start_line=1,
                end_line=1,
                content_hash=line_range_hash(source.content, 1, 1),
            ),
        ),
        allowed_symbols=tuple(sorted({subject_id, "entry"})),
        invariant_considered="The exact entry point must retain its typed source identity.",
    )

    with pytest.raises(ContextBudgetError, match="lacks its exact index entity"):
        ContextBuilder(
            discovery=discovery,
            repository_map=build_repository_map(discovery),
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
        ).build("source_audit", requested_model_surfaces=[request])


def test_compactors_reject_nonempty_mandatory_facts_without_inventory(
    tmp_path: Path,
    config_factory,
) -> None:
    _builder, _request, _upstream, requested_edge = _internal_call_surface_builder(
        tmp_path,
        config_factory,
    )

    with pytest.raises(ValueError, match="required Solidity index entities"):
        compact_solidity_index(
            None,
            role="business_logic",
            required_entity_ids={requested_edge.source_id},
        )
    with pytest.raises(ValueError, match="required Solidity graph edges"):
        compact_solidity_graphs(
            None,
            role="business_logic",
            required_edges=(requested_edge,),
        )


@pytest.mark.parametrize("tamper", ["size", "duplicate"])
def test_provider_preflight_rejects_source_file_map_tampering(
    vulnerable_repo: Path,
    config_factory,
    tamper: str,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    source = next(item for item in discovery.files if item.relative_path == "app.py")
    request = build_source_file_review_request(
        path=source.relative_path,
        size=source.size,
        lines=source.lines,
        sha256=source.sha256,
    )
    package = (
        ContextBuilder(
            discovery=discovery,
            repository_map=build_repository_map(discovery),
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
        )
        .build("source_audit", requested_model_surfaces=[request])
        .model_copy(deep=True)
    )
    record = next(
        item for item in package.repository_map.files if item.path == source.relative_path
    )
    if tamper == "size":
        record.size += 1
    else:
        package.repository_map.files.append(record.model_copy(deep=True))
    package = package.model_copy(update={"bytes_used": len(render_context(package).encode())})

    with pytest.raises(ContextBoundaryError, match="model-surface custody"):
        revalidate_model_surface_context_package(package)


def test_context_builder_package_is_independent_of_unrelated_peer_roles(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 200_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)

    def build(planned_packages: int) -> ContextPackage:
        return ContextBuilder(
            discovery=discovery,
            repository_map=repository_map,
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
            planned_packages=planned_packages,
        ).build("source_audit")

    few_roles = build(7)
    many_roles = build(31)

    assert few_roles.byte_budget == many_roles.byte_budget == 200_000
    assert few_roles.bytes_used == many_roles.bytes_used
    assert render_context(few_roles) == render_context(many_roles)


def test_context_builder_separates_source_ceiling_from_total_package_budget(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 2_000_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=50_000,
    ).build("source_audit")

    categories = context_category_byte_counts(package)
    assert package.byte_budget == 2_000_000
    assert package.bytes_used <= package.byte_budget
    assert (categories["source"] + 2) // 3 <= 50_000


def test_context_metadata_does_not_consume_explicit_source_token_budget(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 100_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=8_192,
    ).build("source_audit", requested_budget=100_000)

    categories = context_category_byte_counts(package)
    assert package.byte_budget == 100_000
    assert package.bytes_used <= package.byte_budget
    assert 0 < (categories["source"] + 2) // 3 <= 8_192
    assert categories["metadata"] > 0


def test_context_builder_never_exceeds_cumulative_source_token_ceiling(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "many-small-logical-blocks"
    source_path = repository / "src" / "many_blocks.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "\n\n".join(
            (f"def bounded_surface_{index}() -> str:\n    return {'x' * 700!r}\n")
            for index in range(12)
        ),
        encoding="utf-8",
    )
    config = config_factory(
        repository={
            "max_file_bytes": 20_000,
            "max_total_context_bytes": 100_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        maximum_source_tokens_per_request=1_000,
    ).build("source_audit")

    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts)
    assert 0 < source_bytes <= 3_000


def test_context_builder_enforces_exact_shard_source_allowlist(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "shard-context"
    repository.mkdir()
    (repository / "primary.py").write_text("def primary():\n    return 1\n", encoding="utf-8")
    (repository / "peer.py").write_text("def peer():\n    return 2\n", encoding="utf-8")
    config = config_factory(
        repository={"max_total_context_bytes": 100_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    first = builder.build(
        "source_audit",
        preferred_paths={"primary.py"},
        allowed_source_paths={"primary.py"},
    )
    second = builder.build(
        "source_audit",
        preferred_paths={"primary.py"},
        allowed_source_paths={"primary.py"},
    )

    assert first == second
    assert {excerpt.path for excerpt in first.excerpts} == {"primary.py"}
    assert any(
        omission.reason is ContextOmissionReason.SHARD_SCOPE_WITHHELD
        for omission in first.omissions
    )


def test_context_builder_retains_preferred_shard_identity_during_map_compaction(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "large-shard-context"
    repository.mkdir()
    for index in range(300):
        (repository / f"source_{index:03d}.py").write_text("VALUE = 1\n", encoding="utf-8")
    preferred_path = "zz_preferred.py"
    (repository / preferred_path).write_text("REVIEWED_VALUE = 2\n", encoding="utf-8")
    config = config_factory(
        repository={
            "max_files": 400,
            "max_total_context_bytes": 500_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    package = builder.build(
        "source_audit",
        preferred_paths={preferred_path},
        allowed_source_paths={preferred_path},
    )

    preferred_identity = next(
        item for item in package.repository_map.files if item.path == preferred_path
    )
    preferred_content = "REVIEWED_VALUE = 2\n"
    assert preferred_identity.size == len(preferred_content.encode())
    assert preferred_identity.lines == 1
    assert preferred_identity.sha256 == hashlib.sha256(preferred_content.encode()).hexdigest()
    assert {excerpt.path for excerpt in package.excerpts} == {preferred_path}


@pytest.mark.parametrize(
    ("allowed", "preferred"),
    [
        ({"missing.py"}, set()),
        ({"../escape.py"}, set()),
        ({"primary.py"}, {"peer.py"}),
    ],
)
def test_context_builder_rejects_invalid_shard_source_allowlists(
    tmp_path: Path,
    config_factory,
    allowed: set[str],
    preferred: set[str],
) -> None:
    repository = tmp_path / "invalid-shard-context"
    repository.mkdir()
    (repository / "primary.py").write_text("def primary():\n    return 1\n", encoding="utf-8")
    (repository / "peer.py").write_text("def peer():\n    return 2\n", encoding="utf-8")
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    with pytest.raises(ContextBudgetError, match=r"shard source allowlist|outside"):
        builder.build(
            "source_audit",
            preferred_paths=preferred,
            allowed_source_paths=allowed,
        )


def test_context_builder_accounts_for_trusted_surface_request_manifest(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 200_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    source = next(item for item in discovery.files if item.relative_path == "app.py")
    request = build_source_file_review_request(
        path=source.relative_path,
        size=source.size,
        lines=source.lines,
        sha256=source.sha256,
    )
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    package = builder.build(
        "source_audit",
        requested_model_surfaces=[request],
    )
    rendered = render_context(package)

    assert package.requested_model_surfaces == (request,)
    assert package.bytes_used == len(rendered.encode())
    assert "<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>" in rendered
    assert "</TRUSTED_MODEL_SURFACE_REQUESTS_JSON>" in rendered
    assert request.surface_id in rendered
    assert request.invariant_considered in rendered

    categories = context_category_byte_counts(package)
    assert sum(categories.values()) == package.bytes_used
    assert categories["source"] > 0
    assert categories["metadata"] > 0
    assert categories["prior_audit"] == 0

    measurements = context_category_measurements(package)
    assert set(measurements) == set(categories)
    assert {
        category: measurement.utf8_bytes for category, measurement in measurements.items()
    } == categories
    assert all(len(measurement.content_sha256) == 64 for measurement in measurements.values())


def test_context_json_escape_overhead_matches_provider_visible_string_encoding(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")

    rendered = render_context(package)
    raw_bytes = len(rendered.encode("utf-8"))
    escaped_bytes = (
        len(
            json.dumps(
                rendered,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        - 2
    )

    assert context_json_escape_overhead_tokens(package) == escaped_bytes - raw_bytes
    assert escaped_bytes > raw_bytes


def test_context_boundary_returns_a_detached_package(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")

    sealed = revalidate_context_package(package)
    original_frameworks = tuple(sealed.repository_map.frameworks)
    package.repository_map.frameworks.append("SyntheticNestedMutation")

    assert sealed is not package
    assert sealed.repository_map is not package.repository_map
    assert sealed.repository_map.frameworks is not package.repository_map.frameworks
    assert tuple(sealed.repository_map.frameworks) == original_frameworks


def test_context_boundary_rejects_nested_mutation_with_stale_rendered_bytes(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")
    package.repository_map.frameworks.append("SyntheticNestedMutation")

    with pytest.raises(ContextBudgetError, match="exact rendered UTF-8 bytes"):
        revalidate_context_package(package)


def test_context_boundary_rejects_stale_declared_bytes(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")
    payload = dict(package.__dict__)
    payload["bytes_used"] = package.bytes_used - 1
    stale = ContextPackage.model_construct(**payload)

    with pytest.raises(ContextBudgetError, match="exact rendered UTF-8 bytes"):
        revalidate_context_package(stale)


def test_context_boundary_rejects_malformed_nested_models(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")
    assert package.repository_map.files
    package.repository_map.files[0].size = -1

    with pytest.raises(ContextBudgetError, match="detached boundary validation"):
        revalidate_context_package(package)


def test_model_surface_context_rejects_zero_source_before_transport(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "oversized-logical-block"
    source_path = repository / "SyntheticVault.sol"
    repository.mkdir()
    source_path.write_text(
        f'contract SyntheticVault {{\n    string internal constant PAD = "{"x" * 75_000}";\n}}\n',
        encoding="utf-8",
    )
    config = config_factory(
        repository={
            "max_file_bytes": 100_000,
            "max_total_context_bytes": 100_000,
        },
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    source = discovery.files[0]
    request = build_source_file_review_request(
        path=source.relative_path,
        size=source.size,
        lines=source.lines,
        sha256=source.sha256,
    )

    with pytest.raises(ContextBudgetError, match="omitted all source evidence"):
        ContextBuilder(
            discovery=discovery,
            repository_map=build_repository_map(discovery),
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[],
        ).build(
            "source_audit",
            requested_model_surfaces=[request],
        )
