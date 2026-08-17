from __future__ import annotations

import json
from typing import cast

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AnalysisState,
    SolidityCoverage,
    SolidityGraphEdge,
    SolidityGraphFactKind,
    SolidityGraphFactOmission,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    SolidityStorageEntry,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.sharding import SolidityCoverageArtifact, SolidityGraphsArtifact
from mmaudit.orchestration.context import (
    _retained_solidity_graph_inventory,
    _solidity_graph_compaction_inventory,
)
from mmaudit.solidity.retrieval import compact_solidity_graphs
from scripts.generate_release_schemas import rendered_schema


def _edge(graph: SolidityGraphKind = SolidityGraphKind.STATE_DEPENDENCY) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id="function:Synthetic.update",
        target_id="state:Synthetic.value",
        label="synthetic state dependency",
        provenance=SolidityProvenance.COMPILER,
        path="Synthetic.sol",
        start_line=4,
        end_line=4,
        source_hash="a" * 64,
        confidence=1,
        transformation="synthetic compiler evidence",
    )


def _occurrence(
    subject_kind: SolidityGraphOccurrenceKind,
    subject: SolidityGraphEdge | SolidityGraphNode | SolidityStorageEntry | str,
    occurrence_count: int = 1,
) -> SolidityGraphRetainedOccurrence:
    return SolidityGraphRetainedOccurrence(
        subject_kind=subject_kind,
        subject_sha256=solidity_graph_occurrence_sha256(subject_kind, subject),
        occurrence_count=occurrence_count,
    )


def _canonical_occurrences(
    *items: SolidityGraphRetainedOccurrence,
) -> tuple[SolidityGraphRetainedOccurrence, ...]:
    return tuple(sorted(items, key=lambda item: (item.subject_kind.value, item.subject_sha256)))


def _complete_coverage_payload() -> dict[str, object]:
    edge_records = {kind.value: 0 for kind in SolidityGraphKind}
    edge_occurrences = dict(edge_records)
    edge_candidates = dict(edge_records)
    edge_records[SolidityGraphKind.STATE_DEPENDENCY.value] = 1
    edge_occurrences[SolidityGraphKind.STATE_DEPENDENCY.value] = 3
    edge_candidates[SolidityGraphKind.STATE_DEPENDENCY.value] = 3
    fact_records = {kind.value: 0 for kind in SolidityGraphFactKind}
    fact_occurrences = dict(fact_records)
    fact_candidates = dict(fact_records)
    fact_records[SolidityGraphFactKind.GRAPH_NODE.value] = 1
    fact_occurrences[SolidityGraphFactKind.GRAPH_NODE.value] = 2
    fact_candidates[SolidityGraphFactKind.GRAPH_NODE.value] = 2
    return {
        "graph_analysis_state": AnalysisState.DETERMINISTIC,
        "graph_edge_counts": edge_records,
        "graph_retained_edge_occurrence_counts": edge_occurrences,
        "graph_candidate_edge_counts": edge_candidates,
        "graph_omitted_edge_counts": {},
        "graph_omission_evidence_sha256s": [],
        "graph_node_counts": {SolidityGraphNodeKind.ENTITY.value: 1},
        "graph_fact_retained_counts": fact_records,
        "graph_fact_retained_occurrence_counts": fact_occurrences,
        "graph_fact_candidate_counts": fact_candidates,
        "graph_fact_omitted_counts": {},
        "graph_fact_omission_evidence_sha256s": [],
        "graph_warnings": [],
    }


def _omission(
    graph: SolidityGraphKind = SolidityGraphKind.STATE_DEPENDENCY,
    *,
    retained_count: int = 1,
    retained_occurrence_count: int | None = None,
) -> SolidityGraphOmission:
    occurrence_count = (
        retained_count if retained_occurrence_count is None else retained_occurrence_count
    )
    return SolidityGraphOmission.build(
        graph=graph,
        candidate_count=occurrence_count + 2,
        retained_count=retained_count,
        retained_occurrence_count=occurrence_count,
        omitted_count=2,
        omitted_canonical_bytes=640,
        omitted_stream_sha256="b" * 64,
        omitted_sample_sha256s=("c" * 64, "d" * 64),
    )


def _partial_graph_set(**updates: object) -> SolidityGraphSet:
    values: dict[str, object] = {
        "edges": [_edge()],
        "analyzed_graphs": [SolidityGraphKind.ASSET_FLOW],
        "coverage": {SolidityGraphKind.STATE_DEPENDENCY.value: 1},
        "generation_complete": False,
        "edge_omissions": (_omission(),),
    }
    values.update(updates)
    if "retained_occurrences" not in updates:
        edges = cast(list[SolidityGraphEdge], values.get("edges", []))
        nodes = cast(list[SolidityGraphNode], values.get("nodes", []))
        storage_layout = cast(list[SolidityStorageEntry], values.get("storage_layout", []))
        warnings = cast(list[str], values.get("warnings", []))
        values["retained_occurrences"] = _canonical_occurrences(
            *(_occurrence(SolidityGraphOccurrenceKind.EDGE, edge) for edge in edges),
            *(_occurrence(SolidityGraphOccurrenceKind.GRAPH_NODE, node) for node in nodes),
            *(
                _occurrence(SolidityGraphOccurrenceKind.STORAGE_ENTRY, entry)
                for entry in storage_layout
            ),
            *(_occurrence(SolidityGraphOccurrenceKind.WARNING, warning) for warning in warnings),
        )
    return SolidityGraphSet.model_validate(values)


def _fact_omission(
    fact_kind: SolidityGraphFactKind = SolidityGraphFactKind.WARNING,
    *,
    retained_count: int = 0,
    retained_occurrence_count: int | None = None,
) -> SolidityGraphFactOmission:
    occurrence_count = (
        retained_count if retained_occurrence_count is None else retained_occurrence_count
    )
    return SolidityGraphFactOmission.build(
        fact_kind=fact_kind,
        candidate_count=occurrence_count + 1,
        retained_count=retained_count,
        retained_occurrence_count=occurrence_count,
        omitted_count=1,
        omitted_canonical_bytes=128,
        omitted_stream_sha256="e" * 64,
        omitted_sample_sha256s=("f" * 64,),
    )


def test_graph_set_requires_an_explicit_empty_retained_occurrence_inventory() -> None:
    with pytest.raises(ValidationError, match="Field required"):
        SolidityGraphSet(edges=[])

    graphs = SolidityGraphSet(edges=[], retained_occurrences=())

    assert graphs.generation_complete is True
    assert graphs.artifact_byte_limit == 100_000_000
    assert graphs.selection_algorithm == "mmaudit.semantic-graph-risk-order.v1"
    assert graphs.edge_omissions == ()
    assert graphs.retained_occurrences == ()


def test_graph_omission_is_bounded_self_hashed_and_round_trips() -> None:
    omission = _omission()
    graphs = _partial_graph_set()

    assert omission.candidate_count == (omission.retained_occurrence_count + omission.omitted_count)
    assert len(omission.omitted_sample_sha256s) == 2
    assert SolidityGraphSet.model_validate_json(graphs.model_dump_json()) == graphs

    tampered = omission.model_dump(mode="json")
    tampered["omitted_canonical_bytes"] += 1
    with pytest.raises(ValidationError, match="evidence hash is inconsistent"):
        SolidityGraphOmission.model_validate(tampered)


@pytest.mark.parametrize("fact_kind", list(SolidityGraphFactKind))
def test_graph_fact_omission_is_bounded_self_hashed_and_marks_partial(
    fact_kind: SolidityGraphFactKind,
) -> None:
    omission = _fact_omission(fact_kind)
    graphs = SolidityGraphSet(
        edges=[],
        retained_occurrences=(),
        generation_complete=False,
        fact_omissions=(omission,),
    )

    assert graphs.fact_omissions == (omission,)
    assert omission.candidate_count == (omission.retained_occurrence_count + omission.omitted_count)
    assert SolidityGraphSet.model_validate_json(graphs.model_dump_json()) == graphs

    tampered = omission.model_dump(mode="json")
    tampered["omitted_canonical_bytes"] += 1
    with pytest.raises(ValidationError, match="evidence hash is inconsistent"):
        SolidityGraphFactOmission.model_validate(tampered)


def test_graph_fact_omissions_require_exact_retained_counts_and_canonical_order() -> None:
    node_omission = _fact_omission(SolidityGraphFactKind.GRAPH_NODE)
    warning_omission = _fact_omission(SolidityGraphFactKind.WARNING)

    with pytest.raises(ValidationError, match="retained count differs"):
        SolidityGraphSet(
            edges=[],
            warnings=["retained warning"],
            retained_occurrences=(
                _occurrence(SolidityGraphOccurrenceKind.WARNING, "retained warning"),
            ),
            generation_complete=False,
            fact_omissions=(warning_omission,),
        )
    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphSet(
            edges=[],
            retained_occurrences=(),
            generation_complete=False,
            fact_omissions=(warning_omission, node_omission),
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"generation_complete": True}, "completeness differs"),
        ({"edge_omissions": ()}, "completeness differs"),
        (
            {
                "analyzed_graphs": [
                    SolidityGraphKind.ASSET_FLOW,
                    SolidityGraphKind.STATE_DEPENDENCY,
                ]
            },
            "cannot be claimed as fully analyzed",
        ),
        ({"edges": []}, "retained count differs"),
        ({"coverage": {}}, "requires an explicit coverage count"),
        (
            {"coverage": {SolidityGraphKind.STATE_DEPENDENCY.value: 0}},
            "differs from graph coverage",
        ),
    ],
)
def test_graph_set_rejects_inconsistent_omission_accounting(
    updates: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _partial_graph_set(**updates)


def test_graph_omissions_must_be_unique_and_canonical() -> None:
    asset_edge = _edge(SolidityGraphKind.ASSET_FLOW)
    asset_omission = _omission(SolidityGraphKind.ASSET_FLOW)
    state_omission = _omission()
    values = {
        "edges": [_edge(), asset_edge],
        "retained_occurrences": _canonical_occurrences(
            _occurrence(SolidityGraphOccurrenceKind.EDGE, _edge()),
            _occurrence(SolidityGraphOccurrenceKind.EDGE, asset_edge),
        ),
        "coverage": {
            SolidityGraphKind.ASSET_FLOW.value: 1,
            SolidityGraphKind.STATE_DEPENDENCY.value: 1,
        },
        "generation_complete": False,
    }

    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphSet(**values, edge_omissions=(state_omission, asset_omission))
    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphSet(**values, edge_omissions=(asset_omission, asset_omission))


def test_graph_compaction_rebuilds_context_local_omission_accounting() -> None:
    graphs = _partial_graph_set()

    projected = compact_solidity_graphs(
        graphs,
        role="specialist:accounting_invariant",
        max_edges=0,
    )

    assert projected is not None
    assert projected.edges == []
    assert projected.coverage[SolidityGraphKind.STATE_DEPENDENCY.value] == 0
    assert projected.generation_complete is False
    assert len(projected.edge_omissions) == 1
    omission = projected.edge_omissions[0]
    assert omission.retained_count == 0
    assert omission.candidate_count == omission.omitted_count == 2
    assert omission.omitted_stream_sha256 == graphs.edge_omissions[0].omitted_stream_sha256
    assert SolidityGraphSet.model_validate(projected.model_dump(mode="python")) == projected


def test_graph_compaction_preserves_analytical_and_fact_omission_commitments() -> None:
    analytic_digest = "1" * 64
    analytic = SolidityGraphOmission.build(
        graph=SolidityGraphKind.STATE_DEPENDENCY,
        candidate_count=2,
        retained_count=0,
        omitted_count=2,
        omitted_canonical_bytes=0,
        analytical_omitted_count=2,
        analytical_population_sample_sha256s=(analytic_digest,),
        omitted_stream_sha256="2" * 64,
        omitted_sample_sha256s=(),
    )
    fact = _fact_omission()
    graphs = SolidityGraphSet(
        edges=[],
        retained_occurrences=(),
        analyzed_graphs=[
            kind for kind in SolidityGraphKind if kind is not SolidityGraphKind.STATE_DEPENDENCY
        ],
        coverage={kind.value: 0 for kind in SolidityGraphKind},
        generation_complete=False,
        edge_omissions=(analytic,),
        fact_omissions=(fact,),
    )

    projected = compact_solidity_graphs(graphs, role="specialist:source_audit", max_edges=0)

    assert projected is not None
    assert projected.edge_omissions[0].analytical_omitted_count == 2
    assert projected.edge_omissions[0].analytical_population_sample_sha256s == (analytic_digest,)
    assert projected.fact_omissions[0].omitted_stream_sha256 == fact.omitted_stream_sha256


def test_graph_compaction_preserves_exact_nonunique_retained_occurrence_counts() -> None:
    state_edge = _edge()
    asset_edge = _edge(SolidityGraphKind.ASSET_FLOW)
    producer_warning = "producer warning"
    state_omission = _omission(retained_occurrence_count=3)
    warning_omission = _fact_omission(
        retained_count=1,
        retained_occurrence_count=2,
    )
    graphs = _partial_graph_set(
        edges=[state_edge, asset_edge],
        coverage={
            SolidityGraphKind.ASSET_FLOW.value: 1,
            SolidityGraphKind.STATE_DEPENDENCY.value: 1,
        },
        edge_omissions=(state_omission,),
        warnings=[producer_warning],
        fact_omissions=(warning_omission,),
        retained_occurrences=_canonical_occurrences(
            _occurrence(SolidityGraphOccurrenceKind.EDGE, state_edge, 3),
            _occurrence(SolidityGraphOccurrenceKind.EDGE, asset_edge),
            _occurrence(SolidityGraphOccurrenceKind.WARNING, producer_warning, 2),
        ),
    )

    projected = compact_solidity_graphs(
        graphs,
        role="specialist:source_audit",
        max_edges=1,
        required_edges=(state_edge,),
    )

    assert projected is not None
    assert projected.edges == [state_edge]
    context_warning = "1 Solidity graph edges omitted from specialist:source_audit context"
    assert projected.warnings == [producer_warning, context_warning]
    occurrence_counts = {
        (item.subject_kind, item.subject_sha256): item.occurrence_count
        for item in projected.retained_occurrences
    }
    assert occurrence_counts == {
        (
            SolidityGraphOccurrenceKind.EDGE,
            solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, state_edge),
        ): 3,
        (
            SolidityGraphOccurrenceKind.WARNING,
            solidity_graph_occurrence_sha256(
                SolidityGraphOccurrenceKind.WARNING,
                producer_warning,
            ),
        ): 2,
        (
            SolidityGraphOccurrenceKind.WARNING,
            solidity_graph_occurrence_sha256(
                SolidityGraphOccurrenceKind.WARNING,
                context_warning,
            ),
        ): 1,
    }
    assert projected.edge_omissions[0].retained_count == 1
    assert projected.edge_omissions[0].retained_occurrence_count == 3
    assert projected.edge_omissions[0].candidate_count == 5
    assert projected.fact_omissions[0].retained_count == 2
    assert projected.fact_omissions[0].retained_occurrence_count == 3
    assert projected.fact_omissions[0].candidate_count == 4


def test_graph_set_rejects_missing_or_tampered_retained_occurrence_inventory() -> None:
    edge = _edge()
    graphs = _partial_graph_set(
        edge_omissions=(_omission(retained_occurrence_count=3),),
        retained_occurrences=(_occurrence(SolidityGraphOccurrenceKind.EDGE, edge, 3),),
    )

    missing = graphs.model_dump(mode="python")
    missing["retained_occurrences"] = ()
    with pytest.raises(ValidationError, match="inventory differs from serialized records"):
        SolidityGraphSet.model_validate(missing)

    wrong_count = graphs.model_dump(mode="python")
    wrong_count["retained_occurrences"][0]["occurrence_count"] = 2
    with pytest.raises(
        ValidationError, match="retained occurrence count differs from its inventory"
    ):
        SolidityGraphSet.model_validate(wrong_count)

    wrong_subject = graphs.model_dump(mode="python")
    wrong_subject["retained_occurrences"][0]["subject_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="inventory differs from serialized records"):
        SolidityGraphSet.model_validate(wrong_subject)


def test_graph_set_rejects_duplicate_or_noncanonical_retained_occurrence_inventory() -> None:
    state_edge = _edge()
    asset_edge = _edge(SolidityGraphKind.ASSET_FLOW)
    occurrences = _canonical_occurrences(
        _occurrence(SolidityGraphOccurrenceKind.EDGE, state_edge),
        _occurrence(SolidityGraphOccurrenceKind.EDGE, asset_edge),
    )
    values = {
        "edges": [state_edge, asset_edge],
        "coverage": {
            SolidityGraphKind.ASSET_FLOW.value: 1,
            SolidityGraphKind.STATE_DEPENDENCY.value: 1,
        },
        "generation_complete": False,
        "edge_omissions": (_omission(),),
    }

    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphSet(**values, retained_occurrences=tuple(reversed(occurrences)))
    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphSet(**values, retained_occurrences=(occurrences[0], occurrences[0]))


def test_context_inventory_accounts_for_rewritten_producer_omission_evidence() -> None:
    fact = _fact_omission(retained_count=1)
    graphs = _partial_graph_set(
        warnings=["producer warning"],
        fact_omissions=(fact,),
    )
    projected = compact_solidity_graphs(graphs, role="specialist:source_audit", max_edges=0)

    assert projected is not None
    assert projected.fact_omissions[0].evidence_sha256 != fact.evidence_sha256
    original_inventory = list(_solidity_graph_compaction_inventory(graphs))
    retained_inventory = list(_retained_solidity_graph_inventory(projected, original=graphs))
    original_fact_record = next(
        item
        for item in original_inventory
        if isinstance(item, dict) and item["field"] == "fact_omissions"
    )
    assert original_fact_record not in retained_inventory


def test_graph_omission_rejects_invalid_counts_and_unbounded_or_uncanonical_samples() -> None:
    payload = _omission().model_dump(mode="json")
    payload["candidate_count"] += 1
    with pytest.raises(ValidationError, match="candidate count differs"):
        SolidityGraphOmission.model_validate(payload)

    with pytest.raises(ValidationError, match="unique and canonically sorted"):
        SolidityGraphOmission.build(
            graph=SolidityGraphKind.STATE_DEPENDENCY,
            candidate_count=3,
            retained_count=1,
            omitted_count=2,
            omitted_canonical_bytes=640,
            omitted_stream_sha256="b" * 64,
            omitted_sample_sha256s=("d" * 64, "c" * 64),
        )

    with pytest.raises(ValidationError):
        SolidityGraphOmission.build(
            graph=SolidityGraphKind.STATE_DEPENDENCY,
            candidate_count=18,
            retained_count=1,
            omitted_count=17,
            omitted_canonical_bytes=5_440,
            omitted_stream_sha256="b" * 64,
            omitted_sample_sha256s=tuple(f"{index:064x}" for index in range(17)),
        )

    with pytest.raises(ValidationError, match="more samples than omitted edge records"):
        SolidityGraphOmission.build(
            graph=SolidityGraphKind.STATE_DEPENDENCY,
            candidate_count=2,
            retained_count=1,
            omitted_count=1,
            omitted_canonical_bytes=320,
            omitted_stream_sha256="b" * 64,
            omitted_sample_sha256s=("c" * 64, "d" * 64),
        )


@pytest.mark.parametrize(
    ("field_name", "message"),
    [
        (
            "graph_retained_edge_occurrence_counts",
            "retained edge occurrences must contain every canonical graph kind",
        ),
        (
            "graph_fact_retained_occurrence_counts",
            "retained fact occurrences must contain every canonical fact kind",
        ),
    ],
)
def test_analyzed_coverage_requires_explicit_complete_occurrence_maps(
    field_name: str,
    message: str,
) -> None:
    payload = _complete_coverage_payload()
    payload.pop(field_name)

    with pytest.raises(ValidationError, match=message):
        SolidityCoverage.model_validate(payload)


def test_analyzed_coverage_rejects_unknown_keys_and_negative_counts() -> None:
    unknown = _complete_coverage_payload()
    edge_counts = cast(dict[str, int], unknown["graph_edge_counts"])
    edge_counts["invented_graph_kind"] = 0
    with pytest.raises(ValidationError, match="every canonical graph kind"):
        SolidityCoverage.model_validate(unknown)

    negative = _complete_coverage_payload()
    retained_occurrences = cast(dict[str, int], negative["graph_retained_edge_occurrence_counts"])
    retained_occurrences[SolidityGraphKind.STATE_DEPENDENCY.value] = -1
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        SolidityCoverage.model_validate(negative)


def test_not_analyzed_coverage_rejects_graph_evidence() -> None:
    assert SolidityCoverage().graph_analysis_state is AnalysisState.NOT_ANALYZED

    with pytest.raises(ValidationError, match=r"not-analyzed.*cannot contain graph evidence"):
        SolidityCoverage(
            graph_edge_counts={kind.value: 0 for kind in SolidityGraphKind},
        )
    with pytest.raises(ValidationError, match=r"not-analyzed.*cannot contain graph evidence"):
        SolidityCoverage(asset_flow_operation_counts={"transfer": 1})


def test_coverage_omission_counts_require_evidence_and_attempted_failed_state() -> None:
    payload = _complete_coverage_payload()
    payload["graph_analysis_state"] = AnalysisState.ATTEMPTED_FAILED
    payload["graph_omitted_edge_counts"] = {SolidityGraphKind.STATE_DEPENDENCY.value: 2}
    payload["graph_omission_evidence_sha256s"] = ["a" * 64]
    candidates = cast(dict[str, int], payload["graph_candidate_edge_counts"])
    candidates[SolidityGraphKind.STATE_DEPENDENCY.value] += 2
    assert SolidityCoverage.model_validate(payload).graph_omitted_edge_counts == {
        SolidityGraphKind.STATE_DEPENDENCY.value: 2
    }

    missing_evidence = {**payload, "graph_omission_evidence_sha256s": []}
    with pytest.raises(ValidationError, match="one-for-one"):
        SolidityCoverage.model_validate(missing_evidence)

    wrong_state = {**payload, "graph_analysis_state": AnalysisState.DETERMINISTIC}
    with pytest.raises(ValidationError, match="attempted-failed state"):
        SolidityCoverage.model_validate(wrong_state)

    attempted_without_omission = _complete_coverage_payload()
    attempted_without_omission["graph_analysis_state"] = AnalysisState.ATTEMPTED_FAILED
    with pytest.raises(ValidationError, match="attempted-failed state"):
        SolidityCoverage.model_validate(attempted_without_omission)

    fact_payload = _complete_coverage_payload()
    fact_payload["graph_analysis_state"] = AnalysisState.ATTEMPTED_FAILED
    fact_payload["graph_fact_omitted_counts"] = {SolidityGraphFactKind.WARNING.value: 1}
    fact_payload["graph_fact_omission_evidence_sha256s"] = ["b" * 64]
    fact_candidates = cast(dict[str, int], fact_payload["graph_fact_candidate_counts"])
    fact_candidates[SolidityGraphFactKind.WARNING.value] = 1
    assert SolidityCoverage.model_validate(fact_payload).graph_fact_omitted_counts == {
        SolidityGraphFactKind.WARNING.value: 1
    }
    with pytest.raises(ValidationError, match="one-for-one"):
        SolidityCoverage.model_validate(
            {**fact_payload, "graph_fact_omission_evidence_sha256s": []}
        )


def test_coverage_artifact_explicitly_requires_graph_comparison_authority() -> None:
    coverage = SolidityCoverage.model_validate(_complete_coverage_payload())
    artifact = SolidityCoverageArtifact(
        evidence_authority="comparison_required",
        coverage=coverage,
    )

    assert artifact.model_dump(mode="json")["evidence_authority"] == "comparison_required"
    with pytest.raises(ValidationError, match="Field required"):
        SolidityCoverageArtifact.model_validate(
            {"schema_version": "1.0", "coverage": coverage.model_dump(mode="json")}
        )
    with pytest.raises(ValidationError, match="comparison_required"):
        SolidityCoverageArtifact.model_validate(
            {
                "schema_version": "1.0",
                "evidence_authority": "authoritative",
                "coverage": coverage.model_dump(mode="json"),
            }
        )


def test_release_coverage_schema_exposes_occurrence_authority_contract() -> None:
    schema = json.loads(rendered_schema("solidity_coverage.schema.json", SolidityCoverageArtifact))
    coverage = schema["$defs"]["SolidityCoverage"]
    properties = coverage["properties"]

    assert "evidence_authority" in schema["required"]
    assert schema["properties"]["evidence_authority"]["const"] == "comparison_required"
    assert "graph_retained_edge_occurrence_counts" in coverage["required"]
    assert "graph_fact_retained_occurrence_counts" in coverage["required"]
    edge_values = properties["graph_retained_edge_occurrence_counts"]["additionalProperties"]
    assert edge_values["minimum"] == 0
    assert edge_values["maximum"] == 2**63 - 1
    assert set(properties["graph_retained_edge_occurrence_counts"]["propertyNames"]["enum"]) == {
        kind.value for kind in SolidityGraphKind
    }
    assert properties["graph_omitted_edge_counts"]["additionalProperties"]["minimum"] == 1
    assert coverage["allOf"]


def test_release_graph_schema_exposes_bounded_typed_omission_contract() -> None:
    schema = json.loads(rendered_schema("solidity_graphs.schema.json", SolidityGraphsArtifact))
    graph_set = schema["$defs"]["SolidityGraphSet"]
    omission = schema["$defs"]["SolidityGraphOmission"]
    fact_omission = schema["$defs"]["SolidityGraphFactOmission"]
    retained_occurrence = schema["$defs"]["SolidityGraphRetainedOccurrence"]

    assert graph_set["properties"]["artifact_byte_limit"]["maximum"] == 100_000_000
    assert "retained_occurrences" in graph_set["required"]
    assert graph_set["properties"]["retained_occurrences"]["maxItems"] == 850_256
    assert graph_set["properties"]["edge_omissions"]["maxItems"] == 64
    assert graph_set["properties"]["fact_omissions"]["maxItems"] == 3
    assert omission["properties"]["omitted_sample_sha256s"]["maxItems"] == 16
    assert omission["properties"]["candidate_count"]["maximum"] == 2**63 - 1
    assert omission["additionalProperties"] is False
    assert fact_omission["properties"]["omitted_sample_sha256s"]["maxItems"] == 16
    assert fact_omission["properties"]["omitted_stream_sha256"]["pattern"] == ("^[0-9a-f]{64}$")
    assert fact_omission["additionalProperties"] is False
    assert retained_occurrence["properties"]["occurrence_count"]["maximum"] == 2**63 - 1
    assert retained_occurrence["additionalProperties"] is False
