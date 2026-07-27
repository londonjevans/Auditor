from __future__ import annotations

from pathlib import Path

from mmaudit.models.schemas import (
    AnalysisState,
    CoverageMetric,
    CoverageProvenance,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.solidity.coverage import build_solidity_coverage, with_model_review_coverage

_HASH = "a" * 64
_MODEL_REVIEW_METRICS = (
    "public_external_entry_points_reviewed",
    "privileged_entry_points_reviewed",
    "state_writing_functions_reviewed",
    "high_value_paths_reviewed",
)


def _entity(entity_id: str, name: str) -> SolidityEntity:
    return SolidityEntity(
        id=entity_id,
        kind=SolidityEntityKind.FUNCTION,
        name=name,
        contract_name="Synthetic",
        path="src/Synthetic.sol",
        start_line=1,
        end_line=2,
        byte_start=0,
        byte_end=20,
        source_hash=_HASH,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="compiler AST",
        visibility="external",
        signature=f"{name}()",
    )


def _edge(graph: SolidityGraphKind, source_id: str, target_id: str) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label=f"{source_id} -> {target_id}",
        provenance=SolidityProvenance.COMPILER,
        path="src/Synthetic.sol",
        start_line=1,
        end_line=2,
        source_hash=_HASH,
        confidence=1,
        transformation="compiler AST",
    )


def _base_inputs() -> tuple[SoliditySymbolIndex, SolidityGraphSet]:
    index = SoliditySymbolIndex(
        projects=[],
        entities=[
            _entity("function:one", "one"),
            _entity("function:two", "two"),
        ],
        ast_sources=["src/Synthetic.sol"],
    )
    graphs = SolidityGraphSet(
        edges=[
            _edge(SolidityGraphKind.PRIVILEGE, "function:one", "modifier:owner"),
            _edge(SolidityGraphKind.STATE_WRITE, "function:two", "state:value"),
            _edge(
                SolidityGraphKind.SENSITIVE_REACHABILITY,
                "function:two",
                "sink:value",
            ),
        ],
        analyzed_graphs=[
            SolidityGraphKind.PRIVILEGE,
            SolidityGraphKind.STATE_WRITE,
            SolidityGraphKind.SENSITIVE_REACHABILITY,
        ],
    )
    return index, graphs


def _base_coverage(
    index: SoliditySymbolIndex,
    graphs: SolidityGraphSet,
) -> SolidityCoverage:
    discovery = DiscoveryResult(
        root=Path("."),
        files=(
            DiscoveredFile(
                absolute_path=Path("src/Synthetic.sol"),
                relative_path="src/Synthetic.sol",
                content="contract Synthetic {}",
                size=21,
                lines=1,
                sha256=_HASH,
                language="Solidity",
                categories=("source",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    return build_solidity_coverage(
        discovery=discovery,
        projects=[],
        compilations=[],
        index=index,
        graphs=graphs,
        scanner_runs=[],
    )


def _metric(numerator: int, denominator: int, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round(numerator / denominator * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=[] if denominator else ["no matching surfaces"],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=(
            [f"{denominator - numerator} surface(s) lack review credit"]
            if denominator > numerator
            else []
        ),
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _review_coverage(*surfaces: ModelReviewSurface) -> ModelReviewCoverage:
    surface_list = sorted(surfaces, key=lambda item: item.surface_id)
    by_kind = {
        kind: _metric(
            sum(surface.reviewed for surface in surface_list if surface.kind is kind),
            sum(surface.kind is kind for surface in surface_list),
            f"{kind.value} review coverage",
        )
        for kind in ModelReviewSurfaceKind
    }
    critical_surfaces = [surface for surface in surface_list if surface.critical]
    critical_reviewed = sum(
        surface.reviewed and len(surface.root_lineages) >= 3 for surface in critical_surfaces
    )
    return ModelReviewCoverage(
        applicable=True,
        surfaces=surface_list,
        overall=_metric(
            sum(surface.reviewed for surface in surface_list),
            len(surface_list),
            "overall review coverage",
        ),
        by_kind=by_kind,
        critical=_metric(
            critical_reviewed,
            len(critical_surfaces),
            "critical review coverage",
        ),
        critical_gate_passed=critical_reviewed == len(critical_surfaces),
    )


def _surface(subject_id: str, *, credited: bool) -> ModelReviewSurface:
    surface_id = ModelSurfaceReviewRequest.calculate_surface_id(
        ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id,
    )
    reference = ModelReviewEvidenceReference(
        surface_id=surface_id,
        request_id="request-1",
        artifact_sha256="b" * 64,
        requested_model="vendor/model" if credited else None,
        model="vendor/model" if credited else None,
        review_role="source_audit",
        status=(
            ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE
            if credited
            else ModelSurfaceReviewStatus.NOT_REVIEWED
        ),
        root_lineage=f"sha256:{'c' * 64}" if credited else None,
        credited=credited,
        reason="validated substantive review" if credited else "model did not review surface",
    )
    return ModelReviewSurface(
        surface_id=surface_id,
        kind=ModelReviewSurfaceKind.ENTRY_POINT,
        subject_id=subject_id,
        label=subject_id,
        critical=False,
        evidence_references=[reference],
    )


def test_full_source_presence_without_explicit_review_surfaces_earns_no_credit() -> None:
    index, graphs = _base_inputs()
    coverage = _base_coverage(index, graphs)

    projected = with_model_review_coverage(
        coverage,
        index,
        _review_coverage(),
        graphs,
    )

    assert projected.functions_reviewed_by_models == 0
    assert {
        name: (
            projected.quality_metrics[name].numerator,
            projected.quality_metrics[name].denominator,
        )
        for name in _MODEL_REVIEW_METRICS
    } == {
        "public_external_entry_points_reviewed": (0, 2),
        "privileged_entry_points_reviewed": (0, 1),
        "state_writing_functions_reviewed": (0, 1),
        "high_value_paths_reviewed": (0, 1),
    }


def test_one_explicit_reviewed_function_updates_only_that_function() -> None:
    index, graphs = _base_inputs()
    coverage = _base_coverage(index, graphs)

    projected = with_model_review_coverage(
        coverage,
        index,
        _review_coverage(_surface("function:one", credited=True)),
        graphs,
    )

    assert projected.functions_reviewed_by_models == 1
    assert projected.quality_metrics["public_external_entry_points_reviewed"].numerator == 1
    assert projected.quality_metrics["privileged_entry_points_reviewed"].numerator == 1
    assert projected.quality_metrics["state_writing_functions_reviewed"].numerator == 0
    assert projected.quality_metrics["high_value_paths_reviewed"].numerator == 0
    assert projected.quality_metrics["state_writing_functions_reviewed"].denominator == 1
    assert projected.quality_metrics["high_value_paths_reviewed"].denominator == 1


def test_not_reviewed_reference_does_not_earn_function_credit() -> None:
    index, graphs = _base_inputs()
    coverage = _base_coverage(index, graphs)

    projected = with_model_review_coverage(
        coverage,
        index,
        _review_coverage(_surface("function:one", credited=False)),
        graphs,
    )

    assert projected.functions_reviewed_by_models == 0
    assert projected.quality_metrics["public_external_entry_points_reviewed"].numerator == 0
    assert projected.quality_metrics["privileged_entry_points_reviewed"].numerator == 0


def test_initial_review_metrics_use_substantive_review_provenance() -> None:
    index, graphs = _base_inputs()
    coverage = _base_coverage(index, graphs)

    for metric_name in _MODEL_REVIEW_METRICS:
        metric = coverage.quality_metrics[metric_name]
        assert CoverageProvenance.MODEL_REVIEW in metric.provenance
        assert CoverageProvenance.MODEL_CONTEXT not in metric.provenance
        assert "validated substantive model reviews" in metric.detail
