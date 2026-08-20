from __future__ import annotations

import hashlib
import itertools

import pytest

from mmaudit.models.coverage_planning import (
    ModelSurfaceCoveragePlan,
    ModelSurfaceReviewerBinding,
    ModelSurfaceRiskTier,
    build_model_surface_coverage_plan,
)
from mmaudit.models.schemas import (
    AnalysisState,
    CoverageMetric,
    CoverageProvenance,
    Location,
    ModelReviewCoverage,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
)
from mmaudit.orchestration.model_coverage import model_review_tiered_completion_gate

_ROOTS = tuple(f"sha256:{index:064x}" for index in range(1, 5))
_TIERS = tuple(ModelSurfaceRiskTier)


def _request(
    tier: ModelSurfaceRiskTier,
    *,
    label_suffix: str = "",
    subject_suffix: str = "",
    invariant_suffix: str = "",
) -> ModelSurfaceReviewRequest:
    kind, critical = {
        ModelSurfaceRiskTier.T0: (ModelReviewSurfaceKind.INVARIANT, True),
        ModelSurfaceRiskTier.T1: (ModelReviewSurfaceKind.ENTRY_POINT, False),
        ModelSurfaceRiskTier.T2: (ModelReviewSurfaceKind.STATE, False),
        ModelSurfaceRiskTier.T3: (ModelReviewSurfaceKind.CONTRACT, False),
    }[tier]
    subject_id = f"synthetic:{tier.value}{subject_suffix}"
    label = f"Synthetic {tier.value}{label_suffix}"
    location = Location(
        path="src/Synthetic.sol",
        start_line=_TIERS.index(tier) + 1,
        end_line=_TIERS.index(tier) + 1,
        symbol=subject_id,
    )
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(kind, subject_id),
        kind=kind,
        subject_id=subject_id,
        contract="Synthetic",
        function_or_state_surface=label,
        critical=critical,
        allowed_locations=(location,),
        allowed_symbols=(subject_id,),
        invariant_considered=f"Review the synthetic {tier.value} invariant.{invariant_suffix}",
    )


def _floor(tier: ModelSurfaceRiskTier, t0_floor: int = 3) -> int:
    if tier is ModelSurfaceRiskTier.T0:
        return t0_floor
    if tier is ModelSurfaceRiskTier.T1:
        return min(2, t0_floor)
    return 1


def _plan(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    *,
    credited_roots: dict[str, tuple[str, ...]] | None = None,
    bindings: tuple[ModelSurfaceReviewerBinding, ...] = (),
    t0_floor: int = 3,
) -> ModelSurfaceCoveragePlan:
    return build_model_surface_coverage_plan(
        requests,
        bindings,
        surface_scope_by_id={request.surface_id: "scope:synthetic" for request in requests},
        credited_root_lineages_by_surface=credited_roots,
        minimum_t0_root_lineages=t0_floor,
    )


def _reference(
    request: ModelSurfaceReviewRequest,
    root: str,
    index: int,
) -> ModelReviewEvidenceReference:
    identity = f"{request.surface_id}:{root}:{index}"
    return ModelReviewEvidenceReference(
        surface_id=request.surface_id,
        request_id=f"request-{hashlib.sha256(identity.encode()).hexdigest()}",
        artifact_sha256=hashlib.sha256(f"artifact:{identity}".encode()).hexdigest(),
        requested_model=f"synthetic/reviewer-{index}",
        model=f"synthetic/reviewer-{index}",
        review_role=f"reviewer_{index}",
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        root_lineage=root,
        credited=True,
        reason="Synthetic response-backed review evidence.",
    )


def _metric(numerator: int, denominator: int, *, detail: str) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=denominator,
        percentage=round((numerator / denominator) * 100, 4) if denominator else None,
        exclusions=[],
        not_applicable_evidence=(
            [] if denominator else ["no deterministic surfaces of this category"]
        ),
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=[] if numerator == denominator else ["synthetic coverage deficit"],
        state=AnalysisState.MODEL_ONLY,
        detail=detail,
    )


def _coverage(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    roots_by_surface: dict[str, tuple[str, ...]],
    *,
    t0_floor: int = 3,
) -> ModelReviewCoverage:
    surfaces = []
    for request in requests:
        references = [
            _reference(request, root, index)
            for index, root in enumerate(roots_by_surface.get(request.surface_id, ()))
        ]
        references.sort(
            key=lambda item: (
                item.request_id,
                item.artifact_sha256,
                item.surface_id,
                item.review_role,
                item.status.value,
            )
        )
        surfaces.append(
            ModelReviewSurface(
                surface_id=request.surface_id,
                kind=request.kind,
                subject_id=request.subject_id,
                label=request.function_or_state_surface,
                critical=request.critical,
                locations=list(request.allowed_locations),
                evidence_references=references,
            )
        )
    surfaces.sort(key=lambda surface: surface.surface_id)
    by_kind = {
        kind: _metric(
            sum(surface.reviewed for surface in surfaces if surface.kind is kind),
            sum(surface.kind is kind for surface in surfaces),
            detail=f"Synthetic {kind.value} coverage.",
        )
        for kind in ModelReviewSurfaceKind
    }
    critical_surfaces = [surface for surface in surfaces if surface.critical]
    critical_numerator = sum(
        surface.reviewed and len(surface.root_lineages) >= t0_floor for surface in critical_surfaces
    )
    critical = _metric(
        critical_numerator,
        len(critical_surfaces),
        detail="Synthetic critical coverage.",
    )
    return ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        minimum_critical_root_lineages=t0_floor,
        surfaces=surfaces,
        overall=_metric(
            sum(surface.reviewed for surface in surfaces),
            len(surfaces),
            detail="Synthetic overall coverage.",
        ),
        by_kind=by_kind,
        critical=critical,
        critical_gate_passed=(
            critical.denominator > 0 and critical.numerator == critical.denominator
        ),
        limitations=[],
    )


def _complete_inputs() -> tuple[
    tuple[ModelSurfaceReviewRequest, ...],
    dict[str, tuple[str, ...]],
]:
    requests_by_tier = {tier: _request(tier) for tier in _TIERS}
    requests = tuple(sorted(requests_by_tier.values(), key=lambda request: request.surface_id))
    roots = {
        request.surface_id: _ROOTS[: _floor(tier)] for tier, request in requests_by_tier.items()
    }
    return requests, roots


def _request_for_tier(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    tier: ModelSurfaceRiskTier,
) -> ModelSurfaceReviewRequest:
    return next(request for request in requests if request.subject_id == f"synthetic:{tier.value}")


def test_tiered_completion_gate_rejoins_every_exact_tier_requirement() -> None:
    requests, roots = _complete_inputs()
    result = model_review_tiered_completion_gate(
        _plan(requests, credited_roots=roots),
        _coverage(requests, roots),
        requests,
        required=True,
    )

    assert result.passed
    assert result.state is AnalysisState.MODEL_ONLY
    assert "T0:1/0,T1:1/0,T2:1/0,T3:1/0" in result.detail


@pytest.mark.parametrize("tier", _TIERS)
def test_tiered_completion_gate_fails_each_tier_root_deficit(
    tier: ModelSurfaceRiskTier,
) -> None:
    requests, planned_roots = _complete_inputs()
    observed_roots = dict(planned_roots)
    request = _request_for_tier(requests, tier)
    observed_roots[request.surface_id] = planned_roots[request.surface_id][:-1]

    result = model_review_tiered_completion_gate(
        _plan(requests, credited_roots=planned_roots),
        _coverage(requests, observed_roots),
        requests,
        required=True,
    )

    assert not result.passed
    assert f"{tier.value}:1/1" in result.detail


@pytest.mark.parametrize("plan_has_extra", (False, True))
def test_tiered_completion_gate_fails_missing_or_extra_plan_surface(
    plan_has_extra: bool,
) -> None:
    requests, roots = _complete_inputs()
    extra = _request(
        ModelSurfaceRiskTier.T3,
        label_suffix=" extra",
        subject_suffix=":extra",
    )
    plan_requests = (*requests, extra) if plan_has_extra else requests[:-1]
    coverage_requests = requests
    all_roots = {**roots, extra.surface_id: _ROOTS[:1]}

    result = model_review_tiered_completion_gate(
        _plan(
            plan_requests,
            credited_roots={item.surface_id: all_roots[item.surface_id] for item in plan_requests},
        ),
        _coverage(coverage_requests, all_roots),
        requests,
        required=True,
    )

    assert not result.passed
    expected = "plan_extra_surfaces=1" if plan_has_extra else "plan_missing_surfaces=1"
    assert expected in result.detail


def test_tiered_completion_gate_rejects_coherent_plan_and_coverage_omission() -> None:
    requests, roots = _complete_inputs()
    omitted = _request_for_tier(requests, ModelSurfaceRiskTier.T3)
    reduced_requests = tuple(request for request in requests if request != omitted)
    reduced_roots = {
        surface_id: surface_roots
        for surface_id, surface_roots in roots.items()
        if surface_id != omitted.surface_id
    }

    result = model_review_tiered_completion_gate(
        _plan(reduced_requests, credited_roots=reduced_roots),
        _coverage(reduced_requests, reduced_roots),
        requests,
        required=True,
    )

    assert not result.passed
    assert "plan_missing_surfaces=1" in result.detail
    assert "coverage_missing_surfaces=1" in result.detail
    assert "T3:1/1" in result.detail


def test_tiered_completion_gate_rejects_semantically_mutated_rehashed_request() -> None:
    requests, roots = _complete_inputs()
    t0 = _request_for_tier(requests, ModelSurfaceRiskTier.T0)
    mutated_t0 = _request(
        ModelSurfaceRiskTier.T0,
        invariant_suffix=" Mutated but canonically rehashed.",
    )
    mutated_requests = tuple(
        mutated_t0 if request.surface_id == t0.surface_id else request for request in requests
    )

    result = model_review_tiered_completion_gate(
        _plan(mutated_requests, credited_roots=roots),
        _coverage(requests, roots),
        requests,
        required=True,
    )

    assert not result.passed
    assert "manifest_mismatches=1" in result.detail
    assert "full_request_mismatches=1" in result.detail
    assert "request_surface_mismatches=0" in result.detail


def test_tiered_completion_gate_rejects_reordered_authoritative_inventory() -> None:
    requests, roots = _complete_inputs()

    result = model_review_tiered_completion_gate(
        _plan(requests, credited_roots=roots),
        _coverage(requests, roots),
        tuple(reversed(requests)),
        required=True,
    )

    assert not result.passed
    assert "unique and sorted by surface ID" in result.detail


def test_tiered_completion_gate_bounds_infinite_authoritative_inventory() -> None:
    requests, roots = _complete_inputs()

    class LyingInfiniteInventory:
        def __len__(self) -> int:
            return 1

        def __iter__(self):  # type: ignore[no-untyped-def]
            return itertools.repeat(requests[0])

    result = model_review_tiered_completion_gate(
        _plan(requests, credited_roots=roots),
        _coverage(requests, roots),
        LyingInfiniteInventory(),  # type: ignore[arg-type]
        required=True,
    )

    assert not result.passed
    assert "exceeds 10000 requests" in result.detail


def test_tiered_completion_gate_rejects_caller_lowered_t0_policy() -> None:
    requests, roots = _complete_inputs()
    lowered_roots = {
        request.surface_id: _ROOTS[: _floor(tier, 2)]
        for tier in _TIERS
        for request in (_request_for_tier(requests, tier),)
    }

    result = model_review_tiered_completion_gate(
        _plan(requests, credited_roots=lowered_roots, t0_floor=2),
        _coverage(requests, roots, t0_floor=3),
        requests,
        required=True,
    )

    assert not result.passed
    assert "policy_mismatches=1" in result.detail


def test_tiered_completion_gate_requires_every_planned_lineage_gap_root() -> None:
    requests = tuple(
        sorted(
            (_request(tier) for tier in _TIERS),
            key=lambda request: request.surface_id,
        )
    )
    bindings = tuple(
        ModelSurfaceReviewerBinding.build(
            review_role=f"reviewer_{index}",
            requested_model=f"synthetic/reviewer-{index}",
            root_lineage=root,
        )
        for index, root in enumerate(_ROOTS[:3])
    )
    plan = _plan(requests, bindings=bindings)
    observed_roots = {
        request.surface_id: tuple(
            sorted(
                {
                    assignment.root_lineage
                    for assignment in plan.assignments
                    if assignment.surface_id == request.surface_id
                }
            )
        )
        for request in requests
    }
    assert model_review_tiered_completion_gate(
        plan,
        _coverage(requests, observed_roots),
        requests,
        required=True,
    ).passed

    t1 = _request_for_tier(requests, ModelSurfaceRiskTier.T1)
    observed_roots[t1.surface_id] = observed_roots[t1.surface_id][:-1]

    result = model_review_tiered_completion_gate(
        plan,
        _coverage(requests, observed_roots),
        requests,
        required=True,
    )

    assert not result.passed
    assert "planned_root_mismatches=1" in result.detail


def test_tiered_completion_gate_returns_failure_for_mutated_plan_not_exception() -> None:
    requests, roots = _complete_inputs()
    plan = _plan(requests, credited_roots=roots)
    mutated = plan.model_copy(update={"plan_sha256": "0" * 64})

    result = model_review_tiered_completion_gate(
        mutated,
        _coverage(requests, roots),
        requests,
        required=True,
    )

    assert not result.passed
    assert result.state is AnalysisState.ATTEMPTED_FAILED
    assert "canonical revalidation" in result.detail


def test_tiered_completion_gate_fails_closed_without_both_artifacts() -> None:
    requests, roots = _complete_inputs()

    assert not model_review_tiered_completion_gate(
        None,
        _coverage(requests, roots),
        requests,
        required=True,
    ).passed
    assert not model_review_tiered_completion_gate(
        _plan(requests, credited_roots=roots),
        None,
        requests,
        required=True,
    ).passed
