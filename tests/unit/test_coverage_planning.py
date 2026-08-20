from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from decimal import Inexact, localcontext
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from mmaudit.models.coverage_planning import (
    MAX_COVERAGE_REVIEWERS,
    MAX_SURFACES_PER_GAP_TASK,
    ModelSurfaceAssignmentPurpose,
    ModelSurfaceCoveragePlan,
    ModelSurfaceResourceFailureCode,
    ModelSurfaceReviewerBinding,
    ModelSurfaceRiskTier,
    ModelSurfaceTaskResourcePreview,
    _canonical_sha256,
    build_model_surface_coverage_plan,
    build_model_surface_coverage_policy,
    build_model_surface_resource_preflight,
    classify_model_surface_risk,
)
from mmaudit.models.schemas import (
    ModelReviewSurfaceKind,
    ModelSurfaceReviewPriority,
    ModelSurfaceReviewRequest,
)


def _root(index: int) -> str:
    return f"sha256:{index:064x}"


def _binding(
    index: int,
    *,
    role: str | None = None,
    root_index: int | None = None,
) -> ModelSurfaceReviewerBinding:
    return ModelSurfaceReviewerBinding.build(
        review_role=role or f"specialist:role_{index:03d}",
        requested_model=f"vendor/security-{index:03d}",
        root_lineage=_root(index if root_index is None else root_index),
    )


def _request(
    index: int,
    *,
    kind: ModelReviewSurfaceKind = ModelReviewSurfaceKind.CONTRACT,
    critical: bool = False,
    elevated: bool = False,
) -> ModelSurfaceReviewRequest:
    subject_id = f"entity:{index:05d}"
    gap_id = f"audited-suite-gap:{index:064x}"
    return ModelSurfaceReviewRequest(
        surface_id=ModelSurfaceReviewRequest.calculate_surface_id(kind, subject_id),
        kind=kind,
        subject_id=subject_id,
        contract=f"Contract{index}",
        function_or_state_surface=f"surface{index}",
        critical=critical,
        allowed_symbols=(subject_id,),
        invariant_considered=f"Review invariant {index}.",
        priority=(
            ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
            if elevated
            else ModelSurfaceReviewPriority.STANDARD
        ),
        coverage_gap_ids=(gap_id,) if elevated else (),
    )


def _scopes(requests: list[ModelSurfaceReviewRequest], scope: str = "scope-main") -> dict[str, str]:
    return {request.surface_id: scope for request in requests}


def _single_task_plan() -> ModelSurfaceCoveragePlan:
    request = _request(1)
    binding = _binding(1)
    return build_model_surface_coverage_plan(
        [request],
        [binding],
        surface_scope_by_id=_scopes([request]),
        mandatory_reviewer_roles=(binding.review_role,),
        minimum_t0_root_lineages=3,
    )


def _preview(
    plan: ModelSurfaceCoveragePlan,
    *,
    task_index: int = 0,
    attempts: int = 2,
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    cost: str = "0.25",
) -> ModelSurfaceTaskResourcePreview:
    return ModelSurfaceTaskResourcePreview.build(
        task=plan.tasks[task_index],
        scheduler_task_id=f"scheduler-task-{task_index + 1:064x}",
        scheduler_task_plan_sha256=f"{task_index + 101:064x}",
        campaign_manifest_sha256=f"{task_index + 201:064x}",
        rendered_context_sha256=f"{task_index + 301:064x}",
        context_request_evidence_sha256=f"{task_index + 401:064x}",
        request_token_plan_projection_sha256=f"{task_index + 501:064x}",
        request_material_projection_sha256=f"{task_index + 601:064x}",
        request_material_projection_utf8_bytes=1_000,
        endpoint_policy_snapshot_sha256=f"{task_index + 701:064x}",
        endpoint_policy_pricing_sha256=f"{task_index + 801:064x}",
        provider_endpoint="synthetic-provider",
        endpoint_pricing_snapshot_sha256=f"{task_index + 901:064x}",
        endpoint_cost_bound_projection_sha256=f"{task_index + 1_001:064x}",
        maximum_attempts=attempts,
        maximum_prompt_tokens_per_attempt=prompt_tokens,
        maximum_completion_tokens_per_attempt=completion_tokens,
        maximum_cost_usd_per_attempt_exact=cost,
    )


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (ModelReviewSurfaceKind.ENTRY_POINT, ModelSurfaceRiskTier.T1),
        (ModelReviewSurfaceKind.CALL, ModelSurfaceRiskTier.T1),
        (ModelReviewSurfaceKind.INTERNAL_FUNCTION, ModelSurfaceRiskTier.T2),
        (ModelReviewSurfaceKind.STATE, ModelSurfaceRiskTier.T2),
        (ModelReviewSurfaceKind.CONTRACT, ModelSurfaceRiskTier.T3),
        (ModelReviewSurfaceKind.SOURCE_FILE, ModelSurfaceRiskTier.T3),
    ],
)
def test_noncritical_tier_mapping_is_exact(
    kind: ModelReviewSurfaceKind,
    expected: ModelSurfaceRiskTier,
) -> None:
    assert classify_model_surface_risk(_request(1, kind=kind)) is expected


@pytest.mark.parametrize("kind", list(ModelReviewSurfaceKind))
def test_every_current_critical_surface_maps_to_t0(kind: ModelReviewSurfaceKind) -> None:
    assert classify_model_surface_risk(_request(1, kind=kind, critical=True)) is (
        ModelSurfaceRiskTier.T0
    )


@pytest.mark.parametrize(
    "kind",
    [
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION,
        ModelReviewSurfaceKind.ASSET_FUNCTION,
        ModelReviewSurfaceKind.INVARIANT,
        ModelReviewSurfaceKind.TEMPLATE,
    ],
)
def test_unsupported_noncritical_security_surfaces_cannot_be_downgraded(
    kind: ModelReviewSurfaceKind,
) -> None:
    with pytest.raises(ValueError, match="cannot be silently downgraded"):
        classify_model_surface_risk(_request(1, kind=kind))


def test_policy_derives_all_completion_blocking_lineage_floors() -> None:
    policy = build_model_surface_coverage_policy(3)

    assert {
        requirement.tier: requirement.minimum_root_lineages for requirement in policy.requirements
    } == {
        ModelSurfaceRiskTier.T0: 3,
        ModelSurfaceRiskTier.T1: 2,
        ModelSurfaceRiskTier.T2: 1,
        ModelSurfaceRiskTier.T3: 1,
    }
    assert all(requirement.completion_blocking for requirement in policy.requirements)
    assert not policy.authorizes_dispatch
    assert not policy.grants_review_credit
    assert not policy.grants_completion_credit


def test_plan_binds_current_critical_request_to_t0_requirement() -> None:
    request = _request(1, kind=ModelReviewSurfaceKind.CONTRACT, critical=True)
    plan = build_model_surface_coverage_plan(
        [request],
        [_binding(1), _binding(2), _binding(3)],
        surface_scope_by_id=_scopes([request]),
        minimum_t0_root_lineages=3,
    )

    assert plan.feasible
    assert plan.requirements[0].risk_tier is ModelSurfaceRiskTier.T0
    assert plan.requirements[0].minimum_root_lineages == 3
    assert plan.lineage_gap_assignment_count == 3


def test_root_aliases_do_not_satisfy_independent_lineage_requirement() -> None:
    request = _request(1, critical=True)
    bindings = [
        _binding(1, root_index=1),
        _binding(2, root_index=1),
        _binding(3, root_index=2),
    ]

    plan = build_model_surface_coverage_plan(
        [request],
        bindings,
        surface_scope_by_id=_scopes([request]),
        minimum_t0_root_lineages=3,
    )

    gap_assignments = [
        assignment
        for assignment in plan.assignments
        if assignment.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
    ]
    assert len(gap_assignments) == 2
    assert len({assignment.root_lineage for assignment in gap_assignments}) == 2
    assert not plan.feasible
    assert plan.deficits[0].missing_root_lineages == 1


def test_existing_credit_is_subtracted_before_minimal_gap_fill() -> None:
    request = _request(1, critical=True)
    plan = build_model_surface_coverage_plan(
        [request],
        [_binding(1), _binding(2), _binding(3)],
        surface_scope_by_id=_scopes([request]),
        credited_root_lineages_by_surface={request.surface_id: (_root(1), _root(2))},
        minimum_t0_root_lineages=3,
    )

    assert plan.feasible
    assert plan.lineage_gap_assignment_count == 1
    assert plan.assignments[0].root_lineage == _root(3)


def test_elevated_gap_uses_false_negative_hunter_before_other_reviewers() -> None:
    request = _request(1, critical=True, elevated=True)
    hunter = _binding(9, role="specialist:false_negative_hunter")
    ordinary = _binding(1, role="specialist:aaa")

    plan = build_model_surface_coverage_plan(
        [request],
        [ordinary, hunter],
        surface_scope_by_id=_scopes([request]),
        minimum_t0_root_lineages=1,
    )

    assert len(plan.assignments) == 1
    assert plan.assignments[0].review_role == hunter.review_role


def test_planning_is_identical_under_request_and_binding_permutation() -> None:
    requests = [
        _request(1, kind=ModelReviewSurfaceKind.ENTRY_POINT),
        _request(2, kind=ModelReviewSurfaceKind.STATE),
        _request(3, kind=ModelReviewSurfaceKind.CONTRACT),
    ]
    bindings = [_binding(1), _binding(2), _binding(3)]
    scopes = {
        requests[0].surface_id: "scope-a",
        requests[1].surface_id: "scope-b",
        requests[2].surface_id: "scope-a",
    }

    first = build_model_surface_coverage_plan(
        requests,
        bindings,
        surface_scope_by_id=scopes,
        minimum_t0_root_lineages=3,
    )
    second = build_model_surface_coverage_plan(
        reversed(requests),
        reversed(bindings),
        surface_scope_by_id=dict(reversed(tuple(scopes.items()))),
        minimum_t0_root_lineages=3,
    )

    assert second == first
    assert second.plan_sha256 == first.plan_sha256


def test_surface_scope_mapping_is_complete_exact_and_single_scope_per_task() -> None:
    requests = [_request(1), _request(2)]
    binding = _binding(1)

    with pytest.raises(ValueError, match="exactly cover"):
        build_model_surface_coverage_plan(
            requests,
            [binding],
            surface_scope_by_id={requests[0].surface_id: "scope-a"},
        )
    with pytest.raises(ValueError, match="exactly cover"):
        build_model_surface_coverage_plan(
            requests,
            [binding],
            surface_scope_by_id={
                **_scopes(requests),
                _request(99).surface_id: "scope-extra",
            },
        )

    plan = build_model_surface_coverage_plan(
        requests,
        [binding],
        surface_scope_by_id={
            requests[0].surface_id: "scope-a",
            requests[1].surface_id: "scope-b",
        },
    )
    assert {task.scope_id for task in plan.tasks} == {"scope-a", "scope-b"}
    assert all(len(task.surface_ids) == 1 for task in plan.tasks)


@pytest.mark.parametrize("surface_count", [32, 33])
def test_task_chunks_are_exact_and_never_exceed_thirty_two(surface_count: int) -> None:
    requests = [_request(index) for index in range(surface_count)]
    plan = build_model_surface_coverage_plan(
        requests,
        [_binding(1)],
        surface_scope_by_id=_scopes(requests),
    )

    expected_sizes = [32] if surface_count == 32 else [32, 1]
    assert [len(task.surface_ids) for task in plan.tasks] == expected_sizes
    planned_ids = tuple(surface_id for task in plan.tasks for surface_id in task.surface_ids)
    assert planned_ids == tuple(sorted(request.surface_id for request in requests))
    assert all(len(task.surface_ids) <= MAX_SURFACES_PER_GAP_TASK for task in plan.tasks)


def test_scope_affinity_compacts_tasks_while_executing_all_mandatory_roles() -> None:
    requests = [_request(index, critical=True) for index in range(32)]
    roles = tuple(f"specialist:mission_{index:02d}" for index in range(24))
    bindings = tuple(_binding(index + 1, role=role) for index, role in enumerate(roles))
    scopes = {request.surface_id: f"scope-{index % 8}" for index, request in enumerate(requests)}

    plan = build_model_surface_coverage_plan(
        requests,
        bindings,
        surface_scope_by_id=scopes,
        mandatory_reviewer_roles=roles,
        minimum_t0_root_lineages=3,
    )

    assert plan.feasible
    assert plan.lineage_gap_assignment_count == 96
    assert plan.responsibility_seed_assignment_count == 0
    assert plan.task_count == 24
    assert {task.review_role for task in plan.tasks} == set(roles)
    assert all(len(task.surface_ids) == 4 for task in plan.tasks)


def test_scope_affinity_rotates_roots_at_the_exact_task_surface_cap() -> None:
    requests = [_request(index, critical=True) for index in range(96)]
    bindings = tuple(_binding(index + 1) for index in range(24))

    plan = build_model_surface_coverage_plan(
        requests,
        bindings,
        surface_scope_by_id=_scopes(requests),
        minimum_t0_root_lineages=3,
    )

    assignment_load = Counter(
        (assignment.scope_id, assignment.review_role) for assignment in plan.assignments
    )
    assert plan.lineage_gap_assignment_count == 288
    assert plan.responsibility_seed_assignment_count == 0
    assert plan.task_count == 9
    assert len({assignment.review_role for assignment in plan.assignments}) == 9
    assert max(assignment_load.values()) == MAX_SURFACES_PER_GAP_TASK


def test_missing_roots_are_reported_without_dispatch_authority() -> None:
    request = _request(1, critical=True)
    plan = build_model_surface_coverage_plan(
        [request],
        [_binding(1)],
        surface_scope_by_id=_scopes([request]),
        minimum_t0_root_lineages=3,
    )

    assert not plan.feasible
    assert not plan.lineage_requirements_satisfied
    assert plan.deficits[0].missing_root_lineages == 2
    assert not plan.authorizes_dispatch
    assert not plan.grants_review_credit
    assert not plan.grants_completion_credit


def test_twenty_four_mandatory_roles_receive_nonempty_work_without_alias_inflation() -> None:
    request = _request(1)
    roles = tuple(f"specialist:mission_{index:02d}" for index in range(24))
    bindings = tuple(
        _binding(index + 1, role=role, root_index=1) for index, role in enumerate(roles)
    )

    plan = build_model_surface_coverage_plan(
        [request],
        bindings,
        surface_scope_by_id=_scopes([request]),
        mandatory_reviewer_roles=roles,
    )

    assert plan.feasible
    assert plan.lineage_gap_assignment_count == 1
    assert plan.responsibility_seed_assignment_count == 23
    assert len(plan.tasks) == 24
    assert {task.review_role for task in plan.tasks} == set(roles)
    assert all(task.surface_ids == (request.surface_id,) for task in plan.tasks)
    lineage_gap_roots = {
        assignment.root_lineage
        for assignment in plan.assignments
        if assignment.counts_toward_lineage_requirement
    }
    assert lineage_gap_roots == {_root(1)}


def test_mandatory_roles_must_be_sorted_bound_and_have_bindings() -> None:
    request = _request(1)
    binding = _binding(1)

    with pytest.raises(ValueError, match="valid, unique, and sorted"):
        build_model_surface_coverage_plan(
            [request],
            [binding],
            surface_scope_by_id=_scopes([request]),
            mandatory_reviewer_roles=(binding.review_role, binding.review_role),
        )
    with pytest.raises(ValueError, match="lacks an exact reviewer binding"):
        build_model_surface_coverage_plan(
            [request],
            [binding],
            surface_scope_by_id=_scopes([request]),
            mandatory_reviewer_roles=("specialist:missing",),
        )
    with pytest.raises(ValueError, match="non-empty surface inventory"):
        build_model_surface_coverage_plan(
            [],
            [binding],
            surface_scope_by_id={},
            mandatory_reviewer_roles=(binding.review_role,),
        )


def test_plan_tamper_and_semantic_reseal_are_rejected() -> None:
    request = _request(1)
    roles = ("specialist:a", "specialist:b")
    bindings = (
        _binding(1, role=roles[0], root_index=1),
        _binding(2, role=roles[1], root_index=1),
    )
    plan = build_model_surface_coverage_plan(
        [request],
        bindings,
        surface_scope_by_id=_scopes([request]),
        mandatory_reviewer_roles=roles,
    )

    tampered = plan.model_dump(mode="python")
    tampered["feasible"] = False
    with pytest.raises(ValidationError, match=r"derived counts|canonical evidence"):
        ModelSurfaceCoveragePlan.model_validate(tampered)

    resealed = plan.model_dump(mode="python")
    resealed["mandatory_reviewer_roles"] = ()
    resealed["plan_sha256"] = _canonical_sha256(
        {key: value for key, value in resealed.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValidationError, match="deterministic minimal plan"):
        ModelSurfaceCoveragePlan.model_validate(resealed)


def test_preview_and_aggregate_preflight_pass_exact_equalities() -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    role = plan.tasks[0].review_role
    model = plan.tasks[0].requested_model

    preflight = build_model_surface_resource_preflight(
        plan,
        [preview],
        maximum_requests=2,
        maximum_input_tokens=200,
        maximum_output_tokens=100,
        maximum_cost_usd_exact="0.5",
        remaining_cost_usd_by_role={role: "0.5"},
        remaining_cost_usd_by_model={model: "0.5"},
    )

    assert preflight.feasible
    assert preflight.failure_codes == ()
    assert preflight.planned_maximum_request_count == 2
    assert preflight.planned_maximum_input_tokens == 200
    assert preflight.planned_maximum_output_tokens == 100
    assert preflight.planned_maximum_cost_usd_exact == "0.5"
    assert preflight.planned_costs_by_role[0].maximum_cost_usd_exact == "0.5"
    assert preflight.planned_costs_by_model[0].maximum_cost_usd_exact == "0.5"


@pytest.mark.parametrize(
    ("override", "failure"),
    [
        ({"maximum_requests": 1}, ModelSurfaceResourceFailureCode.REQUEST_CAP_EXCEEDED),
        (
            {"maximum_input_tokens": 199},
            ModelSurfaceResourceFailureCode.INPUT_TOKEN_CAP_EXCEEDED,
        ),
        (
            {"maximum_output_tokens": 99},
            ModelSurfaceResourceFailureCode.OUTPUT_TOKEN_CAP_EXCEEDED,
        ),
        ({"maximum_cost_usd_exact": "0.499"}, ModelSurfaceResourceFailureCode.USD_CAP_EXCEEDED),
    ],
)
def test_global_resource_one_over_is_rejected(
    override: dict[str, object],
    failure: ModelSurfaceResourceFailureCode,
) -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    arguments: dict[str, Any] = {
        "maximum_requests": 2,
        "maximum_input_tokens": 200,
        "maximum_output_tokens": 100,
        "maximum_cost_usd_exact": "0.5",
    }
    arguments.update(override)

    preflight = build_model_surface_resource_preflight(plan, [preview], **arguments)

    assert not preflight.feasible
    assert failure in preflight.failure_codes


@pytest.mark.parametrize(
    ("dimension", "failure"),
    [
        ("role", ModelSurfaceResourceFailureCode.ROLE_USD_CAP_EXCEEDED),
        ("model", ModelSurfaceResourceFailureCode.MODEL_USD_CAP_EXCEEDED),
    ],
)
def test_scoped_usd_one_over_is_rejected_with_exact_scope_evidence(
    dimension: str,
    failure: ModelSurfaceResourceFailureCode,
) -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    role_caps = {plan.tasks[0].review_role: "0.499"} if dimension == "role" else None
    model_caps = {plan.tasks[0].requested_model: "0.499"} if dimension == "model" else None

    preflight = build_model_surface_resource_preflight(
        plan,
        [preview],
        maximum_requests=2,
        maximum_input_tokens=200,
        maximum_output_tokens=100,
        maximum_cost_usd_exact="0.5",
        remaining_cost_usd_by_role=role_caps,
        remaining_cost_usd_by_model=model_caps,
    )

    assert not preflight.feasible
    assert failure in preflight.failure_codes
    assert len(preflight.scoped_failures) == 1
    assert preflight.scoped_failures[0].failure_code is failure
    assert preflight.scoped_failures[0].planned_maximum_cost_usd_exact == "0.5"
    assert preflight.scoped_failures[0].remaining_cost_cap_usd_exact == "0.499"


@pytest.mark.parametrize(
    ("dimension", "failure"),
    [
        ("role", ModelSurfaceResourceFailureCode.ROLE_USD_CAP_MISSING),
        ("model", ModelSurfaceResourceFailureCode.MODEL_USD_CAP_MISSING),
    ],
)
def test_nonempty_scoped_cap_map_fails_closed_for_unconfigured_planned_key(
    dimension: str,
    failure: ModelSurfaceResourceFailureCode,
) -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    role_caps = {"specialist:other": "1"} if dimension == "role" else None
    model_caps = {"vendor/other-security": "1"} if dimension == "model" else None

    preflight = build_model_surface_resource_preflight(
        plan,
        [preview],
        maximum_requests=2,
        maximum_input_tokens=200,
        maximum_output_tokens=100,
        maximum_cost_usd_exact="0.5",
        remaining_cost_usd_by_role=role_caps,
        remaining_cost_usd_by_model=model_caps,
    )

    assert not preflight.feasible
    assert failure in preflight.failure_codes
    assert preflight.scoped_failures[0].remaining_cost_cap_usd_exact is None


def test_resource_preflight_requires_one_exact_preview_per_task() -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    with pytest.raises(ValueError, match="every coverage task exactly once"):
        build_model_surface_resource_preflight(
            plan,
            [],
            maximum_requests=10,
            maximum_input_tokens=1_000,
            maximum_output_tokens=1_000,
            maximum_cost_usd_exact="10",
        )
    with pytest.raises(ValueError, match="duplicate coverage task"):
        build_model_surface_resource_preflight(
            plan,
            [preview, preview],
            maximum_requests=10,
            maximum_input_tokens=1_000,
            maximum_output_tokens=1_000,
            maximum_cost_usd_exact="10",
        )


def test_private_decimal_context_ignores_hostile_global_precision_and_traps() -> None:
    plan = _single_task_plan()
    with localcontext() as hostile:
        hostile.prec = 2
        hostile.traps[Inexact] = True
        preview = _preview(
            plan,
            attempts=3,
            cost="0.12345678901234567890123456789",
        )
        preflight = build_model_surface_resource_preflight(
            plan,
            [preview],
            maximum_requests=3,
            maximum_input_tokens=300,
            maximum_output_tokens=150,
            maximum_cost_usd_exact="0.37037036703703703670370370367",
        )

    assert preview.maximum_cost_usd_exact == "0.37037036703703703670370370367"
    assert preflight.feasible


@pytest.mark.parametrize("bad_cost", ["0.10", "1e-3", "+1", "-0", "NaN"])
def test_noncanonical_resource_decimal_text_is_rejected(bad_cost: str) -> None:
    plan = _single_task_plan()
    with pytest.raises(ValueError, match="canonical"):
        _preview(plan, cost=bad_cost)


class _LyingIterable[T]:
    def __init__(self, values: tuple[T, ...]) -> None:
        self._values = values

    def __len__(self) -> int:
        return 0

    def __iter__(self) -> Iterator[T]:
        return iter(self._values)


class _InfiniteRoles:
    def __iter__(self) -> Iterator[str]:
        while True:
            yield "specialist:loop"


def test_lie_about_iterable_length_cannot_hide_records() -> None:
    requests = (_request(1), _request(2))
    binding = _binding(1)

    plan = build_model_surface_coverage_plan(
        _LyingIterable(requests),
        _LyingIterable((binding,)),
        surface_scope_by_id=_scopes(list(requests)),
    )

    assert plan.surface_count == 2
    assert plan.task_count == 1


def test_infinite_mandatory_role_iterable_is_bounded_before_materialization() -> None:
    request = _request(1)
    binding = _binding(1)

    with pytest.raises(
        ValueError,
        match=f"bounded maximum of {MAX_COVERAGE_REVIEWERS}",
    ):
        build_model_surface_coverage_plan(
            [request],
            [binding],
            surface_scope_by_id=_scopes([request]),
            mandatory_reviewer_roles=_InfiniteRoles(),
        )


def test_all_nested_durable_artifacts_keep_authority_and_credit_false() -> None:
    plan = _single_task_plan()
    preview = _preview(plan)
    preflight = build_model_surface_resource_preflight(
        plan,
        [preview],
        maximum_requests=2,
        maximum_input_tokens=200,
        maximum_output_tokens=100,
        maximum_cost_usd_exact="0.5",
    )

    def walk(value: object) -> Iterator[BaseModel]:
        if isinstance(value, BaseModel):
            yield value
            for field_name in type(value).model_fields:
                yield from walk(getattr(value, field_name))
        elif isinstance(value, tuple | list):
            for item in value:
                yield from walk(item)

    artifacts = tuple(walk(preflight))
    assert artifacts
    for artifact in artifacts:
        assert getattr(artifact, "authorizes_dispatch", False) is False
        assert getattr(artifact, "grants_review_credit", False) is False
        assert getattr(artifact, "grants_completion_credit", False) is False
