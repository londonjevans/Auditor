"""Deterministic boundary tests for non-dispatching truncation recovery plans."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from decimal import Inexact, localcontext
from itertools import repeat
from typing import Any, Protocol

import pytest
from pydantic import BaseModel, ValidationError

from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS,
    TRUNCATION_RECOVERY_MAX_DEPTH,
    TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_USD_EXACT,
    TruncationRecoveryChannel,
    TruncationRecoveryChannelBinding,
    TruncationRecoveryChannelState,
    TruncationRecoveryChildPlan,
    TruncationRecoveryDisposition,
    TruncationRecoveryParentBinding,
    TruncationRecoveryPlan,
    TruncationRecoveryPolicy,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)


class _NonAuthorizing(Protocol):
    @property
    def provider_dispatch_authorized(self) -> bool: ...

    @property
    def review_credit_authorized(self) -> bool: ...

    @property
    def coverage_credit_authorized(self) -> bool: ...

    @property
    def completion_authorized(self) -> bool: ...

    @property
    def release_authorized(self) -> bool: ...


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _surface(index: int) -> str:
    return "model-surface:" + _digest(f"surface:{index}")


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(type(value).__qualname__)


def _seal(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _binding(
    channel: TruncationRecoveryChannel,
    state: TruncationRecoveryChannelState,
    *,
    count: int,
) -> TruncationRecoveryChannelBinding:
    return TruncationRecoveryChannelBinding.build(
        channel=channel,
        state=state,
        retained_record_count=count,
        retained_inventory_sha256=_digest(f"{channel}:{state}:{count}"),
    )


def _parent(
    *,
    requested_count: int = 5,
    retained_indices: tuple[int, ...] = (0, 1),
    coverage_state: TruncationRecoveryChannelState = (TruncationRecoveryChannelState.INCOMPLETE),
    findings_state: TruncationRecoveryChannelState = (TruncationRecoveryChannelState.COMPLETE),
    summary_state: TruncationRecoveryChannelState = (TruncationRecoveryChannelState.COMPLETE),
    current_depth: int = 0,
    parent_path: str = "",
    reverse_inputs: bool = False,
) -> TruncationRecoveryParentBinding:
    requested = tuple(_surface(index) for index in range(requested_count))
    retained = tuple(requested[index] for index in retained_indices)
    channels: tuple[TruncationRecoveryChannelBinding, ...] = (
        _binding(
            TruncationRecoveryChannel.COVERAGE,
            coverage_state,
            count=len(retained),
        ),
        _binding(TruncationRecoveryChannel.FINDINGS, findings_state, count=0),
        _binding(
            TruncationRecoveryChannel.SUMMARY,
            summary_state,
            count=(1 if summary_state is TruncationRecoveryChannelState.COMPLETE else 0),
        ),
    )
    if reverse_inputs:
        requested = tuple(reversed(requested))
        retained = tuple(reversed(retained))
        channels = tuple(reversed(channels))
    parent_task_prefix = "scheduler-task-" if current_depth == 0 else "scheduler-recovery-task-"
    parent_request_prefix = (
        "scheduler-request-" if current_depth == 0 else "scheduler-recovery-request-"
    )
    return TruncationRecoveryParentBinding.build(
        campaign_id="scheduler-campaign-" + _digest("campaign"),
        pass_plan_id="scheduler-plan-" + _digest("pass-plan"),
        parent_task_id=parent_task_prefix + _digest(f"parent-task:{current_depth}"),
        parent_logical_request_id=(
            parent_request_prefix + _digest(f"parent-request:{current_depth}")
        ),
        parent_task_plan_sha256=_digest("parent-task-plan"),
        parent_activation_sha256=_digest("parent-activation"),
        provider_attempt_evidence_sha256=_digest("parent-provider-attempt"),
        truncation_projection_sha256=_digest("parser-truncation-projection"),
        requested_surface_manifest_sha256=_digest("requested-surface-manifest"),
        requested_surface_ids=requested,
        retained_surface_ids=retained,
        channel_bindings=channels,
        current_depth=current_depth,
        parent_path=parent_path,
    )


def _resources(
    *,
    campaign_cap: str = "250",
    before_cost: str = "0",
    parent_cost: str = "0.4",
    child_cost: str = "0.1",
    requests: int = 0,
    attempts_before: int = 0,
    parent_attempts: int = 1,
    child_attempts: int = 1,
    tokens_before: int = 0,
    parent_tokens: int = 100,
    child_tokens: int = 1_000,
) -> TruncationRecoveryResourceBudget:
    return TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=campaign_cap,
        accounted_usd_before_parent_exact=before_cost,
        parent_accounted_cost_usd_exact=parent_cost,
        child_reserved_usd_exact=child_cost,
        recovery_requests_consumed=requests,
        provider_attempts_before_parent=attempts_before,
        parent_provider_attempts=parent_attempts,
        child_provider_attempts=child_attempts,
        completion_tokens_before_parent=tokens_before,
        parent_completion_tokens=parent_tokens,
        child_completion_tokens=child_tokens,
    )


def _recursive_parent_from_child(
    child: TruncationRecoveryChildPlan,
) -> TruncationRecoveryParentBinding:
    channels = (
        _binding(
            TruncationRecoveryChannel.COVERAGE,
            TruncationRecoveryChannelState.INCOMPLETE,
            count=0,
        ),
        _binding(
            TruncationRecoveryChannel.FINDINGS,
            TruncationRecoveryChannelState.COMPLETE,
            count=0,
        ),
        _binding(
            TruncationRecoveryChannel.SUMMARY,
            TruncationRecoveryChannelState.COMPLETE,
            count=1,
        ),
    )
    return TruncationRecoveryParentBinding.build(
        campaign_id=child.campaign_id,
        pass_plan_id=child.pass_plan_id,
        parent_task_id=child.child_task_id,
        parent_logical_request_id=child.child_logical_request_id,
        parent_task_plan_sha256=child.child_plan_sha256,
        parent_activation_sha256=_digest(f"activation:{child.child_task_id}"),
        provider_attempt_evidence_sha256=_digest(f"attempt:{child.child_task_id}"),
        truncation_projection_sha256=_digest(f"projection:{child.child_task_id}"),
        requested_surface_manifest_sha256=_digest(f"manifest:{child.child_task_id}"),
        requested_surface_ids=child.surface_ids,
        retained_surface_ids=(),
        channel_bindings=channels,
        current_depth=child.depth,
        parent_path=child.path,
    )


def _assert_non_authorizing(model: _NonAuthorizing) -> None:
    assert model.provider_dispatch_authorized is False
    assert model.review_credit_authorized is False
    assert model.coverage_credit_authorized is False
    assert model.completion_authorized is False
    assert model.release_authorized is False


def test_binary_recovery_is_deterministic_strict_and_conservative() -> None:
    parent = _parent()
    reversed_parent = _parent(reverse_inputs=True)

    plan = plan_truncation_recovery(parent=parent, resources=_resources())
    replay = plan_truncation_recovery(parent=reversed_parent, resources=_resources())

    assert parent == reversed_parent
    assert plan == replay
    assert plan.disposition is TruncationRecoveryDisposition.PLANNED
    assert plan.planned_channels == (TruncationRecoveryChannel.COVERAGE,)
    assert len(plan.children) == 2
    assert tuple(len(child.surface_ids) for child in plan.children) == (2, 1)
    assert tuple(child.path for child in plan.children) == ("0", "1")
    assert all(
        0 < len(child.surface_ids) < len(parent.unfinished_surface_ids) for child in plan.children
    )
    assert (
        tuple(surface for child in plan.children for surface in child.surface_ids)
        == parent.unfinished_surface_ids
    )
    assert plan.covered_unfinished_surface_ids == parent.unfinished_surface_ids
    assert len(plan.child_task_ids) == len(set(plan.child_task_ids))
    assert len(plan.child_logical_request_ids) == len(set(plan.child_logical_request_ids))
    assert len(plan.child_plan_sha256s) == len(set(plan.child_plan_sha256s))


@pytest.mark.parametrize(
    "coverage_state",
    [
        TruncationRecoveryChannelState.INCOMPLETE,
        TruncationRecoveryChannelState.INVALID,
    ],
)
def test_later_invalid_channels_do_not_erase_recoverable_coverage(
    coverage_state: TruncationRecoveryChannelState,
) -> None:
    parent = _parent(
        coverage_state=coverage_state,
        findings_state=TruncationRecoveryChannelState.INVALID,
        summary_state=TruncationRecoveryChannelState.INVALID,
    )

    plan = plan_truncation_recovery(parent=parent, resources=_resources())

    assert plan.disposition is TruncationRecoveryDisposition.PLANNED
    assert plan.planned_channels == (TruncationRecoveryChannel.COVERAGE,)
    assert plan.irreducible_channels == (TruncationRecoveryChannel.FINDINGS,)
    assert plan.non_authorizing_incomplete_channels == (TruncationRecoveryChannel.SUMMARY,)
    assert all(child.channel is TruncationRecoveryChannel.COVERAGE for child in plan.children)


def test_singleton_coverage_is_irreducible_not_an_identical_retry() -> None:
    parent = _parent(
        requested_count=2,
        retained_indices=(0,),
        summary_state=TruncationRecoveryChannelState.INCOMPLETE,
    )

    plan = plan_truncation_recovery(parent=parent, resources=_resources())

    assert len(parent.unfinished_surface_ids) == 1
    assert plan.disposition is TruncationRecoveryDisposition.IRREDUCIBLE_WORK
    assert plan.required_child_request_count == 0
    assert plan.children == ()
    assert plan.irreducible_channels == (TruncationRecoveryChannel.COVERAGE,)
    assert plan.non_authorizing_incomplete_channels == (TruncationRecoveryChannel.SUMMARY,)


def test_findings_without_exact_shard_inventory_are_irreducible() -> None:
    parent = _parent(
        requested_count=2,
        retained_indices=(0, 1),
        coverage_state=TruncationRecoveryChannelState.COMPLETE,
        findings_state=TruncationRecoveryChannelState.INVALID,
    )

    plan = plan_truncation_recovery(parent=parent, resources=_resources())

    assert plan.disposition is TruncationRecoveryDisposition.IRREDUCIBLE_WORK
    assert plan.children == ()
    assert plan.irreducible_channels == (TruncationRecoveryChannel.FINDINGS,)


def test_incomplete_summary_is_non_authorizing_and_requires_no_retry() -> None:
    parent = _parent(
        requested_count=2,
        retained_indices=(0, 1),
        coverage_state=TruncationRecoveryChannelState.COMPLETE,
        summary_state=TruncationRecoveryChannelState.INVALID,
    )

    plan = plan_truncation_recovery(parent=parent, resources=_resources())

    assert plan.disposition is TruncationRecoveryDisposition.NO_REMAINING_WORK
    assert plan.children == ()
    assert plan.non_authorizing_incomplete_channels == (TruncationRecoveryChannel.SUMMARY,)


def test_depth_boundary_allows_final_strict_shard_then_fails_closed() -> None:
    final_parent = _parent(
        retained_indices=(),
        current_depth=TRUNCATION_RECOVERY_MAX_DEPTH - 1,
        parent_path="010",
    )
    exhausted_parent = _parent(
        retained_indices=(),
        current_depth=TRUNCATION_RECOVERY_MAX_DEPTH,
        parent_path="0101",
    )

    final_plan = plan_truncation_recovery(parent=final_parent, resources=_resources())
    exhausted = plan_truncation_recovery(
        parent=exhausted_parent,
        resources=_resources(),
    )

    assert final_plan.disposition is TruncationRecoveryDisposition.PLANNED
    assert tuple(child.depth for child in final_plan.children) == (4, 4)
    assert tuple(child.path for child in final_plan.children) == ("0100", "0101")
    assert exhausted.disposition is TruncationRecoveryDisposition.DEPTH_EXHAUSTED
    assert exhausted.required_child_request_count == 2
    assert exhausted.children == ()
    assert exhausted.blocked_channels == (TruncationRecoveryChannel.COVERAGE,)


def test_recovery_child_identity_can_bind_the_exact_next_depth_parent() -> None:
    root_plan = plan_truncation_recovery(
        parent=_parent(requested_count=8, retained_indices=()),
        resources=_resources(),
    )
    depth_one_parent = _recursive_parent_from_child(root_plan.children[0])
    depth_one_plan = plan_truncation_recovery(
        parent=depth_one_parent,
        resources=_resources(requests=2),
    )
    depth_two_parent = _recursive_parent_from_child(depth_one_plan.children[0])

    assert depth_one_parent.current_depth == 1
    assert depth_one_parent.parent_task_id == root_plan.children[0].child_task_id
    assert depth_one_parent.parent_path == root_plan.children[0].path
    assert depth_one_plan.children[0].depth == 2
    assert depth_two_parent.current_depth == 2
    assert depth_two_parent.parent_task_id == depth_one_plan.children[0].child_task_id
    assert depth_two_parent.parent_logical_request_id == (
        depth_one_plan.children[0].child_logical_request_id
    )
    assert depth_two_parent.parent_path == depth_one_plan.children[0].path


@pytest.mark.parametrize(
    ("resources", "expected"),
    [
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                requests=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS - 2,
            ),
            TruncationRecoveryDisposition.PLANNED,
        ),
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                requests=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS - 1,
            ),
            TruncationRecoveryDisposition.REQUEST_EXHAUSTED,
        ),
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                attempts_before=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS - 3,
            ),
            TruncationRecoveryDisposition.PLANNED,
        ),
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                attempts_before=TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS - 2,
            ),
            TruncationRecoveryDisposition.PROVIDER_ATTEMPT_EXHAUSTED,
        ),
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                tokens_before=TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS - 102,
                parent_tokens=100,
                child_tokens=1,
            ),
            TruncationRecoveryDisposition.PLANNED,
        ),
        (
            _resources(
                parent_cost="0",
                child_cost="0",
                tokens_before=TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS - 101,
                parent_tokens=100,
                child_tokens=1,
            ),
            TruncationRecoveryDisposition.TOKEN_EXHAUSTED,
        ),
    ],
)
def test_request_attempt_and_token_boundaries_are_inclusive(
    resources: TruncationRecoveryResourceBudget,
    expected: TruncationRecoveryDisposition,
) -> None:
    plan = plan_truncation_recovery(parent=_parent(), resources=resources)

    assert plan.disposition is expected


def test_configured_250_cap_is_valid_but_planned_total_must_be_strictly_lower() -> None:
    quantum = "0." + ("0" * 35) + "1"
    just_below_after_children = "249." + ("9" * 33) + "997"
    at_cap_after_children = "249." + ("9" * 33) + "998"
    below = _resources(
        before_cost=just_below_after_children,
        parent_cost="0",
        child_cost=quantum,
        parent_tokens=0,
    )
    at_cap = _resources(
        before_cost=at_cap_after_children,
        parent_cost="0",
        child_cost=quantum,
        parent_tokens=0,
    )

    below_plan = plan_truncation_recovery(parent=_parent(), resources=below)
    exhausted = plan_truncation_recovery(parent=_parent(), resources=at_cap)

    assert TRUNCATION_RECOVERY_MAX_USD_EXACT == "250"
    assert below.campaign_cap_usd_exact == "250"
    assert below_plan.total_cost_usd_exact_if_planned == "249." + ("9" * 36)
    assert below_plan.disposition is TruncationRecoveryDisposition.PLANNED
    assert exhausted.total_cost_usd_exact_if_planned == "250"
    assert exhausted.disposition is TruncationRecoveryDisposition.BUDGET_EXHAUSTED
    assert exhausted.children == ()


def test_reconciled_parent_overrun_is_preserved_as_budget_exhaustion() -> None:
    resources = _resources(
        before_cost="249",
        parent_cost="2",
        child_cost="0.1",
    )

    plan = plan_truncation_recovery(parent=_parent(), resources=resources)

    assert plan.disposition is TruncationRecoveryDisposition.BUDGET_EXHAUSTED
    assert plan.total_cost_usd_exact_if_planned == "251.2"
    assert plan.children == ()
    assert plan.parent_cost_refunded is False


def test_private_decimal_context_is_independent_of_hostile_ambient_context() -> None:
    parent = _parent()
    resources = _resources(
        before_cost="249.999999999999999997",
        parent_cost="0",
        child_cost="0.000000000000000001",
        parent_tokens=0,
    )
    baseline = plan_truncation_recovery(parent=parent, resources=resources)

    with localcontext() as ambient:
        ambient.prec = 1
        ambient.traps[Inexact] = True
        hostile = plan_truncation_recovery(parent=parent, resources=resources)

    assert hostile == baseline
    assert hostile.plan_sha256 == baseline.plan_sha256


def test_exhausted_counter_totals_remain_exactly_representable() -> None:
    resources = _resources(
        parent_cost="0",
        child_cost="0",
        requests=1_000_000_000,
        attempts_before=1_000_000_000,
        parent_attempts=1_000_000_000,
        child_attempts=6,
        tokens_before=1_000_000_000,
        parent_tokens=1_000_000_000,
        child_tokens=65_536,
    )

    plan = plan_truncation_recovery(parent=_parent(), resources=resources)

    assert plan.disposition is TruncationRecoveryDisposition.REQUEST_EXHAUSTED
    assert plan.total_recovery_requests_if_planned == 1_000_000_002
    assert plan.total_provider_attempts_if_planned == 2_000_000_012
    assert plan.total_completion_tokens_if_planned == 2_000_131_072
    assert plan.children == ()


def test_parent_attempt_and_cost_are_conserved_without_refund_or_credit() -> None:
    parent = _parent()
    resources = _resources(
        before_cost="1",
        parent_cost="2",
        child_cost="0.5",
        attempts_before=3,
        parent_attempts=2,
    )

    plan = plan_truncation_recovery(parent=parent, resources=resources)

    assert plan.total_cost_usd_exact_if_planned == "4"
    assert plan.total_provider_attempts_if_planned == 7
    assert plan.parent_cost_refunded is False
    models: tuple[_NonAuthorizing, ...] = (
        plan,
        plan.policy,
        plan.parent,
        plan.resources,
        *plan.parent.channel_bindings,
        *plan.children,
    )
    for model in models:
        _assert_non_authorizing(model)


def test_tamper_cannot_be_hidden_by_resealing_outer_artifacts() -> None:
    parent = _parent()
    parent_payload = parent.model_dump(mode="python")
    parent_payload["retained_surface_ids"] = (_surface(999),)
    parent_payload["parent_binding_sha256"] = _seal(
        {key: value for key, value in parent_payload.items() if key != "parent_binding_sha256"}
    )
    with pytest.raises(ValidationError, match="unrequested surface"):
        TruncationRecoveryParentBinding.model_validate(parent_payload, strict=True)

    plan = plan_truncation_recovery(parent=parent, resources=_resources())
    plan_payload = plan.model_dump(mode="python")
    plan_payload["covered_unfinished_surface_ids"] = plan.covered_unfinished_surface_ids[:-1]
    plan_payload["plan_sha256"] = _seal(
        {key: value for key, value in plan_payload.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValidationError, match="covered-surface projection"):
        TruncationRecoveryPlan.model_validate(plan_payload, strict=True)


def test_compiled_policy_and_strict_shrink_cannot_be_relaxed() -> None:
    policy_payload = TruncationRecoveryPolicy.frozen().model_dump(mode="python")
    policy_payload["max_depth"] = TRUNCATION_RECOVERY_MAX_DEPTH + 1
    policy_payload["policy_sha256"] = _seal(
        {key: value for key, value in policy_payload.items() if key != "policy_sha256"}
    )
    with pytest.raises(ValidationError):
        TruncationRecoveryPolicy.model_validate(policy_payload, strict=True)

    parent = _parent()
    with pytest.raises(ValidationError, match="strictly shrink"):
        TruncationRecoveryChildPlan.build(
            parent=parent,
            policy=TruncationRecoveryPolicy.frozen(),
            resources=_resources(),
            ordinal=0,
            channel=TruncationRecoveryChannel.COVERAGE,
            surface_ids=parent.unfinished_surface_ids,
            path="0",
        )
    with pytest.raises(ValidationError, match="path differs"):
        TruncationRecoveryChildPlan.build(
            parent=parent,
            policy=TruncationRecoveryPolicy.frozen(),
            resources=_resources(),
            ordinal=1,
            channel=TruncationRecoveryChannel.COVERAGE,
            surface_ids=parent.unfinished_surface_ids[:1],
            path="0",
        )


def test_public_iterables_are_bounded_before_normalization() -> None:
    class LyingSurfaceIterable:
        def __init__(self) -> None:
            self.consumed = 0

        def __len__(self) -> int:
            return 0

        def __iter__(self) -> Iterator[str]:
            index = 0
            while True:
                self.consumed += 1
                yield _surface(index)
                index += 1

    endless_surfaces = LyingSurfaceIterable()

    with pytest.raises(ValueError, match="exceeds its item limit"):
        TruncationRecoveryParentBinding.build(
            campaign_id="scheduler-campaign-" + _digest("campaign"),
            pass_plan_id="scheduler-plan-" + _digest("pass-plan"),
            parent_task_id="scheduler-task-" + _digest("parent-task"),
            parent_logical_request_id=("scheduler-request-" + _digest("parent-request")),
            parent_task_plan_sha256=_digest("parent-task-plan"),
            parent_activation_sha256=_digest("parent-activation"),
            provider_attempt_evidence_sha256=_digest("parent-provider-attempt"),
            truncation_projection_sha256=_digest("parser-truncation-projection"),
            requested_surface_manifest_sha256=_digest("requested-surface-manifest"),
            requested_surface_ids=endless_surfaces,
            retained_surface_ids=(),
            channel_bindings=(),
        )
    assert endless_surfaces.consumed == 10_001

    valid_parent = _parent()
    with pytest.raises(ValueError, match="exceeds its item limit"):
        TruncationRecoveryParentBinding.build(
            campaign_id=valid_parent.campaign_id,
            pass_plan_id=valid_parent.pass_plan_id,
            parent_task_id=valid_parent.parent_task_id,
            parent_logical_request_id=valid_parent.parent_logical_request_id,
            parent_task_plan_sha256=valid_parent.parent_task_plan_sha256,
            parent_activation_sha256=valid_parent.parent_activation_sha256,
            provider_attempt_evidence_sha256=(valid_parent.provider_attempt_evidence_sha256),
            truncation_projection_sha256=valid_parent.truncation_projection_sha256,
            requested_surface_manifest_sha256=(valid_parent.requested_surface_manifest_sha256),
            requested_surface_ids=valid_parent.requested_surface_ids,
            retained_surface_ids=valid_parent.retained_surface_ids,
            channel_bindings=repeat(valid_parent.channel_bindings[0]),
        )


def test_duplicate_surface_inputs_are_rejected_instead_of_silently_deduplicated() -> None:
    surface = _surface(0)
    with pytest.raises(ValueError, match="duplicate surface ID"):
        TruncationRecoveryParentBinding.build(
            campaign_id="scheduler-campaign-" + _digest("campaign"),
            pass_plan_id="scheduler-plan-" + _digest("pass-plan"),
            parent_task_id="scheduler-task-" + _digest("parent-task"),
            parent_logical_request_id=("scheduler-request-" + _digest("parent-request")),
            parent_task_plan_sha256=_digest("parent-task-plan"),
            parent_activation_sha256=_digest("parent-activation"),
            provider_attempt_evidence_sha256=_digest("parent-provider-attempt"),
            truncation_projection_sha256=_digest("parser-truncation-projection"),
            requested_surface_manifest_sha256=_digest("requested-surface-manifest"),
            requested_surface_ids=(surface, surface),
            retained_surface_ids=(),
            channel_bindings=(),
        )
