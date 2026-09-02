from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError

from mmaudit.models.retrieval import (
    SolidityRetrievalEntity,
    SolidityRetrievalEntityKind,
    SolidityRetrievalExchange,
    SolidityRetrievalOperation,
    SolidityRetrievalRecord,
    SolidityRetrievalRequest,
    SolidityRetrievalResult,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalStatus,
    SolidityRetrievalTranscript,
)
from mmaudit.orchestration.retrieval_budget import (
    SolidityRetrievalRoleBudgetPlan,
    build_solidity_retrieval_role_budget_plan,
)


def _task_id(index: int) -> str:
    return f"scheduler-task-{index:064x}"


def _consumed_transcript(
    policy: SolidityRetrievalRolePolicy,
    *,
    identity: int,
) -> SolidityRetrievalTranscript:
    exchanges: list[SolidityRetrievalExchange] = []
    previous_sha256: str | None = None
    for request_index in range(policy.maximum_requests):
        subject_id = f"entity-{identity}-{request_index}"
        content = f"function function{identity}_{request_index}() internal {{}}\n"
        request = SolidityRetrievalRequest.build(
            operation=SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
            subject_id=subject_id,
        )
        entity = SolidityRetrievalEntity(
            subject_id=subject_id,
            kind=SolidityRetrievalEntityKind.FUNCTION,
            name=f"function{identity}_{request_index}",
            contract_name=None,
            path="src/Safe.sol",
            start_line=request_index + 1,
            end_line=request_index + 1,
            source_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            visibility="internal",
            mutability="nonpayable",
            payable=False,
        )
        result = SolidityRetrievalResult.build(
            request=request,
            status=SolidityRetrievalStatus.COMPLETE,
            records=(
                SolidityRetrievalRecord(
                    entity=entity,
                    content=content,
                ),
            ),
        )
        assert result.result_utf8_bytes <= policy.maximum_result_utf8_bytes
        exchange = SolidityRetrievalExchange.build(
            sequence=request_index + 1,
            previous_exchange_sha256=previous_sha256,
            request=request,
            result=result,
        )
        exchanges.append(exchange)
        previous_sha256 = exchange.exchange_sha256
    return SolidityRetrievalTranscript.build(
        role=policy.role,
        policy_sha256=policy.policy_sha256,
        corpus_sha256="f" * 64,
        exchanges=exchanges,
        accepted_request_count=policy.maximum_requests,
    )


def test_static_role_plan_is_order_independent_and_reserves_one_run_ceiling() -> None:
    task_ids = tuple(_task_id(index) for index in range(1, 7))

    plan = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=tuple(reversed(task_ids)),
    )
    replayed = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=task_ids,
    )

    assert plan == replayed
    assert tuple(allocation.primary_task_id for allocation in plan.allocations) == task_ids
    assert [allocation.policy.maximum_requests for allocation in plan.allocations] == [
        1,
        1,
        1,
        1,
        0,
        0,
    ]
    assert [
        allocation.policy.maximum_total_result_utf8_bytes for allocation in plan.allocations
    ] == [4_096, 4_096, 4_096, 4_096, 0, 0]
    assert [allocation.policy.maximum_total_result_tokens for allocation in plan.allocations] == [
        1_366,
        1_366,
        1_365,
        1_365,
        0,
        0,
    ]
    assert plan.allocated_maximum_requests == plan.ceiling.maximum_requests == 4
    assert (
        plan.allocated_maximum_total_result_utf8_bytes
        == plan.ceiling.maximum_total_result_utf8_bytes
        == 16_384
    )
    assert (
        plan.allocated_maximum_total_result_tokens
        == plan.ceiling.maximum_total_result_tokens
        == 5_462
    )
    assert plan.plan_sha256 == replayed.plan_sha256


def test_static_allocations_bound_concurrent_transcript_consumption() -> None:
    task_ids = tuple(_task_id(index) for index in range(1, 9))
    plan = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=task_ids,
    )

    with ThreadPoolExecutor(max_workers=len(task_ids)) as pool:
        transcripts = tuple(
            pool.map(
                lambda item: _consumed_transcript(
                    plan.policy_for_task(item[1]),
                    identity=item[0],
                ),
                enumerate(reversed(task_ids), start=1),
            )
        )

    assert sum(item.accepted_request_count for item in transcripts) == 4
    assert (
        sum(item.total_result_utf8_bytes for item in transcripts)
        <= plan.allocated_maximum_total_result_utf8_bytes
    )
    assert (
        sum(item.total_estimated_result_tokens for item in transcripts)
        <= plan.allocated_maximum_total_result_tokens
    )
    assert sum(item.single_shot_fallback_required for item in transcripts) == 4


def test_narrow_ceiling_is_balanced_and_surplus_tasks_receive_exact_zero_policies() -> None:
    ceiling = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=2,
        maximum_result_utf8_bytes=100,
        maximum_total_result_utf8_bytes=100,
        maximum_total_result_tokens=34,
    )
    task_ids = (_task_id(3), _task_id(1), _task_id(2))

    plan = SolidityRetrievalRoleBudgetPlan.build(
        role="source_audit",
        primary_task_ids=task_ids,
        ceiling=ceiling,
    )

    assert [allocation.primary_task_id for allocation in plan.allocations] == [
        _task_id(1),
        _task_id(2),
        _task_id(3),
    ]
    assert [allocation.policy.maximum_requests for allocation in plan.allocations] == [1, 1, 0]
    assert [
        allocation.policy.maximum_total_result_utf8_bytes for allocation in plan.allocations
    ] == [50, 50, 0]
    assert [allocation.policy.maximum_total_result_tokens for allocation in plan.allocations] == [
        17,
        17,
        0,
    ]
    surplus = plan.policy_for_task(_task_id(3))
    assert (
        surplus.maximum_requests,
        surplus.maximum_total_result_utf8_bytes,
        surplus.maximum_total_result_tokens,
    ) == (0, 0, 0)


def test_empty_or_zero_role_plan_is_valid_without_budget_inflation() -> None:
    empty = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=(),
    )
    zero_ceiling = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=0,
        maximum_total_result_utf8_bytes=0,
        maximum_total_result_tokens=0,
    )
    zero = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=(_task_id(1), _task_id(2)),
        ceiling=zero_ceiling,
    )

    assert empty.allocations == ()
    assert (
        empty.allocated_maximum_requests,
        empty.allocated_maximum_total_result_utf8_bytes,
        empty.allocated_maximum_total_result_tokens,
    ) == (0, 0, 0)
    assert all(allocation.policy.maximum_requests == 0 for allocation in zero.allocations)
    assert zero.allocated_maximum_requests == 0
    assert zero.allocated_maximum_total_result_utf8_bytes == 0
    assert zero.allocated_maximum_total_result_tokens == 0


def test_role_plan_rejects_identity_role_and_hash_tampering() -> None:
    task_id = _task_id(1)
    plan = build_solidity_retrieval_role_budget_plan(
        role="source_audit",
        primary_task_ids=(task_id,),
    )

    with pytest.raises(ValueError, match="must be unique"):
        build_solidity_retrieval_role_budget_plan(
            role="source_audit",
            primary_task_ids=(task_id, task_id),
        )
    with pytest.raises(ValueError, match="canonical scheduler task ID"):
        build_solidity_retrieval_role_budget_plan(
            role="source_audit",
            primary_task_ids=("source_audit-shard-1",),
        )
    with pytest.raises(ValueError, match="differs from its requested role"):
        build_solidity_retrieval_role_budget_plan(
            role="source_audit",
            primary_task_ids=(task_id,),
            ceiling=SolidityRetrievalRolePolicy.build(role="business_logic"),
        )
    with pytest.raises(KeyError, match="does not contain"):
        plan.policy_for_task(_task_id(2))

    tampered = plan.model_dump(mode="python")
    tampered["allocated_maximum_requests"] = 3
    with pytest.raises(ValidationError, match="totals are inconsistent"):
        SolidityRetrievalRoleBudgetPlan.model_validate(tampered)
