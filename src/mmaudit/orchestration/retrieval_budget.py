"""Deterministic run-level allocation for bounded Solidity retrieval."""

from __future__ import annotations

from collections.abc import Sequence

from mmaudit.models.retrieval import (
    SolidityRetrievalRoleBudgetAllocation,
    SolidityRetrievalRoleBudgetPlan,
    SolidityRetrievalRolePolicy,
)


def build_solidity_retrieval_role_budget_plan(
    *,
    role: str,
    primary_task_ids: Sequence[str],
    ceiling: SolidityRetrievalRolePolicy | None = None,
) -> SolidityRetrievalRoleBudgetPlan:
    """Pre-allocate one role ceiling without runtime scheduling-order dependence."""

    return SolidityRetrievalRoleBudgetPlan.build(
        role=role,
        primary_task_ids=primary_task_ids,
        ceiling=ceiling,
    )


__all__ = [
    "SolidityRetrievalRoleBudgetAllocation",
    "SolidityRetrievalRoleBudgetPlan",
    "build_solidity_retrieval_role_budget_plan",
]
