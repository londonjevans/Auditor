"""Exact role admission for bounded automatic investigator recovery; no model calls."""

from __future__ import annotations

import pytest

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.orchestration import pipeline


@pytest.mark.parametrize("role", SPECIALIST_INVESTIGATOR_ROLES)
def test_nested_specialist_requires_its_original_configured_investigator_role(role: str) -> None:
    pipeline._require_exact_nested_recovery_role(
        request_role=f"specialist:{role}",
        configured_role=role,
        parent_request_role=f"specialist:{role}",
    )


@pytest.mark.parametrize(
    ("request_role", "configured_role"),
    (
        ("source_audit", "source_audit"),
        ("business_logic", "business_logic"),
        ("configuration", "configuration"),
        ("whole_protocol_review:0", "source_audit"),
    ),
)
def test_nested_generic_role_keeps_its_original_parent_binding(
    request_role: str, configured_role: str
) -> None:
    pipeline._require_exact_nested_recovery_role(
        request_role=request_role,
        configured_role=configured_role,
        parent_request_role=request_role,
    )


@pytest.mark.parametrize(
    ("request_role", "configured_role"),
    (
        ("specialist:unknown", "unknown"),
        ("specialist:invariant_review", "invariant_review"),
        ("specialist:falsifier", "falsifier"),
        ("specialist:report_quality", "report_quality"),
        ("specialist:test_generation:exploit_test", "test_generation"),
        (
            "specialist:exploit_reproduction_planner:exploit_test",
            "exploit_reproduction_planner",
        ),
    ),
)
def test_nested_candidate_review_rejects_unknown_and_auxiliary_roles(
    request_role: str, configured_role: str
) -> None:
    with pytest.raises(ValueError, match="original configured investigator role"):
        pipeline._require_exact_nested_recovery_role(
            request_role=request_role,
            configured_role=configured_role,
            parent_request_role=request_role,
        )


@pytest.mark.parametrize(
    ("request_role", "configured_role", "parent_request_role"),
    (
        ("specialist:access_control", "false_negative_hunter", "specialist:access_control"),
        ("specialist:false_negative_hunter", "false_negative_hunter", "specialist:access_control"),
        ("specialist:access_control", "source_audit", "specialist:access_control"),
        ("source_audit", "source_audit", "business_logic"),
    ),
)
def test_nested_recovery_rejects_original_role_pair_substitution(
    request_role: str, configured_role: str, parent_request_role: str
) -> None:
    with pytest.raises(ValueError, match="original configured investigator role"):
        pipeline._require_exact_nested_recovery_role(
            request_role=request_role,
            configured_role=configured_role,
            parent_request_role=parent_request_role,
        )
