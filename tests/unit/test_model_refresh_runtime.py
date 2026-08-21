from __future__ import annotations

import copy
import json
import pickle
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.refresh_runtime as refresh_runtime_module
from mmaudit.models.refresh import (
    SelectedModelRoute,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    seal_model_refresh_attempt,
)
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshEvidence,
    AuditModelRefreshPricingEvidence,
    AuditModelRefreshPricingRouteEvidence,
    VerifiedAuditModelRefreshGuard,
    VerifiedAuditModelRefreshPricingAuthority,
    resolve_verified_audit_model_refresh_guard,
    resolve_verified_audit_model_refresh_pricing_authority,
)
from mmaudit.models.refresh_staging import ValidatedModelRefreshHistory
from tests.refresh_runtime_support import (
    SyntheticRefreshRuntime,
    _workflow_status,
    synthetic_refresh_runtime,
)


def _resolver_arguments(runtime: SyntheticRefreshRuntime) -> dict[str, Any]:
    status = runtime.history.workflow_status
    return {
        "history": runtime.history,
        "expected_workflow_status_sha256": status.workflow_status_sha256,
        "expected_source_commit": status.source_commit,
        "expected_workflow_run_id": status.workflow_run_id,
        "expected_workflow_run_attempt": status.workflow_run_attempt,
        "technical_qualification": runtime.technical_qualification,
        "audit_selection_evidence": runtime.audit_selection_evidence,
        "audit_selection": runtime.audit_selection,
        "expected_pricing_tolerance_fraction": status.pricing_tolerance_fraction,
        "expected_soft_max_age_hours": status.soft_max_age_hours,
        "expected_hard_max_age_hours": status.hard_max_age_hours,
        "verified_at": runtime.verified_at,
    }


def _guard_arguments(runtime: SyntheticRefreshRuntime, *, now: Any = None) -> dict[str, Any]:
    return {
        "now": runtime.verified_at if now is None else now,
        "technical_qualification": runtime.technical_qualification,
        "audit_selection": runtime.audit_selection,
        **runtime.runtime_bindings,
    }


def _pricing_resolver_arguments(runtime: SyntheticRefreshRuntime) -> dict[str, Any]:
    return {
        **_resolver_arguments(runtime),
        "refresh_evidence": runtime.evidence,
        "refresh_guard": runtime.guard,
    }


def _pricing_authority_arguments(
    runtime: SyntheticRefreshRuntime,
    *,
    now: Any = None,
) -> dict[str, Any]:
    return {
        **_guard_arguments(runtime, now=now),
        "refresh_evidence": runtime.evidence,
        "refresh_guard": runtime.guard,
    }


def test_exact_current_refresh_issues_only_a_veto_guard(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)

    assert len(runtime.evidence.routes) == 9
    assert runtime.evidence.technical_model_ids == tuple(
        model.exact_model_id for model in runtime.technical_qualification.models
    )
    assert runtime.evidence.audit_model_ids == tuple(
        model.exact_model_id for model in runtime.audit_selection.models
    )
    assert runtime.evidence.technical_selection_authorized is False
    assert runtime.evidence.audit_selection_authorized is False
    assert runtime.evidence.provider_access_authorized is False
    assert runtime.evidence.production_promotion_authorized is False
    assert runtime.guard.require_current(**_guard_arguments(runtime)) is runtime.guard

    first = runtime.audit_selection.models[0]
    route = runtime.guard.route_for(first.exact_model_id, **_guard_arguments(runtime))
    assert route.exact_model_id == first.exact_model_id
    assert route.approved_provider_endpoint == first.approved_provider_endpoint
    assert route.runtime_authorized is False
    assert runtime.pricing_evidence.pricing_use_authorized is False
    assert runtime.pricing_evidence.provider_access_authorized is False
    assert runtime.pricing_evidence.technical_selection_authorized is False
    assert runtime.pricing_evidence.audit_selection_authorized is False
    assert runtime.pricing_evidence.production_promotion_authorized is False
    assert (
        runtime.pricing_authority.require_current(**_pricing_authority_arguments(runtime))
        is runtime.pricing_authority
    )
    pricing_route = runtime.pricing_authority.route_for(
        first.exact_model_id,
        **_pricing_authority_arguments(runtime),
    )
    assert pricing_route.comparison_state == "EXACT"
    assert pricing_route.baseline_pricing == pricing_route.current_pricing
    assert pricing_route.pricing_use_authorized is False


def test_pricing_evidence_schema_bounds_property_names_and_decimal_values() -> None:
    schema = AuditModelRefreshPricingRouteEvidence.model_json_schema()
    field_pattern = "^[a-z][a-z0-9_]{0,63}$"
    price_pattern = r"^(?:0|[1-9][0-9]{0,11}|(?:0|[1-9][0-9]{0,11})\.[0-9]{0,35}[1-9])$"

    for field in ("baseline_pricing", "current_pricing"):
        pricing_schema = schema["properties"][field]
        assert pricing_schema["minProperties"] == 2
        assert pricing_schema["maxProperties"] == 64
        assert pricing_schema["propertyNames"] == {
            "minLength": 1,
            "maxLength": 64,
            "pattern": field_pattern,
        }
        assert pricing_schema["patternProperties"][field_pattern] == {
            "minLength": 1,
            "maxLength": 49,
            "pattern": price_pattern,
            "type": "string",
        }


def test_extra_unselected_candidate_does_not_change_exact_monitored_set(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path, extra_unselected_candidate=True)

    assert len(runtime.history.candidate_registry.candidates) == 10
    assert len(runtime.evidence.routes) == 9
    assert (
        runtime.evidence.current_candidate_registry_sha256
        != runtime.evidence.technical_candidate_registry_sha256
    )
    assert "juliet/jade-new" not in runtime.evidence.technical_model_ids


def test_selected_price_drift_within_tolerance_requires_separate_pricing_authority(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(
        tmp_path,
        current_pricing={
            "completion": "0.0000021",
            "prompt": "0.000001",
        },
    )

    first = runtime.audit_selection.models[0]
    refresh_route = runtime.guard.route_for(
        first.exact_model_id,
        **_guard_arguments(runtime),
    )
    assert (
        refresh_route.refresh_route.pricing_sha256
        != refresh_route.qualified_pricing_snapshot_sha256
    )
    assert refresh_route.runtime_authorized is False
    pricing_route = runtime.pricing_authority.route_for(
        first.exact_model_id,
        **_pricing_authority_arguments(runtime),
    )
    assert pricing_route.comparison_state == "WITHIN_TOLERANCE"
    assert pricing_route.increased_components == ("completion",)
    assert pricing_route.current_pricing["completion"] == "0.0000021"
    assert pricing_route.baseline_pricing_sha256 == pricing_route.qualified_pricing_snapshot_sha256
    assert pricing_route.current_pricing_sha256 != pricing_route.qualified_pricing_snapshot_sha256


def test_selected_price_drift_above_tolerance_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inconsistent or blocking"):
        synthetic_refresh_runtime(
            tmp_path,
            current_pricing={
                "completion": "0.000002100001",
                "prompt": "0.000001",
            },
        )


def test_price_tolerance_uses_exact_high_precision_boundary(tmp_path: Path) -> None:
    baseline = "0.00000000314159265358979323846264338"
    exact_boundary = "0.000000003298672286269282900385775549"
    runtime = synthetic_refresh_runtime(
        tmp_path / "boundary",
        qualified_pricing={"completion": baseline, "prompt": "0.000001"},
        current_pricing={"completion": exact_boundary, "prompt": "0.000001"},
    )

    first = runtime.audit_selection.models[0]
    route = runtime.pricing_authority.route_for(
        first.exact_model_id,
        **_pricing_authority_arguments(runtime),
    )
    assert route.current_pricing["completion"] == exact_boundary
    assert route.comparison_state == "WITHIN_TOLERANCE"


def test_price_tolerance_rejects_last_canonical_decimal_over_boundary(
    tmp_path: Path,
) -> None:
    baseline = "0.00000000314159265358979323846264338"
    last_decimal_over = "0.00000000329867228626928290038577555"

    with pytest.raises(ValueError, match="inconsistent or blocking"):
        synthetic_refresh_runtime(
            tmp_path,
            qualified_pricing={"completion": baseline, "prompt": "0.000001"},
            current_pricing={"completion": last_decimal_over, "prompt": "0.000001"},
        )


@pytest.mark.parametrize(
    "pricing_arguments",
    (
        {
            "current_pricing": {
                "completion": "0.000002",
                "prompt": "0.000001",
                "request": "0",
            }
        },
        {
            "qualified_pricing": {
                "completion": "0.000002",
                "prompt": "0.000001",
                "request": "0",
            },
            "previous_pricing": {
                "completion": "0.000002",
                "prompt": "0.000001",
                "request": "0",
            },
            "current_pricing": {
                "completion": "0.000002",
                "prompt": "0.000001",
            },
        },
    ),
    ids=("new-component", "missing-component"),
)
def test_new_or_missing_price_component_is_not_authorized(
    tmp_path: Path,
    pricing_arguments: dict[str, dict[str, str]],
) -> None:
    with pytest.raises(ValueError, match="new, missing, or unsupported"):
        synthetic_refresh_runtime(
            tmp_path,
            qualified_pricing=pricing_arguments.get("qualified_pricing"),
            previous_pricing=pricing_arguments.get("previous_pricing"),
            current_pricing=pricing_arguments.get("current_pricing"),
        )


def test_new_cache_read_component_is_blocked_before_runtime_authority(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inconsistent or blocking"):
        synthetic_refresh_runtime(
            tmp_path,
            current_pricing={
                "completion": "0.000002",
                "input_cache_read": "0.0000001",
                "prompt": "0.000001",
            },
        )


def test_pricing_baseline_must_equal_qualified_hash(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="baseline differs from qualification"):
        synthetic_refresh_runtime(
            tmp_path,
            previous_pricing={
                "completion": "0.000003",
                "prompt": "0.000002",
            },
        )


def test_audit_policy_subset_cannot_be_expanded_by_refresh(tmp_path: Path) -> None:
    baseline = synthetic_refresh_runtime(tmp_path / "baseline")
    excluded_id = baseline.technical_qualification.models[0].exact_model_id
    runtime = synthetic_refresh_runtime(
        tmp_path / "excluded",
        excluded_ids=frozenset({excluded_id}),
    )

    assert len(runtime.evidence.routes) == 9
    assert len(runtime.evidence.audit_model_ids) == 8
    excluded = next(
        route for route in runtime.evidence.routes if route.exact_model_id == excluded_id
    )
    assert excluded.audit_selected is False
    with pytest.raises(ValueError, match="verified audit selection"):
        runtime.guard.route_for(excluded_id, **_guard_arguments(runtime))


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("expected_workflow_status_sha256", "f" * 64, "independently expected identity"),
        ("expected_source_commit", "e" * 40, "independently expected identity"),
        ("expected_workflow_run_id", "999", "independently expected identity"),
        ("expected_workflow_run_attempt", "2", "independently expected identity"),
        ("expected_source_commit", None, "source commit is malformed"),
        ("expected_workflow_run_id", 999, "run ID is malformed"),
        ("expected_workflow_run_attempt", 2, "run attempt is malformed"),
    ),
)
def test_independent_workflow_pins_are_exact(
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    arguments = _resolver_arguments(runtime)
    arguments[field] = replacement

    with pytest.raises(ValueError, match=message):
        resolve_verified_audit_model_refresh_guard(**arguments)


def test_runtime_time_wrong_type_fails_as_validation_error(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    arguments = _resolver_arguments(runtime)
    arguments["verified_at"] = "2026-08-17T12:02:00Z"

    with pytest.raises(ValueError, match="whole-second UTC"):
        resolve_verified_audit_model_refresh_guard(**arguments)


def test_valid_empty_selected_routes_cannot_issue_guard(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    history = runtime.history
    assert history.previous_snapshot is not None
    assert history.previous_source_evidence is not None
    assert history.previous_candidate_registry is not None
    assert history.previous_workflow_status is not None
    empty_diff = diff_model_refresh(
        current=history.snapshot,
        previous=history.previous_snapshot,
        previous_source_evidence=history.previous_source_evidence,
        previous_candidate_registry=history.previous_candidate_registry,
        candidate_registry=history.candidate_registry,
        pricing_tolerance_fraction=history.workflow_status.pricing_tolerance_fraction,
        compared_at=history.snapshot.retrieved_at,
        selected_routes=(),
    )
    empty_attempt = seal_model_refresh_attempt(
        attempted_at=history.attempt.attempted_at,
        candidate_registry_sha256=history.candidate_registry.registry_sha256,
        snapshot=history.snapshot,
        diff=empty_diff,
    )
    empty_freshness = evaluate_model_refresh_freshness(
        observed_at=history.snapshot.retrieved_at,
        snapshot=history.snapshot,
        soft_max_age_hours=history.workflow_status.soft_max_age_hours,
        hard_max_age_hours=history.workflow_status.hard_max_age_hours,
        production_selection_present=False,
    )
    empty_status = _workflow_status(
        validated_at=history.workflow_status.validated_at,
        run_id=history.workflow_status.workflow_run_id,
        registry=history.candidate_registry,
        source=history.source_evidence,
        snapshot=history.snapshot,
        diff=empty_diff,
        attempt=empty_attempt,
        freshness=empty_freshness,
        previous_status=history.previous_workflow_status,
        previous_registry=history.previous_candidate_registry,
        previous_source=history.previous_source_evidence,
        previous_snapshot=history.previous_snapshot,
    )
    empty_history = ValidatedModelRefreshHistory(
        workflow_status=empty_status,
        candidate_registry=history.candidate_registry,
        source_evidence=history.source_evidence,
        snapshot=history.snapshot,
        diff=empty_diff,
        attempt=empty_attempt,
        freshness=empty_freshness,
        previous_workflow_status=history.previous_workflow_status,
        previous_candidate_registry=history.previous_candidate_registry,
        previous_source_evidence=history.previous_source_evidence,
        previous_snapshot=history.previous_snapshot,
    )
    arguments = _resolver_arguments(runtime)
    arguments.update(
        history=empty_history,
        expected_workflow_status_sha256=empty_status.workflow_status_sha256,
    )

    with pytest.raises(ValueError, match="selected routes differ from exact production selection"):
        resolve_verified_audit_model_refresh_guard(**arguments)


def test_guard_is_current_through_soft_boundary_only(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    assert runtime.evidence.refresh_current_through == runtime.verified_at + timedelta(hours=1)

    runtime.guard.require_current(
        **_guard_arguments(runtime, now=runtime.evidence.refresh_current_through)
    )
    with pytest.raises(ValueError, match="expired"):
        runtime.guard.require_current(
            **_guard_arguments(
                runtime,
                now=runtime.evidence.refresh_current_through + timedelta(seconds=1),
            )
        )


def test_durable_evidence_and_forged_capabilities_never_recreate_authority(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    parsed = AuditModelRefreshEvidence.model_validate_json(
        runtime.evidence.model_dump_json(), strict=True
    )
    assert parsed == runtime.evidence
    forged = object.__new__(VerifiedAuditModelRefreshGuard)

    with pytest.raises(ValueError, match="absent or forged"):
        forged.require_current(**_guard_arguments(runtime))
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(runtime.guard)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(runtime.guard)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(runtime.guard)


def test_guard_registry_writer_and_state_are_not_module_reachable(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)

    assert runtime.guard.require_current(**_guard_arguments(runtime)) is runtime.guard
    for name in (
        "_IssuedGuardState",
        "_register_guard",
        "_issued_guard_state",
        "_build_guard_registry",
        "_build_refresh_guard_authority",
    ):
        assert not hasattr(refresh_runtime_module, name)


def test_guard_rejects_wrong_external_pin_at_use(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    arguments = _guard_arguments(runtime)
    arguments["expected_workflow_status_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="integrity or exact selection join"):
        runtime.guard.require_current(**arguments)


def test_selected_routes_are_derived_from_all_technical_models(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    expected = tuple(
        SelectedModelRoute(
            exact_model_id=model.exact_model_id,
            provider_endpoint=model.approved_provider_endpoint,
        )
        for model in runtime.technical_qualification.models
    )
    assert runtime.history.diff.selected_routes == expected


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    (
        ("expected_workflow_status_sha256", "f" * 64, "independently expected identity"),
        ("expected_source_commit", "e" * 40, "independently expected identity"),
        ("expected_workflow_run_id", "999", "independently expected identity"),
        ("expected_workflow_run_attempt", "2", "independently expected identity"),
    ),
)
def test_pricing_authority_requires_independent_workflow_pins(
    tmp_path: Path,
    field: str,
    replacement: str,
    message: str,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    arguments = _pricing_resolver_arguments(runtime)
    arguments[field] = replacement

    with pytest.raises(ValueError, match=message):
        resolve_verified_audit_model_refresh_pricing_authority(**arguments)


def test_pricing_authority_rejects_stale_trusted_time(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    stale = runtime.pricing_evidence.expires_at
    resolver_arguments = _pricing_resolver_arguments(runtime)
    resolver_arguments["verified_at"] = stale

    with pytest.raises(ValueError, match=r"not current|expired"):
        resolve_verified_audit_model_refresh_pricing_authority(**resolver_arguments)
    with pytest.raises(ValueError, match="expired"):
        runtime.pricing_authority.require_current(
            **_pricing_authority_arguments(runtime, now=stale)
        )


def test_pricing_authority_rejects_different_refresh_route_set(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path / "expected")
    different = synthetic_refresh_runtime(
        tmp_path / "different",
        extra_unselected_candidate=True,
    )
    arguments = _pricing_resolver_arguments(runtime)
    arguments["refresh_evidence"] = different.evidence

    with pytest.raises(ValueError, match="different refresh evidence"):
        resolve_verified_audit_model_refresh_pricing_authority(**arguments)


def test_noncanonical_durable_pricing_map_is_rejected(tmp_path: Path) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    route_payload = runtime.pricing_evidence.routes[0].model_dump(mode="json")
    current_pricing = dict(route_payload["current_pricing"])
    current_pricing["completion"] = "0.0000020"
    route_payload["current_pricing"] = current_pricing

    with pytest.raises(ValueError, match=r"pattern|canonical"):
        AuditModelRefreshPricingRouteEvidence.model_validate_json(
            json.dumps(route_payload),
            strict=True,
        )


def test_durable_pricing_evidence_and_forgery_never_recreate_authority(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    parsed = AuditModelRefreshPricingEvidence.model_validate_json(
        runtime.pricing_evidence.model_dump_json(),
        strict=True,
    )
    assert parsed == runtime.pricing_evidence
    forged = object.__new__(VerifiedAuditModelRefreshPricingAuthority)

    with pytest.raises(TypeError, match="only be issued by its resolver"):
        VerifiedAuditModelRefreshPricingAuthority()
    with pytest.raises(ValueError, match="absent or forged"):
        forged.require_current(**_pricing_authority_arguments(runtime))
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(runtime.pricing_authority)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(runtime.pricing_authority)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(runtime.pricing_authority)


def test_public_nested_pricing_mutation_cannot_change_private_authority_state(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)
    first = runtime.audit_selection.models[0]
    public_evidence_route = next(
        route
        for route in runtime.pricing_evidence.routes
        if route.exact_model_id == first.exact_model_id
    )
    public_evidence_route.current_pricing["completion"] = "0.9"

    returned_route = runtime.pricing_authority.route_for(
        first.exact_model_id,
        **_pricing_authority_arguments(runtime),
    )
    assert returned_route.current_pricing["completion"] == "0.000002"
    returned_route.current_pricing["completion"] = "0.8"

    second_route = runtime.pricing_authority.route_for(
        first.exact_model_id,
        **_pricing_authority_arguments(runtime),
    )
    assert second_route.current_pricing["completion"] == "0.000002"


def test_pricing_authority_registry_writer_and_state_are_not_module_reachable(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path)

    assert (
        runtime.pricing_authority.require_current(**_pricing_authority_arguments(runtime))
        is runtime.pricing_authority
    )
    for name in (
        "_IssuedPricingState",
        "_register_pricing_authority",
        "_issued_pricing_state",
        "_build_pricing_registry",
        "_build_refresh_pricing_authority",
    ):
        assert not hasattr(refresh_runtime_module, name)
