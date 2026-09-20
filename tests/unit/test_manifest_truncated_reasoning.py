"""Truncated attempts retain exact qualification routing but never response credit."""

from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.registry import ModelRegistry
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record, request_token_plan_from_usage
from mmaudit.orchestration import manifest
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_run_support import OriginalRunAccounting
from tests.unit.test_manifest import _report
from tests.unit.test_truncation_tree_configured_requests import (
    configured_inputs as configured_inputs,
)


def _attempt_arguments(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, *, recovery: bool
) -> dict[str, Any]:
    config, runtime, original, context = configured_inputs["configured"]
    accounting = OriginalRunAccounting(tmp_path / "ledger", configured_requests=True)
    original = reattest_synthetic_real_usage(
        original.model_copy(
            update={
                "status": "rejected_truncated_response",
                "validation_status": ModelRequestValidationStatus.TRUNCATED,
                "validated_response_sha256": None,
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "finish_reason": "length",
                "routing": original.routing
                | {
                    "structured_output": original.routing["structured_output"] | {"truncated": True}
                },
            }
        )
    )
    truncated = accounting.prepare(original, runtime, context=context)
    coordinates = None
    if recovery:
        plan = request_token_plan_from_usage(truncated)
        assert plan is not None
        scope, count = "scheduler-request-" + "a" * 64, 2
        reservation = AtomicRequestLimitReservationEvidence.build(
            request_id=truncated.request_id,
            exact_model_id=truncated.requested_model,
            role=truncated.role,
            request_token_plan_sha256=plan.plan_sha256,
            request_limit_scope=scope,
            request_limit_count_before=count,
            request_limit_maximum=100,
        )
        truncated = reattest_synthetic_real_usage(
            truncated.model_copy(
                update={
                    "routing": truncated.routing
                    | {
                        "atomic_request_limit_reservations": [reservation.model_dump(mode="json")],
                        "atomic_request_limit_reservation_sha256s": [reservation.evidence_sha256],
                        "atomic_request_limit_reservation": reservation.model_dump(mode="json"),
                        "atomic_request_limit_reservation_sha256": reservation.evidence_sha256,
                    }
                }
            )
        )
        coordinates = {truncated.request_id: (scope, count)}
    qualification = runtime.technical_qualification
    validation = ModelRegistry.validate_production_qualification(
        config, qualification, now=qualification.verified_at
    )
    return {
        "config": config,
        "report": _report(config).model_copy(update={"usage": [truncated]}),
        "qualification_runtime": validation.as_dict(),
        "production_qualification": qualification,
        "recovery_request_limit_coordinates": coordinates,
    }


@pytest.mark.parametrize("recovery", (False, True))
def test_truncated_reasoning_keeps_attempt_binding_without_qualified_response_credit(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, recovery: bool
) -> None:
    arguments = _attempt_arguments(configured_inputs, tmp_path, recovery=recovery)
    truncated = arguments["report"].usage[0]
    bindings = {binding.identifier: binding for binding in manifest._model_bindings(**arguments)}
    # Named invariant: paid truncation is retained as an attempt, not a qualified response.
    assert f"reasoning/qualification/{truncated.request_id}" not in bindings
    assert (
        bindings[f"reasoning/truncated-attempt/{truncated.request_id}"].details["response_credit"]
        == "false"
    )
    assert not is_creditable_usage_record(truncated, require_real=True, require_certification=True)
    coordinates = arguments["recovery_request_limit_coordinates"] or {}
    scope, count = coordinates.get(truncated.request_id, (None, None))
    qargs = {
        "usage": truncated,
        "reasoning_policy": build_reasoning_policy(arguments["config"]),
        "validation": ModelRegistry.validate_production_qualification(
            arguments["config"],
            arguments["production_qualification"],
            now=arguments["production_qualification"].verified_at,
        ),
        "recovery_request_limit_scope": scope,
        "recovery_request_limit_count_before": count,
    }
    # Both prior response-credit predicates remain strict even for a valid retained attempt.
    with pytest.raises(ValueError, match="creditable"):
        manifest._require_opaque_reasoning_qualification(
            **qargs, qualification=arguments["production_qualification"]
        )
    with pytest.raises(ValueError, match="creditable"):
        manifest._require_serialized_reasoning_qualification_for_verification(**qargs)

    decoded = UsageRecord.model_validate_json(truncated.model_dump_json())
    detached = arguments | {"report": arguments["report"].model_copy(update={"usage": [decoded]})}
    with pytest.raises(ValueError, match="accountable"):
        manifest._model_bindings(**detached)
    replayed = manifest._model_bindings(
        **(
            detached
            | {
                "production_qualification": None,
                "sealed_verification_bindings": list(bindings.values()),
            }
        )
    )
    assert replayed == sorted(bindings.values(), key=lambda item: item.identifier)


@pytest.mark.parametrize("recovery", (False, True))
@pytest.mark.parametrize(
    "change",
    (
        "context",
        "context-hash",
        "uncertified",
        "provider",
        "benchmark",
        "reasoning-bindings",
        "request-body",
        "mock",
        "status",
    ),
)
def test_truncated_attempt_cannot_hide_missing_or_substituted_custody(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, recovery: bool, change: str
) -> None:
    arguments = _attempt_arguments(configured_inputs, tmp_path, recovery=recovery)
    usage = arguments["report"].usage[0]
    routing = dict(usage.routing)
    updates: dict[str, Any] = {}
    if change == "context":
        routing.pop("context_request_evidence")
    elif change == "context-hash":
        routing["context_request_evidence_sha256"] = "0" * 64
    elif change == "uncertified":
        routing["certification_request"] = False
    elif change == "provider":
        routing["qualified_provider_name"] = "Different synthetic provider"
    elif change == "benchmark":
        routing.pop("benchmark_report_sha256")
    elif change == "reasoning-bindings":
        routing["qualified_reasoning_binding_sha256"] = []
    elif change == "request-body":
        updates["request_body_sha256"] = None
    elif change == "mock":
        updates["execution_evidence"] = ExecutionEvidenceKind.MOCK
    else:
        updates["status"] = "different-failure"
    changed = usage.model_copy(update=updates | {"routing": routing})
    if change != "mock":
        changed = reattest_synthetic_real_usage(changed)
    with pytest.raises(ValueError):
        manifest._model_bindings(
            **(arguments | {"report": arguments["report"].model_copy(update={"usage": [changed]})})
        )


@pytest.mark.parametrize("change", ("missing", "scope", "count", "partial"))
def test_truncated_bridge_accounting_requires_original_external_coordinates(
    configured_inputs: dict[str, tuple[Any, ...]], tmp_path: Path, change: str
) -> None:
    arguments = _attempt_arguments(configured_inputs, tmp_path, recovery=True)
    usage = arguments["report"].usage[0]
    scope, count = arguments["recovery_request_limit_coordinates"][usage.request_id]
    altered = (
        None
        if change == "missing"
        else {
            usage.request_id: (
                scope + "-changed" if change == "scope" else scope,
                None if change == "partial" else count + (change == "count"),
            )
        }
    )
    with pytest.raises(ValueError):
        manifest._model_bindings(**(arguments | {"recovery_request_limit_coordinates": altered}))
