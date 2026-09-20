"""Local synthetic refresh/transport/ledger custody; never real provider evidence."""

from __future__ import annotations

import json
import socket
import subprocess
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.schemas as schemas_module
import mmaudit.operator_secrets as secrets_module
from mmaudit.models.route_cost_reservations import operator_cost_attempts_from_usage
from mmaudit.models.schemas import (
    AuditModelRefreshPricingAttemptEvidence,
    ExecutionEvidenceKind,
    UsageRecord,
)
from mmaudit.orchestration.budgets import UnprovenCostBoundError
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostReservationOverrunError,
)
from tests.unit.test_openrouter import _client, _completion_response
from tests.unit.test_openrouter_policy_eligibility import _reasoning_policy
from tests.unit.test_openrouter_refresh_runtime import (
    _build_harness,
    _complete,
    _register_current_refresh_endpoint,
)


@pytest.fixture(autouse=True)
def local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("refresh integration must not access providers or real secrets")

    original_popen = subprocess.Popen

    def synthetic_signing_only(args: Any, *values: Any, **kwargs: Any) -> Any:
        # Existing qualification fixtures use a disposable synthetic Ed25519 signer.
        assert isinstance(args, list) and args[0] == "/usr/bin/ssh-keygen"
        assert kwargs.get("shell", False) is False
        return original_popen(args, *values, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", synthetic_signing_only)
    monkeypatch.setattr(secrets_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "component,billing",
    (
        ("input_cache_write", "success"),
        ("input_cache_read", "success"),
        ("internal_reasoning", "success"),
        ("web_search", "success"),
        ("input_cache_write", "unknown"),
        ("input_cache_write", "overrun"),
        ("input_cache_write", "ceiling"),
        ("input_cache_write", "retry"),
        ("input_cache_write", "tiered"),
    ),
)
async def test_local_bill_joins_independently_validated_refreshed_price_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component: str,
    billing: str,
) -> None:
    baseline: dict[str, Any] = {
        "completion": "0.000002",
        component: "0.0000005",
        "prompt": "0.000001",
    }
    current = {**baseline, component: "0.00000052"}
    if billing == "tiered":
        tier = {
            "min_prompt_tokens": 1000,
            "completion": "0.000003",
            "prompt": "0.000002",
            component: "0.0000008",
        }
        baseline["overrides"] = [tier]
        current["overrides"] = [{**tier, component: "0.00000082"}]
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        operator_reservation=True,
        force_real_boundary=False,
        qualified_pricing=baseline,
        current_pricing=current,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"synthetic refreshed reservation"}',
            model=model,
            provider=provider,
            reasoning_tokens=2,
        ),
    )
    pricing_route = next(
        route
        for route in harness.runtime.pricing_evidence.routes
        if route.exact_model_id == harness.model and route.audit_selected
    )
    control = harness.client._seal_audit_model_refresh_pricing_control(pricing_route)

    def respond(request: httpx.Request) -> httpx.Response:
        entry = harness.ledger.snapshot().entries[-1]
        assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        assert entry.actual_cost_usd is None and entry.accounted_cost_usd == entry.reserved_usd
        harness.requests.append(json.loads(request.content))
        return _completion_response(
            '{"wrong":"synthetic schema refusal"}'
            if billing == "retry" and len(harness.requests) == 1
            else '{"answer":"synthetic refreshed reservation"}',
            model=harness.model,
            provider=control.provider_endpoint,
            reasoning_tokens=2,
            cost=None
            if billing == "unknown"
            else 21
            if billing == "ceiling"
            else 0.5
            if billing == "overrun"
            else 0.01,
        )

    cost_client, http_client, cost_usage = _client(
        harness.runtime.config,
        respond,
        provider_policy=openrouter_module.OpenRouterProviderPolicy(
            only=(control.provider_endpoint,),
            certification=False,
        ),
        reasoning_policy=_reasoning_policy(harness.runtime.technical_qualification, harness.model),
        qualification_routing=(),
        budget=harness.client.budget,
    )
    _register_current_refresh_endpoint(
        cost_client,
        harness.runtime,
        harness.model,
        route_predicate_profile=control.route_predicate_profile,
    )
    if billing == "retry":
        cost_client.execution = cost_client.execution.model_copy(
            update={"max_model_retries": 0, "max_schema_validation_retries": 1}
        )
    try:
        cost_harness = replace(harness, client=cost_client, usage=cost_usage)
        if billing in {"success", "retry", "tiered"}:
            result = await _complete(cost_harness)
            assert result.value.answer == "synthetic refreshed reservation"
        else:
            with pytest.raises((openrouter_module.OpenRouterError, CostReservationOverrunError)):
                await _complete(cost_harness)
        usage = cost_usage.records[-1]
        billed_attempts = operator_cost_attempts_from_usage(usage)
        contract = billed_attempts[0].reservation
        attempt_ids = tuple(item.attempt_request_id for item in billed_attempts)
        assert openrouter_module._openrouter_client_callables_are_pristine()
        bound = harness.client._endpoint_request_cost_bound(
            model=harness.model,
            request_material=json.dumps(
                harness.requests[0],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            request_token_plan=contract.request_token_plan,
            refresh_pricing_control=control,
        )
        assert bound is not None
        attempt = AuditModelRefreshPricingAttemptEvidence.from_bound(
            logical_request_id=usage.request_id,
            attempt_request_id=attempt_ids[-1],
            attempt_index=len(attempt_ids),
            reservation_checked_at=harness.runtime.verified_at,
            transport_checked_at=harness.runtime.verified_at,
            current_endpoint_snapshot_sha256=control.current_endpoint_snapshot_sha256,
            request_body_sha256=contract.request_material_sha256,
            pricing_evidence=harness.runtime.pricing_evidence,
            pricing_authority=harness.runtime.pricing_authority,
            pricing_route=pricing_route,
            endpoint_cost_bound=bound,
            provider_max_price=dict(control.routing_max_price),
            route_predicate_profile=control.route_predicate_profile,
        )
        projected = harness.client._token_plan_routing_evidence(
            request_token_plan=contract.request_token_plan,
            reservations=tuple(harness.client.budget._issued[item] for item in attempt_ids),
            context_request_evidence=None,
            request_body_sha256=contract.request_material_sha256,
            refresh_pricing_control=control,
            refresh_pricing_attempt_routes={item: pricing_route for item in attempt_ids},
            refresh_pricing_reservation_checks={
                item: harness.runtime.verified_at for item in attempt_ids
            },
            refresh_pricing_transport_checks={
                item: harness.runtime.verified_at for item in attempt_ids
            },
        )
        assert projected["audit_model_refresh_pricing_attempt"] == attempt.model_dump(mode="json")
        raw_usage = usage.model_dump(mode="json")
        raw_usage["routing"].update(
            {
                **harness.client._audit_model_refresh_pricing_routing_evidence(pricing_route),
                **projected,
                "qualified_pricing_snapshot_sha256": pricing_route.qualified_pricing_snapshot_sha256,
            }
        )
        joined_usage = UsageRecord.model_validate_json(json.dumps(raw_usage))
        assert operator_cost_attempts_from_usage(joined_usage) == operator_cost_attempts_from_usage(
            usage
        )
        missing_bills = deepcopy(raw_usage)
        for key in (
            "operator_cost_attempts",
            "operator_cost_attempt_sha256s",
            "cost_enforcement_basis",
        ):
            del missing_bills["routing"][key]
        with pytest.raises(ValueError, match="exact billed attempts"):
            UsageRecord.model_validate_json(json.dumps(missing_bills))
        for changes in (
            {"selection_plan_sha256": "f" * 64},
            {"exact_route_constraint": None},
            {"route_predicate_profile": None},
            {"current_endpoint_snapshot_sha256": "f" * 64},
            {"current_pricing_sha256": "f" * 64},
            {"cost_bound_pricing": (("completion", "0"), ("prompt", "0"))},
            {"routing_max_price": (("completion", 0), ("prompt", 0))},
        ):
            with pytest.raises(UnprovenCostBoundError):
                harness.client._endpoint_request_cost_bound(
                    model=harness.model,
                    request_material=json.dumps(
                        harness.requests[0],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ),
                    request_token_plan=contract.request_token_plan,
                    refresh_pricing_control=replace(control, **changes),
                )
    finally:
        await cost_client.close()
        await http_client.aclose()
        await harness.client.close()
    assert len(harness.requests) == (2 if billing == "retry" else 1)
    body = harness.requests[0]
    assert body["response_format"]["type"] == "json_schema"
    assert body["reasoning"]["effort"] == "high"
    assert component not in body["provider"]["max_price"]
    assert usage.execution_evidence is ExecutionEvidenceKind.MOCK
    assert (
        AuditModelRefreshPricingAttemptEvidence.model_validate_json(attempt.model_dump_json())
        == attempt
    )
    schema = Draft202012Validator(AuditModelRefreshPricingAttemptEvidence.model_json_schema())
    schema.validate(attempt.model_dump(mode="json"))
    assert attempt.schema_version == "1.2"
    assert attempt.baseline_pricing == {k: v for k, v in baseline.items() if k != "overrides"}
    assert attempt.current_pricing == {k: v for k, v in current.items() if k != "overrides"}
    if billing == "tiered":
        assert attempt.baseline_pricing_schedule is not None
        assert attempt.current_pricing_schedule is not None
        assert attempt.current_pricing_schedule == contract.pricing_schedule
    contract = attempt.operator_cost_reservation
    assert contract is not None
    assert not contract.policy.provider_enforced_total_ceiling
    assert attempt.request_body_sha256 == usage.request_body_sha256
    assert attempt.request_material_sha256 == contract.request_material_sha256
    assert attempt.price_cap_algorithm is None
    assert not attempt.pricing_use_authorized and not attempt.provider_access_authorized
    assert "price_cap_algorithm" not in attempt.model_dump(mode="json")
    assert "price_component_unit_envelopes" not in attempt.model_dump(mode="json")
    entry = harness.ledger.snapshot().entries[-1]
    expected_bill = (
        None
        if billing == "unknown"
        else Decimal("21" if billing == "ceiling" else "0.5" if billing == "overrun" else "0.01")
    )
    assert entry.actual_cost_usd == expected_bill
    assert entry.reserved_usd == Decimal(contract.reserved_cost_usd_exact)
    assert not harness.ledger.snapshot().active_reserved_usd
    if billing == "retry":
        assert len(billed_attempts) == 2
        assert all(item.actual_billed_cost_usd_exact == "0.01" for item in billed_attempts)
        assert harness.ledger.snapshot().spent_usd == Decimal("0.02")
        assert Decimal(joined_usage.accounted_cost_usd_exact or "-1") == Decimal("0.02")
    if billing in {"unknown", "overrun", "ceiling"}:
        reopened = AtomicCostLedger.open_existing(harness.ledger.path, cap_usd=Decimal("20"))
        with pytest.raises(CostBudgetExceededError):
            reopened.reserve(
                "forbidden-after-liability", Decimal("0.001"), require_known_prior_costs=True
            )
    for field, value in (
        ("schema_version", "1.1"),
        ("operator_cost_reservation", None),
        ("route_predicate_profile", None),
        ("price_cap_algorithm", None),
        ("price_component_unit_envelopes", None),
        ("qualified_pricing_snapshot_sha256", "f" * 64),
        ("request_body_sha256", "f" * 64),
        ("maximum_cost_usd_exact", "0.000001"),
        ("provider_max_price", {"completion": "0", "prompt": "0"}),
        ("attempt_request_id", "different-request"),
        ("reservation_checked_at", attempt.pricing_expires_at.isoformat().replace("+00:00", "Z")),
    ):
        payload = deepcopy(attempt.model_dump(mode="json"))
        payload[field] = value
        payload["evidence_sha256"] = schemas_module._pricing_attempt_sha256(
            {key: val for key, val in payload.items() if key != "evidence_sha256"}
        )
        with pytest.raises(ValueError):
            AuditModelRefreshPricingAttemptEvidence.model_validate_json(json.dumps(payload))
        if field in {
            "schema_version",
            "operator_cost_reservation",
            "route_predicate_profile",
            "price_cap_algorithm",
            "price_component_unit_envelopes",
        }:
            assert list(schema.iter_errors(payload))
