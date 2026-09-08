from __future__ import annotations

import copy
import hashlib
import json
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.development_costs import (
    ESTIMATE_WARNING,
    DevelopmentCostError,
    DevelopmentCostEstimate,
    DevelopmentCostPolicy,
    estimate_development_request,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.route_constraints import (
    ProviderPriceCapAlgorithm,
    RouteConstraintError,
    normalize_exact_route_pricing,
    project_provider_price_cap,
)
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_cost_support import development_case


def _policy(**updates: Any) -> DevelopmentCostPolicy:
    return DevelopmentCostPolicy.model_validate(
        {
            "overspend_risk_accepted": True,
            "total_budget_usd": "20",
            "per_attempt_budget_usd": "5",
            **updates,
        }
    )


@pytest.mark.parametrize("ack", (False, None, 1, 0, "true", "yes"))
def test_policy_requires_literal_risk_acknowledgement(ack: object) -> None:
    with pytest.raises(ValidationError, match="explicit overspend"):
        _policy(overspend_risk_accepted=ack)


def test_policy_cannot_omit_acknowledgement_or_acquire_production_scope() -> None:
    with pytest.raises(ValidationError):
        DevelopmentCostPolicy(total_budget_usd=Decimal(20), per_attempt_budget_usd=Decimal(5))  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        _policy(purpose="PRODUCTION")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("total_budget_usd", "0"),
        ("total_budget_usd", "251"),
        ("total_budget_usd", 20.0),
        ("total_budget_usd", True),
        ("total_budget_usd", "NaN"),
        ("total_budget_usd", "Infinity"),
        ("total_budget_usd", "1e2"),
        ("total_budget_usd", "1.0000000000000000001"),
        ("total_budget_usd", Decimal("1.0000000000000000001")),
        ("total_budget_usd", Decimal("NaN")),
        ("total_budget_usd", Decimal("Infinity")),
        ("per_attempt_budget_usd", "21"),
        ("safety_multiplier", "1.99"),
        ("safety_multiplier", "11"),
        ("maximum_attempts", True),
        ("maximum_attempts", 0),
        ("maximum_attempts", 33),
    ),
)
def test_policy_rejects_unsafe_or_inexact_values(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _policy(**{field: value})


def test_estimate_uses_tier_maxima_cache_write_floor_bytes_and_all_attempts() -> None:
    snapshot, body = development_case()
    before = snapshot.model_dump_json(), copy.deepcopy(body)
    policy = _policy(maximum_attempts=3)
    estimate = estimate_development_request(
        policy=policy,
        endpoint_snapshot=snapshot,
        request_id="synthetic-1",
        request_body=body,
    )
    material = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert estimate.request_bytes == len(material)
    assert estimate.request_sha256 == hashlib.sha256(material).hexdigest()
    components = {item.component: item for item in estimate.components}
    assert components["prompt"].estimated_unit_price_usd == Decimal("0.000004")
    assert components["completion"].estimated_unit_price_usd == Decimal("0.000012")
    assert components["input_cache_write"].observed_unit_price_usd == 0
    assert components["input_cache_write"].estimated_unit_price_usd == Decimal("0.000004")
    assert components["input_cache_write"].estimated_units == len(material)
    assert components["input_cache_read"].estimated_units == len(material)
    assert components["image"].estimated_units == components["web_search"].estimated_units == 0
    expected = (
        Decimal("0.000009") * len(material) + Decimal("0.000012") * 4096 + Decimal("0.0001")
    ) * 2
    assert estimate.estimated_cost_per_attempt_usd == expected
    assert estimate.estimated_cost_all_attempts_usd == expected * 3
    assert estimate.within_estimated_budget is True
    assert estimate.warning == ESTIMATE_WARNING
    assert (
        estimate.provider_enforced_ceiling
        is estimate.qualification_eligible
        is estimate.release_eligible
        is False
    )
    assert body["messages"][0]["content"] not in estimate.model_dump_json()
    assert (snapshot.model_dump_json(), body) == before
    assert DevelopmentCostEstimate.model_validate_json(estimate.model_dump_json()) == estimate
    # The strict policy is unchanged even for the same synthetic metadata.
    with pytest.raises(RouteConstraintError, match="input_cache_write"):
        project_provider_price_cap(normalize_exact_route_pricing(snapshot.endpoints[0].pricing))
    with pytest.raises(ValidationError):
        OpenRouterStructuredRequestCostPreview.model_validate_json(estimate.model_dump_json())
    assert "DEVELOPMENT" not in " ".join(item.value for item in ProviderPriceCapAlgorithm)


@pytest.mark.parametrize(
    "field", ("provider_enforced_ceiling", "qualification_eligible", "release_eligible")
)
@pytest.mark.parametrize("value", (True, 0, 1, "false"))
def test_estimate_refuses_authority_or_coerced_markers(field: str, value: object) -> None:
    snapshot, body = development_case()
    estimate = estimate_development_request(
        policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
    )
    payload = json.loads(estimate.model_dump_json())
    payload[field] = value
    with pytest.raises(ValidationError):
        DevelopmentCostEstimate.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "field",
    (
        "tools",
        "tool_choice",
        "plugins",
        "web_search",
        "web_search_options",
        "models",
        "n",
        "cache_control",
        "image",
    ),
)
def test_estimate_rejects_unbounded_or_non_text_request_features(field: str) -> None:
    snapshot, body = development_case()
    body[field] = []
    with pytest.raises(DevelopmentCostError, match="without tools or search"):
        estimate_development_request(
            policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
        )


@pytest.mark.parametrize(
    "change",
    (
        "model",
        "fallbacks",
        "zdr",
        "numeric_zdr",
        "stream",
        "output_bool",
        "output_limit",
        "image_message",
        "tool_message",
        "large_message",
        "nonfinite",
    ),
)
def test_estimate_keeps_identity_privacy_and_request_limits(change: str) -> None:
    snapshot, body = development_case()
    if change == "model":
        body["model"] = "synthetic/other-model"
    elif change == "fallbacks":
        body["provider"]["allow_fallbacks"] = True
    elif change in {"zdr", "numeric_zdr"}:
        body["provider"]["zdr"] = False if change == "zdr" else 1
    elif change == "stream":
        body["stream"] = True
    elif change.startswith("output"):
        body["max_tokens"] = True if change == "output_bool" else 65_537
    elif change == "image_message":
        body["messages"][0]["content"] = [
            {"type": "image_url", "image_url": "synthetic://disabled"}
        ]
    elif change == "tool_message":
        body["messages"][0]["role"] = "tool"
    elif change == "large_message":
        body["messages"][0]["content"] = "x" * 280_001
    else:
        body["temperature"] = float("nan")
    with pytest.raises(DevelopmentCostError):
        estimate_development_request(
            policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
        )


def test_estimate_budget_thresholds_and_decimal_context_are_deterministic() -> None:
    snapshot, body = development_case()
    body["messages"][0]["content"] += " λ"
    estimate = estimate_development_request(
        policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
    )
    with localcontext() as context:
        context.prec = 2
        repeated = estimate_development_request(
            policy=_policy(),
            endpoint_snapshot=snapshot,
            request_id="x",
            request_body=dict(reversed(list(body.items()))),
        )
    assert repeated == estimate
    limited = estimate_development_request(
        policy=_policy(per_attempt_budget_usd="0.01"),
        endpoint_snapshot=snapshot,
        request_id="x",
        request_body=body,
    )
    assert limited.within_estimated_budget is False
    exact = _policy(
        total_budget_usd=estimate.estimated_cost_per_attempt_usd,
        per_attempt_budget_usd=estimate.estimated_cost_per_attempt_usd,
    )
    assert (
        estimate_development_request(
            policy=exact, endpoint_snapshot=snapshot, request_id="x", request_body=body
        ).within_estimated_budget
        is True
    )


def test_estimate_rejects_modified_totals() -> None:
    snapshot, body = development_case()
    estimate = estimate_development_request(
        policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
    )
    payload = json.loads(estimate.model_dump_json())
    payload["estimated_cost_per_attempt_usd"] = "0.000001"
    with pytest.raises(ValidationError, match="totals"):
        DevelopmentCostEstimate.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("field", ("estimated_unit_price_usd", "estimated_units"))
def test_estimate_rejects_lowered_cache_write_allowance(field: str) -> None:
    snapshot, body = development_case()
    estimate = estimate_development_request(
        policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
    )
    payload = json.loads(estimate.model_dump_json())
    cache_write = next(
        item for item in payload["components"] if item["component"] == "input_cache_write"
    )
    cache_write[field] = "0" if field == "estimated_unit_price_usd" else 0
    with pytest.raises(ValidationError, match="conservative allowance"):
        DevelopmentCostEstimate.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("tiered", (False, True))
def test_estimate_refuses_unsupported_charging_units_and_unavailable_tiers(tiered: bool) -> None:
    pricing: dict[str, Any] = {"prompt": "0.000002", "completion": "0.000006"}
    if tiered:
        pricing["overrides"] = [{"min_prompt_tokens": 100, "input_cache_write_1h": "0.000002"}]
    else:
        pricing["internal_reasoning"] = "0.000006"
    snapshot, body = development_case(pricing=pricing)
    with pytest.raises(DevelopmentCostError, match=r"unavailable|unsupported charging unit"):
        estimate_development_request(
            policy=_policy(), endpoint_snapshot=snapshot, request_id="x", request_body=body
        )


@pytest.mark.parametrize(
    "filename", ("development_cost_policy.schema.json", "development_cost_estimate.schema.json")
)
def test_development_schema_is_canonical_and_keeps_explicit_risk_and_decimal_strings(
    filename: str,
) -> None:
    material = (Path(__file__).resolve().parents[2] / "schemas" / filename).read_text()
    assert material == rendered_schema(filename, MODELS[filename])
    schema = json.loads(material)
    policy = (
        schema
        if filename == "development_cost_policy.schema.json"
        else schema["$defs"]["DevelopmentCostPolicy"]
    )
    assert "overspend_risk_accepted" in policy["required"]
    assert policy["properties"]["overspend_risk_accepted"]["const"] is True
    assert policy["properties"]["total_budget_usd"]["type"] == "string"
    if filename == "development_cost_estimate.schema.json":
        for marker in ("provider_enforced_ceiling", "qualification_eligible", "release_eligible"):
            assert schema["properties"][marker]["const"] is False
