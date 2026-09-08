"""Local-only pinned source, synthetic HTTP responses, and disposable budget state."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_review import PreparedDevelopmentReview, prepare_development_review
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryPayload,
    validate_openrouter_constrained_model_discovery,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    RoutePredicateProfile,
)
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_cost_support import FIXTURE, development_case

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "solidity" / "development_review"
RESPONSE_FIXTURE = (
    Path(__file__).parent / "fixtures" / "model_responses" / "development_review_response.json"
)
SYNTHETIC_CREDENTIAL = "synthetic-only-development-credential-canary"


def review_case(*, filename: str = "ControlA.sol", attempts: int = 1) -> PreparedDevelopmentReview:
    snapshot, _body = development_case()
    return prepare_development_review(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("5"),
            maximum_attempts=attempts,
        ),
        endpoint_snapshot=snapshot,
        source_filename=filename,
        source_content=(FIXTURE_ROOT / filename).read_bytes(),
        request_id="local-review-1",
    )


def response_payload() -> dict[str, Any]:
    return json.loads(RESPONSE_FIXTURE.read_text())  # type: ignore[no-any-return]


def local_controls(tmp_path: Path) -> tuple[AtomicCostLedger, OperatorSecrets]:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    return ledger, OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})


def discovery_review_case(
    *,
    endpoint_efforts: tuple[ReasoningEffort, ...] | None = None,
    model_efforts: tuple[ReasoningEffort, ...] | None = ("low", "high", "max"),
    model_parameters: tuple[str, ...] | None = None,
    constrained: bool = False,
) -> OpenRouterModelDiscoveryPayload:
    """Build real parser output from inert metadata, never REAL provider provenance."""

    data = json.loads(FIXTURE.read_text())
    model = json.loads((FIXTURE.parent / "development_reasoning_model.json").read_text())["model"]
    if model_parameters is not None:
        model["supported_parameters"] = list(model_parameters)
    endpoint = data["endpoint"]
    endpoint["reasoning"] = (
        None if endpoint_efforts is None else {"supported_efforts": list(endpoint_efforts)}
    )
    if model_efforts is None:
        del model["reasoning"]["supported_efforts"]
    else:
        model["reasoning"]["supported_efforts"] = list(model_efforts)
    if constrained:
        # This isolated fixture has only token charges so strict publication is expressible.
        endpoint["pricing"] = {"prompt": "0.000002", "completion": "0.000006"}
        control = ReasoningControlProfile.build(
            mode="effort", effort="high", reserved_reasoning_tokens=4096
        )
        policy = ReasoningPolicyArtifact.build(
            controls_by_role={role: control for role in CANONICAL_REASONING_POLICY_ROLES}
        )
        role = policy.role_policy_for_request("model_benchmark")
        profile = RoutePredicateProfile.build(
            reasoning_policy_sha256=policy.artifact_sha256,
            reasoning_role_profile_sha256=policy.role_profile.profile_sha256,
            reasoning_role_binding_sha256=role.binding_sha256,
            reasoning_control_profile_sha256=control.profile_sha256,
            reserved_reasoning_tokens=4096,
            minimum_prompt_tokens=100_000,
            required_output_tokens=4096,
            minimum_context_tokens=120_000,
        )
        constraint = ExactRouteConstraint.build(
            role=ExactRouteRole.CANDIDATE,
            exact_model_id=model["id"],
            provider_endpoint=endpoint["tag"],
            profile=profile,
        )
        return validate_openrouter_constrained_model_discovery(
            exact_model_id=model["id"],
            models_payload={"data": [model]},
            single_model_payload={"data": model},
            configured_provider_endpoints=(endpoint["tag"],),
            provider_policy_mode="only",
            endpoint_payload={"data": {"id": model["id"], "endpoints": [endpoint]}},
            require_zdr=True,
            zdr_payload={"data": [{**endpoint, "model_id": model["id"]}]},
            route_predicate_profile=profile,
            exact_route_constraint=constraint,
            expected_selection_plan_sha256="1" * 64,
            reasoning_policy=policy,
            automatic_fallbacks_allowed=False,
        )
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model["id"],
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model["id"], "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model["id"]}]},
    )
    return validate_openrouter_model_discovery(
        exact_model_id=model["id"],
        models_payload={"data": [model]},
        single_model_payload={"data": model},
        endpoint_snapshot=snapshot,
    )
