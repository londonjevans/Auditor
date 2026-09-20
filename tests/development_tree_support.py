"""Synthetic automatic-tree policy; generous fake metadata is not a real admitted route."""

from __future__ import annotations

import json
from decimal import Decimal

from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_tree_plan import DevelopmentTreePlanPolicy
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from tests.development_cost_support import FIXTURE
from tests.development_ensemble_support import ENSEMBLE_MODELS


def tree_metadata(index, *, prompt=4_000_000, context=4_100_000, completion=65536):
    endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
    endpoint.update(
        max_prompt_tokens=prompt, context_length=context, max_completion_tokens=completion
    )
    model = ENSEMBLE_MODELS[index]
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model}]},
    )


def tree_policy(**changes):
    values = dict(
        run_id="synthetic-automatic-tree",
        cost_policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("12"),
            request_timeout_seconds=1,
        ),
        role_metadata=tuple(tree_metadata(i) for i in range(3)),
        maximum_manifest_seconds=60,
        maximum_total_seconds=300,
    )
    values.update(changes)
    return DevelopmentTreePlanPolicy(**values)
