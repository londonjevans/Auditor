"""Synthetic request and metadata shared by development-cost regressions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mmaudit.models.endpoint_snapshots import (
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)

FIXTURE = Path(__file__).parent / "fixtures" / "model_responses" / "development_cost_case.json"


def development_case(
    *, pricing: dict[str, Any] | None = None
) -> tuple[OpenRouterEndpointSnapshotEvidence, dict[str, Any]]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    endpoint = data["endpoint"]
    if pricing is not None:
        endpoint["pricing"] = pricing
    model = data["request"]["model"]
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model}]},
    )
    return snapshot, data["request"]
