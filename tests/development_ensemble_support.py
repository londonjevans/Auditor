"""Synthetic three-role metadata and replies; no live provider or lineage evidence."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_ensemble import (
    PreparedDevelopmentEnsemble,
    prepare_development_ensemble,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from tests.development_audit_support import corpus_sources
from tests.development_benchmark_support import scored_file_response, scored_payload
from tests.development_cost_support import FIXTURE
from tests.development_judgment_support import judgment_metadata, judgment_response

ENSEMBLE_MODELS = (
    "synthetic/ensemble-candidate",
    "synthetic/ensemble-review-one",
    "synthetic/ensemble-review-two",
)


def ensemble_case(*, variant: str = "a", **changes: Any) -> PreparedDevelopmentEnsemble:
    values: dict[str, Any] = dict(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("1"),
        ),
        candidate_metadata=judgment_metadata(model_id=ENSEMBLE_MODELS[0]),
        reviewer_metadata=tuple(judgment_metadata(model_id=name) for name in ENSEMBLE_MODELS[1:]),
        corpus_id=f"unit-ledger-{variant}-v1",
        source_files=corpus_sources(variant),
        run_id="synthetic-ensemble",
    )
    values.update(changes)
    return prepare_development_ensemble(**values)


def high_allowance_metadata(model_id: str):
    endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
    endpoint["max_completion_tokens"] = 65_536
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model_id,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model_id, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model_id}]},
    )


def ensemble_payload(
    role: int, shard: int, *, count: int = 1, verdict: str = "SUPPORTED"
) -> dict[str, Any]:
    if role == 0:
        response = scored_file_response(shard)
        response["findings"] = response["findings"] * count
    else:
        response = judgment_response(f"file-{shard:02d}", count=count, verdict=verdict)
    payload = scored_payload(shard, response=response)
    payload["id"] = f"gen-synthetic-ensemble-{role}-{shard}"
    payload["model"] = ENSEMBLE_MODELS[role]
    routing = payload["openrouter_metadata"]
    routing["requested"] = payload["model"]
    routing["endpoints"]["available"][0]["model"] = payload["model"]
    routing["attempts"][0]["model"] = payload["model"]
    return payload
