"""Frozen local corpus and synthetic observations; never real provider evidence."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

from mmaudit.models.development_audit import (
    DevelopmentAuditAccountingEntry,
    DevelopmentAuditObservation,
    DevelopmentAuditShardObservation,
    development_ledger_request_id,
    prepare_development_audit,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_review import DevelopmentReviewResponse
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.development_cost_support import development_case
from tests.development_review_support import discovery_review_case, response_payload

CORPUS_ROOT = Path(__file__).parent / "fixtures/solidity/development_audit"


def corpus_sources(variant="a"):
    return tuple(
        (name, (CORPUS_ROOT / variant / name).read_bytes())
        for name in ("RoutePolicy.sol", "UnitRouter.sol", "UnitStore.sol")
    )


def audit_case(*, variant="a", run_id="local-sharded-review", discovery=False, policy=None):
    return prepare_development_audit(
        policy=policy
        or DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("5"),
        ),
        endpoint_snapshot=discovery_review_case() if discovery else development_case()[0],
        corpus_id="unit-ledger-" + variant + "-v1",
        source_files=corpus_sources(variant),
        run_id=run_id,
    )


def shard_payload(index, *, cost=0.01, empty=False):
    value = response_payload()
    value["id"] = f"gen-development-shard-{index}"
    value["usage"]["cost"] = cost
    if empty:
        value["choices"][0]["message"]["content"] = json.dumps(
            {
                "summary": "Synthetic mocked primary-file review only.",
                "findings": [],
            }
        )
    return value


def shard_observation(shard, *, index=1):
    payload = shard_payload(index)
    return DevelopmentAuditShardObservation(
        source_filename=shard.source_filename,
        source_sha256=hashlib.sha256(shard.source_content).hexdigest(),
        estimate=shard.estimate,
        attempt=1,
        transport="MOCK_HTTP",
        status="OBSERVED",
        diagnostics=(),
        http_status=200,
        response_sha256=f"{index:064x}",
        generation_id=payload["id"],
        accounting_status=CostEntryStatus.RECONCILED,
        reported_cost_usd=Decimal("0.01"),
        accounted_cost_usd=Decimal("0.01"),
        response=DevelopmentReviewResponse.model_validate_json(
            payload["choices"][0]["message"]["content"]
        ),
        corpus_id=shard.corpus_id,
        corpus_sha256=shard.corpus_sha256,
        run_id=shard.run_id,
        shard_id=shard.shard_id,
    )


def complete_audit_observation():
    prepared = audit_case()
    observations = tuple(
        shard_observation(shard, index=index) for index, shard in enumerate(prepared.shards, 1)
    )
    return DevelopmentAuditObservation(
        plan=prepared.plan,
        transport="MOCK_HTTP",
        status="OBSERVED_ALL_SHARDS",
        stop_reason=None,
        observations=observations,
        accounting=tuple(
            DevelopmentAuditAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
                reservation_id=f"{index:032x}",
                status=CostEntryStatus.RECONCILED,
                reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
                actual_cost_usd=Decimal("0.01"),
                accounted_cost_usd=Decimal("0.01"),
            )
            for index, shard in enumerate(prepared.shards, 1)
        ),
        unobserved_shard_ids=(),
        completed_shard_count=3,
        total_accounted_cost_usd=Decimal("0.03"),
        active_reserved_usd=Decimal(0),
        elapsed_seconds=0.1,
    )
