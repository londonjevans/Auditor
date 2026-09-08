"""Synthetic frozen-corpus candidates and review payloads, never real provider evidence."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.models.development_audit import (
    DevelopmentAuditAccountingEntry,
    development_ledger_request_id,
)
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentObservation,
    DevelopmentJudgmentShardObservation,
    PreparedDevelopmentJudgment,
    prepare_development_judgment,
)
from mmaudit.models.development_review import DevelopmentJudgmentResponse, DevelopmentReviewMetadata
from mmaudit.models.discovery import validate_openrouter_model_discovery
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_audit_support import corpus_sources
from tests.development_benchmark_support import scored_observation, scored_payload
from tests.development_cost_support import FIXTURE

JUDGMENT_FIXTURE = (
    Path(__file__).parent / "fixtures/model_responses/development_judgment_response.json"
)


def judgment_metadata(
    *, model_id: str = "synthetic/development-reviewer", canonical: str | None = None
) -> DevelopmentReviewMetadata:
    endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model_id,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model_id, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model_id}]},
    )
    if canonical is None:
        return snapshot
    model = json.loads((FIXTURE.parent / "development_reasoning_model.json").read_bytes())["model"]
    model.update(id=model_id, canonical_slug=canonical)
    return validate_openrouter_model_discovery(
        exact_model_id=model_id,
        models_payload={"data": [model]},
        single_model_payload={"data": model},
        endpoint_snapshot=snapshot,
    )


def judgment_case(
    *, variant: str = "a", responses: tuple[dict[str, Any], ...] | None = None, **changes: Any
) -> PreparedDevelopmentJudgment:
    candidate = scored_observation(variant=variant, responses=responses)
    values: dict[str, Any] = dict(
        candidate=candidate,
        policy=candidate.plan.shards[0].estimate.policy,
        endpoint_snapshot=judgment_metadata(),
        source_files=corpus_sources(variant),
        run_id="local-judgment",
    )
    values.update(changes)
    return prepare_development_judgment(**values)


def judgment_response(
    shard_id: str = "file-01", *, count: int = 1, verdict: str = "SUPPORTED"
) -> dict[str, Any]:
    value = json.loads(JUDGMENT_FIXTURE.read_bytes())
    original = value["decisions"][0]
    value["decisions"] = [
        {**original, "claim_id": f"{shard_id}:{index:02d}", "verdict": verdict}
        for index in range(1, count + 1)
    ]
    return value  # type: ignore[no-any-return]


def judgment_payload(index: int = 1, *, response: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = scored_payload(index)
    payload["id"] = f"gen-synthetic-judgment-{index}"
    payload["model"] = "synthetic/development-reviewer"
    routing = payload["openrouter_metadata"]
    routing["requested"] = payload["model"]
    routing["endpoints"]["available"][0]["model"] = payload["model"]
    routing["attempts"][0]["model"] = payload["model"]
    payload["choices"][0]["message"]["content"] = json.dumps(
        response or judgment_response(f"file-{index:02d}")
    )
    return payload


def judgment_observation(
    *,
    variant="a",
    responses=None,
    verdicts=("SUPPORTED", "SUPPORTED", "SUPPORTED"),
    completed=None,
    unobserved_cost=None,
):
    """Pure constructed score control; never an executed request or provider receipt."""

    prepared = judgment_case(variant=variant, responses=responses)
    count = len(prepared.shards) if completed is None else completed
    observations = []
    accounting = []
    for ordinal, shard in enumerate(prepared.shards[:count], 1):
        response = DevelopmentJudgmentResponse.model_validate_json(
            json.dumps(
                judgment_response(
                    shard.shard_id, count=len(shard.claims), verdict=verdicts[ordinal - 1]
                )
            )
        )
        observations.append(
            DevelopmentJudgmentShardObservation(
                source_filename=shard.source_filename,
                source_sha256=prepared.plan.candidate.plan.sources[
                    int(shard.shard_id[-1]) - 1
                ].sha256,
                estimate=shard.estimate,
                attempt=1,
                transport="MOCK_HTTP",
                status="OBSERVED",
                diagnostics=(),
                http_status=200,
                response_sha256=canonical_sha256(response.model_dump(mode="json")),
                generation_id=f"gen-synthetic-pure-judgment-{ordinal}",
                accounting_status=CostEntryStatus.RECONCILED,
                reported_cost_usd=Decimal("0.01"),
                accounted_cost_usd=Decimal("0.01"),
                response=response,
                candidate_sha256=prepared.plan.candidate_sha256,
                corpus_id=prepared.plan.candidate.plan.corpus_id,
                run_id=prepared.plan.run_id,
                shard_id=shard.shard_id,
                claims=shard.claims,
                elapsed_seconds=0.01,
            )
        )
        accounting.append(
            DevelopmentAuditAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
                reservation_id=f"{ordinal + 100:032x}",
                status=CostEntryStatus.RECONCILED,
                reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
                actual_cost_usd=Decimal("0.01"),
                accounted_cost_usd=Decimal("0.01"),
            )
        )
    if unobserved_cost is not None:
        shard = prepared.shards[count]
        status = (
            CostEntryStatus.UNCERTAIN_ACCOUNTED
            if unobserved_cost == "uncertain"
            else CostEntryStatus.RESERVED
        )
        accounting.append(
            DevelopmentAuditAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
                reservation_id=f"{count + 101:032x}",
                status=status,
                reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
                actual_cost_usd=None,
                accounted_cost_usd=shard.estimate.estimated_cost_per_attempt_usd
                if status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                else Decimal(0),
            )
        )
    cost = sum((item.accounted_cost_usd for item in accounting), Decimal(0))
    gaps = tuple(claim.claim_id for shard in prepared.shards[count:] for claim in shard.claims)
    return DevelopmentJudgmentObservation(
        plan=prepared.plan,
        transport="MOCK_HTTP",
        status="INCOMPLETE"
        if gaps
        else "OBSERVED_ALL_JUDGMENTS"
        if prepared.shards
        else "NO_CANDIDATES",
        stop_reason="INTERRUPTED" if gaps else None,
        observations=tuple(observations),
        accounting=tuple(accounting),
        unreviewed_claim_ids=gaps,
        completed_judgment_count=sum(len(item.claims) for item in observations),
        judgment_accounted_cost_usd=cost,
        combined_accounted_cost_usd=cost + prepared.plan.candidate.total_accounted_cost_usd,
        active_reserved_usd=sum(
            (item.reserved_usd for item in accounting if item.status is CostEntryStatus.RESERVED),
            Decimal(0),
        ),
        elapsed_seconds=0.1,
        summed_stage_elapsed_seconds=0.1 + prepared.plan.candidate.elapsed_seconds,
    )
