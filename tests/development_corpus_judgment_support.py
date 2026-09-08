"""Synthetic manifest claims and opinions; pure constructed controls are not executed audits."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusObservation,
    DevelopmentCorpusResponse,
    DevelopmentCorpusShardObservation,
)
from mmaudit.models.development_corpus_judgment import prepare_development_corpus_judgment
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.development_corpus_support import corpus_case, corpus_payload, supplied_sources
from tests.development_judgment_support import (
    judgment_metadata,
    judgment_payload,
    judgment_response,
)


def selected_sources(count=4):
    original = supplied_sources()
    return tuple(
        sorted(
            (f"src/section-{index % 2}/Control{index:03d}.sol", original[index % len(original)][1])
            for index in range(count)
        )
    )


def selected_policy(*, carry=False, timeout=None, total="20", per_attempt="1"):
    return DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal(total),
        per_attempt_budget_usd=Decimal(per_attempt),
        request_timeout_seconds=timeout,
        uncertain_cost_policy="CARRY_RESERVED_ESTIMATE" if carry else "STOP",
    )


def pure_candidate(
    *,
    count=4,
    claims=1,
    observed_count=None,
    source_files=None,
    policy=None,
    endpoint_snapshot=None,
):
    """Construct typed model-only evidence; durable integrations execute their own candidate."""

    prepared = corpus_case(
        source_files=selected_sources(count) if source_files is None else source_files,
        policy=selected_policy() if policy is None else policy,
        **({"endpoint_snapshot": endpoint_snapshot} if endpoint_snapshot is not None else {}),
    )
    total = len(prepared.shards)
    observed_count = total if observed_count is None else observed_count
    counts = (claims,) * total if isinstance(claims, int) else claims
    observations = []
    accounting = []
    for index, shard in enumerate(prepared.shards[:observed_count], 1):
        payload = corpus_payload(index, count=counts[index - 1])
        response = DevelopmentCorpusResponse.model_validate_json(
            payload["choices"][0]["message"]["content"], strict=True
        )
        observations.append(
            DevelopmentCorpusShardObservation(
                manifest=prepared.plan.manifest,
                run_id=shard.run_id,
                shard_id=shard.shard_id,
                source_filename=shard.source_filename,
                source_sha256=hashlib.sha256(shard.source_content).hexdigest(),
                estimate=shard.estimate,
                attempt=1,
                transport="MOCK_HTTP",
                status="OBSERVED",
                diagnostics=(),
                http_status=200,
                response_sha256=hashlib.sha256(json.dumps(payload).encode()).hexdigest(),
                generation_id=payload["id"],
                accounting_status=CostEntryStatus.RECONCILED,
                reported_cost_usd=Decimal("0.01"),
                accounted_cost_usd=Decimal("0.01"),
                response=response,
                elapsed_seconds=0.01,
            )
        )
        accounting.append(
            DevelopmentCorpusAccountingEntry(
                shard_id=shard.shard_id,
                ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
                reservation_id=hashlib.sha256(
                    f"synthetic-reservation-{index}".encode()
                ).hexdigest()[:32],
                status=CostEntryStatus.RECONCILED,
                reserved_usd=shard.estimate.estimated_cost_per_attempt_usd,
                actual_cost_usd=Decimal("0.01"),
                accounted_cost_usd=Decimal("0.01"),
            )
        )
    result = DevelopmentCorpusObservation(
        plan=prepared.plan,
        transport="MOCK_HTTP",
        status="OBSERVED_ALL_SHARDS" if observed_count == total else "INCOMPLETE",
        stop_reason=None if observed_count == total else "LOCAL_FAILURE",
        observations=tuple(observations),
        accounting=tuple(accounting),
        unobserved_shard_ids=tuple(s.shard_id for s in prepared.shards[observed_count:]),
        completed_shard_count=observed_count,
        selected_primary_line_count=sum(s.line_count for s in prepared.plan.manifest.sources),
        primary_lines_with_observed_responses=sum(
            s.line_count for s in prepared.plan.manifest.sources[:observed_count]
        ),
        candidate_claim_count=sum(counts[:observed_count]),
        total_accounted_cost_usd=Decimal("0.01") * observed_count,
        reported_actual_cost_usd=Decimal("0.01") * observed_count,
        uncertain_accounted_cost_usd=Decimal("0"),
        active_reserved_usd=Decimal("0"),
        elapsed_seconds=1.0,
    )
    return prepared, result


def review_case(*, count=4, claims=1, observed_count=None, policy=None, **changes):
    original, candidate = pure_candidate(count=count, claims=claims, observed_count=observed_count)
    values = dict(
        candidate=candidate,
        policy=selected_policy() if policy is None else policy,
        endpoint_snapshot=judgment_metadata(),
        source_files=original.shards[0].source_files,
        run_id="synthetic-manifest-judgment",
    )
    values.update(changes)
    return prepare_development_corpus_judgment(**values)


def manifest_judgment_response(
    shard_id="file-0001", *, count=1, verdict="SUPPORTED", filename="src/section-0/Control000.sol"
):
    response = judgment_response(shard_id, count=count, verdict=verdict)
    response["schema_version"] = "2.0"
    for decision in response["decisions"]:
        decision["source_refs"] = [dict(filename=filename, line_start=1, line_end=1)]
    return response


def manifest_judgment_payload(
    index=1, *, shard_id=None, count=1, verdict="SUPPORTED", filename="src/section-0/Control000.sol"
):
    return judgment_payload(
        index,
        response=manifest_judgment_response(
            shard_id or f"file-{index:04d}",
            count=count,
            verdict=verdict,
            filename=filename,
        ),
    )
