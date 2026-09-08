"""Pinned synthetic v2 requests and mock responses; never real provider evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mmaudit.benchmark.development import (
    DevelopmentBenchmarkTruth,
    read_development_benchmark_truth,
)
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    PreparedDevelopmentAudit,
    development_ledger_request_id,
    prepare_development_audit,
)
from tests.development_audit_support import (
    CORPUS_ROOT,
    audit_case,
    complete_audit_observation,
    shard_payload,
)

SCORED_RESPONSE = (
    Path(__file__).parent / "fixtures/model_responses/development_scored_review_response.json"
)


def scored_audit_case(
    *, variant: str = "a", run_id: str = "local-scored-review"
) -> PreparedDevelopmentAudit:
    legacy = audit_case(variant=variant, run_id=run_id)
    first = legacy.shards[0]
    return prepare_development_audit(
        policy=first.estimate.policy,
        endpoint_snapshot=first.endpoint_snapshot,
        corpus_id=first.corpus_id,
        source_files=first.source_files,
        run_id=run_id,
        schema_version="2.0",
    )


def scored_response(*, advisory: bool = False) -> dict[str, Any]:
    response = json.loads(SCORED_RESPONSE.read_text())
    assert type(response) is dict
    if advisory:
        response["findings"][0].update(
            title="Synthetic observability advisory",
            severity="informational",
            kind="advisory",
            vulnerability_class=None,
            violated_invariant=None,
            root_cause_ref=None,
            explanation="This synthetic advisory does not assert a violated invariant.",
            recommendation="Review the optional observability requirement separately.",
        )
    return response


def scored_payload(index: int, *, response: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = shard_payload(index)
    payload["choices"][0]["message"]["content"] = json.dumps(
        scored_response() if response is None else response
    )
    return payload


def benchmark_truth(variant: str = "a") -> DevelopmentBenchmarkTruth:
    return read_development_benchmark_truth((CORPUS_ROOT / f"truth-{variant}.json").read_bytes())


def scored_file_response(index: int, *, advisory: bool = False) -> dict[str, Any]:
    response = scored_response(advisory=advisory)
    start, end = ((40, 46), (12, 15), (26, 37))[index - 1]
    response["findings"][0].update(line_start=start, line_end=end)
    return response


def scored_observation(
    *, variant: str = "a", responses: tuple[dict[str, Any], ...] | None = None
) -> DevelopmentAuditObservation:
    """Pure constructed accounting/response control, not an executed run."""

    prepared = scored_audit_case(variant=variant)
    data = complete_audit_observation().model_dump(mode="json")
    data["plan"] = prepared.plan.model_dump(mode="json")
    for index, shard in enumerate(prepared.shards):
        data["observations"][index].update(
            schema_version="2.0",
            corpus_id=shard.corpus_id,
            corpus_sha256=shard.corpus_sha256,
            run_id=shard.run_id,
            source_sha256=prepared.plan.sources[index].sha256,
            estimate=shard.estimate.model_dump(mode="json"),
            elapsed_seconds=0.01,
            response=scored_file_response(index + 1) if responses is None else responses[index],
        )
        data["accounting"][index].update(
            ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
            reserved_usd=str(shard.estimate.estimated_cost_per_attempt_usd),
        )
    return DevelopmentAuditObservation.model_validate_json(json.dumps(data), strict=True)
