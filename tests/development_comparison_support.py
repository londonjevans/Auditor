"""Independent synthetic run identities and accounting, not real provider observations."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from mmaudit.benchmark.development import bind_development_benchmark, score_development_audit
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    development_ledger_request_id,
)
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_audit_case,
    scored_file_response,
    scored_observation,
)


def comparison_score(run_id="run-a", *, variant="a", mode="matched", failure=None):
    responses = tuple(
        scored_file_response(index, advisory=mode == "advisory") for index in (1, 2, 3)
    )
    if mode == "empty":
        for response in responses:
            response["findings"] = []
    prepared = scored_audit_case(run_id=run_id, variant=variant)
    data = scored_observation(variant=variant, responses=responses).model_dump(mode="json")
    data["plan"] = prepared.plan.model_dump(mode="json")
    for index, shard in enumerate(prepared.shards):
        data["observations"][index].update(
            run_id=run_id,
            estimate=shard.estimate.model_dump(mode="json"),
            generation_id=f"gen-{run_id}-{index}",
            response_sha256=hashlib.sha256(f"synthetic-{run_id}-{index}".encode()).hexdigest(),
        )
        data["accounting"][index].update(
            ledger_request_id=development_ledger_request_id(shard.estimate.request_id),
            reservation_id=hashlib.sha256(f"reservation-{run_id}-{index}".encode()).hexdigest()[
                :32
            ],
            reserved_usd=str(shard.estimate.estimated_cost_per_attempt_usd),
        )
    if failure:
        data.update(
            status="INCOMPLETE",
            stop_reason="SHARD_INCOMPLETE",
            completed_shard_count=1,
            unobserved_shard_ids=["file-02", "file-03"],
        )
        data["observations"] = data["observations"][:2]
        data["accounting"] = data["accounting"][:2]
        reservation = prepared.shards[1].estimate.estimated_cost_per_attempt_usd
        actual = (
            None if failure in {"unknown", "reserved"} else "10" if failure == "overrun" else "0.01"
        )
        accounted = reservation if failure == "unknown" else Decimal(actual or "0")
        status = {
            "unknown": "uncertain_accounted",
            "reserved": "reserved",
            "overrun": "reservation_overrun",
        }.get(failure, "reconciled")
        data["observations"][1].update(
            status="INCOMPLETE",
            diagnostics=[
                {"unknown": "UNKNOWN_COST", "overrun": "COST_OVERRUN"}.get(
                    failure, "INVALID_RESPONSE"
                )
            ],
            response=None,
            reported_cost_usd=actual,
            accounted_cost_usd=str(accounted),
            accounting_status=status,
        )
        data["accounting"][1].update(
            status=status, actual_cost_usd=actual, accounted_cost_usd=str(accounted)
        )
        data["total_accounted_cost_usd"] = str(Decimal("0.01") + accounted)
        if failure == "reserved":
            data["observations"] = data["observations"][:1]
            data["active_reserved_usd"] = str(reservation)
            data["stop_reason"] = "LOCAL_FAILURE"
    observation = DevelopmentAuditObservation.model_validate_json(json.dumps(data), strict=True)
    return score_development_audit(
        binding=bind_development_benchmark(plan=prepared.plan, truth=benchmark_truth(variant)),
        observation=observation,
    )
