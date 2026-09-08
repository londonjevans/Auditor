"""Sequential frozen-corpus development audits with durable, non-qualifying observations."""

from __future__ import annotations

import asyncio
import math
import time
from decimal import Decimal
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel

from mmaudit.benchmark.development import (
    DevelopmentBenchmarkTruth,
    bind_development_benchmark,
    score_development_audit,
)
from mmaudit.models.development_audit import (
    DevelopmentAnyAuditShardObservation,
    DevelopmentAuditAccountingEntry,
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    PreparedDevelopmentAudit,
    PreparedDevelopmentAuditShard,
    development_ledger_request_id,
    prepare_development_audit,
)
from mmaudit.models.development_review import DevelopmentReviewDiagnostic
from mmaudit.models.development_routing import DevelopmentRoutingEvidence, DevelopmentRoutingFailure
from mmaudit.models.development_transport import review_development_audit_shard
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_budget import development_uncertain_reservations
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import revalidate_evidence_file_binding, write_json_evidence
from mmaudit.repository.directory_custody import (
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
)

MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES = 2_000_000


class DevelopmentAuditError(ValueError):
    """Controlled local refusal; no request source, response or credential details."""


def _rebuild(prepared: PreparedDevelopmentAudit) -> PreparedDevelopmentAudit:
    if (
        type(prepared) is not PreparedDevelopmentAudit
        or type(prepared.shards) is not tuple
        or len(prepared.shards) != 3
        or type(prepared.plan) is not DevelopmentAuditPlan
        or any(type(shard) is not PreparedDevelopmentAuditShard for shard in prepared.shards)
    ):
        raise DevelopmentAuditError("development audit requires an exact complete prepared plan")
    plan = DevelopmentAuditPlan.model_validate_json(prepared.plan.model_dump_json(), strict=True)
    first = prepared.shards[0]
    rebuilt = prepare_development_audit(
        policy=plan.shards[0].estimate.policy,
        endpoint_snapshot=first.discovery
        if first.discovery is not None
        else first.endpoint_snapshot,
        corpus_id=plan.corpus_id,
        source_files=first.source_files,
        run_id=plan.run_id,
        maximum_completion_tokens=plan.shards[0].estimate.maximum_completion_tokens,
        schema_version=plan.schema_version,
    )
    if rebuilt != prepared:
        raise DevelopmentAuditError("development audit plan, source or requests changed")
    return rebuilt


def _write(
    output_dir: Path,
    filename: str,
    model: BaseModel,
    *,
    max_bytes: int = MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES,
) -> ManifestFileBinding:
    """Preserve the existing private writer; composed records have a bounded larger envelope."""

    if type(max_bytes) is not int or not 1 <= max_bytes <= 16_000_000:
        raise DevelopmentAuditError("development output byte bound is invalid")
    expected = model.model_dump(mode="json")

    def validate(content: bytes) -> None:
        restored = type(model).model_validate_json(content, strict=True)
        if restored.model_dump(mode="json") != expected:
            raise DevelopmentAuditError("development output differs from its exact observation")

    return write_json_evidence(
        evidence_root=output_dir,
        relative_path=filename,
        value=expected,
        max_bytes=max_bytes,
        validate_content=validate,
        require_private_parent=True,
    )


def _report(
    prepared: PreparedDevelopmentAudit,
    ledger: AtomicCostLedger,
    observations: list[DevelopmentAnyAuditShardObservation],
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"],
    reason: Literal["SHARD_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None,
    elapsed: float,
) -> DevelopmentAuditObservation:
    entries = {entry.request_id: entry for entry in ledger.snapshot().entries}
    accounting: list[DevelopmentAuditAccountingEntry] = []
    for shard in prepared.plan.shards:
        entry = entries.get(development_ledger_request_id(shard.estimate.request_id))
        if entry is not None:
            accounting.append(
                DevelopmentAuditAccountingEntry(
                    shard_id=shard.shard_id,
                    ledger_request_id=entry.request_id,
                    reservation_id=entry.reservation_id,
                    status=entry.status,
                    reserved_usd=entry.reserved_usd,
                    actual_cost_usd=entry.actual_cost_usd,
                    accounted_cost_usd=entry.accounted_cost_usd,
                )
            )
    complete = {item.shard_id for item in observations if item.status == "OBSERVED"}
    gaps = tuple(shard.shard_id for shard in prepared.plan.shards if shard.shard_id not in complete)
    return DevelopmentAuditObservation(
        plan=prepared.plan,
        transport=transport,
        status="OBSERVED_ALL_SHARDS" if not gaps and reason is None else "INCOMPLETE",
        stop_reason=reason,
        observations=tuple(observations),
        accounting=tuple(accounting),
        unobserved_shard_ids=gaps,
        completed_shard_count=len(complete),
        total_accounted_cost_usd=sum((item.accounted_cost_usd for item in accounting), Decimal(0)),
        active_reserved_usd=sum(
            (item.reserved_usd for item in accounting if item.status is CostEntryStatus.RESERVED),
            Decimal(0),
        ),
        elapsed_seconds=elapsed,
    )


async def run_development_audit(
    *,
    prepared: PreparedDevelopmentAudit,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    output_dir: Path,
    allow_code_egress: bool = False,
    maximum_run_seconds: float = 600.0,
    mock_transport: httpx.MockTransport | None = None,
    benchmark_truth: DevelopmentBenchmarkTruth | None = None,
) -> DevelopmentAuditObservation:
    """Run each shard once; keep unknown liabilities and stop each incomplete run.

    Output must be a new directory. Existing run IDs/output are refused, not replayed
    or resumed on assumed success. This does not initialize/reset a ledger or grant
    production audit completion. Cancellation retains durable accounting and prior
    observations, and is re-raised after a best-effort incomplete aggregate write.
    """

    if allow_code_egress is not True:
        raise DevelopmentAuditError("development audit requires explicit source egress consent")
    if type(ledger) is not AtomicCostLedger or type(operator_secrets) is not OperatorSecrets:
        raise DevelopmentAuditError(
            "development audit requires exact ledger and credential handles"
        )
    if not operator_secrets.openrouter_api_key_present:
        raise DevelopmentAuditError("development audit lacks explicit credentials")
    if mock_transport is not None and type(mock_transport) is not httpx.MockTransport:
        raise DevelopmentAuditError(
            "development audit test transport must be an exact MockTransport"
        )
    if (
        type(maximum_run_seconds) not in {int, float}
        or not math.isfinite(maximum_run_seconds)
        or not 0 < maximum_run_seconds <= 1800
    ):
        raise DevelopmentAuditError("development audit requires a bounded run deadline")
    prepared = _rebuild(prepared)
    benchmark_binding = (
        bind_development_benchmark(plan=prepared.plan, truth=benchmark_truth)
        if benchmark_truth is not None
        else None
    )
    state = ledger.snapshot()
    carried_ids = {
        allowance.request_id
        for allowance in development_uncertain_reservations(
            policy=prepared.plan.shards[0].estimate.policy, snapshot=state
        )
    }
    request_ids = {
        development_ledger_request_id(shard.estimate.request_id) for shard in prepared.plan.shards
    }
    if (
        state.cap_usd != prepared.plan.shards[0].estimate.policy.total_budget_usd
        or state.over_cap
        or state.has_reservation_overrun
        or state.active_reserved_usd != 0
        or any(
            (
                entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                and entry.request_id not in carried_ids
            )
            or entry.request_id in request_ids
            for entry in state.entries
        )
        or prepared.plan.estimated_total_cost_usd > state.remaining_usd
    ):
        raise DevelopmentAuditError("development audit preflight refuses cumulative accounting")
    if not output_dir.is_absolute():
        raise DevelopmentAuditError("development audit output path must be absolute")
    parent = observe_unlinked_directory(output_dir.parent, label="development audit output parent")
    output_dir.mkdir(mode=0o700)
    require_same_unlinked_directory_objects(parent, label="development audit output parent")
    custody = observe_unlinked_directory(output_dir, label="development audit output")
    bindings = [_write(output_dir, "plan.json", prepared.plan)]
    if benchmark_binding is not None:
        bindings.append(_write(output_dir, "benchmark-plan.json", benchmark_binding))

    def require_outputs() -> None:
        require_same_unlinked_directory_objects(custody, label="development audit output")
        for binding in bindings:
            revalidate_evidence_file_binding(
                evidence_root=output_dir,
                binding=binding,
                max_bytes=MAX_DEVELOPMENT_AUDIT_ARTIFACT_BYTES,
            )

    start = time.monotonic()
    deadline = start + maximum_run_seconds
    observations: list[DevelopmentAnyAuditShardObservation] = []
    reason: Literal["SHARD_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"] | None = None
    interruption: BaseException | None = None
    try:
        async with asyncio.timeout(maximum_run_seconds):
            for shard in prepared.shards:
                require_outputs()
                if time.monotonic() >= deadline:
                    raise TimeoutError("development run deadline exceeded before dispatch")
                observation = await review_development_audit_shard(
                    prepared=shard,
                    ledger=ledger,
                    operator_secrets=operator_secrets,
                    allow_code_egress=allow_code_egress,
                    mock_transport=mock_transport,
                )
                if observation.status == "OBSERVED" and any(
                    item.generation_id == observation.generation_id for item in observations
                ):
                    routing = observation.routing_evidence
                    if routing is not None:
                        routing = DevelopmentRoutingEvidence.model_validate(
                            {
                                **routing.model_dump(),
                                "failure_codes": (DevelopmentRoutingFailure.GENERATION_REUSE,),
                            }
                        )
                    observation = type(observation).model_validate(
                        {
                            **observation.model_dump(),
                            "status": "INCOMPLETE",
                            "response": None,
                            "diagnostics": (DevelopmentReviewDiagnostic.IDENTITY_MISMATCH,),
                            "routing_evidence": routing,
                        }
                    )
                observations.append(observation)
                require_outputs()
                bindings.append(_write(output_dir, shard.shard_id + ".json", observation))
                if time.monotonic() >= deadline:
                    raise TimeoutError("development run deadline exceeded after observation")
                if observation.status != "OBSERVED":
                    reason = "SHARD_INCOMPLETE"
                    break
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit) as exc:
        interruption = exc
        reason = "INTERRUPTED"
    except Exception:
        reason = "LOCAL_FAILURE"
    try:
        result = _report(
            prepared,
            ledger,
            observations,
            "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
            reason,
            time.monotonic() - start,
        )
        require_outputs()
        bindings.append(_write(output_dir, "result.json", result))
        require_outputs()
        if benchmark_binding is not None:
            score = score_development_audit(binding=benchmark_binding, observation=result)
            bindings.append(_write(output_dir, "score.json", score))
            require_outputs()
    except Exception:
        if interruption is not None:
            raise interruption from None
        raise DevelopmentAuditError(
            "development audit output/accounting could not be finalized"
        ) from None
    if interruption is not None:
        raise interruption
    return result
